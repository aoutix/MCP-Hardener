import { isIP, isIPv4 } from "node:net";

/**
 * Address ranges that must never be reachable from a tool call: loopback,
 * link-local (including the cloud metadata endpoint at 169.254.169.254),
 * private space, CGNAT, and the various documentation and special-use blocks.
 */
const V4_BLOCKS: readonly [string, number, string][] = [
  ["0.0.0.0", 8, "this-network"],
  ["10.0.0.0", 8, "private (RFC1918)"],
  ["100.64.0.0", 10, "carrier-grade NAT"],
  ["127.0.0.0", 8, "loopback"],
  ["169.254.0.0", 16, "link-local / cloud metadata"],
  ["172.16.0.0", 12, "private (RFC1918)"],
  ["192.0.0.0", 24, "IETF protocol assignments"],
  ["192.0.2.0", 24, "documentation (TEST-NET-1)"],
  ["192.168.0.0", 16, "private (RFC1918)"],
  ["198.18.0.0", 15, "benchmarking"],
  ["198.51.100.0", 24, "documentation (TEST-NET-2)"],
  ["203.0.113.0", 24, "documentation (TEST-NET-3)"],
  ["224.0.0.0", 4, "multicast"],
  ["240.0.0.0", 4, "reserved"]
];

function v4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    out = (out << 8) | n;
  }
  return out >>> 0;
}

function inV4Block(ip: number, base: string, bits: number): boolean {
  const baseInt = v4ToInt(base);
  if (baseInt === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ip & mask) === (baseInt & mask);
}

export interface IpVerdict {
  readonly blocked: boolean;
  readonly reason?: string;
}

function classifyV4(ip: string): IpVerdict {
  const n = v4ToInt(ip);
  if (n === null) return { blocked: true, reason: `unparseable IPv4 address ${ip}` };
  if (n === 0xffffffff) return { blocked: true, reason: "broadcast address" };
  for (const [base, bits, label] of V4_BLOCKS) {
    if (inV4Block(n, base, bits)) return { blocked: true, reason: `${ip} is in ${base}/${bits} (${label})` };
  }
  return { blocked: false };
}

function expandV6(ip: string): string[] | null {
  let addr = ip.replace(/^\[|\]$/g, "").split("%")[0]!;
  // An IPv4-mapped tail is handled by the caller; strip a zone id first.
  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const toGroups = (s: string): string[] => (s.length === 0 ? [] : s.split(":"));
  let groups: string[];
  if (halves.length === 2) {
    const head = toGroups(halves[0]!);
    const tail = toGroups(halves[1]!);
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    groups = [...head, ...Array<string>(fill).fill("0"), ...tail];
  } else {
    groups = toGroups(halves[0]!);
  }
  if (groups.length !== 8) return null;
  return groups;
}

function classifyV6(ip: string): IpVerdict {
  const bare = ip.replace(/^\[|\]$/g, "").split("%")[0]!;
  const lower = bare.toLowerCase();

  // IPv4-mapped and NAT64 addresses carry an embedded IPv4 address; the
  // embedded address is what the connection actually reaches.
  const embedded = /(?:^::ffff:|^64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/i.exec(lower);
  if (embedded) {
    const inner = classifyV4(embedded[1]!);
    return inner.blocked ? { blocked: true, reason: `${ip} embeds ${inner.reason}` } : { blocked: false };
  }

  const groups = expandV6(lower);
  if (!groups) return { blocked: true, reason: `unparseable IPv6 address ${ip}` };
  const first = parseInt(groups[0]!, 16);
  if (Number.isNaN(first)) return { blocked: true, reason: `unparseable IPv6 address ${ip}` };

  const allZeroButLast = groups.slice(0, 7).every((g) => parseInt(g, 16) === 0);
  if (allZeroButLast) {
    const last = parseInt(groups[7]!, 16);
    if (last === 1) return { blocked: true, reason: `${ip} is IPv6 loopback` };
    if (last === 0) return { blocked: true, reason: `${ip} is the IPv6 unspecified address` };
    return { blocked: true, reason: `${ip} is in ::/64 (special-use)` };
  }
  if ((first & 0xfe00) === 0xfc00) return { blocked: true, reason: `${ip} is in fc00::/7 (unique local)` };
  if ((first & 0xffc0) === 0xfe80) return { blocked: true, reason: `${ip} is in fe80::/10 (link-local)` };
  if ((first & 0xff00) === 0xff00) return { blocked: true, reason: `${ip} is multicast` };
  if (first === 0x2001 && parseInt(groups[1]!, 16) === 0x0db8) {
    return { blocked: true, reason: `${ip} is in 2001:db8::/32 (documentation)` };
  }
  return { blocked: false };
}

/** True with a reason when this literal address must not be connected to. */
export function classifyAddress(ip: string): IpVerdict {
  const family = isIP(ip.replace(/^\[|\]$/g, "").split("%")[0]!);
  if (family === 0) return { blocked: true, reason: `not an IP address: ${ip}` };
  return isIPv4(ip) ? classifyV4(ip) : classifyV6(ip);
}

export function isIpLiteral(host: string): boolean {
  return isIP(host.replace(/^\[|\]$/g, "")) !== 0;
}
