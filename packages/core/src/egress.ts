import { lookup as dnsLookup } from "node:dns";
import { Agent, request as undiciRequest } from "undici";
import { classifyAddress, isIpLiteral } from "./ip.js";
import type { EgressConfig } from "./policy.js";

export class EgressDenied extends Error {
  constructor(message: string, readonly code: string) {
    super(message);
    this.name = "EgressDenied";
  }
}

export interface EgressCheck {
  readonly ok: boolean;
  readonly code?: string;
  readonly reason?: string;
}

/** Matches an allowlist entry: `api.example.com`, `*.example.com`, or either with `:port`. */
function matchesEntry(entry: string, hostname: string, port: string): boolean {
  const [pattern, entryPort] = splitHostPort(entry);
  if (entryPort !== undefined && entryPort !== port) return false;
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const pat = pattern.toLowerCase().replace(/\.$/, "");
  if (pat.startsWith("*.")) {
    const suffix = pat.slice(1); // ".example.com"
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return host === pat;
}

function splitHostPort(entry: string): [string, string | undefined] {
  if (entry.startsWith("[")) {
    const end = entry.indexOf("]");
    if (end === -1) return [entry, undefined];
    const host = entry.slice(1, end);
    const rest = entry.slice(end + 1);
    return [host, rest.startsWith(":") ? rest.slice(1) : undefined];
  }
  const idx = entry.lastIndexOf(":");
  if (idx > 0 && !entry.slice(idx + 1).includes(".") && /^\d+$/.test(entry.slice(idx + 1))) {
    return [entry.slice(0, idx), entry.slice(idx + 1)];
  }
  return [entry, undefined];
}

function defaultPort(protocol: string): string {
  return protocol === "https:" ? "443" : "80";
}

export interface EgressResponse {
  readonly status: number;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly body: Buffer;
  readonly bytes: number;
  readonly url: string;
  readonly truncated: boolean;
}

export interface EgressRequestInit {
  readonly method?: string;
  readonly headers?: Record<string, string>;
  readonly body?: string | Buffer | undefined;
  readonly signal?: AbortSignal | undefined;
}

/**
 * The only outbound HTTP path in this project. Generated servers use it to
 * reach their REST API and the gateway uses it to reach HTTP upstreams, so one
 * set of limits covers both.
 *
 * Checks, in order: scheme, embedded credentials, method, host allowlist, then
 * DNS resolution with every returned address validated against private space.
 * The verified addresses are pinned for the connection, which closes the DNS
 * rebinding window between the check and the connect.
 */
export class EgressGuard {
  private readonly agentCache = new Map<string, Agent>();
  private readonly streamingAgentCache = new Map<string, Agent>();

  constructor(readonly config: EgressConfig) {}

  /** Synchronous pre-flight: everything decidable without touching the network. */
  check(rawUrl: string, method = "GET"): EgressCheck {
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      return { ok: false, code: "invalid-url", reason: `not a valid URL: ${rawUrl}` };
    }

    if (url.protocol !== "https:" && url.protocol !== "http:") {
      return { ok: false, code: "scheme", reason: `scheme ${url.protocol} is not permitted; use https` };
    }
    if (url.protocol === "http:" && !this.config.allow_http) {
      return {
        ok: false,
        code: "plaintext",
        reason: `plaintext HTTP to ${url.host} is refused; set egress.allow_http to permit it`
      };
    }
    if (url.username || url.password) {
      return { ok: false, code: "url-credentials", reason: "credentials embedded in the URL are refused" };
    }
    const upper = method.toUpperCase();
    if (!this.config.methods.map((m) => m.toUpperCase()).includes(upper)) {
      return {
        ok: false,
        code: "method",
        reason: `method ${upper} is not in egress.methods (${this.config.methods.join(", ")})`
      };
    }

    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    const port = url.port || defaultPort(url.protocol);

    if (isIpLiteral(hostname) && !this.config.allow_ip_literals) {
      return {
        ok: false,
        code: "ip-literal",
        reason: `bare IP target ${hostname} is refused; set egress.allow_ip_literals to permit it`
      };
    }
    if (this.config.allow.length === 0) {
      return {
        ok: false,
        code: "no-allowlist",
        reason: "egress.allow is empty, so no outbound host is permitted"
      };
    }
    if (!this.config.allow.some((entry) => matchesEntry(entry, hostname, port))) {
      return {
        ok: false,
        code: "host",
        reason: `${url.host} is not in egress.allow (${this.config.allow.join(", ")})`
      };
    }
    if (this.config.block_private_ips && isIpLiteral(hostname)) {
      const verdict = classifyAddress(hostname);
      if (verdict.blocked) return { ok: false, code: "private-address", reason: verdict.reason };
    }
    return { ok: true };
  }

  /** Resolves a hostname and refuses the call if any address is in blocked space. */
  async resolveVerified(hostname: string): Promise<{ address: string; family: number }[]> {
    if (isIpLiteral(hostname)) {
      const verdict = classifyAddress(hostname);
      if (this.config.block_private_ips && verdict.blocked) {
        throw new EgressDenied(`refusing to connect: ${verdict.reason}`, "private-address");
      }
      return [{ address: hostname, family: hostname.includes(":") ? 6 : 4 }];
    }

    const records = await new Promise<{ address: string; family: number }[]>((resolve, reject) => {
      dnsLookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
        if (err) reject(new EgressDenied(`DNS lookup for ${hostname} failed: ${err.message}`, "dns"));
        else resolve(addresses as { address: string; family: number }[]);
      });
    });

    if (records.length === 0) {
      throw new EgressDenied(`DNS lookup for ${hostname} returned no addresses`, "dns");
    }
    if (this.config.block_private_ips) {
      for (const record of records) {
        const verdict = classifyAddress(record.address);
        if (verdict.blocked) {
          // Refuse outright rather than filtering: a public hostname that also
          // resolves into private space is the rebinding attack, not a quirk.
          throw new EgressDenied(
            `refusing to connect to ${hostname}: it resolves to ${record.address}, ${verdict.reason}`,
            "private-address"
          );
        }
      }
    }
    return records;
  }

  private agentFor(addresses: { address: string; family: number }[]): Agent {
    const key = addresses.map((a) => a.address).join(",");
    const cached = this.agentCache.get(key);
    if (cached) return cached;
    const agent = new Agent({
      connect: {
        // Pin the connection to the addresses we validated.
        lookup: (_hostname, _options, callback) => {
          callback(null, addresses as never);
        }
      },
      headersTimeout: this.config.timeout_ms,
      bodyTimeout: this.config.timeout_ms,
      connectTimeout: this.config.timeout_ms
    });
    this.agentCache.set(key, agent);
    return agent;
  }

  /**
   * Performs the request with every limit enforced. Redirects are followed
   * manually, re-running the full check against each hop, because undici's
   * redirect interceptor would send us to a host the allowlist never saw.
   */
  /**
   * A guarded request whose response body is *streamed* rather than buffered.
   *
   * `fetch` above reads the whole body so it can cap it, which is right for a
   * REST call and fatal for an MCP transport: a Streamable HTTP server
   * answers with `text/event-stream` and holds it open for the life of the
   * session, so buffering would simply never return. The gateway therefore
   * used a plain global `fetch` for its upstreams and got none of the
   * protections the policy file promised.
   *
   * This is the subset that is sound for a long-lived stream:
   *
   * - the synchronous pre-flight, and DNS resolution with every returned
   *   address checked, so a name that also resolves into private space is
   *   refused rather than filtered;
   * - the connection pinned to those addresses, which closes the window
   *   between checking a name and connecting to it;
   * - a connect and headers timeout, which bound *reaching* the upstream;
   * - redirects refused or counted here rather than followed by the fetch
   *   implementation, so an allowlisted host cannot hand the connection to
   *   one the allowlist never saw;
   * - the response cap, applied as the bytes arrive.
   *
   * Two limits are deliberately not applied. There is no body timeout: an
   * idle event stream is the normal state of a healthy MCP session, not a
   * stall. And the response cap is skipped for `text/event-stream`, where the
   * "body" is every message of a conversation rather than one payload --
   * capping it would end a long session at an arbitrary point. Both are
   * stated here because each is a limit a reader of `policy.yaml` could
   * reasonably expect to apply and will not.
   */
  async streamingFetch(
    rawUrl: string,
    init: { method?: string; headers?: Record<string, string>; body?: unknown; signal?: AbortSignal } = {}
  ): Promise<Response> {
    const method = (init.method ?? "GET").toUpperCase();
    let target = rawUrl;

    for (let hop = 0; ; hop++) {
      const verdict = this.check(target, method);
      if (!verdict.ok) throw new EgressDenied(verdict.reason ?? "egress refused", verdict.code ?? "refused");

      const url = new URL(target);
      const addresses = await this.resolveVerified(url.hostname.replace(/^\[|\]$/g, ""));
      const dispatcher = this.streamingAgentFor(addresses);

      const response = await fetch(target, {
        method,
        ...(init.headers ? { headers: init.headers } : {}),
        ...(init.body !== undefined && init.body !== null ? { body: init.body as RequestInit["body"] } : {}),
        ...(init.signal ? { signal: init.signal } : {}),
        // Never followed by the implementation: a redirect is a request to a
        // URL the allowlist has not seen, so it comes back here to be checked.
        redirect: "manual",
        dispatcher
      } as RequestInit);

      const isRedirect = response.status >= 300 && response.status < 400 && response.status !== 304;
      if (!isRedirect) return this.capped(response);

      if (hop >= this.config.max_redirects) {
        throw new EgressDenied(
          this.config.max_redirects === 0
            ? `upstream returned ${response.status} and egress.max_redirects is 0, so the redirect was refused`
            : `upstream exceeded egress.max_redirects (${this.config.max_redirects})`,
          "redirect"
        );
      }
      const location = response.headers.get("location");
      if (!location) {
        throw new EgressDenied(`upstream returned ${response.status} without a Location header`, "redirect");
      }
      target = new URL(location, target).toString();
    }
  }

  /** Counts bytes as they arrive and aborts past the cap. */
  private capped(response: Response): Response {
    const type = response.headers.get("content-type") ?? "";
    if (!response.body || type.includes("text/event-stream")) return response;

    const limit = this.config.max_body_bytes;
    let seen = 0;
    const body = response.body.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          seen += chunk.byteLength;
          if (seen > limit) {
            controller.error(
              new EgressDenied(
                `response body exceeded egress.max_body_bytes (${limit}); the request was aborted`,
                "response-too-large"
              )
            );
            return;
          }
          controller.enqueue(chunk);
        }
      })
    );
    return new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });
  }

  /**
   * A pinned agent for a stream.
   *
   * Separate from `agentFor` because that one sets `bodyTimeout`, which would
   * tear down an event stream that is merely quiet.
   */
  private streamingAgentFor(addresses: { address: string; family: number }[]): Agent {
    const key = addresses.map((a) => a.address).join(",");
    const cached = this.streamingAgentCache.get(key);
    if (cached) return cached;
    const agent = new Agent({
      connect: {
        lookup: (_hostname, _options, callback) => {
          callback(null, addresses as never);
        }
      },
      headersTimeout: this.config.timeout_ms,
      bodyTimeout: 0,
      connectTimeout: this.config.timeout_ms
    });
    this.streamingAgentCache.set(key, agent);
    return agent;
  }

  async fetch(rawUrl: string, init: EgressRequestInit = {}): Promise<EgressResponse> {
    let method = (init.method ?? "GET").toUpperCase();
    let target = rawUrl;
    let body = init.body;
    let headers = init.headers;

    if (body !== undefined) {
      const size = Buffer.byteLength(body as string | Buffer);
      if (size > this.config.max_request_body_bytes) {
        throw new EgressDenied(
          `request body of ${size} bytes exceeds egress.max_request_body_bytes (${this.config.max_request_body_bytes})`,
          "request-too-large"
        );
      }
    }

    for (let hop = 0; ; hop++) {
      const response = await this.fetchOnce(target, { method, headers, body, signal: init.signal });

      const isRedirect = response.status >= 300 && response.status < 400 && response.status !== 304;
      if (!isRedirect) return response;

      const location = headerValue(response.headers, "location");
      if (hop >= this.config.max_redirects) {
        throw new EgressDenied(
          this.config.max_redirects === 0
            ? `upstream returned ${response.status} and egress.max_redirects is 0, so the redirect was refused`
            : `upstream exceeded egress.max_redirects (${this.config.max_redirects})`,
          "redirect"
        );
      }
      if (!location) {
        throw new EgressDenied(`upstream returned ${response.status} without a Location header`, "redirect");
      }

      let next: URL;
      try {
        next = new URL(location, target);
      } catch {
        throw new EgressDenied(`upstream redirected to an unparseable location`, "redirect");
      }

      // 303, and 301/302 on a non-GET, become GET without a body, per the
      // usual browser rules. The next hop is then checked from scratch.
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && method !== "GET" && method !== "HEAD")) {
        method = "GET";
        body = undefined;
      }
      if (new URL(target).origin !== next.origin) {
        // Never carry credentials across an origin we did not start with.
        headers = stripAuthHeaders(headers);
      }
      target = next.toString();
    }
  }

  private async fetchOnce(rawUrl: string, init: EgressRequestInit): Promise<EgressResponse> {
    const method = (init.method ?? "GET").toUpperCase();
    const verdict = this.check(rawUrl, method);
    if (!verdict.ok) {
      throw new EgressDenied(verdict.reason ?? "egress refused", verdict.code ?? "refused");
    }
    const url = new URL(rawUrl);

    const addresses = await this.resolveVerified(url.hostname.replace(/^\[|\]$/g, ""));
    const dispatcher = this.agentFor(addresses);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error("egress timeout")), this.config.timeout_ms);
    if (init.signal) {
      init.signal.addEventListener("abort", () => controller.abort(init.signal!.reason), { once: true });
    }

    try {
      const response = await undiciRequest(url, {
        method: method as never,
        headers: init.headers,
        body: init.body as never,
        dispatcher,
        signal: controller.signal
      });

      const chunks: Buffer[] = [];
      let bytes = 0;
      let overflow = false;
      for await (const chunk of response.body) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as ArrayBufferLike);
        bytes += buf.length;
        if (bytes > this.config.max_body_bytes) {
          overflow = true;
          controller.abort(new Error("response body limit exceeded"));
          break;
        }
        chunks.push(buf);
      }
      if (overflow) {
        throw new EgressDenied(
          `response body exceeded egress.max_body_bytes (${this.config.max_body_bytes}); the request was aborted`,
          "response-too-large"
        );
      }

      return {
        status: response.statusCode,
        headers: response.headers as Record<string, string | string[] | undefined>,
        body: Buffer.concat(chunks),
        bytes,
        url: url.toString(),
        truncated: false
      };
    } catch (err) {
      if (err instanceof EgressDenied) throw err;
      const message = (err as Error).message ?? String(err);
      if (controller.signal.aborted) {
        throw new EgressDenied(`request to ${url.host} aborted: ${message}`, "aborted");
      }
      throw new EgressDenied(`request to ${url.host} failed: ${message}`, "network");
    } finally {
      clearTimeout(timer);
    }
  }

  async close(): Promise<void> {
    const agents = [...this.agentCache.values(), ...this.streamingAgentCache.values()];
    await Promise.all(agents.map((a) => a.close().catch(() => undefined)));
    this.agentCache.clear();
    this.streamingAgentCache.clear();
  }
}

function headerValue(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== wanted) continue;
    return Array.isArray(value) ? value[0] : value;
  }
  return undefined;
}

const AUTH_HEADERS = new Set(["authorization", "cookie", "proxy-authorization", "x-api-key", "api-key"]);

function stripAuthHeaders(headers: Record<string, string> | undefined): Record<string, string> | undefined {
  if (!headers) return headers;
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!AUTH_HEADERS.has(key.toLowerCase())) out[key] = value;
  }
  return out;
}
