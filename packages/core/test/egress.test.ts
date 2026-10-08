import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";
import { classifyAddress, EgressDenied, EgressGuard, parsePolicy } from "../src/index.js";

function guard(overrides: Record<string, unknown> = {}) {
  const policy = parsePolicy({ version: 1, egress: { allow: ["api.example.com"], ...overrides } });
  return new EgressGuard(policy.egress);
}

describe("address classification", () => {
  it("blocks loopback, link-local metadata, and private space", () => {
    for (const ip of ["127.0.0.1", "127.1.2.3", "0.0.0.0", "169.254.169.254", "10.1.2.3", "192.168.0.1", "172.20.1.1", "100.64.0.1"]) {
      expect(classifyAddress(ip).blocked, ip).toBe(true);
    }
  });

  it("blocks the IPv6 equivalents, including mapped and NAT64 forms of a private v4 address", () => {
    for (const ip of ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::169.254.169.254", "2001:db8::1"]) {
      expect(classifyAddress(ip).blocked, ip).toBe(true);
    }
  });

  it("allows ordinary public addresses", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"]) {
      expect(classifyAddress(ip).blocked, ip).toBe(false);
    }
  });

  it("explains why, so a denial is actionable", () => {
    expect(classifyAddress("169.254.169.254").reason).toMatch(/link-local \/ cloud metadata/);
  });

  it("treats an unparseable address as blocked rather than allowed", () => {
    expect(classifyAddress("not-an-ip").blocked).toBe(true);
    expect(classifyAddress("999.1.1.1").blocked).toBe(true);
  });
});

describe("pre-flight checks", () => {
  it("refuses a host that is not on the allowlist", () => {
    const check = guard().check("https://evil.example.org/data");
    expect(check.ok).toBe(false);
    expect(check.code).toBe("host");
    expect(check.reason).toMatch(/not in egress.allow/);
  });

  it("allows an exact allowlist match", () => {
    expect(guard().check("https://api.example.com/pets").ok).toBe(true);
  });

  it("supports a wildcard subdomain without matching the bare domain or a lookalike", () => {
    const g = guard({ allow: ["*.example.com"] });
    expect(g.check("https://api.example.com/x").ok).toBe(true);
    expect(g.check("https://a.b.example.com/x").ok).toBe(true);
    expect(g.check("https://example.com/x").ok).toBe(false);
    expect(g.check("https://notexample.com/x").ok).toBe(false);
    expect(g.check("https://api.example.com.evil.org/x").ok).toBe(false);
  });

  it("honors a port in an allowlist entry", () => {
    const g = guard({ allow: ["api.example.com:8443"] });
    expect(g.check("https://api.example.com:8443/x").ok).toBe(true);
    expect(g.check("https://api.example.com/x").ok).toBe(false);
  });

  it("refuses plaintext http unless explicitly permitted", () => {
    expect(guard().check("http://api.example.com/x").code).toBe("plaintext");
    expect(guard({ allow_http: true }).check("http://api.example.com/x").ok).toBe(true);
  });

  it("refuses non-http schemes, including file and gopher", () => {
    for (const url of ["file:///etc/passwd", "gopher://api.example.com/", "ftp://api.example.com/"]) {
      expect(guard().check(url).code, url).toBe("scheme");
    }
  });

  it("refuses credentials embedded in the URL", () => {
    expect(guard().check("https://user:pass@api.example.com/x").code).toBe("url-credentials");
  });

  it("refuses a method outside egress.methods", () => {
    const check = guard().check("https://api.example.com/x", "DELETE");
    expect(check.code).toBe("method");
    expect(guard({ methods: ["GET", "DELETE"] }).check("https://api.example.com/x", "DELETE").ok).toBe(true);
  });

  it("refuses a bare IP target unless explicitly permitted", () => {
    expect(guard({ allow: ["8.8.8.8"] }).check("https://8.8.8.8/x").code).toBe("ip-literal");
    expect(guard({ allow: ["8.8.8.8"], allow_ip_literals: true }).check("https://8.8.8.8/x").ok).toBe(true);
  });

  it("still blocks a private IP literal that someone put on the allowlist", () => {
    const g = guard({ allow: ["127.0.0.1", "169.254.169.254"], allow_ip_literals: true });
    expect(g.check("https://127.0.0.1/x").code).toBe("private-address");
    expect(g.check("https://169.254.169.254/latest/meta-data/").code).toBe("private-address");
  });

  it("permits nothing when the allowlist is empty", () => {
    const check = guard({ allow: [] }).check("https://api.example.com/x");
    expect(check.ok).toBe(false);
    expect(check.code).toBe("no-allowlist");
  });

  it("refuses an unparseable URL", () => {
    expect(guard().check("not a url").code).toBe("invalid-url");
  });
});

describe("DNS verification", () => {
  it("refuses a hostname that resolves into private space", async () => {
    // localhost resolves to loopback, so it stands in for any public name
    // whose A record points inside the network.
    const g = guard({ allow: ["localhost"], allow_http: true });
    await expect(g.resolveVerified("localhost")).rejects.toThrow(EgressDenied);
    await expect(g.resolveVerified("localhost")).rejects.toThrow(/resolves to .*loopback/);
  });

  it("refuses a hostname that does not resolve at all", async () => {
    const g = guard({ allow: ["*.invalid"] });
    await expect(g.resolveVerified("nonexistent-host-for-hmcp-tests.invalid")).rejects.toThrow(/DNS lookup/);
  });

  it("can be told not to block private space, for a deliberately internal deployment", async () => {
    const g = guard({ allow: ["localhost"], block_private_ips: false });
    await expect(g.resolveVerified("localhost")).resolves.toBeInstanceOf(Array);
  });
});

describe("live requests", () => {
  let server: Server;
  let port: number;

  beforeAll(async () => {
    server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (url.pathname === "/big") {
        res.writeHead(200, { "content-type": "application/octet-stream" });
        // Stream more than any configured cap without buffering it all.
        let sent = 0;
        const chunk = Buffer.alloc(64 * 1024, 0x41);
        const push = () => {
          while (sent < 8 * 1024 * 1024) {
            sent += chunk.length;
            if (!res.write(chunk)) {
              res.once("drain", push);
              return;
            }
          }
          res.end();
        };
        push();
        return;
      }
      if (url.pathname === "/redirect") {
        res.writeHead(302, { location: "http://127.0.0.1:1/internal" });
        res.end();
        return;
      }
      if (url.pathname === "/slow") {
        setTimeout(() => {
          res.writeHead(200).end("late");
        }, 3000);
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, path: url.pathname, method: req.method }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  /** A guard that can actually reach the loopback test server. */
  function localGuard(overrides: Record<string, unknown> = {}) {
    return guard({
      allow: [`127.0.0.1:${port}`],
      allow_http: true,
      allow_ip_literals: true,
      block_private_ips: false,
      methods: ["GET", "POST"],
      ...overrides
    });
  }

  it("performs an allowed request", async () => {
    const response = await localGuard().fetch(`http://127.0.0.1:${port}/pets`);
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body.toString())).toMatchObject({ ok: true, path: "/pets" });
    expect(response.bytes).toBeGreaterThan(0);
  });

  it("aborts a response that exceeds the body cap instead of buffering it", async () => {
    const g = localGuard({ max_body_bytes: 128 * 1024 });
    await expect(g.fetch(`http://127.0.0.1:${port}/big`)).rejects.toThrow(/exceeded egress.max_body_bytes/);
  });

  it("refuses a redirect when max_redirects is zero", async () => {
    const g = localGuard();
    await expect(g.fetch(`http://127.0.0.1:${port}/redirect`)).rejects.toThrow(/max_redirects is 0/);
  });

  it("re-checks the redirect target against the allowlist rather than following it blindly", async () => {
    // The hop points at 127.0.0.1:1, which is not the allowlisted host:port.
    const g = localGuard({ max_redirects: 3 });
    await expect(g.fetch(`http://127.0.0.1:${port}/redirect`)).rejects.toThrow(/not in egress.allow/);
  });

  it("times out a slow upstream", async () => {
    const g = localGuard({ timeout_ms: 300 });
    await expect(g.fetch(`http://127.0.0.1:${port}/slow`)).rejects.toThrow(EgressDenied);
  });

  it("refuses an oversized request body before sending it", async () => {
    const g = localGuard({ max_request_body_bytes: 16 });
    await expect(
      g.fetch(`http://127.0.0.1:${port}/pets`, { method: "POST", body: "x".repeat(100) })
    ).rejects.toThrow(/exceeds egress.max_request_body_bytes/);
  });

  it("refuses the request when the method is not permitted, without opening a socket", async () => {
    const g = localGuard({ methods: ["GET"] });
    await expect(g.fetch(`http://127.0.0.1:${port}/pets`, { method: "POST" })).rejects.toThrow(
      /not in egress.methods/
    );
  });
});
