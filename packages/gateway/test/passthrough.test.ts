import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { parsePolicy } from "@hmcp/core";
import { Gateway } from "../src/gateway.js";
import { GatewayConfigSchema } from "../src/config.js";
import { serveHttp, type ServingHttp } from "../src/serve-http.js";
import { startMockHttpUpstream, type MockHttpUpstream } from "./fixtures/mock-http-upstream.js";

/**
 * Relaying the caller's own credential to the upstream.
 *
 * The claim being tested is that the gateway never holds a customer's secret
 * and never sends one to the wrong place: each caller's token reaches the
 * upstream on their own calls, no token at all reaches it during startup
 * discovery, and nothing else the caller sent is relayed.
 *
 * The upstream here is a real MCP server over HTTP that records what arrived
 * on the wire, because the only way to check a pass-through is to look at the
 * headers rather than to take the gateway's word for it. It is also the first
 * test in this repo to exercise an `http` upstream at all.
 */

const ISSUER = "https://issuer.test";
const AUDIENCE = "hmcp-gateway";

let dir: string;
let upstream: MockHttpUpstream;
let jwks: HttpServer;
let jwksUrl: string;
let signing: { publicKey: CryptoKey; privateKey: CryptoKey };
let serving: ServingHttp | undefined;
let gateway: Gateway | undefined;
const clients: Client[] = [];

function policy(tenant: boolean): ReturnType<typeof parsePolicy> {
  return parsePolicy({
    version: 1,
    defaults: { mode: "read-only" },
    rules: [{ id: "reads", match: "notes__get_*", effect: "read", decision: "allow" }],
    ...(tenant
      ? {
          tenant: {
            field: "org_id",
            source: {
              kind: "jwt-verified",
              claim: "org_id",
              jwks_uri: jwksUrl,
              issuer: ISSUER,
              audience: AUDIENCE
            },
            inject: []
          }
        }
      : {}),
    approvals: { mode: "cli", store_path: join(dir, "approvals.sqlite") },
    audit: { path: join(dir, "audit.jsonl") },
    egress: {
      allow: ["127.0.0.1"],
      methods: ["GET", "POST", "DELETE"],
      block_private_ips: false,
      allow_http: true,
      allow_ip_literals: true
    }
  });
}

async function boot(options: { tenant?: boolean; passthrough?: Record<string, unknown> } = {}): Promise<void> {
  gateway = new Gateway({
    config: GatewayConfigSchema.parse({
      version: 1,
      name: "test-gateway",
      policy: { version: 1 },
      upstreams: [
        {
          name: "notes",
          transport: "http",
          url: upstream.url,
          headers: { "x-static": "from-config" },
          credential_passthrough: { enabled: true, ...options.passthrough }
        }
      ]
    }),
    policy: policy(options.tenant ?? true),
    cwd: dir
  });
  await gateway.connectUpstreams();
  serving = await serveHttp(gateway, { port: 0 });
}

async function token(org: string): Promise<string> {
  return new SignJWT({ org_id: org })
    .setProtectedHeader({ alg: "ES256", kid: "k1" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(signing.privateKey as never);
}

async function connect(headers: Record<string, string>): Promise<Client> {
  const client = new Client({ name: "agent", version: "1.0.0" }, { capabilities: {} });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${serving!.port}/mcp`), {
      requestInit: { headers }
    })
  );
  clients.push(client);
  return client;
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-pass-"));
  upstream = await startMockHttpUpstream();
  signing = await generateKeyPair("ES256", { extractable: true });
  const jwk = { ...(await exportJWK(signing.publicKey)), kid: "k1", alg: "ES256", use: "sig" };
  jwks = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise<void>((r) => jwks.listen(0, "127.0.0.1", r));
  jwksUrl = `http://127.0.0.1:${(jwks.address() as AddressInfo).port}/jwks.json`;
});

afterEach(async () => {
  for (const c of clients.splice(0)) await c.close().catch(() => undefined);
  if (serving) await serving.close();
  if (gateway) await gateway.close();
  serving = undefined;
  gateway = undefined;
  await upstream.close();
  await new Promise<void>((r) => jwks.close(() => r()));
  rmSync(dir, { recursive: true, force: true });
});

describe("what reaches the upstream", () => {
  it("carries no caller credential during connect and tool discovery", async () => {
    // Startup happens before any caller exists. If a token could reach here,
    // the first customer to connect would have lent theirs to the gateway's
    // own bookkeeping.
    await boot();
    expect(upstream.auth.length).toBeGreaterThan(0);
    expect(upstream.auth.every((a) => a === undefined)).toBe(true);
    // The configured static headers still go, which is the behaviour an
    // upstream set up before pass-through existed depends on.
    expect(upstream.seen.every((h) => h["x-static"] === "from-config")).toBe(true);
  });

  it("sends each caller's own token on their own calls", async () => {
    await boot();
    const acmeToken = await token("acme");
    const globexToken = await token("globex");

    const before = upstream.auth.length;
    const acme = await connect({ authorization: `Bearer ${acmeToken}` });
    await acme.callTool({ name: "notes__get_note", arguments: { id: "n1" } });
    const globex = await connect({ authorization: `Bearer ${globexToken}` });
    await globex.callTool({ name: "notes__get_note", arguments: { id: "n2" } });

    const relayed = upstream.auth.slice(before).filter((a): a is string => a !== undefined);
    expect(relayed).toContain(`Bearer ${acmeToken}`);
    expect(relayed).toContain(`Bearer ${globexToken}`);
    // Two distinct credentials over one shared upstream connection.
    expect(new Set(relayed).size).toBe(2);
  });

  it("relays nothing else the caller sent, not even a cookie", async () => {
    // A cookie forwarded to another origin is the textbook confused deputy.
    // Nothing copies the inbound headers onto the outbound request, so this
    // holds structurally rather than by a deny-list -- and this test is what
    // keeps it that way if someone later reaches for the inbound headers.
    await boot();
    const before = upstream.seen.length;
    const client = await connect({
      authorization: `Bearer ${await token("acme")}`,
      cookie: "session=supersecret"
    });
    await client.callTool({ name: "notes__get_note", arguments: { id: "n1" } });

    const after = upstream.seen.slice(before);
    expect(after.length).toBeGreaterThan(0);
    for (const headers of after) {
      expect(headers["cookie"]).toBeUndefined();
      // The configured headers do survive: an upstream set up before
      // pass-through existed keeps working.
      expect(headers["x-static"]).toBe("from-config");
    }
  });
});

describe("when the upstream will not take it", () => {
  it("says what is actually wrong instead of a generic failure", async () => {
    await boot();
    const client = await connect({ authorization: `Bearer ${await token("acme")}` });
    upstream.reject401 = true;

    const result = await client.callTool({ name: "notes__get_note", arguments: { id: "n1" } });
    expect((result as { isError?: boolean }).isError).toBe(true);
    const text = (result as { content: { text?: string }[] }).content.map((c) => c.text ?? "").join("");
    expect(text).toContain("rejected the passed-through credential");
    expect(text).toContain("per-tenant");
  });
});

describe("when the caller has no credential to pass", () => {
  it("refuses the call under required, rather than quietly using the static headers", async () => {
    // No tenant configuration, so the gateway does not authenticate and no
    // credential exists -- which is exactly the state `required` is about.
    await boot({ tenant: false, passthrough: { required: true } });
    const client = await connect({});
    const result = await client.callTool({ name: "notes__get_note", arguments: { id: "n1" } });

    expect((result as { isError?: boolean }).isError).toBe(true);
    const text = (result as { content: { text?: string }[] }).content.map((c) => c.text ?? "").join("");
    expect(text).toContain("requires the caller's credential");
    expect(text).toContain("arrived without one");
  });

  it("falls back to the configured headers when it is not required", async () => {
    await boot({ tenant: false });
    const client = await connect({});
    const before = upstream.auth.length;
    const result = await client.callTool({ name: "notes__get_note", arguments: { id: "n1" } });

    expect((result as { isError?: boolean }).isError).toBeFalsy();
    expect(upstream.auth.slice(before).every((a) => a === undefined)).toBe(true);
  });
});

describe("the limits policy.yaml promises actually apply", () => {
  it("refuses a redirect instead of following it somewhere unallowlisted", async () => {
    /*
     * The sharpest of the four. `max_redirects` defaults to 0, and the plain
     * global fetch the gateway used to call followed redirects silently --
     * so an allowlisted upstream could hand the connection, and the caller's
     * credential, to a host the allowlist never saw.
     */
    await boot();
    const client = await connect({ authorization: `Bearer ${await token("acme")}` });
    upstream.redirectTo = "http://169.254.169.254/latest/meta-data/";

    const result = await client.callTool({ name: "notes__get_note", arguments: { id: "n1" } });
    expect((result as { isError?: boolean }).isError).toBe(true);
    const text = (result as { content: { text?: string }[] }).content.map((c) => c.text ?? "").join("");
    expect(text).toContain("max_redirects");
  });

  it("still refuses a redirect to a host that is merely not allowlisted", async () => {
    await boot();
    const client = await connect({ authorization: `Bearer ${await token("acme")}` });
    upstream.redirectTo = "http://example.com/elsewhere";

    const result = await client.callTool({ name: "notes__get_note", arguments: { id: "n1" } });
    expect((result as { isError?: boolean }).isError).toBe(true);
  });
});
