import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, request, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { SignJWT, exportJWK, generateKeyPair, type JWK, type CryptoKey } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ApprovalStore, parsePolicy } from "@hmcp/core";
import { Gateway } from "../src/gateway.js";
import { GatewayConfigSchema } from "../src/config.js";
import { serveHttp, type ServingHttp } from "../src/serve-http.js";

/**
 * Deriving the tenant from the caller's token.
 *
 * This is the stage where the hosted design either holds or does not. Every
 * stored row -- the approval queue, standing grants, exposure switches -- is
 * filed under the tenant, so the tenant key is an access-control decision. If
 * it came from anywhere the caller can simply write, a caller could rename
 * itself into another customer's scope and redeem their approvals: the
 * upstream API would still refuse them the *data*, but the gateway's own
 * state would be wide open, and the gateway would be the vulnerability.
 *
 * So the token's signature, issuer, audience and expiry are all checked, the
 * algorithm is pinned rather than read from the token, and the JWKS is
 * fetched through the same egress guard as any other outbound request.
 */

const UPSTREAM = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "mock-upstream.mjs");
const ISSUER = "https://issuer.test";
const AUDIENCE = "hmcp-gateway";

let dir: string;
let jwks: HttpServer;
let jwksUrl: string;
let signing: { publicKey: CryptoKey; privateKey: CryptoKey };
let otherKey: { publicKey: CryptoKey; privateKey: CryptoKey };
let hsSecret: Uint8Array;
let serving: ServingHttp | undefined;
let gateway: Gateway | undefined;
const clients: Client[] = [];

async function publish(keys: { kid: string; key: CryptoKey }[]): Promise<void> {
  const entries: JWK[] = [];
  for (const { kid, key } of keys) entries.push({ ...(await exportJWK(key)), kid, alg: "ES256", use: "sig" });
  jwks = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ keys: entries }));
  });
  await new Promise<void>((r) => jwks.listen(0, "127.0.0.1", r));
  jwksUrl = `http://127.0.0.1:${(jwks.address() as AddressInfo).port}/jwks.json`;
}

function policy(overrides: Record<string, unknown> = {}) {
  return parsePolicy({
    version: 1,
    defaults: { mode: "read-only" },
    rules: [{ id: "reads", match: "notes__get_*", effect: "read", decision: "allow" }],
    tenant: {
      field: "org_id",
      source: { kind: "jwt-verified", claim: "org_id", jwks_uri: jwksUrl, issuer: ISSUER, audience: AUDIENCE },
      inject: []
    },
    approvals: { mode: "cli", store_path: join(dir, "approvals.sqlite") },
    audit: { path: join(dir, "audit.jsonl") },
    // The JWKS is a loopback address, which the egress guard refuses unless
    // it is allowed like any other upstream.
    egress: { allow: ["127.0.0.1"], block_private_ips: false, allow_http: true, allow_ip_literals: true },
    ...overrides
  });
}

async function boot(policyOverrides: Record<string, unknown> = {}): Promise<ServingHttp> {
  gateway = new Gateway({
    config: GatewayConfigSchema.parse({
      version: 1,
      name: "test-gateway",
      policy: { version: 1 },
      upstreams: [{ name: "notes", transport: "stdio", command: process.execPath, args: [UPSTREAM] }]
    }),
    policy: policy(policyOverrides),
    cwd: dir
  });
  await gateway.connectUpstreams();
  serving = await serveHttp(gateway, { port: 0 });
  return serving;
}

async function token(
  claims: Record<string, unknown>,
  options: { key?: CryptoKey; kid?: string; alg?: string; expired?: boolean; audience?: string } = {}
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: options.alg ?? "ES256", kid: options.kid ?? "k1" })
    .setIssuer(ISSUER)
    .setAudience(options.audience ?? AUDIENCE)
    .setIssuedAt(options.expired ? now - 7200 : now)
    .setExpirationTime(options.expired ? now - 3600 : now + 3600)
    .sign((options.key ?? signing.privateKey) as never);
}

async function connect(bearer: string): Promise<Client> {
  const client = new Client({ name: "agent", version: "1.0.0" }, { capabilities: {} });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${serving!.port}/mcp`), {
      requestInit: { headers: { authorization: `Bearer ${bearer}` } }
    })
  );
  clients.push(client);
  return client;
}

/** Raw initialize, for the refusals a client transport would hide. */
function raw(headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port: serving!.port,
        path: "/mcp",
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }
      },
      (res) => {
        let out = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (out += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: out }));
      }
    );
    req.on("error", reject);
    req.end(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "raw", version: "1" } }
      })
    );
  });
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-tenant-"));
  signing = await generateKeyPair("ES256", { extractable: true });
  otherKey = await generateKeyPair("ES256", { extractable: true });
  hsSecret = new Uint8Array(32).fill(7);
  // Only the first key is published, so a token signed with the second has a
  // kid the gateway cannot resolve.
  await publish([{ kid: "k1", key: signing.publicKey }]);
});

afterEach(async () => {
  for (const c of clients.splice(0)) await c.close().catch(() => undefined);
  if (serving) await serving.close();
  if (gateway) await gateway.close();
  serving = undefined;
  gateway = undefined;
  await new Promise<void>((r) => jwks.close(() => r()));
  rmSync(dir, { recursive: true, force: true });
});

describe("a token the gateway accepts", () => {
  it("scopes the caller to the tenant its claim names", async () => {
    await boot();
    const client = await connect(await token({ org_id: "acme", sub: "user-1" }));
    await client.callTool({ name: "notes__get_note", arguments: { id: "n1" } });

    const { readAuditLog } = await import("@hmcp/core");
    const call = readAuditLog(join(dir, "audit.jsonl")).find((r) => r.tool === "notes__get_note");
    expect(call?.tenant).toBe("acme");
  });

  it("keeps two customers' stored state apart", async () => {
    await boot();
    const acme = await connect(await token({ org_id: "acme" }));
    const globex = await connect(await token({ org_id: "globex" }));
    await acme.callTool({ name: "notes__get_note", arguments: { id: "n1" } });
    await globex.callTool({ name: "notes__get_note", arguments: { id: "n2" } });

    // One process, one database, one component -- and two scopes in it.
    const db = new ApprovalStore(join(dir, "approvals.sqlite"));
    db.scoped({ component: "gateway:test-gateway", tenant: "acme" }).disableTool("notes__get_note", "alice");
    expect(
      db.scoped({ component: "gateway:test-gateway", tenant: "globex" }).toolExposure("notes__get_note")
    ).toBeUndefined();
    db.close();

    // And the switch acme made actually takes effect for acme only.
    const refused = await acme.callTool({ name: "notes__get_note", arguments: { id: "n1" } });
    expect((refused as { isError?: boolean }).isError).toBe(true);
    const allowed = await globex.callTool({ name: "notes__get_note", arguments: { id: "n2" } });
    expect((allowed as { isError?: boolean }).isError).toBeFalsy();
  });
});

describe("a token the gateway must refuse", () => {
  it("refuses a request with no token at all", async () => {
    await boot();
    const res = await raw({});
    expect(res.status).toBe(401);
    expect(res.body).toContain("requires a bearer token");
  });

  it("refuses the wrong algorithm, rather than trusting the token's own header", async () => {
    // The classic failure: reading `alg` from the token and believing it.
    await boot();
    const hs = await new SignJWT({ org_id: "acme" })
      .setProtectedHeader({ alg: "HS256", kid: "k1" })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(hsSecret);
    const res = await raw({ authorization: `Bearer ${hs}` });
    expect(res.status).toBe(403);
  });

  it("refuses the wrong audience", async () => {
    await boot();
    const res = await raw({ authorization: `Bearer ${await token({ org_id: "acme" }, { audience: "someone-else" })}` });
    expect(res.status).toBe(403);
    expect(res.body).toContain("aud");
  });

  it("refuses an expired token", async () => {
    await boot();
    const res = await raw({ authorization: `Bearer ${await token({ org_id: "acme" }, { expired: true })}` });
    expect(res.status).toBe(403);
    expect(res.body).toContain("expired");
  });

  it("refuses a signature it cannot resolve a key for", async () => {
    await boot();
    const forged = await token({ org_id: "acme" }, { key: otherKey.privateKey, kid: "k-unknown" });
    const res = await raw({ authorization: `Bearer ${forged}` });
    expect(res.status).toBe(403);
  });

  it("refuses a valid token that carries no tenant claim", async () => {
    await boot();
    const res = await raw({ authorization: `Bearer ${await token({ sub: "user-1" })}` });
    expect(res.status).toBe(403);
    expect(res.body).toContain("no tenant");
  });
});

describe("the JWKS url is an outbound request like any other", () => {
  it("is refused when it points somewhere egress does not allow", async () => {
    // A key-set URL is still a URL this process will dial. Cloud metadata
    // endpoints are the reason this matters.
    await boot({
      tenant: {
        field: "org_id",
        source: {
          kind: "jwt-verified",
          claim: "org_id",
          jwks_uri: "http://169.254.169.254/latest/meta-data/jwks.json",
          issuer: ISSUER,
          audience: AUDIENCE
        },
        inject: []
      }
    });
    const res = await raw({ authorization: `Bearer ${await token({ org_id: "acme" })}` });
    expect(res.status).toBe(403);
    expect(res.body).toContain("key set could not be fetched");
  });
});

describe("refusing to start at all", () => {
  it("will not serve HTTP with a tenant source that resolves once per process", async () => {
    // Coming up and quietly putting every customer in one bucket is worse
    // than not coming up.
    gateway = new Gateway({
      config: GatewayConfigSchema.parse({
        version: 1,
        name: "test-gateway",
        policy: { version: 1 },
        upstreams: [{ name: "notes", transport: "stdio", command: process.execPath, args: [UPSTREAM] }]
      }),
      policy: parsePolicy({
        version: 1,
        tenant: { field: "org_id", source: { kind: "static", value: "acme" }, inject: [] },
        approvals: { store_path: join(dir, "approvals.sqlite") },
        audit: { path: join(dir, "audit.jsonl") }
      }),
      cwd: dir
    });
    await expect(serveHttp(gateway, { port: 0 })).rejects.toThrow(/jwt-verified/);
  });
});
