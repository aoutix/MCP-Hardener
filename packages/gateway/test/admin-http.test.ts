import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, request, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { parsePolicy, readAuditLog, verifyAuditLog } from "@hmcp/core";
import { Gateway } from "../src/gateway.js";
import { GatewayConfigSchema } from "../src/config.js";
import { serveHttp, type ServingHttp } from "../src/serve-http.js";

/**
 * The switch a customer actually reaches.
 *
 * The gateway has honoured exposure overrides for a while, but nothing could
 * create one: the console cannot name a gateway's tools without connecting
 * its upstreams, and that left the control enforced and unreachable. This is
 * the surface that closes it — and the design question it answers is not
 * "how do we write a row" but "who may".
 */

const UPSTREAM = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "mock-upstream.mjs");
const ISSUER = "https://issuer.test";
const AUDIENCE = "hmcp-gateway";
const ADMIN_SCOPE = "hmcp:admin";

let dir: string;
let jwks: HttpServer;
let jwksUrl: string;
let signing: { publicKey: CryptoKey; privateKey: CryptoKey };
let serving: ServingHttp | undefined;
let gateway: Gateway | undefined;
const clients: Client[] = [];

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
    admin: { scope: ADMIN_SCOPE },
    approvals: { mode: "cli", store_path: join(dir, "approvals.sqlite") },
    audit: { path: join(dir, "audit.jsonl") },
    egress: { allow: ["127.0.0.1"], block_private_ips: false, allow_http: true, allow_ip_literals: true },
    ...overrides
  });
}

async function boot(policyOverrides: Record<string, unknown> = {}): Promise<void> {
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
}

async function token(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", kid: "k1" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(signing.privateKey as never);
}

const agentToken = (org: string, sub = "agent-1") => token({ org_id: org, sub });
const adminToken = (org: string, scope: unknown = ADMIN_SCOPE, key = "scope") =>
  token({ org_id: org, sub: "alice", [key]: scope });

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

function call(
  path: string,
  options: { method?: string; bearer?: string; body?: unknown; host?: string } = {}
): Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }> {
  const payload = options.body === undefined ? undefined : JSON.stringify(options.body);
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port: serving!.port,
        path,
        method: options.method ?? "GET",
        headers: {
          ...(options.host ? { host: options.host } : {}),
          ...(options.bearer ? { authorization: `Bearer ${options.bearer}` } : {}),
          ...(payload ? { "content-type": "application/json" } : {})
        }
      },
      (res) => {
        let out = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (out += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: out, headers: res.headers }));
      }
    );
    req.on("error", reject);
    req.end(payload);
  });
}

const audit = () => readAuditLog(join(dir, "audit.jsonl"));

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-admin-"));
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
  await new Promise<void>((r) => jwks.close(() => r()));
  rmSync(dir, { recursive: true, force: true });
});

describe("the switch, end to end", () => {
  it("takes a tool away from the tenant who switched it off, and nobody else", async () => {
    // The test this whole stage exists for.
    await boot();
    const acme = await connect(await agentToken("acme"));
    const globex = await connect(await agentToken("globex"));

    expect((await acme.listTools()).tools.map((t) => t.name)).toContain("notes__get_note");

    const flip = await call("/admin/v1/exposure/notes__get_note", {
      method: "PUT",
      bearer: await adminToken("acme"),
      body: { disabled: true, reason: "incident 412" }
    });
    expect(flip.status).toBe(200);
    expect(JSON.parse(flip.body).changed).toBe(true);

    // Acme's agent can no longer see it, and a call is refused with the reason.
    expect((await acme.listTools()).tools.map((t) => t.name)).not.toContain("notes__get_note");
    const refused = await acme.callTool({ name: "notes__get_note", arguments: { id: "n1" } });
    expect((refused as { isError?: boolean }).isError).toBe(true);
    expect((refused as { content: { text?: string }[] }).content.map((c) => c.text).join("")).toContain("incident 412");

    // Globex is untouched.
    expect((await globex.listTools()).tools.map((t) => t.name)).toContain("notes__get_note");
    const allowed = await globex.callTool({ name: "notes__get_note", arguments: { id: "n2" } });
    expect((allowed as { isError?: boolean }).isError).toBeFalsy();
  });

  it("hands the tool back to policy when switched on again", async () => {
    await boot();
    const bearer = await adminToken("acme");
    await call("/admin/v1/exposure/notes__get_note", { method: "PUT", bearer, body: { disabled: true } });

    const on = await call("/admin/v1/exposure/notes__get_note", { method: "PUT", bearer, body: { disabled: false } });
    expect(JSON.parse(on.body)).toMatchObject({ changed: true, exposure: null });

    // A second enable changed nothing, so it records nothing: a log entry
    // there would describe a permission change that did not happen.
    const before = audit().filter((r) => r.rule_id === "exposure.enable").length;
    const again = await call("/admin/v1/exposure/notes__get_note", { method: "PUT", bearer, body: { disabled: false } });
    expect(JSON.parse(again.body).changed).toBe(false);
    expect(audit().filter((r) => r.rule_id === "exposure.enable")).toHaveLength(before);
  });

  it("records who flipped it, for which customer", async () => {
    await boot();
    await call("/admin/v1/exposure/notes__get_note", {
      method: "PUT",
      bearer: await adminToken("acme"),
      body: { disabled: true, reason: "incident 412" }
    });
    const record = audit().find((r) => r.rule_id === "exposure.disable");
    expect(record).toMatchObject({ actor: "token:alice", tenant: "acme", component: "gateway:test-gateway" });
    expect(record?.reason).toContain("the admin API");
    expect(record?.session.startsWith("admin:")).toBe(true);
    expect(verifyAuditLog(join(dir, "audit.jsonl")).ok).toBe(true);
  });

  it("lists the surface so a tenant can find the tool names", async () => {
    // The console cannot do this; the gateway is the only process that
    // connected the upstreams and therefore knows its own surface.
    await boot();
    const bearer = await adminToken("acme");
    await call("/admin/v1/exposure/notes__get_note", { method: "PUT", bearer, body: { disabled: true } });

    const listed = JSON.parse((await call("/admin/v1/tools", { bearer })).body);
    expect(listed.tenant).toBe("acme");
    const entry = listed.tools.find((t: { name: string }) => t.name === "notes__get_note");
    expect(entry).toMatchObject({ upstream: "notes", effect: "read" });
    expect(entry.disabled).toMatchObject({ setBy: "token:alice" });

    const only = JSON.parse((await call("/admin/v1/exposure", { bearer })).body);
    expect(only.disabled.map((d: { tool: string }) => d.tool)).toEqual(["notes__get_note"]);
  });
});

describe("who may flip it", () => {
  it("refuses a token with no admin scope, and says so in the log", async () => {
    await boot();
    const res = await call("/admin/v1/exposure/notes__get_note", {
      method: "PUT",
      bearer: await agentToken("acme"),
      body: { disabled: true }
    });
    expect(res.status).toBe(403);

    const denied = audit().find((r) => r.rule_id === "admin.denied");
    expect(denied).toMatchObject({ tenant: "acme", actor: "token:agent-1", decision: "deny" });
    // And nothing was written.
    expect(audit().some((r) => r.rule_id === "exposure.disable")).toBe(false);
  });

  it("does not accept a scope that merely contains the required one", async () => {
    // The classic substring bug: "hmcp:admin-readonly" is not "hmcp:admin".
    await boot();
    const res = await call("/admin/v1/exposure/notes__get_note", {
      method: "PUT",
      bearer: await adminToken("acme", "hmcp:admin-readonly"),
      body: { disabled: true }
    });
    expect(res.status).toBe(403);
  });

  it("accepts the array spelling of scopes", async () => {
    await boot();
    const res = await call("/admin/v1/exposure/notes__get_note", {
      method: "PUT",
      bearer: await adminToken("acme", ["other", ADMIN_SCOPE], "scp"),
      body: { disabled: true }
    });
    expect(res.status).toBe(200);
  });

  it("refuses an admin token on the agent surface, so one token cannot do both", async () => {
    // Otherwise an agent holding a token that administers the gateway could
    // clear its own kill switch -- the one thing the switch exists to stop.
    await boot();
    const res = await call("/mcp", { method: "POST", bearer: await adminToken("acme") });
    expect(res.status).toBe(403);
    expect(res.body).toContain("administration happens on /admin/v1");
  });

  it("requires a token at all", async () => {
    await boot();
    const res = await call("/admin/v1/tools");
    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toContain("Bearer");
  });
});

describe("when there is no admin block", () => {
  it("does not admit the surface exists", async () => {
    await boot({ admin: undefined });
    const res = await call("/admin/v1/tools", { bearer: await adminToken("acme") });
    // 404, not 403: a 403 would confirm the feature is here.
    expect(res.status).toBe(404);
    expect(res.body).toContain("the MCP endpoint is at /mcp");
  });

  it("refuses to start when it could not tell an admin from anyone else", async () => {
    gateway = new Gateway({
      config: GatewayConfigSchema.parse({
        version: 1,
        name: "test-gateway",
        policy: { version: 1 },
        upstreams: [{ name: "notes", transport: "stdio", command: process.execPath, args: [UPSTREAM] }]
      }),
      policy: parsePolicy({
        version: 1,
        admin: { scope: ADMIN_SCOPE },
        approvals: { store_path: join(dir, "approvals.sqlite") },
        audit: { path: join(dir, "audit.jsonl") }
      }),
      cwd: dir
    });
    await expect(serveHttp(gateway, { port: 0 })).rejects.toThrow(/no way to tell an administrator/);
  });
});

describe("the shape of the surface", () => {
  it("refuses a tool this gateway does not expose, without writing a row", async () => {
    await boot();
    const bearer = await adminToken("acme");
    const res = await call("/admin/v1/exposure/notes__nope", { method: "PUT", bearer, body: { disabled: true } });
    expect(res.status).toBe(404);
    expect(JSON.parse((await call("/admin/v1/exposure", { bearer })).body).disabled).toEqual([]);
  });

  it("rejects a body with no disabled flag", async () => {
    await boot();
    const res = await call("/admin/v1/exposure/notes__get_note", {
      method: "PUT",
      bearer: await adminToken("acme"),
      body: { reason: "oops" }
    });
    expect(res.status).toBe(422);
  });

  it("answers the wrong method with 405 and an Allow header", async () => {
    await boot();
    const res = await call("/admin/v1/exposure/notes__get_note", { bearer: await adminToken("acme") });
    expect(res.status).toBe(405);
    expect(res.headers["allow"]).toBe("PUT");
  });

  it("checks the Host before it checks the token", async () => {
    // DNS rebinding against a loopback-bound gateway is exactly how a web
    // page would try to reach an admin surface.
    await boot();
    const res = await call("/admin/v1/tools", { host: "evil.example.com" });
    expect(res.status).toBe(403);
    expect(res.body).toContain("does not answer to host");
    expect(res.body).not.toContain("Bearer");
  });
});
