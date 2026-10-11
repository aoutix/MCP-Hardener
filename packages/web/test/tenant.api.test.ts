import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { ApprovalStore } from "@hmcp/core";
import { buildRoutes } from "../src/api.js";
import { createConsoleServer } from "../src/http.js";
import { closeStores } from "../src/model/server.js";
import { publishSurface, tool, writeGatewayFixture, type GatewayFixture } from "./fixtures/gateway.js";

/**
 * Which tenant the console speaks for.
 *
 * This is the console's most dangerous input. Approvals, grants and the
 * exposure switch are keyed `(component, tenant)`, and a hosted gateway
 * resolves the tenant per request from the caller's token. The console resolves
 * from its *own* environment, which for a `jwt-verified` gateway is nothing at
 * all — so it used to read an empty queue and, far worse, write a kill switch
 * into `tenant = ""` that the gateway would never read. A switch in the wrong
 * tenant looks exactly like protection and is none.
 *
 * `hmcp-gateway exposure` already refuses to guess here. These pin down that
 * the console refuses too, and that naming a tenant works.
 */

const TOKEN = "tenant-test-token-0123456789";
const SURFACE = [
  tool("get_note", { effect: "read" }),
  tool("create_note", { effect: "write", description: "Create a note." })
];

let dir: string;
let hosted: GatewayFixture;
let fixed: GatewayFixture;
let server: Server;
let port: number;
let cookies = "";
let csrf = "";

async function api(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`http://127.0.0.1:${port}${path}`, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      Cookie: cookies,
      Origin: `http://127.0.0.1:${port}`,
      ...(init.method && init.method !== "GET"
        ? { "Content-Type": "application/json", "X-HMCP-CSRF": csrf }
        : {})
    }
  });
}

const switchOff = (id: string, name: string, query = "") =>
  api(`/api/v1/servers/${id}/tools/${name}/exposure${query}`, {
    method: "PUT",
    body: JSON.stringify({ disabled: true, reason: "test" })
  });

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-tenant-"));

  /*
   * A hosted gateway: one process, many tenants, each resolved from the
   * verified claim of whatever token made the call. Nothing in the console's
   * environment names any of them.
   */
  hosted = writeGatewayFixture(join(dir, "hosted"), {
    id: "hosted",
    name: "hosted",
    rules: ["- id: allow-reads", '  match: "get_*"', "  effect: read", "  decision: allow"],
    tenant: [
      "tenant:",
      "  field: org_id",
      "  required: true",
      "  source:",
      "    kind: jwt-verified",
      "    claim: org",
      "    issuer: https://issuer.example.com",
      "    audience: hmcp",
      "    jwks_uri: https://issuer.example.com/jwks"
    ]
  });

  /* And a single-tenant one, whose tenant the console can legitimately read. */
  fixed = writeGatewayFixture(join(dir, "fixed"), {
    id: "fixed",
    name: "fixed",
    tenant: ["tenant:", "  field: org_id", "  source:", "    kind: static", "    value: org_fixed"]
  });

  const registryPath = join(dir, "servers.json");
  writeFileSync(registryPath, JSON.stringify({ version: 1, servers: [hosted.entry, fixed.entry] }));

  const make = (p: number) =>
    createConsoleServer({
      routes: buildRoutes({ registryPath }),
      token: TOKEN,
      uiDir: join(dir, "ui"),
      port: p,
      actor: "reviewer"
    });

  server = make(0);
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  port = (server.address() as AddressInfo).port;
  server.close();
  server = make(port);
  await new Promise<void>((done) => server.listen(port, "127.0.0.1", done));

  const res = await fetch(`http://127.0.0.1:${port}/api/v1/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}` },
    body: JSON.stringify({ token: TOKEN })
  });
  const setCookie = res.headers.getSetCookie();
  cookies = setCookie.map((c) => c.split(";")[0]).join("; ");
  csrf = setCookie.find((c) => c.startsWith("hmcp_csrf="))!.split(";")[0]!.split("=")[1]!;
});

beforeEach(() => {
  publishSurface(hosted, SURFACE);
  publishSurface(fixed, SURFACE);
});

afterAll(() => {
  closeStores();
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("a gateway that resolves its tenant per request", () => {
  it("refuses to read a queue without being told whose", async () => {
    const res = await api("/api/v1/servers/hosted/approvals/pending");
    expect(res.status).toBe(422);
    const message = (await res.json()).error.message;
    expect(message).toMatch(/per request/);
    expect(message).toMatch(/\?tenant=/);
  });

  it("refuses to write a kill switch without being told whose", async () => {
    // The row would be written perfectly well, into a tenant the gateway never
    // reads. This is the whole point.
    const res = await switchOff("hosted", "create_note");
    expect(res.status).toBe(422);
    expect((await res.json()).error.message).toMatch(/no single tenant/);
  });

  it("writes into the named tenant, and nowhere else", async () => {
    const res = await switchOff("hosted", "create_note", "?tenant=acme");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.tenant).toBe("acme");
    expect(body.explicitTenant).toBe(true);

    const store = new ApprovalStore(hosted.storePath, dir);
    try {
      expect(store.scoped({ component: hosted.component, tenant: "acme" }).toolExposure("create_note")).toBeDefined();
      // Not the empty tenant, which is where a guess would have landed.
      expect(store.scoped({ component: hosted.component, tenant: "" }).toolExposure("create_note")).toBeUndefined();
      expect(
        store.scoped({ component: hosted.component, tenant: "globex" }).toolExposure("create_note")
      ).toBeUndefined();
    } finally {
      store.close();
    }
  });

  it("shows one tenant's switch to that tenant only", async () => {
    await switchOff("hosted", "create_note", "?tenant=acme");

    const acme = await (await api("/api/v1/servers/hosted/tools?tenant=acme")).json();
    const globex = await (await api("/api/v1/servers/hosted/tools?tenant=globex")).json();

    expect(acme.find((t: { name: string }) => t.name === "create_note").exposure.disabled).toBe(true);
    expect(globex.find((t: { name: string }) => t.name === "create_note").exposure.disabled).toBe(false);
  });

  it("says which tenant the numbers describe", async () => {
    const p = await (await api("/api/v1/servers/hosted/protection?tenant=acme")).json();
    expect(p.tenant_scope).toBe("acme");
    expect(p.explicitTenant).toBe(true);
  });

  it("reports no reach in the server list rather than the empty tenant's", async () => {
    const list = await (await api("/api/v1/servers")).json();
    const row = list.find((s: { id: string }) => s.id === "hosted");
    // The tool count is process-wide and still known; reach is not.
    expect(row.toolCount).toBe(2);
    expect(row.reach).toBeNull();
    expect(row.tenantRequired).toBe(true);
  });

  it("refuses a tenant that could be spelled two ways", async () => {
    const res = await switchOff("hosted", "create_note", "?tenant=acme%20corp");
    expect(res.status).toBe(422);
    expect((await res.json()).error.message).toMatch(/not allowed/);
  });

  it("lists the tenants it has a trace of, so a choice can be offered", async () => {
    await switchOff("hosted", "create_note", "?tenant=acme");
    const body = await (await api("/api/v1/servers/hosted/tenants")).json();
    expect(body.tenants).toContain("acme");
    expect(body.sourceKind).toBe("jwt-verified");
    expect(body.assumed).toBeNull();
    expect(body.whyNotAssumed).toMatch(/per request/);
  });
});

describe("a gateway bound to one tenant", () => {
  it("assumes the tenant it can legitimately read, and says it assumed", async () => {
    const p = await (await api("/api/v1/servers/fixed/protection")).json();
    expect(p.tenant_scope).toBe("org_fixed");
    expect(p.explicitTenant).toBe(false);
  });

  it("still lets a request name a different one", async () => {
    // An operator whose console environment differs from the gateway's can say
    // so, rather than being quietly wrong.
    const res = await switchOff("fixed", "create_note", "?tenant=org_other");
    expect(res.status).toBe(200);
    expect((await res.json()).tenant).toBe("org_other");
  });
});

describe("a gateway with no tenant configured", () => {
  it("refuses a request that names one, rather than writing where nothing reads", async () => {
    const plain = writeGatewayFixture(join(dir, "plain"), { id: "plain", name: "plain" });
    const registryPath = join(dir, "servers.json");
    writeFileSync(
      registryPath,
      JSON.stringify({ version: 1, servers: [hosted.entry, fixed.entry, plain.entry] })
    );
    publishSurface(plain, SURFACE);

    const res = await switchOff("plain", "create_note", "?tenant=acme");
    expect(res.status).toBe(422);
    expect((await res.json()).error.message).toMatch(/no tenant configured/);

    // And with none named it works, under the empty tenant.
    const ok = await switchOff("plain", "create_note");
    expect(ok.status).toBe(200);
    expect((await ok.json()).tenant).toBe("");
  });
});
