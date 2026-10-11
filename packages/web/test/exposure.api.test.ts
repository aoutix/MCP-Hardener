import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { ApprovalStore, componentScope, queryAuditLog, verifyAuditLog } from "@hmcp/core";
import { buildRoutes } from "../src/api.js";
import { createConsoleServer } from "../src/http.js";
import { closeStores } from "../src/model/server.js";
import { publishSurface, tool, writeGatewayFixture, type GatewayFixture } from "./fixtures/gateway.js";

/**
 * The exposure switch, over the API the console actually uses.
 *
 * What these pin down is the safety argument for letting a console own this
 * control at all: switching off always narrows, switching on only clears the
 * override, both directions are audited, and nothing here can release a call
 * `decide()` refuses.
 */

const TOKEN = "exposure-test-token-0123456789";

let dir: string;
let auditPath: string;
let storePath: string;
let server: Server;
let port: number;
let cookies = "";
let csrf = "";
let fixture: GatewayFixture;
let silent: GatewayFixture;

/** The surface a running gateway would publish for these cases. */
const SURFACE = [
  tool("list_invoices", { effect: "read", description: "List invoices.", rawDescription: "List invoices." }),
  tool("create_invoice", {
    effect: "write",
    description: "Create an invoice.",
    rawDescription: "Create an invoice.",
    inputSchema: { type: "object", properties: { amount: { type: "integer" } }, additionalProperties: false }
  }),
  tool("delete_invoice", {
    effect: "destructive",
    description: "Delete an invoice.",
    rawDescription: "Delete an invoice.",
    inputSchema: { type: "object", properties: { id: { type: "string" } }, additionalProperties: false }
  })
];

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-exposure-"));

  fixture = writeGatewayFixture(join(dir, "gw"), {
    id: "srv",
    mode: "approve-writes",
    audit: true,
    hashChain: true,
    rules: [
      "- id: allow-reads",
      '  match: "list_*"',
      "  effect: read",
      "  decision: allow",
      "- id: create-invoice",
      "  match: create_invoice",
      "  effect: write",
      "  decision: approve",
      "- id: no-deletes",
      '  match: "delete_*"',
      "  decision: deny",
      "  reason: this deployment never deletes invoices"
    ]
  });
  auditPath = fixture.auditPath;
  storePath = fixture.storePath;
  publishSurface(fixture, SURFACE);

  // A second gateway that has never published, to assert the switch refuses a
  // surface it cannot confirm rather than writing against a guess.
  silent = writeGatewayFixture(join(dir, "silent"), { id: "quiet", name: "quiet" });

  const registryPath = join(dir, "servers.json");
  writeFileSync(registryPath, JSON.stringify({ version: 1, servers: [fixture.entry, silent.entry] }));

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

afterAll(async () => {
  closeStores();
  await new Promise<void>((done) => server.close(() => done()));
  rmSync(dir, { recursive: true, force: true });
});

async function api(path: string, init: RequestInit = {}): Promise<Response> {
  const headers: Record<string, string> = {
    Origin: `http://127.0.0.1:${port}`,
    Cookie: cookies,
    ...((init.headers as Record<string, string>) ?? {})
  };
  if (init.method && init.method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-HMCP-CSRF"] = csrf;
  }
  return fetch(`http://127.0.0.1:${port}${path}`, { ...init, headers });
}

const setExposure = (tool: string, body: Record<string, unknown>, id = "srv") =>
  api(`/api/v1/servers/${id}/tools/${tool}/exposure`, { method: "PUT", body: JSON.stringify(body) });

/*
 * The console believes a published surface only while a gateway is still
 * announcing itself, and that window is seven seconds. Refreshing it per case
 * keeps these about the switch rather than about how long the suite took.
 */
beforeEach(() => {
  publishSurface(fixture, SURFACE);
});

async function toolFromProtection(name: string) {
  const protection = await (await api("/api/v1/servers/srv/protection")).json();
  return protection.tools.find((t: { name: string }) => t.name === name);
}

describe("switching a function off", () => {
  it("is reported by the protection view and recorded in the audit log", async () => {
    const res = await setExposure("create_invoice", { disabled: true, reason: "incident 412" });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.changed).toBe(true);
    expect(body.warning).toBeNull();
    expect(body.tool.exposure).toMatchObject({ disabled: true, setBy: "reviewer", reason: "incident 412" });

    const tool = await toolFromProtection("create_invoice");
    expect(tool.exposure.disabled).toBe(true);

    // `verdict` stays the *policy* verdict, so the console can still say what
    // switching it back on would restore.
    expect(tool.verdict.ruleId).toBe("create-invoice");
    expect(tool.exposure.policyWouldExpose).toBe(true);

    const record = queryAuditLog(auditPath, { limit: 20 }).records.find((r) => r.rule_id === "exposure.disable");
    expect(record).toBeDefined();
    expect(record!.tool).toBe("create_invoice");
    expect(record!.decision).toBe("deny");
    expect(record!.component).toBe("hmcp-web");
    expect(record!.reason).toContain("incident 412");
    expect(verifyAuditLog(auditPath).ok).toBe(true);
  });

  it("writes a row the running server will read, scoped to that server", async () => {
    const store = new ApprovalStore(storePath, dir);
    try {
      expect(store.scoped(componentScope(fixture.component)).toolExposure("create_invoice")).toBeDefined();
      expect(store.scoped(componentScope("gateway:other")).toolExposure("create_invoice")).toBeUndefined();
      // And the axis the component key alone could never express.
      expect(
        store.scoped({ component: fixture.component, tenant: "acme" }).toolExposure("create_invoice")
      ).toBeUndefined();
    } finally {
      store.close();
    }
  });

  it("is idempotent, and says so rather than claiming a change", async () => {
    const body = await (await setExposure("create_invoice", { disabled: true, reason: "still off" })).json();
    expect(body.tool.exposure.disabled).toBe(true);
    expect(body.changed).toBe(false);
  });
});

describe("switching a function back on", () => {
  it("clears the override and records it", async () => {
    const body = await (await setExposure("create_invoice", { disabled: false })).json();
    expect(body.changed).toBe(true);
    expect(body.tool.exposure.disabled).toBe(false);

    const record = queryAuditLog(auditPath, { limit: 20 }).records.find((r) => r.rule_id === "exposure.enable");
    expect(record).toBeDefined();
    expect(record!.tool).toBe("create_invoice");
    expect(record!.reason).toContain("policy decides it again");
    expect(verifyAuditLog(auditPath).ok).toBe(true);
  });

  it("does not record a change that did not happen", async () => {
    const before = queryAuditLog(auditPath, { limit: 100 }).records.filter(
      (r) => r.rule_id === "exposure.enable"
    ).length;
    const body = await (await setExposure("create_invoice", { disabled: false })).json();
    expect(body.changed).toBe(false);
    const after = queryAuditLog(auditPath, { limit: 100 }).records.filter(
      (r) => r.rule_id === "exposure.enable"
    ).length;
    expect(after).toBe(before);
  });

  it("cannot widen a policy: a function policy denies stays denied", async () => {
    // The reason this control can live in a console at all. `delete_invoice`
    // is refused by rule `no-deletes`; switching it off and on again leaves
    // that verdict exactly where it was.
    await setExposure("delete_invoice", { disabled: true, reason: "belt and braces" });
    expect((await toolFromProtection("delete_invoice")).exposure.disabled).toBe(true);

    await setExposure("delete_invoice", { disabled: false });
    const tool = await toolFromProtection("delete_invoice");
    expect(tool.exposure.disabled).toBe(false);
    expect(tool.verdict.kind).toBe("deny");
    expect(tool.verdict.ruleId).toBe("no-deletes");
    // Which is what the console uses to refuse to offer a switch with nothing
    // to turn on.
    expect(tool.exposure.policyWouldExpose).toBe(false);
  });
});

describe("what the switch refuses", () => {
  it("refuses a tool the server does not expose", async () => {
    const res = await setExposure("purge_everything", { disabled: true });
    expect(res.status).toBe(404);
  });

  it("refuses a gateway that has never said what it serves", async () => {
    // The switch is available for a gateway now, but only against a tool list
    // a live process has published. Writing a row from a guessed name is the
    // failure this refuses: it would read as protection and guard nothing.
    const res = await setExposure("get_note", { disabled: true }, "quiet");
    expect(res.status).toBe(422);
    expect((await res.json()).error.message).toMatch(/has published a tool surface/);
  });

  it("refuses a gateway whose process has stopped announcing itself", async () => {
    // Rows are there, but nothing live claims them, so the list cannot be
    // confirmed as current.
    publishSurface(fixture, SURFACE, { lastSeen: Date.now() - 60_000 });
    const res = await setExposure("create_invoice", { disabled: true, reason: "stale" });
    expect(res.status).toBe(422);
    expect((await res.json()).error.message).toMatch(/no running gateway/);
  });

  it("refuses a tool a different process published", async () => {
    // Two gateways sharing a component would otherwise blend into a surface
    // neither serves.
    publishSurface(fixture, SURFACE, { pid: 9999, lastSeen: Date.now() });
    const store = new ApprovalStore(storePath, dir);
    try {
      store.recordRuntimeState({
        component: fixture.component,
        pid: 1234,
        started_at: Date.now(),
        last_seen: Date.now(),
        policy_digest: "d",
        policy_path: fixture.configPath
      });
    } finally {
      store.close();
    }
    const res = await setExposure("create_invoice", { disabled: true, reason: "other pid" });
    expect(res.status).toBe(422);
  });

  it("refuses a body that does not say which way the switch goes", async () => {
    const res = await setExposure("list_invoices", { reason: "no state given" });
    expect(res.status).toBe(422);
  });

  it("refuses a request with no CSRF header, like every other mutation", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/api/v1/servers/srv/tools/list_invoices/exposure`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}`, Cookie: cookies },
      body: JSON.stringify({ disabled: true })
    });
    expect(res.status).toBe(403);
    expect((await toolFromProtection("list_invoices")).exposure.disabled).toBe(false);
  });

  it("refuses a request with no session", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/api/v1/servers/srv/tools/list_invoices/exposure`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}` },
      body: JSON.stringify({ disabled: true })
    });
    expect(res.status).toBe(401);
  });

  it("never echoes anything but the tool's own state and the scope it wrote", async () => {
    const body = await (await setExposure("list_invoices", { disabled: true, reason: "x" })).json();
    // The tenant is part of the write's own identity, not someone else's
    // state: a caller has to be able to see which scope the switch landed in,
    // because landing in the wrong one is the failure that looks like success.
    expect(Object.keys(body).sort()).toEqual(["changed", "explicitTenant", "tenant", "tool", "warning"]);
    expect(body.tenant).toBe("");
    await setExposure("list_invoices", { disabled: false });
  });
});

/**
 * The console's chrome reports what the model can actually reach rather than
 * what `defaults.mode` declares, so it has to move when a switch moves. That is
 * the whole reason it is derived instead of copied out of the policy file.
 */
describe("reach", () => {
  const reach = async () => (await (await api("/api/v1/servers/srv/protection")).json()).reach;

  it("counts a write that can still be approved as part of the surface", async () => {
    expect(await reach()).toBe("approve-writes");
  });

  it("falls to read-only once the last reachable write is switched off", async () => {
    await setExposure("create_invoice", { disabled: true, reason: "reach test" });
    // delete_invoice is denied by policy, so a read is all that is left.
    expect(await reach()).toBe("read-only");
  });

  it("falls to locked when nothing at all can run", async () => {
    await setExposure("list_invoices", { disabled: true, reason: "reach test" });
    expect(await reach()).toBe("locked");
  });

  it("is never the declared posture: the policy file did not change", async () => {
    const p = await (await api("/api/v1/servers/srv/protection")).json();
    expect(p.posture).toBe("approve-writes");
    expect(p.reach).toBe("locked");
  });

  it("comes back when the switches do", async () => {
    await setExposure("create_invoice", { disabled: false });
    await setExposure("list_invoices", { disabled: false });
    expect(await reach()).toBe("approve-writes");
  });
});
