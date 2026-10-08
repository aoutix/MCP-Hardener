import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { queryAuditLog, verifyAuditLog } from "@hmcp/core";
import { buildRoutes } from "../src/api.js";
import { createConsoleServer } from "../src/http.js";
import { closeStores } from "../src/model/server.js";

const TOKEN = "grants-test-token-0123456789";

let dir: string;
let auditPath: string;
let server: Server;
let port: number;
let cookies = "";
let csrf = "";

const TOOLS = {
  version: 1,
  api: { title: "Billing", version: "1.0.0", base_url: "https://api.example.com" },
  auth: { kind: "none" },
  tools: [
    {
      name: "create_invoice",
      description: "Create an invoice.",
      effect: "write",
      method: "POST",
      path: "/invoices",
      inputSchema: {
        type: "object",
        properties: { amount: { type: "integer" } },
        additionalProperties: false
      },
      bindings: { amount: { in: "body", name: "amount" } },
      bodyMode: "json",
      tenantParams: [],
      annotations: {}
    },
    {
      name: "list_invoices",
      description: "List invoices.",
      effect: "read",
      method: "GET",
      path: "/invoices",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      bindings: {},
      bodyMode: "none",
      tenantParams: [],
      annotations: { readOnlyHint: true }
    }
  ]
};

async function boot(auditTarget: string): Promise<void> {
  const serverDir = join(dir, "srv");
  mkdirSync(serverDir, { recursive: true });
  writeFileSync(join(serverDir, "tools.json"), JSON.stringify(TOOLS));
  writeFileSync(
    join(serverDir, "policy.yaml"),
    [
      "version: 1",
      "defaults:",
      "  mode: approve-writes",
      "rules:",
      "  - id: allow-reads",
      '    match: "list_*"',
      "    effect: read",
      "    decision: allow",
      "  - id: create-invoice",
      "    match: create_invoice",
      "    effect: write",
      "    decision: approve",
      "egress:",
      '  allow: ["api.example.com"]',
      "approvals:",
      "  mode: cli",
      `  store_path: ${join(dir, "approvals.sqlite")}`,
      "audit:",
      "  enabled: true",
      `  path: ${auditTarget}`,
      "  hash_chain: true",
      ""
    ].join("\n")
  );

  const registryPath = join(dir, "servers.json");
  writeFileSync(
    registryPath,
    JSON.stringify({
      version: 1,
      servers: [{ id: "srv", kind: "generated", label: "S", dir: serverDir, added_at: new Date().toISOString() }]
    })
  );

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
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-grants-"));
  auditPath = join(dir, "audit.jsonl");
  await boot(auditPath);
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

const makeGrant = (body: Record<string, unknown>) =>
  api("/api/v1/servers/srv/grants", { method: "POST", body: JSON.stringify(body) });

describe("creating a standing grant", () => {
  it("records it in the audit log, and the chain still verifies", async () => {
    const res = await makeGrant({
      tool_match: "create_invoice",
      constraints: { amount: { max: 500 } },
      ttl_seconds: 3600,
      max_uses: 10,
      reason: "month-end run"
    });
    expect(res.status).toBe(200);
    const grant = await res.json();
    expect(grant.id).toMatch(/^sg_/);
    expect(grant.state).toBe("active");
    expect(grant.uses).toBe(0);

    // The user's requirement: every pre-approval is in the audit log.
    const page = queryAuditLog(auditPath, { limit: 10 });
    const record = page.records.find((r) => r.grant_id === grant.id);
    expect(record).toBeDefined();
    expect(record!.rule_id).toBe("standing_grant.create");
    expect(record!.component).toBe("hmcp-web");
    expect(record!.decision).toBe("approve");
    expect(record!.reason).toContain("month-end run");
    expect(record!.args_redacted).toMatchObject({ tool_match: "create_invoice", max_uses: 10 });

    // And the console's append went through AuditLog, so the chain holds.
    expect(verifyAuditLog(auditPath).ok).toBe(true);
  });

  it("refuses an unbounded wildcard with the reason, and writes nothing", async () => {
    const before = queryAuditLog(auditPath, { limit: 200 }).records.length;
    const res = await makeGrant({ tool_match: "*", ttl_seconds: 3600, reason: "everything" });
    expect(res.status).toBe(422);
    expect((await res.json()).error.message).toMatch(/unbounded wildcard/);
    expect(queryAuditLog(auditPath, { limit: 200 }).records).toHaveLength(before);
  });

  it("refuses a TTL beyond the maximum", async () => {
    const res = await makeGrant({
      tool_match: "create_invoice",
      ttl_seconds: 400 * 86_400,
      max_uses: 1,
      reason: "forever"
    });
    expect(res.status).toBe(422);
    expect((await res.json()).error.message).toMatch(/may not last longer/);
  });

  it("requires a reason", async () => {
    const res = await makeGrant({ tool_match: "create_invoice", ttl_seconds: 60, max_uses: 1 });
    expect(res.status).toBe(422);
  });
});

describe("previewing a grant before creating it", () => {
  it("names the tools it would cover without claiming a use", async () => {
    const res = await api("/api/v1/servers/srv/grants/preview", {
      method: "POST",
      body: JSON.stringify({ tool_match: "create_*", ttl_seconds: 60, max_uses: 1, reason: "preview" })
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    const covered = body.tools.filter((t: { covers: boolean }) => t.covers).map((t: { name: string }) => t.name);
    expect(covered).toEqual(["create_invoice"]);

    const notCovered = body.tools.find((t: { name: string }) => t.name === "list_invoices");
    expect(notCovered.covers).toBe(false);
    expect(notCovered.why).toContain("does not match");
  });

  it("writes nothing at all", async () => {
    const before = queryAuditLog(auditPath, { limit: 500 }).records.length;
    const grantsBefore = (await (await api("/api/v1/servers/srv/grants")).json()).length;
    await api("/api/v1/servers/srv/grants/preview", {
      method: "POST",
      body: JSON.stringify({ tool_match: "create_invoice", ttl_seconds: 60, reason: "preview" })
    });
    expect(queryAuditLog(auditPath, { limit: 500 }).records).toHaveLength(before);
    expect((await (await api("/api/v1/servers/srv/grants")).json())).toHaveLength(grantsBefore);
  });
});

describe("revoking a grant", () => {
  it("records the revocation and refuses a second attempt", async () => {
    const grant = await (
      await makeGrant({ tool_match: "create_invoice", ttl_seconds: 600, max_uses: 2, reason: "to revoke" })
    ).json();

    const res = await api(`/api/v1/servers/srv/grants/${grant.id}`, { method: "DELETE" });
    expect(res.status).toBe(200);
    const revoked = await res.json();
    expect(revoked.state).toBe("revoked");
    expect(revoked.revokedBy).toBe("reviewer");
    expect(revoked.warning).toBeNull();

    const record = queryAuditLog(auditPath, { limit: 20 }).records.find(
      (r) => r.grant_id === grant.id && r.rule_id === "standing_grant.revoke"
    );
    expect(record).toBeDefined();
    expect(record!.decision).toBe("deny");
    expect(verifyAuditLog(auditPath).ok).toBe(true);

    // Revoking twice is a conflict, not a silent success.
    expect((await api(`/api/v1/servers/srv/grants/${grant.id}`, { method: "DELETE" })).status).toBe(409);
  });

  it("404s an unknown grant", async () => {
    expect((await api("/api/v1/servers/srv/grants/sg_nope", { method: "DELETE" })).status).toBe(404);
  });
});

describe("the grant is withdrawn if it cannot be audited", () => {
  it("leaves no usable grant behind when the audit append fails", async () => {
    // A second console whose audit path is a directory, so appendStrict throws.
    const unwritable = join(dir, "a-directory");
    mkdirSync(unwritable, { recursive: true });

    const broken = mkdtempSync(join(tmpdir(), "hmcp-grants-bad-"));
    const prevDir = dir;
    const prevServer = server;
    const prevCookies = cookies;
    const prevCsrf = csrf;
    dir = broken;
    closeStores();
    await new Promise<void>((done) => prevServer.close(() => done()));
    await boot(unwritable);

    // The rollback path logs to stderr by design; keep it out of the report.
    const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    const res = await makeGrant({
      tool_match: "create_invoice",
      ttl_seconds: 600,
      max_uses: 1,
      reason: "should not survive"
    });
    stderr.mockRestore();
    expect(res.status).toBe(500);

    // The requirement is that no pre-approval exists unaudited, so a grant
    // that could not be recorded must not be left able to release a call.
    const grants = await (await api("/api/v1/servers/srv/grants")).json();
    expect(grants.every((g: { state: string }) => g.state !== "active")).toBe(true);

    closeStores();
    await new Promise<void>((done) => server.close(() => done()));
    rmSync(broken, { recursive: true, force: true });
    dir = prevDir;
    server = prevServer;
    cookies = prevCookies;
    csrf = prevCsrf;
    await boot(auditPath);
  });
});
