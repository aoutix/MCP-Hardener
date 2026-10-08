import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { request, type Server } from "node:http";
import { buildRoutes } from "../src/api.js";
import { createConsoleServer } from "../src/http.js";
import { closeStores } from "../src/model/server.js";

/** A sentinel the console must never echo back. */
const SECRET = "SENTINEL-TOKEN-VALUE-do-not-leak";
const TOKEN = "test-token-abcdefghijklmnop";

let dir: string;
let server: Server;
let port: number;
let cookies = "";
let csrf = "";
let uiDir: string;

const TOOLS = {
  version: 1,
  generated_by: "hmcp-gen",
  api: { title: "Billing", version: "1.0.0", base_url: "https://api.example.com" },
  auth: { kind: "bearer", env: "TEST_UPSTREAM_TOKEN" },
  tools: [
    {
      name: "list_invoices",
      description: "List invoices for the caller's organization.",
      effect: "read",
      method: "GET",
      path: "/orgs/{org_id}/invoices",
      inputSchema: {
        type: "object",
        properties: { limit: { type: "integer", minimum: 1, maximum: 50, default: 50 } },
        additionalProperties: false
      },
      bindings: { limit: { in: "query", name: "limit" } },
      bodyMode: "none",
      tenantParams: ["org_id"],
      paginationCap: { param: "limit", max: 50 },
      annotations: { readOnlyHint: true },
      withheldParams: [{ name: "org_id", in: "path", reason: "tenant-scoped; injected from the credential" }]
    },
    {
      name: "create_invoice",
      description: "Create an invoice. This operation changes data.",
      effect: "write",
      method: "POST",
      path: "/orgs/{org_id}/invoices",
      inputSchema: {
        type: "object",
        properties: { amount: { type: "integer" }, currency: { type: "string" } },
        required: ["amount"],
        additionalProperties: false
      },
      bindings: { amount: { in: "body", name: "amount_cents" }, currency: { in: "body", name: "currency" } },
      bodyMode: "json",
      tenantParams: ["org_id"],
      annotations: {},
      withheldParams: [{ name: "org_id", in: "body", reason: "tenant-scoped body field; injected from the credential" }],
      review: "POST /invoices looks like it might only read."
    },
    {
      name: "delete_invoice",
      description: "Delete an invoice. This operation deletes data.",
      effect: "destructive",
      method: "DELETE",
      path: "/orgs/{org_id}/invoices/{id}",
      inputSchema: { type: "object", properties: { id: { type: "string" } }, additionalProperties: false },
      bindings: { id: { in: "path", name: "id" } },
      bodyMode: "none",
      tenantParams: ["org_id"],
      annotations: { destructiveHint: true }
    }
  ],
  generation: {
    spec_format: "openapi-3",
    has_security_schemes: true,
    operations_without_security: [],
    skipped: [{ tool: "purge_audit_log", reason: "left off in the manifest" }]
  }
};

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-web-"));
  const serverDir = join(dir, "billing-mcp");
  mkdirSync(serverDir, { recursive: true });
  writeFileSync(join(serverDir, "tools.json"), JSON.stringify(TOOLS));
  writeFileSync(
    join(serverDir, "policy.yaml"),
    [
      "version: 1",
      "name: billing-test",
      "defaults:",
      "  mode: approve-writes",
      "  on_unclassified: deny",
      "rules:",
      "  - id: allow-reads",
      '    match: "{get,list}_*"',
      "    effect: read",
      "    decision: allow",
      "  - id: create-invoice",
      "    match: create_invoice",
      "    effect: write",
      "    decision: approve",
      "    args:",
      "      amount: { max: 50000 }",
      "  - id: no-deletes",
      '    match: "delete_*"',
      "    decision: deny",
      "    reason: this deployment never deletes billing records",
      "tenant:",
      "  field: org_id",
      "  source:",
      "    kind: static",
      "    value: org_test",
      "egress:",
      '  allow: ["api.example.com"]',
      "approvals:",
      "  mode: cli",
      `  store_path: ${join(dir, "approvals.sqlite")}`,
      "audit:",
      "  enabled: true",
      `  path: ${join(dir, "audit.jsonl")}`,
      "  hash_chain: true",
      ""
    ].join("\n")
  );

  const registryPath = join(dir, "servers.json");
  writeFileSync(
    registryPath,
    JSON.stringify({
      version: 1,
      servers: [
        { id: "billing", kind: "generated", label: "Billing", dir: serverDir, added_at: new Date().toISOString() },
        { id: "broken", kind: "generated", label: "Broken", dir: join(dir, "nope"), added_at: new Date().toISOString() }
      ]
    })
  );

  process.env["TEST_UPSTREAM_TOKEN"] = SECRET;

  uiDir = join(dir, "ui");
  mkdirSync(uiDir, { recursive: true });
  writeFileSync(join(uiDir, "index.html"), "<!doctype html><title>console</title>");

  server = createConsoleServer({
    routes: buildRoutes({ registryPath }),
    token: TOKEN,
    uiDir,
    port: 0,
    actor: "tester"
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  port = (server.address() as AddressInfo).port;
  // The Host check is built from the configured port, so re-make the routes
  // with the port the OS actually handed us.
  server.close();
  server = createConsoleServer({
    routes: buildRoutes({ registryPath }),
    token: TOKEN,
    uiDir,
    port,
    actor: "tester"
  });
  await new Promise<void>((done) => server.listen(port, "127.0.0.1", done));
});

afterAll(async () => {
  closeStores();
  await new Promise<void>((done) => server.close(() => done()));
  rmSync(dir, { recursive: true, force: true });
  delete process.env["TEST_UPSTREAM_TOKEN"];
});

function url(path: string): string {
  return `http://127.0.0.1:${port}${path}`;
}

async function api(path: string, init: RequestInit = {}): Promise<Response> {
  const headers: Record<string, string> = {
    Origin: `http://127.0.0.1:${port}`,
    ...((init.headers as Record<string, string>) ?? {})
  };
  if (cookies) headers["Cookie"] = cookies;
  if (init.method && init.method !== "GET") {
    headers["Content-Type"] ??= "application/json";
    headers["X-HMCP-CSRF"] ??= csrf;
  }
  return fetch(url(path), { ...init, headers, redirect: "manual" });
}

/** A request that can set headers fetch() will not, such as Host. */
function rawGet(path: string, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return new Promise((done, fail) => {
    const req = request(
      { host: "127.0.0.1", port, path, method: "GET", headers: { Host: `127.0.0.1:${port}`, ...headers } },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => done({ status: res.statusCode ?? 0, body }));
      }
    );
    req.on("error", fail);
    req.end();
  });
}

async function login(): Promise<void> {
  const res = await fetch(url("/api/v1/session"), {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}` },
    body: JSON.stringify({ token: TOKEN })
  });
  expect(res.status).toBe(200);
  const setCookie = res.headers.getSetCookie();
  cookies = setCookie.map((c) => c.split(";")[0]).join("; ");
  csrf = setCookie.find((c) => c.startsWith("hmcp_csrf="))!.split(";")[0]!.split("=")[1]!;
}

describe("access control", () => {
  it("refuses an API request with no session", async () => {
    const res = await fetch(url("/api/v1/servers"), { headers: { Origin: `http://127.0.0.1:${port}` } });
    expect(res.status).toBe(401);
  });

  it("refuses a bad token", async () => {
    const res = await fetch(url("/api/v1/session"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}` },
      body: JSON.stringify({ token: "wrong" })
    });
    expect(res.status).toBe(401);
  });

  it("refuses an unexpected Host header, which is the DNS-rebinding defence", async () => {
    // fetch() refuses to set Host, so this goes through node:http. A domain
    // that resolves to 127.0.0.1 to reach this process still sends its own
    // Host, which is exactly what this check catches.
    const { status, body } = await rawGet("/api/v1/health", { Host: "evil.example.com" });
    expect(status).toBe(403);
    expect(JSON.parse(body).error.message).toMatch(/Host/);
  });

  it("accepts localhost as well as 127.0.0.1", async () => {
    const { status } = await rawGet("/api/v1/health", { Host: `localhost:${port}` });
    // Reaches the session check rather than the Host check.
    expect(status).toBe(401);
  });

  it("refuses a foreign Origin", async () => {
    const res = await fetch(url("/api/v1/health"), { headers: { Origin: "http://evil.example.com" } });
    expect(res.status).toBe(403);
  });

  it("accepts the token and issues a session", async () => {
    await login();
    const res = await api("/api/v1/health");
    expect(res.status).toBe(200);
  });

  it("refuses a mutating request with no CSRF header", async () => {
    const res = await fetch(url("/api/v1/servers/billing/grants"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookies, Origin: `http://127.0.0.1:${port}` },
      body: JSON.stringify({})
    });
    expect(res.status).toBe(403);
  });

  it("refuses a mutating request that is not JSON", async () => {
    const res = await fetch(url("/api/v1/servers/billing/grants"), {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: cookies,
        "X-HMCP-CSRF": csrf,
        Origin: `http://127.0.0.1:${port}`
      },
      body: "tool_match=*"
    });
    expect(res.status).toBe(400);
  });

  it("refuses a mutating request with no Origin at all", async () => {
    const res = await fetch(url("/api/v1/servers/billing/grants"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookies, "X-HMCP-CSRF": csrf },
      body: JSON.stringify({})
    });
    expect(res.status).toBe(403);
  });

  it("does not serve a file outside the UI root", async () => {
    // A path that escapes the root falls back to index.html, which is correct
    // for a single-page app. The property under test is that the response is
    // never the contents of the file being reached for, so these assert on the
    // body rather than on the status.
    for (const path of ["/../../package.json", "/..%2f..%2fpackage.json", "/%2e%2e/%2e%2e/package.json"]) {
      const { body } = await rawGet(path, {});
      expect(body, `${path} escaped the UI root`).not.toContain('"@hmcp/web"');
      expect(body, `${path} escaped the UI root`).not.toContain('"workspaces"');
    }
  });
});

describe("servers", () => {
  it("lists working and broken entries side by side", async () => {
    const body = await (await api("/api/v1/servers")).json();
    const billing = body.find((s: { id: string }) => s.id === "billing");
    const broken = body.find((s: { id: string }) => s.id === "broken");

    expect(billing.ok).toBe(true);
    expect(billing.toolCount).toBe(3);
    expect(billing.posture).toBe("approve-writes");
    expect(billing.component).toBe("generated:Billing");

    // Measured, not declared: a read allowed outright plus a write that can
    // still be approved, so writes are part of this server's surface.
    expect(billing.reach).toBe("approve-writes");

    // One unloadable entry must not take the whole list down with it.
    expect(broken.ok).toBe(false);
    expect(broken.error).toMatch(/no tools.json/);
  });

  it("404s an unknown server", async () => {
    expect((await api("/api/v1/servers/nope/protection")).status).toBe(404);
  });
});

describe("the function list", () => {
  it("gives every tool a live verdict attributed to the rule that produced it", async () => {
    const tools = await (await api("/api/v1/servers/billing/tools")).json();
    const byName = Object.fromEntries(tools.map((t: { name: string }) => [t.name, t]));

    expect(byName["list_invoices"].verdict).toMatchObject({ kind: "allow", ruleId: "allow-reads" });
    expect(byName["create_invoice"].verdict).toMatchObject({ kind: "approve", ruleId: "create-invoice" });
    expect(byName["delete_invoice"].verdict).toMatchObject({ kind: "deny", ruleId: "no-deletes" });
    expect(byName["delete_invoice"].verdict.reason).toMatch(/never deletes/);
  });

  it("reports why each parameter was withheld", async () => {
    const tools = await (await api("/api/v1/servers/billing/tools")).json();
    const withheld = tools.find((t: { name: string }) => t.name === "list_invoices").withheldParams;
    expect(withheld).toEqual([
      { name: "org_id", in: "path", reason: "tenant-scoped; injected from the credential" }
    ]);
  });

  it("shows where an argument lands upstream and whether it was renamed", async () => {
    const tool = await (await api("/api/v1/servers/billing/tools/create_invoice")).json();
    const amount = tool.args.find((a: { name: string }) => a.name === "amount");
    expect(amount.binding).toEqual({ in: "body", name: "amount_cents" });
    expect(amount.renamed).toBe(true);
    expect(amount.constrainedByRule).toBe("create-invoice");
  });

  it("carries the needs-a-human-decision note through", async () => {
    const tool = await (await api("/api/v1/servers/billing/tools/create_invoice")).json();
    expect(tool.review).toMatch(/might only read/);
  });
});

describe("a shared approvals database", () => {
  it("shows only the approvals belonging to this server", async () => {
    // Two generated servers share ~/.hmcp/approvals.sqlite by default, and an
    // approval row names the tool but not the server. A request for a tool this
    // server does not expose belongs to someone else and must not appear here.
    const { ApprovalStore, bindingHash } = await import("@hmcp/core");
    const store = new ApprovalStore(join(dir, "approvals.sqlite"));
    const base = (tool: string) => ({
      id: `apr_${tool}`,
      created_at: Date.now(),
      expires_at: Date.now() + 300_000,
      tool,
      effect: "write",
      binding_hash: bindingHash(tool, {}),
      args_redacted: "{}",
      reason: "r",
      actor: "agent",
      session: "s"
    });
    store.insertPending(base("create_invoice"));
    store.insertPending(base("some_other_servers_tool"));
    store.close();

    const pending = await (await api("/api/v1/servers/billing/approvals/pending")).json();
    expect(pending.map((r: { tool: string }) => r.tool)).toEqual(["create_invoice"]);

    const p = await (await api("/api/v1/servers/billing/protection")).json();
    expect(p.approvals.pendingCount).toBe(1);
    expect(p.approvals.pendingElsewhere).toBe(1);
  });
});

describe("the protection view", () => {
  it("is derived from this server's own policy", async () => {
    const p = await (await api("/api/v1/servers/billing/protection")).json();
    expect(p.posture).toBe("approve-writes");
    expect(p.onUnclassified).toBe("deny");
    expect(p.tenant.field).toBe("org_id");
    expect(p.tenant.sourceProse).toBe("a fixed value in the policy");
    expect(p.tenant.resolved).toBe(true);
    expect(p.egress.allow).toEqual(["api.example.com"]);
    expect(p.egress.baseUrlPermitted).toBe(true);
    expect(p.generation.skipped[0]).toEqual({ tool: "purge_audit_log", reason: "left off in the manifest" });
    expect(p.pipeline.length).toBeGreaterThan(5);
  });

  it("names which tools each policy rule actually claims", async () => {
    const p = await (await api("/api/v1/servers/billing/protection")).json();
    const reads = p.rules.find((r: { id: string }) => r.id === "allow-reads");
    expect(reads.matchedTools).toEqual(["list_invoices"]);
    const deletes = p.rules.find((r: { id: string }) => r.id === "no-deletes");
    expect(deletes.matchedTools).toEqual(["delete_invoice"]);
  });

  it("reports the credential's variable name but never its value", async () => {
    const res = await api("/api/v1/servers/billing/protection");
    const text = await res.text();
    expect(text).toContain("TEST_UPSTREAM_TOKEN");
    expect(text).not.toContain(SECRET);
    expect(JSON.parse(text).auth).toEqual({ kind: "bearer", envVar: "TEST_UPSTREAM_TOKEN", envPresent: true });
  });
});

describe("no response leaks a secret", () => {
  it("never includes the upstream credential or the console token", async () => {
    const paths = [
      "/api/v1/health",
      "/api/v1/meta/redaction",
      "/api/v1/servers",
      "/api/v1/servers/billing/protection",
      "/api/v1/servers/billing/tools",
      "/api/v1/servers/billing/tools/create_invoice",
      "/api/v1/servers/billing/scan",
      "/api/v1/servers/billing/approvals",
      "/api/v1/servers/billing/approvals/pending",
      "/api/v1/servers/billing/grants",
      "/api/v1/servers/billing/audit",
      "/api/v1/servers/billing/audit/verify",
      "/api/v1/audit"
    ];
    for (const path of paths) {
      const text = await (await api(path)).text();
      expect(text, `${path} leaked the upstream credential`).not.toContain(SECRET);
      expect(text, `${path} leaked the console token`).not.toContain(TOKEN);
      expect(text, `${path} leaked a private key`).not.toContain("-----BEGIN");
    }
  });
});
