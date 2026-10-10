import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createServer, type IncomingMessage, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { ApprovalStore, parsePolicy, policyDigest, readAuditLog, verifyAuditLog } from "@hmcp/core";

/**
 * The scope the server under test writes its rows under: its component, and
 * the tenant `TEST_ORG` resolves to. A test that opened the database
 * unscoped would be asserting against rows the server cannot see.
 */
const SCOPE = { component: "generated:Billing", tenant: "acme" };
import { HardenedServer, parseToolsFile, type ToolsFile } from "../src/index.js";

/* -------------------------------------------------------- a stand-in REST API */

interface Received {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

let api: HttpServer;
let apiPort: number;
let received: Received[] = [];

beforeAll(async () => {
  api = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      received.push({
        method: req.method ?? "",
        url: req.url ?? "",
        headers: req.headers as Received["headers"],
        body: Buffer.concat(chunks).toString("utf8")
      });
      const url = new URL(req.url ?? "/", "http://localhost");
      if (url.pathname.startsWith("/orgs/") && url.pathname.endsWith("/invoices")) {
        if (req.method === "POST") {
          res.writeHead(201, { "content-type": "application/json" });
          res.end(JSON.stringify({ id: "inv_1", created: true }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ invoices: [{ id: "inv_1" }], org: url.pathname.split("/")[2] }));
        return;
      }
      res.writeHead(404).end(JSON.stringify({ error: "not found" }));
    });
  });
  await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve));
  apiPort = (api.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => api.close(() => resolve()));
});

/* ------------------------------------------------------------------- fixtures */

let dir: string;

function toolsFile(): ToolsFile {
  return parseToolsFile({
    version: 1,
    api: { title: "Billing", version: "1.0.0", base_url: `http://127.0.0.1:${apiPort}` },
    auth: { kind: "bearer", env: "BILLING_TOKEN" },
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
        annotations: { readOnlyHint: true }
      },
      {
        name: "create_invoice",
        description: "Create an invoice.",
        effect: "write",
        method: "POST",
        path: "/orgs/{org_id}/invoices",
        inputSchema: {
          type: "object",
          properties: {
            amount: { type: "integer", minimum: 1 },
            currency: { type: "string", enum: ["usd", "eur"] }
          },
          required: ["amount", "currency"],
          additionalProperties: false
        },
        bindings: {
          amount: { in: "body", name: "amount" },
          currency: { in: "body", name: "currency" }
        },
        bodyMode: "json",
        tenantParams: ["org_id"],
        annotations: {}
      },
      {
        name: "delete_invoice",
        description: "Delete an invoice.",
        effect: "destructive",
        method: "DELETE",
        path: "/orgs/{org_id}/invoices/{invoice_id}",
        inputSchema: {
          type: "object",
          properties: { invoice_id: { type: "string", maxLength: 64 } },
          required: ["invoice_id"],
          additionalProperties: false
        },
        bindings: { invoice_id: { in: "path", name: "invoice_id" } },
        bodyMode: "none",
        tenantParams: ["org_id"],
        annotations: { destructiveHint: true }
      }
    ]
  });
}

function policy(overrides: Record<string, unknown> = {}) {
  return parsePolicy({
    version: 1,
    defaults: { mode: "read-only" },
    rules: [
      { id: "reads", match: "list_*", effect: "read", decision: "allow" },
      {
        id: "invoices",
        match: "create_invoice",
        effect: "write",
        decision: "approve",
        args: { amount: { max: 50000 } }
      },
      { id: "no-deletes", match: "delete_*", decision: "deny", reason: "this deployment never deletes invoices" }
    ],
    tenant: {
      field: "org_id",
      source: { kind: "env", name: "TEST_ORG" },
      inject: ["path"]
    },
    egress: {
      allow: [`127.0.0.1:${apiPort}`],
      methods: ["GET", "POST", "DELETE"],
      allow_http: true,
      allow_ip_literals: true,
      block_private_ips: false
    },
    approvals: { mode: "both", store_path: join(dir, "approvals.sqlite"), ttl_seconds: 300 },
    audit: { path: join(dir, "audit.jsonl") },
    ...overrides
  });
}

interface Harness {
  client: Client;
  server: HardenedServer;
  elicitResponses: { action: "accept" | "decline" | "cancel"; content?: Record<string, unknown> }[];
  elicitPrompts: string[];
  close: () => Promise<void>;
}

async function harness(
  options: { elicitation?: boolean; policyOverrides?: Record<string, unknown>; exposurePollMs?: number } = {}
): Promise<Harness> {
  const elicitResponses: Harness["elicitResponses"] = [];
  const elicitPrompts: string[] = [];

  const client = new Client(
    { name: "test-agent", version: "1.0.0" },
    { capabilities: options.elicitation ? { elicitation: {} } : {} }
  );

  if (options.elicitation) {
    client.setRequestHandler(ElicitRequestSchema, async (request) => {
      elicitPrompts.push(request.params.message);
      return (elicitResponses.shift() ?? { action: "cancel" }) as never;
    });
  }

  const server = new HardenedServer({
    tools: toolsFile(),
    policy: policy(options.policyOverrides),
    cwd: dir,
    ...(options.exposurePollMs !== undefined ? { exposurePollMs: options.exposurePollMs } : {})
  });

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  return {
    client,
    server,
    elicitResponses,
    elicitPrompts,
    close: async () => {
      await client.close().catch(() => undefined);
      await server.close().catch(() => undefined);
    }
  };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-e2e-"));
  received = [];
  process.env["TEST_ORG"] = "acme";
  process.env["BILLING_TOKEN"] = "secret-token-value";
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  delete process.env["TEST_ORG"];
  delete process.env["BILLING_TOKEN"];
});

function textOf(result: unknown): string {
  const content = (result as { content: { type: string; text?: string }[] }).content ?? [];
  return content.map((c) => c.text ?? "").join("\n");
}

/* ---------------------------------------------------------------------- tests */

describe("tool advertisement", () => {
  it("advertises every tool, with the tenant field absent from each schema", async () => {
    const h = await harness();
    try {
      const { tools } = await h.client.listTools();
      expect(tools.map((t) => t.name).sort()).toEqual(["create_invoice", "delete_invoice", "list_invoices"]);
      for (const tool of tools) {
        const properties = Object.keys((tool.inputSchema as { properties?: object }).properties ?? {});
        expect(properties, tool.name).not.toContain("org_id");
      }
    } finally {
      await h.close();
    }
  });

  it("marks reads read-only and deletes destructive", async () => {
    const h = await harness();
    try {
      const { tools } = await h.client.listTools();
      const byName = new Map(tools.map((t) => [t.name, t]));
      expect(byName.get("list_invoices")!.annotations?.readOnlyHint).toBe(true);
      expect(byName.get("delete_invoice")!.annotations?.destructiveHint).toBe(true);
    } finally {
      await h.close();
    }
  });
});

describe("reads", () => {
  it("runs a permitted read and scopes it to the credential's tenant", async () => {
    const h = await harness();
    try {
      const result = await h.client.callTool({ name: "list_invoices", arguments: { limit: 10 } });
      expect(result.isError).toBeFalsy();
      expect(textOf(result)).toContain("inv_1");

      expect(received).toHaveLength(1);
      // The tenant came from the environment, not from the agent.
      expect(received[0]!.url).toContain("/orgs/acme/invoices");
      expect(received[0]!.url).toContain("limit=10");
      expect(received[0]!.headers["authorization"]).toBe("Bearer secret-token-value");
    } finally {
      await h.close();
    }
  });

  it("refuses a page size above the ceiling", async () => {
    const h = await harness();
    try {
      const result = await h.client.callTool({ name: "list_invoices", arguments: { limit: 100000 } });
      expect(result.isError).toBe(true);
      expect(received).toHaveLength(0);
    } finally {
      await h.close();
    }
  });

  it("bounds a call that omits the page size, so no read is unbounded", async () => {
    const h = await harness();
    try {
      await h.client.callTool({ name: "list_invoices", arguments: {} });
      expect(received[0]!.url).toContain("limit=50");
    } finally {
      await h.close();
    }
  });

  it("rejects an argument the schema does not declare, before anything is sent", async () => {
    const h = await harness();
    try {
      const result = await h.client.callTool({
        name: "list_invoices",
        arguments: { limit: 10, org_id: "globex" }
      });
      expect(result.isError).toBe(true);
      expect(received).toHaveLength(0);
    } finally {
      await h.close();
    }
  });
});

describe("tenant scoping", () => {
  it("gives an agent no way to reach another tenant", async () => {
    const h = await harness();
    try {
      // Every spelling of the attempt: the schema is closed, so each is refused
      // before a request is built.
      for (const args of [{ org_id: "globex" }, { organization_id: "globex" }, { Org_Id: "globex" }]) {
        const result = await h.client.callTool({ name: "list_invoices", arguments: args });
        expect(result.isError, JSON.stringify(args)).toBe(true);
      }
      expect(received).toHaveLength(0);
    } finally {
      await h.close();
    }
  });

  it("refuses to start when a required tenant cannot be resolved", () => {
    delete process.env["TEST_ORG"];
    expect(() => new HardenedServer({ tools: toolsFile(), policy: policy(), cwd: dir })).toThrow(
      /tenant scoping is required/
    );
  });

  it("cannot be escaped through a path parameter", async () => {
    const h = await harness({ policyOverrides: { rules: [{ id: "all", match: "*", effect: "read", decision: "allow" }] } });
    try {
      // The server sends DELETE /orgs/acme/invoices/<encoded>, so the traversal
      // stays inside its own path segment.
      await h.client.callTool({ name: "delete_invoice", arguments: { invoice_id: "../../../admin" } });
      expect(received[0]!.url).toBe("/orgs/acme/invoices/..%2F..%2F..%2Fadmin");
      expect(received[0]!.url).not.toContain("/admin");
    } finally {
      await h.close();
    }
  });
});

describe("denials", () => {
  it("refuses a destructive tool and names the rule", async () => {
    const h = await harness();
    try {
      const result = await h.client.callTool({ name: "delete_invoice", arguments: { invoice_id: "inv_1" } });
      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain("no-deletes");
      expect(textOf(result)).toContain("this deployment never deletes invoices");
      expect(received).toHaveLength(0);
    } finally {
      await h.close();
    }
  });

  it("refuses a write whose arguments exceed the rule's bounds", async () => {
    const h = await harness();
    try {
      const result = await h.client.callTool({
        name: "create_invoice",
        arguments: { amount: 90000, currency: "usd" }
      });
      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain("exceeds the policy maximum of 50000");
      expect(received).toHaveLength(0);
    } finally {
      await h.close();
    }
  });
});

describe("approvals through elicitation", () => {
  it("prompts the host and runs the call once the reviewer accepts", async () => {
    const h = await harness({ elicitation: true });
    try {
      h.elicitResponses.push({ action: "accept", content: { approve: true, note: "checked" } });
      const result = await h.client.callTool({
        name: "create_invoice",
        arguments: { amount: 2500, currency: "usd" }
      });

      expect(result.isError).toBeFalsy();
      expect(textOf(result)).toContain("inv_1");
      expect(h.elicitPrompts[0]).toContain("create_invoice");
      expect(h.elicitPrompts[0]).toContain("Approve a write operation?");
      expect(received).toHaveLength(1);
      expect(JSON.parse(received[0]!.body)).toMatchObject({ amount: 2500, currency: "usd" });
    } finally {
      await h.close();
    }
  });

  it("does not run the call when the reviewer declines", async () => {
    const h = await harness({ elicitation: true });
    try {
      h.elicitResponses.push({ action: "accept", content: { approve: false } });
      const result = await h.client.callTool({
        name: "create_invoice",
        arguments: { amount: 2500, currency: "usd" }
      });
      expect(result.isError).toBe(true);
      expect(received).toHaveLength(0);
    } finally {
      await h.close();
    }
  });
});

describe("approvals out of band", () => {
  it("parks the call for a client with no elicitation, then releases it on approval", async () => {
    const h = await harness();
    try {
      const args = { amount: 2500, currency: "usd" };

      const first = await h.client.callTool({ name: "create_invoice", arguments: args });
      expect(first.isError).toBe(true);
      expect(textOf(first)).toContain("hmcp approve");
      expect(received).toHaveLength(0);

      const id = /apr_[0-9a-f]+/.exec(textOf(first))![0];

      // A human reviews it from a separate process.
      const storeDb = new ApprovalStore(join(dir, "approvals.sqlite"));
      const store = storeDb.scoped(SCOPE);
      const pending = store.listPending();
      expect(pending).toHaveLength(1);
      expect(pending[0]!.tool).toBe("create_invoice");
      store.decide(id, "granted", "alice", "spoke to finance");
      storeDb.close();

      const second = await h.client.callTool({ name: "create_invoice", arguments: args });
      expect(second.isError).toBeFalsy();
      expect(received).toHaveLength(1);

      // The grant is spent, so the next identical call is parked again.
      const third = await h.client.callTool({ name: "create_invoice", arguments: args });
      expect(third.isError).toBe(true);
      expect(received).toHaveLength(1);
    } finally {
      await h.close();
    }
  });

  it("will not let an approval for one amount release a larger one", async () => {
    const h = await harness();
    try {
      const first = await h.client.callTool({ name: "create_invoice", arguments: { amount: 10, currency: "usd" } });
      const id = /apr_[0-9a-f]+/.exec(textOf(first))![0];

      const storeDb = new ApprovalStore(join(dir, "approvals.sqlite"));
      const store = storeDb.scoped(SCOPE);
      store.decide(id, "granted", "alice");
      storeDb.close();

      // Same tool, approved moments ago, but different arguments.
      const swapped = await h.client.callTool({
        name: "create_invoice",
        arguments: { amount: 49000, currency: "usd" }
      });
      expect(swapped.isError).toBe(true);
      expect(received).toHaveLength(0);

      // The call that was actually approved still runs.
      const original = await h.client.callTool({ name: "create_invoice", arguments: { amount: 10, currency: "usd" } });
      expect(original.isError).toBeFalsy();
      expect(JSON.parse(received[0]!.body)).toMatchObject({ amount: 10 });
    } finally {
      await h.close();
    }
  });
});

describe("egress limits", () => {
  it("refuses a call to a host the policy does not permit", async () => {
    const h = await harness({ policyOverrides: { egress: { allow: ["api.elsewhere.example.com"], allow_http: true } } });
    try {
      const result = await h.client.callTool({ name: "list_invoices", arguments: { limit: 5 } });
      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain("Egress refused");
      expect(received).toHaveLength(0);
    } finally {
      await h.close();
    }
  });
});

describe("audit trail", () => {
  it("records every decision, allowed or refused, in a verifiable chain", async () => {
    const h = await harness({ elicitation: true });
    try {
      h.elicitResponses.push({ action: "accept", content: { approve: true } });

      await h.client.callTool({ name: "list_invoices", arguments: { limit: 5 } });
      await h.client.callTool({ name: "delete_invoice", arguments: { invoice_id: "inv_1" } });
      await h.client.callTool({ name: "create_invoice", arguments: { amount: 2500, currency: "usd" } });

      const records = readAuditLog(join(dir, "audit.jsonl"));
      expect(records).toHaveLength(3);

      const [read, deleted, written] = records;
      expect(read!.tool).toBe("list_invoices");
      expect(read!.decision).toBe("allow");
      expect(read!.outcome).toBe("completed");
      expect(read!.upstream?.status).toBe(200);
      expect(read!.tenant).toBe("acme");

      expect(deleted!.decision).toBe("deny");
      expect(deleted!.outcome).toBe("denied");
      expect(deleted!.rule_id).toBe("no-deletes");

      expect(written!.decision).toBe("approve");
      expect(written!.outcome).toBe("completed");
      expect(written!.approval_id).toMatch(/^apr_/);
      expect(written!.args_redacted).toMatchObject({ amount: 2500, currency: "usd" });

      expect(verifyAuditLog(join(dir, "audit.jsonl")).ok).toBe(true);
    } finally {
      await h.close();
    }
  });

  it("never writes the upstream credential into the log", async () => {
    const h = await harness();
    try {
      await h.client.callTool({ name: "list_invoices", arguments: { limit: 5 } });
      const raw = readAuditLog(join(dir, "audit.jsonl"));
      expect(JSON.stringify(raw)).not.toContain("secret-token-value");
    } finally {
      await h.close();
    }
  });
});

describe("standing grants, end to end", () => {
  it("releases a matching call without asking, and records that it did", async () => {
    const h = await harness();
    try {
      const args = { amount: 2500, currency: "usd" };

      // A human pre-approves a class of call from a separate process, exactly
      // as the console does.
      const storeDb = new ApprovalStore(join(dir, "approvals.sqlite"));
      const store = storeDb.scoped(SCOPE);
      const grant = store.createGrant({
        tool_match: "create_invoice",
        constraints: { amount: { max: 5000 } },
        expires_at: Date.now() + 60_000,
        max_uses: 1,
        reason: "month-end invoicing run",
        created_by: "alice"
      });
      storeDb.close();

      const first = await h.client.callTool({ name: "create_invoice", arguments: args });
      expect(first.isError).toBeFalsy();
      expect(received).toHaveLength(1);

      const records = readAuditLog(join(dir, "audit.jsonl"));
      const use = records.find((r) => r.rule_id === "standing_grant.use");
      expect(use).toBeDefined();
      expect(use!.grant_id).toBe(grant.id);
      // The call's own record is attributable to the grant too.
      const call = records.find((r) => r.outcome === "completed" && r.rule_id !== "standing_grant.use");
      expect(call!.grant_id).toBe(grant.id);

      // The cap was one use, so the next identical call goes back to a human.
      const second = await h.client.callTool({ name: "create_invoice", arguments: args });
      expect(second.isError).toBe(true);
      expect(textOf(second)).toContain("hmcp approve");
      expect(received).toHaveLength(1);

      expect(verifyAuditLog(join(dir, "audit.jsonl")).ok).toBe(true);
    } finally {
      await h.close();
    }
  });

  it("parks a call whose arguments miss the grant's bounds instead of refusing it", async () => {
    const h = await harness();
    try {
      const storeDb = new ApprovalStore(join(dir, "approvals.sqlite"));
      const store = storeDb.scoped(SCOPE);
      const grant = store.createGrant({
        tool_match: "create_invoice",
        constraints: { amount: { max: 100 } },
        expires_at: Date.now() + 60_000,
        max_uses: 5,
        reason: "small invoices only",
        created_by: "alice"
      });
      storeDb.close();

      // Over the grant's ceiling but within the policy rule's, so the correct
      // outcome is the ordinary human review, not a denial.
      const result = await h.client.callTool({
        name: "create_invoice",
        arguments: { amount: 4000, currency: "usd" }
      });
      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain("hmcp approve");
      expect(received).toHaveLength(0);

      const afterDb = new ApprovalStore(join(dir, "approvals.sqlite"));
      const after = afterDb.scoped(SCOPE);
      expect(after.getGrant(grant.id)!.uses).toBe(0);
      expect(after.listPending()).toHaveLength(1);
      afterDb.close();
    } finally {
      await h.close();
    }
  });

  it("never releases a call that policy denied", async () => {
    const h = await harness();
    try {
      const storeDb = new ApprovalStore(join(dir, "approvals.sqlite"));
      const store = storeDb.scoped(SCOPE);
      // As wide as the schema allows: it still must not reach a denied tool,
      // because a grant is only ever consulted on an "approve" verdict.
      const grant = store.createGrant({
        tool_match: "{create,delete}_*",
        expires_at: Date.now() + 60_000,
        max_uses: 10,
        reason: "deliberately over-broad",
        created_by: "alice"
      });
      storeDb.close();

      const result = await h.client.callTool({ name: "delete_invoice", arguments: { invoice_id: "inv_1" } });
      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain("Refused by policy");
      expect(received).toHaveLength(0);

      const afterDb = new ApprovalStore(join(dir, "approvals.sqlite"));
      const after = afterDb.scoped(SCOPE);
      expect(after.getGrant(grant.id)!.uses).toBe(0);
      afterDb.close();
    } finally {
      await h.close();
    }
  });
});

/** Polls a condition the exposure timer is expected to make true. */
async function waitFor(check: () => Promise<boolean>, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error("condition was never met");
}

describe("the console's exposure switch", () => {
  /** What the console writes when someone flips the switch. */
  function switchOff(tool: string, reason = "switched off for the test"): void {
    const storeDb = new ApprovalStore(join(dir, "approvals.sqlite"), dir);
    const store = storeDb.scoped(SCOPE);
    store.disableTool(tool, "reviewer", reason);
    storeDb.close();
  }

  function switchOn(tool: string): void {
    const storeDb = new ApprovalStore(join(dir, "approvals.sqlite"), dir);
    const store = storeDb.scoped(SCOPE);
    store.enableTool(tool);
    storeDb.close();
  }

  it("stops a read policy allows, without touching the upstream, and records why", async () => {
    const h = await harness();
    // Works first, so the refusal below is attributable to the switch alone.
    expect(textOf(await h.client.callTool({ name: "list_invoices", arguments: {} }))).toContain("inv_1");
    const callsBefore = received.length;

    switchOff("list_invoices", "noisy during the incident");
    const result = await h.client.callTool({ name: "list_invoices", arguments: {} });

    expect((result as { isError?: boolean }).isError).toBe(true);
    expect(textOf(result)).toContain("exposure.disabled");
    expect(textOf(result)).toContain("noisy during the incident");
    // The point of enforcing it in the pipeline rather than only in the
    // advertised list: nothing reached the API.
    expect(received.length).toBe(callsBefore);

    const records = readAuditLog(join(dir, "audit.jsonl"));
    const last = records.at(-1)!;
    expect(last.tool).toBe("list_invoices");
    expect(last.decision).toBe("deny");
    expect(last.rule_id).toBe("exposure.disabled");
    expect(last.outcome).toBe("denied");
    expect(verifyAuditLog(join(dir, "audit.jsonl")).ok).toBe(true);
    await h.close();
  });

  it("withdraws it from the advertised tool list on the next call", async () => {
    const h = await harness();
    switchOff("list_invoices");

    // Any call re-syncs the advertised set, so the switch takes effect in a
    // server that is already running, with no restart.
    await h.client.callTool({ name: "create_invoice", arguments: { amount: 10, currency: "usd" } });

    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names).not.toContain("list_invoices");
    expect(names).toContain("create_invoice");
    await h.close();
  });

  it("is applied before the first advertisement when it was already set", async () => {
    switchOff("delete_invoice");
    const h = await harness();
    expect((await h.client.listTools()).tools.map((t) => t.name)).not.toContain("delete_invoice");
    await h.close();
  });

  it("hands the tool back to policy when switched on, and no further", async () => {
    switchOff("list_invoices");
    switchOff("delete_invoice");
    // A hidden tool's call is rejected by the SDK before our pipeline runs, so
    // switching one back *on* is picked up by the poll rather than by a call.
    const h = await harness({ exposurePollMs: 10 });

    switchOn("list_invoices");
    switchOn("delete_invoice");
    await waitFor(async () => (await h.client.listTools()).tools.some((t) => t.name === "list_invoices"));

    // A read policy allows comes back.
    expect(textOf(await h.client.callTool({ name: "list_invoices", arguments: {} }))).toContain("inv_1");

    // A destructive tool policy denies does not: switching on clears the
    // override and nothing more, so it is refused by its own policy rule.
    const deleted = await h.client.callTool({ name: "delete_invoice", arguments: { invoice_id: "inv_1" } });
    expect((deleted as { isError?: boolean }).isError).toBe(true);
    expect(textOf(deleted)).toContain("no-deletes");
    expect(received.some((r) => r.method === "DELETE")).toBe(false);
    await h.close();
  });

  it("switches off one tool only", async () => {
    const h = await harness();
    switchOff("list_invoices");
    const held = await h.client.callTool({ name: "create_invoice", arguments: { amount: 10, currency: "usd" } });
    // Still the ordinary approve path, not the exposure refusal.
    expect(textOf(held)).toContain("Approval required");
    expect(textOf(held)).not.toContain("exposure.disabled");
    await h.close();
  });
});

describe("telling the console which policy is in force", () => {
  function state() {
    // Unscoped on purpose: runtime state is per-process, not per-tenant, so it
    // lives on the store itself rather than on a scoped view.
    const store = new ApprovalStore(join(dir, "approvals.sqlite"), dir);
    const row = store.runtimeState(SCOPE.component);
    store.close();
    return row;
  }

  it("announces the digest of the policy it parsed, as soon as it is constructed", async () => {
    // Before connect(), because a console may well be reading while a server
    // is still coming up, and an absent row there would read as "not running".
    const h = await harness();
    try {
      const row = state()!;
      expect(row.policy_digest).toBe(policyDigest(policy()));
      expect(row.pid).toBe(process.pid);
      expect(row.started_at).toBeGreaterThan(0);
    } finally {
      await h.close();
    }
  });

  it("announces the policy it was given, not whatever is on disk now", async () => {
    // The whole point: this process holds a parsed copy, and a later edit to
    // the file must not make the row agree with it.
    const h = await harness({ policyOverrides: { egress: { allow: ["127.0.0.1"], timeout_ms: 1234 } } });
    try {
      expect(state()!.policy_digest).not.toBe(policyDigest(policy()));
    } finally {
      await h.close();
    }
  });

  it("keeps the row fresh on the exposure poll, so a live server is not read as a dead one", async () => {
    const h = await harness({ exposurePollMs: 10 });
    try {
      const before = state()!;
      await new Promise((r) => setTimeout(r, 60));
      const after = state()!;
      expect(after.last_seen).toBeGreaterThan(before.last_seen);
      // A beat is not a restart: what it reported must be untouched.
      expect(after.started_at).toBe(before.started_at);
      expect(after.policy_digest).toBe(policyDigest(policy()));
    } finally {
      await h.close();
    }
  });
});
