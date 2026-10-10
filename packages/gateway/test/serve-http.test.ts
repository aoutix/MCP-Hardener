import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { request } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { parsePolicy, readAuditLog } from "@hmcp/core";
import { Gateway } from "../src/gateway.js";
import { GatewayConfigSchema } from "../src/config.js";
import { serveHttp, type ServingHttp } from "../src/serve-http.js";

/**
 * The gateway over HTTP rather than stdio.
 *
 * Stdio is one process per client, started by that client. This is the shape a
 * vendor actually hosts: one process, many clients, each with its own MCP
 * session. What these pin down is that the enforcement is the same — the
 * handlers are the ones the stdio path installs — and that the things which
 * only exist over HTTP are right: a session id per client, a refusal for a
 * session the server no longer holds, and the Host check that closes DNS
 * rebinding against a server running on someone's machine.
 */

const UPSTREAM = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "mock-upstream.mjs");

let dir: string;
let serving: ServingHttp;
let gateway: Gateway;
const clients: Client[] = [];

function policy() {
  return parsePolicy({
    version: 1,
    defaults: { mode: "read-only" },
    rules: [
      { id: "reads", match: "notes__get_*", effect: "read", decision: "allow" },
      { id: "no-deletes", match: "notes__delete_*", decision: "deny", reason: "the gateway does not delete notes" }
    ],
    approvals: { mode: "cli", store_path: join(dir, "approvals.sqlite") },
    audit: { path: join(dir, "audit.jsonl") }
  });
}

async function connect(): Promise<Client> {
  const client = new Client({ name: "test-agent", version: "1.0.0" }, { capabilities: {} });
  await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${serving.port}/mcp`)));
  clients.push(client);
  return client;
}

/** A raw request, for the headers an MCP client will not let us set. */
function raw(headers: Record<string, string>, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port: serving.port,
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
    req.end(body);
  });
}

const INITIALIZE = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "raw", version: "1" } }
});

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-gwhttp-"));
  gateway = new Gateway({
    config: GatewayConfigSchema.parse({
      version: 1,
      name: "test-gateway",
      policy: { version: 1 },
      upstreams: [{ name: "notes", transport: "stdio", command: process.execPath, args: [UPSTREAM] }]
    }),
    policy: policy(),
    cwd: dir
  });
  await gateway.connectUpstreams();
  serving = await serveHttp(gateway, { port: 0 });
});

afterEach(async () => {
  for (const c of clients.splice(0)) await c.close().catch(() => undefined);
  await serving.close();
  await gateway.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("serving the same enforcement over HTTP", () => {
  it("advertises the upstream surface and runs a permitted call", async () => {
    const client = await connect();
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toContain("notes__get_note");

    const result = await client.callTool({ name: "notes__get_note", arguments: { id: "n1" } });
    const text = (result as { content: { text?: string }[] }).content.map((c) => c.text ?? "").join("");
    expect(text).toContain("n1");
  });

  it("refuses what policy refuses, with the rule that did it", async () => {
    const client = await connect();
    const result = await client.callTool({ name: "notes__delete_note", arguments: { id: "n1" } });
    expect((result as { isError?: boolean }).isError).toBe(true);
    const text = (result as { content: { text?: string }[] }).content.map((c) => c.text ?? "").join("");
    expect(text).toContain("the gateway does not delete notes");
  });
});

describe("sessions", () => {
  it("issues one per client and keeps them apart in the audit log", async () => {
    const a = await connect();
    const b = await connect();
    await a.callTool({ name: "notes__get_note", arguments: { id: "n1" } });
    await b.callTool({ name: "notes__get_note", arguments: { id: "n2" } });

    expect(serving.sessionCount()).toBe(2);

    // Only the call records: the gateway also writes startup findings about
    // untrusted upstream text, and those belong to the process rather than to
    // any client.
    const calls = readAuditLog(join(dir, "audit.jsonl")).filter((r) => r.tool === "notes__get_note");
    expect(calls).toHaveLength(2);
    // Two clients, two sessions. A single process-wide id made every call on
    // a shared gateway look like one conversation.
    expect(new Set(calls.map((r) => r.session)).size).toBe(2);
  });

  it("refuses a session it no longer holds rather than inventing one", async () => {
    const res = await raw({ "mcp-session-id": "00000000-0000-4000-8000-000000000000" }, INITIALIZE);
    expect(res.status).toBe(404);
    expect(res.body).toContain("initialize again");
  });

  it("drops one the client terminated", async () => {
    const client = await connect();
    await client.listTools();
    expect(serving.sessionCount()).toBe(1);

    // An explicit DELETE, which is what a well-behaved client sends. Simply
    // dropping the connection does not reach the server at all -- that case
    // is the sweeper's, below.
    const transport = (client as unknown as { _transport: { terminateSession(): Promise<void> } })._transport;
    await transport.terminateSession();
    clients.length = 0;
    await client.close().catch(() => undefined);

    expect(serving.sessionCount()).toBe(0);
  });

  it("sweeps one whose client vanished without saying so", async () => {
    // The case that would otherwise accumulate for ever in a hosted process:
    // a client that goes away without a DELETE leaves its session behind.
    const idle = await serveHttp(gateway, { port: 0, sessionIdleMs: 1100 });
    try {
      const client = new Client({ name: "ghost", version: "1.0.0" }, { capabilities: {} });
      await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${idle.port}/mcp`)));
      expect(idle.sessionCount()).toBe(1);

      await new Promise((r) => setTimeout(r, 1800));
      expect(idle.sessionCount()).toBe(0);
      await client.close().catch(() => undefined);
    } finally {
      await idle.close();
    }
  });
});

describe("the Host check", () => {
  it("refuses a Host it was not deployed under", async () => {
    // Without this, any web page can point a script at localhost and, via DNS
    // rebinding, drive an MCP server on the visitor's machine.
    const res = await raw({ host: "evil.example.com" }, INITIALIZE);
    expect(res.status).toBe(403);
    expect(res.body).toContain("does not answer to host");
  });

  it("refuses before it will say whether a session exists", async () => {
    const res = await raw(
      { host: "evil.example.com", "mcp-session-id": "00000000-0000-4000-8000-000000000000" },
      INITIALIZE
    );
    expect(res.status).toBe(403);
    expect(res.body).not.toContain("session");
  });

  it("answers on a name it was given", async () => {
    const res = await raw({ host: `localhost:${serving.port}` }, INITIALIZE);
    expect(res.status).toBe(200);
  });
});

describe("anything that is not the MCP endpoint", () => {
  it("is a 404, not a hint about what else is running here", async () => {
    const res = await new Promise<number>((resolve, reject) => {
      const req = request(
        { host: "127.0.0.1", port: serving.port, path: "/", method: "GET" },
        (r) => resolve(r.statusCode ?? 0)
      );
      req.on("error", reject);
      req.end();
    });
    expect(res).toBe(404);
  });
});
