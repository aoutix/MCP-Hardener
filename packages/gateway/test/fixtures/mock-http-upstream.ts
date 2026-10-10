import { createServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

/**
 * An MCP server over HTTP that records what actually arrived on the wire.
 *
 * The stdio fixture proves which *calls* reached an upstream; this one proves
 * which *headers* did, which is the only way to check a credential
 * pass-through without taking the gateway's word for it.
 */
export interface MockHttpUpstream {
  readonly url: string;
  /** Every request's authorization header, in order, including undefined. */
  readonly auth: (string | undefined)[];
  /** Headers of the request that carried a tools/call, if any. */
  readonly seen: Record<string, string | string[] | undefined>[];
  /** Respond 401 to the next tools/call, to exercise the rejection path. */
  reject401: boolean;
  /** Redirect the next request here, to exercise the egress redirect rule. */
  redirectTo: string | null;
  close(): Promise<void>;
}

export async function startMockHttpUpstream(): Promise<MockHttpUpstream> {
  const auth: (string | undefined)[] = [];
  const seen: Record<string, string | string[] | undefined>[] = [];
  const sessions = new Map<string, StreamableHTTPServerTransport>();
  const state = { reject401: false, redirectTo: null as string | null };

  function build(): McpServer {
    const server = new McpServer({ name: "mock-http-upstream", version: "1.0.0" });
    server.registerTool(
      "get_note",
      { description: "Fetch a note.", inputSchema: { id: z.string() }, annotations: { readOnlyHint: true } },
      ({ id }) => ({ content: [{ type: "text" as const, text: `note ${id}` }] })
    );
    return server;
  }

  const http = createServer((req, res) => {
    void (async () => {
      const header = req.headers["authorization"];
      auth.push(Array.isArray(header) ? header[0] : header);
      seen.push({ ...req.headers });

      if (state.redirectTo) {
        res.writeHead(302, { location: state.redirectTo });
        res.end();
        return;
      }

      if (state.reject401) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "nope" }));
        return;
      }

      const raw = req.headers["mcp-session-id"];
      const id = Array.isArray(raw) ? raw[0] : raw;
      const existing = id ? sessions.get(id) : undefined;
      if (existing) {
        await existing.handleRequest(req, res);
        return;
      }
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid) => sessions.set(sid, transport)
      });
      await build().connect(transport);
      await transport.handleRequest(req, res);
    })().catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
  const port = (http.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}/mcp`,
    auth,
    seen,
    get reject401() {
      return state.reject401;
    },
    set reject401(v: boolean) {
      state.reject401 = v;
    },
    get redirectTo() {
      return state.redirectTo;
    },
    set redirectTo(v: string | null) {
      state.redirectTo = v;
    },
    close: () =>
      new Promise<void>((resolve) => {
        for (const t of sessions.values()) void t.close().catch(() => undefined);
        (http as HttpServer).close(() => resolve());
      })
  };
}
