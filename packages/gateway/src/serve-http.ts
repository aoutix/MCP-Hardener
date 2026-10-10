import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID } from "node:crypto";
import { HttpError } from "@hmcp/core";
import type { Gateway } from "./gateway.js";

/**
 * Serving the gateway over HTTP instead of stdio.
 *
 * A stdio gateway is one process for one client, started by that client. This
 * is the other shape: one long-lived process that many clients connect to,
 * which is what a vendor hosting a gateway for its customers actually runs.
 *
 * The console's HTTP layer is not reused, and the reasons are worth stating
 * because the overlap looks larger than it is. Three of its four gates would
 * reject every MCP client outright: it refuses anything not from loopback, it
 * requires an `Origin` header on any mutating request, and it demands a
 * session cookie plus a double-submit CSRF token. All three are correct for a
 * privileged browser surface on a developer's machine. An MCP client is not a
 * browser — it sends no Origin, holds no cookie, and every one of its calls is
 * a POST. The one gate that does transfer is the Host allowlist, and it is
 * reimplemented here rather than shared, because the console derives it from
 * its own fixed loopback binding and this does not.
 */

export interface ServeHttpOptions {
  readonly port: number;
  /** Interface to bind. Defaults to loopback: widening it is a decision. */
  readonly host?: string;
  /**
   * Hosts this server will answer to, as they appear in the `Host` header.
   *
   * The Streamable HTTP spec requires this check, and not for politeness:
   * without it any web page can point a script at `http://localhost:<port>`
   * and, because DNS rebinding makes the browser believe it is same-origin,
   * drive an MCP server running on the visitor's machine. The allowlist is
   * what makes the server refuse to answer to a name it was not deployed
   * under.
   */
  readonly allowedHosts?: readonly string[];
  /** How long a session may sit idle before it is dropped. */
  readonly sessionIdleMs?: number;
}

/** One client's protocol state. Everything expensive lives on the Gateway. */
interface Session {
  readonly server: Awaited<ReturnType<Gateway["newSessionServer"]>>["server"];
  readonly transport: StreamableHTTPServerTransport;
  lastSeen: number;
}

export interface ServingHttp {
  readonly http: HttpServer;
  readonly port: number;
  readonly sessionCount: () => number;
  close(): Promise<void>;
}

const DEFAULT_IDLE_MS = 10 * 60 * 1000;

function securityHeaders(res: ServerResponse): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
}

function send(res: ServerResponse, status: number, code: string, message: string): void {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({ error: { code, message } }, null, 2));
}

/**
 * The `Host` header without its port, lowercased.
 *
 * Compared without the port deliberately: the port is not a security boundary
 * — anything that can reach the socket knows it — while the name is what a
 * rebinding attack has to forge.
 */
function hostName(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const value = raw.trim().toLowerCase();
  if (value.startsWith("[")) return value.slice(0, value.indexOf("]") + 1);
  const colon = value.lastIndexOf(":");
  return colon === -1 ? value : value.slice(0, colon);
}

export async function serveHttp(gateway: Gateway, options: ServeHttpOptions): Promise<ServingHttp> {
  const host = options.host ?? "127.0.0.1";
  const idleMs = options.sessionIdleMs ?? DEFAULT_IDLE_MS;
  const allowed = new Set(
    (options.allowedHosts ?? ["127.0.0.1", "localhost", "[::1]"]).map((h) => h.toLowerCase())
  );
  const sessions = new Map<string, Session>();

  function drop(id: string): void {
    const session = sessions.get(id);
    if (!session) return;
    sessions.delete(id);
    void session.transport.close().catch(() => undefined);
    void session.server.close().catch(() => undefined);
  }

  /*
   * A client that goes away without a DELETE leaves its session behind, and a
   * long-lived hosted process would accumulate them for ever. The sweep is
   * unreferenced so it never keeps the process alive on its own.
   */
  const sweeper = setInterval(() => {
    const cutoff = Date.now() - idleMs;
    for (const [id, session] of sessions) if (session.lastSeen < cutoff) drop(id);
  // A quarter of the TTL, so a session is dropped within 25%% of its deadline
  // rather than whenever a fixed timer next happens to fire. Floored so a
  // short TTL cannot turn this into a hot loop.
  }, Math.max(250, Math.floor(idleMs / 4)));
  sweeper.unref?.();

  async function openSession(): Promise<Session> {
    const { server } = gateway.newSessionServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, session);
        session.lastSeen = Date.now();
      }
    });
    const session: Session = { server, transport, lastSeen: Date.now() };
    await server.connect(transport);
    /*
     * The transport is the authority on when a session ends -- a DELETE, a
     * dropped connection -- so eviction hangs off it rather than being
     * inferred here. Chained *after* connect and around whatever the SDK
     * installed, because `Protocol.connect` assigns `transport.onclose`
     * itself: setting it beforehand looks right and is silently discarded.
     */
    const inner = transport.onclose;
    transport.onclose = () => {
      inner?.();
      const id = transport.sessionId;
      if (id) sessions.delete(id);
    };
    return session;
  }

  const http = createServer((req, res) => {
    void handle(req, res).catch((err) => {
      process.stderr.write(`[hmcp-gateway] ${(err as Error).stack ?? err}\n`);
      if (!res.headersSent) send(res, 500, "internal", "the gateway failed to handle this request");
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    securityHeaders(res);

    const name = hostName(req.headers.host);
    if (!name || !allowed.has(name)) {
      // Before anything else, including before the session lookup: a request
      // that fails this check must not be able to learn whether a session id
      // exists.
      send(res, 403, "forbidden", `this gateway does not answer to host ${JSON.stringify(req.headers.host ?? "")}`);
      return;
    }

    const url = new URL(req.url ?? "/", `http://${name}`);
    if (url.pathname !== "/mcp") {
      send(res, 404, "not-found", "the MCP endpoint is at /mcp");
      return;
    }

    const id = req.headers["mcp-session-id"];
    const sessionId = Array.isArray(id) ? id[0] : id;

    try {
      if (sessionId) {
        const session = sessions.get(sessionId);
        if (!session) {
          // The spec's answer for a session the server no longer holds; the
          // client is expected to initialize again rather than retry.
          send(res, 404, "no-session", "unknown or expired MCP session; initialize again");
          return;
        }
        session.lastSeen = Date.now();
        await session.transport.handleRequest(req, res);
        return;
      }

      // No session id: either an initialize, or a client that has lost its
      // session. The transport tells the two apart and answers accordingly.
      const session = await openSession();
      await session.transport.handleRequest(req, res);
    } catch (err) {
      if (err instanceof HttpError) {
        send(res, err.status, err.code, err.message);
        return;
      }
      throw err;
    }
  }

  await new Promise<void>((resolve) => http.listen(options.port, host, resolve));
  const address = http.address();
  const port = typeof address === "object" && address ? address.port : options.port;

  return {
    http,
    port,
    sessionCount: () => sessions.size,
    async close() {
      clearInterval(sweeper);
      for (const id of [...sessions.keys()]) drop(id);
      await new Promise<void>((resolve) => http.close(() => resolve()));
    }
  };
}
