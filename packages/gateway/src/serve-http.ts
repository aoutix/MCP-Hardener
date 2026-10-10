import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID } from "node:crypto";
import {
  ADMIN_DENIED_RULE,
  ExposureAuditFailed,
  HttpError,
  TenantError,
  TenantVerifier,
  applyExposureChange,
  bearerToken,
  parseExposureChange,
  readBody,
  tokenActor,
  unprocessable,
  type ToolExposureRow
} from "@hmcp/core";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { Gateway, GatewayAuthExtra } from "./gateway.js";

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

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body, null, 2));
}

function methodNotAllowed(res: ServerResponse, allow: string): void {
  res.setHeader("Allow", allow);
  send(res, 405, "method-not-allowed", `this route accepts ${allow}`);
}

function describeRow(row: ToolExposureRow | undefined): { setBy: string; setAt: number; reason: string } | null {
  return row ? { setBy: row.set_by, setAt: row.set_at, reason: row.reason } : null;
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

  /*
   * Refuse to start rather than serve many tenants out of one scope.
   *
   * Over HTTP every stored row is filed under the tenant, so an unverified
   * tenant means anyone can file under anyone. The dangerous outcome is not a
   * crash, it is a server that comes up looking fine and quietly puts every
   * customer in the same bucket -- or lets one name themselves as another.
   * A policy with no tenant at all is allowed: that is a single-tenant
   * deployment that happens to be reachable over a socket, and it says so.
   */
  const tenantConfig = gateway.tenantConfig;
  if (tenantConfig && tenantConfig.source.kind !== "jwt-verified") {
    throw new Error(
      `this gateway is configured with tenant.source.kind "${tenantConfig.source.kind}", which resolves ` +
        `one tenant for the whole process. Serving over HTTP means many callers share it, so the tenant ` +
        `has to come from the request: use kind "jwt-verified". Remove the tenant block if this really is ` +
        `a single-tenant deployment.`
    );
  }
  const verifier =
    tenantConfig?.source.kind === "jwt-verified"
      ? new TenantVerifier(tenantConfig.source, gateway.egressGuard)
      : undefined;

  /*
   * An admin surface with no way to authenticate anybody is the worst thing
   * this process could put on a socket, so it refuses to start rather than
   * serving one. A deployment with no identity provider is not left without
   * a switch: that is what `hmcp-gateway exposure` is for.
   */
  const admin = gateway.adminConfig;
  if (admin && !verifier) {
    throw new Error(
      `this gateway has an "admin" policy block but no verified tenant source, so there is no way to tell ` +
        `an administrator from anyone else. Configure tenant.source.kind "jwt-verified", or drop the admin ` +
        `block and use "hmcp-gateway exposure" instead.`
    );
  }
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

  /**
   * The administrative surface: three routes, one tenant, one bit.
   *
   * The tenant is always the one this caller's own token proved. It is never
   * a path segment and never a body field -- a "act for any tenant" mode is
   * a different trust model, and cross-tenant work belongs to whoever holds
   * the database file, which is the CLI.
   */
  async function handleAdmin(url: URL, req: IncomingMessage, res: ServerResponse, auth: AuthInfo): Promise<void> {
    // Written by the verification step above, which is the only way to
    // reach here: `isAdminPath` implies `admin`, and `admin` implies a
    // verifier, so `auth` is always present and always carries both.
    const { tenant, actor } = auth.extra as unknown as GatewayAuthExtra;
    const scoped = gateway.scopedFor(tenant);

    if (!(auth.scopes ?? []).includes(admin!.scope)) {
      /*
       * Audited, unlike a token that fails verification. This one named a
       * tenant, so there is somewhere to file it; an unverified token
       * establishes nothing, and letting it append to a hash-chained log
       * would make the log an amplifier.
       */
      const tool = url.pathname.startsWith("/admin/v1/exposure/")
        ? decodeURIComponent(url.pathname.slice("/admin/v1/exposure/".length))
        : url.pathname;
      gateway.adminAudit(actor, `admin:${randomUUID()}`).append({
        tool,
        decision: "deny",
        outcome: "denied",
        tenant,
        rule_id: ADMIN_DENIED_RULE,
        reason: `${actor} asked to administer this gateway without the required scope`
      });
      send(res, 403, "forbidden", "this token does not carry the scope required to administer this gateway");
      return;
    }

    const path = url.pathname.slice("/admin/v1/".length);

    if (path === "tools") {
      if (req.method !== "GET") return methodNotAllowed(res, "GET");
      const off = new Map(scoped.listDisabledTools().map((r) => [r.tool, r]));
      sendJson(res, 200, {
        tenant,
        tools: gateway.inventory().map((entry) => ({
          name: entry.localName,
          upstream: entry.upstream.spec.name,
          effect: entry.effect ?? null,
          effectSource: entry.effectSource,
          hiddenByPolicy: entry.hidden,
          injection: entry.injection?.patternIds ?? null,
          disabled: describeRow(off.get(entry.localName))
        }))
      });
      return;
    }

    if (path === "exposure") {
      if (req.method !== "GET") return methodNotAllowed(res, "GET");
      sendJson(res, 200, {
        tenant,
        disabled: scoped.listDisabledTools().map((r) => ({ tool: r.tool, ...describeRow(r) }))
      });
      return;
    }

    if (path.startsWith("exposure/")) {
      if (req.method !== "PUT") return methodNotAllowed(res, "PUT");
      const tool = decodeURIComponent(path.slice("exposure/".length));
      // Validated against the live surface, so a typo cannot write an orphan
      // row that looks like protection and guards nothing.
      const entry = gateway.inventory().find((e) => e.localName === tool);
      if (!entry) {
        send(res, 404, "not-found", `this gateway exposes no tool named ${JSON.stringify(tool)}`);
        return;
      }
      const body = ((await readBody(req)) ?? {}) as Record<string, unknown>;
      let change;
      try {
        change = parseExposureChange({ tool, disabled: body["disabled"], reason: body["reason"] ?? "" });
      } catch (err) {
        throw unprocessable(`invalid exposure change: ${(err as Error).message}`);
      }

      try {
        const result = applyExposureChange({
          scoped,
          audit: gateway.adminAudit(actor, `admin:${randomUUID()}`),
          change,
          actor,
          effect: entry.effect ?? null,
          channel: "the admin API"
        });
        sendJson(res, 200, {
          tool,
          tenant,
          ...result,
          exposure: describeRow(scoped.toolExposure(tool))
        });
      } catch (err) {
        if (err instanceof ExposureAuditFailed) throw new HttpError(500, "audit-failed", err.message);
        throw err;
      }
      return;
    }

    send(res, 404, "not-found", "no such admin route");
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

    /*
     * Two surfaces, and nothing about exposure appears on the first one.
     *
     * `/mcp` is what the model talks to. An exposure switch reachable there
     * would be reachable through the exact channel it exists to restrain:
     * upstream tool results are untrusted text this gateway already scans for
     * injection, so one injected result would be one call away from the model
     * clearing its own kill switch, or disabling the tenant's whole surface.
     * Even a read-only "list the switches" tool would hand it a map of the
     * levers. The agent learns a tool is off from the refusal, which is all
     * it needs.
     *
     * `/admin/v1` is what a person talks to, and it exists only when an
     * `admin` block is configured -- otherwise these paths are an ordinary
     * 404, because a 403 would confirm the feature is there.
     */
    const url = new URL(req.url ?? "/", `http://${name}`);
    const isAdminPath = admin !== undefined && url.pathname.startsWith("/admin/v1/");
    if (url.pathname !== "/mcp" && !isAdminPath) {
      send(res, 404, "not-found", "the MCP endpoint is at /mcp");
      return;
    }

    /*
     * Authenticate before anything stateful. The token is verified on every
     * request rather than once per session: a session id is not a credential,
     * and binding authorization to it would mean a token that has since
     * expired or been revoked keeps working for as long as the client holds
     * the session open.
     */
    let auth: AuthInfo | undefined;
    if (verifier) {
      const header = tenantConfig?.source.kind === "jwt-verified" ? tenantConfig.source.header_name : "authorization";
      const token = bearerToken(req.headers, header);
      if (!token) {
        res.setHeader("WWW-Authenticate", 'Bearer realm="hmcp-gateway"');
        send(res, 401, "unauthorized", `this gateway requires a bearer token in the ${header} header`);
        return;
      }
      try {
        const claim = await verifier.verify(token);
        /*
         * One token must not be able to do both jobs. An agent holding a
         * token that carries the admin scope could clear its own kill switch
         * over this surface, which is the single thing the switch exists to
         * prevent -- and "don't mint agent tokens with the admin scope" is a
         * convention, not a control. This makes it a control. It breaks the
         * deployment where one human's token does everything, which is
         * exactly the configuration being refused.
         */
        if (admin && url.pathname === "/mcp" && claim.scopes.includes(admin.scope)) {
          send(
            res,
            403,
            "forbidden",
            `this token carries the ${admin.scope} scope, which administers the gateway. An agent must ` +
              `present a token without it; administration happens on /admin/v1, not here.`
          );
          return;
        }
        // Computed once. `clientId` carries the same value rather than a
        // second, differently-formatted copy of "who is calling".
        const actor = tokenActor(claim.subject);
        const extra: GatewayAuthExtra = { tenant: claim.tenant, actor };
        auth = { token, clientId: actor, scopes: [...claim.scopes], extra: { ...extra } };
      } catch (err) {
        if (err instanceof TenantError) {
          send(res, 403, "forbidden", err.message);
          return;
        }
        throw err;
      }
    }

    const id = req.headers["mcp-session-id"];
    const sessionId = Array.isArray(id) ? id[0] : id;

    // The SDK reads the credential off the request object and surfaces it to
    // handlers as `extra.authInfo`; this is its designated hook.
    const authed = req as IncomingMessage & { auth?: AuthInfo };
    if (auth) authed.auth = auth;

    try {
      // Inside the try, so an HttpError it raises reaches the mapping below
      // rather than escaping as a 500.
      if (isAdminPath) {
        await handleAdmin(url, req, res, auth!);
        return;
      }

      if (sessionId) {
        const session = sessions.get(sessionId);
        if (!session) {
          // The spec's answer for a session the server no longer holds; the
          // client is expected to initialize again rather than retry.
          send(res, 404, "no-session", "unknown or expired MCP session; initialize again");
          return;
        }
        session.lastSeen = Date.now();
        await session.transport.handleRequest(authed, res);
        return;
      }

      // No session id: either an initialize, or a client that has lost its
      // session. The transport tells the two apart and answers accordingly.
      const session = await openSession();
      await session.transport.handleRequest(authed, res);
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
