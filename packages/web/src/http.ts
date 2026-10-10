import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, extname, join, normalize, resolve, sep } from "node:path";
import {
  HttpError,
  MAX_BODY_BYTES,
  badRequest,
  constantTimeEquals,
  expandPath,
  readBody,
  conflict,
  notFound,
  unprocessable
} from "@hmcp/core";

/*
 * Re-exported so the console's own modules keep importing them from here.
 * They live in core because the gateway needs them too and must not depend
 * on the console.
 */
export { HttpError, MAX_BODY_BYTES, badRequest, conflict, notFound, unprocessable };

/**
 * The console's HTTP layer.
 *
 * This process can approve a write that an agent was refused, so it is a
 * privileged surface and is treated as one: loopback only, an explicit token,
 * a Host check that closes DNS rebinding against the console itself, and a
 * double-submit token on everything that mutates.
 */


export interface RequestContext {
  readonly method: string;
  readonly path: string;
  readonly params: Readonly<Record<string, string>>;
  readonly query: URLSearchParams;
  readonly body: unknown;
  readonly actor: string;
}

export type Handler = (ctx: RequestContext) => unknown | Promise<unknown>;

export interface Route {
  readonly method: string;
  /** Path segments; a segment starting with ":" captures. */
  readonly pattern: readonly string[];
  readonly handler: Handler;
}

export function route(method: string, path: string, handler: Handler): Route {
  return { method, pattern: path.split("/").filter(Boolean), handler };
}

function matchRoute(routes: readonly Route[], method: string, segments: readonly string[]) {
  for (const r of routes) {
    if (r.method !== method) continue;
    if (r.pattern.length !== segments.length) continue;
    const params: Record<string, string> = {};
    let ok = true;
    for (const [i, part] of r.pattern.entries()) {
      const actual = segments[i]!;
      if (part.startsWith(":")) params[part.slice(1)] = decodeURIComponent(actual);
      else if (part !== actual) {
        ok = false;
        break;
      }
    }
    if (ok) return { route: r, params };
  }
  return null;
}

/* --------------------------------------------------------------------- token */

/**
 * A token on disk, readable only by its owner.
 *
 * Anyone who can read this file can approve a destructive call, so a
 * group- or world-readable token is treated as a configuration error rather
 * than tolerated.
 */
export function loadOrCreateToken(path = expandPath("~/.hmcp/web-token")): string {
  if (existsSync(path)) {
    const mode = statSync(path).mode & 0o077;
    if (mode !== 0) {
      throw new Error(
        `${path} is readable by other users (mode ${mode.toString(8)}). ` +
          "Anyone who can read it can approve a write. Run: chmod 600 " +
          path
      );
    }
    return readFileSync(path, "utf8").trim();
  }
  const token = randomBytes(32).toString("base64url");
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${token}\n`, { encoding: "utf8", mode: 0o600 });
  return token;
}


/* -------------------------------------------------------------------- static */

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".map": "application/json; charset=utf-8"
};

export interface ServeOptions {
  readonly routes: readonly Route[];
  readonly token: string;
  readonly uiDir: string;
  readonly port: number;
  readonly actor: string;
  /** Extra origins to accept, for running the Vite dev server. Off by default. */
  readonly allowOrigins?: readonly string[];
}

export function createConsoleServer(options: ServeOptions): Server {
  const sessions = new Set<string>();
  const csrfBySession = new Map<string, string>();

  return createServer((req, res) => {
    handle(req, res, options, sessions, csrfBySession).catch((err) => {
      // A stack trace or an unexpected path must not reach the client.
      process.stderr.write(`[hmcp-web] ${(err as Error).stack ?? String(err)}\n`);
      if (!res.headersSent) send(res, 500, { error: { code: "internal", message: "internal error" } });
    });
  });
}

function securityHeaders(res: ServerResponse, isApi: boolean): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  if (isApi) res.setHeader("Cache-Control", "no-store");
  else {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; " +
        "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
    );
  }
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body, null, 2);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(text);
}

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  options: ServeOptions,
  sessions: Set<string>,
  csrfBySession: Map<string, string>
): Promise<void> {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  const isApi = url.pathname.startsWith("/api/");
  securityHeaders(res, isApi);

  // 1. Loopback only. The listener is already bound to 127.0.0.1; this catches
  //    a proxy someone puts in front of it by accident.
  const remote = req.socket.remoteAddress ?? "";
  if (!["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(remote)) {
    send(res, 403, { error: { code: "forbidden", message: "this console only serves loopback requests" } });
    return;
  }

  // 2. Host check. A domain that resolves to 127.0.0.1 in order to reach this
  //    process still sends its own Host header, so this is what closes DNS
  //    rebinding against the console.
  const allowedHosts = [`127.0.0.1:${options.port}`, `localhost:${options.port}`, `[::1]:${options.port}`];
  if (!allowedHosts.includes(req.headers.host ?? "")) {
    send(res, 403, { error: { code: "forbidden", message: `unexpected Host header: ${req.headers.host}` } });
    return;
  }

  const mutating = req.method !== "GET" && req.method !== "HEAD";

  // 3. Origin, when the browser sent one.
  const origin = req.headers.origin;
  if (origin) {
    const allowed = [`http://127.0.0.1:${options.port}`, `http://localhost:${options.port}`].concat(
      options.allowOrigins ?? []
    );
    if (!allowed.includes(origin)) {
      send(res, 403, { error: { code: "forbidden", message: "cross-origin request refused" } });
      return;
    }
  } else if (mutating) {
    send(res, 403, { error: { code: "forbidden", message: "a mutating request must carry an Origin header" } });
    return;
  }

  if (!isApi) {
    serveStatic(req, res, options.uiDir);
    return;
  }

  const cookies = parseCookies(req.headers.cookie);

  // The session exchange: hand in the token printed at startup, get a cookie.
  if (url.pathname === "/api/v1/session" && req.method === "POST") {
    const body = (await readBody(req)) as { token?: unknown };
    if (typeof body?.token !== "string" || !constantTimeEquals(body.token, options.token)) {
      send(res, 401, { error: { code: "unauthorized", message: "bad token" } });
      return;
    }
    const session = randomBytes(24).toString("base64url");
    const csrf = randomBytes(24).toString("base64url");
    sessions.add(session);
    csrfBySession.set(session, csrf);
    res.setHeader("Set-Cookie", [
      `hmcp_web=${session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`,
      `hmcp_csrf=${csrf}; SameSite=Strict; Path=/; Max-Age=28800`
    ]);
    send(res, 200, { ok: true });
    return;
  }

  const session = cookies["hmcp_web"];
  if (!session || !sessions.has(session)) {
    send(res, 401, { error: { code: "unauthorized", message: "no session; reopen the URL printed at startup" } });
    return;
  }

  if (mutating) {
    // 4. Double submit. SameSite=Strict already blocks cross-site cookie
    //    attachment; this covers another local server on a different port,
    //    which is same-site for cookie purposes on loopback.
    const expected = csrfBySession.get(session);
    const supplied = req.headers["x-hmcp-csrf"];
    if (!expected || typeof supplied !== "string" || !constantTimeEquals(supplied, expected)) {
      send(res, 403, { error: { code: "forbidden", message: "missing or stale X-HMCP-CSRF header" } });
      return;
    }
    // A JSON-only body is something an HTML form cannot produce.
    const contentType = (req.headers["content-type"] ?? "").split(";")[0]!.trim();
    if (contentType !== "application/json") {
      send(res, 400, { error: { code: "bad-request", message: "Content-Type must be application/json" } });
      return;
    }
  }

  const segments = url.pathname.split("/").filter(Boolean);
  const matched = matchRoute(options.routes, req.method ?? "GET", segments);
  if (!matched) {
    send(res, 404, { error: { code: "not-found", message: `no route for ${req.method} ${url.pathname}` } });
    return;
  }

  try {
    const body = mutating ? await readBody(req) : undefined;
    const result = await matched.route.handler({
      method: req.method ?? "GET",
      path: url.pathname,
      params: matched.params,
      query: url.searchParams,
      body,
      actor: options.actor
    });
    send(res, 200, result);
  } catch (err) {
    if (err instanceof HttpError) {
      send(res, err.status, {
        error: { code: err.code, message: err.message, ...(err.detail ? { detail: err.detail } : {}) }
      });
      return;
    }
    process.stderr.write(`[hmcp-web] ${(err as Error).stack ?? String(err)}\n`);
    send(res, 500, { error: { code: "internal", message: (err as Error).message } });
  }
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    out[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return out;
}


function serveStatic(req: IncomingMessage, res: ServerResponse, uiDir: string): void {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("method not allowed\n");
    return;
  }
  if (!existsSync(uiDir)) {
    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("The console UI has not been built yet. Run:\n\n  npm run -w @hmcp/web build:ui\n");
    return;
  }

  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  let pathname: string;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    res.writeHead(400).end();
    return;
  }
  // Traversal and NUL are rejected after decoding, then the resolved path is
  // asserted to stay inside the root.
  if (pathname.includes("\0")) {
    res.writeHead(400).end();
    return;
  }
  const root = resolve(uiDir);
  const candidate = resolve(join(root, normalize(pathname)));
  const inRoot = candidate === root || candidate.startsWith(root + sep);

  const file = inRoot && existsSync(candidate) && statSync(candidate).isFile() ? candidate : join(root, "index.html");
  if (!existsSync(file)) {
    res.writeHead(404).end();
    return;
  }

  res.writeHead(200, { "Content-Type": CONTENT_TYPES[extname(file)] ?? "application/octet-stream" });
  if (req.method === "HEAD") {
    res.end();
    return;
  }
  createReadStream(file).pipe(res);
}
