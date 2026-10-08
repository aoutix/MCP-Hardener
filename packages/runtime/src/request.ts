import type { TenantConfig } from "@hmcp/core";
import { tenantInjection } from "@hmcp/core";
import type { Auth, ToolDescriptor } from "./descriptor.js";

export interface BuiltRequest {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: string | undefined;
  /** For the audit record, without the query string's values. */
  readonly auditPath: string;
}

export class RequestBuildError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RequestBuildError";
  }
}

/**
 * Assembles the upstream HTTP request from validated arguments.
 *
 * Tenant values are spliced in here, from the credential rather than from the
 * arguments, and they overwrite anything of the same name. Path segments are
 * encoded, so an argument cannot escape its placeholder and reach another route.
 */
export function buildRequest(options: {
  descriptor: ToolDescriptor;
  args: Record<string, unknown>;
  baseUrl: string;
  auth: Auth;
  tenant?: { config: TenantConfig; value: string } | undefined;
}): BuiltRequest {
  const { descriptor, args, baseUrl, auth, tenant } = options;

  const pathValues: Record<string, string> = {};
  const query = new URLSearchParams();
  const headers: Record<string, string> = { accept: "application/json" };
  const body: Record<string, unknown> = {};

  for (const [argName, raw] of Object.entries(args)) {
    if (raw === undefined) continue;
    const binding = descriptor.bindings[argName];
    if (!binding) continue; // Not bound upstream; ignore rather than forward.

    switch (binding.in) {
      case "path":
        pathValues[binding.name] = String(raw);
        break;
      case "query":
        appendQuery(query, binding.name, raw, descriptor, argName);
        break;
      case "header":
        headers[binding.name] = String(raw);
        break;
      case "body":
        body[binding.name] = raw;
        break;
    }
  }

  // Tenant injection last, so it cannot be overwritten by an argument.
  if (tenant) {
    const injection = tenantInjection(tenant.config, tenant.value);
    for (const [name, value] of Object.entries(injection.path)) pathValues[name] = value;
    for (const [name, value] of Object.entries(injection.query)) query.set(name, value);
    for (const [name, value] of Object.entries(injection.headers)) headers[name] = value;
    if (descriptor.bodyMode === "json") {
      for (const [name, value] of Object.entries(injection.body)) body[name] = value;
    }
  }

  // Substitute path placeholders, encoding each value so a `/` or `..` in an
  // argument stays inside its own segment.
  const missing: string[] = [];
  const path = descriptor.path.replace(/\{([^}]+)\}/g, (_match, nameRaw: string) => {
    const name = nameRaw.trim();
    const value = pathValues[name];
    if (value === undefined || value === "") {
      missing.push(name);
      return "";
    }
    return encodeURIComponent(value);
  });
  if (missing.length > 0) {
    throw new RequestBuildError(
      `cannot build the upstream request: no value for path parameter(s) ${missing.join(", ")}`
    );
  }

  const url = new URL(joinPath(baseUrl, path));
  for (const [key, value] of query) url.searchParams.append(key, value);

  applyAuth(auth, headers, url);

  const hasBody = descriptor.bodyMode === "json" && Object.keys(body).length > 0;
  if (hasBody) headers["content-type"] = descriptor.bodyContentType;

  return {
    url: url.toString(),
    method: descriptor.method.toUpperCase(),
    headers,
    body: hasBody ? JSON.stringify(body) : undefined,
    auditPath: path
  };
}

function appendQuery(
  query: URLSearchParams,
  name: string,
  raw: unknown,
  descriptor: ToolDescriptor,
  argName: string
): void {
  let value = raw;
  // A pagination ceiling is enforced here, not merely advertised in the schema,
  // so an unbounded list cannot be requested even if the schema is edited.
  if (descriptor.paginationCap && descriptor.paginationCap.param === argName) {
    const n = Number(value);
    if (Number.isFinite(n)) value = Math.min(n, descriptor.paginationCap.max);
  }
  if (Array.isArray(value)) {
    for (const item of value) query.append(name, String(item));
  } else {
    query.append(name, String(value));
  }
}

function joinPath(baseUrl: string, path: string): string {
  const base = baseUrl.replace(/\/+$/, "");
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return `${base}${suffix}`;
}

function applyAuth(auth: Auth, headers: Record<string, string>, url: URL): void {
  if (auth.kind === "none") return;
  const secret = process.env[auth.env];
  if (!secret) {
    throw new RequestBuildError(
      `upstream credential is missing: set ${auth.env} in the environment. ` +
        `It is read at call time and never written to the audit log.`
    );
  }
  switch (auth.kind) {
    case "bearer":
      headers["authorization"] = `Bearer ${secret}`;
      break;
    case "header":
      headers[auth.name] = secret;
      break;
    case "query":
      url.searchParams.set(auth.name, secret);
      break;
    case "basic":
      headers["authorization"] = secret.includes(":")
        ? `Basic ${Buffer.from(secret).toString("base64")}`
        : `Basic ${secret}`;
      break;
  }
}

/** Applies a pagination ceiling to arguments before they are audited. */
export function clampPagination(
  descriptor: ToolDescriptor,
  args: Record<string, unknown>
): Record<string, unknown> {
  const cap = descriptor.paginationCap;
  if (!cap) return args;
  const current = args[cap.param];
  const n = current === undefined ? cap.max : Number(current);
  if (!Number.isFinite(n)) return { ...args, [cap.param]: cap.max };
  return n > cap.max ? { ...args, [cap.param]: cap.max } : args;
}
