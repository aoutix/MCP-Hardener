import { readFileSync } from "node:fs";
import { expandPath, type TenantConfig } from "./policy.js";

export class TenantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TenantError";
  }
}

export interface TenantResolverOptions {
  /** Request headers, for the `header` source. Supplied per-call by the gateway. */
  readonly headers?: Record<string, string | string[] | undefined>;
  readonly env?: NodeJS.ProcessEnv;
}

function decodeJwtClaim(token: string, claim: string): string | undefined {
  const parts = token.split(".");
  if (parts.length < 2) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as Record<string, unknown>;
    const value = payload[claim];
    return value === undefined || value === null ? undefined : String(value);
  } catch {
    return undefined;
  }
}

/**
 * Produces the tenant identifier bound to the running credential. This value is
 * never taken from agent input - that is the whole point of tenant scoping, and
 * why the generator strips tenant parameters from agent-facing schemas.
 *
 * Note the `jwt-claim` source reads the claim without verifying the token's
 * signature. The token is our own credential, not attacker-supplied input, so
 * there is nothing to forge here; it is a way to avoid duplicating the tenant
 * id in a second environment variable.
 */
export function resolveTenant(config: TenantConfig, options: TenantResolverOptions = {}): string | undefined {
  const env = options.env ?? process.env;
  const source = config.source;

  switch (source.kind) {
    case "static":
      return source.value;
    case "env": {
      const raw = env[source.name];
      return raw && raw.length > 0 ? raw : undefined;
    }
    case "header": {
      const headers = options.headers ?? {};
      const wanted = source.name.toLowerCase();
      for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() !== wanted) continue;
        const v = Array.isArray(value) ? value[0] : value;
        if (v && v.length > 0) return v;
      }
      return undefined;
    }
    case "jwt-claim": {
      const raw = env[source.token_env];
      if (!raw) return undefined;
      // Accept either a bare token, an "Authorization: Bearer x" value, or a
      // path to a file holding the token.
      let token = raw.replace(/^Bearer\s+/i, "").trim();
      if (!token.includes(".") && token.length > 0) {
        try {
          token = readFileSync(expandPath(token), "utf8").trim().replace(/^Bearer\s+/i, "");
        } catch {
          return undefined;
        }
      }
      return decodeJwtClaim(token, source.name);
    }
  }
}

/** Resolves and fails loudly when the policy marks tenant scoping required. */
export function requireTenant(config: TenantConfig, options: TenantResolverOptions = {}): string | undefined {
  const value = resolveTenant(config, options);
  if (value === undefined && config.required) {
    const where =
      config.source.kind === "static"
        ? "static policy value"
        : config.source.kind === "jwt-claim"
          ? `claim "${config.source.name}" of the token in ${config.source.token_env}`
          : `${config.source.kind} "${config.source.name}"`;
    throw new TenantError(
      `tenant scoping is required but ${config.field} could not be resolved from ${where}. ` +
        `Set it, or set tenant.required to false if this deployment is genuinely single-tenant.`
    );
  }
  return value;
}

export interface TenantInjection {
  readonly path: Record<string, string>;
  readonly query: Record<string, string>;
  readonly body: Record<string, string>;
  readonly headers: Record<string, string>;
}

/**
 * Builds the server-side values to splice into an upstream request. The agent
 * never supplies these and cannot see them in a tool schema.
 */
export function tenantInjection(config: TenantConfig, value: string): TenantInjection {
  const injection: TenantInjection = { path: {}, query: {}, body: {}, headers: {} };
  for (const target of config.inject) {
    switch (target) {
      case "path":
        for (const name of [config.field, ...config.aliases]) injection.path[name] = value;
        break;
      case "query":
        injection.query[config.field] = value;
        break;
      case "body":
        injection.body[config.field] = value;
        break;
      case "header":
        if (config.header_name) injection.headers[config.header_name] = value;
        break;
    }
  }
  return injection;
}

/**
 * The reserved tenant key for "this deployment has no tenant configured".
 *
 * Empty string rather than NULL, because SQLite permits several NULLs in a
 * non-rowid PRIMARY KEY column — `tool_exposure` would quietly stop being
 * unique. Rather than a sentinel like "-", which a real tenant could be
 * called, because `resolveTenant` already rejects an empty value on both the
 * env and header branches, so no real tenant can ever be "".
 */
export const NO_TENANT = "";

/** The longest tenant key accepted. Generous for an id, short of a payload. */
const MAX_TENANT_KEY = 256;

/**
 * Canonicalises a resolved tenant before it is used as a storage key.
 *
 * Single-tenant deployments read this value from their own environment and it
 * is whatever the operator typed. Once a hosted gateway resolves it per
 * request it is attacker-influenced, and a key that can be spelled two ways is
 * a key that can be made to collide or to split: `acme` and `acme ` must not
 * become two scopes, and two different-looking strings must not become one.
 *
 * So: NFC, because the same name composed two ways in Unicode must compare
 * equal; trimmed; length-capped; and restricted to an unambiguous alphabet. A
 * control character has no business in an identifier and is how a value gets
 * smuggled past a log line or a terminal.
 */
export function normalizeTenantKey(raw: string): string {
  const value = raw.normalize("NFC").trim();
  if (value.length === 0) return NO_TENANT;
  if (value.length > MAX_TENANT_KEY) {
    throw new TenantError(
      `tenant identifier is ${value.length} characters; the maximum is ${MAX_TENANT_KEY}`
    );
  }
  if (!/^[A-Za-z0-9._:@-]+$/.test(value)) {
    throw new TenantError(
      `tenant identifier ${JSON.stringify(raw)} contains characters that are not allowed. ` +
        `Letters, digits and ".", "_", ":", "@", "-" only, so that one tenant cannot be ` +
        `spelled two ways or disguised as another.`
    );
  }
  return value;
}

/**
 * What a row in the approvals database belongs to.
 *
 * Two axes, because they answer different questions and neither implies the
 * other. `component` is which server ("generated:Billing"), and is the same
 * string for every deployment of that server. `tenant` is whose data the call
 * touches. One database holds rows for many of both.
 */
export interface Scope {
  readonly component: string;
  readonly tenant: string;
}

/** A scope for a deployment with no tenant configured. */
export function componentScope(component: string): Scope {
  return { component, tenant: NO_TENANT };
}
