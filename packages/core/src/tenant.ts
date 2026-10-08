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
