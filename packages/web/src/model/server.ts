import { existsSync, statSync } from "node:fs";
import { dirname } from "node:path";
import {
  ApprovalStore,
  NO_TENANT,
  expandPath,
  normalizeTenantKey,
  queryAuditLog,
  resolveTenant,
  type Policy,
  type RegistryEntry,
  type Scope,
  type ScopedApprovals
} from "@hmcp/core";
import { loadGatewayConfig, type LoadedGatewayConfig } from "hmcp-gateway";

/**
 * One registered gateway, resolved from disk.
 *
 * Parsing goes through the gateway's own `loadGatewayConfig`, so the console
 * cannot show a gateway that the gateway itself would refuse to start.
 *
 * Note what is *not* here: the tool surface. A gateway's tools come from its
 * upstreams over MCP, which only the gateway process has spoken to, so they are
 * read separately from what that process publishes rather than from a file next
 * to the config.
 */
export interface LoadedServer {
  readonly entry: RegistryEntry;
  /** Base for resolving relative paths in the policy. */
  readonly cwd: string;
  readonly policy: Policy;
  readonly policyPath: string;
  readonly gateway: LoadedGatewayConfig;
  /** The audit `component` records from this server are expected to carry. */
  readonly component: string;
  readonly auditPath: string;
  readonly storePath: string;
  readonly tenantValue: string | undefined;
  /**
   * Why the tenant could not be resolved. The console resolves from its *own*
   * environment, so this is advisory: it means this server would fail to start
   * in this process, which is worth saying but is not the server's verdict.
   */
  readonly tenantError: string | null;
  readonly mtimes: Readonly<Record<string, number>>;
}

function mtime(path: string): number {
  try {
    return statSync(path).mtimeMs;
  } catch {
    return 0;
  }
}

export function loadServer(entry: RegistryEntry): LoadedServer {
  const configPath = expandPath(entry.config_path);
  if (!existsSync(configPath)) throw new Error(`no gateway config at ${configPath}`);
  // Reuses the gateway's own loader, which already resolves an inline-or-path
  // policy against the config's directory. Reimplementing that would be a
  // second answer to the same question.
  const gateway = loadGatewayConfig(configPath);
  const cwd = dirname(configPath);

  return {
    entry,
    cwd,
    policy: gateway.policy,
    policyPath: configPath,
    gateway,
    component: entry.component ?? `gateway:${gateway.config.name}`,
    auditPath: expandPath(gateway.policy.audit.path, cwd),
    storePath: expandPath(gateway.policy.approvals.store_path, cwd),
    ...resolveTenantSafely(gateway.policy),
    mtimes: { [configPath]: mtime(configPath) }
  };
}

/**
 * `resolveTenant`, never `requireTenant`.
 *
 * `requireTenant` throws when the value is missing, which is right at server
 * boot and wrong here: it would make the protection view unavailable for
 * exactly the server whose configuration most needs inspecting. The failure is
 * captured and rendered instead.
 */
function resolveTenantSafely(policy: Policy): { tenantValue: string | undefined; tenantError: string | null } {
  if (!policy.tenant) return { tenantValue: undefined, tenantError: null };
  try {
    const value = resolveTenant(policy.tenant);
    if (value === undefined && policy.tenant.required) {
      return {
        tenantValue: undefined,
        tenantError:
          `tenant scoping is required but no value resolved from ${describeTenantSource(policy)}. ` +
          "This server would refuse to start in this environment."
      };
    }
    return { tenantValue: value, tenantError: null };
  } catch (err) {
    return { tenantValue: undefined, tenantError: (err as Error).message };
  }
}

export function describeTenantSource(policy: Policy): string {
  const tenant = policy.tenant;
  if (!tenant) return "no tenant configuration";
  switch (tenant.source.kind) {
    case "env":
      return `the ${tenant.source.name} environment variable`;
    case "header":
      return `the ${tenant.source.name} request header`;
    case "jwt-claim":
      return `the ${tenant.source.name} claim of the token in ${tenant.source.token_env}`;
    case "jwt-verified":
      return `the verified ${tenant.source.claim} claim of the caller's token, issued by ${tenant.source.issuer}`;
    case "static":
      return "a fixed value in the policy";
  }
}

/**
 * One approval store per server, kept for the process lifetime.
 *
 * Opening and closing per request would thrash the WAL. The store's own
 * constructor already sets `journal_mode = WAL` and `busy_timeout = 5000`,
 * which is what makes sharing the file with a running server safe, so nothing
 * here opens a `DatabaseSync` directly.
 */
const stores = new Map<string, ApprovalStore>();

export function storeFor(server: LoadedServer): ApprovalStore {
  const existing = stores.get(server.storePath);
  if (existing) return existing;
  const store = new ApprovalStore(server.storePath, server.cwd);
  stores.set(server.storePath, store);
  return store;
}

/**
 * Whose rows a request is asking about.
 *
 * This is the console's single most dangerous input, so it is a decision rather
 * than a default. Approvals, grants and the exposure switch are all keyed
 * `(component, tenant)`, and the gateway reads them under the tenant it
 * resolved from the *caller's* token. If the console guesses a different one,
 * every read looks empty and — far worse — every write lands on a row nothing
 * will ever read. A kill switch written into the wrong tenant looks exactly
 * like protection and is none.
 *
 * `hmcp-gateway exposure` already refuses to guess here for the same reason.
 * The console used to guess, from `resolveTenant` over its own environment,
 * while its own comment described that value as advisory.
 */
export type TenantChoice =
  | { readonly ok: true; readonly tenant: string; readonly explicit: boolean }
  | { readonly ok: false; readonly why: string };

/**
 * Settles the tenant for one request.
 *
 * Three cases, and they differ in whether the console can legitimately know
 * the answer:
 *
 * - **No tenant configured.** The gateway scopes everything to `NO_TENANT`, so
 *   that is the only correct key and naming another one is a mistake worth
 *   refusing rather than honouring.
 * - **`jwt-verified`.** Resolved per request from the caller's token. One
 *   gateway serves every tenant at once and the console's own environment says
 *   nothing about any of them, so the request has to name one.
 * - **`static`, `env` or `jwt-claim`.** A property of the deployment, resolved
 *   once at startup, and the console reads it from the same place the gateway
 *   does. Defaulting is legitimate here — but an explicit value still wins, so
 *   an operator whose console environment differs from the gateway's can say
 *   so instead of being quietly wrong.
 */
export function chooseTenant(server: LoadedServer, requested: string | null): TenantChoice {
  const config = server.policy.tenant;

  if (!config) {
    if (requested !== null && requested !== NO_TENANT) {
      return {
        ok: false,
        why:
          `"${server.entry.id}" has no tenant configured, so every row it writes is scoped to the empty ` +
          `tenant. Asking for "${requested}" would read and write rows this gateway never touches.`
      };
    }
    return { ok: true, tenant: NO_TENANT, explicit: false };
  }

  if (requested !== null && requested !== "") {
    try {
      return { ok: true, tenant: normalizeTenantKey(requested), explicit: true };
    } catch (err) {
      return { ok: false, why: (err as Error).message };
    }
  }

  if (config.source.kind === "jwt-verified") {
    return {
      ok: false,
      why:
        `"${server.entry.id}" resolves its tenant per request, from the verified "${config.source.claim}" ` +
        `claim of the caller's token, so there is no single tenant for this console to assume. Name one ` +
        `with ?tenant=<id>. Guessing would read an empty queue and write a switch the gateway never reads.`
    };
  }

  if (server.tenantValue === undefined) {
    return {
      ok: false,
      why:
        server.tenantError ??
        `"${server.entry.id}" requires a tenant and none resolved from ${describeTenantSource(server.policy)}. ` +
        `Name one with ?tenant=<id>.`
    };
  }

  return { ok: true, tenant: server.tenantValue, explicit: false };
}

/**
 * The scope this gateway's rows live under in that store.
 *
 * The console reads a shared database — one file commonly holds rows for
 * several gateways and several tenants — so every read it makes has to say
 * whose rows it wants.
 */
export function scopeFor(server: LoadedServer, tenant: string): Scope {
  return { component: server.component, tenant };
}

/** `storeFor` already narrowed to this gateway and one named tenant. */
export function scopedFor(server: LoadedServer, tenant: string): ScopedApprovals {
  return storeFor(server).scoped(scopeFor(server, tenant));
}

/**
 * Which tenants this gateway has any trace of, so a selector can be offered
 * rather than a free-text box with no hint in it.
 *
 * Two sources, because neither alone is complete. `listScopes` covers tenants
 * with approvals, grants or exposure rows; the audit log covers one that has
 * only ever made calls, which has rows in none of those three. Both are
 * historical — a tenant that has never been seen will not appear, which is why
 * naming one by hand stays possible.
 */
export function knownTenants(server: LoadedServer, auditSample = 2000): string[] {
  const seen = new Set<string>();
  for (const scope of storeFor(server).listScopes()) {
    if (scope.component === server.component) seen.add(scope.tenant);
  }
  if (server.policy.audit.enabled) {
    try {
      for (const record of queryAuditLog(server.auditPath, { limit: auditSample }).records) {
        if (record.component === server.component) seen.add(record.tenant ?? NO_TENANT);
      }
    } catch {
      /* a missing or unreadable log costs the hint, never the page */
    }
  }
  return [...seen].sort();
}

export function closeStores(): void {
  for (const store of stores.values()) {
    try {
      store.close();
    } catch {
      /* best effort on shutdown */
    }
  }
  stores.clear();
}
