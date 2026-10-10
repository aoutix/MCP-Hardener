import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname } from "node:path";
import {
  ApprovalStore,
  NO_TENANT,
  expandPath,
  generatedPaths,
  loadPolicy,
  resolveTenant,
  type Policy,
  type RegistryEntry,
  type Scope,
  type ScopedApprovals
} from "@hmcp/core";
import { parseToolsFile, type ToolsFile } from "@hmcp/server-runtime";
import { loadGatewayConfig, type LoadedGatewayConfig } from "hmcp-gateway";

/**
 * One registered server, resolved from disk.
 *
 * Parsing goes through the same `parseToolsFile` and `loadPolicy` the runtime
 * uses at boot, so the console cannot show a server that the runtime would
 * refuse to start.
 */
export interface LoadedServer {
  readonly entry: RegistryEntry;
  /** Base for resolving relative paths in the policy. */
  readonly cwd: string;
  readonly policy: Policy;
  readonly policyPath: string;
  readonly tools: ToolsFile | null;
  readonly toolsPath: string | null;
  readonly gateway: LoadedGatewayConfig | null;
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
  if (entry.kind === "gateway") return loadGatewayEntry(entry);
  return loadGeneratedEntry(entry);
}

function loadGeneratedEntry(entry: RegistryEntry & { kind: "generated" }): LoadedServer {
  const { toolsPath, policyPath } = generatedPaths(entry);
  if (!existsSync(toolsPath)) throw new Error(`no tools.json at ${toolsPath}`);
  if (!existsSync(policyPath)) throw new Error(`no policy.yaml at ${policyPath}`);

  const tools = parseToolsFile(JSON.parse(readFileSync(toolsPath, "utf8")), toolsPath);
  const policy = loadPolicy(policyPath);
  const cwd = dirname(toolsPath);

  return {
    entry,
    cwd,
    policy,
    policyPath,
    tools,
    toolsPath,
    gateway: null,
    // Mirrors how the runtime labels its own records, so attribution lines up
    // with what is already in existing logs.
    component: entry.component ?? `generated:${tools.api.title}`,
    auditPath: expandPath(policy.audit.path, cwd),
    storePath: expandPath(policy.approvals.store_path, cwd),
    ...resolveTenantSafely(policy),
    mtimes: { [toolsPath]: mtime(toolsPath), [policyPath]: mtime(policyPath) }
  };
}

function loadGatewayEntry(entry: RegistryEntry & { kind: "gateway" }): LoadedServer {
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
    tools: null,
    toolsPath: null,
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
 * The scope this server's rows live under in that store.
 *
 * The console reads a shared database — one file commonly holds rows for
 * several servers — so every read it makes has to say whose rows it wants.
 * Until this existed it did not, and the nearest thing to a filter was a
 * cosmetic check that a row's tool name appeared in this server's tools.json,
 * which told two deployments of the same server apart not at all.
 */
export function scopeOf(server: LoadedServer): Scope {
  return { component: server.component, tenant: server.tenantValue ?? NO_TENANT };
}

/** `storeFor` already narrowed to this server and its tenant. */
export function scopedFor(server: LoadedServer): ScopedApprovals {
  return storeFor(server).scoped(scopeOf(server));
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
