import type { Effect, TenantConfig } from "@hmcp/core";
import { anyGlobMatch } from "@hmcp/core";
import type { Manifest, ManifestTool, Operation, ParsedSpec } from "./types.js";

/** Spec extension that lets an API author classify an operation explicitly. */
export const EFFECT_EXTENSION = "x-hmcp-effect";

/**
 * Paths that commonly express a read as a POST, because the query is too large
 * for a URL. These are *not* reclassified automatically - they are surfaced for
 * a human to confirm, because guessing wrong here turns a write loose.
 */
const READ_SHAPED_POST = /(^|\/)(search|query|lookup|filter|batch-?get|resolve|export|report|validate|preview)(\/|$)/i;

export interface EffectInference {
  readonly effect: Effect;
  /** Set when a human should confirm the classification. */
  readonly review?: string;
}

/**
 * Classifies an operation by HTTP method, which is the only signal that is
 * reliable across specs. DELETE is destructive, POST/PUT/PATCH write, the safe
 * methods read.
 */
export function inferEffect(operation: Operation): EffectInference {
  const declared = (operation as unknown as Record<string, unknown>)[EFFECT_EXTENSION];
  if (declared === "read" || declared === "write" || declared === "destructive") {
    return { effect: declared };
  }

  switch (operation.method) {
    case "GET":
    case "HEAD":
    case "OPTIONS":
    case "TRACE":
      return { effect: "read" };
    case "DELETE":
      return { effect: "destructive" };
    case "POST":
      if (READ_SHAPED_POST.test(operation.path)) {
        return {
          effect: "write",
          review:
            `${operation.method} ${operation.path} looks like a read expressed as a POST. ` +
            `It is classified as a write until you confirm otherwise - change effect to "read" if it has no side effects.`
        };
      }
      return { effect: "write" };
    case "PUT":
    case "PATCH":
      return { effect: "write" };
    default:
      return { effect: "write" };
  }
}

/** Snake-cases an operationId into a tool name. */
export function toToolName(operationId: string): string {
  const name = operationId
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .toLowerCase();
  return name.length > 0 ? name : "operation";
}

/**
 * Assigns a unique tool name per operation. Collisions are resolved
 * deterministically by appending the method and path shape, so regenerating the
 * same spec always produces the same names.
 */
export function assignToolNames(operations: readonly Operation[]): Map<Operation, string> {
  const byName = new Map<string, Operation[]>();
  for (const operation of operations) {
    const base = toToolName(operation.operationId);
    const bucket = byName.get(base);
    if (bucket) bucket.push(operation);
    else byName.set(base, [operation]);
  }

  const assigned = new Map<Operation, string>();
  const used = new Set<string>();
  for (const [base, bucket] of [...byName.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    if (bucket.length === 1 && !used.has(base)) {
      assigned.set(bucket[0]!, base);
      used.add(base);
      continue;
    }
    for (const operation of bucket) {
      let candidate = toToolName(`${base}_${operation.method}_${pathShape(operation.path)}`);
      let suffix = 2;
      while (used.has(candidate)) candidate = `${candidate}_${suffix++}`;
      assigned.set(operation, candidate);
      used.add(candidate);
    }
  }
  return assigned;
}

function pathShape(path: string): string {
  return path
    .split("/")
    .filter((s) => s.length > 0)
    .map((s) => (s.startsWith("{") ? `by_${s.replace(/[{}]/g, "")}` : s))
    .join("_");
}

/** Parameter names that look like a tenant boundary when no policy names one. */
const TENANT_HINTS = [
  "tenant_id",
  "tenantid",
  "org_id",
  "orgid",
  "organization_id",
  "organisation_id",
  "account_id",
  "accountid",
  "workspace_id",
  "customer_id",
  "company_id",
  "project_id"
];

/** True when this parameter name is the tenant boundary the policy describes. */
export function isTenantParam(name: string, tenant: TenantConfig | undefined): boolean {
  const normalized = name.toLowerCase();
  if (tenant) {
    return [tenant.field, ...tenant.aliases].some((f) => f.toLowerCase() === normalized);
  }
  return false;
}

/** Tenant-looking parameters, used to flag an operation that policy does not cover. */
export function tenantLookingParams(operation: Operation): string[] {
  const found = new Set<string>();
  for (const param of operation.parameters) {
    if (TENANT_HINTS.includes(param.name.toLowerCase())) found.add(param.name);
  }
  for (const name of Object.keys(operation.requestBody?.schema.properties ?? {})) {
    if (TENANT_HINTS.includes(name.toLowerCase())) found.add(name);
  }
  return [...found];
}

export interface CurateOptions {
  /** Globs over tool names; when set, only matching tools are considered. */
  readonly include?: readonly string[];
  readonly exclude?: readonly string[];
  readonly tags?: readonly string[];
  /** Keep deprecated operations. Off by default. */
  readonly includeDeprecated?: boolean;
  /**
   * Which effects to enable in the generated manifest. Only reads are enabled
   * by default: a human opts writes in, one at a time.
   */
  readonly enableEffects?: readonly Effect[];
  readonly tenant?: TenantConfig | undefined;
  readonly baseUrl?: string | undefined;
  readonly policyPath?: string | undefined;
}

export interface CurateResult {
  readonly manifest: Manifest;
  readonly skipped: readonly { readonly tool: string; readonly reason: string }[];
  readonly operationsByTool: ReadonlyMap<string, Operation>;
}

/**
 * Turns a parsed spec into a human-editable manifest. Nothing here decides what
 * is safe - it decides what a reviewer is asked about, with writes switched off
 * until someone turns them on.
 */
export function curate(spec: ParsedSpec, options: CurateOptions = {}): CurateResult {
  const enableEffects = new Set<Effect>(options.enableEffects ?? ["read"]);
  const names = assignToolNames(spec.operations);
  const skipped: { tool: string; reason: string }[] = [];
  const tools: ManifestTool[] = [];
  const operationsByTool = new Map<string, Operation>();

  for (const operation of spec.operations) {
    const name = names.get(operation)!;

    if (operation.deprecated && !options.includeDeprecated) {
      skipped.push({ tool: name, reason: "deprecated in the spec" });
      continue;
    }
    if (options.tags && options.tags.length > 0 && !operation.tags.some((t) => options.tags!.includes(t))) {
      skipped.push({ tool: name, reason: `no tag in ${options.tags.join(", ")}` });
      continue;
    }
    if (options.include && options.include.length > 0 && !anyGlobMatch(options.include, name)) {
      skipped.push({ tool: name, reason: "not matched by --include" });
      continue;
    }
    if (options.exclude && options.exclude.length > 0 && anyGlobMatch(options.exclude, name)) {
      skipped.push({ tool: name, reason: "matched by --exclude" });
      continue;
    }

    const { effect, review } = inferEffect(operation);
    const tenantParams = [
      ...new Set([
        ...operation.parameters.filter((p) => isTenantParam(p.name, options.tenant)).map((p) => p.name),
        ...Object.keys(operation.requestBody?.schema.properties ?? {}).filter((n) =>
          isTenantParam(n, options.tenant)
        )
      ])
    ];

    const tool: ManifestTool = {
      name,
      enabled: enableEffects.has(effect),
      effect,
      operationId: operation.operationId,
      method: operation.method,
      path: operation.path,
      summary: operation.summary || operation.description.split("\n")[0]?.slice(0, 120) || ""
    };
    if (review) tool.review = review;
    if (tenantParams.length > 0) tool.tenant_params = tenantParams;

    tools.push(tool);
    operationsByTool.set(name, operation);
  }

  tools.sort((a, b) => a.name.localeCompare(b.name));

  const manifest: Manifest = {
    version: 1,
    spec: spec.sourcePath,
    api: {
      title: spec.title,
      version: spec.version,
      base_url: options.baseUrl ?? spec.servers[0] ?? ""
    },
    tools
  };
  if (options.policyPath) manifest.policy = options.policyPath;
  if (skipped.length > 0) manifest.skipped = [...skipped];

  return { manifest, skipped, operationsByTool };
}

export interface BudgetResult {
  readonly ok: boolean;
  readonly enabled: number;
  readonly budget: number;
  readonly message?: string;
}

/**
 * A tool set is only curated if someone chose its size. Exceeding the budget is
 * a hard stop rather than a warning, because an agent handed 300 tools will not
 * use them well and cannot be reviewed meaningfully.
 */
export function checkBudget(manifest: Manifest, budget: number): BudgetResult {
  const enabled = manifest.tools.filter((t) => t.enabled).length;
  if (enabled <= budget) return { ok: true, enabled, budget };
  return {
    ok: false,
    enabled,
    budget,
    message:
      `${enabled} tools are enabled but the budget is ${budget}. ` +
      `Narrow the set with --include/--exclude/--tag, disable tools in the manifest, ` +
      `or raise tool_budget in the policy if you genuinely need this many.`
  };
}
