/**
 * The typed client.
 *
 * These types mirror the DTOs the backend serialises. They are kept honest by
 * `packages/web/test/api.test.ts`, which asserts on the literal response
 * shapes rather than on the server's own types.
 */

/**
 * The three states the console reports a server's surface in. Deliberately the
 * same three words policy.yaml uses for `defaults.mode`, because a reader who
 * has seen one should recognise the other — but this one is measured, not
 * declared, and the two can legitimately disagree.
 */
export type Reach = "read-only" | "approve-writes" | "locked";

/**
 * A gateway's tool surface is published by a running process, so every number
 * derived from it needs its provenance alongside. "No tools" and "we have not
 * been told" are different claims and the console must not merge them.
 */
export interface Surface {
  live: boolean;
  stale: boolean;
  neverPublished: boolean;
  publishedAt: number | null;
  toolCount: number;
  injectionCount: number;
  hiddenCount: number;
  unclassifiedCount: number;
}

export interface ServerSummary {
  id: string;
  kind: "gateway";
  label: string;
  ok: boolean;
  error?: string;
  component?: string;
  /** The upstream MCP servers this gateway is configured to front. */
  upstreams?: string[];
  /** `null` when nothing has been published — not zero, which would be a claim. */
  toolCount?: number | null;
  /** Which tenant `reach` describes, or null when a request must name one. */
  tenantScope?: string | null;
  tenantRequired?: boolean;
  tenantHint?: string | null;
  surfaceLive?: boolean;
  surfaceStale?: boolean;
  /** `defaults.mode` from the policy: the fallback for an unmatched call. */
  posture?: string;
  /** What the model can reach, or `null` when the surface is unknown. */
  reach?: Reach | null;
  /** Whether a gateway process is announcing itself for this component. */
  running?: boolean;
  auditPath?: string;
  tenantError?: string | null;
}

export interface Finding {
  ruleId: string;
  severity: "high" | "medium" | "low";
  title: string;
  message: string;
  fix: string;
  location: { file: string; path?: string };
}

export interface ToolProtection {
  name: string;
  /** What the model is told, after any rewriting of the upstream's own text. */
  description: string;
  /** What the upstream said. Differs from `description` when it was rewritten. */
  rawDescription: string;
  upstream: string;
  /** `null` when the gateway could not classify it, in which case it is refused. */
  effect: string | null;
  effectSource: string;
  /** Hidden from every tenant by gateway policy, not by one tenant's switch. */
  hiddenByPolicy: boolean;
  injection: string[] | null;
  verdict: { kind: "allow" | "approve" | "deny"; ruleId: string; reason: string };
  verdictStage: string;
  reclassifiedTo: string | null;
  unreachable: boolean;
  requiresApproval: boolean;
  exposure: {
    disabled: boolean;
    setBy: string | null;
    setAt: number | null;
    reason: string | null;
    /** False when policy refuses the tool anyway, so the switch has nothing to turn on. */
    policyWouldExpose: boolean;
  };
  args: {
    name: string;
    type?: string;
    required: boolean;
    description?: string;
    constrainedByRule: string | null;
  }[];
  /** `true` closed, `false` explicitly open, `null` the upstream did not say. */
  schemaClosed: boolean | null;
  standingGrants: {
    grantId: string;
    reason: string;
    covers: boolean;
    why: string;
    uses: number;
    maxUses: number | null;
    expiresAt: number;
  }[];
  inputSchema?: unknown;
  activity?: AuditRecord[];
}

export interface PipelineStep {
  step: number;
  title: string;
  detail: string;
  source: string;
}

export interface ServerProtection {
  id: string;
  label: string;
  kind: string;
  /** Which tenant every scoped number below describes. */
  tenant_scope: string;
  /** Whether the request named it, or the console read it from the config. */
  explicitTenant: boolean;
  posture: string;
  reach: Reach | null;
  surface: Surface;
  onUnclassified: string;
  toolBudget: { budget: number; enabled: number; ok: boolean };
  rules: {
    id: string;
    match: string;
    decision: string;
    effect: string | null;
    reason: string | null;
    argConstraints: string[];
    matchedTools: string[];
    shadowedBy: string | null;
  }[];
  tenant: {
    field: string;
    aliases: string[];
    sourceKind: string;
    sourceName: string | null;
    sourceProse: string;
    inject: string[];
    onMismatch: string;
    required: boolean;
    resolved: boolean;
    error: string | null;
  } | null;
  egress: {
    allow: string[];
    methods: string[];
    maxBodyBytes: number;
    maxRequestBodyBytes: number;
    timeoutMs: number;
    maxRedirects: number;
    blockPrivateIps: boolean;
    allowHttp: boolean;
    allowIpLiterals: boolean;
  };
  approvals: {
    mode: string;
    ttlSeconds: number;
    singleUse: boolean;
    storePath: string;
    pendingCount: number;
    activeGrantCount: number;
    pendingElsewhere: number;
  };
  audit: {
    enabled: boolean;
    path: string;
    hashChain: boolean;
    recordArgs: boolean;
    redact: string[];
    verify: { ok: boolean; written: boolean; count: number; problemCount: number };
  };
  /** Whether a running server is enforcing the configuration shown here. */
  runtime: {
    running: boolean;
    startedAt: number | null;
    /** `null` when nothing is running, so "unknown" stays distinct from "no". */
    policyApplied: boolean | null;
    policyPath: string | null;
  };
  pipeline: PipelineStep[];
  tools: ToolProtection[];
}

export interface Approval {
  id: string;
  createdAt: number;
  expiresAt: number;
  tool: string;
  effect: string | null;
  reason: string;
  actor: string;
  session: string;
  state: string;
  decidedAt: number | null;
  decidedBy: string | null;
  decisionNote: string | null;
  bindingHash: string;
  args: unknown;
  argsError: string | null;
}

export interface Grant {
  id: string;
  createdAt: number;
  expiresAt: number;
  toolMatch: string;
  effect: string | null;
  constraints: Record<string, unknown>;
  maxUses: number | null;
  uses: number;
  reason: string;
  createdBy: string;
  state: string;
  revokedAt: number | null;
  revokedBy: string | null;
  warning?: string | null;
}

export interface AuditRecord {
  ts: string;
  seq: number;
  id: string;
  actor: string;
  session: string;
  component: string;
  tool: string;
  effect: string | null;
  decision: "allow" | "approve" | "deny";
  rule_id: string;
  reason: string;
  tenant: string | null;
  args_hash: string;
  args_redacted: Record<string, unknown> | null;
  upstream: { host: string | null; method: string | null; path: string | null; status: number | null; bytes: number | null } | null;
  outcome: string;
  error: string | null;
  duration_ms: number | null;
  approval_id: string | null;
  grant_id: string | null;
  prev_hash: string;
  hash: string;
  serverId?: string | null;
  attribution?: string;
}

export interface AuditPage {
  records: AuditRecord[];
  nextCursor: number | null;
  scanned: number;
  malformed: number;
  auditPath?: string;
}

export interface RedactionMeta {
  markers: { marker: string; meaning: string }[];
  note: string;
  grantTtlMaxSeconds: number;
  /** Core's decision and outcome vocabularies, so the filters are not a copy. */
  decisions: { value: string; label: string }[];
  outcomes: { value: string; label: string }[];
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string
  ) {
    super(message);
  }
}

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)hmcp_csrf=([^;]+)/);
  return match?.[1] ?? "";
}

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { ...((init.headers as Record<string, string>) ?? {}) };
  if (init.method && init.method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-HMCP-CSRF"] = csrfToken();
  }
  const res = await fetch(path, { ...init, headers });
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const error = body?.error ?? { code: "unknown", message: res.statusText };
    throw new ApiError(res.status, error.code, error.message);
  }
  return body as T;
}

/**
 * Appends the tenant, when one is being named.
 *
 * Omitted rather than sent empty when it is not, because the two mean
 * different things to the backend: absent lets a single-tenant gateway resolve
 * its own, while a value names one explicitly. A hosted gateway, which resolves
 * per request from the caller's token, refuses the absent case outright rather
 * than guessing — so a page that forgets this gets an error it can show, not a
 * silently wrong scope.
 */
function scoped(path: string, tenant?: string | null): string {
  if (!tenant) return path;
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}tenant=${encodeURIComponent(tenant)}`;
}

export interface TenantInfo {
  tenants: string[];
  configured: boolean;
  sourceKind: string | null;
  required: boolean;
  /** Null when a request has to name one. */
  assumed: string | null;
  whyNotAssumed: string | null;
}

export const api = {
  /** Exchanges the token in the startup URL for a session cookie. */
  session: (token: string) => call<{ ok: true }>("/api/v1/session", { method: "POST", body: JSON.stringify({ token }) }),
  redaction: () => call<RedactionMeta>("/api/v1/meta/redaction"),
  servers: () => call<ServerSummary[]>("/api/v1/servers"),
  addServer: (entry: Record<string, unknown>) =>
    call<{ id: string }>("/api/v1/servers", { method: "POST", body: JSON.stringify(entry) }),
  removeServer: (id: string) => call<{ removed: string }>(`/api/v1/servers/${id}`, { method: "DELETE" }),
  tenants: (id: string) => call<TenantInfo>(`/api/v1/servers/${id}/tenants`),
  protection: (id: string, tenant?: string | null) =>
    call<ServerProtection>(scoped(`/api/v1/servers/${id}/protection`, tenant)),
  tools: (id: string, tenant?: string | null) =>
    call<ToolProtection[]>(scoped(`/api/v1/servers/${id}/tools`, tenant)),
  tool: (id: string, name: string, tenant?: string | null) =>
    call<ToolProtection>(scoped(`/api/v1/servers/${id}/tools/${encodeURIComponent(name)}`, tenant)),
  /**
   * Switches one tool off, or hands it back to policy. `disabled: false` only
   * clears the override — it cannot expose a tool that policy refuses.
   */
  setExposure: (id: string, name: string, disabled: boolean, reason = "", tenant?: string | null) =>
    call<{
      tool: ToolProtection;
      changed: boolean;
      warning: string | null;
      /** Which scope the switch landed in, so it can be shown rather than assumed. */
      tenant: string;
      explicitTenant: boolean;
    }>(scoped(`/api/v1/servers/${id}/tools/${encodeURIComponent(name)}/exposure`, tenant), {
      method: "PUT",
      body: JSON.stringify({ disabled, reason })
    }),
  pending: (id: string, tenant?: string | null) =>
    call<Approval[]>(scoped(`/api/v1/servers/${id}/approvals/pending`, tenant)),
  approvals: (id: string, tenant?: string | null) =>
    call<Approval[]>(scoped(`/api/v1/servers/${id}/approvals`, tenant)),
  decide: (id: string, aprId: string, state: "granted" | "denied", note: string, tenant?: string | null) =>
    call<Approval>(scoped(`/api/v1/servers/${id}/approvals/${aprId}/decide`, tenant), {
      method: "POST",
      body: JSON.stringify({ state, note })
    }),
  grants: (id: string, tenant?: string | null) => call<Grant[]>(scoped(`/api/v1/servers/${id}/grants`, tenant)),
  createGrant: (id: string, body: Record<string, unknown>, tenant?: string | null) =>
    call<Grant>(scoped(`/api/v1/servers/${id}/grants`, tenant), { method: "POST", body: JSON.stringify(body) }),
  previewGrant: (id: string, body: Record<string, unknown>, tenant?: string | null) =>
    call<{
      expiresAt: number;
      /** False when no live gateway has published a surface to check against. */
      surfaceKnown: boolean;
      surfaceUnknownWhy: string | null;
      tools: { name: string; effect: string | null; covers: boolean; why: string }[];
    }>(scoped(`/api/v1/servers/${id}/grants/preview`, tenant), {
      method: "POST",
      body: JSON.stringify(body)
    }),
  revokeGrant: (id: string, grantId: string, tenant?: string | null) =>
    call<Grant>(scoped(`/api/v1/servers/${id}/grants/${grantId}`, tenant), { method: "DELETE" }),
  audit: (id: string, params: Record<string, string>) =>
    call<AuditPage>(`/api/v1/servers/${id}/audit?${new URLSearchParams(params)}`),
  verify: (id: string) =>
    call<{ ok: boolean; count: number; problems: { line: number; message: string }[] }>(
      `/api/v1/servers/${id}/audit/verify`
    )
};
