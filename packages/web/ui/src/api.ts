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

export interface ServerSummary {
  id: string;
  kind: "generated" | "gateway";
  label: string;
  ok: boolean;
  error?: string;
  component?: string;
  api?: { title: string; baseUrl: string } | null;
  toolCount?: number | null;
  /** `defaults.mode` from policy.yaml: the fallback for an unmatched call. */
  posture?: string;
  /** What the model can actually reach, derived from every tool's verdict. */
  reach?: Reach;
  auditPath?: string;
  tenantError?: string | null;
  counts?: Record<string, number>;
  scanOk?: boolean;
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
  description: string;
  effect: string;
  method: string;
  path: string;
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
    binding: { in: string; name: string } | null;
    renamed: boolean;
    isPaginationCap: boolean;
    constrainedByRule: string | null;
  }[];
  withheldParams: { name: string; in?: string; reason: string }[];
  tenantParams: { param: string; injectedInto: string[] }[];
  paginationCap: { param: string; max: number } | null;
  schemaClosed: boolean;
  review: string | null;
  /** `specIndex` is absent on a tool generated before the field existed, and
      on any surface that did not come from a spec. */
  source: { operationId?: string; summary?: string; deprecated?: boolean; specIndex?: number } | null;
  annotations: Record<string, boolean | undefined>;
  standingGrants: {
    grantId: string;
    reason: string;
    covers: boolean;
    why: string;
    uses: number;
    maxUses: number | null;
    expiresAt: number;
  }[];
  findings: Finding[];
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
  api: { title: string; version: string; baseUrl: string } | null;
  posture: string;
  reach: Reach;
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
    baseUrlPermitted: boolean | null;
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
  auth: { kind: string; envVar: string | null; envPresent: boolean | null };
  generation: {
    specFormat: string | null;
    hasSecuritySchemes: boolean | null;
    operationsWithoutSecurity: string[];
    skipped: { tool: string; reason: string }[];
  } | null;
  pipeline: PipelineStep[];
  findings: Finding[];
  counts: Record<string, number>;
  scanOk: boolean;
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

export const api = {
  /** Exchanges the token in the startup URL for a session cookie. */
  session: (token: string) => call<{ ok: true }>("/api/v1/session", { method: "POST", body: JSON.stringify({ token }) }),
  redaction: () => call<RedactionMeta>("/api/v1/meta/redaction"),
  servers: () => call<ServerSummary[]>("/api/v1/servers"),
  addServer: (entry: Record<string, unknown>) =>
    call<{ id: string }>("/api/v1/servers", { method: "POST", body: JSON.stringify(entry) }),
  removeServer: (id: string) => call<{ removed: string }>(`/api/v1/servers/${id}`, { method: "DELETE" }),
  protection: (id: string) => call<ServerProtection>(`/api/v1/servers/${id}/protection`),
  tools: (id: string) => call<ToolProtection[]>(`/api/v1/servers/${id}/tools`),
  tool: (id: string, name: string) => call<ToolProtection>(`/api/v1/servers/${id}/tools/${encodeURIComponent(name)}`),
  /**
   * Switches one tool off, or hands it back to policy. `disabled: false` only
   * clears the override — it cannot expose a tool that policy refuses.
   */
  setExposure: (id: string, name: string, disabled: boolean, reason = "") =>
    call<{ tool: ToolProtection; changed: boolean; warning: string | null }>(
      `/api/v1/servers/${id}/tools/${encodeURIComponent(name)}/exposure`,
      { method: "PUT", body: JSON.stringify({ disabled, reason }) }
    ),
  pending: (id: string) => call<Approval[]>(`/api/v1/servers/${id}/approvals/pending`),
  approvals: (id: string) => call<Approval[]>(`/api/v1/servers/${id}/approvals`),
  decide: (id: string, aprId: string, state: "granted" | "denied", note: string) =>
    call<Approval>(`/api/v1/servers/${id}/approvals/${aprId}/decide`, {
      method: "POST",
      body: JSON.stringify({ state, note })
    }),
  grants: (id: string) => call<Grant[]>(`/api/v1/servers/${id}/grants`),
  createGrant: (id: string, body: Record<string, unknown>) =>
    call<Grant>(`/api/v1/servers/${id}/grants`, { method: "POST", body: JSON.stringify(body) }),
  previewGrant: (id: string, body: Record<string, unknown>) =>
    call<{ expiresAt: number; tools: { name: string; effect: string; covers: boolean; why: string }[] }>(
      `/api/v1/servers/${id}/grants/preview`,
      { method: "POST", body: JSON.stringify(body) }
    ),
  revokeGrant: (id: string, grantId: string) =>
    call<Grant>(`/api/v1/servers/${id}/grants/${grantId}`, { method: "DELETE" }),
  audit: (id: string, params: Record<string, string>) =>
    call<AuditPage>(`/api/v1/servers/${id}/audit?${new URLSearchParams(params)}`),
  verify: (id: string) =>
    call<{ ok: boolean; count: number; problems: { line: number; message: string }[] }>(
      `/api/v1/servers/${id}/audit/verify`
    )
};
