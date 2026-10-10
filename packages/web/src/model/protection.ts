import { existsSync } from "node:fs";
import {
  decide,
  globMatch,
  grantMatches,
  policyDigest,
  queryAuditLog,
  resolveEffect,
  runtimeStateIsLive,
  verifyAuditLog,
  type Decision,
  type Policy,
  type StandingGrantRow,
  type ToolExposureRow
} from "@hmcp/core";
import type { ToolDescriptor } from "@hmcp/server-runtime";
import type { Finding, ScanTool } from "@hmcp/scanner";
import { describeTenantSource, scopedFor, storeFor, type LoadedServer } from "./server.js";
import { ENFORCEMENT_PIPELINE } from "./pipeline.js";
import { runScan } from "./scan.js";

/**
 * The protection view model.
 *
 * Every statement here is derived from this server's own configuration and
 * tools. The one exception is `ENFORCEMENT_PIPELINE`, which describes the
 * runtime's code rather than the user's settings and is therefore the only
 * thing that can honestly be written ahead of time.
 */

export interface ToolProtection {
  readonly name: string;
  readonly description: string;
  readonly effect: string;
  readonly method: string;
  readonly path: string;
  /** What `decide()` says right now, with no arguments supplied. */
  readonly verdict: { kind: Decision["kind"]; ruleId: string; reason: string };
  /** Which stage of `decide()` produced the verdict. */
  readonly verdictStage: string;
  /** Set when a policy rule reclassifies the effect the tool was built with. */
  readonly reclassifiedTo: string | null;
  /** Advertised but unrunnable: approval required, approvals disabled. */
  readonly unreachable: boolean;
  readonly requiresApproval: boolean;
  /**
   * The console's exposure switch for this tool.
   *
   * `verdict` above deliberately stays the *policy* verdict even while a tool
   * is switched off, so the console can still say what policy would do and a
   * reviewer can see what turning the switch back on would restore.
   */
  readonly exposure: {
    readonly disabled: boolean;
    readonly setBy: string | null;
    readonly setAt: number | null;
    readonly reason: string | null;
    /**
     * Whether clearing the override would actually expose the tool. False when
     * policy refuses it anyway, in which case the switch has nothing to turn
     * on and the console says so rather than offering a no-op.
     */
    readonly policyWouldExpose: boolean;
  };
  readonly args: readonly {
    readonly name: string;
    readonly type: string | undefined;
    readonly required: boolean;
    readonly description: string | undefined;
    /** Where the value lands upstream, and under what name. */
    readonly binding: { in: string; name: string } | null;
    readonly renamed: boolean;
    readonly isPaginationCap: boolean;
    readonly constrainedByRule: string | null;
  }[];
  readonly withheldParams: readonly { name: string; in?: string; reason: string }[];
  readonly tenantParams: readonly { param: string; injectedInto: readonly string[] }[];
  readonly paginationCap: { param: string; max: number } | null;
  readonly schemaClosed: boolean;
  readonly review: string | null;
  readonly source: { operationId?: string; summary?: string; deprecated?: boolean; specIndex?: number } | null;
  readonly annotations: Readonly<Record<string, boolean | undefined>>;
  readonly standingGrants: readonly {
    readonly grantId: string;
    readonly reason: string;
    readonly covers: boolean;
    readonly why: string;
    readonly uses: number;
    readonly maxUses: number | null;
    readonly expiresAt: number;
  }[];
  readonly findings: readonly Finding[];
}

export interface ServerProtection {
  readonly id: string;
  readonly label: string;
  readonly kind: string;
  readonly api: { title: string; version: string; baseUrl: string } | null;
  /** `defaults.mode` as written in policy.yaml: the fallback, not the surface. */
  readonly posture: string;
  /** What is actually reachable — see `effectiveReach`. */
  readonly reach: Reach;
  readonly onUnclassified: string;
  readonly toolBudget: { budget: number; enabled: number; ok: boolean };
  readonly rules: readonly {
    readonly id: string;
    readonly match: string;
    readonly decision: string;
    readonly effect: string | null;
    readonly reason: string | null;
    readonly argConstraints: readonly string[];
    readonly matchedTools: readonly string[];
    /** An earlier rule already claims every tool this one matches. */
    readonly shadowedBy: string | null;
  }[];
  readonly tenant: {
    readonly field: string;
    readonly aliases: readonly string[];
    readonly sourceKind: string;
    readonly sourceName: string | null;
    readonly sourceProse: string;
    readonly inject: readonly string[];
    readonly onMismatch: string;
    readonly required: boolean;
    readonly resolved: boolean;
    readonly error: string | null;
  } | null;
  readonly egress: {
    readonly allow: readonly string[];
    readonly methods: readonly string[];
    readonly maxBodyBytes: number;
    readonly maxRequestBodyBytes: number;
    readonly timeoutMs: number;
    readonly maxRedirects: number;
    readonly blockPrivateIps: boolean;
    readonly allowHttp: boolean;
    readonly allowIpLiterals: boolean;
    /** Whether the configured upstream is on the allowlist at all. */
    readonly baseUrlPermitted: boolean | null;
  };
  readonly approvals: {
    readonly mode: string;
    readonly ttlSeconds: number;
    readonly singleUse: boolean;
    readonly storePath: string;
    readonly pendingCount: number;
    readonly activeGrantCount: number;
    /** Requests in the same store that belong to some other server. */
    readonly pendingElsewhere: number;
  };
  readonly audit: {
    readonly enabled: boolean;
    readonly path: string;
    readonly hashChain: boolean;
    readonly recordArgs: boolean;
    readonly redact: readonly string[];
    /**
     * `written: false` means the log does not exist yet, which is the normal
     * state of a server that has not run. Without it a brand-new server looks
     * like one whose chain has been tampered with.
     */
    readonly verify: { ok: boolean; written: boolean; count: number; problemCount: number };
  };
  /**
   * Whether what is shown here is what a running server is enforcing.
   *
   * Everything else on this object is read from disk on every request, so it
   * is always current as to the files. A running server is not: it parsed its
   * policy at startup and holds that copy. `applied: false` means those two
   * have diverged and the page is describing a configuration that is not in
   * force — the one state in which these numbers can be confidently wrong.
   */
  readonly runtime: {
    /** A live server has announced itself and refreshed within the TTL. */
    readonly running: boolean;
    /** Epoch ms, as every other timestamp the UI formats. */
    readonly startedAt: number | null;
    /**
     * `null` when nothing is running: not knowing whether the on-disk policy
     * is in force is a different claim from knowing that it is not.
     */
    readonly policyApplied: boolean | null;
    readonly policyPath: string | null;
  };
  readonly auth: { readonly kind: string; readonly envVar: string | null; readonly envPresent: boolean | null };
  readonly generation: {
    readonly specFormat: string | null;
    readonly hasSecuritySchemes: boolean | null;
    readonly operationsWithoutSecurity: readonly string[];
    readonly skipped: readonly { tool: string; reason: string }[];
  } | null;
  readonly pipeline: typeof ENFORCEMENT_PIPELINE;
  readonly findings: readonly Finding[];
  readonly counts: Readonly<Record<string, number>>;
  readonly scanOk: boolean;
  readonly tools: readonly ToolProtection[];
}

/**
 * Attaches scanner findings to the tool they concern.
 *
 * Finding paths come in two shapes — `toolPath()` emits `<tool>.<suffix>` while
 * a couple of rules hand-build `tools.<tool>` — so both are accepted. The match
 * is on a segment boundary rather than a bare prefix, because `get_pet` must
 * not absorb the findings of `get_pet_list`.
 */
export function findingsForTool(findings: readonly Finding[], tool: string, server?: string): Finding[] {
  const bases = server ? [`${server}.${tool}`, `tools.${server}.${tool}`] : [tool, `tools.${tool}`];
  return findings.filter((f) => {
    const p = f.location.path;
    if (!p) return false;
    return bases.some((b) => p === b || p.startsWith(`${b}.`) || p.startsWith(`${b}[`));
  });
}

/** Findings that belong to the surface as a whole rather than to one tool. */
function serverFindings(findings: readonly Finding[], toolNames: readonly string[]): Finding[] {
  return findings.filter((f) => !toolNames.some((name) => findingsForTool([f], name).length > 0));
}

/** Which of `decide()`'s four stages produced a verdict, named from its rule id. */
function verdictStage(ruleId: string): string {
  if (ruleId.startsWith("tenant.")) return "tenant integrity, checked before anything else";
  if (ruleId === "defaults.on_unclassified") return "no effect classification, so the default applied";
  if (ruleId === "defaults.mode") return "no rule matched, so the posture decided";
  return `policy rule "${ruleId}"`;
}

/**
 * What the model can actually do on this server right now.
 *
 * Not to be confused with `posture`, which is `defaults.mode` from the policy
 * file: that is only the fallback for a call no rule matched. A server can
 * declare `read-only` and still hand the model a dozen writes through explicit
 * rules, which is precisely what the console used to misreport — it printed the
 * declared default and let the reader assume it described the surface.
 *
 * This asks the narrower question a reader is actually asking when they glance
 * at the chrome: of everything advertised, what can run? It is taken from the
 * same `decide()` the runtime uses, with the console's own switches subtracted,
 * so it cannot drift from what the server would really do.
 */
export type Reach = "read-only" | "approve-writes" | "locked";

export function effectiveReach(server: LoadedServer): Reach {
  const policy = server.policy;
  const descriptors = server.tools?.tools ?? [];
  const disabled = new Set(scopedFor(server).listDisabledTools().map((row) => row.tool));

  let reachable = 0;
  let mutating = 0;

  for (const descriptor of descriptors) {
    // Switched off here is not reachable, whatever policy would have said.
    if (disabled.has(descriptor.name)) continue;

    const decision = decide({
      tool: descriptor.name,
      effect: descriptor.effect,
      args: {},
      policy,
      ...(policy.tenant ? { tenant: { expected: server.tenantValue } } : {})
    });

    if (decision.kind === "deny") continue;
    // An approval nobody is able to give is not reach either — this is the
    // same condition `unreachable` reports on each row.
    if (decision.kind === "approve" && policy.approvals.mode === "deny") continue;

    reachable++;
    // The effective effect, so a rule that reclassifies a tool as a write is
    // counted as the write it is treated as rather than the read it was built.
    const effect = resolveEffect({ tool: descriptor.name, effect: descriptor.effect, policy });
    if (effect === "write" || effect === "destructive") mutating++;
  }

  if (reachable === 0) return "locked";
  return mutating > 0 ? "approve-writes" : "read-only";
}

export function toolProtection(
  server: LoadedServer,
  descriptor: ToolDescriptor,
  findings: readonly Finding[],
  grants: readonly StandingGrantRow[],
  exposure: ToolExposureRow | undefined
): ToolProtection {
  const policy = server.policy;
  const decision = decide({
    tool: descriptor.name,
    effect: descriptor.effect,
    args: {},
    policy,
    ...(policy.tenant ? { tenant: { expected: server.tenantValue } } : {})
  });

  const effective = resolveEffect({ tool: descriptor.name, effect: descriptor.effect, policy });
  const matchedRule = policy.rules.find((r) => globMatch(r.match, descriptor.name));
  const schema = descriptor.inputSchema;
  const properties = schema.properties ?? {};
  const required = new Set(schema.required ?? []);

  return {
    name: descriptor.name,
    description: descriptor.description,
    effect: descriptor.effect,
    method: descriptor.method,
    path: descriptor.path,
    verdict: { kind: decision.kind, ruleId: decision.ruleId, reason: decision.reason },
    verdictStage: verdictStage(decision.ruleId),
    reclassifiedTo: effective && effective !== descriptor.effect ? effective : null,
    requiresApproval: decision.kind === "approve",
    unreachable: decision.kind === "approve" && policy.approvals.mode === "deny",
    exposure: {
      disabled: exposure !== undefined,
      setBy: exposure?.set_by ?? null,
      setAt: exposure?.set_at ?? null,
      reason: exposure?.reason || null,
      policyWouldExpose: decision.kind !== "deny"
    },
    args: Object.entries(properties).map(([name, node]) => {
      const binding = descriptor.bindings[name];
      return {
        name,
        type: node.type,
        required: required.has(name),
        description: node.description,
        binding: binding ? { in: binding.in, name: binding.name } : null,
        renamed: binding ? binding.name !== name : false,
        isPaginationCap: descriptor.paginationCap?.param === name,
        constrainedByRule: matchedRule?.args?.[name] ? matchedRule.id : null
      };
    }),
    withheldParams: descriptor.withheldParams,
    tenantParams: descriptor.tenantParams.map((param) => ({
      param,
      injectedInto: policy.tenant?.inject ?? []
    })),
    paginationCap: descriptor.paginationCap ?? null,
    schemaClosed: schema.additionalProperties === false,
    review: descriptor.review ?? null,
    source: descriptor.source ?? null,
    annotations: descriptor.annotations,
    standingGrants: grants.map((grant) => {
      const match = grantMatches(grant, descriptor.name, descriptor.effect, {});
      return {
        grantId: grant.id,
        reason: grant.reason,
        covers: match.matches,
        why: match.reason,
        uses: grant.uses,
        maxUses: grant.max_uses,
        expiresAt: grant.expires_at
      };
    }),
    findings: findingsForTool(findings, descriptor.name)
  };
}

function ruleRows(policy: Policy, toolNames: readonly string[]): ServerProtection["rules"] {
  return policy.rules.map((rule, index) => {
    const matched = toolNames.filter((name) => globMatch(rule.match, name));
    // A rule every one of whose tools is already claimed by an earlier rule can
    // never fire, because `decide()` takes the first match. Nothing else tells
    // you that.
    const earlier = policy.rules.slice(0, index);
    const shadow =
      matched.length > 0
        ? earlier.find((prev) => matched.every((name) => globMatch(prev.match, name)))
        : undefined;
    return {
      id: rule.id,
      match: rule.match,
      decision: rule.decision,
      effect: rule.effect ?? null,
      reason: rule.reason ?? null,
      argConstraints: Object.keys(rule.args ?? {}),
      matchedTools: matched,
      shadowedBy: shadow?.id ?? null
    };
  });
}

export function buildProtection(server: LoadedServer): ServerProtection {
  const policy = server.policy;
  const descriptors = server.tools?.tools ?? [];
  const toolNames = descriptors.map((t) => t.name);
  const scan = runScan(server);
  const store = storeFor(server);
  const scoped = scopedFor(server);
  const grants = scoped.listGrants({ activeOnly: true });
  const disabled = new Map(scoped.listDisabledTools().map((row) => [row.tool, row]));

  /*
   * One database commonly holds several servers' rows, so "waiting" has two
   * meanings and the console reports both. `own` is this component and this
   * tenant, which the database filters; `others` is the remainder of the file,
   * shown so that a queue someone else is responsible for is visible rather
   * than invisible. This used to be a tool-name heuristic, which could not
   * tell two tenants of the same server apart at all.
   */
  const ownPending = scoped.listPending(500);
  const allPending = store.listPendingAll(500);
  const pending = { own: ownPending.length, others: allPending.length - ownPending.length };

  const written = policy.audit.enabled && existsSync(server.auditPath);
  const verified = written
    ? verifyAuditLog(server.auditPath)
    : { ok: false, count: 0, problems: [] as readonly { line: number; message: string }[] };

  const auth = server.tools?.auth ?? { kind: "none" as const };
  const envVar = "env" in auth ? auth.env : null;

  /*
   * Compare what a running server says it parsed against what was just read
   * from disk. The digests are of the *parsed* policies, so reformatting or a
   * changed comment is correctly silent and only a difference in what would be
   * enforced shows up.
   *
   * A row from a process that has stopped refreshing is ignored rather than
   * trusted: it describes a server that is no longer deciding anything, and
   * quoting it would be a second way of saying something untrue about what is
   * in force.
   */
  const announced = store.runtimeState(server.component);
  const live = announced && runtimeStateIsLive(announced) ? announced : undefined;
  const runtime = {
    running: live !== undefined,
    startedAt: live?.started_at ?? null,
    policyApplied: live ? live.policy_digest === policyDigest(policy) : null,
    policyPath: live?.policy_path || server.policyPath
  };

  return {
    id: server.entry.id,
    label: server.entry.label,
    kind: server.entry.kind,
    api: server.tools
      ? {
          title: server.tools.api.title,
          version: server.tools.api.version,
          baseUrl: server.tools.api.base_url
        }
      : null,
    posture: policy.defaults.mode,
    reach: effectiveReach(server),
    onUnclassified: policy.defaults.on_unclassified,
    toolBudget: {
      budget: policy.tool_budget,
      enabled: descriptors.length,
      ok: descriptors.length <= policy.tool_budget
    },
    rules: ruleRows(policy, toolNames),
    tenant: policy.tenant
      ? {
          field: policy.tenant.field,
          aliases: policy.tenant.aliases,
          sourceKind: policy.tenant.source.kind,
          sourceName: "name" in policy.tenant.source ? policy.tenant.source.name : null,
          sourceProse: describeTenantSource(policy),
          inject: policy.tenant.inject,
          onMismatch: policy.tenant.on_mismatch,
          required: policy.tenant.required,
          resolved: server.tenantValue !== undefined,
          error: server.tenantError
        }
      : null,
    egress: {
      allow: policy.egress.allow,
      methods: policy.egress.methods,
      maxBodyBytes: policy.egress.max_body_bytes,
      maxRequestBodyBytes: policy.egress.max_request_body_bytes,
      timeoutMs: policy.egress.timeout_ms,
      maxRedirects: policy.egress.max_redirects,
      blockPrivateIps: policy.egress.block_private_ips,
      allowHttp: policy.egress.allow_http,
      allowIpLiterals: policy.egress.allow_ip_literals,
      baseUrlPermitted: server.tools ? baseUrlPermitted(server.tools.api.base_url, policy) : null
    },
    approvals: {
      mode: policy.approvals.mode,
      ttlSeconds: policy.approvals.ttl_seconds,
      singleUse: policy.approvals.single_use,
      storePath: server.storePath,
      pendingCount: pending.own,
      pendingElsewhere: pending.others,
      activeGrantCount: grants.length
    },
    audit: {
      enabled: policy.audit.enabled,
      path: server.auditPath,
      hashChain: policy.audit.hash_chain,
      recordArgs: policy.audit.record_args,
      redact: policy.audit.redact,
      verify: { ok: verified.ok, written, count: verified.count, problemCount: verified.problems.length }
    },
    runtime,
    auth: {
      kind: auth.kind,
      envVar,
      // The variable's *name* is already public in tools.json. Whether it is
      // set is useful. The value is never read here, at any point.
      envPresent: envVar ? process.env[envVar] !== undefined : null
    },
    generation: server.tools?.generation
      ? {
          specFormat: server.tools.generation.spec_format ?? null,
          hasSecuritySchemes: server.tools.generation.has_security_schemes ?? null,
          operationsWithoutSecurity: server.tools.generation.operations_without_security,
          skipped: server.tools.generation.skipped
        }
      : null,
    pipeline: ENFORCEMENT_PIPELINE,
    findings: serverFindings(scan.findings, toolNames),
    counts: scan.counts,
    scanOk: scan.ok,
    tools: descriptors.map((d) => toolProtection(server, d, scan.findings, grants, disabled.get(d.name)))
  };
}

/**
 * Whether the upstream host is on the egress allowlist.
 *
 * A host comparison only: no DNS lookup and no request, because a console
 * rendering a page must not perform network calls on the server's behalf.
 */
function baseUrlPermitted(baseUrl: string, policy: Policy): boolean | null {
  let host: string;
  try {
    const url = new URL(baseUrl);
    host = url.port ? `${url.hostname}:${url.port}` : url.hostname;
  } catch {
    return null;
  }
  return policy.egress.allow.some((pattern) => globMatch(pattern, host) || globMatch(pattern, host.split(":")[0]!));
}

/** The last few decisions recorded for one tool. */
export function recentActivity(server: LoadedServer, tool: string, limit = 10) {
  if (!server.policy.audit.enabled) return [];
  return queryAuditLog(server.auditPath, { tool, limit }).records;
}

export type { ScanTool };
