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
  type ToolSurfaceEntry
} from "@hmcp/core";
import { describeTenantSource, scopedFor, storeFor, type LoadedServer } from "./server.js";
import { ENFORCEMENT_PIPELINE } from "./pipeline.js";
import { toolSurfaceFor, type ToolSurfaceView } from "./tools.js";

/**
 * The protection view model.
 *
 * Every statement here is derived from this gateway's own configuration and the
 * surface it published. The one exception is `ENFORCEMENT_PIPELINE`, which
 * describes the gateway's code rather than the user's settings and is therefore
 * the only thing that can honestly be written ahead of time.
 */

export interface ToolProtection {
  readonly name: string;
  /** What the model is told, after any rewriting of the upstream's own text. */
  readonly description: string;
  /** The upstream's own text. Differs from `description` when it was rewritten. */
  readonly rawDescription: string;
  /** Which upstream server advertises this tool. */
  readonly upstream: string;
  /** Null when the gateway could not classify it, in which case it is refused. */
  readonly effect: string | null;
  /** How the effect was decided: policy, annotation, name, or unclassified. */
  readonly effectSource: string;
  /**
   * Hidden from every tenant by gateway policy — `on_injection: deny` found
   * injected instructions in the upstream's text. Distinct from `exposure`,
   * which is one tenant's switch and is theirs to reverse.
   */
  readonly hiddenByPolicy: boolean;
  /** Injection pattern ids found in the upstream's advertised text. */
  readonly injection: readonly string[] | null;
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
    readonly constrainedByRule: string | null;
  }[];
  /**
   * Whether the upstream declared its argument object closed.
   *
   * Three states, because `additionalProperties` absent is not the same claim
   * as `additionalProperties: false`, and almost no MCP server emits either:
   * the schemas most servers generate simply leave it out. Reading absent as
   * "open" meant every tool on every gateway carried the same warning, which
   * is no signal at all — the scanner has always flagged only an explicit
   * `true`, and this is now consistent with it.
   *
   * `true` closed, `false` explicitly open, `null` the upstream did not say.
   */
  readonly schemaClosed: boolean | null;
  readonly standingGrants: readonly {
    readonly grantId: string;
    readonly reason: string;
    readonly covers: boolean;
    readonly why: string;
    readonly uses: number;
    readonly maxUses: number | null;
    readonly expiresAt: number;
  }[];
}

export interface ServerProtection {
  readonly id: string;
  readonly label: string;
  readonly kind: string;
  /**
   * Which tenant every scoped number below describes.
   *
   * Carried so the page cannot present one tenant's exposure, queue and reach
   * as the gateway's. `explicitTenant` says whether the request named it or the
   * console read it from the deployment's own configuration.
   */
  readonly tenant_scope: string;
  readonly explicitTenant: boolean;
  /** `defaults.mode` as written in the policy: the fallback, not the surface. */
  readonly posture: string;
  /** What is actually reachable, or null when the surface is unknown. */
  readonly reach: Reach | null;
  /**
   * Where the tool list came from and whether it can be believed.
   *
   * A gateway's surface is published by a running process, so "no tools" has
   * two very different meanings — a gateway serving nothing, and a gateway that
   * has not told us anything. Every consumer needs to tell those apart, so the
   * provenance travels with the numbers rather than being inferred from them.
   */
  readonly surface: {
    readonly live: boolean;
    readonly stale: boolean;
    readonly neverPublished: boolean;
    readonly publishedAt: number | null;
    readonly toolCount: number;
    /** Tools whose upstream text carried injected instructions. */
    readonly injectionCount: number;
    /** Tools gateway policy hides from every tenant. */
    readonly hiddenCount: number;
    /** Tools the gateway could not classify, which it refuses. */
    readonly unclassifiedCount: number;
  };
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
  readonly pipeline: typeof ENFORCEMENT_PIPELINE;
  readonly tools: readonly ToolProtection[];
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

/**
 * `null` when the surface is unknown, which is not the same as `"locked"`.
 *
 * A gateway that has never published, or whose process is gone, tells us
 * nothing about what is reachable. Reporting `"locked"` for that case — which
 * is what deriving reach from an empty tool list used to do — states that
 * nothing can run, about a gateway that may be serving every tool it has.
 */
export function effectiveReach(server: LoadedServer, tenant: string, surface?: ToolSurfaceView): Reach | null {
  const policy = server.policy;
  const view = surface ?? toolSurfaceFor(server, tenant);
  if (!view.live) return null;

  let reachable = 0;
  let mutating = 0;

  for (const tool of view.entries) {
    // Switched off here is not reachable, whatever policy would have said, and
    // neither is a tool gateway policy hides from everyone.
    if (tool.disabled || tool.hiddenByPolicy) continue;

    const decision = decide({
      tool: tool.name,
      effect: tool.effect ?? undefined,
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
    const effect = resolveEffect({ tool: tool.name, effect: tool.effect ?? undefined, policy });
    if (effect === "write" || effect === "destructive") mutating++;
  }

  if (reachable === 0) return "locked";
  return mutating > 0 ? "approve-writes" : "read-only";
}

export function toolProtection(
  server: LoadedServer,
  tool: ToolSurfaceEntry,
  grants: readonly StandingGrantRow[]
): ToolProtection {
  const policy = server.policy;
  const effect = tool.effect ?? undefined;
  const decision = decide({
    tool: tool.name,
    effect,
    args: {},
    policy,
    ...(policy.tenant ? { tenant: { expected: server.tenantValue } } : {})
  });

  const effective = resolveEffect({ tool: tool.name, effect, policy });
  const matchedRule = policy.rules.find((r) => globMatch(r.match, tool.name));
  const schema = asObjectSchema(tool.inputSchema);
  const required = new Set(schema.required);

  return {
    name: tool.name,
    description: tool.description,
    rawDescription: tool.rawDescription,
    upstream: tool.upstream,
    effect: tool.effect,
    effectSource: tool.effectSource,
    hiddenByPolicy: tool.hiddenByPolicy,
    injection: tool.injection,
    verdict: { kind: decision.kind, ruleId: decision.ruleId, reason: decision.reason },
    verdictStage: verdictStage(decision.ruleId),
    reclassifiedTo: effective && effective !== tool.effect ? effective : null,
    requiresApproval: decision.kind === "approve",
    unreachable: decision.kind === "approve" && policy.approvals.mode === "deny",
    exposure: {
      disabled: tool.disabled !== null,
      setBy: tool.disabled?.setBy ?? null,
      setAt: tool.disabled?.setAt ?? null,
      reason: tool.disabled?.reason || null,
      policyWouldExpose: decision.kind !== "deny"
    },
    args: Object.entries(schema.properties).map(([name, node]) => ({
      name,
      type: node.type,
      required: required.has(name),
      description: node.description,
      constrainedByRule: matchedRule?.args?.[name] ? matchedRule.id : null
    })),
    schemaClosed:
      schema.additionalProperties === false ? true : schema.additionalProperties === true ? false : null,
    standingGrants: grants.map((grant) => {
      const match = grantMatches(grant, tool.name, tool.effect, {});
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
  };
}

/**
 * Reads an upstream `inputSchema` without trusting its shape.
 *
 * It is whatever a third-party server advertised, passed through verbatim
 * because converting it would mean either losing constraints or widening what
 * is accepted. So it may be any JSON at all, and this narrows it to the parts
 * the view needs without asserting a type it has not checked.
 */
function asObjectSchema(raw: unknown): {
  properties: Record<string, { type?: string; description?: string }>;
  required: string[];
  additionalProperties: unknown;
} {
  const schema = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  const rawProps = schema["properties"];
  const properties: Record<string, { type?: string; description?: string }> = {};
  if (typeof rawProps === "object" && rawProps !== null) {
    for (const [name, node] of Object.entries(rawProps as Record<string, unknown>)) {
      const n = (typeof node === "object" && node !== null ? node : {}) as Record<string, unknown>;
      properties[name] = {
        ...(typeof n["type"] === "string" ? { type: n["type"] } : {}),
        ...(typeof n["description"] === "string" ? { description: n["description"] } : {})
      };
    }
  }
  const rawRequired = schema["required"];
  return {
    properties,
    required: Array.isArray(rawRequired) ? rawRequired.filter((r): r is string => typeof r === "string") : [],
    additionalProperties: schema["additionalProperties"]
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

export function buildProtection(server: LoadedServer, tenant: string, explicit = false): ServerProtection {
  const policy = server.policy;
  const surface = toolSurfaceFor(server, tenant);
  const toolNames = surface.entries.map((t) => t.name);
  const store = storeFor(server);
  const scoped = scopedFor(server, tenant);
  const grants = scoped.listGrants({ activeOnly: true });

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
    tenant_scope: tenant,
    explicitTenant: explicit,
    posture: policy.defaults.mode,
    reach: effectiveReach(server, tenant, surface),
    surface: {
      live: surface.live,
      stale: surface.stale,
      neverPublished: surface.neverPublished,
      publishedAt: surface.publishedAt,
      toolCount: surface.entries.length,
      injectionCount: surface.entries.filter((t) => t.injection && t.injection.length > 0).length,
      hiddenCount: surface.entries.filter((t) => t.hiddenByPolicy).length,
      unclassifiedCount: surface.entries.filter((t) => t.effect === null).length
    },
    onUnclassified: policy.defaults.on_unclassified,
    toolBudget: {
      budget: policy.tool_budget,
      enabled: surface.entries.length,
      ok: surface.entries.length <= policy.tool_budget
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
      allowIpLiterals: policy.egress.allow_ip_literals
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
    pipeline: ENFORCEMENT_PIPELINE,
    tools: surface.entries.map((tool) => toolProtection(server, tool, grants))
  };
}

/** The last few decisions recorded for one tool. */
export function recentActivity(server: LoadedServer, tool: string, limit = 10) {
  if (!server.policy.audit.enabled) return [];
  return queryAuditLog(server.auditPath, { tool, limit }).records;
}

