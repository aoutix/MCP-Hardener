import { globMatch } from "./glob.js";
import { EXPOSURE_RULE } from "./exposure.js";
import type { ArgConstraint, Effect, Policy, Rule, TenantConfig } from "./policy.js";

export type Decision =
  | { readonly kind: "allow"; readonly effect: Effect | null; readonly ruleId: string; readonly reason: string }
  | { readonly kind: "approve"; readonly effect: Effect | null; readonly ruleId: string; readonly reason: string }
  | { readonly kind: "deny"; readonly effect: Effect | null; readonly ruleId: string; readonly reason: string };

export interface TenantContext {
  /** The tenant bound to the running credential. */
  readonly expected: string | undefined;
  /**
   * A tenant value present in the agent-supplied arguments. For generated
   * servers this should always be absent, because the field is stripped from
   * the agent-facing schema; its presence here is a defense-in-depth check that
   * matters most for the gateway, where schemas are not ours to control.
   */
  readonly supplied?: string | undefined;
}

export interface DecideInput {
  readonly tool: string;
  /** Declared effect from a manifest or upstream annotation; undefined means unclassified. */
  readonly effect?: Effect | undefined;
  readonly args?: Record<string, unknown> | undefined;
  readonly policy: Policy;
  readonly tenant?: TenantContext | undefined;
  /**
   * An exposure override from the console has switched this tool off.
   *
   * Looked up by the caller rather than here, because that is a read from the
   * approvals database and `decide()` stays pure and synchronous. It can only
   * ever refuse: there is no value of this that permits a call the rules below
   * would have refused.
   */
  readonly disabled?: boolean | undefined;
  /** Why it was switched off, for the refusal handed back to the agent. */
  readonly disabledReason?: string | undefined;
}

const POSTURE_RULE = "defaults.mode";
const UNCLASSIFIED_RULE = "defaults.on_unclassified";
const TENANT_RULE = "tenant.on_mismatch";

/** First rule whose glob matches, or undefined. */
function firstMatch(rules: readonly Rule[], tool: string): Rule | undefined {
  return rules.find((r) => globMatch(r.match, tool));
}

/**
 * Resolves the effective classification. A matching rule that carries an
 * `effect` reclassifies the tool - that is how a `POST /search` gets moved into
 * the read bucket deliberately, by a named rule, rather than by a heuristic.
 */
export function resolveEffect(input: DecideInput): Effect | null {
  const rule = firstMatch(input.policy.rules, input.tool);
  return rule?.effect ?? input.effect ?? null;
}

export interface ConstraintViolation {
  readonly arg: string;
  readonly message: string;
}

/** Checks one argument against one constraint. */
function checkConstraint(arg: string, value: unknown, c: ArgConstraint): ConstraintViolation | null {
  const fail = (message: string): ConstraintViolation => ({ arg, message });

  if (value === undefined || value === null) {
    return c.required ? fail(`${arg} is required by policy`) : null;
  }
  if (c.const !== undefined && value !== c.const) {
    return fail(`${arg} must equal ${JSON.stringify(c.const)}`);
  }
  if (c.enum && !c.enum.some((allowed) => allowed === value)) {
    return fail(`${arg}=${JSON.stringify(value)} is not one of ${JSON.stringify(c.enum)}`);
  }
  if (c.max !== undefined || c.min !== undefined) {
    const n = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(n)) return fail(`${arg} must be numeric to be bounded by policy`);
    if (c.max !== undefined && n > c.max) return fail(`${arg}=${n} exceeds the policy maximum of ${c.max}`);
    if (c.min !== undefined && n < c.min) return fail(`${arg}=${n} is below the policy minimum of ${c.min}`);
  }
  if (c.maxLength !== undefined) {
    const len = typeof value === "string" ? value.length : Array.isArray(value) ? value.length : undefined;
    if (len === undefined) return fail(`${arg} must be a string or array to be length-bounded`);
    if (len > c.maxLength) return fail(`${arg} length ${len} exceeds the policy maximum of ${c.maxLength}`);
  }
  if (c.pattern !== undefined) {
    if (typeof value !== "string") return fail(`${arg} must be a string to be pattern-matched`);
    let re: RegExp;
    try {
      re = new RegExp(c.pattern);
    } catch {
      // An unparseable pattern is a closed door, not an open one.
      return fail(`${arg} has an unparseable policy pattern`);
    }
    if (!re.test(value)) return fail(`${arg} does not match the required pattern`);
  }
  return null;
}

export function checkArgConstraints(
  args: Record<string, unknown>,
  constraints: Record<string, ArgConstraint>
): ConstraintViolation[] {
  const violations: ConstraintViolation[] = [];
  for (const [arg, c] of Object.entries(constraints)) {
    const v = checkConstraint(arg, args[arg], c);
    if (v) violations.push(v);
  }
  return violations;
}

/** Collects the tenant-identifying names a policy cares about. */
export function tenantFieldNames(tenant: TenantConfig): string[] {
  return [tenant.field, ...tenant.aliases];
}

/**
 * Pulls an agent-supplied tenant value out of an argument object, matching the
 * canonical field name or any alias, case-insensitively.
 */
export function extractSuppliedTenant(
  args: Record<string, unknown> | undefined,
  tenant: TenantConfig
): string | undefined {
  if (!args) return undefined;
  const wanted = new Set(tenantFieldNames(tenant).map((f) => f.toLowerCase()));
  for (const [key, value] of Object.entries(args)) {
    if (!wanted.has(key.toLowerCase())) continue;
    if (value === undefined || value === null) continue;
    return String(value);
  }
  return undefined;
}

/**
 * The single decision point. Pure and synchronous by design: if enforcement
 * ever needed to reach the network to decide, that would be a hole, not a
 * feature. Generated servers and the gateway both route every call through
 * this function, so the two cannot drift apart.
 */
export function decide(input: DecideInput): Decision {
  const { policy, tool } = input;
  const args = input.args ?? {};
  const effect = resolveEffect(input);

  // 0. A tool switched off by an operator is refused before anything else is
  //    weighed, because nothing later can make it reachable again and a reason
  //    that names the switch is more useful than one that names a rule.
  if (input.disabled) {
    return {
      kind: "deny",
      effect,
      ruleId: EXPOSURE_RULE,
      reason: input.disabledReason ?? `tool "${tool}" is switched off`
    };
  }

  // 1. Tenant integrity comes first. A call that tries to name a tenant other
  //    than the credential's own is refused whatever the rules say about it.
  if (policy.tenant) {
    const expected = input.tenant?.expected;
    const supplied = input.tenant?.supplied ?? extractSuppliedTenant(args, policy.tenant);
    if (supplied !== undefined && expected !== undefined && supplied !== expected) {
      if (policy.tenant.on_mismatch === "deny") {
        return {
          kind: "deny",
          effect,
          ruleId: TENANT_RULE,
          reason: `tenant scope violation: call named ${policy.tenant.field}=${JSON.stringify(supplied)} but the credential is bound to a different tenant`
        };
      }
    }
    if (policy.tenant.required && expected === undefined) {
      return {
        kind: "deny",
        effect,
        ruleId: "tenant.required",
        reason: `tenant scoping is required but no value was resolved from ${policy.tenant.source.kind}`
      };
    }
  }

  // 2. An unclassified tool is refused. This is what makes a newly added
  //    upstream tool safe by default rather than reachable by default.
  if (effect === null) {
    const kind = policy.defaults.on_unclassified === "approve" ? "approve" : "deny";
    return {
      kind,
      effect,
      ruleId: UNCLASSIFIED_RULE,
      reason: `tool "${tool}" has no effect classification; policy says ${policy.defaults.on_unclassified} for unclassified tools`
    };
  }

  // 3. First matching rule wins, but its argument bounds are checked first - a
  //    rule that approves transfers under 50k must not approve one over it.
  const rule = firstMatch(policy.rules, tool);
  if (rule) {
    if (rule.args) {
      const violations = checkArgConstraints(args, rule.args);
      if (violations.length > 0) {
        return {
          kind: "deny",
          effect,
          ruleId: rule.id,
          reason: `argument constraints from rule "${rule.id}" not satisfied: ${violations
            .map((v) => v.message)
            .join("; ")}`
        };
      }
    }
    return {
      kind: rule.decision,
      effect,
      ruleId: rule.id,
      reason: rule.reason ?? `rule "${rule.id}" (${rule.match}) says ${rule.decision} for ${effect} tools`
    };
  }

  // 4. No rule matched: fall back to the posture.
  return postureDecision(policy, effect);
}

function postureDecision(policy: Policy, effect: Effect): Decision {
  const base = { effect, ruleId: POSTURE_RULE } as const;
  switch (policy.defaults.mode) {
    case "read-only":
      return effect === "read"
        ? { ...base, kind: "allow", reason: "read-only posture allows reads" }
        : {
            ...base,
            kind: "deny",
            reason: `read-only posture refuses ${effect} tools; add an explicit rule to permit this one`
          };
    case "approve-writes":
      return effect === "read"
        ? { ...base, kind: "allow", reason: "approve-writes posture allows reads" }
        : { ...base, kind: "approve", reason: `approve-writes posture requires approval for ${effect} tools` };
    case "locked":
      return {
        ...base,
        kind: "deny",
        reason: "locked posture refuses everything without an explicit allow rule"
      };
  }
}

/** True when a decision permits the call to reach the upstream. */
export function isPermitted(d: Decision): boolean {
  return d.kind === "allow";
}
