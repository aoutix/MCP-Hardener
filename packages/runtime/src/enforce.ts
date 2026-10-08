import {
  decide,
  EgressDenied,
  type ApprovalBroker,
  type AuditLog,
  type Decision,
  type Effect,
  type Policy
} from "@hmcp/core";

/**
 * The enforcement pipeline, shared by generated servers and the gateway:
 * classify, decide, obtain approval if the decision calls for it, run the call,
 * and record the outcome either way. Both halves of this project call it so the
 * two cannot drift apart.
 */

export interface CallResult {
  readonly ok: boolean;
  /** Text handed back to the agent. */
  readonly message: string;
  readonly decision: Decision;
  readonly approvalId: string | null;
  readonly upstream?: {
    host: string | null;
    method: string | null;
    path: string | null;
    status: number | null;
    bytes: number | null;
  } | null;
}

export interface EnforceOptions {
  readonly policy: Policy;
  readonly audit: AuditLog;
  readonly approvals: ApprovalBroker;
  readonly tenantValue?: string | undefined;
  readonly actor?: string;
  readonly session?: string;
}

export interface EnforceCall<T> {
  readonly tool: string;
  readonly effect: Effect | undefined;
  readonly args: Record<string, unknown>;
  /**
   * Set when an exposure override has switched this tool off. Resolved by the
   * caller, which is the half that knows the server's identity and owns the
   * approvals database handle.
   */
  readonly disabled?: { readonly reason: string } | undefined;
  /** Shown to a human in the approval prompt. */
  readonly target?: string;
  /** Runs only after the decision permits it. */
  readonly run: () => Promise<{
    result: T;
    upstream?: CallResult["upstream"];
  }>;
}

export type EnforceOutcome<T> =
  | { readonly kind: "ok"; readonly result: T; readonly decision: Decision; readonly approvalId: string | null }
  | { readonly kind: "refused"; readonly message: string; readonly decision: Decision };

/**
 * Runs one tool call under policy. `run` is invoked only on a permitting
 * decision; a refusal never reaches it, so there is no path where the upstream
 * is touched before the decision is made.
 */
export async function enforceCall<T>(options: EnforceOptions, call: EnforceCall<T>): Promise<EnforceOutcome<T>> {
  const { policy, audit, approvals } = options;
  const started = Date.now();
  const { args_hash, args_redacted } = audit.prepareArgs(call.args);

  const base = {
    tool: call.tool,
    args_hash,
    args_redacted,
    tenant: options.tenantValue ?? null,
    actor: options.actor,
    session: options.session
  };

  const decision = decide({
    tool: call.tool,
    effect: call.effect,
    args: call.args,
    policy,
    tenant: policy.tenant ? { expected: options.tenantValue } : undefined,
    ...(call.disabled ? { disabled: true, disabledReason: call.disabled.reason } : {})
  });

  let approvalId: string | null = null;
  let grantId: string | null = null;

  if (decision.kind === "deny") {
    audit.append({
      ...base,
      effect: decision.effect,
      decision: "deny",
      rule_id: decision.ruleId,
      reason: decision.reason,
      outcome: "denied",
      duration_ms: Date.now() - started
    });
    return {
      kind: "refused",
      decision,
      message: `Refused by policy (${decision.ruleId}): ${decision.reason}`
    };
  }

  if (decision.kind === "approve") {
    const outcome = await approvals.request({
      tool: call.tool,
      effect: decision.effect,
      args: call.args,
      reason: decision.reason,
      actor: options.actor ?? "agent",
      session: options.session ?? "unknown",
      target: call.target
    });

    if (!outcome.granted) {
      audit.append({
        ...base,
        effect: decision.effect,
        decision: "approve",
        rule_id: decision.ruleId,
        reason: outcome.reason,
        outcome: "pending-approval",
        approval_id: outcome.approvalId,
        duration_ms: Date.now() - started
      });
      const message = [`Approval required (${decision.ruleId}): ${outcome.reason}`, outcome.instructions]
        .filter(Boolean)
        .join("\n\n");
      return { kind: "refused", decision, message };
    }
    approvalId = outcome.approvalId;
    grantId = outcome.via === "standing" ? (outcome.grantId ?? null) : null;

    if (grantId) {
      // Recorded before the call runs, and separately from the call's own
      // record, so that spending a pre-approval is auditable even if the
      // upstream request then fails. This is the "every pre-approval is in the
      // log" guarantee for the use half; create and revoke are written by
      // whoever manages the grant.
      audit.append({
        ...base,
        effect: decision.effect,
        decision: "approve",
        rule_id: "standing_grant.use",
        reason: `released by standing grant ${grantId} without asking a human: ${decision.reason}`,
        outcome: "completed",
        approval_id: approvalId,
        grant_id: grantId,
        duration_ms: Date.now() - started
      });
    }
  }

  try {
    const { result, upstream } = await call.run();
    audit.append({
      ...base,
      effect: decision.effect,
      decision: decision.kind,
      rule_id: decision.ruleId,
      reason: decision.reason,
      outcome: "completed",
      approval_id: approvalId,
      grant_id: grantId,
      upstream: upstream ?? null,
      duration_ms: Date.now() - started
    });
    return { kind: "ok", result, decision, approvalId };
  } catch (err) {
    const message = describeError(err);
    audit.append({
      ...base,
      effect: decision.effect,
      decision: decision.kind,
      rule_id: decision.ruleId,
      reason: decision.reason,
      outcome: "error",
      error: message,
      approval_id: approvalId,
      grant_id: grantId,
      duration_ms: Date.now() - started
    });
    return { kind: "refused", decision, message };
  }
}

function describeError(err: unknown): string {
  if (err instanceof EgressDenied) return `Egress refused (${err.code}): ${err.message}`;
  return (err as Error)?.message ?? String(err);
}
