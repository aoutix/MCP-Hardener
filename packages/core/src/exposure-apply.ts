import type { AuditLog } from "./audit.js";
import type { ScopedApprovals } from "./approvals.js";
import type { Effect } from "./policy.js";
import { EXPOSURE_DISABLE_RULE, EXPOSURE_ENABLE_RULE, type ExposureChange } from "./exposure.js";

/**
 * Switching one tool off, or handing it back to policy.
 *
 * Three callers now flip this bit — the review console, a hosted gateway's
 * admin API, and the gateway CLI — and the rule about what happens when the
 * audit record cannot be written is different in each direction and easy to
 * get backwards. Copying it three times is how two of the copies end up
 * subtly wrong, so it lives here once:
 *
 * - **Switching off only ever tightens.** If the record cannot be written the
 *   change is *kept* and the failure is reported, because undoing a
 *   restriction to preserve the log would be trading safety for bookkeeping.
 * - **Switching on loosens**, so an unauditable change is *put back*. A
 *   permission that was restored with no record of who restored it is exactly
 *   the thing the log exists to prevent.
 * - **Enabling something that was never off writes nothing at all.** A record
 *   there would describe a permission change that did not happen.
 *
 * This file is separate from `exposure.ts` because `approvals.ts` imports
 * that one, and this needs `ScopedApprovals`.
 */

export interface ExposureApplyOptions {
  /** Already bound to one component and one tenant. */
  readonly scoped: ScopedApprovals;
  readonly audit: AuditLog;
  readonly change: ExposureChange;
  /** Who is flipping it, as the audit record will name them. */
  readonly actor: string;
  /** For the record; a gateway's upstream tool may have none. */
  readonly effect: Effect | null | undefined;
  /**
   * Where the flip came from, in prose: "the console", "the admin API",
   * "the gateway CLI". Interpolated into the reason so one code path still
   * produces an honest record for each caller.
   */
  readonly channel: string;
}

export interface ExposureApplyResult {
  /** Whether the row's presence actually flipped. A repeat is not a change. */
  readonly changed: boolean;
  /** Set when the change stands but could not be recorded. */
  readonly warning: string | null;
}

export class ExposureAuditFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExposureAuditFailed";
  }
}

export function applyExposureChange(options: ExposureApplyOptions): ExposureApplyResult {
  const { scoped, audit, change, actor, effect, channel } = options;
  const name = change.tool;
  /*
   * Taken from the scope rather than passed in, so the record and the row it
   * describes can never disagree about whose switch this is.
   */
  const tenant = scoped.scope.tenant || null;
  const before = scoped.toolExposure(name);
  let warning: string | null = null;

  if (change.disabled) {
    const row = scoped.disableTool(name, actor, change.reason);
    try {
      audit.appendStrict({
        tool: name,
        effect: effect ?? null,
        decision: "deny",
        tenant,
        rule_id: EXPOSURE_DISABLE_RULE,
        reason:
          `${name} switched off via ${channel} by ${actor}` +
          (change.reason ? `: ${change.reason}` : "") +
          "; it is no longer advertised to the model and every call to it is refused",
        outcome: "completed",
        args_redacted: { tool: name, effect: effect ?? null, reason: row.reason }
      });
    } catch (err) {
      warning = `${name} was switched off but the audit record failed: ${(err as Error).message}`;
    }
  } else {
    const removed = scoped.enableTool(name);
    if (removed) {
      try {
        audit.appendStrict({
          tool: name,
          effect: effect ?? null,
          decision: "approve",
          tenant,
          rule_id: EXPOSURE_ENABLE_RULE,
          reason:
            `${name} switched back on via ${channel} by ${actor} ` +
            `(switched off by ${removed.set_by} at ${new Date(removed.set_at).toISOString()}); ` +
            "policy decides it again from here",
          outcome: "completed",
          args_redacted: { tool: name, effect: effect ?? null }
        });
      } catch (err) {
        /*
         * Put back. `set_at` becomes now rather than the original moment,
         * which is a small untruth in the restored row -- but the
         * alternative is a `set_at` parameter on the store existing solely
         * for this path, and the audit record of the failed attempt is where
         * the real history lives.
         */
        scoped.disableTool(name, removed.set_by, removed.reason);
        throw new ExposureAuditFailed(
          `${name} was left switched off because switching it on could not be audited: ${(err as Error).message}`
        );
      }
    }
  }

  return { changed: (before !== undefined) !== change.disabled, warning };
}
