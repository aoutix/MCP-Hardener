import { z } from "zod";

/**
 * Exposure overrides: taking one tool off the model's menu from the console,
 * without editing `policy.yaml`.
 *
 * The whole point of this project is that `policy.yaml` is the reviewed,
 * version-controlled answer to "what may this agent do", so a console switch
 * must not become a second, unreviewed policy. What makes this one safe is that
 * it is strictly subtractive:
 *
 * - the only state that is ever stored is `disabled`, for one named tool;
 * - a disabled tool is refused before anything else is considered, and is not
 *   advertised to the model at all;
 * - "enabling" a tool only *deletes* that row. It restores whatever policy
 *   already said, which may well still be deny or approve. There is no stored
 *   state that can make a call reachable that `decide()` would have refused.
 *
 * So the switch can always be turned off, and turning it back on hands the
 * question back to policy rather than answering it. A permission that policy
 * does not already grant still belongs in `policy.yaml`.
 *
 * Rows live in the approvals database, which is the existing channel between
 * the console and a running server: both processes already open it, it is
 * already WAL-mode and lock-safe, and a toggle therefore takes effect without
 * restarting anything.
 */

/** Scoped per server, because one approvals database is shared by default. */
export interface ToolExposureRow {
  /** The audit `component` of the server this applies to. */
  readonly component: string;
  readonly tool: string;
  readonly reason: string;
  readonly set_at: number;
  readonly set_by: string;
}

export const EXPOSURE_SCHEMA = `
CREATE TABLE IF NOT EXISTS tool_exposure (
  component TEXT NOT NULL,
  tenant    TEXT NOT NULL DEFAULT '',
  tool      TEXT NOT NULL,
  reason    TEXT NOT NULL,
  set_at    INTEGER NOT NULL,
  set_by    TEXT NOT NULL,
  PRIMARY KEY (component, tenant, tool)
);
`;

/** The rule id a refusal from an exposure override is recorded under. */
export const EXPOSURE_RULE = "exposure.disabled";

export const ExposureChangeSchema = z
  .object({
    tool: z.string().min(1),
    disabled: z.boolean(),
    /** Free text, recorded in the audit log and shown in the console. */
    reason: z.string().max(500).default("")
  })
  .strict();
export type ExposureChange = z.infer<typeof ExposureChangeSchema>;

export function parseExposureChange(raw: unknown): ExposureChange {
  return ExposureChangeSchema.parse(raw);
}

/** The reason text a refusal carries when a tool is switched off. */
export function exposureDeniedReason(row: ToolExposureRow): string {
  const when = new Date(row.set_at).toISOString();
  return (
    `tool "${row.tool}" was switched off in the console by ${row.set_by} at ${when}` +
    (row.reason ? `: ${row.reason}` : "") +
    ". Policy was not changed; switching it back on restores whatever policy.yaml already said."
  );
}
