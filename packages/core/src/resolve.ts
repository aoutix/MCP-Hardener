import { existsSync } from "node:fs";
import { defaultPolicy, expandPath, loadPolicy, type Policy } from "./policy.js";

/**
 * How every entry point finds its policy: an explicit path, else a
 * `policy.yaml` beside the caller, else the built-in read-only default.
 *
 * This lived inside the CLI, which meant the web console would have had to
 * reimplement it and could have drifted into a different default. The default
 * mattering here is the whole point: falling back to anything other than
 * read-only would make a missing file a way to widen the posture.
 */
export function resolvePolicy(path?: string, cwd = process.cwd()): Policy {
  if (path) return loadPolicy(path);
  const local = expandPath("policy.yaml", cwd);
  if (existsSync(local)) return loadPolicy(local);
  return defaultPolicy();
}

/** Where the approval database lives, given an optional override. */
export function resolveStorePath(override: string | undefined, policy: Policy): string {
  return override ?? policy.approvals.store_path;
}

/** Where the audit log lives, given an optional override. */
export function resolveAuditPath(override: string | undefined, policy: Policy, cwd = process.cwd()): string {
  return expandPath(override ?? policy.audit.path, cwd);
}

/**
 * The records `hmcp audit tail --denied` shows: anything refused, plus anything
 * that did not run to completion.
 */
export const DENIED_QUERY = {
  outcome: ["denied", "pending-approval", "error"] as const
};
