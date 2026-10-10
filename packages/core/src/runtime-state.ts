import { canonicalJson, sha256 } from "./canonical.js";
import type { Policy } from "./policy.js";

/**
 * What a running server last told the world about itself.
 *
 * The console reads `policy.yaml` from disk on every request, which is what
 * makes its numbers live. A running server does not: it parses the policy once
 * at startup and enforces that copy until it is restarted. So the two can
 * disagree, and the console was presenting its own fresher read as though it
 * were what the server is enforcing — confidently reporting a timeout that
 * nothing has applied yet.
 *
 * Nothing on disk could settle that. The audit log only records decisions about
 * calls, so it says a server was alive at some point, never which policy it
 * loaded. The policy file's mtime is no better: an edit after the last recorded
 * call could mean the server has not seen it, or that the server restarted
 * since and has simply had nothing to do.
 *
 * So a server now states it outright. A row here carries the digest of the
 * policy the process actually parsed, and the console compares that against the
 * digest of what it just read. Equal means the displayed configuration is the
 * enforced one; different means it is not, and the console says so rather than
 * implying otherwise by silence.
 *
 * Rows live in the approvals database for the same reasons exposure overrides
 * do: both processes already open it, it is WAL-mode and lock-safe, and it
 * needs no new transport between them.
 *
 * This is advisory, and only ever subtracts confidence. A missing or stale row
 * means the console does not know what is running, never that a call will be
 * treated differently — enforcement reads none of this.
 */
export interface RuntimeStateRow {
  /** The audit `component` of the server this describes. */
  readonly component: string;
  readonly pid: number;
  /** When the process parsed its policy, which is when it started. */
  readonly started_at: number;
  /** Refreshed on the exposure poll; how a dead process is told from a live one. */
  readonly last_seen: number;
  /** `policyDigest` of the policy this process is enforcing. */
  readonly policy_digest: string;
  /** Where it read that policy from, to name the file in a warning. */
  readonly policy_path: string;
}

export const RUNTIME_STATE_SCHEMA = `
CREATE TABLE IF NOT EXISTS runtime_state (
  component     TEXT PRIMARY KEY,
  pid           INTEGER NOT NULL,
  started_at    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  policy_digest TEXT NOT NULL,
  policy_path   TEXT NOT NULL
);
`;

/**
 * A digest of the policy as *parsed*, not as written.
 *
 * Hashing the file bytes would report a change for a reformatted comment and
 * miss that two differently-written files mean the same thing. Hashing the
 * parsed object compares what is actually enforced: defaults are already
 * filled in, key order does not matter, and a whitespace edit is correctly
 * silent.
 */
export function policyDigest(policy: Policy): string {
  return sha256(canonicalJson(policy));
}

/**
 * How long a row stays believable without a refresh.
 *
 * The runtime refreshes on its exposure poll, which defaults to every 2s. Three
 * missed polls plus a second of slack is long enough that a loaded machine does
 * not make a healthy server look dead, and short enough that a console opened
 * after a server exits does not keep quoting it.
 */
export const RUNTIME_STATE_TTL_MS = 7_000;

export function runtimeStateIsLive(row: RuntimeStateRow, now = Date.now()): boolean {
  return now - row.last_seen <= RUNTIME_STATE_TTL_MS;
}
