import { randomBytes } from "node:crypto";
import { z } from "zod";
import { globMatch } from "./glob.js";
import { checkArgConstraints } from "./decide.js";
import { ArgConstraintSchema, EffectSchema, type ArgConstraint, type Effect } from "./policy.js";

/**
 * Standing grants: a pre-approval for a *class* of call rather than one exact
 * call.
 *
 * An ordinary approval is bound to `sha256(tool + canonical arguments)`, which
 * is what stops a grant for a 10-unit transfer releasing a 10,000-unit one. A
 * standing grant deliberately gives that up in exchange for not asking a human
 * the same question repeatedly, so every other bound is kept tight:
 *
 * - it matches a glob over the tool name, not "anything";
 * - its argument constraints are the same `ArgConstraint` vocabulary policy
 *   rules use, checked by the same `checkArgConstraints`;
 * - it always expires, because a pre-approval with no end date is a posture
 *   change and those belong in `policy.yaml` where they get reviewed;
 * - it can cap how many calls it releases;
 * - it is revocable, and creation, use and revocation are all audited.
 *
 * A grant is strictly weaker than editing the policy: it cannot widen what
 * `decide()` permits, only spare a human from re-approving what policy already
 * routed to them.
 */

/**
 * The longest a pre-approval may last. A grant is a concession made without a
 * human in the loop at call time, so it has to come back for renewal; past a
 * month it is a posture change wearing a grant's clothes.
 */
export const MAX_GRANT_TTL_SECONDS = 30 * 24 * 60 * 60;

export type StandingGrantState = "active" | "revoked" | "expired" | "exhausted";

export interface StandingGrantRow {
  readonly id: string;
  /** Which server this belongs to; "" on a row written before scoping. */
  readonly component: string;
  /** Whose data the grant covers; "" when no tenant is configured. */
  readonly tenant: string;
  readonly created_at: number;
  /** Always set. There are no permanent grants on purpose. */
  readonly expires_at: number;
  /** Glob over the tool name, same dialect as `rules[].match`. */
  readonly tool_match: string;
  /** Optional extra restriction; null matches any effect. */
  readonly effect: string | null;
  /** JSON object of `Record<string, ArgConstraint>`. */
  readonly constraints: string;
  /** null means unlimited within the TTL. */
  readonly max_uses: number | null;
  readonly uses: number;
  readonly reason: string;
  readonly created_by: string;
  readonly state: StandingGrantState;
  readonly revoked_at: number | null;
  readonly revoked_by: string | null;
}

export const GRANTS_SCHEMA = `
CREATE TABLE IF NOT EXISTS standing_grants (
  id          TEXT PRIMARY KEY,
  component   TEXT NOT NULL DEFAULT '',
  tenant      TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  tool_match  TEXT NOT NULL,
  effect      TEXT,
  constraints TEXT NOT NULL,
  max_uses    INTEGER,
  uses        INTEGER NOT NULL DEFAULT 0,
  reason      TEXT NOT NULL,
  created_by  TEXT NOT NULL,
  state       TEXT NOT NULL,
  revoked_at  INTEGER,
  revoked_by  TEXT
);
CREATE INDEX IF NOT EXISTS grants_active ON standing_grants (component, tenant, state, expires_at);
`;

export function newGrantId(): string {
  return `sg_${randomBytes(6).toString("hex")}`;
}

/** What a caller supplies; the store assigns the id, state and use count. */
export interface StandingGrantDraft {
  readonly tool_match: string;
  readonly effect?: Effect | null;
  readonly constraints?: Record<string, ArgConstraint>;
  readonly expires_at: number;
  readonly max_uses?: number | null;
  readonly reason: string;
  readonly created_by: string;
}

/**
 * Validates a grant as it arrives from an untrusted surface such as the web
 * console. `expires_at` is required and must be in the future; a grant that is
 * already expired would be silently useless rather than refused.
 */
export const StandingGrantDraftSchema = z
  .object({
    tool_match: z.string().min(1),
    effect: EffectSchema.nullish(),
    constraints: z.record(z.string(), ArgConstraintSchema).default({}),
    expires_at: z.number().int().positive(),
    max_uses: z.number().int().positive().nullish(),
    reason: z.string().min(1),
    created_by: z.string().min(1)
  })
  .strict();

export function parseGrantDraft(raw: unknown, now = Date.now()): StandingGrantDraft {
  const draft = StandingGrantDraftSchema.parse(raw);
  if (draft.expires_at <= now) {
    throw new Error("expires_at is in the past; a grant must be able to release at least one call");
  }
  if (draft.expires_at - now > MAX_GRANT_TTL_SECONDS * 1000) {
    throw new Error(
      `a grant may not last longer than ${MAX_GRANT_TTL_SECONDS / 86400} days; ` +
        "a longer-lived permission belongs in policy.yaml where it gets reviewed"
    );
  }
  // An unparseable pattern would be a closed door rather than an open one, but
  // it is still a typo worth reporting at creation instead of at call time.
  if (draft.tool_match.includes("{") && !draft.tool_match.includes("}")) {
    throw new Error(`tool_match "${draft.tool_match}" has an unclosed brace`);
  }
  // A wildcard grant bounded only by time is indistinguishable from widening
  // the policy, which is the one thing the console must not do quietly. Require
  // a second bound so its blast radius is something a reviewer can state.
  const wildcard = draft.tool_match.includes("*") || draft.tool_match.includes("?");
  const constrained = Object.keys(draft.constraints ?? {}).length > 0;
  if (wildcard && !constrained && (draft.max_uses ?? null) === null) {
    throw new Error(
      `tool_match "${draft.tool_match}" matches a family of tools, so it also needs max_uses ` +
        "or argument constraints; an unbounded wildcard grant is equivalent to editing policy.yaml"
    );
  }
  return draft;
}

/** Decodes the stored constraint JSON, treating corruption as "no match". */
export function grantConstraints(row: StandingGrantRow): Record<string, ArgConstraint> | null {
  try {
    const parsed = JSON.parse(row.constraints) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, ArgConstraint>;
  } catch {
    return null;
  }
}

export interface GrantMatchResult {
  readonly matches: boolean;
  /** Why it did not match, for the console's dry-run preview. */
  readonly reason: string;
}

/**
 * Whether this grant covers this call.
 *
 * A grant whose constraints reject the arguments is *not a match*, which means
 * the caller falls through to ordinary approval. It must never turn into a
 * denial: a narrow pre-approval exists to save a human some clicks, and letting
 * it block a call the human would have waved through would make adding one
 * actively harmful.
 */
export function grantMatches(
  row: StandingGrantRow,
  tool: string,
  effect: Effect | null,
  args: Record<string, unknown>
): GrantMatchResult {
  if (!globMatch(row.tool_match, tool)) {
    return { matches: false, reason: `tool "${tool}" does not match "${row.tool_match}"` };
  }
  if (row.effect !== null && row.effect !== effect) {
    return { matches: false, reason: `grant covers ${row.effect} calls, this one is ${effect ?? "unclassified"}` };
  }
  const constraints = grantConstraints(row);
  if (constraints === null) {
    return { matches: false, reason: "the grant's stored constraints are unreadable" };
  }
  const violations = checkArgConstraints(args, constraints);
  if (violations.length > 0) {
    return {
      matches: false,
      reason: violations.map((v) => `${v.arg}: ${v.message}`).join("; ")
    };
  }
  return { matches: true, reason: `covered by standing grant ${row.id}` };
}

/** True when the grant can still release a call, ignoring argument matching. */
export function grantIsLive(row: StandingGrantRow, now = Date.now()): boolean {
  if (row.state !== "active") return false;
  if (row.expires_at <= now) return false;
  return row.max_uses === null || row.uses < row.max_uses;
}
