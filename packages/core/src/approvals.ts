import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";
import { bindingHash } from "./canonical.js";
import { redactArgs } from "./redact.js";
import { expandPath, type ApprovalsConfig, type Effect } from "./policy.js";
import {
  GRANTS_SCHEMA,
  grantMatches,
  newGrantId,
  type StandingGrantDraft,
  type StandingGrantRow
} from "./grants.js";
import { EXPOSURE_SCHEMA, type ToolExposureRow } from "./exposure.js";
import { migrate } from "./migrate.js";
import type { Scope } from "./tenant.js";
import { RUNTIME_STATE_SCHEMA, type RuntimeStateRow } from "./runtime-state.js";

export type ApprovalState = "pending" | "granted" | "denied" | "used" | "expired";

export interface ApprovalRow {
  readonly id: string;
  /** Which server this belongs to; "" on a row written before scoping. */
  readonly component: string;
  /** Whose data the call touches; "" when no tenant is configured. */
  readonly tenant: string;
  readonly created_at: number;
  readonly expires_at: number;
  readonly tool: string;
  readonly effect: string | null;
  readonly binding_hash: string;
  readonly args_redacted: string;
  readonly reason: string;
  readonly actor: string;
  readonly session: string;
  readonly state: ApprovalState;
  readonly decided_at: number | null;
  readonly decided_by: string | null;
  readonly decision_note: string | null;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS approvals (
  id            TEXT PRIMARY KEY,
  component     TEXT NOT NULL DEFAULT '',
  tenant        TEXT NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  tool          TEXT NOT NULL,
  effect        TEXT,
  binding_hash  TEXT NOT NULL,
  args_redacted TEXT NOT NULL,
  reason        TEXT NOT NULL,
  actor         TEXT NOT NULL,
  session       TEXT NOT NULL,
  state         TEXT NOT NULL,
  decided_at    INTEGER,
  decided_by    TEXT,
  decision_note TEXT
);
CREATE INDEX IF NOT EXISTS approvals_binding ON approvals (component, tenant, binding_hash, state);
CREATE INDEX IF NOT EXISTS approvals_state ON approvals (component, tenant, state, created_at);
`;

export function newApprovalId(): string {
  return `apr_${randomBytes(6).toString("hex")}`;
}

/**
 * Durable store for approval requests and grants. Backed by the built-in
 * `node:sqlite` so there is no native dependency to compile, and so an
 * out-of-band CLI in a separate process can see what a server is waiting on.
 */
/**
 * Durable store for approval requests and grants. Backed by the built-in
 * `node:sqlite` so there is no native dependency to compile, and so an
 * out-of-band CLI in a separate process can see what a server is waiting on.
 *
 * One database holds rows for many servers and many tenants: the default
 * `store_path` is shared, and a hosted gateway serves every tenant from one
 * process. So almost nothing a caller wants to do belongs on this class.
 * `scoped()` hands back the view that does, bound to one component and one
 * tenant, and that is where every query a call path makes now lives.
 *
 * What stays here is the handle, the lifecycle, and the three operations that
 * are legitimately about the whole file: the expiry janitor, an unfiltered
 * read for an operator, and the list of scopes present. Each of those is named
 * so that reaching for it is a decision rather than an accident — which is the
 * point of having moved the rest out, and the reason none of the moved methods
 * were left behind as delegates.
 */
export class ApprovalStore {
  private readonly db: DatabaseSync;
  readonly path: string;

  constructor(path: string, cwd = process.cwd()) {
    this.path = path === ":memory:" ? path : expandPath(path, cwd);
    if (this.path !== ":memory:") mkdirSync(dirname(this.path), { recursive: true });
    this.db = new DatabaseSync(this.path);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("PRAGMA busy_timeout = 5000");
    // After the pragmas, so a migration runs with WAL and the busy timeout
    // already in force: it takes the write lock, and a second process opening
    // the same file concurrently waits rather than failing.
    migrate(this.db, (db) => {
      db.exec(SCHEMA);
      db.exec(GRANTS_SCHEMA);
      db.exec(EXPOSURE_SCHEMA);
      db.exec(RUNTIME_STATE_SCHEMA);
    });
  }

  close(): void {
    this.db.close();
  }

  /**
   * The view a call path works through: every query below is filtered to one
   * component and one tenant, by the database rather than by the caller
   * remembering to.
   */
  scoped(scope: Scope): ScopedApprovals {
    return new ScopedApprovals(this.db, scope);
  }

  /**
   * Marks every past-due pending or granted row expired, across every scope.
   *
   * Deliberately unscoped: expiry is a property of the clock, not of who owns
   * the row, and a tenant whose server never runs again should not keep a
   * stale "pending" row for ever because nobody swept their scope.
   */
  expireStale(now = Date.now()): number {
    const stmt = this.db.prepare(
      "UPDATE approvals SET state = 'expired' WHERE expires_at <= ? AND state IN ('pending','granted')"
    );
    return Number(stmt.run(now).changes);
  }

  /**
   * Every waiting request in the file, whoever it belongs to.
   *
   * For an operator looking at the database as a database — draining rows left
   * by a server that no longer exists, or the ones a pre-scoping version wrote
   * under ("",""). Not for a call path: `scoped(...).listPending()` is.
   */
  listPendingAll(limit = 50): ApprovalRow[] {
    this.expireStale();
    return this.db
      .prepare("SELECT * FROM approvals WHERE state = 'pending' ORDER BY created_at ASC LIMIT ?")
      .all(limit)
      .map((r) => ({ ...r }) as unknown as ApprovalRow);
  }

  /**
   * Every request in the file, decided or not, newest first.
   *
   * The operator counterpart to `scoped(...).list()`. An `hmcp` at a terminal
   * has a policy file and a database path and no idea which component it is
   * standing in front of, so scoping it by default would mean scoping it to a
   * guess. It shows the scope on each row instead.
   */
  listAll(limit = 50): ApprovalRow[] {
    return this.db
      .prepare("SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?")
      .all(limit)
      .map((r) => ({ ...r }) as unknown as ApprovalRow);
  }

  /**
   * One request by id, whatever scope it is in.
   *
   * Safe to be unscoped because the id is the primary key, so there is nothing
   * to confuse it with, and because anyone who can call this already has the
   * database file open — scoping an operator tool against someone holding the
   * file would be theatre. The enforcement path never uses it; it has
   * `scoped(...).get()`, which cannot reach another tenant's row.
   */
  getAny(id: string): ApprovalRow | undefined {
    const row = this.db.prepare("SELECT * FROM approvals WHERE id = ?").get(id);
    return row ? ({ ...row } as unknown as ApprovalRow) : undefined;
  }

  /** An operator's decision on any parked request, by id. */
  decideAny(id: string, state: "granted" | "denied", by: string, note = ""): ApprovalRow | undefined {
    this.expireStale();
    const changes = Number(
      this.db
        .prepare(
          `UPDATE approvals SET state = ?, decided_at = ?, decided_by = ?, decision_note = ?
           WHERE id = ? AND state = 'pending'`
        )
        .run(state, Date.now(), by, note, id).changes
    );
    return changes > 0 ? this.getAny(id) : undefined;
  }

  /** Which (component, tenant) pairs have rows here, for an operator view. */
  listScopes(): Scope[] {
    return this.db
      .prepare(
        `SELECT component, tenant FROM approvals
         UNION
         SELECT component, tenant FROM standing_grants
         UNION
         SELECT component, tenant FROM tool_exposure
         ORDER BY component, tenant`
      )
      .all()
      .map((r) => ({ ...r }) as unknown as Scope);
  }

  // ---- runtime state ---------------------------------------------------
  //
  // Not scoped, and not an oversight: these columns describe an operating
  // system process -- its pid, when it started, when it last checked in, and
  // the digest of the policy it parsed. One hosted process serves every
  // tenant, so there is one row per component and a tenant column would be
  // the wrong axis.

  /**
   * Announces which policy this process is enforcing, replacing any row from a
   * previous run of the same server.
   *
   * One row per component, not per process: two servers sharing a component
   * would be two answers to a question that has one, and the last to start is
   * the better guess. The digest is what the reader actually needs — `pid` and
   * `started_at` are there to make a stale row legible rather than merely wrong.
   */
  recordRuntimeState(row: Omit<RuntimeStateRow, "last_seen"> & { last_seen?: number }): void {
    const seen = row.last_seen ?? Date.now();
    this.db
      .prepare(
        `INSERT INTO runtime_state (component, pid, started_at, last_seen, policy_digest, policy_path)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(component) DO UPDATE SET
           pid = excluded.pid,
           started_at = excluded.started_at,
           last_seen = excluded.last_seen,
           policy_digest = excluded.policy_digest,
           policy_path = excluded.policy_path`
      )
      .run(row.component, row.pid, row.started_at, seen, row.policy_digest, row.policy_path);
  }

  /**
   * Marks this server still alive, without touching what it reported.
   *
   * Scoped to the pid that wrote the row so a process that has been superseded
   * cannot keep a dead predecessor's digest looking fresh.
   */
  touchRuntimeState(component: string, pid: number, now = Date.now()): void {
    this.db
      .prepare("UPDATE runtime_state SET last_seen = ? WHERE component = ? AND pid = ?")
      .run(now, component, pid);
  }

  runtimeState(component: string): RuntimeStateRow | undefined {
    const row = this.db.prepare("SELECT * FROM runtime_state WHERE component = ?").get(component);
    return row ? ({ ...row } as unknown as RuntimeStateRow) : undefined;
  }
}

/**
 * One component's rows, for one tenant.
 *
 * Every statement here carries `component = ? AND tenant = ?`. That is the
 * whole of the isolation, and it is deliberately in the SQL rather than folded
 * into `binding_hash` or enforced by a convention: a `WHERE` clause can be
 * read, grepped and tested, and a caller that forgets the scope cannot compile
 * rather than quietly matching everything.
 *
 * Two bugs this closes, both of which were live whenever a database was shared
 * — which is the default. `consume` matched on `binding_hash` alone, and the
 * hash covers only the tool name and arguments, so one tenant's granted
 * approval released another tenant's identical call. `consumeGrant` matched on
 * tool, effect and arguments, so one tenant's standing grant released another
 * tenant's call and charged the use to the wrong grant.
 */
export class ScopedApprovals {
  constructor(
    private readonly db: DatabaseSync,
    readonly scope: Scope
  ) {}

  private get where(): [string, string] {
    return [this.scope.component, this.scope.tenant];
  }

  /** Expiry is global; it is re-exposed here so scoped reads can sweep first. */
  private expireStale(now = Date.now()): void {
    this.db
      .prepare(
        "UPDATE approvals SET state = 'expired' WHERE expires_at <= ? AND state IN ('pending','granted')"
      )
      .run(now);
  }

  insertPending(
    row: Omit<ApprovalRow, "component" | "tenant" | "decided_at" | "decided_by" | "decision_note" | "state">
  ): ApprovalRow {
    this.db
      .prepare(
        `INSERT INTO approvals (id, component, tenant, created_at, expires_at, tool, effect,
           binding_hash, args_redacted, reason, actor, session, state)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`
      )
      .run(
        row.id,
        ...this.where,
        row.created_at,
        row.expires_at,
        row.tool,
        row.effect,
        row.binding_hash,
        row.args_redacted,
        row.reason,
        row.actor,
        row.session
      );
    return this.get(row.id)!;
  }

  /** Records an already-decided grant, e.g. one obtained via elicitation. */
  insertGranted(
    row: Omit<ApprovalRow, "component" | "tenant" | "decided_at" | "decided_by" | "decision_note" | "state">,
    decidedBy: string,
    note = "",
    state: ApprovalState = "granted"
  ): ApprovalRow {
    this.db
      .prepare(
        `INSERT INTO approvals (id, component, tenant, created_at, expires_at, tool, effect,
           binding_hash, args_redacted, reason, actor, session, state, decided_at, decided_by, decision_note)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        row.id,
        ...this.where,
        row.created_at,
        row.expires_at,
        row.tool,
        row.effect,
        row.binding_hash,
        row.args_redacted,
        row.reason,
        row.actor,
        row.session,
        state,
        Date.now(),
        decidedBy,
        note
      );
    return this.get(row.id)!;
  }

  get(id: string): ApprovalRow | undefined {
    const row = this.db
      .prepare("SELECT * FROM approvals WHERE id = ? AND component = ? AND tenant = ?")
      .get(id, ...this.where);
    return row ? ({ ...row } as unknown as ApprovalRow) : undefined;
  }

  listPending(limit = 50): ApprovalRow[] {
    this.expireStale();
    return this.db
      .prepare(
        `SELECT * FROM approvals WHERE component = ? AND tenant = ? AND state = 'pending'
         ORDER BY created_at ASC LIMIT ?`
      )
      .all(...this.where, limit)
      .map((r) => ({ ...r }) as unknown as ApprovalRow);
  }

  list(limit = 50): ApprovalRow[] {
    return this.db
      .prepare(
        `SELECT * FROM approvals WHERE component = ? AND tenant = ?
         ORDER BY created_at DESC LIMIT ?`
      )
      .all(...this.where, limit)
      .map((r) => ({ ...r }) as unknown as ApprovalRow);
  }

  /** Human decision on a parked request. */
  decide(id: string, state: "granted" | "denied", by: string, note = ""): ApprovalRow | undefined {
    this.expireStale();
    const changes = Number(
      this.db
        .prepare(
          `UPDATE approvals SET state = ?, decided_at = ?, decided_by = ?, decision_note = ?
           WHERE id = ? AND component = ? AND tenant = ? AND state = 'pending'`
        )
        .run(state, Date.now(), by, note, id, ...this.where).changes
    );
    return changes > 0 ? this.get(id) : undefined;
  }

  /**
   * Atomically finds and consumes a usable grant for this exact call. The
   * binding hash covers the tool name and every argument, so a grant issued for
   * one set of arguments cannot release a different one — and the scope filter
   * is what stops an identical call in another tenant from redeeming it.
   */
  consume(binding: string, singleUse: boolean, now = Date.now()): ApprovalRow | undefined {
    this.expireStale(now);
    const candidate = this.db
      .prepare(
        `SELECT * FROM approvals
         WHERE component = ? AND tenant = ? AND binding_hash = ? AND state = 'granted' AND expires_at > ?
         ORDER BY created_at ASC LIMIT 1`
      )
      .get(...this.where, binding, now);
    if (!candidate) return undefined;
    const row = { ...candidate } as unknown as ApprovalRow;
    if (!singleUse) return row;
    const changes = Number(
      this.db
        .prepare("UPDATE approvals SET state = 'used' WHERE id = ? AND state = 'granted'")
        .run(row.id).changes
    );
    // Lost the race to another consumer; treat as not granted rather than
    // letting two calls through on one approval.
    return changes > 0 ? { ...row, state: "used" } : undefined;
  }

  /**
   * `decide` with the "why not" the CLI and the console both need. `decide`
   * returns `undefined` for a missing row and for an already-decided one alike;
   * a reviewer needs to be told which it was.
   */
  decideChecked(
    id: string,
    state: "granted" | "denied",
    by: string,
    note = ""
  ): { ok: true; row: ApprovalRow } | { ok: false; error: string } {
    this.expireStale();
    const existing = this.get(id);
    if (!existing) return { ok: false, error: `no approval request with id ${id}` };
    if (existing.state !== "pending") {
      return { ok: false, error: `approval ${id} is already ${existing.state} and cannot be decided again` };
    }
    const row = this.decide(id, state, by, note);
    // Lost a race with another reviewer between the check and the update.
    if (!row) return { ok: false, error: `approval ${id} was decided by someone else first` };
    return { ok: true, row };
  }

  // ---- standing grants -------------------------------------------------

  createGrant(draft: StandingGrantDraft, now = Date.now()): StandingGrantRow {
    const id = newGrantId();
    this.db
      .prepare(
        `INSERT INTO standing_grants (id, component, tenant, created_at, expires_at, tool_match,
           effect, constraints, max_uses, uses, reason, created_by, state)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 'active')`
      )
      .run(
        id,
        ...this.where,
        now,
        draft.expires_at,
        draft.tool_match,
        draft.effect ?? null,
        JSON.stringify(draft.constraints ?? {}),
        draft.max_uses ?? null,
        draft.reason,
        draft.created_by
      );
    return this.getGrant(id)!;
  }

  getGrant(id: string): StandingGrantRow | undefined {
    const row = this.db
      .prepare("SELECT * FROM standing_grants WHERE id = ? AND component = ? AND tenant = ?")
      .get(id, ...this.where);
    return row ? ({ ...row } as unknown as StandingGrantRow) : undefined;
  }

  listGrants(options: { activeOnly?: boolean; limit?: number } = {}): StandingGrantRow[] {
    this.expireStaleGrants();
    const limit = options.limit ?? 100;
    const sql = options.activeOnly
      ? `SELECT * FROM standing_grants WHERE component = ? AND tenant = ? AND state = 'active'
         ORDER BY created_at DESC LIMIT ?`
      : `SELECT * FROM standing_grants WHERE component = ? AND tenant = ?
         ORDER BY created_at DESC LIMIT ?`;
    return this.db
      .prepare(sql)
      .all(...this.where, limit)
      .map((r) => ({ ...r }) as unknown as StandingGrantRow);
  }

  /** Marks past-due grants expired. Lazy, like `expireStale` for approvals. */
  expireStaleGrants(now = Date.now()): number {
    return Number(
      this.db
        .prepare(
          `UPDATE standing_grants SET state = 'expired'
           WHERE component = ? AND tenant = ? AND expires_at <= ? AND state = 'active'`
        )
        .run(...this.where, now).changes
    );
  }

  revokeGrant(id: string, by: string, now = Date.now()): StandingGrantRow | undefined {
    const changes = Number(
      this.db
        .prepare(
          `UPDATE standing_grants SET state = 'revoked', revoked_at = ?, revoked_by = ?
           WHERE id = ? AND component = ? AND tenant = ? AND state = 'active'`
        )
        .run(now, by, id, ...this.where).changes
    );
    return changes > 0 ? this.getGrant(id) : undefined;
  }

  /**
   * Finds the oldest live grant covering this call and charges one use to it.
   *
   * Returns undefined when nothing covers the call, which is the signal to fall
   * through to ordinary approval. A grant that matches the tool but whose
   * argument constraints reject the arguments is simply not a match: it must not
   * become a denial.
   */
  consumeGrant(
    tool: string,
    effect: Effect | null,
    args: Record<string, unknown>,
    now = Date.now()
  ): StandingGrantRow | undefined {
    this.expireStaleGrants(now);
    const candidates = this.db
      .prepare(
        `SELECT * FROM standing_grants
         WHERE component = ? AND tenant = ? AND state = 'active' AND expires_at > ?
         ORDER BY created_at ASC`
      )
      .all(...this.where, now)
      .map((r) => ({ ...r }) as unknown as StandingGrantRow);

    for (const candidate of candidates) {
      if (!grantMatches(candidate, tool, effect, args).matches) continue;
      // Charge the use and exhaust the grant in one statement, guarded so two
      // concurrent calls cannot both take the last use.
      const changes = Number(
        this.db
          .prepare(
            `UPDATE standing_grants
               SET uses = uses + 1,
                   state = CASE WHEN max_uses IS NOT NULL AND uses + 1 >= max_uses THEN 'exhausted' ELSE 'active' END
             WHERE id = ? AND state = 'active' AND (max_uses IS NULL OR uses < max_uses)`
          )
          .run(candidate.id).changes
      );
      // Lost the race, or it was exhausted between the select and the update.
      // Try the next candidate rather than failing a call a later grant covers.
      if (changes > 0) return this.getGrant(candidate.id);
    }
    return undefined;
  }

  // ---- exposure overrides ----------------------------------------------

  /**
   * Switches one tool off, for this component and this tenant.
   *
   * Idempotent, and it only ever subtracts: there is no corresponding row that
   * can make a call reachable. `set_at` and `set_by` are refreshed on a repeat
   * so the audit trail and the console both show who last asserted it.
   */
  disableTool(tool: string, by: string, reason = ""): ToolExposureRow {
    this.db
      .prepare(
        `INSERT INTO tool_exposure (component, tenant, tool, reason, set_at, set_by)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(component, tenant, tool) DO UPDATE SET
           reason = excluded.reason, set_at = excluded.set_at, set_by = excluded.set_by`
      )
      .run(...this.where, tool, reason, Date.now(), by);
    return this.toolExposure(tool)!;
  }

  /** Clears the override, handing the question back to policy. */
  enableTool(tool: string): ToolExposureRow | undefined {
    const existing = this.toolExposure(tool);
    if (!existing) return undefined;
    this.db
      .prepare("DELETE FROM tool_exposure WHERE component = ? AND tenant = ? AND tool = ?")
      .run(...this.where, tool);
    return existing;
  }

  toolExposure(tool: string): ToolExposureRow | undefined {
    const row = this.db
      .prepare("SELECT * FROM tool_exposure WHERE component = ? AND tenant = ? AND tool = ?")
      .get(...this.where, tool);
    return row ? ({ ...row } as unknown as ToolExposureRow) : undefined;
  }

  /** Every tool switched off in this scope, newest first. */
  listDisabledTools(): ToolExposureRow[] {
    return this.db
      .prepare(
        `SELECT * FROM tool_exposure WHERE component = ? AND tenant = ?
         ORDER BY set_at DESC`
      )
      .all(...this.where)
      .map((r) => ({ ...r }) as unknown as ToolExposureRow);
  }
}


/** Shape of the host-facing elicitation call, kept transport-agnostic. */
export interface ElicitFn {
  (request: {
    message: string;
    requestedSchema: {
      type: "object";
      properties: Record<string, unknown>;
      required?: string[];
    };
  }): Promise<{ action: "accept" | "decline" | "cancel"; content?: Record<string, unknown> }>;
}

export interface ApprovalRequest {
  readonly tool: string;
  readonly effect: Effect | null;
  readonly args: Record<string, unknown>;
  readonly reason: string;
  readonly actor: string;
  readonly session: string;
  /** Shown to the human: what this call will do upstream. */
  readonly target?: string;
}

export type ApprovalOutcome =
  | {
      readonly granted: true;
      readonly approvalId: string;
      readonly via: "cached" | "standing" | "elicit" | "cli";
      /** Set when a standing grant released the call, for the audit record. */
      readonly grantId?: string;
    }
  | {
      readonly granted: false;
      readonly approvalId: string | null;
      readonly reason: string;
      /** Text handed back to the agent telling it how the human can release the call. */
      readonly instructions?: string;
    };

export interface ApprovalBrokerOptions {
  readonly config: ApprovalsConfig;
  /**
   * Already bound to one component and one tenant. The broker reads and writes
   * approvals on the hot path, so handing it an unscoped store is precisely
   * the mistake that let one tenant's grant release another's call — this type
   * is what makes that unrepresentable.
   */
  readonly store: ScopedApprovals;
  /** Supplied when the connected host advertises the elicitation capability. */
  readonly elicit?: ElicitFn | undefined;
  readonly redactKeys?: readonly string[];
  /** Overridable for tests. */
  readonly now?: () => number;
}

/**
 * Runs the approval flow for a single call: reuse an existing grant, else ask
 * the host interactively, else park the request for out-of-band review.
 */
export class ApprovalBroker {
  private readonly config: ApprovalsConfig;
  private readonly store: ScopedApprovals;
  private readonly elicit: ElicitFn | undefined;
  private readonly redactKeys: readonly string[];
  private readonly now: () => number;

  constructor(options: ApprovalBrokerOptions) {
    this.config = options.config;
    this.store = options.store;
    this.elicit = options.elicit;
    this.redactKeys = options.redactKeys ?? [];
    this.now = options.now ?? Date.now;
  }

  async request(req: ApprovalRequest): Promise<ApprovalOutcome> {
    const binding = bindingHash(req.tool, req.args);
    const now = this.now();

    // 1. A grant already issued for this exact call.
    const cached = this.store.consume(binding, this.config.single_use, now);
    if (cached) {
      return { granted: true, approvalId: cached.id, via: "cached" };
    }

    const base = {
      id: newApprovalId(),
      created_at: now,
      expires_at: now + this.config.ttl_seconds * 1000,
      tool: req.tool,
      effect: req.effect,
      binding_hash: binding,
      args_redacted: JSON.stringify(redactArgs(req.args, this.redactKeys)),
      reason: req.reason,
      actor: req.actor,
      session: req.session
    };

    // 2. A standing grant covering this class of call. Recorded as an already
    // consumed approval so the exact arguments still appear in the history and
    // cannot be replayed through the binding-hash path above.
    const grant = this.store.consumeGrant(req.tool, req.effect, req.args, now);
    if (grant) {
      const row = this.store.insertGranted(base, `standing-grant:${grant.id}`, grant.reason, "used");
      return { granted: true, approvalId: row.id, via: "standing", grantId: grant.id };
    }

    if (this.config.mode === "deny") {
      return {
        granted: false,
        approvalId: null,
        reason: "policy requires approval for this call and approvals are disabled"
      };
    }

    // 3. Ask the host, when it can ask a human.
    if ((this.config.mode === "elicit" || this.config.mode === "both") && this.elicit) {
      try {
        const result = await this.elicit({
          message: renderPrompt(req),
          requestedSchema: {
            type: "object",
            properties: {
              approve: {
                type: "boolean",
                title: "Approve this call?",
                description: `Allow ${req.tool} to run with exactly these arguments.`
              },
              note: { type: "string", title: "Note", description: "Recorded in the audit log." }
            },
            required: ["approve"]
          }
        });

        if (result.action === "accept" && result.content?.["approve"] === true) {
          const note = typeof result.content["note"] === "string" ? result.content["note"] : "";
          // Recorded as already consumed: the grant exists for the audit trail,
          // not to be redeemed a second time.
          const row = this.store.insertGranted(base, "elicitation", note, this.config.single_use ? "used" : "granted");
          return { granted: true, approvalId: row.id, via: "elicit" };
        }
        if (result.action === "accept") {
          this.store.insertGranted(base, "elicitation", "explicitly declined by reviewer", "denied");
          return { granted: false, approvalId: base.id, reason: "the reviewer declined this call" };
        }
        return {
          granted: false,
          approvalId: null,
          reason: result.action === "cancel" ? "the approval prompt was cancelled" : "the host declined to prompt"
        };
      } catch (err) {
        // The host advertised elicitation but could not deliver. Fall through to
        // the CLI path if it is available rather than failing open.
        if (this.config.mode === "elicit") {
          return {
            granted: false,
            approvalId: null,
            reason: `approval prompt failed: ${(err as Error).message}`
          };
        }
      }
    }

    if (this.config.mode === "elicit") {
      return {
        granted: false,
        approvalId: null,
        reason: "this call needs approval but the connected client does not support elicitation"
      };
    }

    // 4. Park it for out-of-band review.
    const row = this.store.insertPending(base);
    return {
      granted: false,
      approvalId: row.id,
      reason: `this ${req.effect ?? "unclassified"} call requires human approval`,
      instructions:
        `Approval request ${row.id} is pending. A human can review it with:\n` +
        `  hmcp pending\n` +
        `  hmcp approve ${row.id}   # or: hmcp deny ${row.id}\n` +
        `Then retry this tool call with identical arguments. ` +
        `The approval is bound to these exact arguments and expires in ${this.config.ttl_seconds}s.`
    };
  }
}

function renderPrompt(req: ApprovalRequest): string {
  const args = JSON.stringify(redactArgs(req.args), null, 2);
  const lines = [
    `Approve a ${req.effect ?? "unclassified"} operation?`,
    "",
    `Tool:   ${req.tool}`,
    req.target ? `Target: ${req.target}` : null,
    `Policy: ${req.reason}`,
    "",
    "Arguments:",
    args.length > 2000 ? `${args.slice(0, 2000)}\n…(truncated)` : args
  ];
  return lines.filter((l) => l !== null).join("\n");
}
