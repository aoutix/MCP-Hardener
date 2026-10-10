import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
  unlinkSync
} from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { canonicalJson, hashValue, sha256 } from "./canonical.js";
import { globMatch } from "./glob.js";
import { redactArgs } from "./redact.js";
import { expandPath, type AuditConfig, type DecisionKind, type Effect } from "./policy.js";

export const GENESIS_HASH = "0".repeat(64);

export interface AuditRecord {
  readonly ts: string;
  readonly seq: number;
  readonly id: string;
  readonly actor: string;
  readonly session: string;
  readonly component: string;
  readonly tool: string;
  readonly effect: Effect | null;
  readonly decision: DecisionKind;
  readonly rule_id: string;
  readonly reason: string;
  readonly tenant: string | null;
  readonly args_hash: string;
  readonly args_redacted: Record<string, unknown> | null;
  readonly upstream: {
    readonly host: string | null;
    readonly method: string | null;
    readonly path: string | null;
    readonly status: number | null;
    readonly bytes: number | null;
  } | null;
  readonly outcome: "completed" | "denied" | "pending-approval" | "error";
  readonly error: string | null;
  readonly duration_ms: number | null;
  readonly approval_id: string | null;
  /**
   * Set when a standing grant released this call, or on the administrative
   * records written when one is created or revoked.
   *
   * Records written before standing grants existed have no such key at all.
   * `canonicalJson` drops `undefined`, so those records still hash to exactly
   * what they did before and an old log keeps verifying.
   */
  readonly grant_id: string | null;
  readonly prev_hash: string;
  readonly hash: string;
}

/** Everything except the fields the log assigns itself (ts, seq, id, hashes). */
export interface AuditEntry {
  readonly tool: string;
  readonly decision: DecisionKind;
  readonly outcome: AuditRecord["outcome"];
  readonly effect?: Effect | null;
  readonly rule_id?: string;
  readonly reason?: string;
  readonly tenant?: string | null;
  readonly args_hash?: string;
  readonly args_redacted?: Record<string, unknown> | null;
  readonly upstream?: AuditRecord["upstream"];
  readonly error?: string | null;
  readonly duration_ms?: number | null;
  readonly approval_id?: string | null;
  readonly grant_id?: string | null;
  readonly actor?: string;
  readonly session?: string;
  readonly component?: string;
}

function computeHash(record: Omit<AuditRecord, "hash">): string {
  return sha256(record.prev_hash, canonicalJson({ ...record, hash: undefined }));
}

/**
 * Who a record says made the call.
 *
 * One column holds three very different kinds of answer: an operating-system
 * user (a human at a console or a terminal), the literal "agent" for a server
 * that serves one client and has no identity to offer, and — once a gateway
 * verifies a caller's token — whoever that token names.
 *
 * Only the last of those is chosen by someone outside the deployment, which
 * is why only the last is namespaced. A token minted with `sub: "aditya"`
 * must not produce a line indistinguishable from a human's console approval,
 * and a reserved prefix is what makes that forgery unrepresentable rather
 * than merely unlikely. Prefixing the operator too would churn stored history
 * to protect against nobody.
 */

/** A server with one client and no caller identity to claim. */
export const ACTOR_AGENT = "agent";

/** The gateway process itself: startup findings, structural refusals. */
export const ACTOR_GATEWAY = "gateway";

/**
 * A token that verified but named no subject.
 *
 * Deliberately not "unknown", which already means "could not name the
 * operating-system user". This says something narrower and truer: the token
 * proved a *tenant*, not an identity.
 */
export const ACTOR_ANONYMOUS = "token:anonymous";

/** The longest actor recorded. Generous for a subject, short of a payload. */
const MAX_ACTOR = 128;

/**
 * The actor for a caller named by a verified token.
 *
 * The subject is not quoted anywhere it could be mistaken for structure, but
 * it is interpolated into prose reasons in the console and the admin API, so
 * it is flattened to one line and capped here rather than at each use.
 *
 * The tenant is deliberately *not* folded in: every record already carries a
 * `tenant` column, and `(tenant, actor)` is the real key. Nor is the issuer,
 * which is pinned to one value per deployment. If multiple issuers ever
 * become possible the format grows to `token:<iss>#<sub>`.
 */
export function tokenActor(subject: string | undefined): string {
  if (subject === undefined) return ACTOR_ANONYMOUS;
  // eslint-disable-next-line no-control-regex
  const flat = subject.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  if (flat.length === 0) return ACTOR_ANONYMOUS;
  const capped = flat.length > MAX_ACTOR ? `${flat.slice(0, MAX_ACTOR - 1)}\u2026` : flat;
  return `token:${capped}`;
}

export interface AuditLogOptions {
  readonly config: AuditConfig;
  readonly actor?: string;
  readonly session?: string;
  readonly component?: string;
  /** Base for resolving a relative audit path. */
  readonly cwd?: string;
}

/**
 * Append-only JSONL audit log with an optional hash chain.
 *
 * Each record commits to the one before it, so a deleted or edited line makes
 * `verifyAuditLog` fail at that point. Appends are guarded by an exclusive lock
 * file, because the chain requires a read-tail-then-append critical section and
 * a generated server plus a gateway may share one log.
 */
export class AuditLog {
  readonly path: string;
  readonly enabled: boolean;
  private readonly config: AuditConfig;
  private readonly actor: string;
  private readonly session: string;
  private readonly component: string;

  constructor(options: AuditLogOptions) {
    this.config = options.config;
    this.enabled = options.config.enabled;
    this.path = expandPath(options.config.path, options.cwd ?? process.cwd());
    this.actor = options.actor ?? process.env["HMCP_ACTOR"] ?? `${process.env["USER"] ?? "unknown"}`;
    this.session = options.session ?? randomUUID();
    this.component = options.component ?? "hmcp";
  }

  /**
   * Writes one record and returns it. Failure to log is reported to stderr but
   * never thrown: a broken log must not become a way to suppress enforcement.
   * Callers that need write-or-refuse semantics should use `appendStrict`.
   */
  append(entry: AuditEntry): AuditRecord | null {
    try {
      return this.appendStrict(entry);
    } catch (err) {
      process.stderr.write(`[hmcp] audit append failed: ${(err as Error).message}\n`);
      return null;
    }
  }

  appendStrict(entry: AuditEntry): AuditRecord | null {
    if (!this.enabled) return null;
    mkdirSync(dirname(this.path), { recursive: true });

    return withLock(this.path, () => {
      const tail = this.config.hash_chain ? readTail(this.path) : null;
      const prev_hash = tail?.hash ?? GENESIS_HASH;
      const seq = (tail?.seq ?? -1) + 1;

      const args = entry.args_redacted;
      const unhashed: Omit<AuditRecord, "hash"> = {
        ts: new Date().toISOString(),
        seq,
        id: randomUUID(),
        actor: entry.actor ?? this.actor,
        session: entry.session ?? this.session,
        component: entry.component ?? this.component,
        tool: entry.tool,
        effect: entry.effect ?? null,
        decision: entry.decision,
        rule_id: entry.rule_id ?? "",
        reason: entry.reason ?? "",
        tenant: entry.tenant ?? null,
        args_hash: entry.args_hash ?? hashValue(args ?? {}),
        args_redacted: this.config.record_args ? (args ?? null) : null,
        upstream: entry.upstream ?? null,
        outcome: entry.outcome,
        error: entry.error ?? null,
        duration_ms: entry.duration_ms ?? null,
        approval_id: entry.approval_id ?? null,
        grant_id: entry.grant_id ?? null,
        prev_hash
      };

      const record: AuditRecord = { ...unhashed, hash: computeHash(unhashed) };
      appendFileSync(this.path, JSON.stringify(record) + "\n", { encoding: "utf8", mode: 0o600 });
      return record;
    });
  }

  /** Redacts arguments with this log's configured key list and hashes the original. */
  prepareArgs(args: Record<string, unknown> | undefined): {
    args_hash: string;
    args_redacted: Record<string, unknown>;
  } {
    return {
      args_hash: hashValue(args ?? {}),
      args_redacted: redactArgs(args, this.config.redact)
    };
  }
}

function readTail(path: string): { hash: string; seq: number } | null {
  if (!existsSync(path)) return null;
  const size = statSync(path).size;
  if (size === 0) return null;
  // Logs stay small enough in practice that reading to find the last complete
  // line is simpler and safer than seeking, and correctness matters more here.
  const text = readFileSync(path, "utf8");
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const parsed = JSON.parse(lines[i]!) as AuditRecord;
      if (typeof parsed.hash === "string" && typeof parsed.seq === "number") {
        return { hash: parsed.hash, seq: parsed.seq };
      }
    } catch {
      // Ignore a torn trailing line and keep looking backwards.
    }
  }
  return null;
}

/** Exclusive lock around the read-tail/append critical section. */
function withLock<T>(path: string, fn: () => T): T {
  const lockPath = `${path}.lock`;
  const deadline = Date.now() + 5000;
  let fd: number | undefined;
  for (;;) {
    try {
      fd = openSync(lockPath, "wx");
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      // Reclaim a lock left behind by a process that died mid-append.
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > 10_000) {
          unlinkSync(lockPath);
          continue;
        }
      } catch {
        continue;
      }
      if (Date.now() > deadline) throw new Error(`timed out waiting for audit lock at ${lockPath}`);
      // Busy-wait briefly; the critical section is a few milliseconds long.
      const spinUntil = Date.now() + 5;
      while (Date.now() < spinUntil) {
        /* spin */
      }
    }
  }
  try {
    return fn();
  } finally {
    try {
      if (fd !== undefined) closeSync(fd);
      unlinkSync(lockPath);
    } catch {
      /* best effort */
    }
  }
}

export interface VerifyResult {
  readonly ok: boolean;
  readonly count: number;
  readonly problems: readonly { readonly line: number; readonly message: string }[];
}

/**
 * Walks the chain and reports the first point at which it stops being
 * consistent: a modified record, a removed one, or a reordered one.
 */
export function verifyAuditLog(path: string): VerifyResult {
  const full = expandPath(path);
  const problems: { line: number; message: string }[] = [];
  if (!existsSync(full)) {
    return { ok: false, count: 0, problems: [{ line: 0, message: `no audit log at ${full}` }] };
  }
  const lines = readFileSync(full, "utf8").split("\n");
  let prevHash = GENESIS_HASH;
  let expectedSeq = 0;
  let count = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim().length === 0) continue;
    const lineNo = i + 1;
    let record: AuditRecord;
    try {
      record = JSON.parse(line) as AuditRecord;
    } catch (err) {
      problems.push({ line: lineNo, message: `unparseable JSON: ${(err as Error).message}` });
      continue;
    }
    count++;

    if (record.seq !== expectedSeq) {
      problems.push({
        line: lineNo,
        message: `sequence gap: expected seq ${expectedSeq}, found ${record.seq} (a record was removed or reordered)`
      });
    }
    if (record.prev_hash !== prevHash) {
      problems.push({
        line: lineNo,
        message: `chain break: prev_hash ${short(record.prev_hash)} does not match the previous record's hash ${short(prevHash)}`
      });
    }
    const recomputed = computeHash({ ...record, hash: undefined } as unknown as Omit<AuditRecord, "hash">);
    if (recomputed !== record.hash) {
      problems.push({
        line: lineNo,
        message: `record altered: stored hash ${short(record.hash)} but contents hash to ${short(recomputed)}`
      });
    }
    prevHash = record.hash;
    expectedSeq = record.seq + 1;
  }

  return { ok: problems.length === 0, count, problems };
}

function short(h: string | undefined): string {
  return typeof h === "string" ? h.slice(0, 12) : String(h);
}

export function readAuditLog(path: string): AuditRecord[] {
  const full = expandPath(path);
  if (!existsSync(full)) return [];
  return readFileSync(full, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as AuditRecord);
}

export interface AuditQuery {
  readonly decision?: readonly DecisionKind[];
  readonly outcome?: readonly AuditRecord["outcome"][];
  /** Glob over the tool name, same dialect as policy rule patterns. */
  readonly tool?: string;
  readonly component?: readonly string[];
  /**
   * Whose data the call touched.
   *
   * One log file holds every tenant's records — the hash chain is per file, so
   * splitting it is not free — which makes this the only way to read one
   * tenant's history out of it. `""` selects records from a deployment with no
   * tenant configured, and from anything written before the field was set.
   */
  readonly tenant?: readonly string[];
  readonly actor?: readonly string[];
  /** Inclusive ISO 8601 bounds on `ts`. */
  readonly since?: string;
  readonly until?: string;
  /** Only records with a lower `seq`; the cursor for paging backwards. */
  readonly beforeSeq?: number;
  readonly limit?: number;
  /**
   * Anything refused, or anything that did not run to completion. Kept as one
   * flag rather than expressed through `decision`/`outcome` because it is an
   * OR of the two, and because it is the question a reviewer actually asks.
   */
  readonly noteworthy?: boolean;
}

/** Anything refused, or anything that did not complete. */
export function isNoteworthy(record: AuditRecord): boolean {
  return record.decision === "deny" || record.outcome !== "completed";
}

export interface AuditPage {
  /** Newest first. */
  readonly records: AuditRecord[];
  /** Pass as `beforeSeq` for the next page, or null at the start of the log. */
  readonly nextCursor: number | null;
  readonly scanned: number;
  /** Lines that could not be parsed. Reported rather than thrown on. */
  readonly malformed: number;
}

const QUERY_CHUNK = 64 * 1024;
const QUERY_LIMIT_CAP = 1000;

/**
 * Bounded, newest-first query over the log.
 *
 * `readAuditLog` parses the whole file and throws on the first malformed line,
 * which makes it unusable for a long-running reader: a console asking for the
 * last 50 records should not pay for a 200MB log, and one torn line should not
 * hide every record around it. This scans backwards in fixed chunks and stops
 * as soon as the limit is met, so the cost is proportional to what was asked
 * for rather than to the size of the log.
 *
 * Chunk boundaries are handled as bytes, not text: a partial line is carried
 * over as a Buffer so a multi-byte character split across two reads is decoded
 * once, intact.
 */
export function queryAuditLog(path: string, query: AuditQuery = {}): AuditPage {
  const full = expandPath(path);
  if (!existsSync(full)) return { records: [], nextCursor: null, scanned: 0, malformed: 0 };

  const limit = Math.min(Math.max(query.limit ?? 100, 1), QUERY_LIMIT_CAP);
  const records: AuditRecord[] = [];
  let scanned = 0;
  let malformed = 0;

  const fd = openSync(full, "r");
  try {
    let pos = statSync(full).size;
    let carry = Buffer.alloc(0);

    while (pos > 0 && records.length < limit) {
      const len = Math.min(QUERY_CHUNK, pos);
      pos -= len;
      const buf = Buffer.alloc(len);
      readSync(fd, buf, 0, len, pos);
      const combined = Buffer.concat([buf, carry]);

      let start = 0;
      if (pos > 0) {
        // The first line in this window begins earlier in the file; hold its
        // bytes back until the chunk containing its start has been read.
        const nl = combined.indexOf(0x0a);
        if (nl === -1) {
          carry = combined;
          continue;
        }
        carry = combined.subarray(0, nl);
        start = nl + 1;
      } else {
        carry = Buffer.alloc(0);
      }

      const lines = combined.subarray(start).toString("utf8").split("\n");
      for (let i = lines.length - 1; i >= 0 && records.length < limit; i--) {
        const line = lines[i]!;
        if (line.trim().length === 0) continue;
        scanned++;
        let record: AuditRecord;
        try {
          record = JSON.parse(line) as AuditRecord;
        } catch {
          malformed++;
          continue;
        }
        if (matchesQuery(record, query)) records.push(record);
      }
    }
  } finally {
    closeSync(fd);
  }

  // A short page means the backwards scan ran out of log, so there is nothing
  // older to fetch. A full page means there may be more, even if this pass
  // happened to read as far as byte zero: the loop stops at the limit, not at
  // the start of the file. Reporting "reached the start" from `pos === 0` would
  // silently truncate paging whenever a whole log fit in one chunk.
  const oldest = records[records.length - 1];
  const nextCursor = records.length < limit || !oldest ? null : oldest.seq;
  return { records, nextCursor, scanned, malformed };
}

function matchesQuery(record: AuditRecord, q: AuditQuery): boolean {
  if (q.beforeSeq !== undefined && !(record.seq < q.beforeSeq)) return false;
  if (q.noteworthy && !isNoteworthy(record)) return false;
  if (q.decision && !q.decision.includes(record.decision)) return false;
  if (q.outcome && !q.outcome.includes(record.outcome)) return false;
  if (q.component && !q.component.includes(record.component)) return false;
  if (q.tenant && !q.tenant.includes(record.tenant ?? "")) return false;
  if (q.actor && !q.actor.includes(record.actor)) return false;
  if (q.tool && !globMatch(q.tool, record.tool)) return false;
  // ISO 8601 UTC strings order lexicographically, which is why the log stores
  // them that way.
  if (q.since && record.ts < q.since) return false;
  if (q.until && record.ts > q.until) return false;
  return true;
}
