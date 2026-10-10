import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApprovalStore, LATEST_SCHEMA_VERSION, componentScope } from "../src/index.js";

/**
 * Upgrading a database that already exists.
 *
 * Until versioning arrived the whole schema lifecycle was `CREATE TABLE IF NOT
 * EXISTS`, which silently does nothing to a table that is already there. A new
 * column therefore never appeared, and the first query to mention it failed
 * with `no such column` — at call time, in a running server, with no code
 * anywhere that could have noticed or repaired it.
 *
 * The schema strings below are deliberately copied out as literals rather than
 * imported. Importing the current constants would make this test agree with
 * whatever the code says today, which is the one thing it must not do: its job
 * is to hold a record of what version 0 actually looked like on disk.
 */

const V0_SCHEMA = `
CREATE TABLE IF NOT EXISTS approvals (
  id            TEXT PRIMARY KEY,
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
CREATE INDEX IF NOT EXISTS approvals_binding ON approvals (binding_hash, state);
CREATE INDEX IF NOT EXISTS approvals_state ON approvals (state, created_at);

CREATE TABLE IF NOT EXISTS standing_grants (
  id          TEXT PRIMARY KEY,
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
CREATE INDEX IF NOT EXISTS grants_active ON standing_grants (state, expires_at);

CREATE TABLE IF NOT EXISTS tool_exposure (
  component TEXT NOT NULL,
  tool      TEXT NOT NULL,
  reason    TEXT NOT NULL,
  set_at    INTEGER NOT NULL,
  set_by    TEXT NOT NULL,
  PRIMARY KEY (component, tool)
);

CREATE TABLE IF NOT EXISTS runtime_state (
  component     TEXT PRIMARY KEY,
  pid           INTEGER NOT NULL,
  started_at    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  policy_digest TEXT NOT NULL,
  policy_path   TEXT NOT NULL
);
`;

let dir: string;
let path: string;

/** A database as a pre-versioning build would have left it, with rows in it. */
function writeLegacy(): void {
  const db = new DatabaseSync(path);
  db.exec(V0_SCHEMA);
  db.prepare(
    `INSERT INTO approvals (id, created_at, expires_at, tool, effect, binding_hash,
       args_redacted, reason, actor, session, state)
     VALUES ('apr_old', 1000, 9999999999999, 'create_invoice', 'write', 'hash-1', '{}', 'r', 'agent', 's', 'pending')`
  ).run();
  db.prepare(
    `INSERT INTO standing_grants (id, created_at, expires_at, tool_match, effect, constraints,
       max_uses, uses, reason, created_by, state)
     VALUES ('sg_old', 1000, 9999999999999, 'create_*', 'write', '{}', 5, 0, 'month end', 'alice', 'active')`
  ).run();
  db.prepare(
    `INSERT INTO tool_exposure (component, tool, reason, set_at, set_by)
     VALUES ('generated:Billing', 'delete_invoice', 'incident 412', 1000, 'alice')`
  ).run();
  db.close();
}

function version(): number {
  const db = new DatabaseSync(path);
  const row = db.prepare("PRAGMA user_version").get() as { user_version: number };
  db.close();
  return Number(row.user_version);
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-migrate-"));
  path = join(dir, "approvals.sqlite");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("opening a database written before versioning existed", () => {
  it("upgrades it instead of failing at the first query", () => {
    writeLegacy();
    expect(version()).toBe(0);

    const store = new ApprovalStore(path);
    store.close();

    expect(version()).toBe(LATEST_SCHEMA_VERSION);
  });

  it("keeps the rows that were already there", () => {
    writeLegacy();
    const store = new ApprovalStore(path);
    // The scope columns did not exist, so there is no honest value to give
    // them: they land in the empty scope rather than being guessed into
    // someone's. Guessing wrong on an access-control key is worse than an
    // orphan row, which an operator can still see and drain.
    const orphans = store.listPendingAll();
    expect(orphans).toHaveLength(1);
    expect(orphans[0]!.id).toBe("apr_old");
    expect(orphans[0]!.component).toBe("");
    expect(orphans[0]!.tenant).toBe("");

    const legacy = store.scoped({ component: "", tenant: "" });
    expect(legacy.getGrant("sg_old")!.tool_match).toBe("create_*");
    store.close();
  });

  it("carries an exposure row over under its old component, in the empty tenant", () => {
    writeLegacy();
    const store = new ApprovalStore(path);
    const billing = store.scoped(componentScope("generated:Billing"));
    expect(billing.toolExposure("delete_invoice")!.reason).toBe("incident 412");
    store.close();
  });

  it("widens the exposure key, so two tenants can switch the same tool", () => {
    // The whole point of the rebuild: before it, the primary key was
    // (component, tool) and the second insert would have collided.
    writeLegacy();
    const store = new ApprovalStore(path);
    store.scoped({ component: "gateway:hmcp", tenant: "acme" }).disableTool("create_invoice", "alice");
    store.scoped({ component: "gateway:hmcp", tenant: "globex" }).disableTool("create_invoice", "bob");

    expect(store.scoped({ component: "gateway:hmcp", tenant: "acme" }).toolExposure("create_invoice")!.set_by).toBe(
      "alice"
    );
    expect(store.scoped({ component: "gateway:hmcp", tenant: "globex" }).toolExposure("create_invoice")!.set_by).toBe(
      "bob"
    );
    store.close();
  });
});

describe("opening a database that does not exist yet", () => {
  it("creates it at the current shape and stamps the version", () => {
    const store = new ApprovalStore(path);
    store.close();
    expect(version()).toBe(LATEST_SCHEMA_VERSION);
  });

  it("is a no-op the second time, and the third", () => {
    new ApprovalStore(path).close();
    const second = new ApprovalStore(path);
    second.scoped(componentScope("c")).disableTool("t", "alice");
    second.close();
    new ApprovalStore(path).close();

    expect(version()).toBe(LATEST_SCHEMA_VERSION);
    const store = new ApprovalStore(path);
    expect(store.scoped(componentScope("c")).toolExposure("t")).toBeDefined();
    store.close();
  });
});

describe("opening a database from the future", () => {
  it("refuses, rather than querying columns it does not know about", () => {
    new ApprovalStore(path).close();
    const db = new DatabaseSync(path);
    db.exec(`PRAGMA user_version = ${LATEST_SCHEMA_VERSION + 1}`);
    db.close();

    expect(() => new ApprovalStore(path)).toThrow(/written by a newer hardened-mcp/);
  });
});
