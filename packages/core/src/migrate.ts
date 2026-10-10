import type { DatabaseSync } from "node:sqlite";
import { RUNTIME_STATE_SCHEMA } from "./runtime-state.js";

/**
 * Schema versioning for the approvals database.
 *
 * Until this existed the whole schema lifecycle was four `CREATE TABLE IF NOT
 * EXISTS` statements, which is fine for adding a *table* and silently useless
 * for adding a *column*: the statement is a no-op against a table that already
 * exists, so an upgraded binary would open an old database, see none of its
 * new columns, and fail at the first query with `no such column`. Nothing
 * would have detected it and nothing would have repaired it.
 *
 * `PRAGMA user_version` is the version counter. It is an integer SQLite keeps
 * in the database header, it costs nothing to read, and — the reason it is the
 * right choice here rather than a bookkeeping table — it is transactional, so
 * a migration and the stamp that records it commit or roll back together.
 * There is no window in which the work is done but the version says otherwise.
 */

/** One step. `up` runs inside a transaction that also stamps the version. */
interface Migration {
  readonly name: string;
  readonly up: (db: DatabaseSync) => void;
}

/**
 * Index + 1 is the version a migration produces, so this array is append-only:
 * editing a published entry changes what a version *means* on databases that
 * already claim it.
 */
const MIGRATIONS: readonly Migration[] = [
  {
    name: "scope approvals, grants and exposure by component and tenant",
    up(db) {
      /*
       * `approvals` and `standing_grants` never carried a server identity at
       * all, let alone a tenant, so every query against them returned every
       * row in a database that is shared between servers by default. Two
       * columns with a constant default is a cheap ALTER; SQLite allows it
       * precisely because no existing row has to be rewritten.
       */
      for (const table of ["approvals", "standing_grants"]) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN component TEXT NOT NULL DEFAULT ''`);
        db.exec(`ALTER TABLE ${table} ADD COLUMN tenant TEXT NOT NULL DEFAULT ''`);
      }

      // The old indexes lead with the columns that are now the least
      // selective, so they are replaced rather than supplemented.
      db.exec("DROP INDEX IF EXISTS approvals_binding");
      db.exec("DROP INDEX IF EXISTS approvals_state");
      db.exec("DROP INDEX IF EXISTS grants_active");
      db.exec(
        "CREATE INDEX approvals_binding ON approvals (component, tenant, binding_hash, state)"
      );
      db.exec("CREATE INDEX approvals_state ON approvals (component, tenant, state, created_at)");
      db.exec(
        "CREATE INDEX grants_active ON standing_grants (component, tenant, state, expires_at)"
      );

      /*
       * `tool_exposure` needs its PRIMARY KEY widened from (component, tool)
       * to (component, tenant, tool), and SQLite cannot alter a primary key in
       * place — the table has to be rebuilt. Safe to do bluntly here because
       * the schema has no foreign keys, views or triggers pointing at it, so
       * there is nothing for the rename to leave dangling.
       */
      db.exec(`
        CREATE TABLE tool_exposure_new (
          component TEXT NOT NULL,
          tenant    TEXT NOT NULL DEFAULT '',
          tool      TEXT NOT NULL,
          reason    TEXT NOT NULL,
          set_at    INTEGER NOT NULL,
          set_by    TEXT NOT NULL,
          PRIMARY KEY (component, tenant, tool)
        )
      `);
      db.exec(`
        INSERT INTO tool_exposure_new (component, tenant, tool, reason, set_at, set_by)
        SELECT component, '', tool, reason, set_at, set_by FROM tool_exposure
      `);
      db.exec("DROP TABLE tool_exposure");
      db.exec("ALTER TABLE tool_exposure_new RENAME TO tool_exposure");

      /*
       * `runtime_state` is deliberately untouched. Its columns are pid,
       * started_at, last_seen and the policy digest: that is the liveness of
       * an operating-system process, and one hosted gateway process serves
       * every tenant at once. Tenants do not have processes, so a tenant
       * column there would be the wrong axis and would cost a second rebuild
       * to say nothing.
       */
    }
  },
  {
    name: "create runtime_state for databases versioned before it existed",
    up(db) {
      /*
       * The table arrived after versioning did, so a database already stamped
       * version 1 was never given it and the console failed on first read with
       * `no such table`. Fresh databases get it from `createLatest`; this is
       * the same statement for the ones that do not.
       */
      db.exec(RUNTIME_STATE_SCHEMA);
    }
  }
];

export const LATEST_SCHEMA_VERSION = MIGRATIONS.length;

function userVersion(db: DatabaseSync): number {
  const row = db.prepare("PRAGMA user_version").get() as { user_version?: number } | undefined;
  return Number(row?.user_version ?? 0);
}

/** Whether this database predates versioning, as opposed to being empty. */
function hasLegacyTables(db: DatabaseSync): boolean {
  const row = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='approvals'").get();
  return row !== undefined;
}

/**
 * Brings one database up to `LATEST_SCHEMA_VERSION`.
 *
 * `createLatest` is the caller's "fresh database" path: the current
 * `CREATE TABLE` statements, at their newest shape. It matters that a fresh
 * database takes that path rather than replaying history, because replaying
 * would mean every migration has to stay runnable against the schema of its
 * own era for ever.
 *
 * The awkward case this has to get right is that a brand-new database and one
 * written before versioning existed *both* report version 0. They are told
 * apart by looking for a table only the second would have.
 *
 * Concurrency is real here, not theoretical: the default store path is shared,
 * and a console, a CLI and a server may all open it at once. Each step takes
 * the write lock with BEGIN IMMEDIATE and re-reads the version inside the
 * transaction, so a process that loses the race finds the work already done
 * and skips it rather than applying it twice.
 */
export function migrate(db: DatabaseSync, createLatest: (db: DatabaseSync) => void): void {
  const current = userVersion(db);

  if (current > LATEST_SCHEMA_VERSION) {
    /*
     * A newer build has already upgraded this file. Carrying on would mean
     * querying columns this binary does not know about, or worse, writing rows
     * that the newer one will misread. Refusing to open is the honest failure:
     * it names the cause, where `no such column` three calls later does not.
     */
    throw new Error(
      `approvals database is at schema version ${current}, but this build only understands ` +
        `${LATEST_SCHEMA_VERSION}. It was written by a newer hardened-mcp; upgrade this one.`
    );
  }

  if (current === 0 && !hasLegacyTables(db)) {
    db.exec("BEGIN IMMEDIATE");
    try {
      // Re-check under the lock: another process may have created it meanwhile.
      if (userVersion(db) === 0 && !hasLegacyTables(db)) {
        createLatest(db);
        db.exec(`PRAGMA user_version = ${LATEST_SCHEMA_VERSION}`);
      }
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    return;
  }

  for (let version = current; version < LATEST_SCHEMA_VERSION; version++) {
    const migration = MIGRATIONS[version]!;
    db.exec("BEGIN IMMEDIATE");
    try {
      if (userVersion(db) !== version) {
        // Someone else applied this step while we waited for the lock.
        db.exec("ROLLBACK");
        continue;
      }
      migration.up(db);
      db.exec(`PRAGMA user_version = ${version + 1}`);
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw new Error(
        `approvals database migration ${version + 1} ("${migration.name}") failed: ` +
          `${(err as Error).message}`
      );
    }
  }
}
