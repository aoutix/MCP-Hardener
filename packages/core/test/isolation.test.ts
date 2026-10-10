import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApprovalStore, bindingHash, type ScopedApprovals } from "../src/index.js";

/**
 * Two tenants in one approvals database.
 *
 * This is the case the project had no test for, and the one the default
 * configuration produces: `store_path` defaults to a single shared file, and a
 * hosted gateway serves every tenant from one process. Before scoping, two
 * bugs were live in exactly that arrangement, and both are the kind that grant
 * access rather than deny it:
 *
 *   - `consume` matched on `binding_hash` alone. The hash covers the tool name
 *     and the arguments and nothing else, so one tenant's granted approval
 *     released another tenant's byte-identical call.
 *   - `consumeGrant` matched on tool, effect and arguments. One tenant's
 *     standing grant released another tenant's call — and charged the use to
 *     the grant that did not authorise it, so the counter lied too.
 *
 * An on-disk file rather than `:memory:`, because `:memory:` is private to a
 * connection: two stores over it would be two databases and the test would
 * pass without proving anything.
 */

const COMPONENT = "gateway:hmcp";
const HOUR = 60 * 60 * 1000;

let dir: string;
let db: ApprovalStore;
let acme: ScopedApprovals;
let globex: ScopedApprovals;

const call = { tool: "create_invoice", args: { amount: 2400, currency: "usd" } };

function pendingRow(id: string) {
  return {
    id,
    created_at: Date.now(),
    expires_at: Date.now() + HOUR,
    tool: call.tool,
    effect: "write",
    binding_hash: bindingHash(call.tool, call.args),
    args_redacted: JSON.stringify(call.args),
    reason: "approve-writes posture",
    actor: "agent",
    session: "s"
  };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-isolation-"));
  db = new ApprovalStore(join(dir, "approvals.sqlite"));
  acme = db.scoped({ component: COMPONENT, tenant: "acme" });
  globex = db.scoped({ component: COMPONENT, tenant: "globex" });
});

afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("one tenant's approval", () => {
  it("does not release another tenant's identical call", () => {
    acme.insertPending(pendingRow("apr_acme"));
    acme.decide("apr_acme", "granted", "acme-reviewer");

    const binding = bindingHash(call.tool, call.args);
    // Same tool, same arguments, same hash. Only the tenant differs, and that
    // is the whole of what must keep them apart.
    //
    // Globex goes first, deliberately. The other order proves nothing: a
    // single-use approval is spent by whoever redeems it, so acme consuming
    // first would leave nothing for globex to find whether the scope filter
    // worked or not, and the test would pass against the bug it exists for.
    expect(globex.consume(binding, true)).toBeUndefined();
    expect(acme.consume(binding, true)).toBeDefined();
  });

  it("cannot be seen, fetched or decided from another tenant", () => {
    acme.insertPending(pendingRow("apr_acme"));

    expect(globex.listPending()).toEqual([]);
    expect(globex.get("apr_acme")).toBeUndefined();
    expect(globex.decide("apr_acme", "granted", "impostor")).toBeUndefined();
    // And the row is untouched, not merely hidden.
    expect(acme.get("apr_acme")!.state).toBe("pending");
  });

  it("is still visible to an operator looking at the whole file", () => {
    // Isolation between tenants, not from the person holding the database.
    acme.insertPending(pendingRow("apr_acme"));
    globex.insertPending(pendingRow("apr_globex"));
    expect(db.listPendingAll().map((r) => r.id).sort()).toEqual(["apr_acme", "apr_globex"]);
    expect(db.listScopes()).toEqual([
      { component: COMPONENT, tenant: "acme" },
      { component: COMPONENT, tenant: "globex" }
    ]);
  });
});

describe("one tenant's standing grant", () => {
  it("does not release another tenant's call, nor charge itself for it", () => {
    const grant = acme.createGrant({
      tool_match: "create_*",
      effect: "write",
      expires_at: Date.now() + HOUR,
      max_uses: 5,
      reason: "month-end invoicing run",
      created_by: "acme-reviewer"
    });

    expect(globex.consumeGrant(call.tool, "write", call.args)).toBeUndefined();
    // The counter is the part that used to lie: a cross-tenant release spent
    // a use belonging to a grant that had not authorised anything.
    expect(acme.getGrant(grant.id)!.uses).toBe(0);

    expect(acme.consumeGrant(call.tool, "write", call.args)).toBeDefined();
    expect(acme.getGrant(grant.id)!.uses).toBe(1);
  });

  it("cannot be listed or revoked from another tenant", () => {
    const grant = acme.createGrant({
      tool_match: "create_*",
      expires_at: Date.now() + HOUR,
      reason: "month-end invoicing run",
      created_by: "acme-reviewer"
    });

    expect(globex.listGrants()).toEqual([]);
    expect(globex.getGrant(grant.id)).toBeUndefined();
    expect(globex.revokeGrant(grant.id, "impostor")).toBeUndefined();
    expect(acme.getGrant(grant.id)!.state).toBe("active");
  });
});

describe("two servers rather than two tenants", () => {
  it("are kept apart on the component axis as well", () => {
    const billing = db.scoped({ component: "generated:Billing", tenant: "acme" });
    const payroll = db.scoped({ component: "generated:Payroll", tenant: "acme" });

    billing.insertPending(pendingRow("apr_billing"));

    expect(payroll.listPending()).toEqual([]);
    expect(payroll.consume(bindingHash(call.tool, call.args), true)).toBeUndefined();
  });
});
