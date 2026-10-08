import { describe, expect, it } from "vitest";
import {
  ApprovalStore,
  MAX_GRANT_TTL_SECONDS,
  grantIsLive,
  grantMatches,
  parseGrantDraft,
  type StandingGrantDraft
} from "../src/index.js";

const HOUR = 60 * 60 * 1000;

function store(): ApprovalStore {
  return new ApprovalStore(":memory:");
}

function draft(overrides: Partial<StandingGrantDraft> = {}): StandingGrantDraft {
  return {
    tool_match: "create_invoice",
    expires_at: Date.now() + HOUR,
    reason: "month-end invoicing run",
    created_by: "tester",
    ...overrides
  };
}

describe("grant matching", () => {
  it("matches on the same glob vocabulary as policy rules", () => {
    const s = store();
    const g = s.createGrant(draft({ tool_match: "{create,update}_*", max_uses: 5 }));
    expect(grantMatches(g, "create_invoice", "write", {}).matches).toBe(true);
    expect(grantMatches(g, "update_invoice", "write", {}).matches).toBe(true);
    expect(grantMatches(g, "delete_invoice", "destructive", {}).matches).toBe(false);
    s.close();
  });

  it("restricts by effect when one is named, and matches any effect when null", () => {
    const s = store();
    const anyEffect = s.createGrant(draft());
    expect(grantMatches(anyEffect, "create_invoice", "destructive", {}).matches).toBe(true);

    const writeOnly = s.createGrant(draft({ effect: "write" }));
    expect(grantMatches(writeOnly, "create_invoice", "write", {}).matches).toBe(true);
    const miss = grantMatches(writeOnly, "create_invoice", "destructive", {});
    expect(miss.matches).toBe(false);
    expect(miss.reason).toContain("grant covers write calls");
    s.close();
  });

  it("checks arguments with the policy engine's own constraint checker", () => {
    const s = store();
    const g = s.createGrant(draft({ constraints: { amount: { max: 500 }, currency: { enum: ["usd"] } } }));

    expect(grantMatches(g, "create_invoice", "write", { amount: 100, currency: "usd" }).matches).toBe(true);

    const overAmount = grantMatches(g, "create_invoice", "write", { amount: 90_000, currency: "usd" });
    expect(overAmount.matches).toBe(false);
    // The message comes from checkArgConstraints, which is what proves the
    // constraint vocabulary is shared with policy rules rather than reimplemented.
    expect(overAmount.reason).toContain("amount");

    expect(grantMatches(g, "create_invoice", "write", { amount: 10, currency: "eur" }).matches).toBe(false);
    s.close();
  });

  it("treats an unreadable constraint column as no match, never as permission", () => {
    const s = store();
    const g = s.createGrant(draft());
    const corrupt = { ...g, constraints: "{not json" };
    const result = grantMatches(corrupt, "create_invoice", "write", {});
    expect(result.matches).toBe(false);
    expect(result.reason).toContain("unreadable");
    s.close();
  });
});

describe("grant lifecycle", () => {
  it("expires past-due grants lazily and stops matching them", () => {
    const s = store();
    const g = s.createGrant(draft({ expires_at: Date.now() - 1 }));
    expect(grantIsLive(g)).toBe(false);
    expect(s.expireStaleGrants()).toBe(1);
    expect(s.getGrant(g.id)!.state).toBe("expired");
    expect(s.consumeGrant("create_invoice", "write", {})).toBeUndefined();
    s.close();
  });

  it("charges one use per call and exhausts at the cap", () => {
    const s = store();
    const g = s.createGrant(draft({ max_uses: 2 }));

    expect(s.consumeGrant("create_invoice", "write", {})!.uses).toBe(1);
    const second = s.consumeGrant("create_invoice", "write", {})!;
    expect(second.uses).toBe(2);
    expect(second.state).toBe("exhausted");
    expect(s.consumeGrant("create_invoice", "write", {})).toBeUndefined();
    s.close();
  });

  it("releases without limit when no cap is set", () => {
    const s = store();
    s.createGrant(draft({ max_uses: null }));
    for (let i = 0; i < 5; i++) {
      expect(s.consumeGrant("create_invoice", "write", {})).toBeDefined();
    }
    s.close();
  });

  it("stops releasing once revoked", () => {
    const s = store();
    const g = s.createGrant(draft());
    expect(s.revokeGrant(g.id, "tester")!.state).toBe("revoked");
    expect(s.consumeGrant("create_invoice", "write", {})).toBeUndefined();
    // Revoking twice is not an error the caller can act on, but it must not
    // silently look like a fresh revocation either.
    expect(s.revokeGrant(g.id, "tester")).toBeUndefined();
    s.close();
  });

  it("uses the oldest matching grant first, like the exact-argument path does", () => {
    const s = store();
    const older = s.createGrant(draft({ max_uses: 1, reason: "older" }), Date.now() - 1000);
    s.createGrant(draft({ max_uses: 1, reason: "newer" }), Date.now());
    expect(s.consumeGrant("create_invoice", "write", {})!.id).toBe(older.id);
    s.close();
  });

  it("falls through to a later grant when the first is exhausted", () => {
    const s = store();
    const first = s.createGrant(draft({ max_uses: 1, reason: "first" }), Date.now() - 1000);
    const second = s.createGrant(draft({ max_uses: 1, reason: "second" }), Date.now());
    expect(s.consumeGrant("create_invoice", "write", {})!.id).toBe(first.id);
    expect(s.consumeGrant("create_invoice", "write", {})!.id).toBe(second.id);
    s.close();
  });

  it("never lets concurrent calls exceed the use cap", () => {
    const s = store();
    s.createGrant(draft({ max_uses: 3 }));
    // node:sqlite is synchronous, so this races the CAS the same way two
    // processes would: every attempt runs against the committed use count.
    const released = Array.from({ length: 10 }, () => s.consumeGrant("create_invoice", "write", {})).filter(
      (r) => r !== undefined
    );
    expect(released).toHaveLength(3);
    s.close();
  });
});

describe("grant drafts are bounded at creation", () => {
  it("refuses a grant that has already expired", () => {
    expect(() => parseGrantDraft({ ...draft({ expires_at: Date.now() - 1 }) })).toThrow(/in the past/);
  });

  it("refuses a grant that outlives the maximum TTL", () => {
    const tooLong = Date.now() + (MAX_GRANT_TTL_SECONDS + 86_400) * 1000;
    expect(() => parseGrantDraft({ ...draft({ expires_at: tooLong }) })).toThrow(/may not last longer/);
  });

  it("refuses an unbounded wildcard, which would just be a policy edit", () => {
    expect(() => parseGrantDraft({ ...draft({ tool_match: "*" }) })).toThrow(/unbounded wildcard/);
  });

  it("accepts a wildcard bounded by a use cap or by argument constraints", () => {
    expect(() => parseGrantDraft({ ...draft({ tool_match: "create_*", max_uses: 5 }) })).not.toThrow();
    expect(() =>
      parseGrantDraft({ ...draft({ tool_match: "create_*", constraints: { amount: { max: 10 } } }) })
    ).not.toThrow();
  });

  it("reports an unclosed brace rather than letting it match literally at call time", () => {
    expect(() => parseGrantDraft({ ...draft({ tool_match: "{create,update" }) })).toThrow(/unclosed brace/);
  });

  it("requires a reason, because it goes in the audit log", () => {
    expect(() => parseGrantDraft({ ...draft(), reason: "" })).toThrow();
  });
});
