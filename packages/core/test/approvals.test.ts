import { describe, expect, it, vi } from "vitest";
import { ApprovalBroker, ApprovalStore, bindingHash, parsePolicy } from "../src/index.js";

function setup(overrides: Record<string, unknown> = {}, elicit?: Parameters<typeof makeBroker>[2]) {
  const policy = parsePolicy({ version: 1, approvals: { store_path: ":memory:", ...overrides } });
  const store = new ApprovalStore(":memory:");
  return { policy, store, broker: makeBroker(policy.approvals, store, elicit) };
}

function makeBroker(
  config: ReturnType<typeof parsePolicy>["approvals"],
  store: ApprovalStore,
  elicit?: ConstructorParameters<typeof ApprovalBroker>[0]["elicit"]
) {
  return new ApprovalBroker({ config, store, elicit });
}

const call = {
  tool: "create_transfer",
  effect: "write" as const,
  args: { amount: 10, currency: "usd" },
  reason: "approve-writes posture",
  actor: "tester",
  session: "sess-1"
};

describe("out-of-band CLI approval", () => {
  it("parks the request and tells the agent how a human releases it", async () => {
    const { broker, store } = setup({ mode: "cli" });
    const outcome = await broker.request(call);

    expect(outcome.granted).toBe(false);
    if (outcome.granted) return;
    expect(outcome.approvalId).toMatch(/^apr_/);
    expect(outcome.instructions).toContain(`hmcp approve ${outcome.approvalId}`);
    expect(store.listPending()).toHaveLength(1);
  });

  it("releases the call once a human approves, then never again", async () => {
    const { broker, store } = setup({ mode: "cli" });
    const first = await broker.request(call);
    expect(first.granted).toBe(false);
    if (first.granted) return;

    store.decide(first.approvalId!, "granted", "alice", "checked with finance");

    const second = await broker.request(call);
    expect(second.granted).toBe(true);
    if (!second.granted) return;
    expect(second.via).toBe("cached");

    // Single-use: the retry after consumption parks a fresh request instead of
    // reusing the spent grant.
    const third = await broker.request(call);
    expect(third.granted).toBe(false);
  });

  it("does not release the call when a human denies it", async () => {
    const { broker, store } = setup({ mode: "cli" });
    const first = await broker.request(call);
    if (first.granted) throw new Error("unexpected grant");
    store.decide(first.approvalId!, "denied", "alice");
    expect((await broker.request(call)).granted).toBe(false);
  });

  it("permits repeated use when single_use is off", async () => {
    const { broker, store } = setup({ mode: "cli", single_use: false });
    const first = await broker.request(call);
    if (first.granted) throw new Error("unexpected grant");
    store.decide(first.approvalId!, "granted", "alice");
    expect((await broker.request(call)).granted).toBe(true);
    expect((await broker.request(call)).granted).toBe(true);
  });
});

describe("argument binding", () => {
  it("does not let an approval for one amount release a different amount", async () => {
    const { broker, store } = setup({ mode: "cli" });
    const small = await broker.request(call);
    if (small.granted) throw new Error("unexpected grant");
    store.decide(small.approvalId!, "granted", "alice");

    const large = await broker.request({ ...call, args: { amount: 10000, currency: "usd" } });
    expect(large.granted).toBe(false);

    // The original call is still releasable, so this is binding, not breakage.
    expect((await broker.request(call)).granted).toBe(true);
  });

  it("does not let an approval for one tool release another", async () => {
    const { broker, store } = setup({ mode: "cli" });
    const first = await broker.request(call);
    if (first.granted) throw new Error("unexpected grant");
    store.decide(first.approvalId!, "granted", "alice");
    expect((await broker.request({ ...call, tool: "delete_account" })).granted).toBe(false);
  });

  it("binds regardless of argument key order", () => {
    expect(bindingHash("t", { a: 1, b: 2 })).toBe(bindingHash("t", { b: 2, a: 1 }));
    expect(bindingHash("t", { a: 1 })).not.toBe(bindingHash("t", { a: "1" }));
  });

  it("treats a nested argument change as a different call", () => {
    expect(bindingHash("t", { filter: { org: "acme" } })).not.toBe(bindingHash("t", { filter: { org: "globex" } }));
  });
});

describe("expiry", () => {
  it("refuses a grant that has outlived its ttl", async () => {
    const store = new ApprovalStore(":memory:");
    const policy = parsePolicy({ version: 1, approvals: { mode: "cli", ttl_seconds: 60 } });
    let now = 1_000_000;
    const broker = new ApprovalBroker({ config: policy.approvals, store, now: () => now });

    const first = await broker.request(call);
    if (first.granted) throw new Error("unexpected grant");
    store.decide(first.approvalId!, "granted", "alice");

    now += 61_000;
    store.expireStale(now);
    const retry = await broker.request(call);
    expect(retry.granted).toBe(false);
  });

  it("expires a pending request that nobody reviewed", async () => {
    const store = new ApprovalStore(":memory:");
    const policy = parsePolicy({ version: 1, approvals: { mode: "cli", ttl_seconds: 30 } });
    let now = 2_000_000;
    const broker = new ApprovalBroker({ config: policy.approvals, store, now: () => now });
    const first = await broker.request(call);
    if (first.granted) throw new Error("unexpected grant");

    store.expireStale(now + 31_000);
    expect(store.get(first.approvalId!)!.state).toBe("expired");
    expect(store.decide(first.approvalId!, "granted", "alice")).toBeUndefined();
  });
});

describe("elicitation", () => {
  it("grants immediately when the host's reviewer accepts", async () => {
    const elicit = vi.fn().mockResolvedValue({ action: "accept", content: { approve: true, note: "ok" } });
    const { broker } = setup({ mode: "both" }, elicit);
    const outcome = await broker.request(call);

    expect(outcome.granted).toBe(true);
    if (!outcome.granted) return;
    expect(outcome.via).toBe("elicit");
    const prompt = elicit.mock.calls[0]![0].message as string;
    expect(prompt).toContain("create_transfer");
    expect(prompt).toContain("Approve a write operation?");
  });

  it("refuses when the reviewer declines in the form", async () => {
    const elicit = vi.fn().mockResolvedValue({ action: "accept", content: { approve: false } });
    const { broker } = setup({ mode: "both" }, elicit);
    const outcome = await broker.request(call);
    expect(outcome.granted).toBe(false);
    if (outcome.granted) return;
    expect(outcome.reason).toMatch(/declined/);
  });

  it("refuses when the prompt is cancelled", async () => {
    const elicit = vi.fn().mockResolvedValue({ action: "cancel" });
    const { broker } = setup({ mode: "both" }, elicit);
    expect((await broker.request(call)).granted).toBe(false);
  });

  it("does not grant twice from one elicitation", async () => {
    const elicit = vi.fn().mockResolvedValue({ action: "accept", content: { approve: true } });
    const { broker } = setup({ mode: "both" }, elicit);
    expect((await broker.request(call)).granted).toBe(true);
    // A second call must prompt again rather than redeem the recorded grant.
    expect((await broker.request(call)).granted).toBe(true);
    expect(elicit).toHaveBeenCalledTimes(2);
  });

  it("redacts secrets out of the prompt shown to the reviewer", async () => {
    const elicit = vi.fn().mockResolvedValue({ action: "accept", content: { approve: true } });
    const { broker } = setup({ mode: "both" }, elicit);
    await broker.request({ ...call, args: { amount: 1, api_key: "sk_live_abcdefghijklmnopqrst" } });
    expect(elicit.mock.calls[0]![0].message).not.toContain("sk_live_abcdefghijklmnopqrst");
  });

  it("falls back to the CLI when the host cannot deliver the prompt", async () => {
    const elicit = vi.fn().mockRejectedValue(new Error("client has no UI"));
    const { broker, store } = setup({ mode: "both" }, elicit);
    const outcome = await broker.request(call);
    expect(outcome.granted).toBe(false);
    if (outcome.granted) return;
    expect(outcome.instructions).toContain("hmcp approve");
    expect(store.listPending()).toHaveLength(1);
  });

  it("does not fall back when the policy says elicit only", async () => {
    const elicit = vi.fn().mockRejectedValue(new Error("client has no UI"));
    const { broker, store } = setup({ mode: "elicit" }, elicit);
    const outcome = await broker.request(call);
    expect(outcome.granted).toBe(false);
    if (outcome.granted) return;
    expect(outcome.instructions).toBeUndefined();
    expect(store.listPending()).toHaveLength(0);
  });

  it("reports plainly when elicit-only meets a client without the capability", async () => {
    const { broker } = setup({ mode: "elicit" });
    const outcome = await broker.request(call);
    expect(outcome.granted).toBe(false);
    if (outcome.granted) return;
    expect(outcome.reason).toMatch(/does not support elicitation/);
  });

  it("refuses everything when approvals are disabled", async () => {
    const elicit = vi.fn().mockResolvedValue({ action: "accept", content: { approve: true } });
    const { broker } = setup({ mode: "deny" }, elicit);
    expect((await broker.request(call)).granted).toBe(false);
    expect(elicit).not.toHaveBeenCalled();
  });
});

describe("standing grants in the broker", () => {
  it("releases a matching call and records it as an already-spent approval", async () => {
    const { broker, store } = setup({ mode: "cli" });
    const grant = store.createGrant({
      tool_match: "create_transfer",
      constraints: { amount: { max: 500 } },
      expires_at: Date.now() + 60_000,
      max_uses: 5,
      reason: "payroll run",
      created_by: "operator"
    });

    const outcome = await broker.request(call);
    expect(outcome.granted).toBe(true);
    if (!outcome.granted) return;
    expect(outcome.via).toBe("standing");
    expect(outcome.grantId).toBe(grant.id);

    // The approval row exists for the trail but is already spent, so the exact
    // arguments can never be redeemed a second time through `consume`.
    expect(store.get(outcome.approvalId)!.state).toBe("used");
    expect(store.getGrant(grant.id)!.uses).toBe(1);
  });

  it("marks the row used even when single_use is off, so consume cannot replay it", async () => {
    const { broker, store } = setup({ mode: "cli", single_use: false });
    store.createGrant({
      tool_match: "create_transfer",
      expires_at: Date.now() + 60_000,
      max_uses: 1,
      reason: "one transfer",
      created_by: "operator"
    });

    const first = await broker.request(call);
    expect(first.granted).toBe(true);

    // With a reusable `granted` row this second call would have been released
    // by the binding-hash path without charging a grant use.
    const second = await broker.request(call);
    expect(second.granted).toBe(false);
    expect(store.listPending()).toHaveLength(1);
  });

  it("falls through to human approval when the arguments miss the constraints", async () => {
    const { broker, store } = setup({ mode: "cli" });
    const grant = store.createGrant({
      tool_match: "create_transfer",
      constraints: { amount: { max: 5 } },
      expires_at: Date.now() + 60_000,
      max_uses: 5,
      reason: "small transfers only",
      created_by: "operator"
    });

    // call.args.amount is 10, over the grant's ceiling. A narrow grant must not
    // turn into a denial: the call parks for a human exactly as it would with
    // no grant at all, and the grant is not charged.
    const outcome = await broker.request(call);
    expect(outcome.granted).toBe(false);
    if (outcome.granted) return;
    expect(outcome.instructions).toContain("hmcp approve");
    expect(store.listPending()).toHaveLength(1);
    expect(store.getGrant(grant.id)!.uses).toBe(0);
  });

  it("prefers an exact-argument grant over a standing grant", async () => {
    const { broker, store, policy } = setup({ mode: "cli" });
    const grant = store.createGrant({
      tool_match: "create_transfer",
      expires_at: Date.now() + 60_000,
      max_uses: 5,
      reason: "standing",
      created_by: "operator"
    });
    store.insertGranted(
      {
        id: "apr_exact",
        created_at: Date.now(),
        expires_at: Date.now() + 60_000,
        tool: call.tool,
        effect: call.effect,
        binding_hash: bindingHash(call.tool, call.args),
        args_redacted: "{}",
        reason: "approved by hand",
        actor: "operator",
        session: "sess-1"
      },
      "operator"
    );

    const outcome = await broker.request(call);
    expect(outcome.granted).toBe(true);
    if (!outcome.granted) return;
    expect(outcome.via).toBe("cached");
    // The standing grant's budget is untouched.
    expect(store.getGrant(grant.id)!.uses).toBe(0);
    expect(policy.approvals.single_use).toBe(true);
  });

  it("still honours a standing grant when interactive approval is disabled", async () => {
    // `mode: "deny"` turns off the machinery for *soliciting* a new approval.
    // A standing grant is an approval a human already gave, so it is consulted
    // before that check, exactly as a cached exact-argument grant is. Pinned
    // here deliberately rather than left to the order of two if-statements.
    const { broker, store } = setup({ mode: "deny" });
    store.createGrant({
      tool_match: "create_transfer",
      expires_at: Date.now() + 60_000,
      max_uses: 1,
      reason: "pre-authorised",
      created_by: "operator"
    });
    const outcome = await broker.request(call);
    expect(outcome.granted).toBe(true);
    if (!outcome.granted) return;
    expect(outcome.via).toBe("standing");
  });

  it("does not consult grants for a tool they do not name", async () => {
    const { broker, store } = setup({ mode: "cli" });
    store.createGrant({
      tool_match: "create_invoice",
      expires_at: Date.now() + 60_000,
      max_uses: 5,
      reason: "invoices only",
      created_by: "operator"
    });
    expect((await broker.request(call)).granted).toBe(false);
  });
});

describe("exposure overrides", () => {
  function store(): ApprovalStore {
    return new ApprovalStore(":memory:");
  }

  it("stores only the off state, so enabling is a deletion rather than a permission", () => {
    const s = store();
    expect(s.toolExposure("generated:Billing", "delete_invoice")).toBeUndefined();

    s.disableTool("generated:Billing", "delete_invoice", "alice", "incident 412");
    const row = s.toolExposure("generated:Billing", "delete_invoice")!;
    expect(row.set_by).toBe("alice");
    expect(row.reason).toBe("incident 412");

    expect(s.enableTool("generated:Billing", "delete_invoice")!.set_by).toBe("alice");
    expect(s.toolExposure("generated:Billing", "delete_invoice")).toBeUndefined();
  });

  it("reports that there was nothing to enable, so no change is recorded as one", () => {
    const s = store();
    expect(s.enableTool("generated:Billing", "delete_invoice")).toBeUndefined();
  });

  it("is idempotent, and a repeat records who last asserted it", () => {
    const s = store();
    s.disableTool("generated:Billing", "create_invoice", "alice", "first");
    s.disableTool("generated:Billing", "create_invoice", "bob", "second");
    expect(s.listDisabledTools("generated:Billing")).toHaveLength(1);
    expect(s.toolExposure("generated:Billing", "create_invoice")!.set_by).toBe("bob");
    expect(s.toolExposure("generated:Billing", "create_invoice")!.reason).toBe("second");
  });

  it("scopes by server, because one approvals database is shared by default", () => {
    // Two generated servers may legitimately both expose `list_invoices`.
    // Switching one off must not switch off the other's.
    const s = store();
    s.disableTool("generated:Billing", "list_invoices", "alice");
    expect(s.toolExposure("generated:Billing", "list_invoices")).toBeDefined();
    expect(s.toolExposure("generated:Payroll", "list_invoices")).toBeUndefined();
    expect(s.listDisabledTools("generated:Payroll")).toEqual([]);
  });
});
