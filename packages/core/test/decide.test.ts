import { describe, expect, it } from "vitest";
import { decide, parsePolicy, type Policy } from "../src/index.js";

function policy(overrides: Record<string, unknown> = {}): Policy {
  return parsePolicy({ version: 1, ...overrides });
}

describe("posture defaults", () => {
  it("allows reads and refuses everything that mutates, by default", () => {
    const p = policy();
    expect(decide({ tool: "get_pet", effect: "read", policy: p }).kind).toBe("allow");
    expect(decide({ tool: "create_pet", effect: "write", policy: p }).kind).toBe("deny");
    expect(decide({ tool: "delete_pet", effect: "destructive", policy: p }).kind).toBe("deny");
  });

  it("escalates writes to approval under the approve-writes posture", () => {
    const p = policy({ defaults: { mode: "approve-writes" } });
    expect(decide({ tool: "get_pet", effect: "read", policy: p }).kind).toBe("allow");
    expect(decide({ tool: "create_pet", effect: "write", policy: p }).kind).toBe("approve");
    expect(decide({ tool: "delete_pet", effect: "destructive", policy: p }).kind).toBe("approve");
  });

  it("refuses reads too under the locked posture", () => {
    const p = policy({ defaults: { mode: "locked" } });
    expect(decide({ tool: "get_pet", effect: "read", policy: p }).kind).toBe("deny");
  });

  it("names the posture as the deciding rule so the log explains itself", () => {
    const d = decide({ tool: "create_pet", effect: "write", policy: policy() });
    expect(d.ruleId).toBe("defaults.mode");
    expect(d.reason).toMatch(/read-only posture refuses write/);
  });
});

describe("unclassified tools", () => {
  it("denies a tool with no effect - a newly added upstream tool is not reachable", () => {
    const d = decide({ tool: "mystery_tool", policy: policy() });
    expect(d.kind).toBe("deny");
    expect(d.ruleId).toBe("defaults.on_unclassified");
  });

  it("denies unclassified even when a rule would allow it", () => {
    const p = policy({ rules: [{ id: "wide-open", match: "*", decision: "allow" }] });
    expect(decide({ tool: "mystery_tool", policy: p }).kind).toBe("deny");
  });

  it("can be configured to ask instead of refuse", () => {
    const p = policy({ defaults: { on_unclassified: "approve" } });
    expect(decide({ tool: "mystery_tool", policy: p }).kind).toBe("approve");
  });
});

describe("rules", () => {
  const p = policy({
    rules: [
      { id: "reads", match: "get_*", effect: "read", decision: "allow" },
      { id: "no-delete", match: "delete_*", decision: "deny", reason: "deletes are never permitted here" },
      { id: "invoices", match: "create_invoice", effect: "write", decision: "approve" },
      { id: "catch-all", match: "*", effect: "read", decision: "allow" }
    ]
  });

  it("uses the first matching rule, not the most specific one", () => {
    const d = decide({ tool: "get_pet", policy: p });
    expect(d.ruleId).toBe("reads");
  });

  it("lets a rule reclassify effect, which is how a POST /search becomes a read", () => {
    const d = decide({ tool: "search_pets", effect: "write", policy: p });
    expect(d.effect).toBe("read");
    expect(d.ruleId).toBe("catch-all");
    expect(d.kind).toBe("allow");
  });

  it("surfaces a rule's own reason text", () => {
    expect(decide({ tool: "delete_pet", effect: "destructive", policy: p }).reason).toBe(
      "deletes are never permitted here"
    );
  });

  it("falls through to the posture when no rule matches", () => {
    const narrow = policy({ rules: [{ id: "only-pets", match: "get_pet", effect: "read", decision: "allow" }] });
    expect(decide({ tool: "get_order", effect: "write", policy: narrow }).ruleId).toBe("defaults.mode");
  });
});

describe("argument constraints", () => {
  const p = policy({
    rules: [
      {
        id: "small-transfers",
        match: "create_transfer",
        effect: "write",
        decision: "approve",
        args: { amount: { max: 50000, min: 1 }, currency: { enum: ["usd"] } }
      }
    ]
  });

  it("honors the rule when the arguments are in bounds", () => {
    const d = decide({ tool: "create_transfer", args: { amount: 100, currency: "usd" }, policy: p });
    expect(d.kind).toBe("approve");
  });

  it("denies rather than approves when a bound is exceeded", () => {
    const d = decide({ tool: "create_transfer", args: { amount: 50001, currency: "usd" }, policy: p });
    expect(d.kind).toBe("deny");
    expect(d.reason).toMatch(/exceeds the policy maximum of 50000/);
  });

  it("denies a value outside an enum", () => {
    const d = decide({ tool: "create_transfer", args: { amount: 10, currency: "btc" }, policy: p });
    expect(d.kind).toBe("deny");
    expect(d.reason).toMatch(/not one of/);
  });

  it("denies when a required argument is missing", () => {
    const req = policy({
      rules: [{ id: "r", match: "t", effect: "read", decision: "allow", args: { limit: { required: true } } }]
    });
    expect(decide({ tool: "t", args: {}, policy: req }).kind).toBe("deny");
  });

  it("denies when a pattern does not match", () => {
    const pat = policy({
      rules: [{ id: "r", match: "t", effect: "read", decision: "allow", args: { id: { pattern: "^[0-9]+$" } } }]
    });
    expect(decide({ tool: "t", args: { id: "../../etc/passwd" }, policy: pat }).kind).toBe("deny");
    expect(decide({ tool: "t", args: { id: "42" }, policy: pat }).kind).toBe("allow");
  });

  it("denies a numeric bound applied to a non-numeric value instead of coercing past it", () => {
    const d = decide({ tool: "create_transfer", args: { amount: "lots", currency: "usd" }, policy: p });
    expect(d.kind).toBe("deny");
  });
});

describe("tenant scoping", () => {
  const p = policy({
    rules: [{ id: "reads", match: "*", effect: "read", decision: "allow" }],
    tenant: { field: "org_id", aliases: ["organization_id"], source: { kind: "env", name: "ORG" } }
  });

  it("allows a call that names its own tenant", () => {
    const d = decide({ tool: "list_invoices", args: { org_id: "acme" }, policy: p, tenant: { expected: "acme" } });
    expect(d.kind).toBe("allow");
  });

  it("denies a call that names a different tenant, whatever the rules say", () => {
    const d = decide({ tool: "list_invoices", args: { org_id: "globex" }, policy: p, tenant: { expected: "acme" } });
    expect(d.kind).toBe("deny");
    expect(d.ruleId).toBe("tenant.on_mismatch");
    expect(d.reason).toMatch(/tenant scope violation/);
  });

  it("catches a foreign tenant supplied under an alias", () => {
    const d = decide({
      tool: "list_invoices",
      args: { organization_id: "globex" },
      policy: p,
      tenant: { expected: "acme" }
    });
    expect(d.kind).toBe("deny");
  });

  it("catches a foreign tenant supplied under a differently-cased key", () => {
    const d = decide({ tool: "list_invoices", args: { Org_Id: "globex" }, policy: p, tenant: { expected: "acme" } });
    expect(d.kind).toBe("deny");
  });

  it("refuses to run at all when a required tenant cannot be resolved", () => {
    const d = decide({ tool: "list_invoices", policy: p, tenant: { expected: undefined } });
    expect(d.kind).toBe("deny");
    expect(d.ruleId).toBe("tenant.required");
  });

  it("silently overrides instead of denying when configured to", () => {
    const overriding = policy({
      rules: [{ id: "reads", match: "*", effect: "read", decision: "allow" }],
      tenant: { field: "org_id", source: { kind: "env", name: "ORG" }, on_mismatch: "override" }
    });
    const d = decide({
      tool: "list_invoices",
      args: { org_id: "globex" },
      policy: overriding,
      tenant: { expected: "acme" }
    });
    expect(d.kind).toBe("allow");
  });

  it("tenant checks run ahead of effect classification, so an unclassified cross-tenant call reports the real cause", () => {
    const d = decide({ tool: "mystery", args: { org_id: "globex" }, policy: p, tenant: { expected: "acme" } });
    expect(d.ruleId).toBe("tenant.on_mismatch");
  });
});

describe("policy validation", () => {
  it("rejects duplicate rule ids, which would make the audit log ambiguous", () => {
    expect(() =>
      parsePolicy({
        version: 1,
        rules: [
          { id: "dup", match: "a", decision: "allow" },
          { id: "dup", match: "b", decision: "deny" }
        ]
      })
    ).toThrow(/duplicate rule id/);
  });

  it("rejects an unparseable argument pattern instead of failing open at call time", () => {
    expect(() =>
      parsePolicy({
        version: 1,
        rules: [{ id: "r", match: "a", decision: "allow", args: { x: { pattern: "([" } } }]
      })
    ).toThrow(/invalid regular expression/);
  });

  it("rejects unknown keys so a typo cannot silently disable a control", () => {
    expect(() => parsePolicy({ version: 1, egress: { allow: ["a.com"], blok_private_ips: true } })).toThrow();
  });

  it("requires a header name when tenant injection targets a header", () => {
    expect(() =>
      parsePolicy({
        version: 1,
        tenant: { field: "org", source: { kind: "static", value: "x" }, inject: ["header"] }
      })
    ).toThrow(/header_name is required/);
  });

  it("defaults to read-only with private IPs blocked and no egress allowed", () => {
    const p = parsePolicy({ version: 1 });
    expect(p.defaults.mode).toBe("read-only");
    expect(p.egress.block_private_ips).toBe(true);
    expect(p.egress.allow).toEqual([]);
    expect(p.egress.allow_http).toBe(false);
    expect(p.audit.hash_chain).toBe(true);
  });
});

describe("exposure overrides", () => {
  it("refuses a switched-off tool that every rule and the posture would allow", () => {
    const p = policy({ rules: [{ id: "reads", match: "get_*", effect: "read", decision: "allow" }] });
    expect(decide({ tool: "get_pet", effect: "read", policy: p }).kind).toBe("allow");

    const off = decide({ tool: "get_pet", effect: "read", policy: p, disabled: true });
    expect(off.kind).toBe("deny");
    expect(off.ruleId).toBe("exposure.disabled");
  });

  it("carries the supplied reason, so a refusal names the switch rather than a rule", () => {
    const off = decide({
      tool: "get_pet",
      effect: "read",
      policy: policy(),
      disabled: true,
      disabledReason: "switched off by alice while we investigate"
    });
    expect(off.reason).toBe("switched off by alice while we investigate");
  });

  it("is decided before tenant integrity, so one refusal is not reported as the other", () => {
    const p = policy({
      tenant: { field: "org_id", source: { kind: "static", value: "acme" } }
    });
    const crossTenant = {
      tool: "get_pet",
      effect: "read" as const,
      args: { org_id: "other" },
      policy: p,
      tenant: { expected: "acme" }
    };
    expect(decide(crossTenant).ruleId).toBe("tenant.on_mismatch");
    expect(decide({ ...crossTenant, disabled: true }).ruleId).toBe("exposure.disabled");
  });

  it("can only ever subtract: there is no value of `disabled` that permits a denied call", () => {
    // The whole safety argument for letting a console own this switch. A tool
    // policy refuses stays refused whether it is switched off or not, so
    // clearing an override can never widen what decide() permits.
    const p = policy({ rules: [{ id: "no-deletes", match: "delete_*", decision: "deny" }] });
    for (const disabled of [true, false, undefined]) {
      expect(decide({ tool: "delete_pet", effect: "destructive", policy: p, disabled }).kind).toBe("deny");
    }
  });
});
