import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { parsePolicy } from "@hmcp/core";
import { GatewayConfigSchema, loadGatewayConfig } from "../src/config.js";
import { parseServers, type ClaudeServer } from "../src/client-config.js";
import { planAdoption, type AdoptionPlan } from "../src/adopt-plan.js";
import { emitClientEntry, emitGatewayYaml, emitPolicyYaml, type ProbedTool } from "../src/adopt-emit.js";

/**
 * The two files adoption writes.
 *
 * What is tested here is mostly that the generated pair actually loads --
 * emitting YAML the gateway then refuses would turn adoption into a worse
 * version of writing it by hand -- plus the handful of values that are easy to
 * "tidy up" later and must not be: an empty `rules`, a POST in
 * `egress.methods`, and an `effect:` in every rule stub.
 */

function planOf(raw: Record<string, unknown>, options: Record<string, unknown> = {}): AdoptionPlan {
  const { servers, malformed } = parseServers(raw);
  expect(malformed).toEqual([]);
  return planAdoption(servers as ReadonlyMap<string, ClaudeServer>, {
    gatewayEntryName: "hmcp",
    ...options
  });
}

const emitOptions = { name: "claude-code", posture: "approve-writes" } as const;

const STDIO = { notes: { command: "node", args: ["notes.js"], env: { TOKEN: "t" } } };
const HTTP = { tickets: { type: "http", url: "https://mcp.example.com/mcp" } };

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-emit-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("gateway.yaml", () => {
  it("parses as a gateway config", () => {
    const yaml = emitGatewayYaml(planOf(STDIO), emitOptions);
    expect(() => GatewayConfigSchema.parse(parseYaml(yaml))).not.toThrow();
  });

  it("drops the empty defaults the schema filled in", () => {
    // `env: {}` and `pass_env: []` on every upstream is noise in a file meant
    // to be read.
    const yaml = emitGatewayYaml(planOf({ plain: { command: "node" } }), emitOptions);
    const upstream = (parseYaml(yaml) as { upstreams: Record<string, unknown>[] }).upstreams[0]!;
    expect(Object.keys(upstream).sort()).toEqual(["command", "name", "transport"]);
  });

  it("keeps pass_env when there is something to forward", () => {
    const yaml = emitGatewayYaml(planOf(STDIO), emitOptions);
    expect(yaml).toMatch(/pass_env:\n\s+- TOKEN/);
  });

  it("records why each server was skipped, so the reason outlives the terminal", () => {
    const plan = planOf({ ...STDIO, legacy: { type: "sse", url: "https://x/sse" } });
    const yaml = emitGatewayYaml(plan, emitOptions);
    expect(yaml).toMatch(/# {3}legacy: .*SSE/);
    expect(() => GatewayConfigSchema.parse(parseYaml(yaml))).not.toThrow();
  });

  it("warns in the file itself when --copy-env put a secret in it", () => {
    const plan = planOf(
      { tickets: { type: "http", url: "https://x.example.com/mcp", headers: { authorization: "Bearer ${T}" } } },
      { copyEnv: true, env: { T: "secret" } }
    );
    expect(emitGatewayYaml(plan, emitOptions)).toMatch(/Do not commit this file/);
  });
});

describe("policy.yaml", () => {
  it("parses as a policy", () => {
    const yaml = emitPolicyYaml(planOf(STDIO), emitOptions);
    expect(() => parsePolicy(parseYaml(yaml), "generated")).not.toThrow();
  });

  it("emits no rules at all", () => {
    // decide() falls back to the posture, and a glob rule here would match one
    // naming convention while overriding the gateway's own classification --
    // including its refusal to believe a server that calls its delete tool
    // read-only.
    const policy = parsePolicy(parseYaml(emitPolicyYaml(planOf(STDIO), emitOptions)), "generated");
    expect(policy.rules).toEqual([]);
  });

  it("carries the posture it was asked for", () => {
    const policy = parsePolicy(parseYaml(emitPolicyYaml(planOf(STDIO), emitOptions)), "generated");
    expect(policy.defaults.mode).toBe("approve-writes");
    expect(policy.defaults.on_unclassified).toBe("deny");
  });

  it("names POST in egress.methods, without which every HTTP upstream is refused", () => {
    // Opening a Streamable HTTP session is a POST, checked against this list
    // before the connection is made. The schema default is [GET, HEAD].
    const policy = parsePolicy(parseYaml(emitPolicyYaml(planOf(HTTP), emitOptions)), "generated");
    expect(policy.egress.methods).toContain("POST");
    expect(policy.egress.allow).toContain("mcp.example.com");
  });

  it("leaves the egress defaults alone when nothing speaks HTTP", () => {
    const yaml = emitPolicyYaml(planOf(STDIO), emitOptions);
    expect(yaml).not.toMatch(/egress:/);
  });

  it("relaxes the SSRF guard only when an adopted upstream needed it, and says which", () => {
    const plan = planOf({ figma: { type: "http", url: "http://127.0.0.1:3845/mcp" } }, { allowLocalHttp: true });
    const yaml = emitPolicyYaml(plan, emitOptions);
    const policy = parsePolicy(parseYaml(yaml), "generated");
    expect(policy.egress.block_private_ips).toBe(false);
    expect(policy.egress.allow_http).toBe(true);
    expect(policy.egress.allow_ip_literals).toBe(true);
    expect(yaml).toMatch(/WARNING/);
    expect(yaml).toMatch(/# {3}figma \(figma\)/);
  });

  it("keeps approvals on `both`, the only mode that works either way", () => {
    const policy = parsePolicy(parseYaml(emitPolicyYaml(planOf(STDIO), emitOptions)), "generated");
    expect(policy.approvals.mode).toBe("both");
  });
});

describe("the rule stubs for unclassified tools", () => {
  const unclassified: ProbedTool[] = [
    {
      localName: "notes__frobnicate",
      upstream: "notes",
      effect: null,
      effectSource: "unclassified",
      hidden: false,
      injection: null
    }
  ];

  it("gives every stub an effect, which is the part that does the work", () => {
    // An unclassified tool is refused before rules are consulted, so a stub
    // carrying only `decision:` would change nothing.
    const yaml = emitPolicyYaml(planOf(STDIO), { ...emitOptions, unclassified });
    const stub = yaml.split("\n").filter((l) => l.includes("notes__frobnicate") || l.includes("effect:"));
    expect(stub.join("\n")).toMatch(/effect:/);
    expect(yaml).toMatch(/#\s+- id: classify-notes__frobnicate/);
    expect(yaml).toMatch(/#\s+match: "notes__frobnicate"/);
  });

  it("explains that leaving effect out makes the rule a no-op", () => {
    const yaml = emitPolicyYaml(planOf(STDIO), { ...emitOptions, unclassified });
    expect(yaml).toMatch(/refused BEFORE rules are consulted/);
  });

  it("leaves the stubs commented, so the policy still parses unchanged", () => {
    const yaml = emitPolicyYaml(planOf(STDIO), { ...emitOptions, unclassified });
    expect(parsePolicy(parseYaml(yaml), "generated").rules).toEqual([]);
  });

  it("says nothing about budgets or stubs when there is nothing to say", () => {
    const yaml = emitPolicyYaml(planOf(STDIO), emitOptions);
    expect(yaml).not.toMatch(/could not be classified/);
    expect(yaml).not.toMatch(/tool_budget/);
  });

  it("mentions the tool budget as a comment rather than quietly raising it", () => {
    const yaml = emitPolicyYaml(planOf(STDIO), { ...emitOptions, toolCount: 73 });
    expect(yaml).toMatch(/# tool_budget: 73/);
    expect(parsePolicy(parseYaml(yaml), "generated").tool_budget).toBe(40);
  });
});

describe("the pair, loaded together", () => {
  it("loads through loadGatewayConfig, resolving the relative policy path", () => {
    // The real test: `policy: ./policy.yaml` resolves against the config's own
    // directory, which is what makes the generated directory movable.
    const plan = planOf({ ...STDIO, ...HTTP });
    writeFileSync(join(dir, "gateway.yaml"), emitGatewayYaml(plan, emitOptions));
    writeFileSync(join(dir, "policy.yaml"), emitPolicyYaml(plan, emitOptions));

    const loaded = loadGatewayConfig(join(dir, "gateway.yaml"));
    expect(loaded.config.upstreams.map((u) => u.name).sort()).toEqual(["notes", "tickets"]);
    expect(loaded.config.namespace).toBe(true);
    expect(loaded.policy.defaults.mode).toBe("approve-writes");
    expect(loaded.policy.egress.methods).toContain("POST");
  });
});

describe("the client entry", () => {
  it("points at the config and carries the environment the upstreams forward", () => {
    const entry = emitClientEntry(planOf(STDIO), {
      configPath: "/abs/.hmcp/gateway.yaml",
      command: "npx",
      args: ["-y", "hmcp-gateway@0.1.0"]
    });
    expect(entry).toEqual({
      command: "npx",
      args: ["-y", "hmcp-gateway@0.1.0", "serve", "-c", "/abs/.hmcp/gateway.yaml"],
      env: { TOKEN: "t" }
    });
  });

  it("omits env entirely when no upstream needs any", () => {
    const entry = emitClientEntry(planOf({ plain: { command: "node" } }), {
      configPath: "/abs/gateway.yaml",
      command: "npx",
      args: []
    });
    expect(entry).not.toHaveProperty("env");
  });
});
