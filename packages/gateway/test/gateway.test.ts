import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parsePolicy } from "@hmcp/core";
import { classify } from "../src/classify.js";
import { GatewayConfigSchema, loadGatewayConfig } from "../src/config.js";
import type { UpstreamTool } from "../src/upstream.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-gw-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function tool(overrides: Partial<UpstreamTool> = {}): UpstreamTool {
  return { name: "get_note", description: "Fetch a note.", inputSchema: { type: "object" }, annotations: undefined, ...overrides };
}

const basePolicy = parsePolicy({ version: 1 });

describe("effect classification", () => {
  it("prefers a policy rule over everything else", () => {
    const policy = parsePolicy({
      version: 1,
      rules: [{ id: "r", match: "notes__delete_note", effect: "read", decision: "allow" }]
    });
    const result = classify(tool({ name: "delete_note" }), "notes__delete_note", policy);
    expect(result).toEqual({ effect: "read", source: "policy" });
  });

  it("infers from the name when nothing else says", () => {
    expect(classify(tool({ name: "get_note" }), "notes__get_note", basePolicy).effect).toBe("read");
    expect(classify(tool({ name: "create_note" }), "notes__create_note", basePolicy).effect).toBe("write");
    expect(classify(tool({ name: "delete_note" }), "notes__delete_note", basePolicy).effect).toBe("destructive");
    expect(classify(tool({ name: "purge_all" }), "notes__purge_all", basePolicy).effect).toBe("destructive");
  });

  it("leaves an unrecognizable tool unclassified, which the posture then refuses", () => {
    const result = classify(tool({ name: "frobnicate" }), "notes__frobnicate", basePolicy);
    expect(result.effect).toBeUndefined();
    expect(result.source).toBe("unclassified");
  });

  it("accepts a readOnlyHint only when the name does not contradict it", () => {
    const honest = classify(
      tool({ name: "get_note", annotations: { readOnlyHint: true } }),
      "notes__get_note",
      basePolicy
    );
    expect(honest).toEqual({ effect: "read", source: "annotation" });

    // A server cannot mark its own delete tool read-only to slip past the
    // read-only posture.
    const lying = classify(
      tool({ name: "delete_note", annotations: { readOnlyHint: true } }),
      "notes__delete_note",
      basePolicy
    );
    expect(lying.effect).toBe("destructive");
    expect(lying.source).toBe("name");
  });

  it("believes a server that admits it mutates, and takes the worse reading", () => {
    expect(
      classify(tool({ name: "frobnicate", annotations: { readOnlyHint: false } }), "notes__frobnicate", basePolicy)
        .effect
    ).toBe("write");
    expect(
      classify(tool({ name: "delete_note", annotations: { readOnlyHint: false } }), "notes__delete_note", basePolicy)
        .effect
    ).toBe("destructive");
  });

  it("honors a destructiveHint outright", () => {
    expect(
      classify(tool({ name: "frobnicate", annotations: { destructiveHint: true } }), "notes__frobnicate", basePolicy)
        .effect
    ).toBe("destructive");
  });
});

describe("config", () => {
  it("rejects an upstream name that would break namespacing", () => {
    const result = GatewayConfigSchema.safeParse({
      version: 1,
      policy: { version: 1 },
      upstreams: [{ name: "Notes Server", transport: "stdio", command: "node" }]
    });
    expect(result.success).toBe(false);
  });

  it("rejects duplicate upstream names", () => {
    const result = GatewayConfigSchema.safeParse({
      version: 1,
      policy: { version: 1 },
      upstreams: [
        { name: "notes", transport: "stdio", command: "a" },
        { name: "notes", transport: "stdio", command: "b" }
      ]
    });
    expect(result.success).toBe(false);
  });

  it("defaults to stripping injected descriptions and namespacing tools", () => {
    const result = GatewayConfigSchema.parse({
      version: 1,
      policy: { version: 1 },
      upstreams: [{ name: "notes", transport: "stdio", command: "node" }]
    });
    expect(result.on_injection).toBe("strip");
    expect(result.namespace).toBe(true);
  });

  it("passes no environment to a child process unless asked", () => {
    const result = GatewayConfigSchema.parse({
      version: 1,
      policy: { version: 1 },
      upstreams: [{ name: "notes", transport: "stdio", command: "node" }]
    });
    const upstream = result.upstreams[0]!;
    expect(upstream.transport).toBe("stdio");
    if (upstream.transport !== "stdio") return;
    expect(upstream.env).toEqual({});
    expect(upstream.pass_env).toEqual([]);
  });

  it("loads an inline policy and a referenced one alike", () => {
    writeFileSync(
      join(dir, "policy.yaml"),
      "version: 1\ndefaults:\n  mode: locked\negress:\n  allow: [api.example.com]\n"
    );
    writeFileSync(
      join(dir, "gateway.yaml"),
      `version: 1\npolicy: ./policy.yaml\nupstreams:\n  - name: notes\n    transport: stdio\n    command: node\n`
    );
    const loaded = loadGatewayConfig(join(dir, "gateway.yaml"));
    expect(loaded.policy.defaults.mode).toBe("locked");
    expect(loaded.config.upstreams).toHaveLength(1);
  });

  it("reports an invalid config with the offending path", () => {
    writeFileSync(join(dir, "bad.yaml"), "version: 1\nupstreams: []\n");
    expect(() => loadGatewayConfig(join(dir, "bad.yaml"))).toThrow(/invalid gateway config/);
  });
});
