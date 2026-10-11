import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { parsePolicy, readAuditLog } from "@hmcp/core";
import { GatewayConfigSchema } from "../src/config.js";
import { Gateway } from "../src/gateway.js";
import { displayKey, toolNameProblem } from "../src/toolname.js";

/**
 * An upstream tool name is a storage key, not a label.
 *
 * The exposure switch, every approval row and `bindingHash` are stored under
 * it, and an operator reads it to decide what to switch off. So two names a
 * human cannot tell apart but the database can are the one failure the kill
 * switch cannot survive: switching one off leaves the other live, callable,
 * and reported as off. `normalizeTenantKey` refuses this class of thing for
 * tenants; names arriving from a server we do not control need it more.
 */

const HOSTILE = resolve(import.meta.dirname, "./fixtures/hostile-names.mjs");

describe("whether a name can be used at all", () => {
  it("accepts the conventions upstreams actually use", () => {
    for (const name of ["get_note", "get-note", "getNote", "get.note", "記録を取得", "v2_get_note"]) {
      expect(toolNameProblem(name), name).toBeUndefined();
    }
  });

  it.each([
    ["a zero-width space", "get_note​"],
    ["a soft hyphen", "get­note"],
    ["a right-to-left override", "get_‮noted_eteled"],
    ["a terminal escape", "delete_all\u001b[2J"],
    ["a byte-order mark", "﻿get_note"],
    ["a bidi isolate", "get⁦note"]
  ])("refuses %s, which a reviewer cannot see", (_what, name) => {
    expect(toolNameProblem(name)).toMatch(/cannot see/);
  });

  it("refuses a decomposed name, which could be written a second way", () => {
    // "é" as e + combining acute. It renders identically to the composed form
    // and would be stored under a different key.
    expect(toolNameProblem("créer_note")).toMatch(/NFC/);
    expect(toolNameProblem("créer_note")).toBeUndefined();
  });

  it("refuses an empty, overlong or space-padded name", () => {
    expect(toolNameProblem("")).toMatch(/empty/);
    expect(toolNameProblem("a".repeat(129))).toMatch(/maximum/);
    expect(toolNameProblem(" get_note")).toMatch(/whitespace/);
  });

  it("treats separators and case as indistinguishable for a reviewer", () => {
    // Each of these is readable alone. None should sit next to another in a
    // list a human is about to act on.
    const keys = ["get_note", "get-note", "getNote", "GET.NOTE", "get note"].map(displayKey);
    expect(new Set(keys).size).toBe(1);
    expect(displayKey("get_note")).not.toBe(displayKey("get_notes"));
  });
});

describe("a live upstream that attacks through its tool names", () => {
  let dir: string;
  let gateway: Gateway;
  let client: Client;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), "hmcp-toolname-"));
    gateway = new Gateway({
      config: GatewayConfigSchema.parse({
        version: 1,
        name: "test-gateway",
        policy: { version: 1 },
        namespace: false,
        upstreams: [{ name: "hostile", transport: "stdio", command: process.execPath, args: [HOSTILE] }]
      }),
      policy: parsePolicy({
        version: 1,
        defaults: { mode: "read-only" },
        rules: [{ id: "reads", match: "get*", effect: "read", decision: "allow" }],
        approvals: { mode: "cli", store_path: join(dir, "approvals.sqlite") },
        audit: { enabled: true, path: join(dir, "audit.jsonl"), hash_chain: true },
        egress: { allow: ["example.com"] }
      }),
      cwd: dir
    });

    const [a, b] = InMemoryTransport.createLinkedPair();
    await gateway.start(a);
    client = new Client({ name: "test", version: "0" });
    await client.connect(b);
  });

  afterEach(async () => {
    await client.close().catch(() => undefined);
    await gateway.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("exposes exactly one tool per name a reviewer can read", async () => {
    const names = (await client.listTools()).tools.map((t) => t.name);
    // The honest one survives; the four that are unreadable or indistinguishable
    // from it do not.
    expect(names).toEqual(["get_note"]);
  });

  it("refuses the lookalike identically to a tool that does not exist", async () => {
    // The point of withholding rather than hiding: probing must not reveal
    // that the upstream advertised it.
    const lookalike = await client.callTool({ name: "get_note​", arguments: { id: "n1" } });
    const absent = await client.callTool({ name: "no_such_tool", arguments: {} });
    const text = (r: unknown) => ((r as { content: { text: string }[] }).content[0]?.text ?? "").replace(/".*"/, '"X"');
    expect(text(lookalike)).toBe(text(absent));
    expect(lookalike.isError).toBe(true);
  });

  it("records why each one was withheld, so the operator is not left guessing", () => {
    const records = readAuditLog(join(dir, "audit.jsonl")).filter(
      (r) => r.rule_id === "gateway.unusable-tool-name"
    );
    expect(records).toHaveLength(4);
    expect(records.every((r) => r.decision === "deny" && r.outcome === "denied")).toBe(true);

    const reasons = records.map((r) => r.reason).join("\n");
    expect(reasons).toMatch(/cannot see/);
    expect(reasons).toMatch(/could not tell it apart from "get_note"/);
    // And the record itself does not carry a live escape sequence into
    // whatever reads the log.
    expect(reasons).not.toContain("\u001b");
  });

  it("never reaches the upstream for a withheld name", async () => {
    await client.callTool({ name: "delete_all\u001b[2J\u001b[1;1H", arguments: { id: "n1" } }).catch(() => undefined);
    const ran = readAuditLog(join(dir, "audit.jsonl")).filter((r) => r.outcome === "completed");
    expect(ran).toHaveLength(0);
  });
});
