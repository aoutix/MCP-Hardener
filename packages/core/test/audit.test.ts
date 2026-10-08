import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, parsePolicy, readAuditLog, verifyAuditLog, GENESIS_HASH } from "../src/index.js";

let dir: string;
let logPath: string;

function makeLog(overrides: Record<string, unknown> = {}) {
  const policy = parsePolicy({ version: 1, audit: { path: logPath, ...overrides } });
  return new AuditLog({ config: policy.audit, actor: "tester", session: "sess-1", component: "test" });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-audit-"));
  logPath = join(dir, "audit.jsonl");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("append", () => {
  it("writes one record per call with an incrementing sequence", () => {
    const log = makeLog();
    log.append({ tool: "get_pet", decision: "allow", outcome: "completed", effect: "read" });
    log.append({ tool: "delete_pet", decision: "deny", outcome: "denied", effect: "destructive" });

    const records = readAuditLog(logPath);
    expect(records).toHaveLength(2);
    expect(records.map((r) => r.seq)).toEqual([0, 1]);
    expect(records[0]!.prev_hash).toBe(GENESIS_HASH);
    expect(records[1]!.prev_hash).toBe(records[0]!.hash);
  });

  it("records the deciding rule and the outcome, not just the fact of a call", () => {
    const log = makeLog();
    log.append({
      tool: "create_invoice",
      decision: "deny",
      outcome: "denied",
      effect: "write",
      rule_id: "defaults.mode",
      reason: "read-only posture refuses write tools",
      upstream: { host: "api.example.com", method: "POST", path: "/invoices", status: null, bytes: null }
    });
    const [record] = readAuditLog(logPath);
    expect(record!.rule_id).toBe("defaults.mode");
    expect(record!.outcome).toBe("denied");
    expect(record!.upstream?.host).toBe("api.example.com");
  });

  it("redacts secrets out of arguments before they reach disk", () => {
    const log = makeLog();
    const { args_hash, args_redacted } = log.prepareArgs({
      customer: "acme",
      api_key: "sk_live_abcdefghijklmnopqrst",
      note: "token is ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });
    log.append({ tool: "t", decision: "allow", outcome: "completed", args_hash, args_redacted });

    const raw = readFileSync(logPath, "utf8");
    expect(raw).not.toContain("sk_live_abcdefghijklmnopqrst");
    expect(raw).not.toContain("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    expect(raw).toContain("acme");

    const [record] = readAuditLog(logPath);
    expect(record!.args_redacted!["api_key"]).toBe("[redacted:key]");
    expect(record!.args_redacted!["note"]).toBe("[redacted:github-token]");
    // The hash still commits to the real arguments, so the record is verifiable
    // against a replay without storing the secret.
    expect(args_hash).toHaveLength(64);
  });

  it("can hash arguments without recording them at all", () => {
    const log = makeLog({ record_args: false });
    const { args_hash, args_redacted } = log.prepareArgs({ customer: "acme" });
    log.append({ tool: "t", decision: "allow", outcome: "completed", args_hash, args_redacted });
    const [record] = readAuditLog(logPath);
    expect(record!.args_redacted).toBeNull();
    expect(record!.args_hash).toBe(args_hash);
  });

  it("writes nothing when auditing is disabled", () => {
    const log = makeLog({ enabled: false });
    expect(log.append({ tool: "t", decision: "allow", outcome: "completed" })).toBeNull();
    expect(readAuditLog(logPath)).toEqual([]);
  });

  it("creates the log with owner-only permissions", () => {
    const log = makeLog();
    log.append({ tool: "t", decision: "allow", outcome: "completed" });
    expect(statSync(logPath).mode & 0o077).toBe(0);
  });
});

describe("verify", () => {
  function seed(count = 3) {
    const log = makeLog();
    for (let i = 0; i < count; i++) {
      log.append({ tool: `tool_${i}`, decision: "allow", outcome: "completed", effect: "read" });
    }
  }

  it("passes on an untouched log", () => {
    seed();
    const result = verifyAuditLog(logPath);
    expect(result.ok).toBe(true);
    expect(result.count).toBe(3);
    expect(result.problems).toEqual([]);
  });

  it("fails when a record's contents are edited", () => {
    seed();
    const lines = readFileSync(logPath, "utf8").trimEnd().split("\n");
    const tampered = JSON.parse(lines[1]!);
    tampered.decision = "allow";
    tampered.tool = "something_else";
    lines[1] = JSON.stringify(tampered);
    writeFileSync(logPath, lines.join("\n") + "\n");

    const result = verifyAuditLog(logPath);
    expect(result.ok).toBe(false);
    expect(result.problems.some((p) => p.line === 2 && /record altered/.test(p.message))).toBe(true);
  });

  it("fails when a record is removed", () => {
    seed();
    const lines = readFileSync(logPath, "utf8").trimEnd().split("\n");
    writeFileSync(logPath, [lines[0], lines[2]].join("\n") + "\n");

    const result = verifyAuditLog(logPath);
    expect(result.ok).toBe(false);
    expect(result.problems.some((p) => /sequence gap/.test(p.message))).toBe(true);
    expect(result.problems.some((p) => /chain break/.test(p.message))).toBe(true);
  });

  it("fails when records are reordered", () => {
    seed();
    const lines = readFileSync(logPath, "utf8").trimEnd().split("\n");
    writeFileSync(logPath, [lines[0], lines[2], lines[1]].join("\n") + "\n");
    expect(verifyAuditLog(logPath).ok).toBe(false);
  });

  it("fails when a record is appended without a valid chain link", () => {
    seed();
    const forged = {
      ts: new Date().toISOString(),
      seq: 3,
      id: "forged",
      actor: "attacker",
      session: "x",
      component: "test",
      tool: "delete_everything",
      effect: "destructive",
      decision: "allow",
      rule_id: "none",
      reason: "",
      tenant: null,
      args_hash: "",
      args_redacted: null,
      upstream: null,
      outcome: "completed",
      error: null,
      duration_ms: null,
      approval_id: null,
      prev_hash: GENESIS_HASH,
      hash: "0".repeat(64)
    };
    writeFileSync(logPath, readFileSync(logPath, "utf8") + JSON.stringify(forged) + "\n");
    const result = verifyAuditLog(logPath);
    expect(result.ok).toBe(false);
    expect(result.problems.some((p) => /chain break|record altered/.test(p.message))).toBe(true);
  });

  it("reports a missing log rather than silently passing", () => {
    const result = verifyAuditLog(join(dir, "nope.jsonl"));
    expect(result.ok).toBe(false);
    expect(result.problems[0]!.message).toMatch(/no audit log/);
  });
});

describe("concurrent appends", () => {
  it("keeps the chain intact when two logs share one file", () => {
    const a = makeLog();
    const b = makeLog();
    for (let i = 0; i < 10; i++) {
      (i % 2 === 0 ? a : b).append({ tool: `t${i}`, decision: "allow", outcome: "completed", effect: "read" });
    }
    const result = verifyAuditLog(logPath);
    expect(result.ok).toBe(true);
    expect(result.count).toBe(10);
  });
});
