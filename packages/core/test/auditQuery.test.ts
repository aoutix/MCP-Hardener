import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appendFileSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, parsePolicy, queryAuditLog, readAuditLog, verifyAuditLog } from "../src/index.js";

let dir: string;
let logPath: string;

function makeLog(overrides: Record<string, unknown> = {}) {
  const policy = parsePolicy({ version: 1, audit: { path: logPath, ...overrides } });
  return new AuditLog({ config: policy.audit, actor: "tester", session: "sess-1", component: "test" });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-auditq-"));
  logPath = join(dir, "audit.jsonl");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("queryAuditLog", () => {
  it("returns nothing for a missing or empty log instead of throwing", () => {
    expect(queryAuditLog(join(dir, "absent.jsonl")).records).toHaveLength(0);
    writeFileSync(logPath, "");
    expect(queryAuditLog(logPath).records).toHaveLength(0);
    writeFileSync(logPath, "\n\n  \n");
    expect(queryAuditLog(logPath).records).toHaveLength(0);
  });

  it("returns the newest records first", () => {
    const log = makeLog();
    log.append({ tool: "first", decision: "allow", outcome: "completed" });
    log.append({ tool: "second", decision: "allow", outcome: "completed" });
    log.append({ tool: "third", decision: "allow", outcome: "completed" });

    const page = queryAuditLog(logPath);
    expect(page.records.map((r) => r.tool)).toEqual(["third", "second", "first"]);
  });

  it("pages backwards through the log, covering every record exactly once", () => {
    const log = makeLog();
    for (let i = 0; i < 25; i++) {
      log.append({ tool: `tool_${i}`, decision: "allow", outcome: "completed" });
    }

    const seen: number[] = [];
    let cursor: number | undefined;
    for (;;) {
      const page = queryAuditLog(logPath, { limit: 7, beforeSeq: cursor });
      seen.push(...page.records.map((r) => r.seq));
      if (page.nextCursor === null || page.records.length === 0) break;
      cursor = page.nextCursor;
    }

    expect(seen).toHaveLength(25);
    expect(new Set(seen).size).toBe(25);
    expect([...seen].sort((a, b) => a - b)).toEqual(Array.from({ length: 25 }, (_, i) => i));
  });

  it("skips a malformed line and keeps the records on either side of it", () => {
    const log = makeLog();
    log.append({ tool: "before", decision: "allow", outcome: "completed" });
    appendFileSync(logPath, "{this is not json\n");
    log.append({ tool: "after", decision: "allow", outcome: "completed" });

    const page = queryAuditLog(logPath);
    expect(page.records.map((r) => r.tool)).toEqual(["after", "before"]);
    expect(page.malformed).toBe(1);

    // The contrast that motivates this function existing at all: the old
    // reader loses the whole log to one torn line.
    expect(() => readAuditLog(logPath)).toThrow();
  });

  it("skips a torn trailing line, as a reader racing an append would see", () => {
    const log = makeLog();
    log.append({ tool: "complete", decision: "allow", outcome: "completed" });
    appendFileSync(logPath, '{"ts":"2026-01-01T00:00:00.000Z","seq":1,"to');

    const page = queryAuditLog(logPath);
    expect(page.records.map((r) => r.tool)).toEqual(["complete"]);
    expect(page.malformed).toBe(1);
  });

  it("filters by decision, outcome, component, actor and tool glob", () => {
    const log = makeLog();
    log.append({ tool: "get_pet", decision: "allow", outcome: "completed", effect: "read" });
    log.append({ tool: "delete_pet", decision: "deny", outcome: "denied", effect: "destructive" });
    log.append({ tool: "create_pet", decision: "approve", outcome: "pending-approval", effect: "write" });
    log.append({ tool: "get_store", decision: "allow", outcome: "error", component: "other", actor: "someone" });

    expect(queryAuditLog(logPath, { decision: ["deny"] }).records.map((r) => r.tool)).toEqual(["delete_pet"]);
    expect(queryAuditLog(logPath, { outcome: ["denied", "error"] }).records.map((r) => r.tool)).toEqual([
      "get_store",
      "delete_pet"
    ]);
    expect(queryAuditLog(logPath, { component: ["other"] }).records.map((r) => r.tool)).toEqual(["get_store"]);
    expect(queryAuditLog(logPath, { actor: ["someone"] }).records.map((r) => r.tool)).toEqual(["get_store"]);
    expect(queryAuditLog(logPath, { tool: "get_*" }).records.map((r) => r.tool)).toEqual(["get_store", "get_pet"]);
    expect(queryAuditLog(logPath, { tool: "{create,delete}_*" }).records).toHaveLength(2);
  });

  it("filters by an ISO time window", () => {
    const log = makeLog();
    const first = log.append({ tool: "early", decision: "allow", outcome: "completed" })!;
    const last = log.append({ tool: "late", decision: "allow", outcome: "completed" })!;

    expect(queryAuditLog(logPath, { since: last.ts }).records.map((r) => r.tool)).toContain("late");
    expect(queryAuditLog(logPath, { until: first.ts }).records.map((r) => r.tool)).toContain("early");
  });

  it("surfaces grant_id so administrative records can be told apart", () => {
    const log = makeLog();
    log.append({
      tool: "create_invoice",
      decision: "approve",
      outcome: "completed",
      rule_id: "standing_grant.create",
      grant_id: "sg_abc123"
    });
    log.append({ tool: "get_pet", decision: "allow", outcome: "completed" });

    const page = queryAuditLog(logPath);
    expect(page.records.find((r) => r.grant_id === "sg_abc123")).toBeDefined();
    expect(page.records.find((r) => r.tool === "get_pet")!.grant_id).toBeNull();
  });

  it("reads a record that straddles a chunk boundary", () => {
    const log = makeLog();
    // Comfortably longer than the smallest chunk the reader will use.
    const big = "x".repeat(200_000);
    log.append({ tool: "huge", decision: "allow", outcome: "completed", reason: big });
    log.append({ tool: "after_huge", decision: "allow", outcome: "completed" });

    const page = queryAuditLog(logPath, { limit: 10 });
    expect(page.records.map((r) => r.tool)).toEqual(["after_huge", "huge"]);
    expect(page.records[1]!.reason).toHaveLength(big.length);
  });

  it("decodes a multi-byte character split across two reads", () => {
    const log = makeLog();
    // Pad so the emoji is very unlikely to land on a 64KiB boundary by luck,
    // then assert it survives however the chunking falls.
    log.append({ tool: "unicode", decision: "allow", outcome: "completed", reason: `${"é".repeat(40_000)}🔐` });
    const page = queryAuditLog(logPath);
    expect(page.records[0]!.reason.endsWith("🔐")).toBe(true);
  });

  it("costs far less than the size of the log", () => {
    const log = makeLog();
    for (let i = 0; i < 2000; i++) {
      log.append({ tool: `tool_${i}`, decision: "allow", outcome: "completed", reason: "x".repeat(200) });
    }
    const size = statSync(logPath).size;
    const page = queryAuditLog(logPath, { limit: 20 });

    expect(page.records).toHaveLength(20);
    // The performance claim is a test rather than a comment: a bounded page
    // must not pay for the whole file.
    expect(page.scanned).toBeLessThan(200);
    expect(size).toBeGreaterThan(300_000);
  });

  it("caps the limit so a client cannot ask for the whole log", () => {
    const log = makeLog();
    for (let i = 0; i < 5; i++) log.append({ tool: `t${i}`, decision: "allow", outcome: "completed" });
    expect(queryAuditLog(logPath, { limit: 10_000 }).records).toHaveLength(5);
    expect(queryAuditLog(logPath, { limit: 0 }).records).toHaveLength(1);
  });

  it("leaves the chain verifiable after an out-of-band append, as the console makes", () => {
    const server = makeLog();
    server.append({ tool: "get_pet", decision: "allow", outcome: "completed" });

    // A second AuditLog on the same file, the way the web backend appends.
    const console_ = makeLog();
    console_.appendStrict({
      tool: "create_invoice",
      decision: "approve",
      outcome: "completed",
      rule_id: "standing_grant.create",
      grant_id: "sg_deadbeef",
      component: "hmcp-web"
    });
    server.append({ tool: "get_pet", decision: "allow", outcome: "completed" });

    const verified = verifyAuditLog(logPath);
    expect(verified.problems).toEqual([]);
    expect(verified.ok).toBe(true);
    expect(verified.count).toBe(3);
    expect(queryAuditLog(logPath).records.map((r) => r.seq)).toEqual([2, 1, 0]);
  });
});

describe("filtering by tenant", () => {
  it("reads one customer's history out of a log that holds everyone's", () => {
    // The hash chain is per file, so a hosted gateway interleaves every
    // tenant's records in one log. This filter is the only way back out.
    const log = makeLog();
    log.append({ tool: "create_invoice", decision: "allow", outcome: "completed", tenant: "acme" });
    log.append({ tool: "create_invoice", decision: "allow", outcome: "completed", tenant: "globex" });
    log.append({ tool: "list_invoices", decision: "allow", outcome: "completed", tenant: "acme" });

    const acme = queryAuditLog(logPath, { tenant: ["acme"] });
    expect(acme.records.map((r) => r.tool)).toEqual(["list_invoices", "create_invoice"]);
    expect(acme.records.every((r) => r.tenant === "acme")).toBe(true);

    expect(queryAuditLog(logPath, { tenant: ["globex"] }).records).toHaveLength(1);
    expect(queryAuditLog(logPath, { tenant: ["acme", "globex"] }).records).toHaveLength(3);
  });

  it('treats a record with no tenant as ""', () => {
    // A single-tenant deployment records null, and so does every record
    // written before the field was populated; neither should be unreachable.
    const log = makeLog();
    log.append({ tool: "list_invoices", decision: "allow", outcome: "completed" });

    expect(queryAuditLog(logPath, { tenant: [""] }).records).toHaveLength(1);
    expect(queryAuditLog(logPath, { tenant: ["acme"] }).records).toHaveLength(0);
  });
});
