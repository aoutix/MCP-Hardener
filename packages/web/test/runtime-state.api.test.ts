import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApprovalStore, policyDigest } from "@hmcp/core";
import { buildProtection } from "../src/model/protection.js";
import { closeStores, loadServer } from "../src/model/server.js";

/**
 * Whether the console's reading of `policy.yaml` is what a server is applying.
 *
 * The console re-reads the file on every request; a running server parsed it
 * once at startup. Those two can disagree, and before this the page presented
 * its own fresher read as though it were what calls were being held to. What
 * these pin down is that the page only ever claims a policy is in force when a
 * live process has said it parsed that same policy.
 */

const TOOLS = {
  version: 1,
  api: { title: "Billing", version: "1.0.0", base_url: "https://api.example.com" },
  auth: { kind: "none" },
  tools: [
    {
      name: "list_invoices",
      description: "List invoices.",
      effect: "read",
      method: "GET",
      path: "/invoices",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      bindings: {},
      bodyMode: "none",
      tenantParams: [],
      annotations: { readOnlyHint: true }
    }
  ]
};

const COMPONENT = "generated:Billing";

let dir: string;
let serverDir: string;
let storePath: string;

function writePolicy(timeoutMs: number): void {
  writeFileSync(
    join(serverDir, "policy.yaml"),
    [
      "version: 1",
      "defaults:",
      "  mode: read-only",
      "rules:",
      "  - id: allow-reads",
      '    match: "list_*"',
      "    effect: read",
      "    decision: allow",
      "egress:",
      '  allow: ["api.example.com"]',
      `  timeout_ms: ${timeoutMs}`,
      "approvals:",
      "  mode: cli",
      `  store_path: ${storePath}`,
      "audit:",
      "  enabled: false",
      ""
    ].join("\n")
  );
}

function protection() {
  return buildProtection(
    loadServer({
      id: "srv",
      kind: "generated",
      label: "S",
      dir: serverDir,
      added_at: new Date().toISOString()
    } as Parameters<typeof loadServer>[0])
  );
}

/** Stands in for a running server announcing what it parsed. */
function announce(digest: string, lastSeen = Date.now()): void {
  const store = new ApprovalStore(storePath);
  store.recordRuntimeState({
    component: COMPONENT,
    pid: 4242,
    started_at: lastSeen,
    last_seen: lastSeen,
    policy_digest: digest,
    policy_path: join(serverDir, "policy.yaml")
  });
  store.close();
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-runtime-state-"));
  serverDir = join(dir, "srv");
  storePath = join(dir, "approvals.sqlite");
  mkdirSync(serverDir, { recursive: true });
  writeFileSync(join(serverDir, "tools.json"), JSON.stringify(TOOLS));
  writePolicy(8000);
});

afterEach(() => {
  closeStores();
  rmSync(dir, { recursive: true, force: true });
});

describe("whether the displayed policy is the enforced one", () => {
  it("says it does not know when no server is running", () => {
    // Not the same claim as "the file is not in force": with nothing running
    // there is nothing to be out of step with, and the page must not imply a
    // problem where there is none.
    const p = protection();
    expect(p.runtime.running).toBe(false);
    expect(p.runtime.policyApplied).toBeNull();
    expect(p.runtime.startedAt).toBeNull();
  });

  it("confirms the file is in force when a live server parsed this same policy", () => {
    announce(policyDigest(protection_policy()));
    const p = protection();
    expect(p.runtime.running).toBe(true);
    expect(p.runtime.policyApplied).toBe(true);
    expect(p.egress.timeoutMs).toBe(8000);
  });

  it("reports the drift when the file has changed under a running server", () => {
    announce(policyDigest(protection_policy()));
    writePolicy(9000);

    const p = protection();
    // The displayed number is the new one, which is the point: it is accurate
    // about the file and now says so rather than implying it is enforced.
    expect(p.egress.timeoutMs).toBe(9000);
    expect(p.runtime.running).toBe(true);
    expect(p.runtime.policyApplied).toBe(false);
  });

  it("is silent about a cosmetic edit that changes nothing enforced", () => {
    announce(policyDigest(protection_policy()));
    // Same policy, rewritten: a trailing comment and reordered keys.
    writeFileSync(
      join(serverDir, "policy.yaml"),
      [
        "# reviewed 2026-10-10",
        "version: 1",
        "egress:",
        `  timeout_ms: 8000`,
        '  allow: ["api.example.com"]',
        "defaults:",
        "  mode: read-only",
        "rules:",
        "  - id: allow-reads",
        '    match: "list_*"',
        "    effect: read",
        "    decision: allow",
        "approvals:",
        "  mode: cli",
        `  store_path: ${storePath}`,
        "audit:",
        "  enabled: false",
        ""
      ].join("\n")
    );
    expect(protection().runtime.policyApplied).toBe(true);
  });

  it("stops quoting a server that has stopped refreshing", () => {
    // A row left behind by a process that exited describes nothing that is
    // deciding calls, so it must not be read as either agreement or drift.
    announce(policyDigest(protection_policy()), Date.now() - 60_000);
    const p = protection();
    expect(p.runtime.running).toBe(false);
    expect(p.runtime.policyApplied).toBeNull();
  });
});

/** The policy as the console currently reads it, for digesting in a test. */
function protection_policy() {
  return loadServer({
    id: "srv",
    kind: "generated",
    label: "S",
    dir: serverDir,
    added_at: new Date().toISOString()
  } as Parameters<typeof loadServer>[0]).policy;
}
