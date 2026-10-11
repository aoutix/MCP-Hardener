import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApprovalStore, policyDigest } from "@hmcp/core";
import { buildProtection } from "../src/model/protection.js";
import { closeStores, loadServer } from "../src/model/server.js";
import { writeGatewayFixture, type GatewayFixture } from "./fixtures/gateway.js";

/**
 * Whether the console's reading of the gateway config is what a gateway is
 * applying.
 *
 * The console re-reads the file on every request; a running gateway parsed it
 * once at startup. Those two can disagree, and before this the page presented
 * its own fresher read as though it were what calls were being held to. What
 * these pin down is that the page only ever claims a policy is in force when a
 * live process has said it parsed that same policy.
 */

let dir: string;
let fixture: GatewayFixture;

function writeConfig(timeoutMs: number): void {
  fixture = writeGatewayFixture(dir, { egressLines: [`timeout_ms: ${timeoutMs}`] });
}

function protection() {
  // No tenant configured on this fixture, so the empty tenant is the only
  // correct scope — the same one `chooseTenant` settles on.
  return buildProtection(loadServer(fixture.entry), "");
}

/** Stands in for a running gateway announcing what it parsed. */
function announce(digest: string, lastSeen = Date.now()): void {
  const store = new ApprovalStore(fixture.storePath);
  store.recordRuntimeState({
    component: fixture.component,
    pid: 4242,
    started_at: lastSeen,
    last_seen: lastSeen,
    policy_digest: digest,
    policy_path: fixture.configPath
  });
  store.close();
}

/** The policy as the console currently reads it, for digesting in a test. */
function currentPolicy() {
  return loadServer(fixture.entry).policy;
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-runtime-state-"));
  writeConfig(8000);
});

afterEach(() => {
  closeStores();
  rmSync(dir, { recursive: true, force: true });
});

describe("whether the displayed policy is the enforced one", () => {
  it("says it does not know when no gateway is running", () => {
    // Not the same claim as "the file is not in force": with nothing running
    // there is nothing to be out of step with, and the page must not imply a
    // problem where there is none.
    const p = protection();
    expect(p.runtime.running).toBe(false);
    expect(p.runtime.policyApplied).toBeNull();
    expect(p.runtime.startedAt).toBeNull();
  });

  it("confirms the file is in force when a live gateway parsed this same policy", () => {
    announce(policyDigest(currentPolicy()));
    const p = protection();
    expect(p.runtime.running).toBe(true);
    expect(p.runtime.policyApplied).toBe(true);
    expect(p.egress.timeoutMs).toBe(8000);
  });

  it("reports the drift when the file has changed under a running gateway", () => {
    announce(policyDigest(currentPolicy()));
    writeConfig(9000);

    const p = protection();
    // The displayed number is the new one, which is the point: it is accurate
    // about the file and now says so rather than implying it is enforced.
    expect(p.egress.timeoutMs).toBe(9000);
    expect(p.runtime.running).toBe(true);
    expect(p.runtime.policyApplied).toBe(false);
  });

  it("is silent about a cosmetic edit that changes nothing enforced", () => {
    announce(policyDigest(currentPolicy()));
    // Same policy, rewritten: a leading comment and reordered keys.
    writeFileSync(
      fixture.configPath,
      [
        "# reviewed 2026-10-10",
        "version: 1",
        "name: notes",
        "upstreams:",
        "  - name: notes",
        "    transport: stdio",
        "    command: node",
        '    args: ["--version"]',
        "on_injection: strip",
        "namespace: false",
        "policy:",
        "  version: 1",
        "  egress:",
        "    timeout_ms: 8000",
        '    allow: ["api.example.com"]',
        "  defaults:",
        "    mode: read-only",
        "  rules:",
        "    - id: allow-reads",
        '      match: "get_*"',
        "      effect: read",
        "      decision: allow",
        "  approvals:",
        "    mode: cli",
        `    store_path: ${fixture.storePath}`,
        "  audit:",
        "    enabled: false",
        `    path: ${fixture.auditPath}`,
        ""
      ].join("\n")
    );
    expect(protection().runtime.policyApplied).toBe(true);
  });

  it("stops quoting a gateway that has stopped refreshing", () => {
    // A row left behind by a process that exited describes nothing that is
    // deciding calls, so it must not be read as either agreement or drift.
    announce(policyDigest(currentPolicy()), Date.now() - 60_000);
    const p = protection();
    expect(p.runtime.running).toBe(false);
    expect(p.runtime.policyApplied).toBeNull();
  });
});
