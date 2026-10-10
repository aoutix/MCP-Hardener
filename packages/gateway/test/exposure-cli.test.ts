import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ApprovalStore, readAuditLog, verifyAuditLog } from "@hmcp/core";
import { ExposureCommandError, runExposureCommand } from "../src/exposure-cli.js";

/**
 * The operator's switch.
 *
 * The admin API serves a customer of a hosted gateway; this serves the person
 * who owns the machine, including in the two cases the API cannot — a gateway
 * with no identity provider, and the incident where the identity provider is
 * the thing that is down.
 */

const UPSTREAM = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "mock-upstream.mjs");

let dir: string;
let configPath: string;
let out: string[];
const write = (line: string) => out.push(line);

function writeConfig(tenantBlock: string): void {
  writeFileSync(
    configPath,
    [
      "version: 1",
      "name: test-gateway",
      "upstreams:",
      "  - name: notes",
      "    transport: stdio",
      "    command: " + JSON.stringify(process.execPath),
      "    args:",
      "      - " + JSON.stringify(UPSTREAM),
      "policy:",
      "  version: 1",
      "  defaults:",
      "    mode: read-only",
      ...tenantBlock.split("\n").filter(Boolean),
      "  approvals:",
      "    store_path: " + JSON.stringify(join(dir, "approvals.sqlite")),
      "  audit:",
      "    path: " + JSON.stringify(join(dir, "audit.jsonl")),
      ""
    ].join("\n")
  );
}

const JWT_TENANT = `  tenant:
    field: org_id
    inject: []
    source:
      kind: jwt-verified
      claim: org_id
      public_key: "-----BEGIN PUBLIC KEY-----\\nnot-used-here\\n-----END PUBLIC KEY-----"
      issuer: https://issuer.test
      audience: hmcp-gateway`;

function rows(tenant: string) {
  const store = new ApprovalStore(join(dir, "approvals.sqlite"));
  const found = store.scoped({ component: "gateway:test-gateway", tenant }).listDisabledTools();
  store.close();
  return found;
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hmcp-expcli-"));
  configPath = join(dir, "gateway.yaml");
  out = [];
});

afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("a gateway whose tenant comes from each caller's token", () => {
  it("refuses to guess whose switch is meant", async () => {
    // Writing under "" while the running gateway reads under "acme" would
    // look exactly like protection and be none.
    writeConfig(JWT_TENANT);
    await expect(runExposureCommand({ config: configPath, action: "off", tool: "notes__get_note", write })).rejects.toThrow(
      ExposureCommandError
    );
    await expect(
      runExposureCommand({ config: configPath, action: "off", tool: "notes__get_note", write })
    ).rejects.toThrow(/--tenant/);
  });

  it("writes under the same key the gateway reads", async () => {
    writeConfig(JWT_TENANT);
    await runExposureCommand({
      config: configPath,
      action: "off",
      tool: "notes__get_note",
      tenant: "  Acme  ",
      reason: "incident 412",
      write
    });
    // Normalized on the way in, exactly as the HTTP path normalizes the claim.
    expect(rows("Acme").map((r) => r.tool)).toEqual(["notes__get_note"]);
    expect(rows("  Acme  ")).toEqual([]);
    expect(rows("")).toEqual([]);
  });
});

describe("flipping the switch", () => {
  it("records who did it, with the operator's own name", async () => {
    writeConfig("");
    await runExposureCommand({
      config: configPath,
      action: "off",
      tool: "notes__get_note",
      reason: "incident 412",
      write
    });

    expect(rows("").map((r) => r.tool)).toEqual(["notes__get_note"]);
    const record = readAuditLog(join(dir, "audit.jsonl")).find((r) => r.rule_id === "exposure.disable");
    // The CLI used to write no audit record at all for anything.
    expect(record?.reason).toContain("the gateway CLI");
    expect(record?.actor).not.toMatch(/^token:/);
    expect(record?.component).toBe("gateway:test-gateway");
    expect(verifyAuditLog(join(dir, "audit.jsonl")).ok).toBe(true);
  });

  it("hands it back, and says so when nothing changed", async () => {
    writeConfig("");
    await runExposureCommand({ config: configPath, action: "off", tool: "notes__get_note", write });
    out = [];
    await runExposureCommand({ config: configPath, action: "on", tool: "notes__get_note", write });
    expect(rows("")).toEqual([]);
    expect(out.join("\n")).toContain("handed back to policy");

    out = [];
    await runExposureCommand({ config: configPath, action: "on", tool: "notes__get_note", write });
    expect(out.join("\n")).toContain("nothing changed");
  });

  it("refuses a tool this gateway does not expose", async () => {
    writeConfig("");
    await expect(
      runExposureCommand({ config: configPath, action: "off", tool: "notes__nope", write })
    ).rejects.toThrow(/exposes no tool named/);
    expect(rows("")).toEqual([]);
  });

  it("takes the name on trust under --force, and says it is doing so", async () => {
    // The upstream may be the broken thing; starting it to flip a bit is the
    // wrong trade during an incident.
    writeConfig("");
    await runExposureCommand({
      config: configPath,
      action: "off",
      tool: "notes__whatever_the_name_is",
      force: true,
      write
    });
    expect(out.join("\n")).toContain("taken on trust");
    expect(rows("").map((r) => r.tool)).toEqual(["notes__whatever_the_name_is"]);
  });

  it("lists what is off", async () => {
    writeConfig("");
    await runExposureCommand({ config: configPath, action: "off", tool: "notes__get_note", reason: "r", write });
    out = [];
    await runExposureCommand({ config: configPath, action: "list", json: true, write });
    const parsed = JSON.parse(out.join("\n"));
    expect(parsed.disabled.map((d: { tool: string }) => d.tool)).toEqual(["notes__get_note"]);
  });
});
