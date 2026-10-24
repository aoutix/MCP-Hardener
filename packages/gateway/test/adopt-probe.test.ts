import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runAdoptCommand } from "../src/adopt-cli.js";

/**
 * The report, against real upstreams.
 *
 * This is the half of adoption that decides whether anyone trusts the other
 * half. The mock upstream advertises, on purpose, a tool nothing can classify,
 * a delete tool that claims to be read-only, and a description carrying an
 * injection payload; the hostile fixture advertises names the gateway will not
 * pass on at all. All four have to appear in the report, because each one is a
 * way the agent's tools quietly change when the gateway goes in.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const MOCK = join(FIXTURES, "mock-upstream.mjs");
const HOSTILE = join(FIXTURES, "hostile-names.mjs");

let root: string;
let home: string;
let project: string;
let out: string[];

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "hmcp-probe-"));
  home = join(root, "home");
  project = join(root, "project");
  mkdirSync(home, { recursive: true });
  mkdirSync(project, { recursive: true });
  out = [];
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function writeProject(servers: Record<string, unknown>): void {
  writeFileSync(join(project, ".mcp.json"), JSON.stringify({ mcpServers: servers }, null, 2));
}

function stdio(script: string): Record<string, unknown> {
  return { command: process.execPath, args: [script] };
}

async function adopt(extra: Record<string, unknown> = {}): Promise<string> {
  await runAdoptCommand({
    cwd: project,
    home,
    scope: "project",
    registry: join(root, "servers.json"),
    write: (line) => out.push(line),
    ...extra
  });
  return out.join("\n");
}

describe("the probe report", () => {
  it("lists every tool with how it was classified and from what", async () => {
    writeProject({ notes: stdio(MOCK) });
    const report = await adopt();
    expect(report).toMatch(/notes__get_note\s+read\s+\(name\)/);
    expect(report).toMatch(/notes__create_note\s+write\s+\(name\)/);
  });

  it("names the tools that will be refused, and why", async () => {
    writeProject({ notes: stdio(MOCK) });
    const report = await adopt();
    expect(report).toMatch(/WILL BE REFUSED/);
    expect(report).toMatch(/notes__frobnicate/);
    expect(report).toMatch(/on_unclassified: deny/);
  });

  it("does not believe a server that marks its own delete tool read-only", async () => {
    writeProject({ notes: stdio(MOCK) });
    const report = await adopt();
    // The annotation says read-only; the name says otherwise, and the name wins.
    expect(report).toMatch(/notes__delete_note\s+destructive\s+\(name\)/);
  });

  it("reports an injection in an upstream description and what was done about it", async () => {
    writeProject({ notes: stdio(MOCK) });
    const report = await adopt();
    expect(report).toMatch(/INJECTION FOUND/);
    expect(report).toMatch(/notes__summarize_inbox: .*-> strip/);
  });

  it("lists the writes that will wait for a human", async () => {
    writeProject({ notes: stdio(MOCK) });
    const report = await adopt();
    expect(report).toMatch(/WILL ASK FOR APPROVAL/);
    expect(report).toMatch(/hmcp approve/);
  });

  it("refuses the writes instead under a read-only posture", async () => {
    writeProject({ notes: stdio(MOCK) });
    const report = await adopt({ posture: "read-only" });
    expect(report).toMatch(/WILL BE REFUSED -- \d+ tool\(s\) that mutate state/);
    expect(report).not.toMatch(/WILL ASK FOR APPROVAL/);
  });

  it("reports a tool it will not pass on, rather than letting it vanish", async () => {
    // These are absent from the inventory by design -- they were never
    // registered -- so without being asked for separately they would simply
    // not appear, which reads as the gateway having broken the server.
    writeProject({ hostile: stdio(HOSTILE) });
    const report = await adopt();
    expect(report).toMatch(/WITHHELD/);
    expect(report).toMatch(/refused as though it did not\n?\s*exist/);
  });

  it("labels a tool_budget finding as advisory, and says nothing when there is none", async () => {
    // Nothing in the gateway enforces the budget, so the note must not read as
    // a thing that will refuse a call -- and must not appear when the finding
    // it explains did not fire.
    writeProject({ notes: stdio(MOCK) });
    const report = await adopt();
    // Six tools against the default budget of 40, so the finding does not fire
    // and the explanation of it has nothing to explain.
    expect(report).not.toMatch(/against a budget of/);
    expect(report).not.toMatch(/tool_budget finding/);
  });

  it("says the probe starts the servers, rather than claiming a free dry run", async () => {
    writeProject({ notes: stdio(MOCK) });
    const report = await adopt();
    expect(report).toMatch(/Starting each server once/);
  });
});

describe("a dry run", () => {
  it("writes nothing and says what --apply would do", async () => {
    writeProject({ notes: stdio(MOCK) });
    const report = await adopt();
    expect(report).toMatch(/Nothing has been written/);
    expect(report).toMatch(/Re-run with --apply/);

    // The client config is untouched, and no generated directory exists.
    const after = JSON.parse(readFileSync(join(project, ".mcp.json"), "utf8"));
    expect(Object.keys(after.mcpServers)).toEqual(["notes"]);
    expect(() => readFileSync(join(project, ".hmcp", "gateway.yaml"))).toThrow();
  });

  it("reports a failing upstream without changing anything", async () => {
    writeProject({ broken: { command: process.execPath, args: [join(FIXTURES, "does-not-exist.mjs")] } });
    await expect(adopt()).rejects.toThrow(/could not connect the upstreams/);
    const after = JSON.parse(readFileSync(join(project, ".mcp.json"), "utf8"));
    expect(Object.keys(after.mcpServers)).toEqual(["broken"]);
  });

  it("stops before probing when every server was skipped", async () => {
    writeProject({ legacy: { type: "sse", url: "https://x.example.com/sse" } });
    const report = await adopt();
    expect(report).toMatch(/Nothing left to wrap/);
    expect(report).not.toMatch(/Starting each server once/);
  });
});

describe("the generated policy, after a probe", () => {
  it("carries a stub for each tool the probe could not classify", async () => {
    writeProject({ notes: stdio(MOCK) });
    await adopt({ apply: true, local: true });
    const policy = readFileSync(join(project, ".hmcp", "policy.yaml"), "utf8");
    expect(policy).toMatch(/#\s+- id: classify-notes__frobnicate/);
    expect(policy).toMatch(/#\s+effect: read/);
  });

  it("notes the real tool count against the budget", async () => {
    writeProject({ notes: stdio(MOCK) });
    await adopt({ apply: true, local: true });
    const policy = readFileSync(join(project, ".hmcp", "policy.yaml"), "utf8");
    expect(policy).toMatch(/currently exposes \d+ tool\(s\)/);
  });
});
