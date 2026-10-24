import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { readRegistry } from "@hmcp/core";
import { parse as parseYaml } from "yaml";
import { AdoptCommandError, runAdoptCommand, runRevertCommand } from "../src/adopt-cli.js";
import { loadGatewayConfig } from "../src/config.js";

/**
 * Editing a config the client owns, and being able to put it back.
 *
 * The property that matters most is that `--revert` restores exactly what was
 * there. Everything else in this command is recoverable by editing a file; an
 * adoption that cannot be undone is not.
 */

const MOCK = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "mock-upstream.mjs");

let root: string;
let home: string;
let project: string;
let registry: string;
let out: string[];

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "hmcp-install-"));
  home = join(root, "home");
  project = join(root, "project");
  registry = join(root, "servers.json");
  mkdirSync(home, { recursive: true });
  mkdirSync(project, { recursive: true });
  out = [];
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function stdio(): Record<string, unknown> {
  return { command: process.execPath, args: [MOCK] };
}

function writeProjectFile(value: unknown): void {
  writeFileSync(join(project, ".mcp.json"), JSON.stringify(value, null, 2));
}

function readProjectFile(): { mcpServers: Record<string, unknown>; [k: string]: unknown } {
  return JSON.parse(readFileSync(join(project, ".mcp.json"), "utf8"));
}

async function adopt(extra: Record<string, unknown> = {}): Promise<string> {
  out = [];
  await runAdoptCommand({
    cwd: project,
    home,
    scope: "project",
    registry,
    local: true,
    write: (line) => out.push(line),
    ...extra
  });
  return out.join("\n");
}

async function revert(extra: Record<string, unknown> = {}): Promise<string> {
  out = [];
  await runRevertCommand({
    cwd: project,
    home,
    scope: "project",
    registry,
    write: (line) => out.push(line),
    ...extra
  });
  return out.join("\n");
}

describe("installing", () => {
  it("replaces the adopted entries with a single gateway entry", async () => {
    writeProjectFile({ mcpServers: { notes: stdio(), other: stdio() } });
    await adopt({ apply: true });

    const after = readProjectFile();
    expect(Object.keys(after.mcpServers)).toEqual(["hmcp"]);
    expect(after.mcpServers["hmcp"]).toMatchObject({
      command: process.execPath,
      args: [expect.stringContaining("cli.js"), "serve", "-c", join(project, ".hmcp", "gateway.yaml")]
    });
  });

  it("leaves keys it does not own alone", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() }, someOtherTool: { keep: "this" } });
    await adopt({ apply: true });
    expect(readProjectFile().someOtherTool).toEqual({ keep: "this" });
  });

  it("writes a config that loads, fronting the adopted servers", async () => {
    writeProjectFile({ mcpServers: { notes: stdio(), "My-Other": stdio() } });
    await adopt({ apply: true });

    const loaded = loadGatewayConfig(join(project, ".hmcp", "gateway.yaml"));
    expect(loaded.config.upstreams.map((u) => u.name).sort()).toEqual(["my_other", "notes"]);
    expect(loaded.policy.defaults.mode).toBe("approve-writes");
  });

  it("moves the environment onto the gateway's entry so pass_env can find it", async () => {
    writeProjectFile({ mcpServers: { notes: { ...stdio(), env: { TOKEN: "t-123" } } } });
    await adopt({ apply: true });

    expect(readProjectFile().mcpServers["hmcp"]).toMatchObject({ env: { TOKEN: "t-123" } });
    const config = parseYaml(readFileSync(join(project, ".hmcp", "gateway.yaml"), "utf8")) as {
      upstreams: { pass_env?: string[] }[];
    };
    expect(config.upstreams[0]!.pass_env).toEqual(["TOKEN"]);
    // And the secret is not duplicated into the generated file.
    expect(readFileSync(join(project, ".hmcp", "gateway.yaml"), "utf8")).not.toMatch(/t-123/);
  });

  it("keeps a skipped server configured directly in the client", async () => {
    writeProjectFile({ mcpServers: { notes: stdio(), legacy: { type: "sse", url: "https://x/sse" } } });
    await adopt({ apply: true });
    expect(Object.keys(readProjectFile().mcpServers).sort()).toEqual(["hmcp", "legacy"]);
  });

  it("writes a verbatim copy of the original file", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    const before = readProjectFile();
    await adopt({ apply: true });
    expect(JSON.parse(readFileSync(join(project, ".mcp.json.hmcp-backup"), "utf8"))).toEqual(before);
  });

  it("warns when the backups now hold a literal credential", async () => {
    // The backups copy the replaced entries verbatim, and whatever protected
    // the original file does not cover two new ones.
    writeProjectFile({ mcpServers: { notes: { ...stdio(), env: { TOKEN: "ghp_literal" } } } });
    const report = await adopt({ apply: true });
    expect(report).toMatch(/held a literal value/);
    expect(readFileSync(join(project, ".mcp.json.hmcp-backup"), "utf8")).toMatch(/ghp_literal/);
  });

  it("says nothing about literals when every value was a ${VAR}", async () => {
    writeProjectFile({ mcpServers: { notes: { ...stdio(), env: { TOKEN: "${GH_PAT}" } } } });
    expect(await adopt({ apply: true })).not.toMatch(/held a literal value/);
  });

  it("pins the published version when not pointed at a local build", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true, local: false, pinVersion: "0.1.0" });
    expect(readProjectFile().mcpServers["hmcp"]).toMatchObject({
      command: "npx",
      args: ["-y", "hmcp-gateway@0.1.0", "serve", "-c", join(project, ".hmcp", "gateway.yaml")]
    });
  });

  it("writes a relative -c path on request, for a config meant to be shared", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true, relativeConfig: true });
    const entry = readProjectFile().mcpServers["hmcp"] as { args: string[] };
    expect(entry.args[entry.args.length - 1]).toBe(join(".hmcp", "gateway.yaml"));
  });

  it("prints the checklist, including why the console looks empty", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    const report = await adopt({ apply: true });
    expect(report).toMatch(/To confirm it is actually enforcing/);
    expect(report).toMatch(/NO tools/);
    expect(report).toMatch(/adopt --revert/);
  });
});

describe("running it twice", () => {
  it("is a no-op when nothing new has appeared", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });
    const after = readProjectFile();

    const report = await adopt({ apply: true });
    expect(report).toMatch(/Already adopted/);
    expect(report).toMatch(/Nothing to do/);
    expect(readProjectFile()).toEqual(after);
  });

  it("merges only the server that appeared since", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });

    const current = readProjectFile();
    writeProjectFile({ mcpServers: { ...current.mcpServers, later: stdio() } });
    const report = await adopt({ apply: true });

    expect(report).toMatch(/1 new server\(s\) appeared/);
    const loaded = loadGatewayConfig(join(project, ".hmcp", "gateway.yaml"));
    expect(loaded.config.upstreams.map((u) => u.name).sort()).toEqual(["later", "notes"]);
    expect(Object.keys(readProjectFile().mcpServers)).toEqual(["hmcp"]);
  });

  it("does not give a merged upstream a name the gateway already uses", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });

    const current = readProjectFile();
    // A second server whose name normalizes onto the first one's.
    writeProjectFile({ mcpServers: { ...current.mcpServers, "Notes": stdio() } });
    await adopt({ apply: true });

    const loaded = loadGatewayConfig(join(project, ".hmcp", "gateway.yaml"));
    expect(loaded.config.upstreams.map((u) => u.name).sort()).toEqual(["notes", "notes_2"]);
  });

  it("refuses a gateway entry it has no backup for", async () => {
    // Replacing an entry we cannot restore is not an operation with an undo.
    writeProjectFile({
      mcpServers: { hmcp: { command: "npx", args: ["-y", "hmcp-gateway", "serve"] }, notes: stdio() }
    });
    await expect(adopt({ apply: true })).rejects.toThrow(AdoptCommandError);
    await expect(adopt({ apply: true })).rejects.toThrow(/no adoption backup/);
  });

  it("recognises a renamed gateway entry by what it runs", async () => {
    writeProjectFile({ mcpServers: { "my-proxy": { command: "npx", args: ["-y", "hmcp-gateway", "serve"] } } });
    await expect(adopt({ apply: true })).rejects.toThrow(/already an hmcp gateway/);
  });
});

describe("reverting", () => {
  it("restores exactly what was there", async () => {
    const before = { mcpServers: { notes: stdio(), other: { ...stdio(), env: { K: "v" } } }, extra: { x: 1 } };
    writeProjectFile(before);
    await adopt({ apply: true });
    await revert();
    expect(readProjectFile()).toEqual(before);
  });

  it("removes the gateway entry and the backup record", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });
    await revert();
    expect(readProjectFile().mcpServers["hmcp"]).toBeUndefined();
    expect(existsSync(join(project, ".hmcp-adopt-backup.json"))).toBe(false);
  });

  it("leaves the generated files unless asked to purge them", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });

    const report = await revert();
    expect(report).toMatch(/Left in place/);
    expect(existsSync(join(project, ".hmcp", "gateway.yaml"))).toBe(true);
  });

  it("deletes them with --purge", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });
    await revert({ purge: true });
    expect(existsSync(join(project, ".hmcp", "gateway.yaml"))).toBe(false);
  });

  it("refuses rather than clobbering a name taken since adoption", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });

    // Something else now answers to "notes". It is not this command's to
    // discard on the way to undoing its own work.
    const current = readProjectFile();
    writeProjectFile({ mcpServers: { ...current.mcpServers, notes: { command: "something-else" } } });

    await expect(revert()).rejects.toThrow(/now has a different server under each/);
    expect(readProjectFile().mcpServers["notes"]).toEqual({ command: "something-else" });
  });

  it("errors when there is no backup to revert from", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await expect(revert()).rejects.toThrow(/no adoption backup/);
  });

  it("restores the originals even if the gateway entry was removed by hand", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });
    writeProjectFile({ mcpServers: {} });

    const report = await revert();
    expect(report).toMatch(/is not in .* any more/);
    expect(Object.keys(readProjectFile().mcpServers)).toEqual(["notes"]);
  });
});

describe("the console registry", () => {
  it("records an absolute config path, because the console resolves it elsewhere", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });

    const entries = readRegistry(registry).servers;
    expect(entries).toHaveLength(1);
    expect(entries[0]!.config_path).toBe(join(project, ".hmcp", "gateway.yaml"));
    expect(entries[0]!.kind).toBe("gateway");
  });

  it("derives an id a registry row accepts", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });
    expect(readRegistry(registry).servers[0]!.id).toMatch(/^[a-z0-9][a-z0-9_-]{0,63}$/);
  });

  it("honours an explicit id", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true, id: "my-gateway" });
    expect(readRegistry(registry).servers[0]!.id).toBe("my-gateway");
  });

  it("refuses an id already taken, before touching the client config", async () => {
    // The refusal has to come first. Rewriting the client config and then
    // failing to register would leave a gateway entry with no backup beside
    // it, which is the one state adopt itself refuses to touch -- reachable
    // here by a name clash in an unrelated file.
    writeFileSync(
      registry,
      JSON.stringify(
        {
          version: 1,
          servers: [
            {
              id: "taken",
              kind: "gateway",
              label: "other",
              config_path: "/x/gateway.yaml",
              added_at: "2026-01-01T00:00:00.000Z"
            }
          ]
        },
        null,
        2
      )
    );
    const before = { mcpServers: { notes: stdio() } };
    writeProjectFile(before);

    await expect(adopt({ apply: true, id: "taken" })).rejects.toThrow(/already has a server with id "taken"/);
    expect(readProjectFile()).toEqual(before);
    expect(existsSync(join(project, ".hmcp-adopt-backup.json"))).toBe(false);
    expect(readRegistry(registry).servers).toHaveLength(1);
  });

  it("skips registration on --no-register", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true, register: false });
    expect(readRegistry(registry).servers).toEqual([]);
  });

  it("removes its own row on revert and leaves others alone", async () => {
    writeFileSync(
      registry,
      JSON.stringify(
        {
          version: 1,
          servers: [
            { id: "someone-else", kind: "gateway", label: "other", config_path: "/x/gateway.yaml", added_at: "2026-01-01T00:00:00.000Z" }
          ]
        },
        null,
        2
      )
    );
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });
    expect(readRegistry(registry).servers).toHaveLength(2);

    await revert();
    expect(readRegistry(registry).servers.map((s) => s.id)).toEqual(["someone-else"]);
  });

  it("does not add a second row when merging into an existing gateway", async () => {
    writeProjectFile({ mcpServers: { notes: stdio() } });
    await adopt({ apply: true });

    const current = readProjectFile();
    writeProjectFile({ mcpServers: { ...current.mcpServers, later: stdio() } });
    await adopt({ apply: true });

    expect(readRegistry(registry).servers).toHaveLength(1);
  });
});
