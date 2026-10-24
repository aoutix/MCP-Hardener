import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ClientConfigError,
  parseServers,
  readClientConfig,
  resolveScope,
  writeClientConfig
} from "../src/client-config.js";

/**
 * Reading and writing a config another program owns.
 *
 * The asymmetry worth testing is that this code is a guest in these files:
 * it must tolerate fields it does not know, must not lose the ones it does not
 * touch, and must not widen the permissions on a file holding an OAuth
 * account.
 */

let home: string;
let project: string;

beforeEach(() => {
  const root = mkdtempSync(join(tmpdir(), "hmcp-client-"));
  home = join(root, "home");
  project = join(root, "project");
  mkdirSync(home, { recursive: true });
  mkdirSync(project, { recursive: true });
});

afterEach(() => {
  rmSync(join(home, ".."), { recursive: true, force: true });
});

function writeProject(servers: unknown, extra: Record<string, unknown> = {}): void {
  writeFileSync(join(project, ".mcp.json"), JSON.stringify({ mcpServers: servers, ...extra }, null, 2));
}

function writeClaudeJson(value: unknown, mode = 0o600): void {
  const path = join(home, ".claude.json");
  writeFileSync(path, JSON.stringify(value, null, 2));
  chmodSync(path, mode);
}

const options = () => ({ cwd: project, home });

describe("reading each scope", () => {
  it("reads project scope from .mcp.json", () => {
    writeProject({ notes: { command: "node", args: ["notes.js"] } });
    const file = readClientConfig("project", options());
    expect(Object.keys(file.servers)).toEqual(["notes"]);
    expect(file.exists).toBe(true);
  });

  it("reads local scope from the project's own block in ~/.claude.json", () => {
    writeClaudeJson({ projects: { [project]: { mcpServers: { tickets: { type: "http", url: "https://x/mcp" } } } } });
    expect(Object.keys(readClientConfig("local", options()).servers)).toEqual(["tickets"]);
    // The same file's top-level block is a different scope and must not leak in.
    expect(Object.keys(readClientConfig("user", options()).servers)).toEqual([]);
  });

  it("reads user scope from the top level of the same file", () => {
    writeClaudeJson({ mcpServers: { global: { command: "node" } }, projects: {} });
    expect(Object.keys(readClientConfig("user", options()).servers)).toEqual(["global"]);
    expect(Object.keys(readClientConfig("local", options()).servers)).toEqual([]);
  });

  it("treats a missing file as an empty scope rather than an error", () => {
    const file = readClientConfig("project", options());
    expect(file.exists).toBe(false);
    expect(file.servers).toEqual({});
  });

  it("refuses a file that is not JSON, naming it", () => {
    writeFileSync(join(project, ".mcp.json"), "{ not json");
    expect(() => readClientConfig("project", options())).toThrow(ClientConfigError);
    expect(() => readClientConfig("project", options())).toThrow(/\.mcp\.json is not valid JSON/);
  });
});

describe("parsing entries", () => {
  it("keeps an unknown field rather than refusing the entry", () => {
    // The format belongs to the client, which adds fields between releases. A
    // strict parse here would refuse a config that is merely newer.
    const { servers, malformed } = parseServers({
      notes: { command: "node", args: ["n.js"], timeoutMs: 5000, somethingNew: true }
    });
    expect(malformed).toEqual([]);
    expect(servers.get("notes")).toMatchObject({ command: "node", timeoutMs: 5000 });
  });

  it("costs a malformed entry itself and not its siblings", () => {
    const { servers, malformed } = parseServers({
      good: { command: "node" },
      a_string: "not an object",
      no_command: { args: ["x"] },
      alsogood: { type: "http", url: "https://x/mcp" }
    });
    expect([...servers.keys()].sort()).toEqual(["alsogood", "good"]);
    expect(malformed.map((m) => m.name).sort()).toEqual(["a_string", "no_command"]);
    expect(malformed.find((m) => m.name === "a_string")!.message).toMatch(/not a JSON object/);
  });

  it("holds an entry declaring a remote type to the remote shape", () => {
    // A remote entry missing its url should say so, not complain about a
    // missing `command` from the wrong schema.
    const { malformed } = parseServers({ remote: { type: "http" } });
    expect(malformed[0]!.message).toMatch(/url/);
  });

  it("reports an unrecognised transport type", () => {
    const { malformed } = parseServers({ odd: { type: "websocket", url: "ws://x" } });
    expect(malformed[0]!.message).toMatch(/unrecognised transport type "websocket"/);
  });

  it("defaults args, env and headers so planning need not re-check", () => {
    const { servers } = parseServers({
      a: { command: "node" },
      b: { type: "http", url: "https://x/mcp" }
    });
    expect(servers.get("a")).toMatchObject({ args: [], env: {} });
    expect(servers.get("b")).toMatchObject({ headers: {} });
  });
});

describe("choosing a scope", () => {
  it("uses the only populated scope when nobody said", () => {
    writeProject({ notes: { command: "node" } });
    expect(resolveScope(undefined, options()).scope).toBe("project");
  });

  it("refuses rather than merging when more than one is populated", () => {
    // Which project sees which server is the client's semantic, not ours.
    writeProject({ notes: { command: "node" } });
    writeClaudeJson({ mcpServers: { global: { command: "node" } } });
    expect(() => resolveScope(undefined, options())).toThrow(/more than one scope/);
    expect(() => resolveScope(undefined, options())).toThrow(/--scope project/);
  });

  it("names all three paths when nothing is configured anywhere", () => {
    expect(() => resolveScope(undefined, options())).toThrow(/found no MCP servers/);
    expect(() => resolveScope(undefined, options())).toThrow(/\.claude\.json/);
  });

  it("honours an explicit scope even when it is empty", () => {
    writeProject({ notes: { command: "node" } });
    expect(resolveScope("user", options()).scope).toBe("user");
  });
});

describe("writing back", () => {
  it("leaves every key it does not own alone", () => {
    writeProject({ notes: { command: "node" } }, { someOtherTool: { keep: "this" } });
    const file = readClientConfig("project", options());
    writeClientConfig(file, { hmcp: { command: "npx" } });
    const after = JSON.parse(readFileSync(join(project, ".mcp.json"), "utf8"));
    expect(after.someOtherTool).toEqual({ keep: "this" });
    expect(after.mcpServers).toEqual({ hmcp: { command: "npx" } });
  });

  it("changes only the project's own block in local scope", () => {
    writeClaudeJson({
      oauthAccount: { email: "someone@example.com" },
      projects: {
        [project]: { mcpServers: { notes: { command: "node" } }, enabledMcpjsonServers: ["notes"] },
        "/somewhere/else": { mcpServers: { other: { command: "node" } } }
      }
    });
    const file = readClientConfig("local", options());
    writeClientConfig(file, { hmcp: { command: "npx" } });

    const after = JSON.parse(readFileSync(join(home, ".claude.json"), "utf8"));
    expect(after.oauthAccount).toEqual({ email: "someone@example.com" });
    expect(after.projects["/somewhere/else"].mcpServers).toEqual({ other: { command: "node" } });
    expect(after.projects[project].mcpServers).toEqual({ hmcp: { command: "npx" } });
    // Sibling keys inside the project's own block survive too.
    expect(after.projects[project].enabledMcpjsonServers).toEqual(["notes"]);
  });

  it("preserves the file's mode rather than widening it", () => {
    writeClaudeJson({ mcpServers: { a: { command: "node" } } }, 0o600);
    const file = readClientConfig("user", options());
    writeClientConfig(file, { hmcp: { command: "npx" } });
    expect(statSync(join(home, ".claude.json")).mode & 0o777).toBe(0o600);
  });

  it("creates a new file at 0600", () => {
    const file = readClientConfig("project", options());
    writeClientConfig(file, { hmcp: { command: "npx" } });
    expect(statSync(join(project, ".mcp.json")).mode & 0o777).toBe(0o600);
  });
});
