import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { z } from "zod";

/**
 * Claude Code's own MCP server configuration: finding it, reading it, and
 * putting it back.
 *
 * This is the one file in the gateway that touches a config another program
 * owns, and that ownership drives two departures from how every other schema
 * here is written.
 *
 * The schemas are loose rather than `.strict()`. The gateway's own config is
 * strict because the gateway defines it, and an unknown key there is a typo
 * worth refusing. This format belongs to Claude Code, which adds fields
 * between releases; a strict parse would make `adopt` refuse a config that is
 * perfectly good and merely newer than this build.
 *
 * And entries are validated one at a time rather than as a whole file, so a
 * single malformed entry costs itself and not every sibling. That is the same
 * reasoning as `dropUnknownKinds` in core's registry: a config shared between
 * versions must not let one bad row hide the rest.
 */

/** A server Claude Code starts as a child process. */
export const ClaudeStdioServerSchema = z.looseObject({
  type: z.literal("stdio").optional(),
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
  env: z.record(z.string(), z.string()).default({})
});

/** A server Claude Code reaches over the network. */
export const ClaudeRemoteServerSchema = z.looseObject({
  type: z.enum(["http", "sse"]),
  url: z.string().min(1),
  headers: z.record(z.string(), z.string()).default({})
});

export type ClaudeStdioServer = z.infer<typeof ClaudeStdioServerSchema>;
export type ClaudeRemoteServer = z.infer<typeof ClaudeRemoteServerSchema>;
export type ClaudeServer = ClaudeStdioServer | ClaudeRemoteServer;

export function isRemote(server: ClaudeServer): server is ClaudeRemoteServer {
  return server.type === "http" || server.type === "sse";
}

export class ClientConfigError extends Error {}

/** Where one scope's servers live. */
export type Scope = "project" | "local" | "user";

export interface ScopeTarget {
  readonly scope: Scope;
  /** The JSON file holding them. */
  readonly path: string;
  /** Where inside that file, for an error message a human can act on. */
  readonly where: string;
}

export interface ScopeOptions {
  readonly cwd?: string;
  readonly home?: string;
}

/**
 * The three places Claude Code keeps MCP servers, in the order it resolves
 * them.
 *
 * `local` is per-project state inside the user-wide file, which is why its
 * entry is keyed by an absolute project path rather than living next to the
 * project.
 */
export function scopeTargets(options: ScopeOptions = {}): ScopeTarget[] {
  const cwd = resolve(options.cwd ?? process.cwd());
  const home = options.home ?? homedir();
  const claudeJson = join(home, ".claude.json");
  return [
    { scope: "project", path: join(cwd, ".mcp.json"), where: "mcpServers" },
    { scope: "local", path: claudeJson, where: `projects[${cwd}].mcpServers` },
    { scope: "user", path: claudeJson, where: "mcpServers" }
  ];
}

function targetFor(scope: Scope, options: ScopeOptions): ScopeTarget {
  const target = scopeTargets(options).find((t) => t.scope === scope);
  if (!target) throw new ClientConfigError(`unknown scope "${scope}"`);
  return target;
}

export interface ClientConfigFile {
  readonly target: ScopeTarget;
  /** The whole file, so everything this command does not own survives a write. */
  readonly raw: Record<string, unknown>;
  /** The `mcpServers` object for this scope, values still unvalidated. */
  readonly servers: Record<string, unknown>;
  readonly exists: boolean;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/**
 * Reads one scope.
 *
 * A missing file is an empty scope rather than an error, matching
 * `readRegistry`: not having adopted anything yet is a state, not a fault.
 */
export function readClientConfig(scope: Scope, options: ScopeOptions = {}): ClientConfigFile {
  const target = targetFor(scope, options);
  if (!existsSync(target.path)) {
    return { target, raw: {}, servers: {}, exists: false };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(target.path, "utf8"));
  } catch (err) {
    throw new ClientConfigError(`${target.path} is not valid JSON: ${(err as Error).message}`);
  }
  const raw = asRecord(parsed);
  if (!raw) throw new ClientConfigError(`${target.path} does not contain a JSON object`);

  return { target, raw, servers: serversIn(raw, target), exists: true };
}

/** The `mcpServers` object this scope reads, or an empty one. */
function serversIn(raw: Record<string, unknown>, target: ScopeTarget): Record<string, unknown> {
  if (target.scope !== "local") return asRecord(raw["mcpServers"]) ?? {};
  const projects = asRecord(raw["projects"]) ?? {};
  const key = projectKey(target);
  return asRecord(asRecord(projects[key])?.["mcpServers"]) ?? {};
}

/** `projects[<abs cwd>]`, recovered from the target's own `where`. */
function projectKey(target: ScopeTarget): string {
  const match = /^projects\[(.*)\]\.mcpServers$/.exec(target.where);
  if (!match) throw new ClientConfigError(`cannot read a project key out of "${target.where}"`);
  return match[1]!;
}

export interface ParsedServers {
  readonly servers: ReadonlyMap<string, ClaudeServer>;
  /** Entries that did not validate, each with the reason, never silently dropped. */
  readonly malformed: readonly { readonly name: string; readonly message: string }[];
}

/**
 * Validates each entry on its own.
 *
 * An entry carrying `type: "http"` or `"sse"` is held to the remote shape
 * rather than being offered to both: a remote entry missing its `url` should
 * report that, not the stdio schema's complaint about a missing `command`.
 */
export function parseServers(raw: Record<string, unknown>): ParsedServers {
  const servers = new Map<string, ClaudeServer>();
  const malformed: { name: string; message: string }[] = [];

  for (const name of Object.keys(raw).sort()) {
    const entry = asRecord(raw[name]);
    if (!entry) {
      malformed.push({ name, message: "the entry is not a JSON object" });
      continue;
    }
    const type = entry["type"];
    const schema =
      type === "http" || type === "sse"
        ? ClaudeRemoteServerSchema
        : type === undefined || type === "stdio"
          ? ClaudeStdioServerSchema
          : undefined;
    if (!schema) {
      malformed.push({ name, message: `unrecognised transport type ${JSON.stringify(type)}` });
      continue;
    }
    const result = schema.safeParse(entry);
    if (!result.success) {
      malformed.push({
        name,
        message: result.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ")
      });
      continue;
    }
    servers.set(name, result.data as ClaudeServer);
  }

  return { servers, malformed };
}

/**
 * Which scope `adopt` should act on when nobody said.
 *
 * More than one populated scope refuses rather than merging. Which project
 * sees which server is a semantic Claude Code owns, and collapsing three
 * scopes into one gateway would change it -- a user-scope server would start
 * being visible only in the project that happened to run `adopt`.
 */
export function resolveScope(explicit: Scope | undefined, options: ScopeOptions = {}): ScopeTarget {
  if (explicit) return targetFor(explicit, options);

  const populated = scopeTargets(options)
    .map((target) => ({ target, count: Object.keys(readClientConfig(target.scope, options).servers).length }))
    .filter((s) => s.count > 0);

  if (populated.length === 1) return populated[0]!.target;
  if (populated.length === 0) {
    throw new ClientConfigError(
      "found no MCP servers to adopt. Looked in:\n" +
        scopeTargets(options)
          .map((t) => `  ${t.scope.padEnd(8)} ${t.path} (${t.where})`)
          .join("\n")
    );
  }
  throw new ClientConfigError(
    "more than one scope has MCP servers, and which project sees which server is Claude Code's to " +
      "decide, not this command's. Pass --scope to say which one to adopt:\n" +
      populated.map((s) => `  --scope ${s.target.scope.padEnd(8)} ${s.count} server(s) in ${s.target.path}`).join("\n")
  );
}

/** Writes `servers` back into the scope, leaving the rest of the file alone. */
export function writeClientConfig(file: ClientConfigFile, servers: Record<string, unknown>): void {
  const raw = structuredClone(file.raw);
  if (file.target.scope === "local") {
    const projects = asRecord(raw["projects"]) ?? {};
    const key = projectKey(file.target);
    const project = asRecord(projects[key]) ?? {};
    raw["projects"] = { ...projects, [key]: { ...project, mcpServers: servers } };
  } else {
    raw["mcpServers"] = servers;
  }
  writeJsonPreservingMode(file.target.path, raw);
}

/**
 * Atomic write through a temporary file, as `writeRegistry` does: a crash
 * mid-write must not leave a half-written config that then fails to parse and
 * takes every one of the user's MCP servers with it.
 *
 * The existing mode is preserved rather than assumed. `~/.claude.json` is
 * `0600` on a normal install and holds an OAuth account; widening it while
 * adding a server would be a quiet regression. A file we are creating gets
 * `0600` outright.
 */
function writeJsonPreservingMode(path: string, value: unknown): void {
  const mode = existsSync(path) ? statSync(path).mode & 0o777 : 0o600;
  mkdirSync(dirname(path), { recursive: true });
  const tmp = join(dirname(path), `.${Date.now()}.${Math.random().toString(36).slice(2)}.tmp`);
  writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode });
  renameSync(tmp, path);
}

/** A verbatim copy of the file before adoption touched it. */
export function wholeFileBackupPath(target: ScopeTarget): string {
  return `${target.path}.hmcp-backup`;
}

/** The structured record `--revert` reads. */
export function backupPath(target: ScopeTarget): string {
  return join(dirname(target.path), ".hmcp-adopt-backup.json");
}

export const AdoptBackupSchema = z
  .object({
    version: z.literal(1),
    created_at: z.string(),
    scope: z.enum(["project", "local", "user"]),
    config_path: z.string(),
    gateway_entry_name: z.string(),
    /** The original entries, verbatim, keyed by the name they had. */
    replaced: z.record(z.string(), z.unknown()),
    generated: z.array(z.string()),
    registry_id: z.string().optional()
  })
  .strict();
export type AdoptBackup = z.infer<typeof AdoptBackupSchema>;

export function readBackup(target: ScopeTarget): AdoptBackup | undefined {
  const path = backupPath(target);
  if (!existsSync(path)) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new ClientConfigError(`${path} is not valid JSON: ${(err as Error).message}`);
  }
  const result = AdoptBackupSchema.safeParse(parsed);
  if (!result.success) {
    throw new ClientConfigError(
      `${path} is not a backup this build understands:\n` +
        result.error.issues.map((i) => `  ${i.path.join(".") || "(root)"}: ${i.message}`).join("\n")
    );
  }
  return result.data;
}

export function writeBackup(target: ScopeTarget, backup: AdoptBackup): void {
  AdoptBackupSchema.parse(backup);
  writeJsonPreservingMode(backupPath(target), backup);
}

/** Copies the file verbatim, for the human who would rather just move it back. */
export function writeWholeFileBackup(file: ClientConfigFile): void {
  if (!file.exists) return;
  writeJsonPreservingMode(wholeFileBackupPath(file.target), file.raw);
}
