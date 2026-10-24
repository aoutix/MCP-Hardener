import { existsSync, mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  defaultRegistryPath,
  readRegistry,
  writeRegistry,
  type Posture,
  type RegistryEntry
} from "@hmcp/core";
import { toText } from "@hmcp/scanner";
import { loadGatewayConfig } from "./config.js";
import { Gateway } from "./gateway.js";
import {
  ClientConfigError,
  isRemote,
  parseServers,
  readBackup,
  readClientConfig,
  resolveScope,
  wholeFileBackupPath,
  writeBackup,
  writeClientConfig,
  writeWholeFileBackup,
  type AdoptBackup,
  type ClaudeServer,
  type ClientConfigFile,
  type Scope,
  type ScopeTarget
} from "./client-config.js";
import { planAdoption, type AdoptionPlan } from "./adopt-plan.js";
import { emitClientEntry, emitGatewayYaml, emitPolicyYaml, type ProbedTool } from "./adopt-emit.js";

/**
 * Putting the gateway in front of the MCP servers a client already has.
 *
 * The gateway has always been able to do this; what it could not do was be
 * installed. Doing it by hand means writing an upstream block per server with
 * its exact command and environment, writing a policy, editing the client's
 * own config to point at the gateway instead, and adding a row to the registry
 * so the console can see it. Four files, and every one of them a chance to
 * produce something that looks protected and is not.
 *
 * So the shape of this command is: say what it would do, then do it on
 * `--apply`, and keep enough to undo it. The report is the important half. A
 * gateway that refuses a tool the agent needed is a bad afternoon; a gateway
 * that silently stopped passing a tool on, and nobody noticed, is the failure
 * worth designing against.
 *
 * Factored out of `cli.ts` with an injected `write` so tests call it rather
 * than shelling out, as `exposure-cli.ts` does.
 */

export class AdoptCommandError extends Error {}

export interface AdoptCommandOptions {
  readonly scope?: Scope | undefined;
  readonly cwd?: string | undefined;
  readonly home?: string | undefined;
  /** Write the files and edit the client config. Off by default. */
  readonly apply?: boolean | undefined;
  /** The gateway's `name`, which becomes the audit component. */
  readonly name?: string | undefined;
  /** What the gateway's entry is called in the client config. */
  readonly entryName?: string | undefined;
  readonly posture?: Posture | undefined;
  readonly copyEnv?: boolean | undefined;
  readonly allowLocalHttp?: boolean | undefined;
  readonly strictEgress?: boolean | undefined;
  /** `--name <original>=<upstream>` pairs. */
  readonly names?: readonly string[] | undefined;
  /** Point the client at this build on disk instead of at a published version. */
  readonly local?: boolean | undefined;
  /** The published version to pin in the client entry. */
  readonly pinVersion?: string | undefined;
  /** Write a relative `-c` path, for a config meant to be committed and shared. */
  readonly relativeConfig?: boolean | undefined;
  readonly register?: boolean | undefined;
  readonly id?: string | undefined;
  readonly registry?: string | undefined;
  /** Where the generated files go, overriding the per-scope default. */
  readonly outDir?: string | undefined;
  readonly write?: ((line: string) => void) | undefined;
}

export interface RevertCommandOptions {
  readonly scope?: Scope | undefined;
  readonly cwd?: string | undefined;
  readonly home?: string | undefined;
  /** Also delete the generated gateway.yaml and policy.yaml. */
  readonly purge?: boolean | undefined;
  readonly registry?: string | undefined;
  readonly write?: ((line: string) => void) | undefined;
}

const DEFAULT_ENTRY_NAME = "hmcp";
const DEFAULT_GATEWAY_NAME = "claude-code";
const DEFAULT_PIN = "0.1.0";

function out(options: { readonly write?: ((line: string) => void) | undefined }): (line: string) => void {
  return options.write ?? ((line: string) => process.stdout.write(`${line}\n`));
}

/** Where the generated pair lives for this scope. */
function generatedDir(target: ScopeTarget, options: AdoptCommandOptions): string {
  if (options.outDir) return resolve(options.outDir);
  const cwd = resolve(options.cwd ?? process.cwd());
  // A relative `policy:` resolves against the config's own directory, so a
  // directory holding both is self-contained and can be moved as a unit.
  return target.scope === "user" ? join(dirname(target.path), ".hmcp", "claude-code") : join(cwd, ".hmcp");
}

function parseNameOverrides(pairs: readonly string[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const pair of pairs) {
    const at = pair.indexOf("=");
    if (at <= 0 || at === pair.length - 1) {
      throw new AdoptCommandError(`--name expects <original>=<upstream>, not ${JSON.stringify(pair)}`);
    }
    map.set(pair.slice(0, at), pair.slice(at + 1));
  }
  return map;
}

/** This build's own `cli.js`, for the `--local` entry. */
function localCliPath(): string {
  return fileURLToPath(new URL("./cli.js", import.meta.url));
}

function clientCommand(options: AdoptCommandOptions): { command: string; args: string[] } {
  if (options.local) return { command: process.execPath, args: [localCliPath()] };
  return { command: "npx", args: ["-y", `hmcp-gateway@${options.pinVersion ?? DEFAULT_PIN}`] };
}

/**
 * Whether this client entry is a gateway of ours.
 *
 * By name and by what it runs, because the two can disagree: a user may rename
 * the entry, and a stale entry from an older adoption may not use the name
 * this run would pick.
 */
function isOurGateway(name: string, server: ClaudeServer, entryName: string): boolean {
  if (name === entryName) return true;
  if (isRemote(server)) return false;
  return [server.command, ...server.args].some((w) => w.includes("hmcp-gateway") || w.endsWith("gateway/dist/cli.js"));
}

/** The `-c` path an existing gateway entry was pointed at. */
function configPathOf(server: ClaudeServer): string | undefined {
  if (isRemote(server)) return undefined;
  const at = server.args.indexOf("-c");
  const value = at >= 0 ? server.args[at + 1] : undefined;
  return value === undefined ? undefined : resolve(value);
}

const REGISTRY_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/**
 * An id legal for a registry row.
 *
 * Deliberately not the upstream-name normalizer: a registry id may contain
 * dashes and an upstream name may not, and sharing one function would quietly
 * hold both to the stricter rule.
 */
function registryId(label: string, taken: ReadonlySet<string>): string {
  let base = label
    .normalize("NFC")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (!REGISTRY_ID.test(base)) base = `gateway-${base}`.slice(0, 64);
  if (!REGISTRY_ID.test(base)) base = "gateway";
  let candidate = base;
  for (let n = 2; taken.has(candidate); n++) candidate = `${base}-${n}`;
  return candidate;
}

interface Probe {
  readonly tools: readonly ProbedTool[];
  readonly withheld: readonly { readonly localName: string; readonly upstream: string; readonly reason: string }[];
  readonly scanText: string;
}

/**
 * Starts every upstream once to ask what it offers, then throws it away.
 *
 * This is the only part of a dry run that is not free: it spawns each stdio
 * server as a child process and dials each HTTP one. It also builds the audit
 * log and approvals store, because a `Gateway` does that in its constructor,
 * and a tool withheld for its name is audited during connect. Those records
 * are genuinely this gateway's and are left where they belong rather than
 * redirected somewhere temporary.
 *
 * `announceServing()` is deliberately not called. It publishes an inventory
 * and claims a live pid, and a command that is about to exit must not leave a
 * console believing a gateway is running.
 */
async function probe(configPath: string): Promise<Probe> {
  const { config, policy } = loadGatewayConfig(configPath);
  const gateway = new Gateway({ config, policy, cwd: dirname(configPath) });
  try {
    await gateway.connectUpstreams();
    const tools = gateway.inventory().map(
      (entry): ProbedTool => ({
        localName: entry.localName,
        upstream: entry.upstream.spec.name,
        effect: entry.effect ?? null,
        effectSource: entry.effectSource,
        hidden: entry.hidden,
        injection: entry.injection
      })
    );
    return {
      tools,
      withheld: gateway.withheld(),
      scanText: toText(gateway.scanUpstreams(), "upstream MCP servers")
    };
  } finally {
    await gateway.close().catch(() => undefined);
  }
}

function describePlan(plan: AdoptionPlan, write: (line: string) => void): void {
  if (plan.malformed.length > 0) {
    write("");
    write("Entries that did not parse, and were left alone:");
    for (const bad of plan.malformed) write(`  ${bad.name}: ${bad.message}`);
  }

  write("");
  write(`Will wrap ${plan.upstreams.length} server(s):`);
  for (const planned of plan.upstreams) {
    const renamed = planned.originalName === planned.upstream.name ? "" : `  (was "${planned.originalName}")`;
    const how =
      planned.upstream.transport === "stdio"
        ? `stdio: ${planned.upstream.command} ${planned.upstream.args.join(" ")}`.trimEnd()
        : `http: ${planned.upstream.url}`;
    write(`  ${planned.upstream.name}${renamed}`);
    write(`    ${how}`);
    for (const warning of planned.warnings) write(`    note: ${warning}`);
  }

  if (plan.skipped.length > 0) {
    write("");
    write(`Will NOT wrap ${plan.skipped.length} server(s). These stay configured directly in the client:`);
    for (const skip of plan.skipped) {
      write(`  ${skip.name}`);
      write(`    why: ${skip.reason}`);
      write(`    fix: ${skip.remedy}`);
    }
  }

  if (Object.keys(plan.gatewayEnv).length > 0) {
    write("");
    write("Environment moved onto the gateway's own client entry, and forwarded by name:");
    for (const key of Object.keys(plan.gatewayEnv).sort()) write(`  ${key}`);
    write("  (the values stay in the client config they were already in; gateway.yaml holds none)");
  }

  if (plan.secretsOnDisk) {
    write("");
    write("--copy-env: a literal credential will be written into gateway.yaml. Do not commit it.");
  }

  if (plan.egressNeedsLocalHttp) {
    write("");
    write("--allow-local-http: egress.block_private_ips, allow_ip_literals and allow_http are");
    write("set to permit loopback. That applies to every HTTP upstream of this gateway, not");
    write("only the one that needed it.");
  }
}

function describeProbe(result: Probe, posture: Posture, write: (line: string) => void): void {
  const byUpstream = new Map<string, ProbedTool[]>();
  for (const tool of result.tools) {
    const list = byUpstream.get(tool.upstream) ?? [];
    list.push(tool);
    byUpstream.set(tool.upstream, list);
  }

  write("");
  write(`${result.tools.length} tool(s) across ${byUpstream.size} server(s):`);
  for (const upstream of [...byUpstream.keys()].sort()) {
    write("");
    write(`  ${upstream}`);
    for (const tool of byUpstream.get(upstream)!) {
      const flags = [
        tool.hidden ? "hidden" : null,
        tool.injection ? `injection:${tool.injection.action}` : null
      ].filter(Boolean);
      write(
        `    ${tool.localName.padEnd(44)} ${(tool.effect ?? "unclassified").padEnd(13)} ` +
          `(${tool.effectSource})${flags.length > 0 ? `  [${flags.join(", ")}]` : ""}`
      );
    }
  }

  const unclassified = result.tools.filter((t) => t.effect === null && !t.hidden);
  const held = result.tools.filter((t) => t.effect !== null && t.effect !== "read" && !t.hidden);
  const injected = result.tools.filter((t) => t.injection !== null);
  const tooLong = result.tools.filter((t) => t.localName.length > 64);

  if (unclassified.length > 0) {
    write("");
    write(`WILL BE REFUSED -- ${unclassified.length} tool(s) nothing could classify:`);
    for (const tool of unclassified) write(`  ${tool.localName}`);
    write("  `on_unclassified: deny` refuses these. policy.yaml carries a commented stub for");
    write("  each one; uncomment it to classify that tool deliberately.");
  }

  if (held.length > 0) {
    write("");
    const verb = posture === "read-only" || posture === "locked" ? "WILL BE REFUSED" : "WILL ASK FOR APPROVAL";
    write(`${verb} -- ${held.length} tool(s) that mutate state:`);
    for (const tool of held) write(`  ${tool.localName.padEnd(44)} ${tool.effect}`);
    if (posture === "approve-writes") {
      write("  Each call waits for a human: the client's own prompt where it supports one,");
      write("  otherwise `hmcp pending` and `hmcp approve <id>`, or the console.");
    }
  }

  if (injected.length > 0) {
    write("");
    write(`INJECTION FOUND in ${injected.length} upstream description(s):`);
    for (const tool of injected) {
      write(`  ${tool.localName}: ${tool.injection!.patternIds.join(", ")} -> ${tool.injection!.action}`);
    }
  }

  if (result.withheld.length > 0) {
    write("");
    write(`WITHHELD -- ${result.withheld.length} tool(s) the gateway will not pass on at all:`);
    for (const tool of result.withheld) write(`  ${tool.localName}: ${tool.reason}`);
    write("  These never reach the agent, and a call to one is refused as though it did not");
    write("  exist. The upstream still advertises them.");
  }

  if (tooLong.length > 0) {
    write("");
    write(`NAME TOO LONG -- ${tooLong.length} namespaced name(s) over 64 characters:`);
    for (const tool of tooLong) write(`  ${tool.localName} (${tool.localName.length})`);
    write("  Some clients refuse a tool name this long. Pass --name <server>=<shorter> to");
    write("  shrink the prefix.");
  }

  write("");
  write(result.scanText.trimEnd());
  if (result.scanText.includes("against a budget of")) {
    // Said only when there is a budget finding to say it about: nothing in the
    // gateway enforces the budget, so a reader should not take that finding
    // for a thing that will refuse a call.
    write("");
    write("The tool_budget finding above is advisory. Nothing in the gateway enforces the");
    write("budget; it reports that a tool set this size is hard for a human to review.");
  }
}

interface Generated {
  readonly dir: string;
  readonly configPath: string;
  readonly policyPath: string;
}

function emitInto(dir: string, plan: AdoptionPlan, options: AdoptCommandOptions, probed?: Probe): Generated {
  const name = options.name ?? DEFAULT_GATEWAY_NAME;
  const posture = options.posture ?? "approve-writes";
  mkdirSync(dir, { recursive: true });
  const configPath = join(dir, "gateway.yaml");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(configPath, emitGatewayYaml(plan, { name, posture }), { encoding: "utf8", mode: 0o600 });
  writeFileSync(
    policyPath,
    emitPolicyYaml(plan, {
      name,
      posture,
      ...(probed ? { unclassified: probed.tools.filter((t) => t.effect === null && !t.hidden) } : {}),
      ...(probed ? { toolCount: probed.tools.length } : {})
    }),
    { encoding: "utf8", mode: 0o600 }
  );
  return { dir, configPath, policyPath };
}

export async function runAdoptCommand(options: AdoptCommandOptions): Promise<void> {
  const write = out(options);
  const entryName = options.entryName ?? DEFAULT_ENTRY_NAME;
  const scopeOptions = {
    ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
    ...(options.home !== undefined ? { home: options.home } : {})
  };

  let target: ScopeTarget;
  try {
    target = resolveScope(options.scope, scopeOptions);
  } catch (err) {
    throw err instanceof ClientConfigError ? new AdoptCommandError(err.message) : err;
  }

  const file = readClientConfig(target.scope, scopeOptions);
  const parsed = parseServers(file.servers);
  const { malformed } = parsed;
  // Copied because an already-adopted scope has its gateway entry removed from
  // the set before planning.
  const servers = new Map(parsed.servers);

  write(`Client config: ${target.path}`);
  write(`Scope:         ${target.scope} (${target.where})`);

  /*
   * An existing gateway entry means this scope has been adopted before, and
   * the right behaviour depends on whether anything new has appeared beside
   * it. Without the backup there is no safe move at all: replacing an entry we
   * cannot restore is not an operation with an undo.
   */
  const existing = [...servers.entries()].find(([name, server]) => isOurGateway(name, server, entryName));
  const backup = readBackup(target);
  let reservedNames: string[] = [];
  let existingConfigPath: string | undefined;

  if (existing) {
    if (!backup) {
      throw new AdoptCommandError(
        `"${existing[0]}" in ${target.path} is already an hmcp gateway, but there is no adoption backup ` +
          `beside it. Replacing it would leave nothing to restore the original servers from. Move that ` +
          `entry aside by hand, or run adopt in a scope that has not been adopted.`
      );
    }
    existingConfigPath = configPathOf(existing[1]);
    if (existingConfigPath && existsSync(existingConfigPath)) {
      reservedNames = loadGatewayConfig(existingConfigPath).config.upstreams.map((u) => u.name);
    }
    servers.delete(existing[0]);
    if (servers.size === 0) {
      write("");
      write(`Already adopted: "${existing[0]}" fronts ${reservedNames.length} upstream(s) and nothing new`);
      write("has appeared beside it. Nothing to do.");
      return;
    }
    write("");
    write(`Already adopted. ${servers.size} new server(s) appeared beside "${existing[0]}" and will be`);
    write(`merged into ${existingConfigPath ?? "its config"}.`);
  }

  const gatewayDir = generatedDir(target, options);
  const gatewayConfigPath = existingConfigPath ?? join(gatewayDir, "gateway.yaml");

  const plan = planAdoption(servers, {
    gatewayEntryName: entryName,
    gatewayConfigPath,
    ...(options.copyEnv !== undefined ? { copyEnv: options.copyEnv } : {}),
    ...(options.allowLocalHttp !== undefined ? { allowLocalHttp: options.allowLocalHttp } : {}),
    ...(options.strictEgress !== undefined ? { strictEgress: options.strictEgress } : {}),
    names: parseNameOverrides(options.names ?? []),
    reservedNames,
    malformed
  });

  describePlan(plan, write);

  if (plan.upstreams.length === 0) {
    write("");
    write("Nothing left to wrap, so there is no gateway to write. Nothing was changed.");
    return;
  }

  /*
   * Merging means the generated files describe the union, so the plan is
   * widened with what the existing gateway already fronts before anything is
   * emitted or probed.
   */
  const merged = existingConfigPath ? mergeWithExisting(plan, existingConfigPath) : plan;

  write("");
  write("Starting each server once to ask what it offers. This spawns the stdio servers");
  write("and dials the HTTP ones; nothing is written to the client config yet.");

  const scratch = mkdtempSync(join(tmpdir(), "hmcp-adopt-"));
  let probed: Probe;
  try {
    const staged = emitInto(scratch, merged, options);
    probed = await probe(staged.configPath);
  } catch (err) {
    throw new AdoptCommandError(
      `could not connect the upstreams as configured: ${(err as Error).message}\n` +
        `Nothing was changed. Fix the server that failed, or drop it with --name, and try again.`
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  describeProbe(probed, options.posture ?? "approve-writes", write);

  if (!options.apply) {
    write("");
    write("Nothing has been written. Re-run with --apply to:");
    write(`  write ${join(gatewayDir, "gateway.yaml")} and policy.yaml`);
    write(`  replace ${merged.upstreams.length} entr(ies) in ${target.path} with one "${entryName}" entry`);
    write(`  back the originals up to ${wholeFileBackupPath(target)}`);
    if (options.register !== false) write("  register the gateway with the console");
    return;
  }

  const generated = emitInto(gatewayDir, merged, options, probed);
  write("");
  write(`Wrote ${generated.configPath}`);
  write(`Wrote ${generated.policyPath}`);

  const id = installEntry({ file, target, plan, merged, generated, options, backup, existing, write });
  printChecklist({ target, generated, entryName, id, options, write });
}

/** Widens a plan with the upstreams a gateway being merged into already has. */
function mergeWithExisting(plan: AdoptionPlan, existingConfigPath: string): AdoptionPlan {
  const { config } = loadGatewayConfig(existingConfigPath);
  const already = config.upstreams.map((upstream) => ({
    upstream,
    originalName: upstream.name,
    warnings: [] as string[]
  }));
  return { ...plan, upstreams: [...already, ...plan.upstreams] };
}

interface InstallArgs {
  readonly file: ClientConfigFile;
  readonly target: ScopeTarget;
  readonly plan: AdoptionPlan;
  readonly merged: AdoptionPlan;
  readonly generated: Generated;
  readonly options: AdoptCommandOptions;
  readonly backup: AdoptBackup | undefined;
  readonly existing: readonly [string, ClaudeServer] | undefined;
  readonly write: (line: string) => void;
}

function installEntry(args: InstallArgs): string | undefined {
  const { file, target, plan, merged, generated, options, write } = args;
  const entryName = options.entryName ?? DEFAULT_ENTRY_NAME;
  const adopted = plan.upstreams.map((u) => u.originalName);

  /*
   * Everything that can refuse happens before anything is written.
   *
   * Registration used to run after the client config had been rewritten,
   * which meant a taken registry id left the gateway entry in place with no
   * backup beside it -- the one state `adopt` itself then refuses to touch,
   * reachable by a name clash in an unrelated file.
   */
  const registration = options.register === false ? undefined : prepareRegistration(args);

  // Then the verbatim copy: whatever goes wrong after this, the original file
  // is sitting beside it.
  writeWholeFileBackup(file);

  const servers: Record<string, unknown> = { ...file.servers };
  for (const name of adopted) delete servers[name];
  if (args.existing) delete servers[args.existing[0]];

  const { command, args: commandArgs } = clientCommand(options);
  const configPath = options.relativeConfig
    ? relative(dirname(target.path), generated.configPath)
    : generated.configPath;
  servers[entryName] = emitClientEntry(merged, { configPath, command, args: commandArgs });

  writeClientConfig(file, servers);
  write(`Rewrote ${target.path}: ${adopted.length} entr(ies) replaced by "${entryName}"`);

  const registryIdUsed = registration ? commitRegistration(registration, write) : undefined;

  const replaced: Record<string, unknown> = { ...(args.backup?.replaced ?? {}) };
  for (const name of adopted) replaced[name] = file.servers[name];

  writeBackup(target, {
    version: 1,
    created_at: new Date().toISOString(),
    scope: target.scope,
    config_path: target.path,
    gateway_entry_name: entryName,
    replaced,
    generated: [generated.configPath, generated.policyPath],
    ...(registryIdUsed !== undefined ? { registry_id: registryIdUsed } : {})
  });

  /*
   * Both backups hold the original entries verbatim, so if one of those
   * carried a literal credential rather than a `${VAR}`, adoption has just
   * written that credential into two new files. Said out loud, because the
   * files are new and whatever protected the original -- a gitignore rule, a
   * mode -- does not cover them.
   */
  if (hasLiteralSecret(replaced)) {
    write("");
    write("One of the replaced entries held a literal value in `env` or `headers`, which both");
    write("backups now contain. If the original config was kept out of version control, keep");
    write(`these out too: ${wholeFileBackupPath(target)} and the .hmcp-adopt-backup.json beside it.`);
  }

  return registryIdUsed;
}

/**
 * Whether any replaced entry carried a value that is a secret rather than a
 * reference to one.
 *
 * A `${VAR}` is a pointer and costs nothing to copy; anything else might be
 * the credential itself. Deliberately not trying to tell a token from a
 * setting: the point is to say "look at this", not to classify it.
 */
function hasLiteralSecret(replaced: Readonly<Record<string, unknown>>): boolean {
  for (const entry of Object.values(replaced)) {
    if (typeof entry !== "object" || entry === null) continue;
    for (const field of ["env", "headers"]) {
      const block = (entry as Record<string, unknown>)[field];
      if (typeof block !== "object" || block === null) continue;
      for (const value of Object.values(block as Record<string, unknown>)) {
        if (typeof value === "string" && value !== "" && !/\$\{[^}]*\}/.test(value)) return true;
      }
    }
  }
  return false;
}

interface Registration {
  readonly registryPath: string;
  readonly entry: RegistryEntry | undefined;
  /** Already registered from an earlier adoption; nothing to write. */
  readonly existingId: string | undefined;
}

/** Decides the registry row and proves it can be written, without writing it. */
function prepareRegistration(args: InstallArgs): Registration {
  const { generated, options, target } = args;
  const registryPath = options.registry ?? defaultRegistryPath();

  // Validate the config before persisting a path the console will later open.
  // This is the same check `loadServer` makes, done here rather than by
  // importing it: the console package depends on this one, so reaching back
  // into it would turn the dependency into a cycle.
  loadGatewayConfig(generated.configPath);

  const registry = readRegistry(registryPath);
  if (args.backup?.registry_id) {
    const already = registry.servers.find((s) => s.id === args.backup!.registry_id);
    if (already) return { registryPath, entry: undefined, existingId: already.id };
  }

  const taken = new Set(registry.servers.map((s) => s.id));
  if (options.id !== undefined && taken.has(options.id)) {
    throw new AdoptCommandError(
      `the registry at ${registryPath} already has a server with id "${options.id}". ` +
        `Pass a different --id, or --no-register.`
    );
  }

  const label = basename(dirname(dirname(generated.configPath))) || target.scope;
  return {
    registryPath,
    entry: {
      id: options.id ?? registryId(label, taken),
      kind: "gateway",
      label: `${label} (${target.scope})`,
      // Absolute, always: the console expands this against its own working
      // directory, which is not this one.
      config_path: generated.configPath,
      added_at: new Date().toISOString()
    },
    existingId: undefined
  };
}

function commitRegistration(registration: Registration, write: (line: string) => void): string | undefined {
  if (registration.entry === undefined) return registration.existingId;
  const registry = readRegistry(registration.registryPath);
  writeRegistry(
    { ...registry, servers: [...registry.servers, registration.entry] },
    registration.registryPath
  );
  write(`Registered with the console as "${registration.entry.id}" in ${registration.registryPath}`);
  return registration.entry.id;
}

function printChecklist(args: {
  readonly target: ScopeTarget;
  readonly generated: Generated;
  readonly entryName: string;
  readonly id: string | undefined;
  readonly options: AdoptCommandOptions;
  readonly write: (line: string) => void;
}): void {
  const { generated, entryName, write } = args;
  write("");
  write("Done. To confirm it is actually enforcing, in this order:");
  write("");
  write(`  1. hmcp-gateway tools -c ${generated.configPath}`);
  write("     The gateway's own view, with the client not involved yet.");
  write("  2. Restart the client. It reads its MCP config at startup, and a new");
  write("     project-scope server may need approving there first.");
  write(`  3. Ask it to list its tools. "${entryName}" should carry the namespaced ones.`);
  write("  4. Call a read tool. It should simply work.");
  write("  5. Call a write tool. It should wait -- either the client prompts, or");
  write("     `hmcp pending` shows it and `hmcp approve <id>` releases it.");
  write("  6. Call one of the unclassified tools listed above. It should be refused,");
  write("     naming defaults.on_unclassified. This is the step that proves the");
  write("     gateway is in the path rather than merely installed.");
  write("  7. hmcp audit tail   -- every one of those calls, allowed or not.");
  write("");
  write("  The console (hmcp-web) will show this gateway registered but with NO tools");
  write("  until it has served at least once, and will mark them stale whenever no");
  write("  gateway process is alive: the tool list it shows is what a running gateway");
  write("  published, not something the console goes and asks for. Over stdio the");
  write("  gateway lives only while the client holds the session, so the console is");
  write("  live only while the client is running. That is expected, not a failed");
  write("  adoption.");
  write("");
  write("  hmcp-gateway adopt --revert   puts the original entries back.");
}

export async function runRevertCommand(options: RevertCommandOptions): Promise<void> {
  const write = out(options);
  const scopeOptions = {
    ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
    ...(options.home !== undefined ? { home: options.home } : {})
  };

  /*
   * Revert reads the backup, so it cannot use the populated-scope heuristic:
   * after adoption the scope holds one entry, and the scope that was adopted
   * is the one with a backup beside it.
   */
  const targets = options.scope
    ? [resolveScope(options.scope, scopeOptions)]
    : (["project", "local", "user"] as const).map((scope) => resolveScope(scope, scopeOptions));

  const found = targets.map((target) => ({ target, backup: readBackup(target) })).filter((t) => t.backup);
  if (found.length === 0) {
    throw new AdoptCommandError(
      "found no adoption backup, so there is nothing to revert. Looked beside:\n" +
        targets.map((t) => `  ${t.path}`).join("\n")
    );
  }
  if (found.length > 1) {
    throw new AdoptCommandError(
      "more than one scope has an adoption backup. Pass --scope to say which to revert:\n" +
        found.map((f) => `  --scope ${f.target.scope.padEnd(8)} ${f.target.path}`).join("\n")
    );
  }

  const { target, backup } = found[0]!;
  const file = readClientConfig(target.scope, scopeOptions);
  const servers: Record<string, unknown> = { ...file.servers };

  const entry = servers[backup!.gateway_entry_name];
  if (entry === undefined) {
    write(`"${backup!.gateway_entry_name}" is not in ${target.path} any more; restoring the originals anyway.`);
  }

  /*
   * A name taken since adoption is reported rather than clobbered. Whatever is
   * sitting there now is something the user added on purpose, and it is not
   * this command's to overwrite on the way to undoing its own work.
   */
  const collisions = Object.keys(backup!.replaced).filter(
    (name) => servers[name] !== undefined && name !== backup!.gateway_entry_name
  );
  if (collisions.length > 0) {
    throw new AdoptCommandError(
      `these names were adopted, and ${target.path} now has a different server under each:\n` +
        collisions.map((n) => `  ${n}`).join("\n") +
        `\nRename or remove them first; restoring over them would discard what is there now.`
    );
  }

  delete servers[backup!.gateway_entry_name];
  for (const [name, original] of Object.entries(backup!.replaced)) servers[name] = original;
  writeClientConfig(file, servers);
  write(`Restored ${Object.keys(backup!.replaced).length} entr(ies) to ${target.path}`);

  if (backup!.registry_id) {
    const registryPath = options.registry ?? defaultRegistryPath();
    const registry = readRegistry(registryPath);
    const kept = registry.servers.filter((s) => s.id !== backup!.registry_id);
    if (kept.length !== registry.servers.length) {
      writeRegistry({ ...registry, servers: kept }, registryPath);
      write(`Removed "${backup!.registry_id}" from ${registryPath}`);
    }
  }

  if (options.purge) {
    for (const path of backup!.generated) {
      if (existsSync(path)) {
        unlinkSync(path);
        write(`Deleted ${path}`);
      }
    }
  } else if (backup!.generated.length > 0) {
    write(`Left in place: ${backup!.generated.join(", ")} (--purge deletes them)`);
  }

  unlinkSync(join(dirname(target.path), ".hmcp-adopt-backup.json"));
  write("Restart the client to pick up the restored servers.");
}
