#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { Command } from "commander";
import { parse as parseYaml } from "yaml";
import {
  ApprovalStore,
  defaultPolicy,
  expandPath,
  loadPolicy,
  parsePolicy,
  PolicyError,
  queryAuditLog,
  verifyAuditLog,
  type ApprovalRow,
  type Policy
} from "@hmcp/core";
import { scan, toMarkdown, toSarif, toText, type ScanTool } from "@hmcp/scanner";

const program = new Command();

program
  .name("hmcp")
  .description("Review approvals, verify the audit trail, and scan a hardened MCP server.")
  .version("0.1.0");

/* ------------------------------------------------------------------ approvals */

program
  .command("pending")
  .description("List tool calls waiting for a human decision.")
  .option("-p, --policy <file>", "policy file, to locate the approval store")
  .option("--store <file>", "approval store path")
  .option("--json", "emit JSON", false)
  .action((options) => {
    run(() => {
      const store = openStore(options);
      try {
        const rows = store.listPendingAll();
        if (options.json) {
          log(JSON.stringify(rows, null, 2));
          return;
        }
        if (rows.length === 0) {
          log("Nothing is waiting for approval.");
          return;
        }
        log(`${rows.length} call(s) waiting:`);
        for (const row of rows) log("\n" + describe(row));
        log("");
        log(`Approve with:  hmcp approve <id>`);
        log(`Refuse with:   hmcp deny <id>`);
      } finally {
        store.close();
      }
    });
  });

program
  .command("approve")
  .description("Release one pending call. The grant is bound to the exact arguments shown.")
  .argument("<id>", "approval id, as shown by `hmcp pending`")
  .option("-p, --policy <file>", "policy file, to locate the approval store")
  .option("--store <file>", "approval store path")
  .option("-m, --note <text>", "note recorded with the decision", "")
  .action((id: string, options) => decideOne(id, "granted", options));

program
  .command("deny")
  .description("Refuse one pending call.")
  .argument("<id>", "approval id, as shown by `hmcp pending`")
  .option("-p, --policy <file>", "policy file, to locate the approval store")
  .option("--store <file>", "approval store path")
  .option("-m, --note <text>", "note recorded with the decision", "")
  .action((id: string, options) => decideOne(id, "denied", options));

program
  .command("approvals")
  .description("Show recent approval history, decided or not.")
  .option("-p, --policy <file>", "policy file, to locate the approval store")
  .option("--store <file>", "approval store path")
  .option("-n, --limit <count>", "how many to show", "20")
  .action((options) => {
    run(() => {
      const store = openStore(options);
      try {
        const rows = store.listAll(Number(options.limit));
        if (rows.length === 0) {
          log("No approval requests have been recorded.");
          return;
        }
        for (const row of rows) {
          const decided = row.decided_at ? new Date(row.decided_at).toISOString() : "-";
          log(
            `${row.id}  ${row.state.padEnd(8)} ${scopeLabel(row).padEnd(30)} ${row.tool.padEnd(28)} ` +
              `${(row.effect ?? "?").padEnd(12)} by ${(row.decided_by ?? "-").padEnd(14)} ${decided}`
          );
        }
      } finally {
        store.close();
      }
    });
  });

function decideOne(id: string, state: "granted" | "denied", options: Record<string, unknown>): void {
  run(() => {
    const store = openStore(options);
    try {
      const existing = store.getAny(id);
      if (!existing) throw new CliError(`no approval request with id "${id}". Run "hmcp pending" to see what is open.`);
      if (existing.state !== "pending") {
        throw new CliError(
          `approval "${id}" is already ${existing.state}, so it cannot be decided again. ` +
            `If the agent needs to retry, it must make a fresh request.`
        );
      }

      log(describe(existing));
      log("");

      const row = store.decideAny(id, state, actor(), (options["note"] as string) ?? "");
      if (!row) throw new CliError(`approval "${id}" could not be decided; it may have just expired.`);

      log(
        state === "granted"
          ? `Granted. The agent may now retry this call with identical arguments; the grant is single-use where ` +
              `policy says so, and it expires at ${new Date(row.expires_at).toISOString()}.`
          : `Refused. The agent cannot run this call.`
      );
    } finally {
      store.close();
    }
  });
}

/**
 * Which server and customer a row belongs to, for an operator reading a file
 * that holds several of both.
 *
 * A row written before scoping existed carries neither, and says so rather
 * than being quietly attributed to whoever is looking.
 */
function scopeLabel(row: { component: string; tenant: string }): string {
  if (!row.component && !row.tenant) return "(unscoped, pre-upgrade)";
  const tenant = row.tenant ? `/${row.tenant}` : "";
  return `${row.component || "(none)"}${tenant}`;
}

function describe(row: ApprovalRow): string {
  let args = row.args_redacted;
  try {
    args = JSON.stringify(JSON.parse(row.args_redacted), null, 2);
  } catch {
    /* leave as stored */
  }
  return [
    `  id:       ${row.id}`,
    `  scope:    ${scopeLabel(row)}`,
    `  tool:     ${row.tool}  (${row.effect ?? "unclassified"})`,
    `  asked by: ${row.actor}  session ${row.session.slice(0, 8)}`,
    `  because:  ${row.reason}`,
    `  expires:  ${new Date(row.expires_at).toISOString()}`,
    `  arguments (secrets redacted):`,
    args
      .split("\n")
      .map((l) => `    ${l}`)
      .join("\n")
  ].join("\n");
}

/* ---------------------------------------------------------------------- audit */

const audit = program.command("audit").description("Inspect the audit trail.");

audit
  .command("verify")
  .description("Check the hash chain for edited, removed or reordered records.")
  .option("-p, --policy <file>", "policy file, to locate the log")
  .option("-f, --file <file>", "audit log path")
  .action((options) => {
    run(() => {
      const path = auditPath(options);
      const result = verifyAuditLog(path);
      if (result.ok) {
        log(`${path}: ${result.count} record(s), chain intact.`);
        return;
      }
      log(`${path}: ${result.count} record(s), ${result.problems.length} problem(s).`);
      log("");
      for (const problem of result.problems) log(`  line ${problem.line}: ${problem.message}`);
      log("");
      log("A chain break means the log was altered after it was written. Treat it as an incident.");
      process.exitCode = 1;
    });
  });

audit
  .command("tail")
  .description("Show the most recent decisions.")
  .option("-p, --policy <file>", "policy file, to locate the log")
  .option("-f, --file <file>", "audit log path")
  .option("-n, --limit <count>", "how many to show", "20")
  .option("--denied", "only show refused calls", false)
  .option("--json", "emit JSON", false)
  .action((options) => {
    run(() => {
      const path = auditPath(options);
      const limit = Number(options.limit);
      // Bounded and newest-first, then reversed to keep this command's existing
      // oldest-first output. The previous read parsed the whole log and threw on
      // a single torn line, which could hide every record around it.
      const page = queryAuditLog(path, { limit, ...(options.denied ? { noteworthy: true } : {}) });
      const records = [...page.records].reverse();

      if (options.json) {
        log(JSON.stringify(records, null, 2));
        return;
      }
      if (records.length === 0) {
        log(`${path}: nothing recorded yet.`);
        return;
      }
      for (const r of records) {
        log(
          `${r.ts}  ${r.decision.padEnd(7)} ${r.outcome.padEnd(16)} ${r.tool.padEnd(30)} ` +
            `${(r.effect ?? "-").padEnd(12)} ${r.rule_id}`
        );
        // An error explains the outcome better than the rule that permitted it.
        const detail = r.outcome === "error" ? r.error || r.reason : r.reason || r.error;
        if (r.decision !== "allow" || r.outcome !== "completed") log(`${" ".repeat(26)}${detail ?? ""}`);
      }
    });
  });

/* ----------------------------------------------------------------------- scan */

program
  .command("scan")
  .description("Scan a generated server's tools.json against its policy.")
  .option("-t, --tools <file>", "tool descriptor file", "tools.json")
  .option("-p, --policy <file>", "policy file", "policy.yaml")
  .option("--sarif <file>", "also write SARIF")
  .option("--md <file>", "also write markdown")
  .option("--baseline <file>", "accept findings recorded in this baseline")
  .option("--allow-high", "exit 0 even with a high-severity finding", false)
  .action((options) => {
    run(() => {
      const toolsPath = resolve(options.tools as string);
      if (!existsSync(toolsPath)) throw new CliError(`no tool descriptor file at ${toolsPath}`);

      const descriptor = JSON.parse(readFileSync(toolsPath, "utf8")) as {
        api?: { title?: string; base_url?: string };
        tools?: {
          name: string;
          description?: string;
          effect?: ScanTool["effect"];
          method?: string;
          path?: string;
          inputSchema?: unknown;
          tenantParams?: string[];
          paginationCap?: unknown;
        }[];
      };

      const policy = existsSync(resolve(options.policy as string))
        ? loadPolicy(options.policy as string)
        : defaultPolicy();

      const tools: ScanTool[] = (descriptor.tools ?? []).map((t) => ({
        name: t.name,
        description: t.description ?? "",
        effect: t.effect,
        method: t.method,
        path: t.path,
        inputSchema: t.inputSchema,
        tenantParams: t.tenantParams,
        hasPaginationCap: t.paginationCap !== undefined
      }));

      const result = scan(
        {
          kind: "generated",
          file: options.tools as string,
          policy,
          tools,
          api: descriptor.api?.base_url
            ? { title: descriptor.api.title ?? "api", base_url: descriptor.api.base_url }
            : undefined
        },
        { baseline: readBaseline(options.baseline as string | undefined) }
      );

      process.stdout.write(toText(result, toolsPath));
      if (options.sarif) {
        writeFileSync(resolve(options.sarif as string), toSarif(result, toolsPath), "utf8");
        log(`SARIF written to ${options.sarif}`);
      }
      if (options.md) {
        writeFileSync(resolve(options.md as string), toMarkdown(result, toolsPath), "utf8");
        log(`Markdown written to ${options.md}`);
      }
      if (!result.ok && !options.allowHigh) process.exitCode = 1;
    });
  });

/* ---------------------------------------------------------------------- policy */

program
  .command("policy")
  .description("Validate a policy file and print the effective settings, defaults included.")
  .argument("[file]", "policy file", "policy.yaml")
  .action((file: string) => {
    run(() => {
      const policy = loadPolicy(file);
      log(`${resolve(file)} is valid.`);
      log("");
      log(`posture:        ${policy.defaults.mode} (unclassified tools: ${policy.defaults.on_unclassified})`);
      log(`rules:          ${policy.rules.length}`);
      for (const rule of policy.rules) {
        log(`  ${rule.id.padEnd(26)} ${rule.match.padEnd(22)} ${rule.decision}${rule.effect ? ` as ${rule.effect}` : ""}`);
      }
      log(
        `tenant:         ${policy.tenant ? `${policy.tenant.field} from ${policy.tenant.source.kind}` : "not configured"}`
      );
      log(`egress allow:   ${policy.egress.allow.length > 0 ? policy.egress.allow.join(", ") : "(nothing)"}`);
      log(`egress methods: ${policy.egress.methods.join(", ")}`);
      log(`body cap:       ${policy.egress.max_body_bytes} bytes`);
      log(`private IPs:    ${policy.egress.block_private_ips ? "blocked" : "ALLOWED"}`);
      log(`approvals:      ${policy.approvals.mode}, ttl ${policy.approvals.ttl_seconds}s, single-use ${policy.approvals.single_use}`);
      log(`audit:          ${policy.audit.enabled ? expandPath(policy.audit.path) : "DISABLED"}${policy.audit.hash_chain ? " (hash-chained)" : ""}`);
      log(`tool budget:    ${policy.tool_budget}`);
    });
  });

/* ---------------------------------------------------------------------- shared */

function resolvePolicy(options: Record<string, unknown>): Policy {
  const path = options["policy"] as string | undefined;
  if (path) return loadPolicy(path);
  if (existsSync("policy.yaml")) return parsePolicy(parseYaml(readFileSync("policy.yaml", "utf8")), "policy.yaml");
  return defaultPolicy();
}

function openStore(options: Record<string, unknown>): ApprovalStore {
  const override = options["store"] as string | undefined;
  return new ApprovalStore(override ?? resolvePolicy(options).approvals.store_path);
}

function auditPath(options: Record<string, unknown>): string {
  const override = options["file"] as string | undefined;
  return expandPath(override ?? resolvePolicy(options).audit.path);
}

function readBaseline(path: string | undefined) {
  if (!path) return undefined;
  const full = resolve(path);
  if (!existsSync(full)) throw new CliError(`no baseline file at ${full}`);
  return JSON.parse(readFileSync(full, "utf8")) as never;
}

function actor(): string {
  return process.env["HMCP_ACTOR"] ?? process.env["USER"] ?? "unknown";
}

class CliError extends Error {}

function log(message: string): void {
  process.stdout.write(`${message}\n`);
}

function run(fn: () => void): void {
  try {
    fn();
  } catch (err) {
    if (err instanceof CliError || err instanceof PolicyError) {
      process.stderr.write(`\nerror: ${err.message}\n`);
      process.exit(1);
    }
    throw err;
  }
}

program.parse(process.argv);
