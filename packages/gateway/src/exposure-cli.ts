import {
  ApprovalStore,
  AuditLog,
  NO_TENANT,
  applyExposureChange,
  normalizeTenantKey,
  parseExposureChange,
  requireTenant,
  type ToolExposureRow
} from "@hmcp/core";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { loadGatewayConfig } from "./config.js";
import { Gateway } from "./gateway.js";

/**
 * Flipping a gateway's exposure switch from a terminal.
 *
 * The admin API is for a customer of a hosted gateway. This is for the
 * person who owns the machine, and it exists for the cases that one cannot
 * serve: a gateway with no identity provider configured at all, a gateway
 * speaking stdio, and the incident where the identity provider is itself the
 * thing that is down. A kill switch reachable only through a dependency is
 * not much of a kill switch.
 *
 * Factored out of `cli.ts` so the tests can call it rather than shelling out,
 * which is how every other gateway test works.
 */

export interface ExposureCommandOptions {
  readonly config: string;
  readonly action: "list" | "off" | "on";
  readonly tool?: string | undefined;
  readonly tenant?: string | undefined;
  readonly reason?: string | undefined;
  /** Skip connecting upstreams, and so skip validating the tool name. */
  readonly force?: boolean | undefined;
  readonly json?: boolean | undefined;
  /** Injected by the CLI; the tests capture it. */
  readonly write?: (line: string) => void;
}

export class ExposureCommandError extends Error {}

/** A human at a terminal with the database file: the OS user really is who. */
function operator(): string {
  return process.env["HMCP_ACTOR"] ?? process.env["USER"] ?? "operator";
}

/**
 * Which tenant's switch this is.
 *
 * Under `jwt-verified` there is no process tenant to resolve — the running
 * gateway gets one per request — so the operator has to say. Guessing `""`
 * here would write a row the gateway never reads, which looks exactly like
 * protection and is none: the most likely bug in this whole design, and the
 * reason this refuses rather than defaults.
 */
function resolveTenantKey(
  policy: ReturnType<typeof loadGatewayConfig>["policy"],
  supplied: string | undefined
): string {
  if (supplied !== undefined) return normalizeTenantKey(supplied);
  if (!policy.tenant) return NO_TENANT;
  if (policy.tenant.source.kind === "jwt-verified") {
    throw new ExposureCommandError(
      "this gateway resolves its tenant from each caller's token, so there is no single tenant to act on. " +
        "Pass --tenant <id> to say whose switch you mean."
    );
  }
  return normalizeTenantKey(requireTenant(policy.tenant) ?? NO_TENANT);
}

function describe(row: ToolExposureRow): string {
  return `${row.tool}  off since ${new Date(row.set_at).toISOString()} by ${row.set_by}${
    row.reason ? ` — ${row.reason}` : ""
  }`;
}

export async function runExposureCommand(options: ExposureCommandOptions): Promise<void> {
  const write = options.write ?? ((line: string) => process.stdout.write(`${line}\n`));
  const { config, policy } = loadGatewayConfig(options.config);
  const tenant = resolveTenantKey(policy, options.tenant);
  const cwd = dirname(options.config);
  const component = `gateway:${config.name}`;

  const store = new ApprovalStore(policy.approvals.store_path, cwd);
  const scoped = store.scoped({ component, tenant });

  /*
   * Connecting spawns or dials every upstream, which is how the tool names
   * are known. `--force` skips it precisely because in an incident the
   * upstream may be the broken thing, and starting it just to flip a bit is
   * the wrong trade.
   */
  let gateway: Gateway | undefined;
  let names: string[] | undefined;
  if (options.action !== "list" && options.force) {
    write(`[hmcp-gateway] --force: not connecting upstreams, so "${options.tool}" is taken on trust`);
  } else {
    gateway = new Gateway({ config, policy, cwd });
    await gateway.connectUpstreams();
    names = gateway.inventory().map((e) => e.localName);
  }

  try {
    if (options.action === "list") {
      const rows = scoped.listDisabledTools();
      if (options.json) {
        write(JSON.stringify({ component, tenant, disabled: rows }, null, 2));
        return;
      }
      write(`${component}${tenant ? ` / ${tenant}` : " (no tenant)"}`);
      if (rows.length === 0) {
        write("  nothing is switched off.");
      } else {
        for (const row of rows) write(`  ${describe(row)}`);
      }
      if (names) write(`  ${names.length} tool(s) exposed upstream.`);
      return;
    }

    const tool = options.tool!;
    if (names && !names.includes(tool)) {
      throw new ExposureCommandError(
        `this gateway exposes no tool named "${tool}". Run "hmcp-gateway tools" to see what it does, ` +
          `or pass --force if the upstream is down and you are sure of the name.`
      );
    }

    const change = parseExposureChange({
      tool,
      disabled: options.action === "off",
      reason: options.reason ?? ""
    });
    const { changed, warning } = applyExposureChange({
      scoped,
      audit: new AuditLog({
        config: policy.audit,
        session: `cli:${randomUUID()}`,
        component,
        actor: operator(),
        cwd
      }),
      change,
      actor: operator(),
      effect: gateway?.inventory().find((e) => e.localName === tool)?.effect ?? null,
      channel: "the gateway CLI"
    });

    if (!changed) {
      write(`${tool} was already ${options.action === "off" ? "switched off" : "on"}; nothing changed.`);
    } else if (options.action === "off") {
      write(`${tool} is switched off for ${tenant || "this gateway"}. It takes effect on the next call; no restart.`);
    } else {
      write(`${tool} is handed back to policy, which may still refuse it.`);
    }
    if (warning) write(`warning: ${warning}`);
  } finally {
    store.close();
    if (gateway) await gateway.close().catch(() => undefined);
  }
}
