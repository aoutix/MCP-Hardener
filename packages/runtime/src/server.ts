import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { parse as parseYaml } from "yaml";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ApprovalBroker,
  ApprovalStore,
  AuditLog,
  EgressGuard,
  expandPath,
  exposureDeniedReason,
  parsePolicy,
  policyDigest,
  requireTenant,
  type ElicitFn,
  type Policy
} from "@hmcp/core";
import { parseToolsFile, type ToolDescriptor, type ToolsFile } from "./descriptor.js";
import { toZod } from "./schema.js";
import { buildRequest, clampPagination } from "./request.js";
import { enforceCall } from "./enforce.js";

/**
 * `registerTool` infers its callback's argument type from a Zod *shape*. We
 * supply a complete strict schema instead, which is what makes undeclared
 * arguments an error rather than silently stripped - so the inference is
 * bypassed here deliberately, with the validated arguments typed as a plain
 * record. Validation still happens in the SDK against the schema we pass.
 */
type ToolRegistrar = (
  name: string,
  config: {
    description: string;
    inputSchema: unknown;
    annotations: Record<string, unknown>;
  },
  callback: (
    args: Record<string, unknown>
  ) => Promise<{ isError?: boolean; content: { type: "text"; text: string }[] }>
) => RegisteredTool;

/** The slice of the SDK's handle we use: hiding a tool from `tools/list`. */
interface RegisteredTool {
  enabled: boolean;
  enable(): void;
  disable(): void;
}

export interface HardenedServerOptions {
  readonly tools: ToolsFile;
  readonly policy: Policy;
  /** Overrides the base URL in the descriptor file. */
  readonly baseUrl?: string | undefined;
  readonly cwd?: string;
  /**
   * How often to re-read the console's exposure overrides, in milliseconds.
   * 0 disables polling, leaving the per-call check as the only trigger.
   */
  readonly exposurePollMs?: number;
  /**
   * Where the policy was read from, recorded so the console can name the file
   * when what this process is enforcing has drifted from what is on disk.
   * Absent for a policy supplied inline, which has no file to name.
   */
  readonly policyPath?: string;
}

/**
 * An MCP server over a REST API in which every tool call passes through the
 * shared enforcement pipeline. Read-only by default, tenant-scoped, writes held
 * for approval, egress limited, every outcome recorded.
 */
export class HardenedServer {
  readonly server: McpServer;
  private readonly tools: ToolsFile;
  private readonly policy: Policy;
  private readonly egress: EgressGuard;
  private readonly audit: AuditLog;
  private readonly approvalStore: ApprovalStore;
  private readonly session = randomUUID();
  private readonly baseUrl: string;
  private tenantValue: string | undefined;
  /** The audit `component`, which is also the key exposure overrides use. */
  private readonly component: string;
  /** SDK handles, so a tool switched off in the console can be hidden. */
  private readonly registered = new Map<string, RegisteredTool>();
  private readonly exposurePollMs: number;
  private exposureTimer: NodeJS.Timeout | undefined;

  constructor(options: HardenedServerOptions) {
    this.tools = options.tools;
    this.policy = options.policy;
    this.baseUrl = options.baseUrl ?? options.tools.api.base_url;

    if (!this.baseUrl) {
      throw new Error(
        "no upstream base URL: set it in the spec's servers list, in tools.json, or with HMCP_BASE_URL"
      );
    }

    // Resolved once at startup so a missing tenant fails loudly here rather
    // than turning into an unscoped query later.
    this.tenantValue = this.policy.tenant ? requireTenant(this.policy.tenant) : undefined;

    this.egress = new EgressGuard(this.policy.egress);
    this.component = `generated:${options.tools.api.title}`;
    this.audit = new AuditLog({
      config: this.policy.audit,
      session: this.session,
      component: this.component,
      cwd: options.cwd
    });
    this.approvalStore = new ApprovalStore(this.policy.approvals.store_path, options.cwd);

    this.server = new McpServer(
      { name: `hmcp-${slug(options.tools.api.title)}`, version: options.tools.api.version },
      {
        instructions:
          `Hardened MCP server for ${options.tools.api.title}. ` +
          `Posture: ${this.policy.defaults.mode}. ` +
          `Calls that mutate state may require human approval, and refusals explain which policy rule applied. ` +
          `Tool arguments are validated and bounded; a refusal is not a reason to retry with different arguments.`
      }
    );

    for (const descriptor of options.tools.tools) {
      this.register(descriptor);
    }
    // A tool switched off before this process started must not be advertised
    // even once, so the first sync happens here rather than on the first call.
    this.exposurePollMs = options.exposurePollMs ?? 2000;
    this.syncExposure();
    this.announce(options.policyPath ?? "");
  }

  /**
   * Records which policy this process parsed, for the console to compare
   * against what is on disk now.
   *
   * Best-effort on purpose: this is a claim about configuration, not a part of
   * enforcing it, so a database that cannot be written must not stop a server
   * from starting. The console treats a missing row as "unknown" and says so,
   * which is the same thing a failure here produces.
   */
  private announce(policyPath: string): void {
    try {
      this.approvalStore.recordRuntimeState({
        component: this.component,
        pid: process.pid,
        started_at: Date.now(),
        policy_digest: policyDigest(this.policy),
        policy_path: policyPath
      });
    } catch {
      /* ignored: advisory only */
    }
  }

  /**
   * Brings the advertised tool set in line with the exposure overrides.
   *
   * The console writes those rows while this process is running, so this is
   * called at startup, on a short timer, and again at the top of every tool
   * call: a toggle takes effect without restarting the server, and the SDK
   * emits `notifications/tools/list_changed` so a connected client re-reads
   * the list. The timer is what covers a tool being switched back *on*, since
   * a call to a hidden tool is rejected by the SDK before our own code runs.
   *
   * Hiding a tool is presentation. It is not what stops the call: `decide()`
   * refuses a disabled tool whatever the advertised list happens to say, which
   * is what covers the window between a toggle and the next sync.
   */
  private syncExposure(): void {
    let disabled: ReadonlySet<string>;
    try {
      // The same poll doubles as the liveness beat: it already runs at the
      // right cadence and already has the database open, so a reader can tell
      // a running server's claim from one a dead process left behind.
      this.approvalStore.touchRuntimeState(this.component, process.pid);
      disabled = new Set(this.approvalStore.listDisabledTools(this.component).map((r) => r.tool));
    } catch {
      // The store is unreadable. Leave the advertised list alone rather than
      // guessing in either direction; the per-call check below reads it again
      // and a failure there refuses the call.
      return;
    }
    for (const [name, tool] of this.registered) {
      const shouldBeEnabled = !disabled.has(name);
      if (tool.enabled !== shouldBeEnabled) {
        if (shouldBeEnabled) tool.enable();
        else tool.disable();
      }
    }
  }

  /**
   * The override for one tool, or undefined.
   *
   * A store that cannot be read is treated as "switched off": an exposure
   * override can only ever refuse, so failing closed here costs availability
   * and never reachability.
   */
  private exposureBlock(tool: string): { reason: string } | undefined {
    try {
      const row = this.approvalStore.toolExposure(this.component, tool);
      return row ? { reason: exposureDeniedReason(row) } : undefined;
    } catch (err) {
      return {
        reason:
          `the exposure overrides could not be read (${(err as Error).message}), ` +
          "so this call is refused rather than assumed to be permitted"
      };
    }
  }

  /** Elicitation is used only when the connected host says it supports it. */
  private elicitFn(): ElicitFn | undefined {
    const capabilities = this.server.server.getClientCapabilities();
    if (!capabilities?.elicitation) return undefined;
    return async (request) =>
      this.server.server.elicitInput({
        mode: "form",
        message: request.message,
        requestedSchema: request.requestedSchema as never
      }) as never;
  }

  private broker(): ApprovalBroker {
    return new ApprovalBroker({
      config: this.policy.approvals,
      store: this.approvalStore,
      elicit: this.elicitFn(),
      redactKeys: this.policy.audit.redact
    });
  }

  private register(descriptor: ToolDescriptor): void {
    const registerTool = this.server.registerTool.bind(this.server) as unknown as ToolRegistrar;

    const handle = registerTool(
      descriptor.name,
      {
        description: descriptor.description,
        // The full schema is passed, not a shape: a shape is assembled into a
        // non-strict object that silently strips undeclared arguments, whereas
        // this rejects them and tells the agent why. That matters for a tenant
        // field - "there is no such argument" is better feedback than silence.
        inputSchema: toZod(descriptor.inputSchema),
        annotations: {
          title: descriptor.name,
          readOnlyHint: descriptor.annotations.readOnlyHint ?? descriptor.effect === "read",
          destructiveHint: descriptor.annotations.destructiveHint ?? descriptor.effect === "destructive",
          idempotentHint: descriptor.annotations.idempotentHint
        }
      },
      async (rawArgs) => {
        // Picks up a toggle made since the last call, and republishes the list.
        this.syncExposure();
        const disabled = this.exposureBlock(descriptor.name);

        // The schema already bounds a supplied page size; this fills in a
        // ceiling when the agent omitted one, so no call is unbounded.
        const args = clampPagination(descriptor, rawArgs ?? {});

        const outcome = await enforceCall(
          {
            policy: this.policy,
            audit: this.audit,
            approvals: this.broker(),
            tenantValue: this.tenantValue,
            actor: "agent",
            session: this.session
          },
          {
            tool: descriptor.name,
            effect: descriptor.effect,
            args,
            ...(disabled ? { disabled } : {}),
            target: `${descriptor.method} ${this.baseUrl}${descriptor.path}`,
            run: async () => {
              const request = buildRequest({
                descriptor,
                args,
                baseUrl: this.baseUrl,
                auth: this.tools.auth,
                tenant:
                  this.policy.tenant && this.tenantValue
                    ? { config: this.policy.tenant, value: this.tenantValue }
                    : undefined
              });

              const response = await this.egress.fetch(request.url, {
                method: request.method,
                headers: request.headers,
                body: request.body
              });

              const host = new URL(request.url).host;
              return {
                result: response,
                upstream: {
                  host,
                  method: request.method,
                  path: request.auditPath,
                  status: response.status,
                  bytes: response.bytes
                }
              };
            }
          }
        );

        if (outcome.kind === "refused") {
          return { isError: true, content: [{ type: "text" as const, text: outcome.message }] };
        }

        const response = outcome.result;
        const text = response.body.toString("utf8");
        const prefix =
          response.status >= 400
            ? `Upstream returned HTTP ${response.status}.\n\n`
            : "";
        return {
          isError: response.status >= 400,
          content: [{ type: "text" as const, text: `${prefix}${text || "(empty response)"}` }]
        };
      }
    );

    this.registered.set(descriptor.name, handle);
  }

  /** Connects over stdio, or over a supplied transport (used by tests). */
  async connect(transport?: Parameters<McpServer["connect"]>[0]): Promise<void> {
    await this.server.connect(transport ?? new StdioServerTransport());
    if (this.exposurePollMs > 0) {
      this.exposureTimer = setInterval(() => this.syncExposure(), this.exposurePollMs);
      // Unreferenced, so a poll for a local file never keeps the process alive.
      this.exposureTimer.unref?.();
    }
  }

  async close(): Promise<void> {
    if (this.exposureTimer) clearInterval(this.exposureTimer);
    await this.server.close();
    await this.egress.close();
    this.approvalStore.close();
  }
}

/** Boots a generated server from its two data files. */
export async function startFromFiles(options: {
  toolsPath: string;
  policyPath: string;
  baseUrl?: string | undefined;
  cwd?: string;
}): Promise<HardenedServer> {
  const toolsRaw = JSON.parse(readFileSync(expandPath(options.toolsPath, options.cwd), "utf8")) as unknown;
  const policyRaw = parseYaml(readFileSync(expandPath(options.policyPath, options.cwd), "utf8")) as unknown;

  const server = new HardenedServer({
    tools: parseToolsFile(toolsRaw, options.toolsPath),
    policy: parsePolicy(policyRaw, options.policyPath),
    baseUrl: options.baseUrl ?? process.env["HMCP_BASE_URL"],
    cwd: options.cwd,
    policyPath: options.policyPath
  });
  await server.connect();
  return server;
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "") || "api";
}
