import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ApprovalStore, policyDigest, type Policy, type ToolInventoryInput } from "@hmcp/core";
import type { RegistryEntry } from "@hmcp/core";

/**
 * A registered gateway, for the console's tests.
 *
 * The console never connects a gateway's upstreams, so the upstream command
 * here is never run and does not need to exist. What the console *does* read is
 * the config, and whatever the gateway published into the approvals database —
 * so a test stands in for a running gateway by publishing, exactly as
 * `announceServing` does, rather than by writing a file the console parses.
 */
export interface GatewayFixture {
  readonly dir: string;
  readonly configPath: string;
  readonly storePath: string;
  readonly auditPath: string;
  readonly component: string;
  readonly entry: RegistryEntry;
}

export interface GatewayFixtureOptions {
  readonly name?: string;
  readonly id?: string;
  /** Extra keys inside the policy's `egress:` block. */
  readonly egressLines?: readonly string[];
  /** Extra keys at the top level of the inline `policy:` block. */
  readonly policyLines?: readonly string[];
  readonly hashChain?: boolean;
  readonly tenant?: readonly string[];
  /**
   * An extra HTTP upstream carrying this static header value, for asserting the
   * console never echoes an upstream's credential.
   */
  readonly upstreamSecret?: string;
  readonly mode?: string;
  readonly approvalsMode?: string;
  readonly audit?: boolean;
  readonly rules?: readonly string[];
}

export function writeGatewayFixture(dir: string, options: GatewayFixtureOptions = {}): GatewayFixture {
  const name = options.name ?? "notes";
  const id = options.id ?? "gw";
  const storePath = join(dir, "approvals.sqlite");
  const auditPath = join(dir, "audit.jsonl");
  const configPath = join(dir, "gateway.yaml");
  mkdirSync(dir, { recursive: true });

  const rules =
    options.rules ?? ["- id: allow-reads", '  match: "get_*"', "  effect: read", "  decision: allow"];

  writeFileSync(
    configPath,
    [
      "version: 1",
      `name: ${name}`,
      "upstreams:",
      "  - name: notes",
      "    transport: stdio",
      "    command: node",
      '    args: ["--version"]',
      ...(options.upstreamSecret
        ? [
            "  - name: billing",
            "    transport: http",
            "    url: https://api.example.com/mcp",
            "    headers:",
            `      authorization: "Bearer ${options.upstreamSecret}"`
          ]
        : []),
      "on_injection: strip",
      "namespace: false",
      "policy:",
      "  version: 1",
      "  defaults:",
      `    mode: ${options.mode ?? "read-only"}`,
      ...(options.policyLines ?? []).map((line) => `  ${line}`),
      "  rules:",
      ...rules.map((line) => `    ${line}`),
      ...(options.tenant ?? []).map((line) => `  ${line}`),
      "  egress:",
      '    allow: ["api.example.com"]',
      ...(options.egressLines ?? []).map((line) => `    ${line}`),
      "  approvals:",
      `    mode: ${options.approvalsMode ?? "cli"}`,
      `    store_path: ${storePath}`,
      "  audit:",
      `    enabled: ${options.audit ?? false}`,
      `    path: ${auditPath}`,
      ...(options.hashChain ? ["    hash_chain: true"] : []),
      ""
    ].join("\n")
  );

  return {
    dir,
    configPath,
    storePath,
    auditPath,
    component: `gateway:${name}`,
    entry: {
      id,
      kind: "gateway",
      label: "Notes gateway",
      config_path: configPath,
      added_at: new Date().toISOString()
    }
  };
}

/** One upstream tool, in the shape a gateway publishes. */
export function tool(name: string, over: Partial<ToolInventoryInput> = {}): ToolInventoryInput {
  return {
    tool: name,
    upstream: "notes",
    effect: "read",
    effectSource: "policy",
    description: `${name} does a thing.`,
    rawDescription: `${name} does a thing.`,
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    hidden: false,
    injection: null,
    ...over
  };
}

/**
 * Stands in for a running gateway: publishes a surface and announces liveness.
 *
 * Both halves matter. A console trusts an inventory only when a live
 * `runtime_state` row names the same pid that wrote it, so a test that
 * published without announcing would be testing the stale path.
 */
export function publishSurface(
  fixture: GatewayFixture,
  tools: readonly ToolInventoryInput[],
  options: { pid?: number; policy?: Policy; lastSeen?: number; digest?: string } = {}
): void {
  const store = new ApprovalStore(fixture.storePath);
  const pid = options.pid ?? 4242;
  const lastSeen = options.lastSeen ?? Date.now();
  store.publishInventory(fixture.component, pid, tools);
  store.recordRuntimeState({
    component: fixture.component,
    pid,
    started_at: lastSeen,
    last_seen: lastSeen,
    policy_digest: options.digest ?? (options.policy ? policyDigest(options.policy) : "unknown"),
    policy_path: fixture.configPath
  });
  store.close();
}
