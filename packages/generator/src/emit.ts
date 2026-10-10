import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { stringify as stringifyYaml } from "yaml";
import type { Policy } from "@hmcp/core";
import type { Auth, ToolDescriptor, ToolsFile } from "@hmcp/server-runtime";
import type { ScanTool } from "@hmcp/scanner";
import { buildDescriptor, DEFAULT_CAPS, type NarrowCaps } from "./narrow.js";
import type { Manifest, Operation, ParsedSpec } from "./types.js";

export interface EmitOptions {
  readonly manifest: Manifest;
  readonly spec: ParsedSpec;
  readonly policy: Policy;
  readonly outDir: string;
  readonly baseUrl?: string | undefined;
  readonly auth?: Auth | undefined;
  readonly caps?: NarrowCaps;
  /** Written into the generated policy.yaml; defaults to the policy as loaded. */
  readonly policySource?: string | undefined;
  /**
   * Dependency specifier for the runtime in the generated package.json. A
   * version range once the package is published, or a `file:` path to a local
   * checkout, which is what makes the generated project installable today.
   */
  readonly runtimeSpecifier?: string | undefined;
  /** Operation ids the spec exposes without declaring authentication. */
  readonly operationsWithoutSecurity?: readonly string[] | undefined;
}

export interface EmitResult {
  readonly toolsFile: ToolsFile;
  readonly files: readonly string[];
  readonly omitted: readonly {
    readonly tool: string;
    readonly param: string;
    readonly in: string;
    readonly reason: string;
  }[];
  /** Normalized view handed to the scanner. */
  readonly scanTools: readonly ScanTool[];
}

/**
 * Writes the generated server project.
 *
 * The emitted artifact is deliberately data plus a small bootstrap, not
 * thousands of lines of generated enforcement code: a reviewer reads one
 * declarative tool manifest, and the code that enforces policy is the shared,
 * tested runtime rather than a per-generation copy that can drift.
 */
export function emit(options: EmitOptions): EmitResult {
  const { manifest, spec, policy, outDir } = options;
  const caps = options.caps ?? DEFAULT_CAPS;

  const operationsById = new Map<string, Operation>();
  /*
   * Where each operation sits in the spec, so a manifest written before
   * `spec_index` existed still produces a tool surface that can be shown in
   * spec order. The manifest's own value wins where it has one — it was
   * recorded against the spec that was current when the manifest was reviewed
   * — and this is the fallback, derived from the spec being built against.
   * Without it, "spec order" would only ever work for a surface that had been
   * re-planned, not merely rebuilt.
   */
  const specIndexByOperation = new Map<string, number>();
  for (const [index, operation] of spec.operations.entries()) {
    const key = operationKey(operation.method, operation.path);
    operationsById.set(key, operation);
    specIndexByOperation.set(key, index);
  }

  const descriptors: ToolDescriptor[] = [];
  const omitted: { tool: string; param: string; in: string; reason: string }[] = [];

  for (const tool of manifest.tools) {
    if (!tool.enabled) continue;
    const operation = operationsById.get(operationKey(tool.method, tool.path));
    if (!operation) {
      throw new Error(
        `manifest tool "${tool.name}" refers to ${tool.method} ${tool.path}, which is not in ${spec.sourcePath}. ` +
          `Re-run "hmcp-gen plan" against the current spec.`
      );
    }
    const built = buildDescriptor({
      operation,
      tool: {
        ...tool,
        spec_index: tool.spec_index ?? specIndexByOperation.get(operationKey(tool.method, tool.path))
      },
      tenant: policy.tenant,
      caps
    });
    descriptors.push(built.descriptor);
    for (const entry of built.omitted) {
      omitted.push({ tool: tool.name, param: entry.name, in: entry.in, reason: entry.reason });
    }
  }

  const baseUrl = options.baseUrl ?? manifest.api.base_url ?? spec.servers[0] ?? "";
  const toolsFile: ToolsFile = {
    version: 1,
    generated_by: "hmcp-gen",
    generated_at: new Date().toISOString(),
    api: { title: manifest.api.title, version: manifest.api.version, base_url: baseUrl },
    auth: options.auth ?? inferAuth(spec),
    tools: descriptors,
    // What the generator declined to expose. `plan` prints this and then it
    // used to be lost; persisting it lets a reviewer see the operations an
    // agent cannot reach, which is as much a part of the surface as the ones
    // it can.
    generation: {
      spec_format: spec.originalFormat,
      has_security_schemes: spec.hasSecuritySchemes,
      operations_without_security: [...(options.operationsWithoutSecurity ?? [])],
      skipped: [
        ...(manifest.skipped ?? []),
        ...manifest.tools
          .filter((t) => !t.enabled)
          .map((t) => ({ tool: t.name, reason: "left off in the manifest" }))
      ]
    }
  };

  mkdirSync(outDir, { recursive: true });
  const files: string[] = [];
  const write = (relative: string, content: string) => {
    const full = join(outDir, relative);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content, "utf8");
    files.push(relative);
  };

  write("tools.json", JSON.stringify(toolsFile, null, 2) + "\n");
  write("policy.yaml", options.policySource ?? stringifyYaml(policy));
  write("package.json", packageJson(toolsFile, options.runtimeSpecifier ?? "^0.1.0"));
  write("server.mjs", bootstrap());
  write(".env.example", envExample(toolsFile, policy));
  write("README.md", readme(toolsFile, policy, omitted, options.runtimeSpecifier ?? "^0.1.0"));

  return { toolsFile, files, omitted, scanTools: descriptors.map(toScanTool) };
}

function toScanTool(descriptor: ToolDescriptor): ScanTool {
  return {
    name: descriptor.name,
    description: descriptor.description,
    effect: descriptor.effect,
    method: descriptor.method,
    path: descriptor.path,
    inputSchema: descriptor.inputSchema,
    tenantParams: descriptor.tenantParams,
    hasPaginationCap: descriptor.paginationCap !== undefined
  };
}

function operationKey(method: string, path: string): string {
  return `${method.toUpperCase()} ${path}`;
}

/** Derives the credential shape from the spec's first security scheme. */
function inferAuth(spec: ParsedSpec): Auth {
  const envName = `${envPrefix(spec.title)}_TOKEN`;
  for (const scheme of Object.values(spec.securitySchemes)) {
    if (scheme.type === "http" && scheme.scheme === "bearer") return { kind: "bearer", env: envName };
    if (scheme.type === "http" && scheme.scheme === "basic") return { kind: "basic", env: envName };
    if (scheme.type === "apiKey" && scheme.in === "header" && scheme.name) {
      return { kind: "header", env: envName, name: scheme.name };
    }
    if (scheme.type === "apiKey" && scheme.in === "query" && scheme.name) {
      return { kind: "query", env: envName, name: scheme.name };
    }
    if (scheme.type === "oauth2" || scheme.type === "openIdConnect") {
      // The server presents an access token it is given; it does not run a flow.
      return { kind: "bearer", env: envName };
    }
  }
  return { kind: "none" };
}

export function envPrefix(title: string): string {
  return (
    title
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, "_")
      .replace(/^_|_$/g, "")
      .slice(0, 24) || "API"
  );
}

function packageJson(tools: ToolsFile, runtimeSpecifier: string): string {
  return (
    JSON.stringify(
      {
        name: `hmcp-${slug(tools.api.title)}`,
        version: tools.api.version === "0.0.0" ? "0.1.0" : tools.api.version,
        private: true,
        type: "module",
        description: `Hardened MCP server for ${tools.api.title}, generated by hmcp-gen`,
        bin: { [`hmcp-${slug(tools.api.title)}`]: "./server.mjs" },
        scripts: {
          start: "node server.mjs",
          scan: "hmcp scan --tools tools.json --policy policy.yaml"
        },
        dependencies: { "@hmcp/server-runtime": runtimeSpecifier }
      },
      null,
      2
    ) + "\n"
  );
}

function bootstrap(): string {
  return `#!/usr/bin/env node
// Generated by hmcp-gen. The tool surface lives in tools.json and the policy in
// policy.yaml; enforcement lives in @hmcp/server-runtime, which both this
// server and hmcp-gateway share. Edit the two data files, not this bootstrap.
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { startFromFiles } from "@hmcp/server-runtime";

const here = dirname(fileURLToPath(import.meta.url));

try {
  await startFromFiles({
    toolsPath: join(here, "tools.json"),
    policyPath: process.env.HMCP_POLICY ?? join(here, "policy.yaml"),
    baseUrl: process.env.HMCP_BASE_URL,
    cwd: here
  });
} catch (err) {
  // stdio carries the protocol, so diagnostics go to stderr.
  process.stderr.write(\`[hmcp] failed to start: \${err?.message ?? err}\\n\`);
  process.exit(1);
}
`;
}

function envExample(tools: ToolsFile, policy: Policy): string {
  const lines = [`# Environment for ${tools.api.title}.`, `# Secrets are read at call time and never logged.`, ""];
  if (tools.auth.kind !== "none") {
    lines.push(`# Upstream credential (${tools.auth.kind}).`);
    lines.push(`${tools.auth.env}=`);
    lines.push("");
  }
  if (policy.tenant && policy.tenant.source.kind === "env") {
    lines.push(`# Tenant this server is bound to. Every call is scoped to it.`);
    lines.push(`${policy.tenant.source.name}=`);
    lines.push("");
  }
  if (policy.tenant && policy.tenant.source.kind === "jwt-claim") {
    lines.push(`# Token whose "${policy.tenant.source.name}" claim is the tenant.`);
    lines.push(`${policy.tenant.source.token_env}=`);
    lines.push("");
  }
  lines.push(`# Override the upstream base URL (default: ${tools.api.base_url}).`);
  lines.push(`# HMCP_BASE_URL=`);
  lines.push("");
  lines.push(`# Override the policy file.`);
  lines.push(`# HMCP_POLICY=`);
  return lines.join("\n") + "\n";
}

function readme(
  tools: ToolsFile,
  policy: Policy,
  omitted: readonly { tool: string; param: string; reason: string }[],
  runtimeSpecifier: string
): string {
  const byEffect = { read: 0, write: 0, destructive: 0 };
  for (const tool of tools.tools) byEffect[tool.effect]++;

  const lines: string[] = [];
  lines.push(`# ${tools.api.title} (hardened MCP server)`);
  lines.push("");
  lines.push(`Generated by \`hmcp-gen\` from an OpenAPI spec. ${tools.tools.length} tools are exposed:`);
  lines.push(`${byEffect.read} read, ${byEffect.write} write, ${byEffect.destructive} destructive.`);
  lines.push("");
  lines.push("## What is enforced");
  lines.push("");
  lines.push(
    `- **Posture:** \`${policy.defaults.mode}\`. A tool with no effect classification is ` +
      `${policy.defaults.on_unclassified === "deny" ? "refused" : "held for approval"}.`
  );
  lines.push(
    `- **Approvals:** \`${policy.approvals.mode}\`. A grant is bound to the exact arguments it was shown, ` +
      `${policy.approvals.single_use ? "is single-use" : "is reusable"}, and expires after ${policy.approvals.ttl_seconds}s.`
  );
  lines.push(
    `- **Egress:** only ${policy.egress.allow.length > 0 ? policy.egress.allow.map((a) => `\`${a}\``).join(", ") : "nothing (the allowlist is empty)"}, ` +
      `methods ${policy.egress.methods.join("/")}, responses capped at ${policy.egress.max_body_bytes} bytes` +
      `${policy.egress.block_private_ips ? ", private and link-local addresses refused" : ""}.`
  );
  if (policy.tenant) {
    lines.push(
      `- **Tenant scoping:** every call is scoped to \`${policy.tenant.field}\`, resolved from ` +
        `${describeSource(policy.tenant)}. The field is absent from every tool schema, so the model cannot name another tenant.`
    );
  }
  lines.push(`- **Audit:** \`${policy.audit.path}\`${policy.audit.hash_chain ? ", hash-chained" : ""}. Verify with \`hmcp audit verify\`.`);
  lines.push("");
  lines.push("## Running it");
  lines.push("");
  lines.push("```bash");
  lines.push("npm install");
  lines.push("cp .env.example .env   # fill in the credential");
  lines.push("npm start");
  lines.push("```");
  lines.push("");
  if (runtimeSpecifier.startsWith("file:")) {
    lines.push(
      `This project depends on \`@hmcp/server-runtime\` at \`${runtimeSpecifier}\`, a local checkout. ` +
        "Build that checkout before installing here, and re-generate with `--runtime` if it moves."
    );
  } else {
    lines.push(
      `This project depends on \`@hmcp/server-runtime\` at \`${runtimeSpecifier}\`. If that package is not ` +
        "published to your registry, re-generate with `--runtime file:/path/to/hardened-mcp/packages/runtime` " +
        "to install it from a local checkout."
    );
  }
  lines.push("");
  lines.push("Register it with an MCP client by pointing the client at `node server.mjs`.");
  lines.push("");
  lines.push("## Tools");
  lines.push("");
  lines.push("| Tool | Effect | Upstream |");
  lines.push("| --- | --- | --- |");
  for (const tool of tools.tools) {
    lines.push(`| \`${tool.name}\` | ${tool.effect} | \`${tool.method} ${tool.path}\` |`);
  }

  if (omitted.length > 0) {
    lines.push("");
    lines.push("## Parameters withheld from agents");
    lines.push("");
    lines.push("| Tool | Parameter | Why |");
    lines.push("| --- | --- | --- |");
    for (const entry of omitted) {
      lines.push(`| \`${entry.tool}\` | \`${entry.param}\` | ${entry.reason} |`);
    }
  }

  // Tools whose effect the generator inferred rather than knew. Until now this
  // reached only `hmcp-gen plan`'s stdout, so it was gone by the time anyone
  // reviewed the built server - and a misclassified write is exactly what turns
  // a read-only posture into nothing.
  const needsReview = tools.tools.filter((t) => t.review);
  if (needsReview.length > 0) {
    lines.push("");
    lines.push("## Tools a human should confirm");
    lines.push("");
    lines.push("The generator inferred these classifications and could not decide safely.");
    lines.push("");
    lines.push("| Tool | Effect as built | Why it needs a look |");
    lines.push("| --- | --- | --- |");
    for (const tool of needsReview) {
      lines.push(`| \`${tool.name}\` | ${tool.effect} | ${tool.review} |`);
    }
  }

  const skipped = tools.generation?.skipped ?? [];
  if (skipped.length > 0) {
    lines.push("");
    lines.push("## Operations an agent cannot reach");
    lines.push("");
    lines.push(`${skipped.length} operation(s) in the spec were not exposed:`);
    lines.push("");
    for (const entry of skipped) {
      lines.push(`- \`${entry.tool}\` — ${entry.reason}`);
    }
  }

  lines.push("");
  lines.push("## Changing it");
  lines.push("");
  lines.push(
    "Edit `policy.yaml` to change what is permitted, and `tools.json` to change the surface. " +
      "Re-run `npm run scan` afterwards; the scan fails on a high-severity finding."
  );
  return lines.join("\n") + "\n";
}

function describeSource(tenant: NonNullable<Policy["tenant"]>): string {
  switch (tenant.source.kind) {
    case "env":
      return `the \`${tenant.source.name}\` environment variable`;
    case "header":
      return `the \`${tenant.source.name}\` request header`;
    case "jwt-claim":
      return `the \`${tenant.source.name}\` claim of the token in \`${tenant.source.token_env}\``;
    case "static":
      return "a fixed value in the policy";
  }
}

function slug(value: string): string {
  return (
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "") || "api"
  );
}
