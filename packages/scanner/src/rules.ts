import { classifyAddress, decide, findSecrets, isIpLiteral } from "@hmcp/core";
import { findInjection } from "./injection.js";
import type { Finding, Rule, ScanTarget, ScanTool } from "./types.js";

/** Parameter names that look like a tenant boundary. */
const TENANT_HINTS = [
  "tenant_id",
  "tenantid",
  "org_id",
  "orgid",
  "organization_id",
  "organisation_id",
  "account_id",
  "accountid",
  "workspace_id",
  "customer_id",
  "company_id"
];

function schemaProperties(schema: unknown): Record<string, Record<string, unknown>> {
  if (!schema || typeof schema !== "object") return {};
  const props = (schema as Record<string, unknown>)["properties"];
  return props && typeof props === "object" ? (props as Record<string, Record<string, unknown>>) : {};
}

/** Walks a JSON Schema, yielding each node with its dotted path. */
function walkSchema(
  schema: unknown,
  path: string,
  visit: (node: Record<string, unknown>, path: string) => void,
  depth = 0
): void {
  if (!schema || typeof schema !== "object" || depth > 10) return;
  const node = schema as Record<string, unknown>;
  visit(node, path);
  for (const [key, child] of Object.entries(schemaProperties(node))) {
    walkSchema(child, `${path}.${key}`, visit, depth + 1);
  }
  if (node["items"]) walkSchema(node["items"], `${path}[]`, visit, depth + 1);
}

function toolPath(tool: ScanTool, suffix: string): string {
  return `${tool.server ? `${tool.server}.` : ""}${tool.name}.${suffix}`;
}

/** HMCP001 - a tool that mutates state is reachable without approval. */
const unapprovedWrites: Rule = {
  id: "HMCP001",
  severity: "high",
  title: "Write reachable without approval",
  run: (target) => {
    const policy = target.policy;
    if (!policy) return [];
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      if (!tool.effect || tool.effect === "read") continue;
      const decision = decide({ tool: tool.name, effect: tool.effect, args: {}, policy });
      if (decision.kind !== "allow") continue;
      findings.push({
        ruleId: "HMCP001",
        severity: "high",
        title: "Write reachable without approval",
        message:
          `Tool "${tool.name}" is classified ${tool.effect} but policy rule "${decision.ruleId}" allows it outright. ` +
          `An agent can ${tool.effect === "destructive" ? "delete data" : "change data"} with no human in the loop.`,
        fix:
          `Change rule "${decision.ruleId}" to decision: approve (or deny), or narrow its match so it no longer ` +
          `covers "${tool.name}".`,
        location: { file: target.file, path: toolPath(tool, "effect") }
      });
    }
    return findings;
  }
};

/** HMCP002 - tenant scoping is advertised but not actually enforced. */
const tenantScoping: Rule = {
  id: "HMCP002",
  severity: "high",
  title: "Tenant scoping not enforced",
  run: (target) => {
    const findings: Finding[] = [];
    const tenant = target.policy?.tenant;

    for (const tool of target.tools) {
      const names = Object.keys(schemaProperties(tool.inputSchema));
      const declared = new Set((tool.tenantParams ?? []).map((p) => p.toLowerCase()));

      if (tenant) {
        const fields = [tenant.field, ...tenant.aliases].map((f) => f.toLowerCase());
        // The field is still agent-settable, so the model can name a tenant.
        for (const name of names) {
          if (!fields.includes(name.toLowerCase())) continue;
          findings.push({
            ruleId: "HMCP002",
            severity: "high",
            title: "Tenant scoping not enforced",
            message:
              `Tool "${tool.name}" exposes "${name}" as an agent-supplied argument while policy declares ` +
              `${tenant.field} as the tenant boundary. The model can request another tenant's data.`,
            fix:
              `Remove "${name}" from the tool's input schema and list it under tenantParams so the server injects ` +
              `it from the credential.`,
            location: { file: target.file, path: toolPath(tool, `inputSchema.properties.${name}`) }
          });
        }

        // A path placeholder that should be tenant-bound but is not.
        for (const match of (tool.path ?? "").matchAll(/\{([^}]+)\}/g)) {
          const placeholder = match[1]!.trim();
          if (!fields.includes(placeholder.toLowerCase())) continue;
          if (declared.has(placeholder.toLowerCase())) continue;
          findings.push({
            ruleId: "HMCP002",
            severity: "high",
            title: "Tenant scoping not enforced",
            message:
              `Tool "${tool.name}" targets ${tool.path} whose {${placeholder}} segment is the tenant boundary, ` +
              `but it is not bound server-side.`,
            fix: `Add "${placeholder}" to the tool's tenantParams so it is filled from the credential.`,
            location: { file: target.file, path: toolPath(tool, "path") }
          });
        }
      } else {
        // No tenant policy at all, but the surface clearly has tenants.
        const suspects = names.filter((n) => TENANT_HINTS.includes(n.toLowerCase()));
        if (suspects.length > 0) {
          findings.push({
            ruleId: "HMCP002",
            severity: "high",
            title: "Tenant scoping not enforced",
            message:
              `Tool "${tool.name}" accepts ${suspects.map((s) => `"${s}"`).join(", ")}, which looks like a tenant ` +
              `boundary, but the policy declares no tenant scoping. Nothing stops the agent from naming any tenant.`,
            fix:
              `Add a tenant block to the policy naming the field and its source, so the value is injected from the ` +
              `credential instead of accepted as an argument.`,
            location: { file: target.file, path: toolPath(tool, "inputSchema") }
          });
        }
      }
    }
    return findings;
  }
};

/** HMCP003 - a list operation with no ceiling on how much it returns. */
const unboundedList: Rule = {
  id: "HMCP003",
  severity: "medium",
  title: "List operation without a result ceiling",
  run: (target) => {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      if (tool.effect !== "read") continue;
      if (tool.hasPaginationCap) continue;
      const path = tool.path ?? "";
      // A collection route ends in a plural segment rather than an id.
      const isCollection = path.length > 0 && !/\}\/?$/.test(path) && /s\/?$/.test(path);
      const looksLikeList = isCollection || /^(list|search|get_all|find)/.test(tool.name);
      if (!looksLikeList) continue;
      findings.push({
        ruleId: "HMCP003",
        severity: "medium",
        title: "List operation without a result ceiling",
        message:
          `Tool "${tool.name}" returns a collection with no pagination ceiling. A single call can pull an ` +
          `unbounded amount of data into the model's context and out of the upstream.`,
        fix:
          `Expose the operation's pagination parameter with a paginationCap, or lower egress.max_body_bytes so an ` +
          `oversized response is refused.`,
        location: { file: target.file, path: toolPath(tool, "paginationCap") }
      });
    }
    return findings;
  }
};

/** HMCP004 - a secret that leaked out of the spec and into the tool surface. */
const leakedSecrets: Rule = {
  id: "HMCP004",
  severity: "high",
  title: "Secret in the generated tool surface",
  run: (target) => {
    const findings: Finding[] = [];
    const report = (text: string, where: string) => {
      for (const hit of findSecrets(text)) {
        findings.push({
          ruleId: "HMCP004",
          severity: "high",
          title: "Secret in the generated tool surface",
          message:
            `A ${hit.label} appears in ${where}. Anything here is sent to the model and written into transcripts.`,
          fix: `Remove the credential from the source spec and rotate it - treat it as disclosed.`,
          location: { file: target.file, path: where }
        });
      }
    };

    if (target.api?.base_url) report(target.api.base_url, "api.base_url");
    for (const source of target.sourceTexts ?? []) report(source.text, source.path);
    for (const tool of target.tools) {
      report(tool.description, toolPath(tool, "description"));
      walkSchema(tool.inputSchema, toolPath(tool, "inputSchema"), (node, path) => {
        for (const key of ["description", "default", "example"]) {
          const value = node[key];
          if (typeof value === "string") report(value, `${path}.${key}`);
        }
      });
    }
    return findings;
  }
};

/** HMCP005 - prompt injection in text the model will read. */
const promptInjection: Rule = {
  id: "HMCP005",
  severity: "high",
  title: "Prompt injection in tool text",
  run: (target) => {
    const findings: Finding[] = [];
    const origin =
      target.kind === "upstream"
        ? "an upstream MCP server's advertised text"
        : "the source API spec";

    const report = (text: string, where: string) => {
      for (const hit of findInjection(text)) {
        findings.push({
          ruleId: "HMCP005",
          severity: "high",
          title: "Prompt injection in tool text",
          message:
            `Text in ${where} ${hit.label}: ${hit.excerpt}. This text comes from ${origin} and is placed directly ` +
            `in the model's context, so it can steer the agent.`,
          fix:
            target.kind === "upstream"
              ? `Deny this tool in policy, or let the gateway strip the description before advertising it.`
              : `Fix the description in the source spec, or override it in the manifest.`,
          location: { file: target.file, path: where }
        });
      }
    };

    for (const source of target.sourceTexts ?? []) report(source.text, source.path);
    for (const tool of target.tools) {
      report(tool.description, toolPath(tool, "description"));
      walkSchema(tool.inputSchema, toolPath(tool, "inputSchema"), (node, path) => {
        if (typeof node["description"] === "string") report(node["description"], `${path}.description`);
      });
    }
    return findings;
  }
};

/** HMCP006 - a schema loose enough to forward whatever the model invents. */
const permissiveSchema: Rule = {
  id: "HMCP006",
  severity: "medium",
  title: "Overly permissive input schema",
  run: (target) => {
    const findings: Finding[] = [];
    const add = (message: string, fix: string, path: string) =>
      findings.push({
        ruleId: "HMCP006",
        severity: "medium",
        title: "Overly permissive input schema",
        message,
        fix,
        location: { file: target.file, path }
      });

    for (const tool of target.tools) {
      walkSchema(tool.inputSchema, toolPath(tool, "inputSchema"), (node, path) => {
        const type = node["type"];
        if (type === "object") {
          if (node["additionalProperties"] === true) {
            add(
              `${path} accepts additional properties, so arguments the schema never declared are forwarded upstream.`,
              `Set additionalProperties to false.`,
              path
            );
          }
          const props = schemaProperties(node);
          if (Object.keys(props).length === 0 && node["additionalProperties"] !== false) {
            add(
              `${path} is a free-form object with no declared properties, which forwards arbitrary JSON upstream.`,
              `Declare the properties the operation actually accepts, or drop the field.`,
              path
            );
          }
        }
        if (type === "string" && node["maxLength"] === undefined && node["enum"] === undefined) {
          add(
            `${path} is an unbounded string, so a single argument can carry an arbitrarily large payload.`,
            `Add a maxLength.`,
            path
          );
        }
        if (type === "array" && node["maxItems"] === undefined) {
          add(`${path} is an unbounded array.`, `Add a maxItems.`, path);
        }
        if (type === undefined && path.endsWith("]") === false && Object.keys(schemaProperties(node)).length === 0) {
          add(`${path} declares no type, so it accepts any JSON value.`, `Give the field an explicit type.`, path);
        }
      });
    }
    return findings;
  }
};

/** HMCP007 - the upstream the server actually talks to is not the one policy permits. */
const egressMismatch: Rule = {
  id: "HMCP007",
  severity: "high",
  title: "Egress target not permitted by policy",
  run: (target) => {
    const policy = target.policy;
    const baseUrl = target.api?.base_url;
    if (!policy || !baseUrl) return [];

    const findings: Finding[] = [];
    const push = (message: string, fix: string) =>
      findings.push({
        ruleId: "HMCP007",
        severity: "high",
        title: "Egress target not permitted by policy",
        message,
        fix,
        location: { file: target.file, path: "api.base_url" }
      });

    let url: URL;
    try {
      url = new URL(baseUrl);
    } catch {
      push(`The base URL "${baseUrl}" is not a valid absolute URL.`, `Set a full https:// base URL.`);
      return findings;
    }

    if (url.protocol === "http:" && !policy.egress.allow_http) {
      push(
        `The upstream base URL is plaintext HTTP (${baseUrl}), so credentials and data would cross the network in the clear.`,
        `Use https, or set egress.allow_http if this is a local development target.`
      );
    } else if (url.protocol !== "https:" && url.protocol !== "http:") {
      push(`The base URL uses the ${url.protocol} scheme.`, `Use https.`);
    }

    const host = url.hostname;
    if (isIpLiteral(host)) {
      const verdict = classifyAddress(host);
      if (verdict.blocked) {
        push(
          `The upstream base URL points at ${host}, which is ${verdict.reason}. A tool call would reach into the ` +
            `host's own network rather than a public API.`,
          `Point the base URL at the real API host.`
        );
      }
    }

    const allowed = isHostAllowed(host, url.port || (url.protocol === "https:" ? "443" : "80"), policy.egress.allow);

    if (policy.egress.allow.length === 0) {
      push(
        `egress.allow is empty while the server is configured to call ${url.host}; every call will be refused at runtime.`,
        `Add "${url.host}" to egress.allow.`
      );
    } else if (!allowed) {
      push(
        `The server calls ${url.host} but egress.allow permits only ${policy.egress.allow.join(", ")}. ` +
          `Every call will be refused at runtime.`,
        `Add "${url.host}" to egress.allow.`
      );
    }
    return findings;
  }
};

function splitEntry(entry: string): [string, string | undefined] {
  if (entry.startsWith("[")) {
    const end = entry.indexOf("]");
    if (end === -1) return [entry, undefined];
    const rest = entry.slice(end + 1);
    return [entry.slice(1, end), rest.startsWith(":") ? rest.slice(1) : undefined];
  }
  const idx = entry.lastIndexOf(":");
  if (idx > 0 && /^\d+$/.test(entry.slice(idx + 1))) return [entry.slice(0, idx), entry.slice(idx + 1)];
  return [entry, undefined];
}

/** Mirrors the runtime guard's allowlist matching, so a scan and a call agree. */
function isHostAllowed(host: string, port: string, allow: readonly string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return allow.some((entry) => {
    const [pattern, entryPort] = splitEntry(entry);
    if (entryPort !== undefined && entryPort !== port) return false;
    const p = pattern.toLowerCase().replace(/\.$/, "");
    if (p.startsWith("*.")) {
      const suffix = p.slice(1);
      return h.endsWith(suffix) && h.length > suffix.length;
    }
    return h === p;
  });
}

/** HMCP008 - the upstream API declares no authentication. */
const missingAuth: Rule = {
  id: "HMCP008",
  severity: "medium",
  title: "Upstream API declares no authentication",
  run: (target) => {
    const spec = target.spec;
    if (!spec) return [];
    const findings: Finding[] = [];
    if (!spec.hasSecuritySchemes) {
      findings.push({
        ruleId: "HMCP008",
        severity: "medium",
        title: "Upstream API declares no authentication",
        message:
          `The source spec declares no security schemes, so the generated server has no credential to present and ` +
          `no tenant to derive. Either the API is genuinely open, or the spec is incomplete - and an incomplete ` +
          `spec means the generated tenant scoping rests on nothing.`,
        fix: `Add the securitySchemes section to the spec, or configure auth explicitly when generating.`,
        location: { file: target.file, path: "auth" }
      });
    } else if (spec.operationsWithoutSecurity.length > 0) {
      findings.push({
        ruleId: "HMCP008",
        severity: "medium",
        title: "Upstream API declares no authentication",
        message:
          `${spec.operationsWithoutSecurity.length} exposed operation(s) declare no security requirement: ` +
          `${spec.operationsWithoutSecurity.slice(0, 5).join(", ")}` +
          `${spec.operationsWithoutSecurity.length > 5 ? ", …" : ""}.`,
        fix: `Add a security requirement to those operations in the spec, or exclude them from the tool set.`,
        location: { file: target.file, path: "tools" }
      });
    }
    return findings;
  }
};

/** HMCP009 - too many tools, or two tools a model cannot tell apart. */
const toolSetHygiene: Rule = {
  id: "HMCP009",
  severity: "medium",
  title: "Tool set is hard to review or to tell apart",
  run: (target) => {
    const findings: Finding[] = [];
    const budget = target.policy?.tool_budget;

    if (budget !== undefined && target.tools.length > budget) {
      findings.push({
        ruleId: "HMCP009",
        severity: "medium",
        title: "Tool set is hard to review or to tell apart",
        message:
          `${target.tools.length} tools are exposed against a budget of ${budget}. A set this size cannot be ` +
          `meaningfully reviewed, and a model chooses worse from it.`,
        fix: `Disable the tools an agent does not need, or raise tool_budget deliberately.`,
        location: { file: target.file, path: "tools" }
      });
    }

    // Names that collapse to the same thing once separators and case are gone
    // are a confusion risk, and a way to smuggle a lookalike tool in.
    const normalized = new Map<string, string[]>();
    for (const tool of target.tools) {
      const key = tool.name.toLowerCase().replace(/[^a-z0-9]/g, "");
      const bucket = normalized.get(key);
      if (bucket) bucket.push(tool.name);
      else normalized.set(key, [tool.name]);
    }
    for (const [, names] of normalized) {
      if (names.length < 2) continue;
      findings.push({
        ruleId: "HMCP009",
        severity: "medium",
        title: "Tool set is hard to review or to tell apart",
        message: `Tools ${names.map((n) => `"${n}"`).join(" and ")} differ only in punctuation or case, so a model may pick the wrong one.`,
        fix: `Rename one of them to something distinct.`,
        location: { file: target.file, path: `tools.${names[0]}` }
      });
    }

    // A name outside the plain-ASCII vocabulary can impersonate another tool.
    for (const tool of target.tools) {
      if (!/^[a-z0-9_][a-z0-9_-]*$/i.test(tool.name)) {
        findings.push({
          ruleId: "HMCP009",
          severity: "medium",
          title: "Tool set is hard to review or to tell apart",
          message:
            `Tool name "${tool.name}" contains characters outside [A-Za-z0-9_-]. Non-ASCII look-alikes can ` +
            `impersonate another tool in a way a reviewer will not notice.`,
          fix: `Rename it using ASCII letters, digits, underscores and hyphens.`,
          location: { file: target.file, path: `tools.${tool.name}` }
        });
      }
    }
    return findings;
  }
};

/** HMCP010 - the audit trail is off, weakened, or unprotected. */
const auditIntegrity: Rule = {
  id: "HMCP010",
  severity: "high",
  title: "Audit trail is missing or weakened",
  run: (target) => {
    const policy = target.policy;
    if (!policy) return [];
    const findings: Finding[] = [];
    const push = (severity: Finding["severity"], message: string, fix: string, path: string) =>
      findings.push({
        ruleId: "HMCP010",
        severity,
        title: "Audit trail is missing or weakened",
        message,
        fix,
        location: { file: target.file, path }
      });

    if (!policy.audit.enabled) {
      push(
        "high",
        `Auditing is disabled, so denied and approved calls leave no record and nothing can be reconstructed afterwards.`,
        `Set audit.enabled to true.`,
        "audit.enabled"
      );
    } else if (!policy.audit.hash_chain) {
      push(
        "medium",
        `The audit log has no hash chain, so a record can be edited or removed without trace.`,
        `Set audit.hash_chain to true.`,
        "audit.hash_chain"
      );
    }

    if (policy.approvals.mode === "deny" && policy.defaults.mode === "approve-writes") {
      push(
        "medium",
        `The posture sends writes to approval while approvals.mode is "deny", so every write fails rather than ` +
          `reaching a human. That is safe, but it is probably not what was intended.`,
        `Set approvals.mode to "both", or set the posture to read-only and say so plainly.`,
        "approvals.mode"
      );
    }
    return findings;
  }
};

export const RULES: readonly Rule[] = [
  unapprovedWrites,
  tenantScoping,
  unboundedList,
  leakedSecrets,
  promptInjection,
  permissiveSchema,
  egressMismatch,
  missingAuth,
  toolSetHygiene,
  auditIntegrity
];
