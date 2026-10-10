import type { TenantConfig } from "@hmcp/core";
import type { Binding, JsonSchemaNode, ToolDescriptor } from "@hmcp/server-runtime";
import { isTenantParam } from "./curate.js";
import type { JsonSchema, ManifestTool, Operation } from "./types.js";

/** Caps applied where a spec leaves a field unbounded. */
export interface NarrowCaps {
  readonly maxStringLength: number;
  readonly maxArrayItems: number;
  readonly paginationMax: number;
  readonly maxDescriptionLength: number;
}

export const DEFAULT_CAPS: NarrowCaps = {
  maxStringLength: 4096,
  maxArrayItems: 100,
  paginationMax: 100,
  maxDescriptionLength: 600
};

/** Query parameter names that mean "how many", in the specs people actually write. */
const PAGINATION_PARAMS = ["limit", "per_page", "perpage", "page_size", "pagesize", "count", "max_results", "size", "top"];

/** Header parameters a tool must never let an agent set. */
const FORBIDDEN_HEADERS = [
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "host",
  "x-api-key",
  "api-key",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-real-ip",
  "content-length",
  "transfer-encoding"
];

/**
 * Characters that can hide text from a human reviewing a tool description while
 * leaving it visible to the model: zero-width spaces, joiners, and the
 * bidirectional overrides behind the "Trojan Source" trick.
 */
const INVISIBLE_CHARS = /[­​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;

/** Strips invisible characters and control codes, then caps the length. */
export function sanitizeText(text: string, maxLength = DEFAULT_CAPS.maxDescriptionLength): string {
  const cleaned = text
    .replace(INVISIBLE_CHARS, "")
    // Control characters, which can hide or reorder text in a terminal.
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength - 1).trimEnd()}…` : cleaned;
}

/**
 * Reduces a spec's schema to the narrowed vocabulary the runtime accepts, and
 * closes it: objects reject unknown properties, strings and arrays get a
 * ceiling, and anything the generator cannot express is dropped rather than
 * passed through as "any".
 */
export function narrowSchema(schema: JsonSchema | undefined, caps = DEFAULT_CAPS, depth = 0): JsonSchemaNode {
  if (!schema || typeof schema !== "object" || depth > 8) return { type: "string", maxLength: caps.maxStringLength };

  const merged = mergeAllOf(schema);
  const variant = merged.oneOf?.[0] ?? merged.anyOf?.[0];
  const source = variant ? { ...mergeAllOf(variant), description: merged.description ?? variant.description } : merged;

  const type = normalizeType(source);
  const node: JsonSchemaNode = {};
  if (type) node.type = type;

  const description = typeof source.description === "string" ? sanitizeText(source.description, 300) : "";
  if (description) node.description = description;

  if (Array.isArray(source.enum) && source.enum.length > 0) {
    node.enum = source.enum.filter(
      (v): v is string | number | boolean | null =>
        v === null || ["string", "number", "boolean"].includes(typeof v)
    );
  }
  if (source.nullable === true) node.nullable = true;
  if (source.default !== undefined && isScalar(source.default)) node.default = source.default;
  if (typeof source.format === "string") node.format = source.format;

  switch (type) {
    case "string": {
      if (typeof source.pattern === "string") node.pattern = source.pattern;
      if (typeof source.minLength === "number") node.minLength = source.minLength;
      // An enum is already a tighter constraint than any length cap.
      if (node.enum === undefined) {
        node.maxLength = Math.min(
          typeof source.maxLength === "number" ? source.maxLength : caps.maxStringLength,
          caps.maxStringLength
        );
      }
      break;
    }
    case "number":
    case "integer": {
      if (typeof source.minimum === "number") node.minimum = source.minimum;
      if (typeof source.maximum === "number") node.maximum = source.maximum;
      break;
    }
    case "array": {
      node.items = narrowSchema(source.items, caps, depth + 1);
      if (typeof source.minItems === "number") node.minItems = source.minItems;
      node.maxItems = Math.min(
        typeof source.maxItems === "number" ? source.maxItems : caps.maxArrayItems,
        caps.maxArrayItems
      );
      break;
    }
    case "object": {
      const properties: Record<string, JsonSchemaNode> = {};
      for (const [key, child] of Object.entries(source.properties ?? {})) {
        properties[key] = narrowSchema(child, caps, depth + 1);
      }
      node.properties = properties;
      const required = (source.required ?? []).filter((r) => r in properties);
      if (required.length > 0) node.required = required;
      // Always closed: an argument the schema does not name never reaches the
      // upstream, whatever the spec said about additionalProperties.
      node.additionalProperties = false;
      break;
    }
    default:
      break;
  }

  return node;
}

function isScalar(value: unknown): boolean {
  return ["string", "number", "boolean"].includes(typeof value);
}

function normalizeType(schema: JsonSchema): JsonSchemaNode["type"] | undefined {
  const raw = Array.isArray(schema.type) ? schema.type.find((t) => t !== "null") : schema.type;
  switch (raw) {
    case "string":
    case "number":
    case "integer":
    case "boolean":
    case "object":
    case "array":
      return raw;
    default:
      // An untyped schema with properties is an object; otherwise treat it as a
      // bounded string rather than letting arbitrary JSON through.
      if (schema.properties) return "object";
      if (schema.items) return "array";
      if (schema.enum) return "string";
      return "string";
  }
}

/** Merges an allOf chain into one schema, shallowly, which covers real specs. */
function mergeAllOf(schema: JsonSchema): JsonSchema {
  if (!Array.isArray(schema.allOf) || schema.allOf.length === 0) return schema;
  const out: JsonSchema = { ...schema };
  delete out.allOf;
  out.properties = { ...(schema.properties ?? {}) };
  out.required = [...(schema.required ?? [])];
  for (const part of schema.allOf) {
    const merged = mergeAllOf(part);
    out.type = out.type ?? merged.type;
    out.properties = { ...merged.properties, ...out.properties };
    out.required = [...new Set([...(merged.required ?? []), ...out.required])];
    out.description = out.description ?? merged.description;
  }
  if (out.required.length === 0) delete out.required;
  return out;
}

export interface BuildDescriptorOptions {
  readonly operation: Operation;
  readonly tool: ManifestTool;
  readonly tenant?: TenantConfig | undefined;
  readonly caps?: NarrowCaps;
}

/** Where a withheld parameter lived in the upstream request. */
export type OmittedIn = "path" | "query" | "header" | "cookie" | "body";

export interface BuildDescriptorResult {
  readonly descriptor: ToolDescriptor;
  /** Parameters deliberately left out, with the reason, for the build report. */
  readonly omitted: readonly { readonly name: string; readonly in: OmittedIn; readonly reason: string }[];
}

/**
 * Builds the runtime descriptor for one enabled tool.
 *
 * Three things happen here that matter: tenant parameters are removed from the
 * agent-facing schema and recorded for server-side injection, credential-ish
 * headers are dropped so a tool cannot set them, and a pagination ceiling is
 * attached where the operation looks like a list.
 */
export function buildDescriptor(options: BuildDescriptorOptions): BuildDescriptorResult {
  const { operation, tool } = options;
  const caps = options.caps ?? DEFAULT_CAPS;
  const omitted: { name: string; in: OmittedIn; reason: string }[] = [];

  const properties: Record<string, JsonSchemaNode> = {};
  const required: string[] = [];
  const bindings: Record<string, Binding> = {};
  const tenantParams = new Set<string>(tool.tenant_params ?? []);
  const omitList = new Set((tool.omit_params ?? []).map((n) => n.toLowerCase()));
  let paginationCap: ToolDescriptor["paginationCap"];

  const claim = (preferred: string): string => {
    let name = preferred;
    let suffix = 2;
    while (name in properties) name = `${preferred}_${suffix++}`;
    return name;
  };

  for (const param of operation.parameters) {
    const lower = param.name.toLowerCase();

    if (isTenantParam(param.name, options.tenant) || tenantParams.has(param.name)) {
      tenantParams.add(param.name);
      omitted.push({
        name: param.name,
        in: param.location,
        reason: "tenant-scoped; injected from the credential"
      });
      continue;
    }
    if (omitList.has(lower)) {
      omitted.push({ name: param.name, in: param.location, reason: "omitted by the manifest" });
      continue;
    }
    if (param.location === "cookie") {
      omitted.push({ name: param.name, in: "cookie", reason: "cookie parameters are not exposed to agents" });
      continue;
    }
    if (param.location === "header" && FORBIDDEN_HEADERS.includes(lower)) {
      omitted.push({
        name: param.name,
        in: "header",
        reason: "credential or hop-by-hop header; set by the server, not the agent"
      });
      continue;
    }

    const argName = claim(toArgName(param.name));
    const schema = narrowSchema(param.schema, caps);
    if (param.description) schema.description = sanitizeText(param.description, 300);

    if (param.location === "query" && !paginationCap) {
      paginationCap = applyPaginationCap(param.name, argName, schema, caps);
    }

    properties[argName] = schema;
    bindings[argName] = { in: param.location, name: param.name };
    if (param.required) required.push(argName);
  }

  let bodyMode: ToolDescriptor["bodyMode"] = "none";
  if (operation.requestBody && operation.method !== "GET" && operation.method !== "HEAD") {
    bodyMode = "json";
    const bodySchema = narrowSchema(operation.requestBody.schema, caps);
    const bodyRequired = new Set(bodySchema.required ?? []);

    if (bodySchema.type === "object" && bodySchema.properties) {
      for (const [name, child] of Object.entries(bodySchema.properties)) {
        if (isTenantParam(name, options.tenant) || tenantParams.has(name)) {
          tenantParams.add(name);
          omitted.push({ name, in: "body", reason: "tenant-scoped body field; injected from the credential" });
          continue;
        }
        if (omitList.has(name.toLowerCase())) {
          omitted.push({ name, in: "body", reason: "omitted by the manifest" });
          continue;
        }
        if (isFreeForm(child)) {
          // The spec declares an open-ended object. Emitting it closed would
          // leave a field that accepts nothing, so it is dropped and reported -
          // a reviewer can add a concrete shape if the field is needed.
          omitted.push({
            name,
            in: "body",
            reason: "free-form object in the spec; declare its properties to expose it"
          });
          continue;
        }
        const argName = claim(toArgName(name));
        // A search expressed as a POST carries its page size in the body, so
        // the ceiling has to be found there too, not only in the query string.
        if (!paginationCap) {
          paginationCap = applyPaginationCap(name, argName, child, caps);
        }
        properties[argName] = child;
        bindings[argName] = { in: "body", name };
        if (bodyRequired.has(name)) required.push(argName);
      }
    } else {
      // A non-object body (an array or a scalar) is exposed as one argument.
      const argName = claim("body");
      properties[argName] = bodySchema;
      bindings[argName] = { in: "body", name: "body" };
      if (operation.requestBody.required) required.push(argName);
    }
  }

  const descriptor: ToolDescriptor = {
    name: tool.name,
    description: buildDescription(operation, tool, [...tenantParams], options.tenant),
    effect: tool.effect,
    method: operation.method,
    path: operation.path,
    inputSchema: {
      type: "object",
      properties,
      ...(required.length > 0 ? { required } : {}),
      additionalProperties: false
    },
    bindings,
    bodyMode,
    bodyContentType: operation.requestBody?.contentType ?? "application/json",
    tenantParams: [...tenantParams],
    ...(paginationCap ? { paginationCap } : {}),
    annotations: {
      readOnlyHint: tool.effect === "read",
      destructiveHint: tool.effect === "destructive",
      idempotentHint: ["GET", "HEAD", "PUT", "DELETE"].includes(operation.method)
    },
    // Persisted rather than only reported: a reviewer reading tools.json can
    // now see that a parameter is absent on purpose and why, which until now
    // survived only in the generated README's prose.
    withheldParams: omitted.map((o) => ({ name: o.name, in: o.in, reason: o.reason })),
    ...(tool.review ? { review: tool.review } : {}),
    source: {
      ...(operation.operationId ? { operationId: operation.operationId } : {}),
      ...(operation.summary ? { summary: operation.summary } : {}),
      ...(operation.deprecated ? { deprecated: operation.deprecated } : {}),
      // Carried through from the manifest: the tool list is in name order, so
      // without this the order the spec author chose is lost for good.
      ...(tool.spec_index !== undefined ? { specIndex: tool.spec_index } : {})
    }
  };

  return { descriptor, omitted };
}

/**
 * Turns a "how many" parameter into a bounded integer with a server-side
 * ceiling. Returns undefined when the name is not a pagination parameter.
 */
function applyPaginationCap(
  upstreamName: string,
  argName: string,
  schema: JsonSchemaNode,
  caps: NarrowCaps
): ToolDescriptor["paginationCap"] | undefined {
  if (!PAGINATION_PARAMS.includes(upstreamName.toLowerCase())) return undefined;
  const max = Math.min(
    typeof schema.maximum === "number" ? schema.maximum : caps.paginationMax,
    caps.paginationMax
  );
  schema.type = "integer";
  schema.minimum = 1;
  schema.maximum = max;
  schema.default = max;
  delete schema.maxLength;
  return { param: argName, max };
}

/**
 * True for an object the spec left open-ended. Narrowing one produces a field
 * that accepts no properties at all, which is worse than not having it.
 */
function isFreeForm(node: JsonSchemaNode): boolean {
  return node.type === "object" && Object.keys(node.properties ?? {}).length === 0;
}

function toArgName(name: string): string {
  const cleaned = name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .toLowerCase();
  return cleaned.length > 0 ? cleaned : "value";
}

/**
 * Composes the tool description from sanitized spec text, and states the
 * tenant scoping in it so the model is not left guessing why a tenant argument
 * it expected is absent.
 */
function buildDescription(
  operation: Operation,
  tool: ManifestTool,
  tenantParams: readonly string[],
  tenant: TenantConfig | undefined
): string {
  const parts: string[] = [];
  const summary = sanitizeText(tool.summary || operation.summary || operation.description);
  if (summary) parts.push(summary);
  parts.push(`(${operation.method} ${operation.path})`);

  if (tool.effect === "destructive") parts.push("This operation deletes data and requires approval.");
  else if (tool.effect === "write") parts.push("This operation changes data and may require approval.");

  if (tenantParams.length > 0 && tenant) {
    parts.push(
      `Scoped automatically to the caller's ${tenant.field}; it is set by the server and cannot be supplied as an argument.`
    );
  }
  return parts.join(" ");
}
