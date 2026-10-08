import SwaggerParser from "@apidevtools/swagger-parser";
import { createRequire } from "node:module";
import type { JsonSchema, Operation, Parameter, ParsedSpec, RequestBody } from "./types.js";

const require = createRequire(import.meta.url);

export class SpecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SpecError";
  }
}

const HTTP_METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"] as const;

type AnyRecord = Record<string, unknown>;

/**
 * Loads a spec, converting Swagger 2.0 up to OpenAPI 3 first, then validating
 * and dereferencing so downstream code never has to chase a `$ref`.
 */
export async function parseSpec(path: string): Promise<ParsedSpec> {
  let raw: AnyRecord;
  try {
    raw = (await SwaggerParser.parse(path)) as AnyRecord;
  } catch (err) {
    throw new SpecError(`cannot parse ${path}: ${(err as Error).message}`);
  }

  const isSwagger2 = typeof raw["swagger"] === "string" && raw["swagger"].startsWith("2");
  let document: AnyRecord = raw;

  if (isSwagger2) {
    const converter = require("swagger2openapi") as {
      convertObj: (
        spec: unknown,
        options: Record<string, unknown>
      ) => Promise<{ openapi: AnyRecord }>;
    };
    try {
      const converted = await converter.convertObj(raw, { patch: true, warnOnly: true });
      document = converted.openapi;
    } catch (err) {
      throw new SpecError(`cannot convert Swagger 2.0 spec ${path} to OpenAPI 3: ${(err as Error).message}`);
    }
  }

  let api: AnyRecord;
  try {
    // Dereference rather than bundle: generation needs concrete schemas, and a
    // circular $ref would otherwise surface much later as a confusing failure.
    api = (await SwaggerParser.dereference(document as never)) as unknown as AnyRecord;
  } catch (err) {
    throw new SpecError(`spec ${path} is not valid OpenAPI: ${(err as Error).message}`);
  }

  const info = (api["info"] ?? {}) as AnyRecord;
  const components = (api["components"] ?? {}) as AnyRecord;
  const securitySchemes = (components["securitySchemes"] ?? {}) as Record<string, AnyRecord>;

  const servers = extractServers(api["servers"]);
  const globalSecurity = securityNames(api["security"]);
  const operations: Operation[] = [];

  const paths = (api["paths"] ?? {}) as Record<string, AnyRecord>;
  for (const [path, pathItemRaw] of Object.entries(paths)) {
    if (!pathItemRaw || typeof pathItemRaw !== "object") continue;
    const pathItem = pathItemRaw as AnyRecord;
    const sharedParams = Array.isArray(pathItem["parameters"]) ? pathItem["parameters"] : [];

    for (const method of HTTP_METHODS) {
      const opRaw = pathItem[method];
      if (!opRaw || typeof opRaw !== "object") continue;
      const op = opRaw as AnyRecord;

      const params = [...sharedParams, ...(Array.isArray(op["parameters"]) ? op["parameters"] : [])];
      operations.push({
        operationId: typeof op["operationId"] === "string" && op["operationId"].length > 0
          ? op["operationId"]
          : synthesizeOperationId(method, path),
        method: method.toUpperCase(),
        path,
        summary: str(op["summary"]),
        description: str(op["description"]),
        tags: Array.isArray(op["tags"]) ? op["tags"].filter((t): t is string => typeof t === "string") : [],
        deprecated: op["deprecated"] === true,
        parameters: params.map(normalizeParameter).filter((p): p is Parameter => p !== null),
        requestBody: normalizeRequestBody(op["requestBody"]),
        security: op["security"] === undefined ? globalSecurity : securityNames(op["security"]),
        servers: extractServers(op["servers"]),
        responseDescription: firstResponseDescription(op["responses"])
      });
    }
  }

  return {
    title: str(info["title"]) || "api",
    version: str(info["version"]) || "0.0.0",
    description: str(info["description"]),
    servers,
    operations,
    hasSecuritySchemes: Object.keys(securitySchemes).length > 0,
    securitySchemes: Object.fromEntries(
      Object.entries(securitySchemes).map(([name, scheme]) => [
        name,
        {
          type: str(scheme["type"]),
          scheme: str(scheme["scheme"]) || undefined,
          name: str(scheme["name"]) || undefined,
          in: str(scheme["in"]) || undefined
        }
      ])
    ),
    globalSecurity,
    sourcePath: path,
    originalFormat: isSwagger2 ? "swagger-2" : "openapi-3"
  };
}

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function extractServers(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((server) => {
      if (!server || typeof server !== "object") return null;
      const s = server as AnyRecord;
      let url = str(s["url"]);
      if (!url) return null;
      // Substitute server variable defaults so the base URL is concrete.
      const variables = (s["variables"] ?? {}) as Record<string, AnyRecord>;
      for (const [name, variable] of Object.entries(variables)) {
        const fallback = str(variable["default"]);
        if (fallback) url = url.replaceAll(`{${name}}`, fallback);
      }
      return url;
    })
    .filter((u): u is string => u !== null);
}

function securityNames(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const names = new Set<string>();
  for (const requirement of value) {
    if (!requirement || typeof requirement !== "object") continue;
    for (const name of Object.keys(requirement as AnyRecord)) names.add(name);
  }
  return [...names];
}

function synthesizeOperationId(method: string, path: string): string {
  const segments = path
    .split("/")
    .filter((s) => s.length > 0)
    .map((s) => (s.startsWith("{") ? `by_${s.replace(/[{}]/g, "")}` : s));
  return [method, ...segments].join("_");
}

function normalizeParameter(value: unknown): Parameter | null {
  if (!value || typeof value !== "object") return null;
  const p = value as AnyRecord;
  const name = str(p["name"]);
  const location = str(p["in"]);
  if (!name || !["path", "query", "header", "cookie"].includes(location)) return null;
  return {
    name,
    location: location as Parameter["location"],
    required: p["required"] === true || location === "path",
    description: str(p["description"]),
    schema: (p["schema"] ?? { type: "string" }) as JsonSchema
  };
}

function normalizeRequestBody(value: unknown): RequestBody | null {
  if (!value || typeof value !== "object") return null;
  const body = value as AnyRecord;
  const content = (body["content"] ?? {}) as Record<string, AnyRecord>;
  // Prefer JSON; fall back to whatever the operation does offer so the
  // generated tool at least reports the content type honestly.
  const preferred =
    Object.keys(content).find((ct) => ct.includes("json")) ?? Object.keys(content)[0] ?? "application/json";
  const media = content[preferred] ?? {};
  return {
    required: body["required"] === true,
    contentType: preferred,
    schema: (media["schema"] ?? { type: "object" }) as JsonSchema,
    description: str(body["description"])
  };
}

function firstResponseDescription(value: unknown): string {
  if (!value || typeof value !== "object") return "";
  for (const [code, response] of Object.entries(value as Record<string, AnyRecord>)) {
    if (!/^2\d\d$/.test(code) && code !== "default") continue;
    if (response && typeof response === "object") return str(response["description"]);
  }
  return "";
}
