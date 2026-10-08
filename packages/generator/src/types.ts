import type { Effect } from "@hmcp/core";

/** A single OpenAPI operation, reduced to what matters for generating a tool. */
export interface Operation {
  readonly operationId: string;
  readonly method: string;
  readonly path: string;
  readonly summary: string;
  readonly description: string;
  readonly tags: readonly string[];
  readonly deprecated: boolean;
  readonly parameters: readonly Parameter[];
  readonly requestBody: RequestBody | null;
  readonly security: readonly string[];
  /** Per-operation server override, when the spec declares one. */
  readonly servers: readonly string[];
  readonly responseDescription: string;
}

export interface Parameter {
  readonly name: string;
  readonly location: "path" | "query" | "header" | "cookie";
  readonly required: boolean;
  readonly description: string;
  readonly schema: JsonSchema;
}

export interface RequestBody {
  readonly required: boolean;
  readonly contentType: string;
  readonly schema: JsonSchema;
  readonly description: string;
}

/** A structural subset of JSON Schema; enough to narrow and to emit zod. */
export interface JsonSchema {
  type?: string | string[];
  format?: string;
  enum?: unknown[];
  items?: JsonSchema;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  additionalProperties?: boolean | JsonSchema;
  description?: string;
  default?: unknown;
  example?: unknown;
  examples?: unknown[];
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  nullable?: boolean;
  oneOf?: JsonSchema[];
  anyOf?: JsonSchema[];
  allOf?: JsonSchema[];
  [key: string]: unknown;
}

export interface ParsedSpec {
  readonly title: string;
  readonly version: string;
  readonly description: string;
  readonly servers: readonly string[];
  readonly operations: readonly Operation[];
  /** True when the spec declares at least one security scheme. */
  readonly hasSecuritySchemes: boolean;
  readonly securitySchemes: Readonly<Record<string, { type: string; scheme?: string; name?: string; in?: string }>>;
  /** Global security requirement names, if any. */
  readonly globalSecurity: readonly string[];
  readonly sourcePath: string;
  readonly originalFormat: "openapi-3" | "swagger-2";
}

/** One entry in the human-editable manifest. */
export interface ManifestTool {
  name: string;
  enabled: boolean;
  effect: Effect;
  /** Set when the generator inferred the effect and wants a human to confirm. */
  review?: string;
  operationId: string;
  method: string;
  path: string;
  summary: string;
  /** Tenant parameters stripped from the agent-facing schema and injected server-side. */
  tenant_params?: string[];
  /** Parameters dropped from the tool entirely. */
  omit_params?: string[];
}

export interface Manifest {
  version: 1;
  spec: string;
  api: { title: string; version: string; base_url: string };
  policy?: string;
  tools: ManifestTool[];
  /**
   * Operations `curate` declined to turn into candidate tools at all, with the
   * reason. Persisted because `build` reads the manifest from disk long after
   * the `CurateResult` that knew this has gone, and a reviewer should be able
   * to see what the spec contained but the surface does not.
   */
  skipped?: { tool: string; reason: string }[];
}
