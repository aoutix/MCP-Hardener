import { z } from "zod";
import { EffectSchema } from "@hmcp/core";

/**
 * The generated server's entire tool surface is this data file. Keeping it
 * declarative is deliberate: the thing a reviewer and the scanner read is a
 * manifest, not thousands of lines of emitted code, and the enforcement path
 * lives in one tested runtime rather than being copied per generation.
 */

/** Narrowed JSON Schema vocabulary - what the generator is allowed to emit. */
export const JsonSchemaNodeSchema: z.ZodType<JsonSchemaNode> = z.lazy(() =>
  z
    .object({
      type: z.enum(["string", "number", "integer", "boolean", "object", "array"]).optional(),
      description: z.string().optional(),
      enum: z.array(z.union([z.string(), z.number(), z.boolean(), z.null()])).optional(),
      const: z.union([z.string(), z.number(), z.boolean()]).optional(),
      format: z.string().optional(),
      pattern: z.string().optional(),
      minLength: z.number().optional(),
      maxLength: z.number().optional(),
      minimum: z.number().optional(),
      maximum: z.number().optional(),
      items: JsonSchemaNodeSchema.optional(),
      minItems: z.number().optional(),
      maxItems: z.number().optional(),
      properties: z.record(z.string(), JsonSchemaNodeSchema).optional(),
      required: z.array(z.string()).optional(),
      additionalProperties: z.boolean().optional(),
      nullable: z.boolean().optional(),
      default: z.unknown().optional()
    })
    .strict()
);

export interface JsonSchemaNode {
  type?: "string" | "number" | "integer" | "boolean" | "object" | "array";
  description?: string;
  enum?: (string | number | boolean | null)[];
  const?: string | number | boolean;
  format?: string;
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  items?: JsonSchemaNode;
  minItems?: number;
  maxItems?: number;
  properties?: Record<string, JsonSchemaNode>;
  required?: string[];
  additionalProperties?: boolean;
  nullable?: boolean;
  default?: unknown;
}

/** Where one agent-facing input lands in the upstream HTTP request. */
export const BindingSchema = z
  .object({
    in: z.enum(["path", "query", "header", "body"]),
    /** Upstream name, which may differ from the agent-facing one. */
    name: z.string().min(1)
  })
  .strict();
export type Binding = z.infer<typeof BindingSchema>;

export const ToolDescriptorSchema = z
  .object({
    name: z.string().min(1),
    description: z.string(),
    effect: EffectSchema,
    method: z.string().min(1),
    /** Upstream path template, e.g. `/orgs/{org_id}/invoices`. */
    path: z.string().min(1),
    inputSchema: JsonSchemaNodeSchema,
    bindings: z.record(z.string(), BindingSchema).default({}),
    bodyMode: z.enum(["none", "json"]).default("none"),
    bodyContentType: z.string().default("application/json"),
    /**
     * Tenant parameters. Absent from inputSchema by construction - they are
     * filled from the credential, so the model cannot express another tenant.
     */
    tenantParams: z.array(z.string()).default([]),
    /** Server-side ceiling applied to a pagination argument. */
    paginationCap: z.object({ param: z.string(), max: z.number().int().positive() }).optional(),
    annotations: z
      .object({
        readOnlyHint: z.boolean().optional(),
        destructiveHint: z.boolean().optional(),
        idempotentHint: z.boolean().optional()
      })
      .default({}),
    /**
     * Parameters the generator withheld from the agent, with the reason.
     *
     * The generator has always computed these; before this field they reached
     * only the generated README and were lost from the machine-readable
     * surface. A reviewer looking at `tools.json` could see that `org_id` was
     * absent but not that it was absent *deliberately*, which is the part that
     * matters. Defaulted, so a file generated before this field still parses.
     */
    withheldParams: z
      .array(
        z
          .object({
            name: z.string().min(1),
            in: z.enum(["path", "query", "header", "cookie", "body"]).optional(),
            reason: z.string()
          })
          .strict()
      )
      .default([]),
    /** Set when the generator inferred the effect and wants a human to confirm. */
    review: z.string().optional(),
    /** Provenance, so a surface can be explained without re-reading the spec. */
    source: z
      .object({
        operationId: z.string().optional(),
        summary: z.string().optional(),
        deprecated: z.boolean().optional()
      })
      .strict()
      .optional()
  })
  .strict();
export type ToolDescriptor = z.infer<typeof ToolDescriptorSchema>;

/** How the generated server authenticates to the upstream API. */
export const AuthSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("none") }).strict(),
  z.object({ kind: z.literal("bearer"), env: z.string().min(1) }).strict(),
  z.object({ kind: z.literal("header"), env: z.string().min(1), name: z.string().min(1) }).strict(),
  z.object({ kind: z.literal("query"), env: z.string().min(1), name: z.string().min(1) }).strict(),
  z.object({ kind: z.literal("basic"), env: z.string().min(1) }).strict()
]);
export type Auth = z.infer<typeof AuthSchema>;

export const ToolsFileSchema = z
  .object({
    version: z.literal(1),
    generated_by: z.string().default("hmcp-gen"),
    generated_at: z.string().optional(),
    api: z
      .object({
        title: z.string(),
        version: z.string(),
        base_url: z.string().min(1)
      })
      .strict(),
    auth: AuthSchema.default({ kind: "none" }),
    tools: z.array(ToolDescriptorSchema),
    /**
     * How this surface came to be: what the generator declined to expose and
     * what it knows about the spec's own security. Optional, so every existing
     * `tools.json` still parses.
     */
    generation: z
      .object({
        spec_format: z.enum(["openapi-3", "swagger-2"]).optional(),
        has_security_schemes: z.boolean().optional(),
        operations_without_security: z.array(z.string()).default([]),
        /** Operations that exist in the spec but are not reachable by an agent. */
        skipped: z.array(z.object({ tool: z.string(), reason: z.string() }).strict()).default([])
      })
      .strict()
      .optional()
  })
  .strict();
export type ToolsFile = z.infer<typeof ToolsFileSchema>;

export function parseToolsFile(raw: unknown, source = "tools.json"): ToolsFile {
  const result = ToolsFileSchema.safeParse(raw);
  if (!result.success) {
    const detail = result.error.issues.map((i) => `  ${i.path.join(".") || "(root)"}: ${i.message}`).join("\n");
    throw new Error(`invalid tool descriptor file ${source}:\n${detail}`);
  }
  return result.data;
}
