import { z, type ZodTypeAny } from "zod";
import type { JsonSchemaNode } from "./descriptor.js";

/**
 * Converts the narrowed JSON Schema the generator emits into zod, which the MCP
 * SDK uses both to advertise the tool and to validate incoming arguments. One
 * schema drives both, so advertisement and enforcement cannot disagree.
 */
export function toZod(node: JsonSchemaNode): ZodTypeAny {
  let schema = build(node);
  if (node.description) schema = schema.describe(node.description);
  if (node.nullable) schema = schema.nullable();
  if (node.default !== undefined) schema = schema.default(node.default as never);
  return schema;
}

function build(node: JsonSchemaNode): ZodTypeAny {
  if (node.const !== undefined) return z.literal(node.const as string | number | boolean);

  if (node.enum && node.enum.length > 0) {
    const values = node.enum.filter((v) => v !== null);
    if (values.every((v) => typeof v === "string")) {
      return z.enum(values as [string, ...string[]]);
    }
    return z.union(
      values.map((v) => z.literal(v as string | number | boolean)) as unknown as [ZodTypeAny, ZodTypeAny]
    );
  }

  switch (node.type) {
    case "string": {
      let s = z.string();
      if (node.minLength !== undefined) s = s.min(node.minLength);
      if (node.maxLength !== undefined) s = s.max(node.maxLength);
      if (node.pattern !== undefined) {
        try {
          s = s.regex(new RegExp(node.pattern));
        } catch {
          // A pattern we cannot compile is dropped rather than silently
          // accepted as a match-anything; the length cap still applies.
        }
      }
      return s;
    }
    case "integer":
    case "number": {
      let n = node.type === "integer" ? z.number().int() : z.number();
      if (node.minimum !== undefined) n = n.min(node.minimum);
      if (node.maximum !== undefined) n = n.max(node.maximum);
      return n;
    }
    case "boolean":
      return z.boolean();
    case "array": {
      let a = z.array(node.items ? toZod(node.items) : z.unknown());
      if (node.minItems !== undefined) a = a.min(node.minItems);
      if (node.maxItems !== undefined) a = a.max(node.maxItems);
      return a;
    }
    case "object": {
      const shape: Record<string, ZodTypeAny> = {};
      const required = new Set(node.required ?? []);
      for (const [key, child] of Object.entries(node.properties ?? {})) {
        const field = toZod(child);
        shape[key] = required.has(key) ? field : field.optional();
      }
      // The generator always narrows objects to additionalProperties: false, so
      // an argument the schema does not name is rejected rather than forwarded.
      return node.additionalProperties === true ? z.object(shape).loose() : z.object(shape).strict();
    }
    default:
      return z.unknown();
  }
}

/** The SDK's `registerTool` takes a shape, so the top level is unwrapped. */
export function toZodShape(node: JsonSchemaNode): Record<string, ZodTypeAny> {
  if (node.type !== "object" || !node.properties) return {};
  const shape: Record<string, ZodTypeAny> = {};
  const required = new Set(node.required ?? []);
  for (const [key, child] of Object.entries(node.properties)) {
    const field = toZod(child);
    shape[key] = required.has(key) ? field : field.optional();
  }
  return shape;
}
