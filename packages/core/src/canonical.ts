import { createHash } from "node:crypto";

/**
 * Deterministic JSON serialization: object keys sorted, no insignificant
 * whitespace, `undefined` properties dropped. Two structurally equal values
 * always produce the same string, which is what makes argument-bound approval
 * grants and the audit hash chain meaningful.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value));
}

function normalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) return String(value);
    if (typeof value === "bigint") return value.toString();
    return value;
  }
  if (Array.isArray(value)) return value.map(normalize);
  if (value instanceof Date) return value.toISOString();

  const source = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(source).sort()) {
    const v = source[key];
    if (v === undefined) continue;
    out[key] = normalize(v);
  }
  return out;
}

export function sha256(...parts: string[]): string {
  const h = createHash("sha256");
  for (const part of parts) h.update(part, "utf8");
  return h.digest("hex");
}

/** Hash of a value's canonical form. Used for args_hash in the audit log. */
export function hashValue(value: unknown): string {
  return sha256(canonicalJson(value));
}

/**
 * Identity of a specific call: the tool plus its exact arguments. An approval
 * grant is bound to this, so approving `{amount: 10}` cannot release
 * `{amount: 10000}`.
 */
export function bindingHash(tool: string, args: unknown): string {
  return sha256(tool, "\n", canonicalJson(args ?? {}));
}
