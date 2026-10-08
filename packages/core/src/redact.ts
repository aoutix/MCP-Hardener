/**
 * Redaction runs before anything is written to the audit log or shown in an
 * approval prompt. The same patterns back scanner rule HMCP004, which looks for
 * secrets that leaked into an API spec.
 */

/** Argument/field names whose values are never recorded. */
export const SECRET_KEY_PATTERN =
  /(^|[_\-.])(pass|passwd|password|secret|token|apikey|api_key|accesskey|access_key|authorization|auth|credential|credentials|privatekey|private_key|session|sessionid|cookie|bearer|signature|otp|pin|ssn|cardnumber|card_number|cvv|cvc|client_secret|refresh_token|id_token)([_\-.]|$)/i;

export interface SecretPattern {
  readonly id: string;
  readonly label: string;
  readonly regex: RegExp;
}

/**
 * Value shapes that are secrets regardless of the key they sit under. Ordered
 * most-specific first so the reported label is the useful one.
 */
export const SECRET_VALUE_PATTERNS: readonly SecretPattern[] = [
  { id: "private-key", label: "pem private key", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { id: "aws-access-key", label: "aws access key id", regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/ },
  { id: "github-token", label: "github token", regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/ },
  { id: "github-pat", label: "github fine-grained pat", regex: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { id: "slack-token", label: "slack token", regex: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: "google-api-key", label: "google api key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "stripe-key", label: "stripe secret key", regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/ },
  { id: "anthropic-key", label: "anthropic-style key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { id: "openai-key", label: "openai-style key", regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/ },
  { id: "jwt", label: "jwt", regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
  { id: "basic-auth-url", label: "credentials in url", regex: /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i },
  { id: "bearer-header", label: "bearer header", regex: /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/ },
  {
    id: "high-entropy-hex",
    label: "long hex string",
    // Requires both a digit and a letter: a real hash or token has both, while
    // a long run of one repeated character is almost never a secret.
    regex: /\b(?=[0-9a-fA-F]{40,}\b)(?=[0-9a-fA-F]*[0-9])(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{40,}\b/
  }
];

export interface SecretHit {
  readonly patternId: string;
  readonly label: string;
  readonly match: string;
}

/** Finds secret-shaped substrings. Used by the scanner; returns [] for clean text. */
export function findSecrets(text: string): SecretHit[] {
  const hits: SecretHit[] = [];
  for (const p of SECRET_VALUE_PATTERNS) {
    const m = p.regex.exec(text);
    if (m) hits.push({ patternId: p.id, label: p.label, match: m[0] });
  }
  return hits;
}

export interface RedactOptions {
  /** Extra key names (exact, case-insensitive) to redact. */
  readonly extraKeys?: readonly string[];
  /** Strings longer than this are truncated. */
  readonly maxStringLength?: number;
  /** Depth beyond which subtrees collapse to a marker. */
  readonly maxDepth?: number;
  /** Arrays longer than this are truncated. */
  readonly maxArrayLength?: number;
}

const DEFAULTS = { maxStringLength: 512, maxDepth: 12, maxArrayLength: 100 };

function isSecretKey(key: string, extra: ReadonlySet<string>): boolean {
  return extra.has(key.toLowerCase()) || SECRET_KEY_PATTERN.test(key);
}

function redactString(value: string, maxLen: number): string {
  for (const p of SECRET_VALUE_PATTERNS) {
    if (p.regex.test(value)) return `[redacted:${p.id}]`;
  }
  if (value.length > maxLen) {
    return `${value.slice(0, maxLen)}…[truncated ${value.length - maxLen} chars]`;
  }
  return value;
}

/**
 * Deep copy with secrets removed. Never mutates the input, tolerates cycles,
 * and always returns something JSON-serializable - it sits on the path to the
 * audit log, so it must not be able to throw.
 */
export function redact(value: unknown, options: RedactOptions = {}): unknown {
  const maxStringLength = options.maxStringLength ?? DEFAULTS.maxStringLength;
  const maxDepth = options.maxDepth ?? DEFAULTS.maxDepth;
  const maxArrayLength = options.maxArrayLength ?? DEFAULTS.maxArrayLength;
  const extra = new Set((options.extraKeys ?? []).map((k) => k.toLowerCase()));
  const seen = new WeakSet<object>();

  const walk = (node: unknown, depth: number): unknown => {
    if (node === null || node === undefined) return node ?? null;
    const t = typeof node;
    if (t === "string") return redactString(node as string, maxStringLength);
    if (t === "number") return Number.isFinite(node as number) ? node : String(node);
    if (t === "boolean") return node;
    if (t === "bigint") return (node as bigint).toString();
    if (t === "function" || t === "symbol") return `[${t}]`;
    if (node instanceof Date) return node.toISOString();
    if (depth >= maxDepth) return "[redacted:max-depth]";

    const obj = node as object;
    if (seen.has(obj)) return "[redacted:circular]";
    seen.add(obj);

    try {
      if (Array.isArray(node)) {
        const items = node.slice(0, maxArrayLength).map((v) => walk(v, depth + 1));
        if (node.length > maxArrayLength) items.push(`[truncated ${node.length - maxArrayLength} items]`);
        return items;
      }
      if (node instanceof Map) return walk(Object.fromEntries(node), depth);
      if (node instanceof Set) return walk([...node], depth);

      const out: Record<string, unknown> = {};
      for (const [key, v] of Object.entries(node as Record<string, unknown>)) {
        out[key] = isSecretKey(key, extra) ? "[redacted:key]" : walk(v, depth + 1);
      }
      return out;
    } finally {
      seen.delete(obj);
    }
  };

  return walk(value, 0);
}

/** Convenience wrapper for argument objects. */
export function redactArgs(
  args: Record<string, unknown> | undefined,
  extraKeys: readonly string[] = []
): Record<string, unknown> {
  const result = redact(args ?? {}, { extraKeys });
  return result && typeof result === "object" && !Array.isArray(result)
    ? (result as Record<string, unknown>)
    : {};
}
