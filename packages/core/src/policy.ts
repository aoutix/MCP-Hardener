import { z } from "zod";
import { parse as parseYaml } from "yaml";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve, isAbsolute } from "node:path";

/**
 * What a tool does to the world. Classification drives every default: a tool
 * with no effect is unclassified and therefore denied.
 */
export const EffectSchema = z.enum(["read", "write", "destructive"]);
export type Effect = z.infer<typeof EffectSchema>;

export const DecisionKindSchema = z.enum(["allow", "approve", "deny"]);
export type DecisionKind = z.infer<typeof DecisionKindSchema>;

/**
 * Default posture when no rule matches. `read-only` is the shipped default:
 * reads pass, anything that mutates is refused outright.
 */
export const PostureSchema = z.enum(["read-only", "approve-writes", "locked"]);
export type Posture = z.infer<typeof PostureSchema>;

/** Bounds on a single argument, checked before a rule's decision is honored. */
export const ArgConstraintSchema = z
  .object({
    max: z.number().optional(),
    min: z.number().optional(),
    enum: z.array(z.union([z.string(), z.number(), z.boolean()])).optional(),
    pattern: z.string().optional(),
    maxLength: z.number().int().positive().optional(),
    required: z.boolean().optional(),
    const: z.union([z.string(), z.number(), z.boolean()]).optional()
  })
  .strict();
export type ArgConstraint = z.infer<typeof ArgConstraintSchema>;

export const RuleSchema = z
  .object({
    /** Stable identifier recorded in the audit log for every decision. */
    id: z.string().min(1),
    /** Glob over the agent-facing tool name. */
    match: z.string().min(1),
    /** Reclassifies the tool's effect when set. */
    effect: EffectSchema.optional(),
    decision: DecisionKindSchema,
    args: z.record(z.string(), ArgConstraintSchema).optional(),
    reason: z.string().optional()
  })
  .strict();
export type Rule = z.infer<typeof RuleSchema>;

/**
 * A tenant read out of a signature-verified bearer token.
 *
 * The only source kind safe to use when the token arrives per request from
 * the caller, which is the hosted-gateway case. The others take their value
 * from the deployment -- an env var, a static string, a credential the
 * operator placed -- and are trustworthy precisely because nothing the caller
 * controls reaches them.
 *
 * Kept separate from `jwt-claim` rather than added to it as a flag. There is
 * no setting here that turns verification off, and `jwt-claim` keeps meaning
 * what it has always meant instead of quietly becoming unsafe.
 */
export const JwtVerifiedSourceSchema = z
  .object({
    kind: z.literal("jwt-verified"),
    /** The claim carrying the tenant, e.g. "org_id". */
    claim: z.string().min(1),
    /** Where to fetch the signing keys. Dialled through the egress guard. */
    jwks_uri: z.string().url().optional(),
    /** A pinned PEM public key, for a deployment with no JWKS endpoint. */
    public_key: z.string().min(1).optional(),
    /** Both required: a token valid for somewhere else is not valid here. */
    issuer: z.string().min(1),
    audience: z.string().min(1),
    /** Header carrying the token. */
    header_name: z.string().min(1).default("authorization")
  })
  .strict()
  .refine((v) => (v.jwks_uri === undefined) !== (v.public_key === undefined), {
    message: "exactly one of tenant.source.jwks_uri or tenant.source.public_key is required"
  });
export type JwtVerifiedSource = z.infer<typeof JwtVerifiedSourceSchema>;

/**
 * Who may change this deployment's configuration through an API.
 *
 * Deliberately its own block rather than a field on `tenant.source`.
 * `tenant.source` answers "which customer is this", which is a tenancy
 * question; this answers "may they flip a switch", which is an authorization
 * one. Folding them together would also make an admin surface appear the
 * moment anyone configured JWT tenancy, and the common case is multi-tenant
 * hosting with no admin surface at all.
 *
 * One field on purpose. A list of privileged subjects here would be
 * operational state wearing the clothes of reviewed policy.
 */
export const AdminConfigSchema = z
  .object({
    /**
     * The scope a token must carry, compared with exact string equality.
     *
     * Pick one only this deployment's authorization server grants. A scope
     * some other resource server hands out would otherwise let its tokens
     * administer this one — `aud` is verified too, which limits the damage,
     * but the rule should not have to lean on that.
     */
    scope: z.string().min(1)
  })
  .strict();
export type AdminConfig = z.infer<typeof AdminConfigSchema>;

export const TenantSourceSchema = z.union([
  z.object({ kind: z.literal("env"), name: z.string().min(1) }).strict(),
  z.object({ kind: z.literal("header"), name: z.string().min(1) }).strict(),
  z.object({ kind: z.literal("jwt-claim"), name: z.string().min(1), token_env: z.string().min(1) }).strict(),
  z.object({ kind: z.literal("static"), value: z.string().min(1) }).strict(),
  JwtVerifiedSourceSchema
]);
export type TenantSource = z.infer<typeof TenantSourceSchema>;

export const TenantConfigSchema = z
  .object({
    /** Canonical parameter name, e.g. `org_id`. */
    field: z.string().min(1),
    /** Other spellings the same identifier appears under. */
    aliases: z.array(z.string().min(1)).default([]),
    source: TenantSourceSchema,
    /** Where the value is injected into the upstream request. */
    inject: z.array(z.enum(["path", "query", "body", "header"])).default(["path", "query", "body"]),
    /** Header name when `inject` includes "header". */
    header_name: z.string().optional(),
    /**
     * What to do when the agent supplies a tenant value that differs from the
     * one bound to the credential. `deny` refuses the call; `override` silently
     * replaces it. `deny` is the default because a mismatch is a signal.
     */
    on_mismatch: z.enum(["deny", "override"]).default("deny"),
    /** Refuse to start when the source yields no value. */
    required: z.boolean().default(true)
  })
  .strict();
export type TenantConfig = z.infer<typeof TenantConfigSchema>;

export const EgressConfigSchema = z
  .object({
    /** Hostnames, optionally `*.` prefixed and optionally `:port` suffixed. */
    allow: z.array(z.string().min(1)).default([]),
    methods: z.array(z.string().min(1)).default(["GET", "HEAD"]),
    max_body_bytes: z.number().int().positive().default(1_048_576),
    max_request_body_bytes: z.number().int().positive().default(262_144),
    timeout_ms: z.number().int().positive().default(10_000),
    max_redirects: z.number().int().min(0).default(0),
    /** Refuse targets that resolve to loopback, link-local or RFC1918 space. */
    block_private_ips: z.boolean().default(true),
    /** Permit plaintext HTTP. Off by default. */
    allow_http: z.boolean().default(false),
    /** Permit bare IP literals as targets. Off by default. */
    allow_ip_literals: z.boolean().default(false)
  })
  .strict();
export type EgressConfig = z.infer<typeof EgressConfigSchema>;

export const ApprovalsConfigSchema = z
  .object({
    /**
     * `elicit` asks the MCP host; `cli` parks the request for out-of-band
     * review; `both` tries elicitation and falls back to the CLI, which is the
     * only option that works across clients with and without the capability.
     */
    mode: z.enum(["elicit", "cli", "both", "deny"]).default("both"),
    ttl_seconds: z.number().int().positive().default(300),
    /** A grant releases exactly one call. */
    single_use: z.boolean().default(true),
    store_path: z.string().default("~/.hmcp/approvals.sqlite")
  })
  .strict();
export type ApprovalsConfig = z.infer<typeof ApprovalsConfigSchema>;

export const AuditConfigSchema = z
  .object({
    enabled: z.boolean().default(true),
    path: z.string().default("~/.hmcp/audit.jsonl"),
    /** Tamper-evident chaining. Disabling it is a scanner finding. */
    hash_chain: z.boolean().default(true),
    /** Extra argument names to redact beyond the built-in denylist. */
    redact: z.array(z.string().min(1)).default([]),
    /** Record redacted arguments alongside their hash. */
    record_args: z.boolean().default(true)
  })
  .strict();
export type AuditConfig = z.infer<typeof AuditConfigSchema>;

export const DefaultsSchema = z
  .object({
    mode: PostureSchema.default("read-only"),
    /** Tools whose effect is unknown. Denying is the whole point. */
    on_unclassified: z.enum(["deny", "approve"]).default("deny")
  })
  .strict();

export const PolicySchema = z
  .object({
    version: z.literal(1),
    name: z.string().optional(),
    defaults: DefaultsSchema.default(() => DefaultsSchema.parse({})),
    rules: z.array(RuleSchema).default([]),
    tenant: TenantConfigSchema.optional(),
    admin: AdminConfigSchema.optional(),
    egress: EgressConfigSchema.default(() => EgressConfigSchema.parse({})),
    approvals: ApprovalsConfigSchema.default(() => ApprovalsConfigSchema.parse({})),
    audit: AuditConfigSchema.default(() => AuditConfigSchema.parse({})),
    /** Cap on how many tools may be exposed at once. */
    tool_budget: z.number().int().positive().default(40)
  })
  .strict()
  .superRefine((policy, ctx) => {
    const seen = new Set<string>();
    policy.rules.forEach((rule, i) => {
      if (seen.has(rule.id)) {
        ctx.addIssue({
          code: "custom",
          path: ["rules", i, "id"],
          message: `duplicate rule id "${rule.id}" - ids appear in the audit log and must be unique`
        });
      }
      seen.add(rule.id);
      if (rule.args) {
        for (const [arg, c] of Object.entries(rule.args)) {
          if (c.pattern) {
            try {
              new RegExp(c.pattern);
            } catch {
              ctx.addIssue({
                code: "custom",
                path: ["rules", i, "args", arg, "pattern"],
                message: `invalid regular expression: ${c.pattern}`
              });
            }
          }
        }
      }
    });
    if (policy.tenant?.inject.includes("header") && !policy.tenant.header_name) {
      ctx.addIssue({
        code: "custom",
        path: ["tenant", "header_name"],
        message: 'tenant.header_name is required when inject includes "header"'
      });
    }
  });

export type Policy = z.infer<typeof PolicySchema>;

/** Expands a leading `~` and resolves against `base`. */
export function expandPath(p: string, base = process.cwd()): string {
  const expanded = p.startsWith("~/") || p === "~" ? resolve(homedir(), p.slice(1).replace(/^\//, "")) : p;
  return isAbsolute(expanded) ? expanded : resolve(base, expanded);
}

export class PolicyError extends Error {
  constructor(message: string, readonly issues?: readonly { path: string; message: string }[]) {
    super(message);
    this.name = "PolicyError";
  }
}

export function parsePolicy(raw: unknown, source = "<inline>"): Policy {
  const result = PolicySchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues.map((i) => ({
      path: i.path.join("."),
      message: i.message
    }));
    const detail = issues.map((i) => `  ${i.path || "(root)"}: ${i.message}`).join("\n");
    throw new PolicyError(`invalid policy in ${source}:\n${detail}`, issues);
  }
  return result.data;
}

export function loadPolicy(path: string): Policy {
  const full = expandPath(path);
  let text: string;
  try {
    text = readFileSync(full, "utf8");
  } catch (err) {
    throw new PolicyError(`cannot read policy at ${full}: ${(err as Error).message}`);
  }
  return parsePolicy(parseYaml(text), full);
}

/**
 * The posture this project ships: reads allowed, writes and deletes refused,
 * nothing leaves the machine, everything logged.
 */
export function defaultPolicy(): Policy {
  return parsePolicy({ version: 1, name: "default-read-only" });
}
