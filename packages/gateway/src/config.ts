import { readFileSync } from "node:fs";
import { dirname } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { expandPath, parsePolicy, type Policy } from "@hmcp/core";

/** One MCP server the gateway sits in front of. */
export const UpstreamSchema = z.discriminatedUnion("transport", [
  z
    .object({
      name: z
        .string()
        .min(1)
        .regex(/^[a-z0-9_]+$/, "an upstream name must be lowercase letters, digits and underscores"),
      transport: z.literal("stdio"),
      command: z.string().min(1),
      args: z.array(z.string()).default([]),
      /** Environment for the child process. Nothing else is inherited. */
      env: z.record(z.string(), z.string()).default({}),
      /** Names to pass through from the gateway's own environment. */
      pass_env: z.array(z.string()).default([]),
      cwd: z.string().optional()
    })
    .strict(),
  z
    .object({
      name: z
        .string()
        .min(1)
        .regex(/^[a-z0-9_]+$/, "an upstream name must be lowercase letters, digits and underscores"),
      transport: z.literal("http"),
      url: z.string().url(),
      headers: z.record(z.string(), z.string()).default({})
    })
    .strict()
]);
export type Upstream = z.infer<typeof UpstreamSchema>;

export const GatewayConfigSchema = z
  .object({
    version: z.literal(1),
    name: z.string().default("hmcp-gateway"),
    /** Inline policy, or a path to one. */
    policy: z.union([z.string(), z.record(z.string(), z.unknown())]),
    upstreams: z.array(UpstreamSchema).min(1),
    /**
     * What to do with a tool whose description contains an injection attempt.
     * `strip` replaces the description and keeps the tool usable; `deny` hides
     * the tool; `annotate` leaves the text but prefixes a warning.
     */
    on_injection: z.enum(["strip", "deny", "annotate"]).default("strip"),
    /** Prefix upstream tool names with `<server>__`. */
    namespace: z.boolean().default(true)
  })
  .strict()
  .superRefine((config, ctx) => {
    const seen = new Set<string>();
    config.upstreams.forEach((upstream, i) => {
      if (seen.has(upstream.name)) {
        ctx.addIssue({
          code: "custom",
          path: ["upstreams", i, "name"],
          message: `duplicate upstream name "${upstream.name}"`
        });
      }
      seen.add(upstream.name);
    });
  });

export type GatewayConfig = z.infer<typeof GatewayConfigSchema>;

export interface LoadedGatewayConfig {
  readonly config: GatewayConfig;
  readonly policy: Policy;
}

export function loadGatewayConfig(path: string): LoadedGatewayConfig {
  const full = expandPath(path);
  const raw = parseYaml(readFileSync(full, "utf8")) as unknown;
  const result = GatewayConfigSchema.safeParse(raw);
  if (!result.success) {
    const detail = result.error.issues.map((i) => `  ${i.path.join(".") || "(root)"}: ${i.message}`).join("\n");
    throw new Error(`invalid gateway config ${full}:\n${detail}`);
  }
  const config = result.data;

  // A relative policy path is relative to the config file's directory, which is
  // what someone writing `policy: ./policy.yaml` means.
  const policy =
    typeof config.policy === "string"
      ? parsePolicy(parseYaml(readFileSync(expandPath(config.policy, dirname(full)), "utf8")), config.policy)
      : parsePolicy(config.policy, `${full}#/policy`);

  return { config, policy };
}
