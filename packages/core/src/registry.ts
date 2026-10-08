import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";
import { expandPath } from "./policy.js";

/**
 * The set of servers a console knows about.
 *
 * Paths enter the system only here, through an explicit registration that is
 * validated when it is made. Nothing else in a console takes a filesystem path
 * from a caller, which is what keeps a read route from being talked into
 * opening an arbitrary file.
 */

const ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export const RegistryEntrySchema = z.discriminatedUnion("kind", [
  z
    .object({
      id: z.string().regex(ID, "an id is lower-case letters, digits, dashes and underscores"),
      kind: z.literal("generated"),
      label: z.string().min(1),
      /** Directory holding tools.json and policy.yaml. */
      dir: z.string().min(1).optional(),
      tools_path: z.string().min(1).optional(),
      policy_path: z.string().min(1).optional(),
      /** Overrides the audit `component` used to attribute records. */
      component: z.string().min(1).optional(),
      added_at: z.string()
    })
    .strict()
    .superRefine((entry, ctx) => {
      if (!entry.dir && !entry.tools_path) {
        ctx.addIssue({ code: "custom", path: ["dir"], message: "set dir, or tools_path and policy_path" });
      }
      if (entry.dir && (entry.tools_path || entry.policy_path)) {
        ctx.addIssue({ code: "custom", path: ["dir"], message: "set dir or the explicit paths, not both" });
      }
    }),
  z
    .object({
      id: z.string().regex(ID, "an id is lower-case letters, digits, dashes and underscores"),
      kind: z.literal("gateway"),
      label: z.string().min(1),
      config_path: z.string().min(1),
      component: z.string().min(1).optional(),
      added_at: z.string()
    })
    .strict()
]);
export type RegistryEntry = z.infer<typeof RegistryEntrySchema>;

export const RegistrySchema = z
  .object({
    version: z.literal(1),
    servers: z.array(RegistryEntrySchema).default([])
  })
  .strict()
  .superRefine((reg, ctx) => {
    // Mirrors the duplicate-rule-id check in PolicySchema: a repeated id would
    // make which server you were looking at depend on array order.
    const seen = new Set<string>();
    for (const [index, entry] of reg.servers.entries()) {
      if (seen.has(entry.id)) {
        ctx.addIssue({ code: "custom", path: ["servers", index, "id"], message: `duplicate server id "${entry.id}"` });
      }
      seen.add(entry.id);
    }
  });
export type Registry = z.infer<typeof RegistrySchema>;

export function defaultRegistryPath(): string {
  return expandPath(process.env["HMCP_REGISTRY"] ?? "~/.hmcp/servers.json");
}

export class RegistryError extends Error {
  constructor(
    message: string,
    readonly issues?: readonly { path: string; message: string }[]
  ) {
    super(message);
    this.name = "RegistryError";
  }
}

export function parseRegistry(raw: unknown, source = "<inline>"): Registry {
  const result = RegistrySchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues.map((i) => ({ path: i.path.join(".") || "(root)", message: i.message }));
    throw new RegistryError(
      `invalid server registry ${source}:\n${issues.map((i) => `  ${i.path}: ${i.message}`).join("\n")}`,
      issues
    );
  }
  return result.data;
}

/** A missing registry is an empty one, not an error. */
export function readRegistry(path = defaultRegistryPath()): Registry {
  const full = expandPath(path);
  if (!existsSync(full)) return { version: 1, servers: [] };
  return parseRegistry(JSON.parse(readFileSync(full, "utf8")), full);
}

/**
 * Writes via a temporary file and a rename, so a crash mid-write cannot leave a
 * half-written registry that then fails to parse and hides every server.
 */
export function writeRegistry(registry: Registry, path = defaultRegistryPath()): void {
  const full = expandPath(path);
  parseRegistry(registry, full);
  mkdirSync(dirname(full), { recursive: true });
  const tmp = join(dirname(full), `.${Date.now()}.servers.json.tmp`);
  writeFileSync(tmp, JSON.stringify(registry, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
  renameSync(tmp, full);
}

/** Where a generated entry's two files live. */
export function generatedPaths(entry: RegistryEntry & { kind: "generated" }): {
  toolsPath: string;
  policyPath: string;
} {
  if (entry.dir) {
    const dir = expandPath(entry.dir);
    return { toolsPath: join(dir, "tools.json"), policyPath: join(dir, "policy.yaml") };
  }
  return {
    toolsPath: expandPath(entry.tools_path!),
    policyPath: expandPath(entry.policy_path ?? "policy.yaml")
  };
}
