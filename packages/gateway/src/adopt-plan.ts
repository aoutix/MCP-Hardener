import { classifyAddress, isIpLiteral } from "@hmcp/core";
import { UpstreamSchema, type Upstream } from "./config.js";
import { isRemote, type ClaudeServer } from "./client-config.js";

/**
 * Turning the MCP servers a client already has into gateway upstreams.
 *
 * Pure: no filesystem, no network, no child processes. Everything that can be
 * decided from the config alone is decided here, so the hard part of adoption
 * is testable without starting anything.
 *
 * The rule throughout is that a server is either adopted or reported with a
 * reason and a remedy. Nothing is silently dropped -- a server that quietly
 * stops being reachable after adoption is the worst outcome this command has,
 * because it looks exactly like the gateway working.
 */

export interface PlannedUpstream {
  readonly upstream: Upstream;
  /** What the client called it, which is not always a legal upstream name. */
  readonly originalName: string;
  readonly warnings: readonly string[];
}

export interface SkippedServer {
  readonly name: string;
  readonly reason: string;
  readonly remedy: string;
}

export interface AdoptionPlan {
  readonly upstreams: readonly PlannedUpstream[];
  readonly skipped: readonly SkippedServer[];
  /**
   * Environment the gateway's own client entry must carry, so each upstream
   * can name it in `pass_env`.
   */
  readonly gatewayEnv: Readonly<Record<string, string>>;
  /** Hostnames to seed `egress.allow` with. */
  readonly egressAllow: readonly string[];
  /** An adopted HTTP upstream is only reachable with the SSRF guard relaxed. */
  readonly egressNeedsLocalHttp: boolean;
  /** `--copy-env` put a literal value into the generated config. */
  readonly secretsOnDisk: boolean;
  /** Original name to upstream name, for every server whose name changed. */
  readonly nameMap: ReadonlyMap<string, string>;
  /** Malformed client entries, passed through so one report covers everything. */
  readonly malformed: readonly { readonly name: string; readonly message: string }[];
}

export interface PlanOptions {
  /** The name the gateway's own entry will have, so it is never adopted. */
  readonly gatewayEntryName: string;
  /** The config path the gateway will be pointed at, for the recursion check. */
  readonly gatewayConfigPath?: string | undefined;
  /** Resolve `${VAR}` and write literal secrets into the generated config. */
  readonly copyEnv?: boolean | undefined;
  /** Adopt HTTP upstreams on loopback or private addresses. */
  readonly allowLocalHttp?: boolean | undefined;
  /** Pin seeded egress entries to the port the upstream uses. */
  readonly strictEgress?: boolean | undefined;
  /** `--name <original>=<upstream>` overrides. */
  readonly names?: ReadonlyMap<string, string> | undefined;
  /**
   * Upstream names already in use, when adopting more servers into a gateway
   * that exists. A new upstream must not take a name whose tools already have
   * exposure rows and approvals stored under it.
   */
  readonly reservedNames?: readonly string[] | undefined;
  /** For `${VAR}` resolution under `--copy-env`. */
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  readonly malformed?: readonly { readonly name: string; readonly message: string }[] | undefined;
}

const UPSTREAM_NAME = /^[a-z0-9_]+$/;
const INTERPOLATION = /\$\{[^}]*\}/;

/**
 * An upstream name legal under `UpstreamSchema`: lowercase letters, digits and
 * underscores.
 *
 * This is not cosmetic. The result becomes the `<server>__` prefix on every
 * tool name, and that name is a storage key -- the exposure switch, every
 * approval row and each binding hash are stored under it. So it has to be
 * stable across runs, which is why collisions resolve by sorted original name
 * rather than by whatever order the client's JSON happened to be in.
 */
export function normalizeUpstreamName(name: string): string {
  return name
    .normalize("NFC")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function assignNames(
  originals: readonly string[],
  overrides: ReadonlyMap<string, string>,
  reserved: readonly string[]
): { map: Map<string, string>; problems: Map<string, string> } {
  const map = new Map<string, string>();
  const problems = new Map<string, string>();
  const taken = new Set<string>(reserved);
  let anonymous = 0;

  // Sorted, so two runs over the same set produce the same prefixes.
  for (const original of [...originals].sort()) {
    const override = overrides.get(original);
    if (override !== undefined) {
      if (!UPSTREAM_NAME.test(override)) {
        problems.set(original, `--name ${original}=${override} is not a legal upstream name (${UPSTREAM_NAME})`);
        continue;
      }
      if (taken.has(override)) {
        problems.set(original, `--name ${original}=${override} collides with another upstream`);
        continue;
      }
      taken.add(override);
      map.set(original, override);
      continue;
    }

    let base = normalizeUpstreamName(original);
    if (base === "") base = `server_${++anonymous}`;
    let candidate = base;
    for (let n = 2; taken.has(candidate); n++) candidate = `${base}_${n}`;
    taken.add(candidate);
    map.set(original, candidate);
  }

  return { map, problems };
}

/** Hostname of a URL, or undefined when it will not parse. */
function hostOf(url: string): { hostname: string; host: string; protocol: string } | undefined {
  try {
    const parsed = new URL(url);
    return { hostname: parsed.hostname, host: parsed.host, protocol: parsed.protocol };
  } catch {
    return undefined;
  }
}

/**
 * Whether this host is one the egress guard refuses without the SSRF
 * protections turned off.
 *
 * `localhost` counts even though it is not a literal: `resolveVerified`
 * resolves it and then refuses the loopback address it gets back, so the
 * hostname form is no more adoptable than `127.0.0.1`.
 */
function isLocalTarget(hostname: string): boolean {
  const bare = hostname.replace(/^\[|\]$/g, "");
  if (bare === "localhost" || bare.endsWith(".localhost")) return true;
  if (!isIpLiteral(bare)) return false;
  return classifyAddress(bare).blocked;
}

/**
 * Whether this entry is the gateway itself.
 *
 * Three independent checks because any one of them can be defeated by a user
 * who renamed something: the entry's name, the command it runs, and the config
 * it points at. Adopting the gateway would make it an upstream of itself.
 */
function isGatewayItself(name: string, server: ClaudeServer, options: PlanOptions): boolean {
  if (name === options.gatewayEntryName) return true;
  if (isRemote(server)) return false;
  const words = [server.command, ...server.args];
  if (words.some((w) => w.includes("hmcp-gateway"))) return true;
  if (options.gatewayConfigPath !== undefined && words.includes(options.gatewayConfigPath)) return true;
  return false;
}

export function planAdoption(servers: ReadonlyMap<string, ClaudeServer>, options: PlanOptions): AdoptionPlan {
  const upstreams: PlannedUpstream[] = [];
  const skipped: SkippedServer[] = [];
  const gatewayEnv: Record<string, string> = {};
  /** Which server claimed each env name, so a collision can name both. */
  const envOwner = new Map<string, string>();
  const egressAllow = new Set<string>();
  const nameMap = new Map<string, string>();
  let egressNeedsLocalHttp = false;
  let secretsOnDisk = false;

  const { map: names, problems: nameProblems } = assignNames(
    [...servers.keys()],
    options.names ?? new Map<string, string>(),
    options.reservedNames ?? []
  );

  for (const [original, problem] of nameProblems) {
    skipped.push({
      name: original,
      reason: problem,
      remedy: `pass a different --name ${original}=<name> using lowercase letters, digits and underscores`
    });
  }

  for (const original of [...servers.keys()].sort()) {
    const server = servers.get(original)!;
    const name = names.get(original);
    if (name === undefined) continue; // already reported as a name problem

    if (isGatewayItself(original, server, options)) {
      skipped.push({
        name: original,
        reason: "this entry is the gateway itself",
        remedy: "nothing to do; the gateway cannot be an upstream of itself"
      });
      continue;
    }

    if (isRemote(server)) {
      const planned = planRemote(original, name, server, options, egressAllow);
      if ("skip" in planned) {
        skipped.push(planned.skip);
        continue;
      }
      if (planned.needsLocalHttp) egressNeedsLocalHttp = true;
      if (planned.secretOnDisk) secretsOnDisk = true;
      upstreams.push(planned.planned);
      if (name !== original) nameMap.set(original, name);
      continue;
    }

    const planned = planStdio(original, name, server, options, gatewayEnv, envOwner);
    if ("skip" in planned) {
      skipped.push(planned.skip);
      continue;
    }
    if (planned.secretOnDisk) secretsOnDisk = true;
    upstreams.push(planned.planned);
    if (name !== original) nameMap.set(original, name);
  }

  /*
   * The translator and the schema must not be able to drift. Validating here
   * means a tightened `UpstreamSchema` fails in this package's tests rather
   * than in a user's terminal as a zod dump halfway through adoption.
   */
  for (const { upstream, originalName } of upstreams) {
    const result = UpstreamSchema.safeParse(upstream);
    if (!result.success) {
      throw new Error(
        `internal: the upstream planned for "${originalName}" does not satisfy UpstreamSchema:\n` +
          result.error.issues.map((i) => `  ${i.path.join(".") || "(root)"}: ${i.message}`).join("\n")
      );
    }
  }

  return {
    upstreams,
    skipped,
    gatewayEnv,
    egressAllow: [...egressAllow].sort(),
    egressNeedsLocalHttp,
    secretsOnDisk,
    nameMap,
    malformed: options.malformed ?? []
  };
}

type PlanResult =
  | { readonly skip: SkippedServer }
  | { readonly planned: PlannedUpstream; readonly needsLocalHttp?: boolean; readonly secretOnDisk?: boolean };

function planRemote(
  original: string,
  name: string,
  server: Extract<ClaudeServer, { type: "http" | "sse" }>,
  options: PlanOptions,
  egressAllow: Set<string>
): PlanResult {
  if (server.type === "sse") {
    return {
      skip: {
        name: original,
        reason: "it speaks SSE, and the gateway's upstream transports are stdio and Streamable HTTP only",
        remedy:
          "ask the vendor for the Streamable HTTP endpoint, or leave this server configured directly and " +
          "outside the gateway"
      }
    };
  }

  const parsed = hostOf(server.url);
  if (!parsed) {
    return {
      skip: {
        name: original,
        reason: `its url ${JSON.stringify(server.url)} will not parse`,
        remedy: "fix the url in the client config and run adopt again"
      }
    };
  }

  const warnings: string[] = [];
  let secretOnDisk = false;
  const headers: Record<string, string> = {};

  for (const [header, value] of Object.entries(server.headers)) {
    if (!INTERPOLATION.test(value)) {
      headers[header] = value;
      continue;
    }
    /*
     * `gateway.yaml` rejects `${...}` in a header rather than expanding it, so
     * a config that looked like it was interpolating a secret would ship the
     * word. Refusing here, with the name of the header, is the same refusal
     * the schema would make later -- but as a line in a report instead of a
     * zod dump mid-adoption.
     *
     * Note this is not a case for credential_passthrough, whatever the
     * schema's own message suggests: that forwards the *caller's* token, and a
     * client speaking stdio to the gateway presents no token at all.
     */
    if (!options.copyEnv) {
      return {
        skip: {
          name: original,
          reason: `its ${header} header interpolates ${value.match(INTERPOLATION)![0]}, which gateway.yaml refuses because the value would be sent literally`,
          remedy:
            "re-run with --copy-env to resolve it from this shell now, or add the upstream by hand with the " +
            "literal value in place"
        }
      };
    }
    const resolved = expandInterpolation(value, options.env ?? process.env);
    if (resolved === undefined) {
      return {
        skip: {
          name: original,
          reason: `its ${header} header interpolates a variable that is not set in this shell`,
          remedy: `export it and run adopt again, or add the upstream by hand with the literal value`
        }
      };
    }
    headers[header] = resolved;
    secretOnDisk = true;
    warnings.push(`the ${header} header was resolved to a literal value in the generated config`);
  }

  if (isLocalTarget(parsed.hostname) && !options.allowLocalHttp) {
    return {
      skip: {
        name: original,
        reason:
          `it listens on ${parsed.host}, and the egress guard refuses loopback and private addresses ` +
          `(egress.block_private_ips, allow_ip_literals and allow_http all stand in the way)`,
        remedy:
          "re-run with --allow-local-http, which turns those protections off for every HTTP upstream this " +
          "gateway has -- not just this one"
      }
    };
  }

  const local = isLocalTarget(parsed.hostname);
  if (local) {
    warnings.push(
      "adopting this upstream relaxes the SSRF protections for every HTTP upstream of this gateway"
    );
  }
  if (parsed.protocol === "http:") {
    warnings.push("it is reached over plaintext HTTP, which the generated policy has to permit");
  }

  egressAllow.add(options.strictEgress ? parsed.host : parsed.hostname);

  return {
    planned: {
      upstream: UpstreamSchema.parse({
        name,
        transport: "http",
        url: server.url,
        headers
      }),
      originalName: original,
      warnings
    },
    needsLocalHttp: local,
    secretOnDisk
  };
}

function planStdio(
  original: string,
  name: string,
  server: Extract<ClaudeServer, { command: string }>,
  options: PlanOptions,
  gatewayEnv: Record<string, string>,
  envOwner: Map<string, string>
): PlanResult {
  const warnings: string[] = [];
  const passEnv: string[] = [];
  const ownEnv: Record<string, string> = {};
  let secretOnDisk = false;

  for (const key of Object.keys(server.env).sort()) {
    const value = server.env[key]!;

    if (options.copyEnv) {
      /*
       * `--copy-env` is the only place two upstreams can hold different values
       * for the same variable name, because each gets its own `env` block.
       */
      const resolved = INTERPOLATION.test(value) ? expandInterpolation(value, options.env ?? process.env) : value;
      if (resolved === undefined) {
        return {
          skip: {
            name: original,
            reason: `its ${key} is set from a variable that is not set in this shell`,
            remedy: "export it and run adopt again"
          }
        };
      }
      ownEnv[key] = resolved;
      secretOnDisk = true;
      continue;
    }

    /*
     * The value moves to the gateway's own client entry and the upstream names
     * it in `pass_env`. That keeps the secret in the file it was already in,
     * at the permissions it already had, and keeps `gateway.yaml` free of
     * secrets and safe to commit. It also works whether the original value was
     * a literal or a `${VAR}` the client expands, because the value is carried
     * across verbatim for the client to handle as it already did.
     *
     * Copying it into `gateway.yaml` instead would put a secret in a new file,
     * and naming it in `pass_env` without moving it would read the *gateway's*
     * environment, where a value that only ever lived in the client config is
     * simply absent -- the server would then fail to authenticate with nothing
     * to point at.
     */
    const owner = envOwner.get(key);
    if (owner !== undefined && gatewayEnv[key] !== value) {
      /*
       * `pass_env` is a list of names, so it cannot rename: one gateway entry
       * can carry exactly one value for `API_KEY`. Both servers are skipped
       * rather than one quietly getting the other's credential.
       */
      return {
        skip: {
          name: original,
          reason:
            `it sets ${key} to a different value than "${owner}" does, and the gateway forwards an ` +
            `environment variable under its own name, so one entry cannot carry both`,
          remedy: `re-run with --copy-env, which gives each upstream its own env block in gateway.yaml`
        }
      };
    }
    if (owner === undefined) {
      gatewayEnv[key] = value;
      envOwner.set(key, original);
    }
    passEnv.push(key);
  }

  if (passEnv.length > 0) {
    warnings.push(`${passEnv.join(", ")} moved to the gateway's own client entry and forwarded by name`);
  }

  return {
    planned: {
      upstream: UpstreamSchema.parse({
        name,
        transport: "stdio",
        command: server.command,
        args: server.args,
        env: ownEnv,
        pass_env: passEnv
      }),
      originalName: original,
      warnings
    },
    secretOnDisk
  };
}

/**
 * Expands `${VAR}` and `${VAR:-default}`, the two forms the client supports.
 *
 * Returns undefined when a variable with no default is unset, so the caller
 * can skip the server and say which one rather than writing an empty
 * credential into a config.
 */
export function expandInterpolation(
  value: string,
  env: Readonly<Record<string, string | undefined>>
): string | undefined {
  let missing = false;
  const out = value.replace(/\$\{([^}:]+)(?::-([^}]*))?\}/g, (_match, name: string, fallback?: string) => {
    const resolved = env[name];
    if (resolved !== undefined && resolved !== "") return resolved;
    if (fallback !== undefined) return fallback;
    missing = true;
    return "";
  });
  return missing ? undefined : out;
}
