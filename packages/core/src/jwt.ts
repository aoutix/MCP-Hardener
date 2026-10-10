import { createRemoteJWKSet, customFetch, errors, importSPKI, jwtVerify, type JWTPayload, type KeyObject } from "jose";
import { TenantError, normalizeTenantKey } from "./tenant.js";
import type { EgressGuard } from "./egress.js";
import type { JwtVerifiedSource } from "./policy.js";

/**
 * Deriving a tenant from a token the caller supplied.
 *
 * Everywhere else in this project the tenant comes from the deployment: a
 * static value, an environment variable, a claim in a credential the operator
 * configured. Those are trustworthy because nothing the agent controls reaches
 * them, which is exactly what `jwt-claim`'s comment says — "our own
 * credential, not attacker-supplied input, so there is nothing to forge".
 *
 * A hosted gateway breaks that assumption. The token arrives per request, from
 * the caller, and the tenant read out of it becomes the key that every stored
 * row is filed under. If the signature is not checked, anyone can rename
 * themselves into another customer's scope and redeem their approvals: the
 * upstream API would still refuse their data, but the gateway's own state —
 * the approval queue, the standing grants, the exposure switches — would be
 * wide open. The gateway would be the vulnerability.
 *
 * So this is a separate source kind rather than a flag on the old one. There
 * is no configuration that turns verification off, and `jwt-claim` keeps its
 * original meaning rather than quietly becoming unsafe.
 *
 * Verification is `jose`, not hand-rolled. Algorithm confusion and `alg: none`
 * are the classic ways a bespoke JWT check fails open, and a tool that exists
 * to be the careful layer should not be improvising its own crypto.
 */

/** Only asymmetric signatures, and only two. */
const ALGORITHMS = ["RS256", "ES256"] as const;

export interface TenantClaimResult {
  readonly tenant: string;
  /** For the audit record: who the token says is calling. */
  readonly subject: string | undefined;
}

type KeySource = ReturnType<typeof createRemoteJWKSet> | KeyObject | Uint8Array;

/**
 * Verifies bearer tokens and reads the tenant claim out of them.
 *
 * Built once and reused: `createRemoteJWKSet` caches the key set and handles
 * rotation, so a per-request instance would fetch the JWKS on every call and
 * hand an attacker a trivial amplifier against the authorization server.
 */
export class TenantVerifier {
  private readonly keys: Promise<KeySource>;

  constructor(
    private readonly source: JwtVerifiedSource,
    /**
     * Used to fetch the JWKS. Not optional, and not a plain `fetch`: a URL
     * taken from configuration is still a URL this process will dial, so it
     * goes through the same allowlist, private-address check and DNS pinning
     * as every other outbound request. A `jwks_uri` pointing at a cloud
     * metadata endpoint is refused for the same reason an upstream would be.
     */
    private readonly egress: EgressGuard
  ) {
    this.keys = this.loadKeys();
    // Nothing awaits this at construction; swallow so an unreachable JWKS at
    // boot surfaces on the first call rather than as an unhandled rejection.
    void this.keys.catch(() => undefined);
  }

  private async loadKeys(): Promise<KeySource> {
    if (this.source.public_key) return importSPKI(this.source.public_key, ALGORITHMS[0]);
    return createRemoteJWKSet(new URL(this.source.jwks_uri!), {
      [customFetch]: async (url: string, init) => {
        const response = await this.egress.fetch(url, {
          method: "GET",
          headers: Object.fromEntries(init.headers.entries()),
          ...(init.signal ? { signal: init.signal } : {})
        });
        return new Response(response.body, {
          status: response.status,
          headers: { "content-type": "application/json" }
        });
      }
    });
  }

  /**
   * The tenant this token speaks for, or a `TenantError` naming why not.
   *
   * Every refusal is deliberately the same shape to the caller: a bad
   * signature, an unknown key, the wrong audience and an expired token are all
   * "this token does not establish a tenant", because telling them apart over
   * the wire is a probing oracle. The distinction is kept for the log.
   */
  async verify(token: string): Promise<TenantClaimResult> {
    let payload: JWTPayload;
    try {
      const keys = await this.keys;
      ({ payload } = await jwtVerify(token, keys as Parameters<typeof jwtVerify>[1], {
        issuer: this.source.issuer,
        audience: this.source.audience,
        // Pinned, never read from the token's own header: letting the token
        // choose its algorithm is how `alg: none` and HS256-signed-with-the-
        // public-key attacks get in.
        algorithms: [...ALGORITHMS],
        requiredClaims: ["iss", "aud", "exp"]
      }));
    } catch (err) {
      throw new TenantError(describeFailure(err));
    }

    const raw = payload[this.source.claim];
    if (raw === undefined || raw === null || raw === "") {
      throw new TenantError(
        `the token is valid but carries no ${JSON.stringify(this.source.claim)} claim, ` +
          "so there is no tenant to scope this call to"
      );
    }
    if (typeof raw !== "string" && typeof raw !== "number") {
      throw new TenantError(
        `the ${JSON.stringify(this.source.claim)} claim is a ${typeof raw}; a tenant identifier must be a string`
      );
    }

    return {
      tenant: normalizeTenantKey(String(raw)),
      subject: typeof payload.sub === "string" ? payload.sub : undefined
    };
  }
}

/** Keeps the cause in the log without turning the response into an oracle. */
function describeFailure(err: unknown): string {
  if (err instanceof errors.JWTExpired) return "the token has expired";
  if (err instanceof errors.JWTClaimValidationFailed) {
    return `the token's ${err.claim} claim is not accepted here`;
  }
  if (err instanceof errors.JWSSignatureVerificationFailed) return "the token's signature does not verify";
  if (err instanceof errors.JWKSNoMatchingKey) {
    return "no key in the configured JWKS matches this token";
  }
  if (err instanceof errors.JOSEAlgNotAllowed) {
    return `the token is signed with an algorithm this gateway does not accept (allowed: ${ALGORITHMS.join(", ")})`;
  }
  if (err instanceof errors.JWKSTimeout || (err as Error)?.name === "EgressDenied") {
    return `the key set could not be fetched: ${(err as Error).message}`;
  }
  return `the token could not be verified: ${(err as Error).message}`;
}

/** The bearer token on a request, or undefined. */
export function bearerToken(
  headers: Record<string, string | string[] | undefined>,
  headerName = "authorization"
): string | undefined {
  const wanted = headerName.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== wanted) continue;
    const raw = Array.isArray(value) ? value[0] : value;
    if (!raw) continue;
    const match = /^bearer\s+(.+)$/i.exec(raw.trim());
    return match ? match[1]!.trim() : raw.trim();
  }
  return undefined;
}
