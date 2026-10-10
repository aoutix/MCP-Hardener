import { AsyncLocalStorage } from "node:async_hooks";
import type { EgressGuard } from "@hmcp/core";
import type { Upstream } from "./config.js";

/**
 * Sending the caller's own credential to the upstream.
 *
 * The gateway's position is that it should never hold a customer's secret.
 * The upstream API already authenticates and already scopes data to whoever
 * the token belongs to — that is its job and it has been doing it since
 * before MCP existed — so the gateway's job is the orthogonal one: deciding
 * whether this operation should happen at all, holding it for a human,
 * bounding it, recording it. Passing the credential straight through keeps
 * those two jobs separate, and means a compromise here leaks nothing, because
 * there is nothing stored to leak.
 *
 * The obstacle was that an upstream MCP client is created once, at startup,
 * with its headers baked into `requestInit` for the life of the process. The
 * way out is the SDK's `fetch` option, which is documented as covering every
 * network request the transport makes and does: one client, headers decided
 * at send time.
 *
 * Which leaves the question of how a per-request credential reaches a
 * function called deep inside the transport. `AsyncLocalStorage` carries it,
 * and the store is entered as narrowly as possible — around the upstream call
 * itself, not around the HTTP handler. That is deliberate. A wider scope
 * would put a tenant's credential in context during startup discovery and
 * during `tools/list`, where it has no business being, and would depend on
 * the store surviving the transport's own server-to-client plumbing. Narrow
 * means a leak is structurally impossible rather than merely unlikely.
 */

export interface UpstreamCredential {
  /** The caller's bearer token, exactly as presented. */
  readonly token: string;
  /** For the error message when an upstream rejects it. */
  readonly tenant: string | undefined;
}

/**
 * What the store holds. The distinction that matters is not "credential or
 * not" but "inside a tool call or not": connect, tool discovery and the
 * session DELETE all legitimately have no caller, while a tool call that
 * arrives without one is the case `required` exists to refuse. Collapsing
 * those two into `undefined` made a `required` upstream fail at startup.
 */
interface CallScope {
  readonly credential: UpstreamCredential | undefined;
}

const store = new AsyncLocalStorage<CallScope>();

/**
 * Runs `fn` as a tool call, with this caller's credential (if any) available
 * to upstream requests made inside it.
 *
 * Always enters the store, even with no credential, so that the requests the
 * gateway makes on its own behalf stay distinguishable from a call made
 * without one.
 */
export function withCredential<T>(credential: UpstreamCredential | undefined, fn: () => Promise<T>): Promise<T> {
  return store.run({ credential }, fn);
}

/** The credential for the call in progress, if there is one. */
export function currentCredential(): UpstreamCredential | undefined {
  return store.getStore()?.credential;
}

/** Whether we are inside a tool call at all, credential or not. */
export function inCall(): boolean {
  return store.getStore() !== undefined;
}

export class UpstreamCredentialRejected extends Error {
  constructor(upstream: string) {
    super(
      `upstream "${upstream}" rejected the passed-through credential with 401. If it binds its MCP session ` +
        `to the token that initialized it, a shared connection cannot carry per-caller credentials; set ` +
        `credential_passthrough.session to "per-tenant" for this upstream, or check the token's scopes.`
    );
    this.name = "UpstreamCredentialRejected";
  }
}

/**
 * A `fetch` for the SDK's HTTP client transport that attaches the caller's
 * credential when there is one, and the configured static headers when there
 * is not.
 *
 * The "when there is not" case is the important default. Connect, tool
 * discovery and the session DELETE all run outside any call, so they get the
 * configuration's own headers and never a customer's token.
 */
export function credentialFetch(
  spec: Extract<Upstream, { transport: "http" }>,
  egress: EgressGuard
): (url: string | URL, init?: RequestInit) => Promise<Response> {
  const passthrough = spec.credential_passthrough;

  return async (url, init) => {
    const target = typeof url === "string" ? url : url.toString();

    /*
     * Only two things are ever on an upstream request: the headers this
     * upstream was configured with, and — inside a tool call — the one header
     * carrying the caller's token. The caller's other headers are not
     * filtered out here because they never arrive: nothing copies the inbound
     * request's headers onto the outbound one, so a cookie or an x-api-key
     * the caller sent has no path to a different origin. That is a stronger
     * guarantee than a deny-list, which has to be kept complete to be worth
     * anything, and `passthrough.test.ts` holds it in place.
     */
    const headers = new Headers(init?.headers);

    const credential = currentCredential();
    if (passthrough.enabled && credential) {
      headers.set(passthrough.header, `Bearer ${credential.token}`);
    } else if (passthrough.enabled && passthrough.required && inCall()) {
      // Only inside a call: the gateway's own connect and discovery requests
      // have no caller by definition, and refusing those would mean a
      // `required` upstream could never be reached at all.
      throw new Error(
        `upstream "${spec.name}" requires the caller's credential, and this call arrived without one. ` +
          `Configure this gateway with a tenant source that authenticates the caller.`
      );
    }

    /*
     * Through the guard, not the global fetch.
     *
     * Egress used to run only at connect time, so an upstream allowlisted
     * once was then free to be redirected anywhere for the rest of the
     * process, with none of the timeouts or caps that `policy.yaml` promises.
     * `streamingFetch` applies what can soundly be applied to a transport
     * that holds an event stream open -- the pre-flight, DNS verification,
     * connection pinning, a connect and headers timeout, redirect refusal,
     * and the response cap on everything that is not itself a stream.
     */
    const response = await egress.streamingFetch(target, {
      method: (init?.method ?? "POST").toUpperCase(),
      headers: Object.fromEntries(headers.entries()),
      ...(init?.body !== undefined && init?.body !== null ? { body: init.body } : {}),
      ...(init?.signal ? { signal: init.signal } : {})
    });
    if (response.status === 401 && passthrough.enabled && credential) {
      throw new UpstreamCredentialRejected(spec.name);
    }
    return response;
  };
}
