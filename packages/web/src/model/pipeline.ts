/**
 * The enforcement pipeline, in the order it actually runs.
 *
 * This is the one part of the protection view that is written ahead of time
 * rather than derived, because it describes the runtime's code and not the
 * user's configuration. Each step carries the file and lines it corresponds to
 * so it can be checked against the source.
 *
 * KEEP IN SYNC with `packages/runtime/src/enforce.ts`, `request.ts`, and
 * `packages/core/src/egress.ts`. If you change the order enforcement happens
 * in, change it here in the same commit.
 */
export const ENFORCEMENT_PIPELINE = [
  {
    step: 1,
    title: "Tenant resolved once, at startup",
    detail:
      "The tenant value is read from the credential when the server boots, not per call. A required " +
      "tenant that cannot be resolved stops the server from starting at all, rather than failing " +
      "later on a call that looked fine.",
    source: "runtime/src/server.ts:78"
  },
  {
    step: 2,
    title: "Arguments validated against a closed schema",
    detail:
      "The MCP SDK checks arguments against the tool's schema, which declares additionalProperties: " +
      "false. An argument the schema does not name is rejected with an error rather than quietly " +
      "stripped, so an attempt to smuggle a tenant id in is visible instead of silent.",
    source: "runtime/src/server.ts:131-137"
  },
  {
    step: 3,
    title: "Pagination ceiling applied before anything is recorded",
    detail:
      "A missing page-size argument is filled in with the server's ceiling, so no call is unbounded " +
      "and the arguments written to the audit log are the ones that will actually be used.",
    source: "runtime/src/request.ts:164-174"
  },
  {
    step: 4,
    title: "Policy decides, and the decision is pure",
    detail:
      "decide() runs in this order: tenant integrity, then unclassified handling, then the first " +
      "matching rule with its argument bounds checked before its decision is honoured, then the " +
      "posture. It is synchronous and touches no network, so enforcement can never depend on a " +
      "service being reachable.",
    source: "core/src/decide.ts:133"
  },
  {
    step: 5,
    title: "A refusal never reaches the upstream",
    detail:
      "On a deny the call is recorded and returned as an error. The upstream request is not built " +
      "and no credential is read, so a refused call cannot have a side effect.",
    source: "runtime/src/enforce.ts:88-103"
  },
  {
    step: 6,
    title: "Approvals are bound to the exact arguments",
    detail:
      "A grant commits to sha256(tool + canonical arguments), so an approval for one set of " +
      "arguments cannot release another. A standing grant is checked here too, and is bounded by " +
      "its argument constraints, its expiry and its use cap.",
    source: "core/src/approvals.ts:256"
  },
  {
    step: 7,
    title: "Tenant injected last, after the agent's arguments are placed",
    detail:
      "Arguments are written into the request first and the tenant value after, so no argument can " +
      "overwrite it. Path placeholders are percent-encoded, so a value cannot escape its segment.",
    source: "runtime/src/request.ts:63-90"
  },
  {
    step: 8,
    title: "Egress checked, then the resolved addresses pinned",
    detail:
      "Scheme, plaintext HTTP, credentials in the URL, method, IP literals and the host allowlist are " +
      "checked first. Then every DNS answer is validated against private, loopback and link-local " +
      "space and the addresses are pinned for the connection, which closes the rebinding window. " +
      "Redirects are re-validated per hop rather than followed.",
    source: "core/src/egress.ts:84-140"
  },
  {
    step: 9,
    title: "The outcome is recorded either way",
    detail:
      "Completed, denied, held for approval or errored, one hash-chained record is appended with the " +
      "arguments redacted and hashed. An edited, removed or reordered record is detectable.",
    source: "runtime/src/enforce.ts:137-162"
  }
] as const;
