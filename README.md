# hardened-mcp

Two tools that share one policy engine and one audit log:

- **`hmcp-gen`** turns an OpenAPI or Swagger spec into a hardened MCP server — read-only by
  default, writes behind approvals, tenant scoping enforced server-side, a curated tool set
  rather than one tool per operation, and a scan of its own output that fails the build.
- **`hmcp-gateway`** sits between an agent and MCP servers you did not generate and may not
  control, applying the same read-only defaults, write approvals and egress limits.

Wrapping a REST API as an MCP server is usually a one-liner, and what it produces is usually
unsafe: every operation becomes a tool, `DELETE` is as reachable as `GET`, tenant identifiers sit
in the agent-facing schema where a model can change them, descriptions carry whatever the spec
author wrote, and nothing is recorded. The aim here is that the blast radius of a tool set is a
property of its configuration rather than of the spec author's intent, and that every call can be
reconstructed from the log afterwards.

## What it enforces

| | |
| --- | --- |
| **Read-only by default** | Reads pass; anything that mutates is refused unless a named rule permits it. A tool with no effect classification is refused outright, so a newly added upstream tool is not reachable until someone classifies it. |
| **Approvals bound to arguments** | A grant is bound to `sha256(tool + canonical arguments)`, single-use, and TTL'd. An approval for a 10-unit transfer cannot release a 10,000-unit one. Asked through MCP elicitation where the client supports it, and parked for `hmcp approve` where it does not. |
| **Tenant scoping that is structural** | Tenant parameters are removed from the agent-facing schema and injected from the credential at call time. The model has no argument in which to name another tenant, and a mismatch is refused before classification. |
| **Egress limits** | Host allowlist, method allowlist, HTTPS-only, response and request size caps, timeouts. DNS results are checked against private, loopback and link-local space (including `169.254.169.254`) and then pinned for the connection, which closes the rebinding window. Redirects are re-validated per hop rather than followed. |
| **Audit log** | Append-only JSONL, hash-chained, one record per decision whether allowed, refused or held. Arguments are redacted before they reach disk and hashed so the record stays verifiable. `hmcp audit verify` detects an edited, removed or reordered record. |
| **Curated tools** | `plan` writes a manifest a human edits; only what they enable becomes a tool. Writes are off by default and a tool budget is a hard stop. |
| **A scan of its own output** | Ten rules over the generated surface, including prompt injection in spec-derived text and secrets that leaked out of a spec. SARIF and markdown; a high-severity finding fails the build. |

## Install

```bash
npm install
npm run build
npm test
```

Node 22.5 or newer, which is where the built-in `node:sqlite` the approval store uses became
available. There is no native dependency to compile.

## Generating a server

```bash
# 1. Inspect the spec. Nothing is generated yet.
node packages/generator/dist/cli.js plan examples/petstore/openapi.yaml \
  -p examples/petstore/policy.yaml -o tools.manifest.yaml
```

```
Petstore 1.2.0 (openapi-3)
  8 operations in the spec
  8 candidate tools: 3 read, 3 write, 2 destructive
  3 enabled, 5 left off

  1 operation(s) need a human decision:
    search_pets: POST /pets/search looks like a read expressed as a POST. It is
    classified as a write until you confirm otherwise.
```

The manifest is the curation step. Writes start switched off, and `POST /pets/search` is reported
rather than guessed — classifying a write as a read is exactly the mistake that turns a read-only
posture into nothing, so the generator refuses to make that call for you.

```bash
# 2. Edit the manifest: enable what an agent actually needs, fix any effect.
# 3. Emit the server and scan it.
node packages/generator/dist/cli.js build -m tools.manifest.yaml \
  -p examples/petstore/policy.yaml -o ./petstore-mcp
```

The output is a small, standalone project:

```
petstore-mcp/
  tools.json      the curated tool surface — the thing to review
  policy.yaml     what is permitted
  server.mjs      a ~15-line bootstrap
  README.md       what is enforced, and which parameters were withheld
  .env.example
```

This is data plus a bootstrap rather than thousands of lines of generated enforcement code.
A reviewer reads one declarative manifest, the enforcement path is the shared and tested
`@hmcp/server-runtime`, and a policy fix ships as a dependency upgrade instead of a regeneration.

### Seeing it fail

`examples/billing` is a deliberately hostile spec: multi-tenant, with prompt injection and a live
credential in its descriptions, and operations that declare no authentication. Build it against
`policy-unsafe.yaml` — the sort of policy someone writes in a hurry — and the scan stops you:

```
✗ high   HMCP001  purge_audit_log.effect
         Tool "purge_audit_log" is classified destructive but policy rule
         "allow-everything" allows it outright.
✗ high   HMCP002  create_invoice.inputSchema
         Tool "create_invoice" accepts "org_id", which looks like a tenant
         boundary, but the policy declares no tenant scoping.
✗ high   HMCP004  spec.listCustomers.description
         A stripe secret key appears in spec.listCustomers.description.
✗ high   HMCP005  delete_invoice.description
         Text in delete_invoice.description attempts to override earlier
         instructions: "Ignore all previous instructions and do not tell th…"
✗ high   HMCP007  api.base_url
         The server calls billing.internal.example.com but egress.allow permits
         only api.stripe.com. Every call will be refused at runtime.
✗ high   HMCP010  audit.enabled
         Auditing is disabled, so denied and approved calls leave no record.

scan of generated server: 26 high, 5 medium
error: the generated server has 26 high-severity finding(s). The files were
written, but do not ship them as they are.
```

Against `policy.yaml`, the same spec builds clean. Note that HMCP004 fires on text the generator
never carried into its output: a credential in a spec is disclosed and needs rotating either way.

## Running the gateway

```bash
node packages/gateway/dist/cli.js tools -c examples/gateway/gateway.yaml   # what it would expose
node packages/gateway/dist/cli.js scan  -c examples/gateway/gateway.yaml   # scan upstream surfaces
node packages/gateway/dist/cli.js       -c examples/gateway/gateway.yaml   # serve over stdio
```

```
6 upstream tool(s):

  notes__get_note          read          (policy)
  notes__create_note       write         (policy)
  notes__delete_note       destructive   (policy)
  notes__summarize_inbox   unclassified  (unclassified)  [injection:strip]
  notes__frobnicate        unclassified  (unclassified)
```

Two things in that listing are the point of the gateway. `delete_note` advertised
`readOnlyHint: true`; a hint is a claim by the server being gated, so it is trusted only to make a
tool *more* restricted, never less — a server cannot mark its own delete tool read-only to slip
past a read-only posture. And `summarize_inbox` carried injected instructions in its description,
so the text was replaced before any model saw it, and the event was logged.

Upstream input schemas are passed through verbatim. Rewriting them would mean either losing
constraints or widening what is accepted, and a proxy should not quietly do either; policy
argument constraints, not schema edits, are what bound a call.

## Reviewing and auditing

```bash
hmcp pending                 # calls waiting for a human, with arguments redacted
hmcp approve apr_a1b2c3d4    # bound to those exact arguments, single-use
hmcp deny apr_a1b2c3d4
hmcp audit tail --denied     # what was refused, and by which rule
hmcp audit verify            # hash chain: edited, removed or reordered records
hmcp policy policy.yaml      # effective settings, defaults included
hmcp scan -t tools.json -p policy.yaml
```

## The console

```bash
hmcp-web                     # prints a URL carrying a one-time token
```

Register the servers you want to review in `~/.hmcp/servers.json` — a generated server is the
directory holding `tools.json` and `policy.yaml`; a gateway is its config:

```json
{
  "version": 1,
  "servers": [
    { "id": "billing", "kind": "generated", "label": "Billing", "dir": "./billing-mcp",
      "added_at": "2026-10-08T00:00:00Z" },
    { "id": "notes", "kind": "gateway", "label": "Notes", "config_path": "./gateway.yaml",
      "added_at": "2026-10-08T00:00:00Z" }
  ]
}
```

Five views, with a switcher across registered servers:

| | |
| --- | --- |
| **Functions** | Every tool the model can call, with the description it is given, each argument and where it lands upstream, and the verdict `decide()` returns for it right now — attributed to the rule that produced it. A tool that is advertised but can never run is labelled as such. Each one carries an exposure switch, below. |
| **Approvals** | What is waiting for a human, with arguments as recorded. Approving releases those exact arguments and nothing else. |
| **Pre-approvals** | Standing grants, below. |
| **Protection** | What is actually protecting *this* server: posture, every rule and which tools it claims, tenant injection, egress limits, credential handling, the audit chain's state, which operations were never exposed, every withheld parameter with its reason, and the tools the generator asked a human to confirm. Derived from the server's own files rather than written in advance. |
| **Audit log** | Bounded, newest-first, filterable, with the chain's verification state and each record's place in it. |

The console binds to `127.0.0.1` only, authenticates with a token in `~/.hmcp/web-token`, checks
`Host` and `Origin`, and requires a double-submit header on everything that mutates. It never
reads an upstream credential — it reports the variable's *name* and whether it is set. It never
writes `tools.json` or `policy.yaml`: policy stays something you edit and review in git. The one
thing it can change about a tool surface is switching a function off, below, which can only ever
narrow it.

Anyone who can reach the port and read `~/.hmcp` can approve a destructive call, so there is
deliberately no option to bind it anywhere else.

### Switching a function off

The exposure switch on the Functions page takes one tool off the model's menu, on a server that
is already running. It is the only thing in the console that changes what a server exposes, and
like a standing grant it is deliberately weaker than editing the policy — in the other direction:

- **off** means off. The tool is withdrawn from `tools/list`, and `decide()` refuses it under
  `exposure.disabled` before tenant integrity, classification or any rule is weighed, so nothing
  reaches the upstream even from a client holding a stale tool list.
- **on** does not mean allowed. Switching a tool back on *deletes* the override and nothing more:
  the tool returns to whatever `policy.yaml` already said, which may still be deny or approve. The
  only state ever stored is "off, for this one tool", so there is no value anywhere in this
  database that can release a call `decide()` refuses.
- A tool policy refuses already has no switch to throw, and the console says so rather than
  offering a control that cannot change the outcome.
- Both directions are written to the audit log, as `exposure.disable` and `exposure.enable`.
- Switching a *write* or *destructive* tool back on asks once first, with a "don't show this
  again" for the reviewer who does not need telling twice. Switching anything off is never
  confirmed: it only ever narrows what the model can reach.

Overrides live in the approvals database, which the console and a running server already share,
so a toggle takes effect within a couple of seconds and needs no restart. They are keyed by the
server's audit `component`, because one database serves several servers by default. A gateway has
no switch: its surface belongs to its upstreams and is discovered at connect time.

This is why the console can own this one control while still never writing `tools.json` or
`policy.yaml`. Granting a permission policy does not already grant remains an edit to
`policy.yaml`, reviewed in git.

### Pre-approving a class of request

A standing grant says "stop asking me about this particular kind of call". It is deliberately the
weakest form of a permission change:

- it matches a glob over the tool name, using the same vocabulary as `rules[].match`;
- its argument bounds are the same `ArgConstraint` vocabulary a policy rule uses, checked by the
  same function, so `amount: { max: 500 }` means exactly what it means in a policy;
- it always expires, and never more than 30 days out;
- it can cap how many calls it releases;
- it is revocable, and creation, every use and revocation are all written to the audit log;
- a glob that matches a family of tools must also set a use cap or argument bounds — an unbounded
  wildcard grant is refused, because that is a policy edit and belongs in `policy.yaml`.

It **cannot widen what policy permits.** A grant is only consulted for a call that policy already
routed to a human, so it can spare you a question but never answer one you were never asked: an
over-broad grant still cannot release a call that `decide()` denied. A grant whose bounds reject
the arguments is simply not a match, so the call goes to a human as it would have anyway — a
narrow pre-approval can never *block* something you would have waved through.

The settings page previews a draft against the tools that exist right now, before anything is
saved, so the blast radius is visible at the point of decision.

## Policy

One file governs both halves.

```yaml
version: 1

defaults:
  mode: read-only          # read-only | approve-writes | locked
  on_unclassified: deny    # a tool with no effect is not reachable

rules:                     # first match wins; the id is recorded in the audit log
  - id: allow-reads
    match: "{get,list}_*"
    effect: read
    decision: allow

  - id: create-invoice
    match: create_invoice
    effect: write
    decision: approve
    args:                  # checked before the decision is honored
      amount: { min: 1, max: 50000 }
      currency: { enum: [usd] }

  - id: no-deletes
    match: "{delete,purge}_*"
    decision: deny
    reason: this deployment never deletes billing records

tenant:
  field: org_id
  aliases: [organization_id]
  source: { kind: env, name: BILLING_ORG_ID }   # or header | jwt-claim | static
  inject: [path, query, body]
  on_mismatch: deny

egress:
  allow: ["api.example.com"]       # exact, "*.example.com", or either with :port
  methods: [GET, POST]
  max_body_bytes: 1048576
  max_redirects: 0
  block_private_ips: true

approvals:
  mode: both               # elicit | cli | both | deny
  ttl_seconds: 300
  single_use: true

audit:
  path: ~/.hmcp/audit.jsonl
  hash_chain: true
  redact: [memo]

tool_budget: 20
```

An argument bound is checked *before* a rule's decision is honored, so a rule that approves
transfers under 50,000 denies one over it rather than sending it to a human who might wave it
through. An unparseable pattern in a policy is a closed door, not an open one.

## Scanner rules

| id | severity | what it catches |
| --- | --- | --- |
| HMCP001 | high | a write or destructive tool reachable with `decision: allow` |
| HMCP002 | high | a tenant boundary left agent-settable, or a multi-tenant surface with no tenant policy |
| HMCP003 | medium | a collection read with no pagination ceiling |
| HMCP004 | high | a credential in a description, example, base URL, or the source spec |
| HMCP005 | high | prompt injection — instruction overrides, injected roles, secrecy, exfiltration, urgency, invisible characters |
| HMCP006 | medium | a schema loose enough to forward whatever the model invents |
| HMCP007 | high | an upstream the policy does not permit, plaintext HTTP, or a private address |
| HMCP008 | medium | the spec or an exposed operation declares no authentication |
| HMCP009 | medium | over budget, or two tools a model cannot tell apart |
| HMCP010 | high | auditing disabled, the chain off, or approvals that can never be given |

`--baseline` accepts known findings; `--sarif` feeds code scanning. A high-severity finding exits
non-zero.

## Layout

```
packages/
  core/            policy schema, the decision engine, approvals, standing grants, audit, redaction, egress
  runtime/         @hmcp/server-runtime: the enforcement pipeline and MCP server for generated projects
  scanner/         the ten rules, with SARIF and markdown reporters
  generator/       hmcp-gen: spec → curated manifest → hardened server
  gateway/         hmcp-gateway: agent ↔ upstream MCP proxy
  cli/             hmcp: approvals, audit, scan, policy
  web/             hmcp-web: the review console (src/ is the backend, ui/ the React app)
examples/
  petstore/        a clean spec that builds clean
  billing/         a hostile spec, with an unsafe and a hardened policy
  gateway/         a gateway config and policy
```

Everything security-relevant lives in `core`, so the generator and the gateway cannot drift apart.
`decide()` is pure and synchronous on purpose: if enforcement ever needed to reach the network to
make a decision, that would be a hole rather than a feature.

## Testing

```bash
npm test
```

363 tests. The ones worth knowing about:

- **Decision tables** over every effect × rule × posture × tenant combination, including the
  default-deny path for an unclassified tool.
- **Approval binding** — an approval for `{amount: 10}` does not release `{amount: 49000}`, a
  spent grant does not release a second call, and an expired one does not release anything.
- **SSRF** — the guard refuses `127.0.0.1`, `169.254.169.254`, IPv4-mapped and NAT64 forms of a
  private address, a hostname that resolves into private space, plaintext HTTP, credentials in a
  URL, an oversized response, and a redirect to an off-allowlist host.
- **Audit tamper-evidence** — verification passes on a clean log and fails on an edited, removed,
  reordered or forged record.
- **End-to-end**, with a real MCP client driving a generated server against a stand-in API: a read
  is scoped to the credential's tenant, every spelling of a cross-tenant attempt is refused, a
  path parameter cannot escape its segment, a write is held and then released by an out-of-band
  approval, and the credential never appears in the log.
- **The gateway against a real upstream MCP server** that advertises a dishonest `readOnlyHint`
  and an injected description.
- **All ten scanner rules**, each individually and together on a target built to trip every one.
- **Standing grants** — matching, expiry, use caps, revocation, that concurrent calls cannot
  exceed a cap, that a grant whose bounds reject the arguments falls through to a human rather
  than denying, and that an over-broad grant still cannot release a call policy denied.
- **The bounded audit query** — that a malformed line is skipped and counted rather than thrown
  on (directly contrasted with `readAuditLog`, which throws), that paging covers every record
  exactly once, that a record spanning a read boundary survives, and that a page costs far less
  than the size of the log.
- **`tools.json` backward compatibility** — a file generated before the console's fields existed
  still parses, and the schema is still closed to unknown keys.
- **The exposure switch** — that a switched-off tool is refused before tenant integrity and
  before any rule, that the refusal names the switch and never reaches the upstream, that the
  tool leaves the advertised list in a server already running and comes back when switched on,
  that switching one on hands it back to policy *and no further* (a tool policy denies stays
  denied), that both directions are audited and a change that did not happen is not, and that
  overrides are scoped per server so a shared database cannot switch off the wrong tool.
- **The console's API** — that a request with no session, a foreign `Origin`, an unexpected
  `Host`, or no CSRF header is refused; that a path cannot escape the UI root; that creating a
  pre-approval writes an audit record and leaves the chain verifiable; that a grant which cannot
  be audited is withdrawn rather than left usable; and a sweep asserting no response body
  contains an upstream credential.

## Limits worth knowing

- The audit log's hash chain makes tampering *evident*, not impossible. Anyone who can write the
  file can rewrite the chain from a chosen point; detecting that needs the verified head stored
  somewhere else. Appends are guarded by a lock file, so one log can be shared by several
  processes on one machine, but not over a network filesystem.
- `tenant.source: jwt-claim` reads the claim without verifying the token's signature. The token is
  our own credential rather than attacker-supplied input, so there is nothing to forge; it exists
  to avoid duplicating the tenant id in a second environment variable.
- Prompt-injection detection is pattern-based. It catches the known shapes and will miss novel
  phrasings, so it belongs behind the structural controls — read-only defaults, approvals, egress
  limits — not in front of them.
- A stdio upstream is a child process. The gateway controls its environment and arguments, but
  once running it is a local process and the egress allowlist does not apply to it; only HTTP
  upstreams pass through the guard.
- Effect inference for an upstream MCP tool falls back to name shape, which is a heuristic. That
  is why anything unmatched stays unclassified and therefore refused, rather than being guessed
  into the read bucket.
- A standing grant trades the exact-argument binding for not asking twice. Everything else about
  it is bounded, but that trade is real: within its pattern, its argument bounds, its expiry and
  its use cap, calls run without a human seeing them. The narrower the grant, the less this
  matters.
- A tool switched off in the console is withdrawn from `tools/list`, and the MCP SDK rejects a
  call to a tool it is not advertising as an unknown tool name — before our pipeline runs, so
  that one attempt is not itself written to the audit log. The switch being thrown is recorded,
  and a call made in the window before the server next syncs is refused and recorded in full; it
  is only a stale client calling an already-hidden tool that leaves no record of the attempt.
- The console resolves a tenant from its *own* environment, so "this server would refuse to
  start" means in the console's process, which may not be the server's. It is reported as such
  rather than presented as the server's state.
- The combined audit view attributes records by `component`, because a record does not carry a
  registry id and several servers may share one log. Where a shared log makes attribution
  ambiguous the console says so rather than guessing.
