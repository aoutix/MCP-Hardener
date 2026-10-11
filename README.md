# hardened-mcp

A policy gateway for MCP servers you did not write and do not control.

**`hmcp-gateway`** sits between an agent and its MCP servers. Point the agent at the gateway
instead of the server and three things become true without touching either one:

- **A tool can be switched off.** Per tenant, on a running gateway, enforced before anything else
  is weighed — so a caller holding a valid token still cannot reach it.
- **A write can be held for a human**, bound to its exact arguments. An approval for a 10-unit
  transfer cannot release a 10,000-unit one.
- **A class of call can be pre-approved**, bounded by argument constraints, an expiry and a use
  count, and revocable.

Every decision is recorded in a hash-chained log, whether it was allowed, refused or held.

Connecting an agent to an MCP server is usually a one-liner, and what it gets is usually
unguarded: `delete_*` is as reachable as `get_*`, a tool's description is whatever its author
wrote and is read by the model as instructions, a server can claim its own delete tool is
read-only, and nothing is written down. The aim here is that the blast radius of a tool set is a
property of your configuration rather than of the upstream author's intent, and that every call
can be reconstructed from the log afterwards.

## What it enforces

| | |
| --- | --- |
| **Read-only by default** | Reads pass; anything that mutates is refused unless a named rule permits it. A tool with no effect classification is refused outright, so a newly added upstream tool is not reachable until someone classifies it. |
| **Approvals bound to arguments** | A grant is bound to `sha256(tool + canonical arguments)`, single-use, and TTL'd. An approval for a 10-unit transfer cannot release a 10,000-unit one. Asked through MCP elicitation where the client supports it, and parked for `hmcp approve` where it does not. |
| **Tenant scoping** | The tenant comes from the caller's verified token, never from an argument the model can set, and a mismatch is refused before classification. Approvals, pre-approvals and kill switches are all keyed `(component, tenant)` and filtered in SQL, so one customer's controls cannot reach another's. |
| **Egress limits** | Host allowlist, method allowlist, HTTPS-only, response and request size caps, timeouts. DNS results are checked against private, loopback and link-local space (including `169.254.169.254`) and then pinned for the connection, which closes the rebinding window. Redirects are re-validated per hop rather than followed. |
| **Audit log** | Append-only JSONL, hash-chained, one record per decision whether allowed, refused or held. Arguments are redacted before they reach disk and hashed so the record stays verifiable. `hmcp audit verify` detects an edited, removed or reordered record. |
| **Untrusted upstream text** | A tool's description is written by the server being gated and read by the model as instructions. It is scanned for injected instructions before being advertised, and `on_injection` decides whether the text is replaced, labelled, or the tool withheld entirely. The console shows both what the upstream said and what the model was told. |
| **Dishonest annotations** | An upstream's own hints are trusted only to make a tool *more* restricted, never less, so a server cannot mark its delete tool `readOnlyHint` to slip past a read-only posture. The name is what contradicts a hint, and it is read across snake_case, kebab-case, camelCase and dotted naming — a classifier that only reads one convention is a check that falls open against every server using another. |
| **Names a reviewer can read** | A tool name is the key the kill switch, every approval row and `bindingHash` are stored under, so an upstream advertising two names that render identically would mean switching one off and leaving the other live. A name carrying invisible characters, bidirectional overrides or terminal escapes is withheld, as is a second name a reviewer could not tell from the first. |
| **A tool budget** | A hard stop on how much surface one gateway may expose at all. |

## Install

```bash
npm install
npm run build
npm test
```

Node 22.5 or newer, which is where the built-in `node:sqlite` the approval store uses became
available. There is no native dependency to compile.

## Seeing all of it at once

```bash
npm run demo
```

Registers a gateway over a real upstream MCP server, drives it over stdio until the approval queue
and the audit log have something in them, then starts the console and prints the URL — with the
gateway still running behind it.

The seeding goes through the real gateway rather than writing rows into the store, so every row on
the Approvals page arrived through `decide()`, carries a real argument binding, and has the audit
records to match. The upstream is the gateway tests' own fixture, which deliberately advertises a
tool whose description carries an injection payload and a delete tool claiming to be read-only —
both are what the gateway is for, so the demo shows them rather than a well-behaved stub.

The gateway is left running on purpose. A gateway's tool surface is something a *live* process
publishes, so with nothing running the console would correctly report that it cannot confirm the
tool list, and the kill switch would correctly refuse to write against it.

State goes in `.demo/`, which is disposable and gitignored. `~/.hmcp` is never written to: it holds
a real registry and an audit log of real calls, and seeded fixtures do not belong in that record.

```
--reset           delete .demo/ and build it from scratch
--port <n>        console port (default 7777)
--pending <n>     pending approvals to top the queue up to (default 4)
--no-seed         leave the approval queue and audit log alone
--no-console      set the state up and stop, without serving
```

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
```

## The console

```bash
hmcp-web                     # prints a URL carrying a one-time token
```

Register the gateways you want to review in `~/.hmcp/servers.json`, or add one through the form the
console shows when none is registered:

```json
{
  "version": 1,
  "servers": [
    { "id": "notes", "kind": "gateway", "label": "Notes", "config_path": "./gateway.yaml",
      "added_at": "2026-10-08T00:00:00Z" }
  ]
}
```

Registering reads the config and nothing else — it deliberately does not spawn a gateway's
upstreams, because a page load should not start child processes.

### Where the tool list comes from

A gateway's tools are not on disk. They come from each upstream's own MCP `tools/list` — the same
call, and the same three fields, the agent is given — and only the gateway process has made that
call. So a running gateway publishes what it is serving into the approvals database, and the
console reads that rather than connecting upstreams itself.

The consequence is that the tool list has a provenance, which a file would not: rows were written
by some process at some time, and that process may be gone. The console tracks that and keeps
three states apart that used to look identical — a gateway serving nothing, a gateway that has
never reported, and a gateway whose last report cannot be confirmed as current. The kill switch is
offered only in the first case, because writing an exposure row against a tool name nobody is
serving produces a row that reads as protection and guards nothing.

### Which tenant you are looking at

Approvals, pre-approvals and kill switches are keyed `(component, tenant)`, and a hosted gateway
resolves the tenant per request from the caller's verified token. So the console has to be told
whose rows it is showing, and it refuses rather than guessing: for a `jwt-verified` gateway there
is no single tenant to assume, and assuming the empty one would read an empty queue and write a
switch the gateway never reads. A gateway bound to one tenant through `static`, `env` or
`jwt-claim` is read from the same place the gateway reads it, and the console says that it assumed
rather than being told.

Five views, with a switcher across registered servers:

| | |
| --- | --- |
| **Functions** | Every tool the model can call, which upstream it came from, the description it is given — alongside what the upstream actually said, where the two differ — how its effect was classified, and the verdict `decide()` returns for it right now, attributed to the rule that produced it. A tool that is advertised but can never run is labelled as such. Each one carries an exposure switch, below. |
| **Approvals** | What is waiting for a human, with arguments as recorded. Approving releases those exact arguments and nothing else. |
| **Pre-approvals** | Standing grants, below. |
| **Protection** | What is actually protecting *this* gateway, for the tenant in view: posture, every rule and which tools it claims, tenant scoping, egress limits, the audit chain's state, and the surface the gateway reported with how much of it carries injected text or no classification at all. Derived from the gateway's own config and what it published, rather than written in advance. |
| **Audit log** | Bounded, newest-first, filterable, with the chain's verification state and each record's place in it. |

The console binds to `127.0.0.1` only, authenticates with a token in `~/.hmcp/web-token`, checks
`Host` and `Origin`, and requires a double-submit header on everything that mutates. It never
reads an upstream credential. It never writes a gateway config: policy stays something you edit and
review in git. The one thing it can change about a tool surface is switching a function off, below,
which can only ever narrow it.

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
so a toggle takes effect on the gateway's next call and needs no restart. They are keyed
`(component, tenant)`, because one database serves several gateways and several tenants by
default, and because a kill switch is one customer's to set and theirs to reverse.

This is why the console can own this one control while never writing a gateway config. Granting a
permission policy does not already grant remains an edit to the policy, reviewed in git.

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
    reason: this deployment never deletes records

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
| HMCP004 | high | a credential in a description, an example, or a base URL |
| HMCP005 | high | prompt injection — instruction overrides, injected roles, secrecy, exfiltration, urgency, invisible characters |
| HMCP006 | medium | a schema loose enough to forward whatever the model invents |
| HMCP007 | high | an upstream the policy does not permit, plaintext HTTP, or a private address |
| HMCP008 | medium | an exposed operation declares no authentication |
| HMCP009 | medium | over budget, or two tools a model cannot tell apart |
| HMCP010 | high | auditing disabled, the chain off, or approvals that can never be given |

Run them over a gateway's upstreams with `hmcp-gateway scan`. `--sarif` feeds code scanning, and a
high-severity finding exits non-zero.

HMCP005 is the one that earns its place here: it reads the descriptions a third-party server
advertises, which the model is given as instructions. That is a threat you have whether or not you
use this.

## Layout

```
packages/
  core/            policy schema, the decision engine, the enforcement pipeline, approvals,
                   standing grants, the tool inventory, audit, redaction, egress
  scanner/         the ten rules, with SARIF and markdown reporters
  gateway/         hmcp-gateway: agent ↔ upstream MCP proxy
  cli/             hmcp: approvals, audit, policy
  web/             hmcp-web: the review console (src/ is the backend, ui/ the React app)
examples/
  gateway/         a gateway config and policy
```

Everything security-relevant lives in `core`, so the gateway enforcing a call and the console
describing it cannot drift apart.
`decide()` is pure and synchronous on purpose: if enforcement ever needed to reach the network to
make a decision, that would be a hole rather than a feature.

## Testing

```bash
npm test
```

403 tests. The ones worth knowing about:

- **Decision tables** over every effect × rule × posture × tenant combination, including the
  default-deny path for an unclassified tool.
- **Approval binding** — an approval for `{amount: 10}` does not release `{amount: 49000}`, a
  spent grant does not release a second call, and an expired one does not release anything.
- **SSRF** — the guard refuses `127.0.0.1`, `169.254.169.254`, IPv4-mapped and NAT64 forms of a
  private address, a hostname that resolves into private space, plaintext HTTP, credentials in a
  URL, an oversized response, and a redirect to an off-allowlist host.
- **Audit tamper-evidence** — verification passes on a clean log and fails on an edited, removed,
  reordered or forged record.
- **The gateway against a real upstream MCP server** that advertises a dishonest `readOnlyHint`
  and an injected description, over both stdio and Streamable HTTP, with the tenant taken from a
  signature-verified token and the caller's credential passed through.
- **All ten scanner rules**, each individually and together on a target built to trip every one.
- **Standing grants** — matching, expiry, use caps, revocation, that concurrent calls cannot
  exceed a cap, that a grant whose bounds reject the arguments falls through to a human rather
  than denying, and that an over-broad grant still cannot release a call policy denied.
- **The bounded audit query** — that a malformed line is skipped and counted rather than thrown
  on (directly contrasted with `readAuditLog`, which throws), that paging covers every record
  exactly once, that a record spanning a read boundary survives, and that a page costs far less
  than the size of the log.
- **Which tenant the console speaks for** — that a gateway resolving its tenant per request is
  refused rather than guessed at, both for reading a queue and for writing a kill switch; that a
  named tenant's switch is written into that tenant and nowhere else; that one tenant's switch is
  invisible to another; that a tenant which could be spelled two ways is refused; and that a
  gateway with no tenant configured refuses a request naming one.
- **The published tool surface** — that publishing replaces the previous set rather than merging
  into it, so a tool an upstream stopped offering disappears; that one component's surface cannot
  reach another's; that the writing process is recorded, so two gateways sharing a component
  cannot be blended into a surface neither serves; and that the kill switch refuses a surface no
  live process confirms.
- **Schema migration** — that a database written before versioning existed upgrades without
  losing rows, that one stamped before `tool_inventory` existed gains it, and that nothing is
  backfilled, because "unknown" is the only honest answer for a gateway that has not run.
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
  limits — not in front of them. Note what that ordering buys: a tool's description never reaches
  a decision. `decide()` and `classify()` read the name, the effect, the arguments and the
  upstream's annotations, and nothing reads the description, so injected text cannot change a
  verdict however novel its phrasing. It is advertised to the model, scanned, and displayed —
  that is all.
- `strip` replaces a description wholesale, so a false positive costs the model the information it
  needs and it will misuse the tool rather than fail. That is a lossy default rather than an
  unsafe one — nothing in `decide()` reads a description — and it is narrowable: `on_injection` can
  be set per upstream, and `injection_overrides` per tool for a reviewed false positive. The
  weakest of the three still prefixes a warning, so an override can restore a description but
  never hide that it tripped a pattern, and the audit record says when an override produced the
  action.
- A refusal tells the agent only that a tool was switched off, not who switched it off or the
  reason they typed. Those stay in the audit log and the console. The agent is the operator's own,
  and the upstream never sees either string, but a reason can carry the circumstances of an
  incident and a model influenced by injected text elsewhere could carry it out through a tool
  that is still allowed.
- Untrusted text is escaped where it is printed, not where it is stored. JSON escapes control
  characters on the way into the audit log, so the file is safe to `cat`; it is parsing a record
  back and printing it that would otherwise let an upstream rewrite a terminal, so every line the
  CLI emits passes through one escaper.
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
