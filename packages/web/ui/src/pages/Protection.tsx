import { useState } from "react";
import { api, type ServerProtection } from "../api";
import {
  Banner,
  EffectBadge,
  Empty,
  Field,
  Mono,
  Panel,
  ReachBadge,
  Tag,
  VerdictBadge,
  bytes,
  relativeTime,
  useResource
} from "../components";

/**
 * Part 4: how this gateway is being protected.
 *
 * Every number, host and verdict on this page is read from this gateway's own
 * configuration and the surface it published, or computed by the same functions
 * the gateway uses to decide a call. The only prose written ahead of time is
 * the pipeline description, which describes the gateway's code rather than the
 * user's configuration, and each of its steps cites the file it corresponds to.
 */
export function Protection({ serverId, tenant }: { serverId: string; tenant: string | null }) {
  const { data, error, loading } = useResource(() => api.protection(serverId, tenant), [serverId, tenant]);

  if (error) return <Banner tone="bad">{error}</Banner>;
  if (loading && !data) return <Empty>Reading this server's configuration…</Empty>;
  if (!data) return <Empty>Nothing to show.</Empty>;

  return (
    <div className="space-y-4">
      <TenantScope p={data} />
      <Headline p={data} />
      <Pipeline p={data} />
      <Posture p={data} />
      <Surface p={data} />
      <Rules p={data} />
      {data.tenant && <Tenant p={data} />}
      <Egress p={data} />
      <Approvals p={data} />
      <Audit p={data} />
    </div>
  );
}

/*
 * Which tenant the whole page is about.
 *
 * Approvals, grants, the exposure switch and reach are all keyed by tenant, so
 * without this the page presents one tenant's answers as the gateway's. Shown
 * only where the gateway has tenants at all.
 */
function TenantScope({ p }: { p: ServerProtection }) {
  if (!p.tenant) return null;
  return (
    <Banner tone="info">
      Every figure below is for tenant <Mono>{p.tenant_scope === "" ? "(none)" : p.tenant_scope}</Mono>
      {p.explicitTenant
        ? "."
        : `, which this console read from ${p.tenant.sourceProse} rather than being told.`}{" "}
      Approvals, pre-approvals, switches and reach are all per tenant.
    </Banner>
  );
}

function Headline({ p }: { p: ServerProtection }) {
  return (
    <div className="space-y-2">
      {/*
       * Three states, not two. "Nothing published" used to render as a clean
       * bill of health, because an empty finding list and a clean scan were the
       * same value -- so the page said nothing was wrong about a surface it had
       * never seen. Saying "unknown" is the only honest version of that.
       */}
      {p.surface.neverPublished ? (
        <Banner tone="warn">
          This gateway has never reported what it serves, so nothing below describes its tools. Start it once and it
          will publish the surface its upstreams advertise.
        </Banner>
      ) : p.surface.stale ? (
        <Banner tone="warn">
          No running gateway is announcing itself, so this is the last surface one published
          {p.surface.publishedAt ? <> — {relativeTime(p.surface.publishedAt)}</> : null}. It may no longer be what
          the upstreams offer.
        </Banner>
      ) : p.surface.injectionCount > 0 ? (
        <Banner tone="bad">
          {p.surface.injectionCount} of {p.surface.toolCount} tools advertise text carrying injected instructions.
          {p.surface.hiddenCount > 0 && ` ${p.surface.hiddenCount} withheld from the model entirely.`} Upstream tool
          text is not trustworthy on this gateway.
        </Banner>
      ) : p.surface.unclassifiedCount > 0 ? (
        <Banner tone="warn">
          {p.surface.unclassifiedCount} tool(s) could not be classified, so they are refused. Name them in a policy
          rule to make them reachable.
        </Banner>
      ) : (
        <Banner tone="ok">
          {p.surface.toolCount} tool(s) reported, all classified, none advertising injected instructions.
        </Banner>
      )}
      {p.tenant?.error && (
        <Banner tone="warn">
          {p.tenant.error} (The console resolves the tenant from its own environment, which may differ from the
          gateway's.)
        </Banner>
      )}
      {!p.audit.enabled && (
        <Banner tone="bad">
          Auditing is disabled, so approved and refused calls leave no record on this server.
        </Banner>
      )}
      {p.audit.enabled && !p.audit.verify.written && (
        <Banner tone="warn">
          Nothing has been written to the audit log yet. That is expected if this gateway has not run.
        </Banner>
      )}
      {p.audit.enabled && p.audit.verify.written && !p.audit.verify.ok && (
        <Banner tone="bad">
          The audit chain does not verify: {p.audit.verify.problemCount} problem(s) across{" "}
          {p.audit.verify.count} record(s). A record may have been edited, removed or reordered.
        </Banner>
      )}
    </div>
  );
}

function Pipeline({ p }: { p: ServerProtection }) {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <Panel
      title="What happens to a tool call, in order"
      subtitle="This describes the enforcement path every upstream call takes. Each step cites its source."
    >
      <ol className="space-y-1.5">
        {p.pipeline.map((step) => (
          <li key={step.step} className="rounded-md border border-edge">
            <button
              onClick={() => setOpen(open === step.step ? null : step.step)}
              className="flex w-full items-center gap-3 px-3 py-2 text-left"
            >
              <span className="mono flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-edge text-xs">
                {step.step}
              </span>
              <span className="text-sm font-medium">{step.title}</span>
              <span className="ml-auto text-xs text-ink-soft">{open === step.step ? "−" : "+"}</span>
            </button>
            {open === step.step && (
              <div className="border-t border-edge px-3 py-2">
                <p className="text-sm text-ink-soft">{step.detail}</p>
                <p className="mt-1 text-xs">
                  <Mono>{step.source}</Mono>
                </p>
              </div>
            )}
          </li>
        ))}
      </ol>
    </Panel>
  );
}

function Posture({ p }: { p: ServerProtection }) {
  return (
    <Panel title="Posture">
      <dl className="grid gap-3 sm:grid-cols-3">
        <Field label="Mode (when no rule matches)">
          <Mono>{p.posture}</Mono>
        </Field>
        {/* The two disagree whenever a rule widens or narrows the fallback,
            which is most of the time — so they are shown side by side rather
            than leaving the declared value to stand for both. */}
        <Field label="What that leaves reachable">
          <ReachBadge reach={p.reach} />
        </Field>
        <Field label="A tool with no effect classification">
          {p.onUnclassified === "deny" ? "is refused outright" : "is held for approval"}
        </Field>
        <Field label="Tool budget">
          {p.toolBudget.enabled} of {p.toolBudget.budget} used{" "}
          {p.toolBudget.ok ? "" : <Tag>over budget</Tag>}
        </Field>
      </dl>
    </Panel>
  );
}

function Rules({ p }: { p: ServerProtection }) {
  return (
    <Panel
      title={`${p.rules.length} policy rule(s)`}
      subtitle="First match wins, and the id of the rule that decided a call is written to the audit log."
    >
      {p.rules.length === 0 ? (
        <Empty>No rules. Every call is decided by the posture alone.</Empty>
      ) : (
        <ol className="space-y-2">
          {p.rules.map((rule) => (
            <li key={rule.id} className="rounded-md border border-edge bg-surface p-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <Mono>{rule.id}</Mono>
                <span className="mono text-xs text-ink-soft">{rule.match}</span>
                <VerdictBadge kind={rule.decision} />
                {rule.effect && <EffectBadge effect={rule.effect} />}
                {rule.shadowedBy && (
                  <Tag title={`Rule "${rule.shadowedBy}" matches every tool this rule matches, and comes first.`}>
                    never fires — shadowed by {rule.shadowedBy}
                  </Tag>
                )}
              </div>
              {rule.reason && <p className="mt-1 text-sm text-ink-soft">{rule.reason}</p>}
              <div className="mt-1.5 flex flex-wrap items-baseline gap-1.5 text-xs">
                <span className="text-ink-soft">
                  {rule.matchedTools.length === 0 ? "matches no tool on this server" : "matches"}
                </span>
                {rule.matchedTools.map((t) => (
                  <Mono key={t}>{t}</Mono>
                ))}
              </div>
              {rule.argConstraints.length > 0 && (
                <p className="mt-1 text-xs text-ink-soft">
                  Argument bounds on {rule.argConstraints.join(", ")}, checked before this rule's decision is
                  honoured.
                </p>
              )}
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}

function Tenant({ p }: { p: ServerProtection }) {
  const t = p.tenant!;
  return (
    <Panel title="Tenant scoping" subtitle="Structural rather than advisory: the field is absent from every tool schema.">
      <dl className="grid gap-3 sm:grid-cols-2">
        <Field label="Field">
          <Mono>{t.field}</Mono>
          {t.aliases.length > 0 && <span className="ml-1 text-xs text-ink-soft">aliases: {t.aliases.join(", ")}</span>}
        </Field>
        <Field label="Resolved from">{t.sourceProse}</Field>
        <Field label="Injected into">
          {t.inject.map((i) => (
            <Mono key={i}>{i}</Mono>
          ))}
        </Field>
        <Field label="On a mismatch">
          {t.onMismatch === "deny" ? "the call is refused before classification" : "the value is overridden"}
        </Field>
      </dl>
      <p className="mt-3 text-sm text-ink-soft">
        Because <Mono>{t.field}</Mono> is not in any tool's schema, the model has no argument in which to
        name another tenant. The value is injected after the model's arguments are placed, so an argument
        cannot overwrite it.
      </p>
    </Panel>
  );
}

function Surface({ p }: { p: ServerProtection }) {
  const s = p.surface;
  return (
    <Panel
      title="The surface this gateway reported"
      subtitle="Taken from each upstream's own tools/list — the same call, and the same fields, the agent is given."
    >
      {s.neverPublished ? (
        <Empty>
          Nothing published yet. The console does not connect a gateway's upstreams itself, so this fills in once the
          gateway has run.
        </Empty>
      ) : (
        <>
          <dl className="grid gap-3 sm:grid-cols-3">
            <Field label="Tools reported">{s.toolCount}</Field>
            <Field label="Withheld by policy">
              {s.hiddenCount === 0 ? "none" : `${s.hiddenCount} — injected text, on_injection: deny`}
            </Field>
            <Field label="Unclassified">
              {s.unclassifiedCount === 0 ? "none" : `${s.unclassifiedCount}, refused`}
            </Field>
            <Field label="Advertising injected text">{s.injectionCount === 0 ? "none" : s.injectionCount}</Field>
            <Field label="Reported">{s.publishedAt ? relativeTime(s.publishedAt) : "—"}</Field>
            <Field label="Confirmed current">
              {s.live ? (
                "yes — a gateway is announcing itself"
              ) : (
                <span className="text-write">no — nothing is announcing itself</span>
              )}
            </Field>
          </dl>
          <p className="mt-3 text-xs text-ink-soft">
            {/* The distinction the whole panel exists to carry. */}
            Only a surface a live gateway confirms can be switched here: writing a kill switch against a tool name
            that is no longer served produces a row that reads as protection and guards nothing.
          </p>
        </>
      )}
    </Panel>
  );
}

function Egress({ p }: { p: ServerProtection }) {
  const e = p.egress;
  return (
    <Panel title="Egress limits">
      <dl className="grid gap-3 sm:grid-cols-2">
        <Field label="Hosts permitted">
          {e.allow.length === 0 ? (
            <span className="text-deny">nothing — the allowlist is empty, so every call is refused</span>
          ) : (
            e.allow.map((h) => <Mono key={h}>{h}</Mono>)
          )}
        </Field>
        <Field label="Methods">{e.methods.join(", ")}</Field>
        <Field label="Response cap">{bytes(e.maxBodyBytes)}</Field>
        <Field label="Request body cap">{bytes(e.maxRequestBodyBytes)}</Field>
        <Field label="Timeout">{e.timeoutMs} ms</Field>
        <Field label="Redirects">{e.maxRedirects === 0 ? "not followed" : `up to ${e.maxRedirects}, re-validated per hop`}</Field>
        <Field label="Private and link-local addresses">
          {e.blockPrivateIps ? "refused, and DNS answers are pinned for the connection" : "permitted"}
        </Field>
        <Field label="Plaintext HTTP">{e.allowHttp ? "permitted" : "refused"}</Field>
      </dl>
    </Panel>
  );
}


function Approvals({ p }: { p: ServerProtection }) {
  return (
    <Panel title="Approvals">
      <dl className="grid gap-3 sm:grid-cols-3">
        <Field label="Mode">
          <Mono>{p.approvals.mode}</Mono>
        </Field>
        <Field label="A grant expires after">{p.approvals.ttlSeconds} s</Field>
        <Field label="Reuse">{p.approvals.singleUse ? "single-use" : "reusable until it expires"}</Field>
        <Field label="Waiting now">{p.approvals.pendingCount}</Field>
        <Field label="Active pre-approvals">{p.approvals.activeGrantCount}</Field>
      </dl>
      {p.approvals.pendingElsewhere > 0 && (
        <p className="mt-2 text-xs text-ink-soft">
          {p.approvals.pendingElsewhere} further request(s) share this approvals database but belong to
          another server, and are not counted or shown here.
        </p>
      )}
      <p className="mt-3 text-sm text-ink-soft">
        A grant commits to the tool name and every argument, so an approval for one call cannot release a
        different one.
      </p>
    </Panel>
  );
}

function Audit({ p }: { p: ServerProtection }) {
  return (
    <Panel title="Audit trail">
      <dl className="grid gap-3 sm:grid-cols-2">
        <Field label="Log">
          <Mono>{p.audit.path}</Mono>
        </Field>
        <Field label="Records">{p.audit.verify.written ? p.audit.verify.count : "none written yet"}</Field>
        <Field label="Hash chain">{p.audit.hashChain ? "on — tampering is detectable" : "off"}</Field>
        <Field label="Arguments">
          {p.audit.recordArgs ? "recorded, redacted and hashed" : "not recorded"}
          {p.audit.redact.length > 0 && (
            <span className="ml-1 text-xs text-ink-soft">also hiding: {p.audit.redact.join(", ")}</span>
          )}
        </Field>
      </dl>
    </Panel>
  );
}
