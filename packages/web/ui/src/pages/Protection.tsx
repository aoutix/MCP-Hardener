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
  SeverityBadge,
  Tag,
  VerdictBadge,
  bytes,
  useResource
} from "../components";

/**
 * Part 4: how this server is being protected.
 *
 * Every number, host, path and verdict on this page is read from this server's
 * own tools.json and policy.yaml, or computed by the same functions the runtime
 * uses. The only prose written ahead of time is the pipeline description, which
 * describes the runtime's code rather than the user's configuration, and each
 * of its steps cites the file it corresponds to.
 */
export function Protection({ serverId }: { serverId: string }) {
  const { data, error, loading } = useResource(() => api.protection(serverId), [serverId]);

  if (error) return <Banner tone="bad">{error}</Banner>;
  if (loading && !data) return <Empty>Reading this server's configuration…</Empty>;
  if (!data) return <Empty>Nothing to show.</Empty>;

  return (
    <div className="space-y-4">
      <Headline p={data} />
      <Pipeline p={data} />
      <Posture p={data} />
      <Rules p={data} />
      {data.tenant && <Tenant p={data} />}
      <Egress p={data} />
      <Credentials p={data} />
      <Approvals p={data} />
      <Audit p={data} />
      {data.generation && <Generation p={data} />}
      <Withheld p={data} />
      <Reviews p={data} />
      <ServerFindings p={data} />
    </div>
  );
}

function Headline({ p }: { p: ServerProtection }) {
  const high = p.counts["high"] ?? 0;
  const medium = p.counts["medium"] ?? 0;
  return (
    <div className="space-y-2">
      {high > 0 ? (
        <Banner tone="bad">
          {high} high-severity finding{high === 1 ? "" : "s"} on this surface
          {medium > 0 && `, and ${medium} medium`}. This server should not be shipped as it is.
        </Banner>
      ) : medium > 0 ? (
        <Banner tone="warn">{medium} medium-severity finding(s). Nothing high-severity.</Banner>
      ) : (
        <Banner tone="ok">The scanner finds nothing wrong with this surface.</Banner>
      )}
      {p.tenant?.error && (
        <Banner tone="warn">
          {p.tenant.error} (The console resolves the tenant from its own environment, which may differ
          from the server's.)
        </Banner>
      )}
      {!p.audit.enabled && (
        <Banner tone="bad">
          Auditing is disabled, so approved and refused calls leave no record on this server.
        </Banner>
      )}
      {p.audit.enabled && !p.audit.verify.written && (
        <Banner tone="warn">
          Nothing has been written to the audit log yet. That is expected if this server has not run.
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
      subtitle="This describes the shared runtime every generated server and the gateway use. Each step cites its source."
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
      {p.api && e.baseUrlPermitted === false && (
        <div className="mt-3">
          <Banner tone="bad">
            This server calls <Mono>{p.api.baseUrl}</Mono>, which the allowlist does not permit. Every call
            will be refused at runtime.
          </Banner>
        </div>
      )}
    </Panel>
  );
}

function Credentials({ p }: { p: ServerProtection }) {
  return (
    <Panel title="Credentials">
      <dl className="grid gap-3 sm:grid-cols-3">
        <Field label="Scheme">{p.auth.kind}</Field>
        {p.auth.envVar && (
          <>
            <Field label="Read from">
              <Mono>{p.auth.envVar}</Mono>
            </Field>
            <Field label="Set in this environment">{p.auth.envPresent ? "yes" : "no"}</Field>
          </>
        )}
      </dl>
      <p className="mt-3 text-xs text-ink-soft">
        The console reports the variable's name and whether it is set. It never reads the value, and the
        value is never sent to the browser.
      </p>
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

function Generation({ p }: { p: ServerProtection }) {
  const g = p.generation!;
  return (
    <Panel title="How this surface was generated">
      <dl className="grid gap-3 sm:grid-cols-3">
        {g.specFormat && <Field label="Spec format">{g.specFormat}</Field>}
        <Field label="Spec declares authentication">
          {g.hasSecuritySchemes === null ? "unknown" : g.hasSecuritySchemes ? "yes" : "no"}
        </Field>
        <Field label="Operations not exposed">{g.skipped.length}</Field>
      </dl>

      {g.operationsWithoutSecurity.length > 0 && (
        <div className="mt-3">
          <p className="text-sm">These exposed operations declare no authentication in the spec:</p>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {g.operationsWithoutSecurity.map((o) => (
              <li key={o}>
                <Mono>{o}</Mono>
              </li>
            ))}
          </ul>
        </div>
      )}

      {g.skipped.length > 0 && (
        <div className="mt-3">
          <p className="text-sm">Operations an agent cannot reach at all:</p>
          <ul className="mt-1 space-y-1 text-sm">
            {g.skipped.map((s) => (
              <li key={s.tool} className="flex flex-wrap items-baseline gap-2">
                <Mono>{s.tool}</Mono>
                <span className="text-ink-soft">{s.reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  );
}

function Withheld({ p }: { p: ServerProtection }) {
  const rows = p.tools.flatMap((t) => t.withheldParams.map((w) => ({ tool: t.name, ...w })));
  if (rows.length === 0) return null;

  const byReason = new Map<string, typeof rows>();
  for (const row of rows) {
    byReason.set(row.reason, [...(byReason.get(row.reason) ?? []), row]);
  }

  return (
    <Panel
      title={`${rows.length} parameter(s) withheld from the model`}
      subtitle="Present upstream, absent from every tool schema, grouped by why."
    >
      <div className="space-y-3">
        {[...byReason.entries()].map(([reason, group]) => (
          <div key={reason}>
            <p className="text-sm font-medium">{reason}</p>
            <ul className="mt-1 flex flex-wrap gap-1.5">
              {group.map((row) => (
                <li key={`${row.tool}.${row.name}`}>
                  <Tag title={`${row.tool} — ${row.in ?? "unknown location"}`}>
                    {row.tool}.{row.name}
                  </Tag>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function Reviews({ p }: { p: ServerProtection }) {
  const rows = p.tools.filter((t) => t.review);
  if (rows.length === 0) return null;
  return (
    <Panel
      title={`${rows.length} tool(s) a human should confirm`}
      subtitle="The generator inferred these classifications and could not decide safely."
    >
      <ul className="space-y-2">
        {rows.map((t) => (
          <li key={t.name} className="rounded-md border border-medium/40 bg-medium/5 p-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <Mono>{t.name}</Mono>
              <EffectBadge effect={t.effect} />
              <VerdictBadge kind={t.verdict.kind} />
            </div>
            <p className="mt-1 text-sm text-ink-soft">{t.review}</p>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function ServerFindings({ p }: { p: ServerProtection }) {
  if (p.findings.length === 0) return null;
  return (
    <Panel title="Findings about the surface as a whole">
      <ul className="space-y-2">
        {p.findings.map((f, i) => (
          <li key={i} className="text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={f.severity} />
              <Mono>{f.ruleId}</Mono>
              <span className="font-medium">{f.title}</span>
              {f.location.path && <span className="mono text-xs text-ink-soft">{f.location.path}</span>}
            </div>
            <p className="mt-0.5 text-ink-soft">{f.message}</p>
            <p className="mt-0.5 text-xs text-ink-soft">Fix: {f.fix}</p>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
