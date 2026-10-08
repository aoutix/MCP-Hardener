import { useEffect, useState } from "react";
import { api, ApiError, type Grant } from "../api";
import {
  Banner,
  Button,
  EffectBadge,
  Empty,
  Field,
  Mono,
  Panel,
  Tag,
  relativeTime,
  useResource
} from "../components";

const TTL_PRESETS = [
  { label: "1 hour", seconds: 3600 },
  { label: "8 hours", seconds: 8 * 3600 },
  { label: "24 hours", seconds: 24 * 3600 },
  { label: "7 days", seconds: 7 * 86_400 },
  { label: "30 days", seconds: 30 * 86_400 }
];

interface Constraint {
  arg: string;
  kind: "max" | "min" | "enum" | "const" | "pattern" | "maxLength";
  value: string;
}

/**
 * Part 3: pre-approving a class of request.
 *
 * A standing grant is deliberately the weakest form of a permission change:
 * it matches a glob, is bounded by the same argument constraints policy rules
 * use, always expires, can cap its own uses, and is revocable. It cannot widen
 * what policy permits — it is only consulted for a call policy already routed
 * to a human, so it can spare the human a question but never answer one they
 * were never asked.
 */
export function Settings({ serverId }: { serverId: string }) {
  const grants = useResource(() => api.grants(serverId), [serverId], 15000);
  const [failure, setFailure] = useState<string | null>(null);

  async function revoke(id: string) {
    setFailure(null);
    try {
      const result = await api.revokeGrant(serverId, id);
      if (result.warning) setFailure(result.warning);
      grants.reload();
    } catch (err) {
      setFailure(err instanceof ApiError ? err.message : String(err));
    }
  }

  const active = (grants.data ?? []).filter((g) => g.state === "active");
  const past = (grants.data ?? []).filter((g) => g.state !== "active");

  return (
    <div className="space-y-4">
      {failure && <Banner tone="bad">{failure}</Banner>}

      <Banner tone="warn">
        A pre-approval lets calls through without asking. It is bounded by its arguments, its expiry and
        its use count, every one is written to the audit log, and it can be revoked at any time — but it
        is still a decision to stop reviewing something. Keep them narrow and short.
      </Banner>

      <GrantEditor serverId={serverId} onCreated={grants.reload} />

      <Panel title={`${active.length} active pre-approval(s)`}>
        {active.length === 0 ? (
          <Empty>Nothing is pre-approved. Every write will be held for a human.</Empty>
        ) : (
          <div className="space-y-2">
            {active.map((g) => (
              <GrantCard key={g.id} grant={g} onRevoke={() => revoke(g.id)} />
            ))}
          </div>
        )}
      </Panel>

      {past.length > 0 && (
        <Panel title="Expired, exhausted and revoked">
          <div className="space-y-2">
            {past.map((g) => (
              <GrantCard key={g.id} grant={g} />
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

function GrantCard({ grant, onRevoke }: { grant: Grant; onRevoke?: () => void }) {
  const constraints = Object.entries(grant.constraints ?? {});
  return (
    <article className="rounded-lg border border-edge bg-surface p-3">
      <header className="flex flex-wrap items-center gap-2">
        <span className="mono text-sm font-semibold">{grant.toolMatch}</span>
        {grant.effect && <EffectBadge effect={grant.effect} />}
        <Mono>{grant.id}</Mono>
        <Tag>{grant.state}</Tag>
        {onRevoke && (
          <span className="ml-auto">
            <Button tone="deny" onClick={onRevoke}>
              Revoke
            </Button>
          </span>
        )}
      </header>

      <dl className="mt-2 grid gap-2 sm:grid-cols-3">
        <Field label="Uses">
          {grant.uses} of {grant.maxUses ?? "unlimited"}
        </Field>
        <Field label={grant.state === "active" ? "Expires" : "Expired"}>{relativeTime(grant.expiresAt)}</Field>
        <Field label="Created by">{grant.createdBy}</Field>
        <Field label="Reason">{grant.reason}</Field>
        {grant.revokedBy && <Field label="Revoked by">{grant.revokedBy}</Field>}
      </dl>

      {constraints.length > 0 && (
        <div className="mt-2">
          <p className="text-xs text-ink-soft">Arguments must satisfy:</p>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {constraints.map(([arg, c]) => (
              <li key={arg}>
                <Tag>
                  {arg} {JSON.stringify(c)}
                </Tag>
              </li>
            ))}
          </ul>
        </div>
      )}
      {constraints.length === 0 && grant.maxUses !== null && (
        <p className="mt-2 text-xs text-ink-soft">
          No argument bounds — only the use cap and the expiry limit what this releases.
        </p>
      )}
    </article>
  );
}

function GrantEditor({ serverId, onCreated }: { serverId: string; onCreated: () => void }) {
  const [toolMatch, setToolMatch] = useState("");
  const [effect, setEffect] = useState("");
  const [ttl, setTtl] = useState(3600);
  const [maxUses, setMaxUses] = useState("5");
  const [reason, setReason] = useState("");
  const [constraints, setConstraints] = useState<Constraint[]>([]);
  const [preview, setPreview] = useState<{ name: string; effect: string; covers: boolean; why: string }[] | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function body() {
    const parsed: Record<string, Record<string, unknown>> = {};
    for (const c of constraints) {
      if (!c.arg || c.value === "") continue;
      const value =
        c.kind === "enum"
          ? c.value.split(",").map((s) => coerce(s.trim()))
          : c.kind === "pattern"
            ? c.value
            : coerce(c.value);
      parsed[c.arg] = { ...(parsed[c.arg] ?? {}), [c.kind]: value };
    }
    return {
      tool_match: toolMatch,
      effect: effect || null,
      constraints: parsed,
      ttl_seconds: ttl,
      max_uses: maxUses === "" ? null : Number(maxUses),
      reason
    };
  }

  /**
   * The preview is the honest part of this page: it asks the server which of
   * the tools that exist right now this draft would cover, before anything is
   * saved. It writes nothing and claims no uses.
   */
  useEffect(() => {
    if (!toolMatch) {
      setPreview(null);
      setProblem(null);
      return;
    }
    let live = true;
    const id = setTimeout(() => {
      api
        .previewGrant(serverId, { ...body(), reason: reason || "preview" })
        .then((result) => {
          if (!live) return;
          setPreview(result.tools);
          setProblem(null);
        })
        .catch((err: Error) => {
          if (!live) return;
          setPreview(null);
          setProblem(err.message);
        });
    }, 250);
    return () => {
      live = false;
      clearTimeout(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serverId, toolMatch, effect, ttl, maxUses, JSON.stringify(constraints)]);

  async function create() {
    setBusy(true);
    setProblem(null);
    try {
      await api.createGrant(serverId, body());
      setToolMatch("");
      setReason("");
      setConstraints([]);
      setPreview(null);
      onCreated();
    } catch (err) {
      setProblem(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const covered = preview?.filter((t) => t.covers) ?? [];

  return (
    <Panel title="Pre-approve a class of request" subtitle="Nothing is saved until you create it.">
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="flex flex-col gap-1">
          <span className="text-xs text-ink-soft">
            Tool pattern — <Mono>*</Mono>, <Mono>?</Mono> and <Mono>{"{a,b}"}</Mono>, as in policy rules
          </span>
          <input
            value={toolMatch}
            onChange={(e) => setToolMatch(e.target.value)}
            placeholder="create_invoice or {create,update}_*"
            className="mono rounded-md border border-edge bg-surface px-2 py-1.5 text-sm"
          />
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs text-ink-soft">Restrict to one effect (optional)</span>
          <select
            value={effect}
            onChange={(e) => setEffect(e.target.value)}
            className="rounded-md border border-edge bg-surface px-2 py-1.5 text-sm"
          >
            <option value="">any effect</option>
            <option value="read">read only</option>
            <option value="write">write only</option>
            <option value="destructive">destructive only</option>
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs text-ink-soft">Expires after</span>
          <select
            value={ttl}
            onChange={(e) => setTtl(Number(e.target.value))}
            className="rounded-md border border-edge bg-surface px-2 py-1.5 text-sm"
          >
            {TTL_PRESETS.map((p) => (
              <option key={p.seconds} value={p.seconds}>
                {p.label}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs text-ink-soft">Release at most this many calls (blank for unlimited)</span>
          <input
            value={maxUses}
            onChange={(e) => setMaxUses(e.target.value.replace(/[^0-9]/g, ""))}
            placeholder="5"
            className="rounded-md border border-edge bg-surface px-2 py-1.5 text-sm"
          />
        </label>

        <label className="flex flex-col gap-1 sm:col-span-2">
          <span className="text-xs text-ink-soft">Reason — required, and written to the audit log</span>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Month-end invoicing run, approved by finance"
            className="rounded-md border border-edge bg-surface px-2 py-1.5 text-sm"
          />
        </label>
      </div>

      <div className="mt-3">
        <div className="flex items-center justify-between">
          <p className="text-xs text-ink-soft">
            Argument bounds — checked before the grant releases anything, with the same rules a policy uses
          </p>
          <Button onClick={() => setConstraints([...constraints, { arg: "", kind: "max", value: "" }])}>
            Add a bound
          </Button>
        </div>
        {constraints.length > 0 && (
          <ul className="mt-2 space-y-2">
            {constraints.map((c, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2">
                <input
                  value={c.arg}
                  onChange={(e) => update(i, { arg: e.target.value })}
                  placeholder="argument"
                  className="mono w-36 rounded-md border border-edge bg-surface px-2 py-1 text-sm"
                />
                <select
                  value={c.kind}
                  onChange={(e) => update(i, { kind: e.target.value as Constraint["kind"] })}
                  className="rounded-md border border-edge bg-surface px-2 py-1 text-sm"
                >
                  <option value="max">at most</option>
                  <option value="min">at least</option>
                  <option value="enum">one of</option>
                  <option value="const">exactly</option>
                  <option value="pattern">matches</option>
                  <option value="maxLength">no longer than</option>
                </select>
                <input
                  value={c.value}
                  onChange={(e) => update(i, { value: e.target.value })}
                  placeholder={c.kind === "enum" ? "usd, eur" : "500"}
                  className="mono w-40 rounded-md border border-edge bg-surface px-2 py-1 text-sm"
                />
                <Button onClick={() => setConstraints(constraints.filter((_, j) => j !== i))}>Remove</Button>
              </li>
            ))}
          </ul>
        )}
      </div>

      {problem && (
        <div className="mt-3">
          <Banner tone="bad">{problem}</Banner>
        </div>
      )}

      {preview && (
        <div className="mt-3 rounded-md border border-edge bg-surface p-3">
          <p className="text-sm font-medium">
            {covered.length === 0
              ? "This would cover no tool that exists on this server."
              : `This would cover ${covered.length} tool(s) right now:`}
          </p>
          {covered.length > 0 && (
            <ul className="mt-1.5 flex flex-wrap gap-1.5">
              {covered.map((t) => (
                <li key={t.name} className="flex items-center gap-1">
                  <Mono>{t.name}</Mono>
                  <EffectBadge effect={t.effect} />
                </li>
              ))}
            </ul>
          )}
          <p className="mt-2 text-xs text-ink-soft">
            Shown for the tools on this server today. A tool added later that matches the pattern would also
            be covered, which is why the use cap and expiry matter.
          </p>
        </div>
      )}

      <div className="mt-3 flex items-center gap-2">
        <Button tone="approve" disabled={busy || !toolMatch || !reason} onClick={create}>
          Create pre-approval
        </Button>
        {(!toolMatch || !reason) && <span className="text-xs text-ink-soft">A pattern and a reason are required.</span>}
      </div>
    </Panel>
  );

  function update(index: number, patch: Partial<Constraint>) {
    setConstraints(constraints.map((c, i) => (i === index ? { ...c, ...patch } : c)));
  }
}

function coerce(value: string): unknown {
  if (value === "true") return true;
  if (value === "false") return false;
  const n = Number(value);
  return Number.isFinite(n) && value.trim() !== "" ? n : value;
}
