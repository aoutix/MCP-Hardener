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

/*
 * Offered only up to the ceiling the server reports.
 *
 * The last of these used to sit exactly on `MAX_GRANT_TTL_SECONDS`, so any
 * future tightening in core would have had the UI offer a preset the API then
 * refused with a 422. The ceiling is served, so it is read.
 */
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
export function Settings({ serverId, tenant }: { serverId: string; tenant: string | null }) {
  const grants = useResource(() => api.grants(serverId, tenant), [serverId, tenant], 15000);
  const [failure, setFailure] = useState<string | null>(null);

  async function revoke(id: string) {
    setFailure(null);
    try {
      const result = await api.revokeGrant(serverId, id, tenant);
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

      <GrantEditor serverId={serverId} tenant={tenant} onCreated={grants.reload} />

      <Panel title={`${active.length} active pre-approval(s)`}>
        {active.length === 0 ? (
          /*
           * What policy does with an unapproved write is policy's business, and
           * it is not always "hold it": this used to assert a human reviews
           * every write, which is false whenever a rule allows one outright.
           */
          <Empty>
            Nothing is pre-approved. Writes are handled by policy alone — see the Protection tab for what that
            means on this gateway.
          </Empty>
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

function GrantEditor({
  serverId,
  tenant,
  onCreated
}: {
  serverId: string;
  tenant: string | null;
  onCreated: () => void;
}) {
  const [toolMatch, setToolMatch] = useState("");
  const [effect, setEffect] = useState("");
  const [ttl, setTtl] = useState(3600);
  const [maxUses, setMaxUses] = useState("5");
  const [reason, setReason] = useState("");
  const [constraints, setConstraints] = useState<Constraint[]>([]);
  const [preview, setPreview] = useState<
    { name: string; effect: string | null; covers: boolean; why: string }[] | null
  >(null);
  const [surfaceKnown, setSurfaceKnown] = useState(true);
  const [surfaceUnknownWhy, setSurfaceUnknownWhy] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  /* The gateway's own tool list and the grant ceiling, both served. */
  const tools = useResource(() => api.tools(serverId, tenant), [serverId, tenant]);
  const meta = useResource(() => api.redaction(), []);
  const surface = tools.data ?? [];
  const ttlCeiling = meta.data?.grantTtlMaxSeconds ?? Number.POSITIVE_INFINITY;
  const presets = TTL_PRESETS.filter((p) => p.seconds <= ttlCeiling);

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
        .previewGrant(serverId, { ...body(), reason: reason || "preview" }, tenant)
        .then((result) => {
          if (!live) return;
          setPreview(result.tools);
          setSurfaceKnown(result.surfaceKnown);
          setSurfaceUnknownWhy(result.surfaceUnknownWhy);
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
      await api.createGrant(serverId, body(), tenant);
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

  /*
   * A pattern suggestion taken from the surface rather than invented. The
   * placeholder used to name `create_invoice`, a tool from an example spec that
   * no gateway here serves.
   */
  const toolHint = surface.length > 0 ? `${surface[0]!.name} or ${surface[0]!.name.split("_")[0]}_*` : "name or glob";

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
            placeholder={toolHint}
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
            {presets.map((p) => (
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
            placeholder="Why this is being pre-approved, and who agreed to it"
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
                  placeholder={c.kind === "enum" ? "comma-separated values" : "value"}
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
          {/*
           * "Covers nothing" and "we cannot tell" must not look the same here.
           * This control releases calls without a human, so a preview that
           * silently reported an empty surface as a narrow grant was the most
           * dangerous wrong answer in the console.
           */}
          {!surfaceKnown ? (
            <p className="text-sm font-medium text-write">
              Cannot say what this would cover: {surfaceUnknownWhy ?? "no gateway has reported its tools."}
            </p>
          ) : (
            <p className="text-sm font-medium">
              {covered.length === 0
                ? "This would cover no tool this gateway is currently serving."
                : `This would cover ${covered.length} tool(s) right now:`}
            </p>
          )}
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
            Shown for the tools this gateway is serving today. A tool an upstream adds later that matches the
            pattern would also be covered, which is why the use cap and expiry matter.
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
