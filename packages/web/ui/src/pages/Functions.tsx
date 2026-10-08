import { useEffect, useMemo, useState } from "react";
import { api, type ServerProtection, type ToolProtection } from "../api";
import {
  Banner,
  Button,
  Empty,
  Icon,
  Modal,
  Mono,
  RedactedArgs,
  SeverityBadge,
  Tag,
  VerdictBadge,
  bytes,
  relativeTime,
  useDismissed,
  useResource
} from "../components";

/** What `useExposure` hands to the list and the detail pane. */
type ExposureControl = ReturnType<typeof useExposure>;

type ExposureKind = "exposed" | "review" | "internal" | "off";

/**
 * What the model can actually do with this function, collapsed to the states
 * the list is grouped by. It is derived from the verdict the server's own
 * `decide()` produced, never from the policy file read a second time here —
 * except for `off`, which is the console's own switch and takes precedence
 * because the runtime refuses a switched-off tool before weighing anything.
 */
function exposureOf(tool: ToolProtection): { kind: ExposureKind; label: string; title: string } {
  if (tool.exposure.disabled) {
    const who = tool.exposure.setBy ? ` by ${tool.exposure.setBy}` : "";
    const why = tool.exposure.reason ? `: ${tool.exposure.reason}` : "";
    return {
      kind: "off",
      label: "Switched off",
      title:
        `Switched off in the console${who}${why}. It is not advertised to the model and every call is refused. ` +
        (tool.exposure.policyWouldExpose
          ? "Policy was not changed — switching it back on restores what policy.yaml says."
          : "Policy refuses this function anyway, so switching it back on leaves it unreachable.")
    };
  }
  if (tool.unreachable) {
    return {
      kind: "internal",
      label: "Unreachable",
      title: "Approval is required for this function, but approvals are disabled in this policy."
    };
  }
  if (tool.review) return { kind: "review", label: "Needs review", title: tool.review };
  if (tool.verdict.kind === "deny") return { kind: "internal", label: "Internal", title: tool.verdict.reason };
  if (tool.verdict.kind === "approve") return { kind: "review", label: "Needs approval", title: tool.verdict.reason };
  return { kind: "exposed", label: "Exposed", title: tool.verdict.reason };
}

const PERMISSION: Record<string, { label: string; className: string }> = {
  read: { label: "Read-only", className: "text-read" },
  write: { label: "Write", className: "text-write" },
  destructive: { label: "Destructive", className: "text-destructive" }
};

function signatureOf(tool: ToolProtection): string {
  const args = tool.args.map((a) => `${a.name}${a.required ? "" : "?"}: ${a.type ?? "any"}`).join(", ");
  return `(${args})`;
}

function authLabel(server: ServerProtection | null): string {
  const kind = server?.auth.kind;
  if (!kind || kind === "none") return "No upstream auth";
  if (kind === "bearer") return "Bearer token";
  if (kind === "apiKey" || kind === "api_key") return "API key";
  if (kind === "basic") return "Basic auth";
  return kind;
}

export function Functions({ serverId, onServerChanged }: { serverId: string; onServerChanged: () => void }) {
  const { data, error, loading, reload } = useResource(() => api.protection(serverId), [serverId]);
  const [query, setQuery] = useState("");
  const [effect, setEffect] = useState("all");
  const [filter, setFilter] = useState<"all" | ExposureKind>("all");
  const [sort, setSort] = useState<"source" | "risk" | "name">("source");
  const [selected, setSelected] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(true);
  /**
   * Functions kept in the list although they no longer match the active tab,
   * because they stopped matching it under the pointer: switching one off from
   * the Exposed tab used to make the row vanish mid-click, which left no way to
   * see what the switch did or to put it straight back. They are released when
   * the tab changes — leaving that section is the point at which the filter
   * becomes a question being asked again rather than the view being worked in.
   */
  const [held, setHeld] = useState<string[]>([]);
  const exposure = useExposure(
    serverId,
    data,
    reload,
    (name) => setHeld((h) => (h.includes(name) ? h : [...h, name])),
    onServerChanged
  );

  const all = useMemo(() => data?.tools ?? [], [data]);

  useEffect(() => {
    setHeld([]);
  }, [filter]);

  const tools = useMemo(() => {
    const rank = { destructive: 0, write: 1, read: 2 } as Record<string, number>;
    const filtered = all.filter((t) => {
      if (filter !== "all" && exposureOf(t).kind !== filter && !held.includes(t.name)) return false;
      if (effect !== "all" && t.effect !== effect) return false;
      if (!query) return true;
      return `${t.name} ${t.description} ${t.method} ${t.path}`.toLowerCase().includes(query.toLowerCase());
    });
    if (sort === "name") return [...filtered].sort((a, b) => a.name.localeCompare(b.name));
    if (sort === "risk") return [...filtered].sort((a, b) => (rank[a.effect] ?? 3) - (rank[b.effect] ?? 3));
    return filtered;
  }, [all, query, effect, filter, sort, held]);

  useEffect(() => {
    if (tools.length > 0 && !tools.some((t) => t.name === selected)) setSelected(tools[0]!.name);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tools]);

  if (error) {
    return (
      <div className="p-7">
        <Banner tone="bad">{error}</Banner>
      </div>
    );
  }
  if (loading && !data) return <Empty>Loading functions…</Empty>;

  const counts = { exposed: 0, review: 0, internal: 0, off: 0 };
  for (const t of all) counts[exposureOf(t).kind]++;

  const active = tools.find((t) => t.name === selected) ?? null;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <header className="border-b border-edge px-7 pt-6 pb-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-[1.75rem] font-semibold tracking-tight">All functions</h1>
            <p className="mt-1 text-sm text-ink-soft">
              Everything this server exposes to the model. See exactly who can do what.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button onClick={() => location.reload()}>
              <Icon name="refresh" size={15} className="text-ink-soft" /> Refresh
            </Button>
            <Button tone="primary" onClick={() => exportTools(serverId, all)}>
              <Icon name="download" size={15} /> Export
            </Button>
          </div>
        </div>

        <div className="mt-5 flex items-center justify-end gap-2 text-sm">
          <span className="mono text-[0.8125rem] text-ink-soft">
            {data?.api?.title ?? "upstream"} {data?.api?.version ?? ""}
          </span>
        </div>
      </header>

      {(exposure.error || exposure.notice) && (
        <div className="border-b border-edge px-7 py-3">
          <button onClick={exposure.clear} className="block w-full text-left" title="Dismiss">
            <Banner tone={exposure.error ? "bad" : "warn"}>{exposure.error ?? exposure.notice}</Banner>
          </button>
        </div>
      )}

      <div className="flex min-h-0 flex-1">
        <section className="flex min-w-0 flex-1 flex-col border-r border-edge">
          <div className="flex flex-wrap items-center gap-2.5 px-7 pt-5">
            <div className="relative min-w-56 flex-1">
              <Icon name="search" size={15} className="absolute top-1/2 left-3 -translate-y-1/2 text-ink-faint" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search functions, descriptions or paths…"
                className="w-full rounded-xl border border-edge bg-white/55 py-2.5 pr-3 pl-9 text-sm placeholder:text-ink-faint focus:border-accent/60 focus:ring-2 focus:ring-accent/15 focus:outline-none"
              />
            </div>
            <Select value={effect} onChange={setEffect}>
              <option value="all">All permissions</option>
              <option value="read">Read-only</option>
              <option value="write">Write</option>
              <option value="destructive">Destructive</option>
            </Select>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 px-7 pt-4">
            <div className="flex flex-wrap items-center gap-1">
              <FilterTab id="all" active={filter} onPick={setFilter} label="All functions" count={all.length} />
              <FilterTab id="exposed" active={filter} onPick={setFilter} label="Exposed" count={counts.exposed} />
              <FilterTab id="internal" active={filter} onPick={setFilter} label="Internal" count={counts.internal} />
              <FilterTab
                id="review"
                active={filter}
                onPick={setFilter}
                label="Needs review"
                count={counts.review}
                tone={counts.review > 0 ? "text-write" : undefined}
              />
              {/* Kept while it is the active filter, so re-enabling the last
                  switched-off function does not strand the list on a tab that
                  has just disappeared. */}
              {(counts.off > 0 || filter === "off") && (
                <FilterTab id="off" active={filter} onPick={setFilter} label="Switched off" count={counts.off} />
              )}
            </div>
            <button
              onClick={() => setSort(sort === "source" ? "risk" : sort === "risk" ? "name" : "source")}
              className="flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-[0.8125rem] text-ink-soft transition hover:bg-white/50 hover:text-ink"
            >
              <Icon name="sort" size={15} />
              {sort === "source" ? "Spec order" : sort === "risk" ? "Most permissive" : "Name"}
            </button>
          </div>

          <div className="mt-3 grid grid-cols-[minmax(0,1fr)_170px_110px_132px] gap-3 border-y border-edge bg-white/35 px-7 py-2 text-[0.6875rem] font-medium tracking-[0.06em] text-ink-faint uppercase">
            <span>Function</span>
            <span>Authentication</span>
            <span>Permissions</span>
            <span>Exposure</span>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto">
            {tools.length === 0 ? (
              <Empty>No function matches that filter.</Empty>
            ) : (
              tools.map((tool) => (
                <FunctionRow
                  key={tool.name}
                  tool={tool}
                  server={data}
                  selected={tool.name === selected}
                  onSelect={() => {
                    setSelected(tool.name);
                    setDetailOpen(true);
                  }}
                  onToggle={exposure.onToggle(tool)}
                  busy={exposure.busy(tool)}
                  flash={exposure.flash(tool)}
                  held={filter !== "all" && exposureOf(tool).kind !== filter}
                />
              ))
            )}
          </div>

          <div className="flex items-center gap-2 border-t border-edge px-7 py-3 text-[0.8125rem] text-ink-soft">
            <Icon name="shield" size={15} className="text-accent" />
            <span>
              <span className="text-ink">{counts.exposed} functions</span> are reachable by the model.
            </span>
            <span className="text-ink-faint">
              {counts.review} held for review or approval, {counts.internal} can never run
              {counts.off > 0 ? `, ${counts.off} switched off here` : ""}.
            </span>
          </div>
        </section>

        {detailOpen ? (
          <aside className="flex w-[398px] shrink-0 flex-col overflow-hidden">
            {active ? (
              <FunctionDetail
                key={active.name}
                serverId={serverId}
                server={data}
                fallback={active}
                onCollapse={() => setDetailOpen(false)}
                exposure={exposure}
              />
            ) : (
              <Empty>Select a function.</Empty>
            )}
          </aside>
        ) : (
          <aside className="flex w-12 shrink-0 justify-center pt-3.5">
            <button
              onClick={() => setDetailOpen(true)}
              title="Show function details"
              className="rounded-lg p-1.5 text-ink-faint transition hover:bg-white/50 hover:text-ink"
            >
              <Icon name="expand" size={17} />
            </button>
          </aside>
        )}
      </div>

      {exposure.dialog}
    </div>
  );
}

/**
 * Owns the exposure switch for the whole page: who is mid-flight, what went
 * wrong, and the one confirmation step.
 *
 * Both the list and the detail pane drive the same switch, so the rule about
 * when to warn lives here once rather than in two places that could disagree.
 */
function useExposure(
  serverId: string,
  server: ServerProtection | null,
  reload: () => void,
  /** Told which function just changed, so the list can keep showing it. */
  onApplied: (name: string) => void,
  /**
   * Told that the server's reach may have moved. Switching the last reachable
   * write off, or the first one back on, changes what the chrome outside this
   * page is claiming about the whole server, and that claim is served by a
   * resource this page does not own.
   */
  onServerChanged: () => void
) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<ToolProtection | null>(null);
  /** name → the direction it moved, for one pass of the switch and row animation. */
  const [flash, setFlash] = useState<Record<string, boolean>>({});
  const warning = useDismissed("expose-mutating-function");

  // A gateway's surface is its upstreams', discovered at connect time; there is
  // no curated descriptor to switch off, and the backend refuses it too.
  const editable = server?.kind === "generated";

  async function apply(tool: ToolProtection, disabled: boolean) {
    setBusy(tool.name);
    setError(null);
    setNotice(null);
    try {
      const result = await api.setExposure(serverId, tool.name, disabled);
      if (result.warning) setNotice(result.warning);
      onApplied(tool.name);
      setFlash((f) => ({ ...f, [tool.name]: !disabled }));
      // Long enough for both keyframe passes to finish; dropping the entry is
      // what lets the same switch bloom again on the next click.
      setTimeout(() => {
        setFlash((f) => {
          const next = { ...f };
          delete next[tool.name];
          return next;
        });
      }, 900);
      reload();
      onServerChanged();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  function toggle(tool: ToolProtection) {
    const turningOn = tool.exposure.disabled;
    const mutating = tool.effect === "write" || tool.effect === "destructive";
    // Switching a function off only narrows what the model can reach, so it
    // goes through unprompted. Switching one back on hands a function that
    // changes data back to policy, and that is worth one deliberate pause.
    if (turningOn && mutating && !warning.dismissed) {
      setConfirming(tool);
      return;
    }
    void apply(tool, !turningOn);
  }

  return {
    error,
    notice,
    clear: () => {
      setError(null);
      setNotice(null);
    },
    /** undefined for a server whose exposure this console does not own. */
    onToggle: (tool: ToolProtection) => (editable ? () => toggle(tool) : undefined),
    busy: (tool: ToolProtection) => busy === tool.name,
    flash: (tool: ToolProtection) => flash[tool.name],
    dialog: confirming ? (
      <ExposeWarning
        tool={confirming}
        onCancel={() => setConfirming(null)}
        onConfirm={(dismiss) => {
          if (dismiss) warning.dismiss();
          const tool = confirming;
          setConfirming(null);
          void apply(tool, false);
        }}
      />
    ) : null
  };
}

/**
 * The one confirmation in this page.
 *
 * It says what switching on actually does, which is less than it sounds: the
 * override is cleared and policy decides again. Stating the verdict the
 * function will land on is the whole value of asking.
 */
function ExposeWarning({
  tool,
  onCancel,
  onConfirm
}: {
  tool: ToolProtection;
  onCancel: () => void;
  onConfirm: (dismiss: boolean) => void;
}) {
  const [dismiss, setDismiss] = useState(false);
  const permission = PERMISSION[tool.effect] ?? { label: tool.effect, className: "text-ink" };
  const landsOn =
    tool.verdict.kind === "allow"
      ? "run without asking anyone"
      : tool.verdict.kind === "approve"
        ? "be held for human approval on every call"
        : "still be refused";

  return (
    <Modal
      title={`Switch ${tool.name} back on?`}
      onClose={onCancel}
      footer={
        <>
          <Button tone="primary" onClick={() => onConfirm(dismiss)}>
            <Icon name="plug" size={15} /> Switch on
          </Button>
          <Button onClick={onCancel}>Cancel</Button>
          <label className="ml-auto flex cursor-pointer items-center gap-1.5 text-xs text-ink-soft">
            <input
              type="checkbox"
              checked={dismiss}
              onChange={(e) => setDismiss(e.target.checked)}
              className="accent-accent-strong"
            />
            Don’t show this again
          </label>
        </>
      }
    >
      <p>
        <span className="mono font-semibold">{tool.name}</span> is a{" "}
        <span className={`font-semibold ${permission.className}`}>{permission.label.toLowerCase()}</span> function —{" "}
        <span className="mono">
          {tool.method} {tool.path}
        </span>
        . Switching it on puts it back on the model’s menu.
      </p>
      <p className="mt-3">
        This does not change <span className="mono">policy.yaml</span>. It clears the console’s override and lets
        policy decide again: under rule <Mono>{tool.verdict.ruleId}</Mono> this call will {landsOn}.
      </p>
      {tool.effect === "destructive" && (
        <div className="mt-3">
          <Banner tone="warn">
            This function deletes data. Everything policy says about it still applies, but nothing here does any more.
          </Banner>
        </div>
      )}
      <p className="mt-3 text-xs text-ink-soft">
        The change is written to the audit log, and takes effect on the server’s next call without a restart.
      </p>
    </Modal>
  );
}

function exportTools(serverId: string, tools: ToolProtection[]) {
  const blob = new Blob([JSON.stringify(tools, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${serverId}-functions.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function Select({
  value,
  onChange,
  children
}: {
  value: string;
  onChange: (v: string) => void;
  children: React.ReactNode;
}) {
  return (
    <div className="relative">
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="appearance-none rounded-xl border border-edge bg-white/55 py-2.5 pr-8 pl-3 text-sm font-medium focus:border-accent/60 focus:outline-none"
      >
        {children}
      </select>
      <Icon name="chevron" size={15} className="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2 text-ink-faint" />
    </div>
  );
}

function FilterTab({
  id,
  active,
  onPick,
  label,
  count,
  tone
}: {
  id: "all" | ExposureKind;
  active: string;
  onPick: (v: "all" | ExposureKind) => void;
  label: string;
  count: number;
  tone?: string;
}) {
  const on = active === id;
  return (
    <button
      onClick={() => onPick(id)}
      className={`rounded-lg px-3 py-1.5 text-[0.8125rem] font-medium transition ${
        on ? "bg-white/60 text-ink" : "text-ink-soft hover:text-ink"
      }`}
    >
      {label} <span className={`ml-1 ${tone ?? "text-ink-faint"}`}>{count}</span>
    </button>
  );
}

/**
 * The exposure switch.
 *
 * Off means off: the tool is not advertised and every call to it is refused.
 * On does *not* mean allowed — it means "policy decides", so a function policy
 * refuses still reads as Internal with the switch left where policy puts it.
 * That asymmetry is the point, and it is why this console can own this one
 * control without becoming a second, unreviewed policy file.
 *
 * Without `onToggle` it renders as the indicator it has always been, which is
 * what a gateway gets: its surface belongs to its upstreams.
 */
function ExposureSwitch({
  tool,
  title,
  onToggle,
  busy,
  bloom
}: {
  tool: ToolProtection;
  title: string;
  onToggle?: () => void;
  busy?: boolean;
  /** Which way this switch has just moved, for one pass of the bloom. */
  bloom?: boolean;
}) {
  const { disabled, policyWouldExpose } = tool.exposure;
  const on = !disabled && policyWouldExpose;
  /**
   * A function policy already refuses has nothing to switch: the override can
   * only subtract, and there is nothing left to subtract. Offering a control
   * that cannot change the outcome would be the one dishonest thing this page
   * could do.
   */
  const actionable = onToggle !== undefined && (disabled || policyWouldExpose);

  const body = (
    <span
      className={`switch-track inline-flex h-[18px] w-8 shrink-0 items-center justify-start rounded-full px-0.5 ${
        on ? "switch-on" : ""
      } ${busy ? "bg-ink-faint" : on ? "bg-accent-strong" : "bg-edge"} ${
        // Only once the write has landed: blooming on the click and again on
        // the reload would read as two separate changes.
        bloom === undefined || busy ? "" : bloom ? "switch-bloom-on" : "switch-bloom-off"
      }`}
    >
      <span className={`switch-knob h-3.5 w-3.5 rounded-full bg-white shadow-xs ${busy ? "animate-pulse" : ""}`} />
    </span>
  );

  if (!actionable) {
    return (
      <span
        role="img"
        aria-label={`${on ? "Exposed" : "Not exposed"}${
          onToggle ? " — policy already refuses this function, so there is nothing to switch off" : ""
        }`}
        title={
          onToggle
            ? `${title}\n\nPolicy already refuses this function, so there is nothing to switch off.`
            : title
        }
      >
        {body}
      </span>
    );
  }

  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={`Expose ${tool.name} to the model`}
      disabled={busy}
      title={`${title}\n\nClick to switch ${disabled ? "on" : "off"}.`}
      onClick={(e) => {
        // The row behind this is itself clickable; a toggle must not also
        // change which function the detail pane is showing.
        e.stopPropagation();
        onToggle();
      }}
      className="rounded-full focus:ring-2 focus:ring-accent/40 focus:outline-none disabled:cursor-wait"
    >
      {body}
    </button>
  );
}

function FunctionRow({
  tool,
  server,
  selected,
  onSelect,
  onToggle,
  busy,
  flash,
  held
}: {
  tool: ToolProtection;
  server: ServerProtection | null;
  selected: boolean;
  onSelect: () => void;
  onToggle?: () => void;
  busy?: boolean;
  flash?: boolean;
  /** Shown only because it was switched here; it no longer matches the tab. */
  held?: boolean;
}) {
  const exposure = exposureOf(tool);
  const permission = PERMISSION[tool.effect] ?? { label: tool.effect, className: "text-ink" };
  const warn = exposure.kind === "review";
  const off = exposure.kind === "off";

  // A div rather than a button: the row carries the exposure switch, and a
  // button inside a button is not valid and does not reach the keyboard.
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect();
        }
      }}
      className={`relative grid w-full cursor-default grid-cols-[minmax(0,1fr)_170px_110px_132px] items-start gap-3 border-b px-7 py-3.5 text-left transition-[background-color,opacity] duration-300 focus:outline-none focus-visible:bg-accent/20 ${
        selected ? "bg-accent/20 hover:bg-accent/26" : "hover:bg-accent/10"
      } ${off ? "opacity-60" : ""} ${held ? "row-held border-dashed border-edge" : "border-edge"} ${
        flash === undefined ? "" : flash ? "row-flash-on" : "row-flash-off"
      }`}
    >
      {selected && <span className="bg-accent absolute inset-y-0 left-0 w-[3px]" aria-hidden />}

      <span className="min-w-0">
        <span className="flex items-center gap-1.5">
          <span className={`mono truncate text-sm font-semibold ${selected ? "text-accent-strong" : ""}`}>
            {tool.name}
          </span>
          {selected && <Icon name="external" size={12} className="text-accent" />}
        </span>
        <span className="mono mt-0.5 block truncate text-[0.8125rem] text-ink-soft">
          {signatureOf(tool)} <span className="text-ink-faint">→ {tool.method} {tool.path}</span>
        </span>
        <span className="mt-1 block truncate text-[0.8125rem] text-ink-soft">{tool.description}</span>
      </span>

      <span className="min-w-0 pt-0.5">
        <span className={`flex items-center gap-1.5 text-[0.8125rem] ${warn ? "text-write" : ""}`}>
          <Icon name={warn ? "alert" : "lock"} size={13} className={warn ? "" : "text-ink-faint"} />
          <span className="truncate">{authLabel(server)}</span>
        </span>
        <span className={`mono mt-0.5 block truncate text-xs ${warn ? "text-write" : "text-ink-faint"}`}>
          {off ? "exposure.disabled" : tool.unreachable ? "unreachable" : tool.review ? "unclassified" : tool.verdict.ruleId}
        </span>
      </span>

      <span className={`pt-0.5 text-[0.8125rem] font-medium ${permission.className}`}>{permission.label}</span>

      <span className="min-w-0 pt-0.5">
        <span className="flex items-center gap-2">
          <ExposureSwitch tool={tool} title={exposure.title} onToggle={onToggle} busy={busy} bloom={flash} />
          <span className={`truncate text-[0.8125rem] ${warn ? "text-write" : "text-ink-soft"}`}>
            {exposure.label}
          </span>
        </span>
        {held && (
          <span
            className="mt-0.5 block truncate text-[0.6875rem] text-ink-faint"
            title="Kept here so you can see what changed. It leaves this list when you pick another tab."
          >
            not in this tab any more
          </span>
        )}
      </span>
    </div>
  );
}

function FunctionDetail({
  serverId,
  server,
  fallback,
  onCollapse,
  exposure: control
}: {
  serverId: string;
  server: ServerProtection | null;
  fallback: ToolProtection;
  onCollapse: () => void;
  exposure: ExposureControl;
}) {
  const { data } = useResource(() => api.tool(serverId, fallback.name), [serverId, fallback.name]);
  // The list is reloaded after a toggle, so `fallback` carries the fresher
  // exposure state; this pane's own fetch is not repeated on every change.
  const tool = data ? { ...data, exposure: fallback.exposure } : fallback;
  const exposure = exposureOf(tool);
  const [tab, setTab] = useState<"configuration" | "schema" | "activity">("configuration");

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center justify-between border-b border-edge px-5 py-2.5">
        <span className="text-[0.8125rem] font-medium text-ink-soft">Function details</span>
        <button
          onClick={onCollapse}
          title="Hide function details"
          className="rounded-md p-1 text-ink-faint transition hover:bg-white/50 hover:text-ink"
        >
          <Icon name="collapse" size={16} />
        </button>
      </div>

      <div className="px-5 pt-4">
        <div className="flex items-start justify-between gap-3">
          <h2 className="mono text-[1.0625rem] font-semibold">{tool.name}</h2>
          <span
            className={`shrink-0 rounded-md px-2 py-0.5 text-xs font-medium ${
              exposure.kind === "exposed"
                ? "bg-accent-soft text-accent-strong"
                : exposure.kind === "review"
                  ? "bg-write/10 text-write"
                  : "bg-subtle text-ink-soft"
            }`}
          >
            {exposure.label}
          </span>
        </div>
        <p className="mt-1.5 text-[0.8125rem] leading-relaxed text-ink-soft">{tool.description}</p>
        <div className="mono mt-2 flex items-center gap-1.5 text-xs text-ink-soft">
          <Icon name="file" size={13} className="text-ink-faint" />
          <span className="truncate">
            {tool.method} {tool.path}
          </span>
        </div>
      </div>

      <div className="mt-3 flex gap-4 border-b border-edge px-5">
        {(["configuration", "schema", "activity"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`-mb-px border-b-2 py-2 text-[0.8125rem] font-medium capitalize transition ${
              tab === t ? "border-accent text-ink" : "border-transparent text-ink-soft hover:text-ink"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
        {tab === "configuration" && <ConfigurationTab tool={tool} server={server} exposure={control} />}
        {tab === "schema" && <SchemaTab tool={tool} />}
        {tab === "activity" && <ActivityTab tool={tool} />}
      </div>

      <div className="flex gap-2 border-t border-edge px-5 py-3">
        <CopySchema tool={tool} />
        <Button onClick={() => setTab("activity")}>
          <Icon name="clock" size={15} className="text-ink-soft" /> Recent calls
        </Button>
      </div>
    </div>
  );
}

function CopySchema({ tool }: { tool: ToolProtection }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      onClick={() => {
        void navigator.clipboard.writeText(JSON.stringify(tool.inputSchema ?? {}, null, 2));
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      }}
    >
      <Icon name={done ? "check" : "copy"} size={15} className="text-ink-soft" />
      {done ? "Copied" : "Copy schema"}
    </Button>
  );
}

function Section({
  icon,
  title,
  aside,
  children
}: {
  icon: string;
  title: string;
  aside?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section>
      <header className="mb-2.5 flex items-center gap-1.5">
        <Icon name={icon} size={15} className="text-ink-soft" />
        <h3 className="text-[0.8125rem] font-semibold">{title}</h3>
        {aside && <span className="ml-auto">{aside}</span>}
      </header>
      {children}
    </section>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 text-[0.8125rem]">
      <dt className="shrink-0 text-ink-soft">{label}</dt>
      <dd className="min-w-0 truncate text-right font-medium">{children}</dd>
    </div>
  );
}

function ConfigurationTab({
  tool,
  server,
  exposure: control
}: {
  tool: ToolProtection;
  server: ServerProtection | null;
  exposure: ExposureControl;
}) {
  const exposure = exposureOf(tool);
  const permission = PERMISSION[tool.effect] ?? { label: tool.effect, className: "text-ink" };
  const audit = server?.audit;

  return (
    <div className="space-y-5">
      {tool.review && (
        <Banner tone="warn">
          <strong>The generator could not classify this safely.</strong> {tool.review}
        </Banner>
      )}
      {tool.unreachable && !tool.exposure.disabled && (
        <Banner tone="warn">
          Advertised to the model but it can never run: it needs approval, and approvals are disabled.
        </Banner>
      )}
      {tool.exposure.disabled && (
        <Banner tone="warn">
          <strong>Switched off in this console.</strong> It is not advertised to the model and every call to it is
          refused{tool.exposure.setBy ? `, since ${tool.exposure.setBy} switched it off` : ""}
          {tool.exposure.setAt ? ` ${relativeTime(tool.exposure.setAt)}` : ""}.{" "}
          {tool.exposure.reason || null} Policy was not edited — <Mono>policy.yaml</Mono> still says{" "}
          <Mono>{tool.verdict.ruleId}</Mono>.
        </Banner>
      )}

      <section>
        <div className="flex items-center gap-2">
          <Icon name="plug" size={15} className="text-ink-soft" />
          <span className="text-[0.8125rem] font-semibold">Exposed as MCP tool</span>
          <span className="ml-auto">
            <ExposureSwitch
              tool={tool}
              title={exposure.title}
              onToggle={control.onToggle(tool)}
              busy={control.busy(tool)}
              bloom={control.flash(tool)}
            />
          </span>
        </div>
        <label className="mt-3 block text-xs text-ink-soft">Tool name</label>
        <input
          readOnly
          value={tool.name}
          className="mono mt-1 w-full rounded-lg border border-edge bg-white/50 px-3 py-2 text-[0.8125rem]"
        />
      </section>

      <Section icon="shield" title="Access policy">
        <dl className="space-y-2">
          <Row label="Authentication">{authLabel(server)}</Row>
          <Row label="Policy rule">
            <Mono>{tool.verdict.ruleId}</Mono>
          </Row>
          <Row label="Verdict">
            <span
              className={
                tool.verdict.kind === "allow"
                  ? "text-accent-strong"
                  : tool.verdict.kind === "approve"
                    ? "text-write"
                    : "text-deny"
              }
            >
              {tool.verdict.kind === "allow" ? "Allowed" : tool.verdict.kind === "approve" ? "Needs approval" : "Refused"}
            </span>
          </Row>
          <Row label="Permission">
            <span className={permission.className}>{permission.label}</span>
          </Row>
          {tool.reclassifiedTo && (
            <Row label="Reclassified">
              <span className="text-write">
                built {tool.effect}, treated {tool.reclassifiedTo}
              </span>
            </Row>
          )}
          <Row label="Tenant isolation">
            {tool.tenantParams.length > 0 ? (
              <span className="text-accent-strong">Enforced</span>
            ) : (
              <span className="text-ink-soft">Not configured</span>
            )}
          </Row>
        </dl>
        <p className="mt-2 flex items-start gap-1.5 text-xs text-ink-soft" title={tool.verdictStage}>
          <span aria-hidden>↳</span> {tool.verdict.reason}
        </p>
      </Section>

      <Section
        icon="braces"
        title="Input validation"
        aside={
          <span
            className={`rounded-md px-2 py-0.5 text-xs font-medium ${
              tool.schemaClosed ? "bg-accent-soft text-accent-strong" : "bg-write/10 text-write"
            }`}
          >
            {tool.schemaClosed ? "Strict" : "Open"}
          </span>
        }
      >
        <div className="rounded-lg border border-edge bg-white/45 px-3 py-2.5">
          {tool.args.length === 0 ? (
            <p className="mono text-xs text-ink-soft">no arguments</p>
          ) : (
            tool.args.map((arg) => (
              <p key={arg.name} className="mono text-xs">
                {arg.name} <span className="text-ink-soft">{arg.type ?? "any"}</span>{" "}
                <span className="text-ink-soft">{arg.required ? "required" : "optional"}</span>
              </p>
            ))
          )}
          <p className="mono mt-1.5 text-[0.6875rem] text-ink-faint">
            additionalProperties: {String(!tool.schemaClosed)}
            {tool.paginationCap && ` · ${tool.paginationCap.param} ≤ ${tool.paginationCap.max}`}
          </p>
        </div>
        <p className="mt-2 flex items-start gap-1.5 text-xs text-ink-soft">
          <Icon
            name={tool.schemaClosed ? "check" : "alert"}
            size={13}
            className={`mt-0.5 ${tool.schemaClosed ? "text-accent" : "text-write"}`}
          />
          {tool.schemaClosed
            ? "An argument the schema does not name is rejected, not silently dropped."
            : "This schema accepts undeclared arguments."}
        </p>
      </Section>

      <Section icon="timer" title="Runtime safeguards">
        <dl className="space-y-2">
          <Row label="Upstream timeout">
            {server ? <span className="mono">{server.egress.timeoutMs.toLocaleString()} ms</span> : "—"}
          </Row>
          <Row label="Response cap">
            {server ? <span className="mono">{bytes(server.egress.maxBodyBytes)}</span> : "—"}
          </Row>
          <Row label="Pagination cap">
            {tool.paginationCap ? (
              <span className="mono">
                {tool.paginationCap.param} ≤ {tool.paginationCap.max}
              </span>
            ) : (
              <span className="text-ink-soft">None</span>
            )}
          </Row>
          <Row label="Audit logging">
            {audit?.enabled ? (
              <span className="text-accent-strong">
                Enabled{audit.redact.length > 0 ? " · redacted" : ""}
              </span>
            ) : (
              <span className="text-write">Disabled</span>
            )}
          </Row>
        </dl>
      </Section>

      {tool.withheldParams.length > 0 && (
        <Section icon="lock" title="Withheld from the model">
          <ul className="space-y-1.5 text-[0.8125rem]">
            {tool.withheldParams.map((p) => (
              <li key={`${p.in}:${p.name}`} className="flex flex-wrap items-baseline gap-1.5">
                <span className="mono">{p.name}</span>
                {p.in && <Tag>{p.in}</Tag>}
                <span className="text-ink-soft">{p.reason}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {tool.tenantParams.length > 0 && (
        <Section icon="shield-check" title="Tenant scoping">
          <ul className="space-y-1 text-[0.8125rem] text-ink-soft">
            {tool.tenantParams.map((t) => (
              <li key={t.param}>
                <span className="mono text-ink">{t.param}</span> is injected into {t.injectedInto.join(", ")} after the
                model's arguments are placed, so an argument cannot overwrite it.
              </li>
            ))}
          </ul>
        </Section>
      )}

      {tool.standingGrants.length > 0 && (
        <Section icon="check-circle" title="Standing grants">
          <ul className="space-y-1.5 text-[0.8125rem]">
            {tool.standingGrants.map((g) => (
              <li key={g.grantId} className="flex flex-wrap items-baseline gap-1.5">
                <Mono>{g.grantId}</Mono>
                {g.covers ? (
                  <Tag title={g.why}>covers this function</Tag>
                ) : (
                  <span className="text-xs text-ink-soft">does not apply — {g.why}</span>
                )}
                <span className="text-xs text-ink-faint">
                  {g.uses}/{g.maxUses ?? "∞"} uses, expires {relativeTime(g.expiresAt)}
                </span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {tool.findings.length > 0 && (
        <Section icon="alert" title="Scanner findings">
          <ul className="space-y-2.5">
            {tool.findings.map((f, i) => (
              <li key={i} className="text-[0.8125rem]">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <Mono>{f.ruleId}</Mono>
                  <span className="font-medium">{f.title}</span>
                </div>
                <p className="mt-0.5 text-ink-soft">{f.message}</p>
                <p className="mt-0.5 text-xs text-ink-faint">Fix: {f.fix}</p>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}

function SchemaTab({ tool }: { tool: ToolProtection }) {
  return (
    <div className="space-y-5">
      <Section icon="braces" title="Arguments the model may supply">
        {tool.args.length === 0 ? (
          <Empty>This function takes no arguments.</Empty>
        ) : (
          <table className="w-full text-left text-[0.8125rem]">
            <thead className="text-xs text-ink-faint">
              <tr>
                <th className="py-1 pr-3 font-medium">Name</th>
                <th className="py-1 pr-3 font-medium">Type</th>
                <th className="py-1 font-medium">Lands upstream as</th>
              </tr>
            </thead>
            <tbody>
              {tool.args.map((arg) => (
                <tr key={arg.name} className="border-t border-edge align-top">
                  <td className="py-1.5 pr-3">
                    <span className="mono">{arg.name}</span>
                    {arg.required && <span className="ml-1 text-xs text-ink-faint">required</span>}
                  </td>
                  <td className="py-1.5 pr-3 text-ink-soft">{arg.type ?? "—"}</td>
                  <td className="py-1.5">
                    {arg.binding ? (
                      <span className="mono text-xs">
                        {arg.binding.in}.{arg.binding.name}
                      </span>
                    ) : (
                      "—"
                    )}
                    {arg.renamed && (
                      <Tag title={`The model sees "${arg.name}"; upstream receives "${arg.binding!.name}".`}>
                        renamed
                      </Tag>
                    )}
                    {arg.constrainedByRule && <Tag>bounded by {arg.constrainedByRule}</Tag>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section icon="file" title="MCP annotations">
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(tool.annotations).filter(([, v]) => v).length === 0 ? (
            <span className="text-[0.8125rem] text-ink-soft">none</span>
          ) : (
            Object.entries(tool.annotations)
              .filter(([, v]) => v)
              .map(([k]) => <Tag key={k}>{k}</Tag>)
          )}
          {tool.source?.operationId && <Tag title="Operation id in the spec">{tool.source.operationId}</Tag>}
          {tool.source?.deprecated && <Tag>deprecated in the spec</Tag>}
        </div>
      </Section>

      {tool.inputSchema !== undefined && tool.inputSchema !== null && (
        <Section icon="braces" title="The schema the model receives">
          <RedactedArgs args={tool.inputSchema} />
        </Section>
      )}
    </div>
  );
}

function ActivityTab({ tool }: { tool: ToolProtection }) {
  if (!tool.activity || tool.activity.length === 0) {
    return <Empty>No recorded calls to this function yet.</Empty>;
  }
  return (
    <ul className="space-y-2">
      {tool.activity.map((r) => (
        <li key={r.id} className="rounded-lg border border-edge px-3 py-2 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono text-ink-soft">{r.ts}</span>
            <VerdictBadge kind={r.decision} />
          </div>
          <p className="mt-1 text-[0.8125rem]">{r.outcome}</p>
          <p className="text-ink-soft">{r.reason}</p>
        </li>
      ))}
    </ul>
  );
}
