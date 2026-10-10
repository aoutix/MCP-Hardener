import { useMemo, useState } from "react";
import { api, ApiError, type Approval } from "../api";
import {
  Banner,
  Button,
  EffectBadge,
  Empty,
  Field,
  Hint,
  Icon,
  Mono,
  Panel,
  RedactedArgs,
  Tag,
  relativeTime,
  useResource
} from "../components";

type Order = "newest" | "oldest";

/**
 * Search and time order are applied to the waiting queue and to the history
 * together, because the question being asked is about a function ("what has
 * `create_invoice` been doing?") and that function appears in both lists.
 *
 * Both sort on `createdAt` — when the agent asked — rather than on the decision
 * time, so a row does not move when somebody decides it, and so the order
 * matches the timestamp each list actually displays.
 */
function arrange(rows: readonly Approval[] | null, query: string, order: Order): Approval[] {
  const needle = query.trim().toLowerCase();
  const matched = needle
    ? rows?.filter((r) => `${r.tool} ${r.reason} ${r.actor} ${r.id}`.toLowerCase().includes(needle))
    : rows;
  return [...(matched ?? [])].sort((a, b) => (order === "newest" ? b.createdAt - a.createdAt : a.createdAt - b.createdAt));
}

/**
 * Part 2: calls an agent made that policy routed to a human.
 *
 * A grant is bound to the exact arguments shown here, so approving is a
 * decision about this call and not about the tool in general. Polled at 2s
 * because somebody is waiting on the other end.
 */
export function Approvals({ serverId }: { serverId: string }) {
  const pending = useResource(() => api.pending(serverId), [serverId], 2000);
  const history = useResource(() => api.approvals(serverId), [serverId], 15000);
  const [busy, setBusy] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [order, setOrder] = useState<Order>("newest");

  const waiting = useMemo(() => arrange(pending.data, query, order), [pending.data, query, order]);
  const decided = useMemo(() => arrange(history.data, query, order), [history.data, query, order]);
  const searching = query.trim().length > 0;

  async function decide(id: string, state: "granted" | "denied") {
    setBusy(id);
    setFailure(null);
    try {
      await api.decide(serverId, id, state, notes[id] ?? "");
      pending.reload();
      history.reload();
    } catch (err) {
      // The server's message is the truth here: the request may have expired
      // or been decided by someone else between render and click.
      setFailure(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-[1.75rem] font-semibold tracking-tight">Approvals</h1>
        <p className="mt-1 text-sm text-ink-soft">
          Calls the policy held back for a human. Each decision covers one call, not the function behind it.
        </p>

        <div className="mt-5 flex flex-wrap items-center gap-2.5">
          {/* The frost, the lit edge and the hover lift all live on the wrapper
              rather than on the input, so the magnifier and the clear button
              rise with the field instead of staying behind on the page. */}
          <div className="glass-control relative min-w-56 flex-1 rounded-xl">
            <Icon name="search" size={15} className="absolute top-1/2 left-3 -translate-y-1/2 text-ink-faint" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by function, reason, caller or request id…"
              aria-label="Search approvals"
              className="w-full bg-transparent py-2.5 pr-9 pl-9 text-sm placeholder:text-ink-faint focus:outline-none"
            />
            {searching && (
              <Hint label="Clear the search and show every approval again">
                <button
                  onClick={() => setQuery("")}
                  aria-label="Clear the search"
                  className="absolute top-1/2 right-2.5 -translate-y-1/2 rounded p-0.5 text-ink-faint transition hover:text-ink"
                >
                  <Icon name="close" size={14} />
                </button>
              </Hint>
            )}
          </div>

          <SortBadge order={order} onToggle={() => setOrder(order === "newest" ? "oldest" : "newest")} />
        </div>
      </header>

      {failure && <Banner tone="bad">{failure}</Banner>}
      {pending.error && <Banner tone="bad">{pending.error}</Banner>}

      <Panel
        title={
          searching
            ? `${waiting.length} of ${pending.data?.length ?? 0} call(s) waiting for a human`
            : `${pending.data?.length ?? 0} call(s) waiting for a human`
        }
        subtitle="Each approval is bound to these exact arguments and expires on its own."
        actions={<Button onClick={pending.reload}>Refresh</Button>}
      >
        {waiting.length === 0 ? (
          <Empty>
            {searching
              ? "No waiting call matches that search."
              : "Nothing is waiting. Calls that need approval will appear here."}
          </Empty>
        ) : (
          <div className="space-y-3">
            {waiting.map((row) => (
              <article key={row.id} className="rounded-lg border border-edge bg-surface p-3">
                <header className="flex flex-wrap items-center gap-2">
                  <span className="mono text-sm font-semibold">{row.tool}</span>
                  {row.effect && <EffectBadge effect={row.effect} />}
                  <Mono>{row.id}</Mono>
                  <span className="ml-auto text-xs text-ink-soft">
                    asked {relativeTime(row.createdAt)} · expires {relativeTime(row.expiresAt)}
                  </span>
                </header>

                <dl className="mt-2 grid gap-2 sm:grid-cols-2">
                  <Field label="Why it was held">{row.reason}</Field>
                  <Field label="Asked by">
                    {row.actor} <span className="text-xs text-ink-soft">session {row.session}</span>
                  </Field>
                </dl>

                <div className="mt-2">
                  <p className="mb-1 text-xs text-ink-soft">
                    Arguments, as recorded. Approving releases exactly these and nothing else.
                  </p>
                  <RedactedArgs args={row.args} error={row.argsError} />
                </div>

                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <input
                    value={notes[row.id] ?? ""}
                    onChange={(e) => setNotes({ ...notes, [row.id]: e.target.value })}
                    placeholder="Note for the audit log (optional)"
                    className="min-w-48 flex-1 rounded-md border border-edge bg-panel px-2 py-1.5 text-sm"
                  />
                  <Button tone="approve" disabled={busy === row.id} onClick={() => decide(row.id, "granted")}>
                    Approve
                  </Button>
                  <Button tone="deny" disabled={busy === row.id} onClick={() => decide(row.id, "denied")}>
                    Deny
                  </Button>
                </div>
              </article>
            ))}
          </div>
        )}
      </Panel>

      <Panel
        title={searching ? `Decided earlier · ${decided.length} of ${history.data?.length ?? 0}` : "Decided earlier"}
        subtitle="Includes calls released by a standing grant, which are recorded as already spent."
      >
        {decided.length === 0 ? (
          <Empty>{searching ? "No decided call matches that search." : "No approval history yet."}</Empty>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-xs text-ink-soft">
              <tr>
                <th className="py-1 pr-3 font-medium">Tool</th>
                <th className="py-1 pr-3 font-medium">State</th>
                <th className="py-1 pr-3 font-medium">Decided by</th>
                <th className="py-1 font-medium">When</th>
              </tr>
            </thead>
            <tbody>
              {decided.map((row) => (
                <tr key={row.id} className="border-t border-edge/60">
                  <td className="py-1.5 pr-3">
                    <span className="mono">{row.tool}</span>
                  </td>
                  <td className="py-1.5 pr-3">
                    <StateTag row={row} />
                  </td>
                  <td className="py-1.5 pr-3 text-ink-soft">{row.decidedBy ?? "—"}</td>
                  <td className="py-1.5 text-xs text-ink-soft">{relativeTime(row.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

const ORDERS: Record<Order, { icon: string; label: string; title: string }> = {
  newest: {
    icon: "arrow-down",
    label: "Newest first",
    title: "Sorted by newest first — the call that came in most recently is at the top. Click to sort by oldest."
  },
  oldest: {
    icon: "arrow-up",
    label: "Oldest first",
    title: "Sorted by oldest first — the call that has been waiting longest is at the top. Click to sort by newest."
  }
};

/**
 * One button carrying the order in force. The face names the current state and
 * the tooltip names what a click does, so neither has to carry both meanings.
 */
function SortBadge({ order, onToggle }: { order: Order; onToggle: () => void }) {
  const info = ORDERS[order];
  return (
    <button
      type="button"
      onClick={onToggle}
      /* No hover bubble: the face already names the order, and the arrow says
         which way. The sentence stays as the accessible name, where it is read
         on demand rather than drawn over the page. */
      aria-label={info.title}
      className="glass-control flex items-center gap-1.5 rounded-xl px-3 py-2.5 text-[0.8125rem] whitespace-nowrap text-ink-soft hover:text-ink"
    >
      <Icon name={info.icon} size={14} />
      {info.label}
    </button>
  );
}

function StateTag({ row }: { row: Approval }) {
  const standing = row.decidedBy?.startsWith("standing-grant:");
  if (standing) {
    return <Tag title={`Released without asking, by ${row.decidedBy}.`}>released by a standing grant</Tag>;
  }
  return <Tag>{row.state}</Tag>;
}
