import { useState } from "react";
import { api, ApiError, type Approval } from "../api";
import {
  Banner,
  Button,
  EffectBadge,
  Empty,
  Field,
  Mono,
  Panel,
  RedactedArgs,
  Tag,
  relativeTime,
  useResource
} from "../components";

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
      {failure && <Banner tone="bad">{failure}</Banner>}
      {pending.error && <Banner tone="bad">{pending.error}</Banner>}

      <Panel
        title={`${pending.data?.length ?? 0} call(s) waiting for a human`}
        subtitle="Each approval is bound to these exact arguments and expires on its own."
        actions={<Button onClick={pending.reload}>Refresh</Button>}
      >
        {!pending.data || pending.data.length === 0 ? (
          <Empty>Nothing is waiting. Calls that need approval will appear here.</Empty>
        ) : (
          <div className="space-y-3">
            {pending.data.map((row) => (
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

      <Panel title="Decided earlier" subtitle="Includes calls released by a standing grant, which are recorded as already spent.">
        {!history.data || history.data.length === 0 ? (
          <Empty>No approval history yet.</Empty>
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
              {history.data.map((row) => (
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

function StateTag({ row }: { row: Approval }) {
  const standing = row.decidedBy?.startsWith("standing-grant:");
  if (standing) {
    return <Tag title={`Released without asking, by ${row.decidedBy}.`}>released by a standing grant</Tag>;
  }
  return <Tag>{row.state}</Tag>;
}
