import { useState } from "react";
import { api, type AuditRecord } from "../api";
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
  VerdictBadge,
  useResource
} from "../components";

/**
 * Part 5: the audit log.
 *
 * Reads are bounded and newest-first, so a long log costs the same as a short
 * one. Administrative records — a pre-approval created or revoked, an approval
 * decided in this console — appear here alongside tool calls, which is the
 * point: a decision to stop reviewing something is itself an event worth
 * recording.
 */
export function Audit({ serverId }: { serverId: string }) {
  const [filters, setFilters] = useState({ decision: "", outcome: "", tool: "", noteworthy: false });
  const [cursor, setCursor] = useState<number | undefined>();
  const [pages, setPages] = useState<AuditRecord[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);

  const params: Record<string, string> = { limit: "50" };
  if (filters.decision) params["decision"] = filters.decision;
  if (filters.outcome) params["outcome"] = filters.outcome;
  if (filters.tool) params["tool"] = filters.tool;
  if (filters.noteworthy) params["noteworthy"] = "1";
  if (cursor !== undefined) params["cursor"] = String(cursor);

  const page = useResource(() => api.audit(serverId, params), [serverId, JSON.stringify(params)]);
  const verify = useResource(() => api.verify(serverId), [serverId]);

  // Paging appends; changing a filter starts over.
  const records = cursor === undefined ? (page.data?.records ?? []) : [...pages, ...(page.data?.records ?? [])];

  function changeFilter(patch: Partial<typeof filters>) {
    setFilters({ ...filters, ...patch });
    setCursor(undefined);
    setPages([]);
  }

  return (
    <div className="space-y-4">
      {verify.data && (
        <Banner tone={verify.data.ok ? "ok" : "bad"}>
          {verify.data.ok ? (
            <>
              The hash chain verifies across {verify.data.count} record(s): nothing has been edited, removed
              or reordered.
            </>
          ) : (
            <>
              <strong>The chain does not verify.</strong>{" "}
              {verify.data.problems.slice(0, 3).map((p) => `line ${p.line}: ${p.message}`).join("; ")}
              {verify.data.problems.length > 3 && ` …and ${verify.data.problems.length - 3} more`}
            </>
          )}
        </Banner>
      )}

      {page.data && page.data.malformed > 0 && (
        <Banner tone="warn">
          {page.data.malformed} line(s) in this window could not be parsed. They are skipped rather than
          hidden; <Mono>hmcp audit verify</Mono> reports where they are.
        </Banner>
      )}

      <Panel title="Filter">
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={filters.tool}
            onChange={(e) => changeFilter({ tool: e.target.value })}
            placeholder="Tool glob, e.g. create_*"
            className="mono min-w-44 flex-1 rounded-md border border-edge bg-surface px-2 py-1.5 text-sm"
          />
          <select
            value={filters.decision}
            onChange={(e) => changeFilter({ decision: e.target.value })}
            className="rounded-md border border-edge bg-surface px-2 py-1.5 text-sm"
          >
            <option value="">any decision</option>
            <option value="allow">allowed</option>
            <option value="approve">approved</option>
            <option value="deny">denied</option>
          </select>
          <select
            value={filters.outcome}
            onChange={(e) => changeFilter({ outcome: e.target.value })}
            className="rounded-md border border-edge bg-surface px-2 py-1.5 text-sm"
          >
            <option value="">any outcome</option>
            <option value="completed">completed</option>
            <option value="denied">denied</option>
            <option value="pending-approval">held for approval</option>
            <option value="error">error</option>
          </select>
          <label className="flex items-center gap-1.5 text-sm">
            <input
              type="checkbox"
              checked={filters.noteworthy}
              onChange={(e) => changeFilter({ noteworthy: e.target.checked })}
            />
            only refused or incomplete
          </label>
          <Button onClick={page.reload}>Refresh</Button>
        </div>
      </Panel>

      {page.error && <Banner tone="bad">{page.error}</Banner>}

      {records.length === 0 ? (
        <Empty>{page.loading ? "Reading the log…" : "No record matches that filter."}</Empty>
      ) : (
        <Panel title={`${records.length} record(s)`} subtitle={page.data?.auditPath}>
          <div className="space-y-1">
            {records.map((r) => (
              <div key={r.id} className="rounded-md border border-edge">
                <button
                  onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                  className="flex w-full flex-wrap items-center gap-2 px-3 py-2 text-left"
                >
                  <span className="mono text-xs text-ink-soft">{r.ts.replace("T", " ").slice(0, 19)}</span>
                  <VerdictBadge kind={r.decision} />
                  <span className="mono text-sm">{r.tool}</span>
                  {r.effect && <EffectBadge effect={r.effect} />}
                  <Tag>{r.outcome}</Tag>
                  {r.grant_id && <Tag title="Released by a standing pre-approval">pre-approved</Tag>}
                  <span className="mono ml-auto text-xs text-ink-soft">{r.rule_id}</span>
                </button>

                {expanded === r.id && (
                  <div className="space-y-3 border-t border-edge px-3 py-2.5">
                    <dl className="grid gap-2 sm:grid-cols-2">
                      <Field label="Reason">{r.reason || "—"}</Field>
                      <Field label="Actor">{r.actor}</Field>
                      <Field label="Component">{r.component}</Field>
                      <Field label="Sequence">#{r.seq}</Field>
                      {r.tenant && <Field label="Tenant">{r.tenant}</Field>}
                      {r.approval_id && (
                        <Field label="Approval">
                          <Mono>{r.approval_id}</Mono>
                        </Field>
                      )}
                      {r.grant_id && (
                        <Field label="Standing grant">
                          <Mono>{r.grant_id}</Mono>
                        </Field>
                      )}
                      {r.duration_ms !== null && <Field label="Took">{r.duration_ms} ms</Field>}
                      {r.error && <Field label="Error">{r.error}</Field>}
                    </dl>

                    {r.upstream && (
                      <Field label="Upstream">
                        <span className="mono text-xs">
                          {r.upstream.method} {r.upstream.host}
                          {r.upstream.path} → {r.upstream.status ?? "—"}
                        </span>
                      </Field>
                    )}

                    <div>
                      <p className="mb-1 text-xs text-ink-soft">Arguments, as recorded</p>
                      <RedactedArgs args={r.args_redacted} />
                    </div>

                    <details>
                      <summary className="cursor-pointer text-xs text-ink-soft">Chain</summary>
                      <dl className="mt-1.5 space-y-1 text-xs">
                        <Field label="This record">
                          <span className="mono break-all">{r.hash}</span>
                        </Field>
                        <Field label="Commits to">
                          <span className="mono break-all">{r.prev_hash}</span>
                        </Field>
                        <Field label="Arguments hash">
                          <span className="mono break-all">{r.args_hash}</span>
                        </Field>
                      </dl>
                    </details>
                  </div>
                )}
              </div>
            ))}
          </div>

          {page.data?.nextCursor !== null && page.data?.nextCursor !== undefined && (
            <div className="mt-3 flex items-center gap-3">
              <Button
                onClick={() => {
                  setPages(records);
                  setCursor(page.data!.nextCursor!);
                }}
              >
                Load older
              </Button>
              <span className="text-xs text-ink-soft">Scanned {page.data.scanned} line(s) for this page.</span>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}
