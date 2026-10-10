import { randomBytes } from "node:crypto";
import {
  AuditLog,
  MAX_GRANT_TTL_SECONDS,
  grantMatches,
  parseExposureChange,
  parseGrantDraft,
  queryAuditLog,
  readRegistry,
  verifyAuditLog,
  writeRegistry,
  type ApprovalRow,
  type AuditRecord,
  type DecisionKind,
  type Registry,
  type RegistryEntry,
  type StandingGrantRow
} from "@hmcp/core";
import { badRequest, conflict, notFound, route, unprocessable, type Route } from "./http.js";
import { buildProtection, effectiveReach, recentActivity, toolProtection } from "./model/protection.js";
import { invalidateScan, runScan } from "./model/scan.js";
import { loadServer, scopeOf, scopedFor, storeFor, type LoadedServer } from "./model/server.js";
import { ENFORCEMENT_PIPELINE } from "./model/pipeline.js";

export interface ApiOptions {
  readonly registryPath: string;
}

/* ------------------------------------------------------------------ helpers */

function registry(options: ApiOptions): Registry {
  return readRegistry(options.registryPath);
}

function entryById(options: ApiOptions, id: string): RegistryEntry {
  const found = registry(options).servers.find((s) => s.id === id);
  if (!found) throw notFound(`no registered server with id "${id}"`);
  return found;
}

function serverById(options: ApiOptions, id: string): LoadedServer {
  try {
    return loadServer(entryById(options, id));
  } catch (err) {
    if ((err as { status?: number }).status) throw err;
    throw unprocessable(`server "${id}" could not be loaded: ${(err as Error).message}`);
  }
}

/** An audit log scoped to one server's own configuration. */
function auditFor(server: LoadedServer, actor: string): AuditLog {
  return new AuditLog({
    config: server.policy.audit,
    actor,
    component: "hmcp-web",
    cwd: server.cwd
  });
}

/** Arguments reach the console already redacted; this only decodes them. */
function parseArgs(row: ApprovalRow): { args: unknown; argsError: string | null } {
  try {
    return { args: JSON.parse(row.args_redacted), argsError: null };
  } catch {
    return { args: row.args_redacted, argsError: "stored arguments are not valid JSON" };
  }
}

function approvalDto(row: ApprovalRow) {
  const { args, argsError } = parseArgs(row);
  return {
    id: row.id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    tool: row.tool,
    effect: row.effect,
    reason: row.reason,
    actor: row.actor,
    session: row.session,
    state: row.state,
    decidedAt: row.decided_at,
    decidedBy: row.decided_by,
    decisionNote: row.decision_note,
    bindingHash: row.binding_hash,
    args,
    argsError
  };
}

function grantDto(row: StandingGrantRow) {
  let constraints: unknown = {};
  try {
    constraints = JSON.parse(row.constraints);
  } catch {
    constraints = {};
  }
  return {
    id: row.id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    toolMatch: row.tool_match,
    effect: row.effect,
    constraints,
    maxUses: row.max_uses,
    uses: row.uses,
    reason: row.reason,
    createdBy: row.created_by,
    state: row.state,
    revokedAt: row.revoked_at,
    revokedBy: row.revoked_by
  };
}

function csv(query: URLSearchParams, key: string): string[] | undefined {
  const raw = query.get(key);
  if (!raw) return undefined;
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function intParam(query: URLSearchParams, key: string): number | undefined {
  const raw = query.get(key);
  if (raw === null) return undefined;
  const value = Number(raw);
  if (!Number.isFinite(value)) throw badRequest(`${key} must be a number`);
  return value;
}

/* ------------------------------------------------------------------- routes */

export function buildRoutes(options: ApiOptions): Route[] {
  return [
    route("GET", "/api/v1/health", () => ({ ok: true, pipelineSteps: ENFORCEMENT_PIPELINE.length })),

    /**
     * The redaction legend. The UI explains markers rather than printing them,
     * and the patterns live in core, so they are served rather than duplicated.
     */
    route("GET", "/api/v1/meta/redaction", () => ({
      markers: [
        { marker: "[redacted:key]", meaning: "the argument's name looked like a secret" },
        { marker: "[redacted:<pattern>]", meaning: "the value matched a known credential shape" },
        { marker: "[redacted:circular]", meaning: "the value referred back to itself" },
        { marker: "[redacted:max-depth]", meaning: "nested deeper than the redactor follows" },
        { marker: "…[truncated N chars]", meaning: "a long string was cut short" },
        { marker: "[truncated N items]", meaning: "a long array was cut short" }
      ],
      note:
        "Names are redacted by name, not by content, so a value may be harmless and still hidden. " +
        "An argument called `session` is redacted for this reason. The original values were never " +
        "written to disk, so nothing here can be un-redacted.",
      grantTtlMaxSeconds: MAX_GRANT_TTL_SECONDS
    })),

    /* servers */

    route("GET", "/api/v1/servers", () =>
      registry(options).servers.map((entry) => {
        try {
          const server = loadServer(entry);
          const scan = runScan(server);
          return {
            id: entry.id,
            kind: entry.kind,
            label: entry.label,
            ok: true,
            component: server.component,
            api: server.tools ? { title: server.tools.api.title, baseUrl: server.tools.api.base_url } : null,
            toolCount: server.tools?.tools.length ?? null,
            posture: server.policy.defaults.mode,
            reach: effectiveReach(server),
            auditPath: server.auditPath,
            storePath: server.storePath,
            tenantError: server.tenantError,
            counts: scan.counts,
            scanOk: scan.ok
          };
        } catch (err) {
          // A broken entry is listed with its error. Failing the whole list
          // would hide every working server behind one bad path.
          return { id: entry.id, kind: entry.kind, label: entry.label, ok: false, error: (err as Error).message };
        }
      })
    ),

    route("POST", "/api/v1/servers", (ctx) => {
      const body = (ctx.body ?? {}) as Record<string, unknown>;
      const reg = registry(options);
      const id = typeof body["id"] === "string" && body["id"] ? body["id"] : `srv_${randomBytes(3).toString("hex")}`;
      if (reg.servers.some((s) => s.id === id)) throw conflict(`a server with id "${id}" is already registered`);

      const entry = { ...body, id, added_at: new Date().toISOString() } as RegistryEntry;
      // Probe before persisting, so the registry cannot hold an entry that
      // never loads. A gateway probe stops at the config: registering a server
      // must not spawn its upstream child processes.
      let loaded: LoadedServer;
      try {
        loaded = loadServer(entry);
      } catch (err) {
        throw unprocessable(`that server could not be loaded: ${(err as Error).message}`);
      }
      writeRegistry({ ...reg, servers: [...reg.servers, entry] }, options.registryPath);
      return { id, component: loaded.component };
    }),

    route("DELETE", "/api/v1/servers/:id", (ctx) => {
      const reg = registry(options);
      const id = ctx.params["id"]!;
      if (!reg.servers.some((s) => s.id === id)) throw notFound(`no registered server with id "${id}"`);
      // Only the registry entry is removed; the referenced files are never touched.
      writeRegistry({ ...reg, servers: reg.servers.filter((s) => s.id !== id) }, options.registryPath);
      invalidateScan(id);
      return { removed: id };
    }),

    /* tools and protection */

    route("GET", "/api/v1/servers/:id/protection", (ctx) => buildProtection(serverById(options, ctx.params["id"]!))),

    route("GET", "/api/v1/servers/:id/tools", (ctx) => {
      const protection = buildProtection(serverById(options, ctx.params["id"]!));
      return protection.tools;
    }),

    route("GET", "/api/v1/servers/:id/tools/:tool", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      const name = ctx.params["tool"]!;
      const tool = buildProtection(server).tools.find((t) => t.name === name);
      if (!tool) throw notFound(`no tool "${name}" on server "${server.entry.id}"`);
      const descriptor = server.tools?.tools.find((t) => t.name === name);
      return { ...tool, inputSchema: descriptor?.inputSchema ?? null, activity: recentActivity(server, name) };
    }),

    /**
     * The exposure switch: take one tool off the model's menu, or hand it back
     * to policy.
     *
     * This is the one mutation the console makes to what a server exposes, and
     * it is deliberately one-directional in effect. Switching a tool off
     * refuses it before anything else is weighed and hides it from
     * `tools/list`. Switching it back on only *deletes* that row: the tool
     * returns to whatever `policy.yaml` already said, which may still be deny
     * or approve. Nothing stored here can release a call `decide()` refuses, so
     * the console still cannot widen a policy — which is why it may do this at
     * all without writing to `policy.yaml`.
     */
    route("PUT", "/api/v1/servers/:id/tools/:tool/exposure", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      const name = ctx.params["tool"]!;

      // A gateway's surface is its upstreams' and is discovered at connect
      // time; there is no curated descriptor list here to switch a tool off in.
      if (!server.tools) {
        throw unprocessable(
          `"${server.entry.id}" is a gateway, whose tool surface comes from its upstreams; ` +
            "exposure overrides apply to generated servers"
        );
      }
      const descriptor = server.tools.tools.find((t) => t.name === name);
      if (!descriptor) throw notFound(`no tool "${name}" on server "${server.entry.id}"`);

      const body = (ctx.body ?? {}) as Record<string, unknown>;
      let change;
      try {
        change = parseExposureChange({ tool: name, disabled: body["disabled"], reason: body["reason"] ?? "" });
      } catch (err) {
        throw unprocessable(`invalid exposure change: ${(err as Error).message}`);
      }

      const scoped = scopedFor(server);
      const before = scoped.toolExposure(name);
      let warning: string | null = null;

      if (change.disabled) {
        const row = scoped.disableTool(name, ctx.actor, change.reason);
        // Switching a tool off only ever tightens, so — as with revoking a
        // standing grant — the change is kept even if the record cannot be
        // written, and the failure is reported rather than undoing the fix.
        try {
          auditFor(server, ctx.actor).appendStrict({
            tool: name,
            effect: descriptor.effect,
            decision: "deny",
            rule_id: "exposure.disable",
            reason:
              `${name} switched off in the console by ${ctx.actor}` +
              (change.reason ? `: ${change.reason}` : "") +
              "; it is no longer advertised to the model and every call to it is refused",
            outcome: "completed",
            args_redacted: { tool: name, effect: descriptor.effect, reason: row.reason }
          });
        } catch (err) {
          warning = `${name} was switched off but the audit record failed: ${(err as Error).message}`;
        }
      } else {
        const removed = scoped.enableTool(name);
        // Nothing was switched off, so nothing changed. Writing a record here
        // would put a permission change in the log that never happened.
        if (removed) {
          try {
            auditFor(server, ctx.actor).appendStrict({
              tool: name,
              effect: descriptor.effect,
              decision: "approve",
              rule_id: "exposure.enable",
              reason:
                `${name} switched back on in the console by ${ctx.actor} ` +
                `(switched off by ${removed.set_by} at ${new Date(removed.set_at).toISOString()}); ` +
                "policy decides it again from here",
              outcome: "completed",
              args_redacted: { tool: name, effect: descriptor.effect }
            });
          } catch (err) {
            // Unlike the other direction this one loosens, so an unauditable
            // change is put back rather than left in place unrecorded.
            scoped.disableTool(name, removed.set_by, removed.reason);
            throw new Error(
              `${name} was left switched off because switching it on could not be audited: ${(err as Error).message}`
            );
          }
        }
      }

      const scan = runScan(server);
      const tool = toolProtection(
        server,
        descriptor,
        scan.findings,
        scoped.listGrants({ activeOnly: true }),
        scoped.toolExposure(name)
      );
      return { tool, changed: (before !== undefined) !== change.disabled, warning };
    }),

    route("GET", "/api/v1/servers/:id/scan", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      if (ctx.query.get("refresh")) invalidateScan(server.entry.id);
      return runScan(server);
    }),

    /* approvals */

    route("GET", "/api/v1/servers/:id/approvals/pending", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      return scopedFor(server)
        .listPending(intParam(ctx.query, "limit") ?? 50)
        .map(approvalDto);
    }),

    route("GET", "/api/v1/servers/:id/approvals", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      return scopedFor(server)
        .list(intParam(ctx.query, "limit") ?? 50)
        .map(approvalDto);
    }),

    route("POST", "/api/v1/servers/:id/approvals/:aprId/decide", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      const body = (ctx.body ?? {}) as { state?: unknown; note?: unknown };
      if (body.state !== "granted" && body.state !== "denied") {
        throw badRequest('state must be "granted" or "denied"');
      }
      const note = typeof body.note === "string" ? body.note : "";
      const result = scopedFor(server).decideChecked(ctx.params["aprId"]!, body.state, ctx.actor, note);
      if (!result.ok) {
        throw result.error.includes("no approval request") ? notFound(result.error) : conflict(result.error);
      }

      // The CLI leaves no audit trace when a human approves; the console should
      // not inherit that gap. A decision is itself a security event.
      const { args } = parseArgs(result.row);
      auditFor(server, ctx.actor).append({
        tool: result.row.tool,
        effect: (result.row.effect as AuditRecord["effect"]) ?? null,
        decision: body.state === "granted" ? "approve" : "deny",
        rule_id: "approval.decide",
        reason: `${body.state === "granted" ? "approved" : "denied"} by ${ctx.actor} in the console${note ? `: ${note}` : ""}`,
        outcome: "completed",
        approval_id: result.row.id,
        args_redacted: (args ?? null) as Record<string, unknown> | null
      });
      return approvalDto(result.row);
    }),

    /* standing grants */

    route("GET", "/api/v1/servers/:id/grants", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      const activeOnly = ctx.query.get("state") === "active";
      return scopedFor(server)
        .listGrants({ activeOnly, limit: intParam(ctx.query, "limit") ?? 100 })
        .map(grantDto);
    }),

    route("POST", "/api/v1/servers/:id/grants", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      const body = (ctx.body ?? {}) as Record<string, unknown>;

      // Accept a TTL and derive the deadline, which is what a form can express.
      const ttl = Number(body["ttl_seconds"]);
      const expires = Number.isFinite(ttl) ? Date.now() + ttl * 1000 : Number(body["expires_at"]);

      let draft;
      try {
        draft = parseGrantDraft({
          tool_match: body["tool_match"],
          effect: body["effect"] ?? null,
          constraints: body["constraints"] ?? {},
          expires_at: expires,
          max_uses: body["max_uses"] ?? null,
          reason: body["reason"],
          created_by: ctx.actor
        });
      } catch (err) {
        throw unprocessable((err as Error).message);
      }

      const scoped = scopedFor(server);
      const grant = scoped.createGrant(draft);

      // The requirement is that no pre-approval exists unaudited, so this uses
      // appendStrict (which throws) rather than append (which only warns), and
      // the grant is withdrawn if the record cannot be written.
      try {
        auditFor(server, ctx.actor).appendStrict({
          tool: grant.tool_match,
          effect: (grant.effect as AuditRecord["effect"]) ?? null,
          decision: "approve",
          rule_id: "standing_grant.create",
          reason:
            `standing grant ${grant.id} created by ${ctx.actor}: ${grant.reason} ` +
            `(matches ${grant.tool_match}, ${grant.max_uses === null ? "unlimited uses" : `${grant.max_uses} use(s)`}, ` +
            `expires ${new Date(grant.expires_at).toISOString()})`,
          outcome: "completed",
          grant_id: grant.id,
          args_redacted: {
            tool_match: grant.tool_match,
            effect: grant.effect,
            constraints: draft.constraints ?? {},
            max_uses: grant.max_uses,
            expires_at: grant.expires_at
          }
        });
      } catch (err) {
        scoped.revokeGrant(grant.id, "system");
        throw new Error(`the grant was withdrawn because it could not be audited: ${(err as Error).message}`);
      }

      return grantDto(scoped.getGrant(grant.id)!);
    }),

    route("DELETE", "/api/v1/servers/:id/grants/:grantId", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      const scoped = scopedFor(server);
      const id = ctx.params["grantId"]!;
      const existing = scoped.getGrant(id);
      if (!existing) throw notFound(`no standing grant with id "${id}"`);

      const revoked = scoped.revokeGrant(id, ctx.actor);
      if (!revoked) throw conflict(`standing grant ${id} is already ${existing.state}`);

      // Revocation tightens, so unlike creation it is kept even if the audit
      // append fails; the failure is reported instead of undoing the fix.
      let warning: string | null = null;
      try {
        auditFor(server, ctx.actor).appendStrict({
          tool: revoked.tool_match,
          decision: "deny",
          rule_id: "standing_grant.revoke",
          reason: `standing grant ${revoked.id} revoked by ${ctx.actor} after ${revoked.uses} use(s)`,
          outcome: "completed",
          grant_id: revoked.id
        });
      } catch (err) {
        warning = `the grant was revoked but the audit record failed: ${(err as Error).message}`;
      }
      return { ...grantDto(revoked), warning };
    }),

    /**
     * Dry run: what would this grant release, right now?
     *
     * Writes nothing and claims no uses. This is what makes the settings page
     * honest — you see the blast radius before you create the grant.
     */
    route("POST", "/api/v1/servers/:id/grants/preview", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      const body = (ctx.body ?? {}) as Record<string, unknown>;
      const descriptors = server.tools?.tools ?? [];

      const ttl = Number(body["ttl_seconds"]);
      const expires = Number.isFinite(ttl) ? Date.now() + ttl * 1000 : Date.now() + 3600_000;

      let draft;
      try {
        draft = parseGrantDraft({
          tool_match: body["tool_match"],
          effect: body["effect"] ?? null,
          constraints: body["constraints"] ?? {},
          expires_at: expires,
          max_uses: body["max_uses"] ?? null,
          reason: typeof body["reason"] === "string" && body["reason"] ? body["reason"] : "preview",
          created_by: ctx.actor
        });
      } catch (err) {
        throw unprocessable((err as Error).message);
      }

      const candidate: StandingGrantRow = {
        id: "sg_preview",
        ...scopeOf(server),
        created_at: Date.now(),
        expires_at: draft.expires_at,
        tool_match: draft.tool_match,
        effect: draft.effect ?? null,
        constraints: JSON.stringify(draft.constraints ?? {}),
        max_uses: draft.max_uses ?? null,
        uses: 0,
        reason: draft.reason,
        created_by: draft.created_by,
        state: "active",
        revoked_at: null,
        revoked_by: null
      };

      return {
        expiresAt: draft.expires_at,
        tools: descriptors.map((d) => {
          const match = grantMatches(candidate, d.name, d.effect, {});
          return { name: d.name, effect: d.effect, covers: match.matches, why: match.reason };
        })
      };
    }),

    /* audit */

    route("GET", "/api/v1/servers/:id/audit", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      const page = queryAuditLog(server.auditPath, {
        limit: intParam(ctx.query, "limit") ?? 50,
        ...(intParam(ctx.query, "cursor") !== undefined ? { beforeSeq: intParam(ctx.query, "cursor")! } : {}),
        ...(csv(ctx.query, "decision") ? { decision: csv(ctx.query, "decision") as DecisionKind[] } : {}),
        ...(csv(ctx.query, "outcome") ? { outcome: csv(ctx.query, "outcome") as AuditRecord["outcome"][] } : {}),
        ...(csv(ctx.query, "component") ? { component: csv(ctx.query, "component")! } : {}),
        // One log holds every tenant's records, so this is how a reviewer
        // reads one customer's history out of it. `?tenant=` with an empty
        // value selects the records that carry no tenant.
        ...(ctx.query.has("tenant") ? { tenant: csv(ctx.query, "tenant") ?? [""] } : {}),
        ...(ctx.query.get("tool") ? { tool: ctx.query.get("tool")! } : {}),
        ...(ctx.query.get("since") ? { since: ctx.query.get("since")! } : {}),
        ...(ctx.query.get("noteworthy") ? { noteworthy: true } : {})
      });
      return { ...page, auditPath: server.auditPath };
    }),

    route("GET", "/api/v1/servers/:id/audit/verify", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      return verifyAuditLog(server.auditPath);
    }),

    /**
     * Combined view across servers.
     *
     * Deduped by audit path, because two servers legitimately share one log by
     * default. Where a path is shared, records are attributed by `component`
     * and the ambiguity is reported rather than guessed at.
     */
    route("GET", "/api/v1/audit", (ctx) => {
      const wanted = csv(ctx.query, "servers");
      const entries = registry(options).servers.filter((s) => !wanted || wanted.includes(s.id));
      const limit = intParam(ctx.query, "limit") ?? 50;

      const byPath = new Map<string, LoadedServer[]>();
      const broken: { id: string; error: string }[] = [];
      for (const entry of entries) {
        try {
          const server = loadServer(entry);
          const list = byPath.get(server.auditPath) ?? [];
          list.push(server);
          byPath.set(server.auditPath, list);
        } catch (err) {
          broken.push({ id: entry.id, error: (err as Error).message });
        }
      }

      const records: (AuditRecord & { serverId: string | null; attribution: string })[] = [];
      for (const [path, servers] of byPath) {
        const page = queryAuditLog(path, { limit, ...(ctx.query.get("noteworthy") ? { noteworthy: true } : {}) });
        for (const record of page.records) {
          const byComponent = servers.find((s) => s.component === record.component);
          const attribution = byComponent ? "component" : servers.length === 1 ? "path" : "ambiguous";
          records.push({
            ...record,
            serverId: byComponent?.entry.id ?? (servers.length === 1 ? servers[0]!.entry.id : null),
            attribution
          });
        }
      }

      records.sort((a, b) => (a.ts === b.ts ? b.seq - a.seq : a.ts < b.ts ? 1 : -1));

      // Surfaced so the UI can say why some records are attributed by
      // component rather than simply by which server was asked for.
      const sharedPaths = [...byPath.entries()]
        .filter(([, servers]) => servers.length > 1)
        .map(([path, servers]) => ({ path, servers: servers.map((s) => s.entry.id) }));

      return { records: records.slice(0, limit), sharedPaths, broken };
    })
  ];
}
