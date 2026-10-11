import { randomBytes } from "node:crypto";
import {
  AuditLog,
  applyExposureChange,
  MAX_GRANT_TTL_SECONDS,
  NO_TENANT,
  grantMatches,
  parseExposureChange,
  parseGrantDraft,
  queryAuditLog,
  readRegistry,
  runtimeStateIsLive,
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
import {
  chooseTenant,
  knownTenants,
  loadServer,
  scopeFor,
  scopedFor,
  storeFor,
  type LoadedServer
} from "./model/server.js";
import { surfaceWritable, toolSurfaceFor } from "./model/tools.js";
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

/**
 * One server, and the tenant whose rows this request is about.
 *
 * Every scoped route goes through this rather than resolving a tenant of its
 * own, so no route can be written that forgets to and quietly falls back to the
 * empty tenant. `chooseTenant` refuses where the console cannot legitimately
 * know the answer, and the refusal surfaces as a 422 explaining how to name one.
 */
function scopedRequest(
  options: ApiOptions,
  id: string,
  query: URLSearchParams
): { server: LoadedServer; tenant: string; explicit: boolean } {
  const server = serverById(options, id);
  const choice = chooseTenant(server, query.get("tenant"));
  if (!choice.ok) throw unprocessable(choice.why);
  return { server, tenant: choice.tenant, explicit: choice.explicit };
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
      grantTtlMaxSeconds: MAX_GRANT_TTL_SECONDS,
      /*
       * The audit vocabulary, served for the same reason the markers are: these
       * are core's enums, and the filter UI had its own copy of both lists. A
       * value added to `DecisionKind` would have been unfilterable until
       * someone noticed the dropdown was short.
       */
      decisions: [
        { value: "allow", label: "allowed" },
        { value: "approve", label: "approved" },
        { value: "deny", label: "denied" }
      ],
      outcomes: [
        { value: "completed", label: "completed" },
        { value: "denied", label: "denied" },
        { value: "pending-approval", label: "held for approval" },
        { value: "error", label: "error" }
      ]
    })),

    /* servers */

    route("GET", "/api/v1/servers", () =>
      registry(options).servers.map((entry) => {
        try {
          const server = loadServer(entry);
          /*
           * The inventory is process-wide, so the tool count needs no tenant.
           * Reach does: it subtracts whatever that tenant switched off. Where
           * the console cannot know which tenant to speak for, it says so with
           * a null rather than quietly reporting the empty tenant's answer as
           * the gateway's.
           */
          const choice = chooseTenant(server, null);
          const surface = toolSurfaceFor(server, choice.ok ? choice.tenant : NO_TENANT);
          const announced = storeFor(server).runtimeState(server.component);
          return {
            id: entry.id,
            kind: entry.kind,
            label: entry.label,
            ok: true,
            component: server.component,
            upstreams: server.gateway.config.upstreams.map((u) => u.name),
            /*
             * Null, not zero, when nothing has been published. A gateway that
             * has not reported is not a gateway serving no tools, and the two
             * used to be the same number here.
             */
            toolCount: surface.live ? surface.entries.length : null,
            surfaceLive: surface.live,
            surfaceStale: surface.stale,
            posture: server.policy.defaults.mode,
            reach: choice.ok ? effectiveReach(server, choice.tenant, surface) : null,
            tenantScope: choice.ok ? choice.tenant : null,
            tenantRequired: !choice.ok,
            tenantHint: choice.ok ? null : choice.why,
            running: announced !== undefined && runtimeStateIsLive(announced),
            auditPath: server.auditPath,
            storePath: server.storePath,
            tenantError: server.tenantError
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
      return { removed: id };
    }),

    /* tools and protection */

    /**
     * Which tenants this gateway has any trace of.
     *
     * Served so the console can offer a choice instead of a blank box, and so
     * nothing in the UI has to carry a tenant list of its own. Historical, not
     * authoritative: a tenant that has never made a call or had a row written
     * will not be here, which is why naming one directly stays possible.
     */
    route("GET", "/api/v1/servers/:id/tenants", (ctx) => {
      const server = serverById(options, ctx.params["id"]!);
      const config = server.policy.tenant;
      const assumed = chooseTenant(server, null);
      return {
        tenants: knownTenants(server),
        configured: config !== null && config !== undefined,
        sourceKind: config?.source.kind ?? null,
        required: config?.required ?? false,
        /** Null when the request has to name one. */
        assumed: assumed.ok ? assumed.tenant : null,
        whyNotAssumed: assumed.ok ? null : assumed.why
      };
    }),

    route("GET", "/api/v1/servers/:id/protection", (ctx) => {
      const { server, tenant, explicit } = scopedRequest(options, ctx.params["id"]!, ctx.query);
      return buildProtection(server, tenant, explicit);
    }),

    route("GET", "/api/v1/servers/:id/tools", (ctx) => {
      const { server, tenant, explicit } = scopedRequest(options, ctx.params["id"]!, ctx.query);
      return buildProtection(server, tenant, explicit).tools;
    }),

    route("GET", "/api/v1/servers/:id/tools/:tool", (ctx) => {
      const { server, tenant, explicit } = scopedRequest(options, ctx.params["id"]!, ctx.query);
      const name = ctx.params["tool"]!;
      const tool = buildProtection(server, tenant, explicit).tools.find((t) => t.name === name);
      if (!tool) throw notFound(`no tool "${name}" on server "${server.entry.id}"`);
      const entry = toolSurfaceFor(server, tenant).entries.find((t) => t.name === name);
      return { ...tool, inputSchema: entry?.inputSchema ?? null, activity: recentActivity(server, name) };
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
      const { server, tenant, explicit } = scopedRequest(options, ctx.params["id"]!, ctx.query);
      const name = ctx.params["tool"]!;

      /*
       * The tool name is checked against what a *live* gateway says it is
       * serving, which is the whole reason this route can exist at all now.
       * A name taken from a stale list would write a row that reads as
       * protection and guards nothing -- the gateway's own admin API refuses
       * for exactly this reason before it writes.
       */
      const surface = toolSurfaceFor(server, tenant);
      const writable = surfaceWritable(surface);
      if (!writable.ok) throw unprocessable(`cannot change exposure for "${server.entry.id}": ${writable.why}`);

      const entry = surface.entries.find((t) => t.name === name);
      if (!entry) {
        throw notFound(
          `no tool "${name}" in what "${server.entry.id}" is currently serving. ` +
            `Its upstreams advertise: ${surface.entries.map((t) => t.name).join(", ") || "nothing"}.`
        );
      }

      const body = (ctx.body ?? {}) as Record<string, unknown>;
      let change;
      try {
        change = parseExposureChange({ tool: name, disabled: body["disabled"], reason: body["reason"] ?? "" });
      } catch (err) {
        throw unprocessable(`invalid exposure change: ${(err as Error).message}`);
      }

      const scoped = scopedFor(server, tenant);
      /*
       * The disable-keeps / enable-rolls-back asymmetry lives in core, because
       * the gateway's admin API and its CLI flip the same bit and three
       * hand-copied versions of that rule is how two of them end up wrong.
       */
      const { changed, warning } = applyExposureChange({
        scoped,
        audit: auditFor(server, ctx.actor),
        change,
        actor: ctx.actor,
        effect: entry.effect ?? undefined,
        channel: `the console, for tenant ${tenant === "" ? "(none)" : tenant}`
      });

      // Re-read, so the row returned reflects the write that just happened
      // rather than the surface as it was before it.
      const updated = toolSurfaceFor(server, tenant).entries.find((t) => t.name === name) ?? entry;
      const tool = toolProtection(server, updated, scoped.listGrants({ activeOnly: true }));
      return { tool, changed, warning, tenant, explicitTenant: explicit };
    }),

    /* approvals */

    route("GET", "/api/v1/servers/:id/approvals/pending", (ctx) => {
      const { server, tenant } = scopedRequest(options, ctx.params["id"]!, ctx.query);
      return scopedFor(server, tenant)
        .listPending(intParam(ctx.query, "limit") ?? 50)
        .map(approvalDto);
    }),

    route("GET", "/api/v1/servers/:id/approvals", (ctx) => {
      const { server, tenant } = scopedRequest(options, ctx.params["id"]!, ctx.query);
      return scopedFor(server, tenant)
        .list(intParam(ctx.query, "limit") ?? 50)
        .map(approvalDto);
    }),

    route("POST", "/api/v1/servers/:id/approvals/:aprId/decide", (ctx) => {
      const { server, tenant } = scopedRequest(options, ctx.params["id"]!, ctx.query);
      const body = (ctx.body ?? {}) as { state?: unknown; note?: unknown };
      if (body.state !== "granted" && body.state !== "denied") {
        throw badRequest('state must be "granted" or "denied"');
      }
      const note = typeof body.note === "string" ? body.note : "";
      const result = scopedFor(server, tenant).decideChecked(ctx.params["aprId"]!, body.state, ctx.actor, note);
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
      const { server, tenant } = scopedRequest(options, ctx.params["id"]!, ctx.query);
      const activeOnly = ctx.query.get("state") === "active";
      return scopedFor(server, tenant)
        .listGrants({ activeOnly, limit: intParam(ctx.query, "limit") ?? 100 })
        .map(grantDto);
    }),

    route("POST", "/api/v1/servers/:id/grants", (ctx) => {
      const { server, tenant } = scopedRequest(options, ctx.params["id"]!, ctx.query);
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

      const scoped = scopedFor(server, tenant);
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
      const { server, tenant } = scopedRequest(options, ctx.params["id"]!, ctx.query);
      const scoped = scopedFor(server, tenant);
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
      const { server, tenant } = scopedRequest(options, ctx.params["id"]!, ctx.query);
      const body = (ctx.body ?? {}) as Record<string, unknown>;
      /*
       * The point of a preview is to show the blast radius before a grant is
       * created, so an empty list has to mean "covers nothing" and nothing
       * else. Reading an unpublished surface would have it quietly claim that
       * about a grant covering every tool the gateway serves.
       */
      const surface = toolSurfaceFor(server, tenant);
      const writable = surfaceWritable(surface);

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
        ...scopeFor(server, tenant),
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
        surfaceKnown: writable.ok,
        surfaceUnknownWhy: writable.ok ? null : writable.why,
        tools: surface.entries.map((entry) => {
          const match = grantMatches(candidate, entry.name, entry.effect, {});
          return { name: entry.name, effect: entry.effect, covers: match.matches, why: match.reason };
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
        // Recording which agent made a call is only half the requirement;
        // without this it would be written down and unaskable.
        ...(csv(ctx.query, "actor") ? { actor: csv(ctx.query, "actor")! } : {}),
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
