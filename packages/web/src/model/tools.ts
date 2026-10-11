import { runtimeStateIsLive, toolSurface, type ToolSurfaceEntry } from "@hmcp/core";
import { scopedFor, scopeFor, storeFor, type LoadedServer } from "./server.js";

/**
 * A gateway's tool surface, as this console can know it.
 *
 * The console never speaks MCP to an upstream. It would have to spawn child
 * processes and open sockets to do it, on a page load, for a surface the
 * gateway has already discovered — so instead the gateway publishes what it is
 * serving and this reads that.
 *
 * The consequence is that the surface has a *provenance*, which a file on disk
 * did not: rows were written by some process at some time, and that process may
 * be gone. Everything a reader needs to judge that is on this object rather
 * than left for each caller to work out, because the failure that matters is
 * silent — presenting a dead gateway's tool list as what is being served now.
 */
export interface ToolSurfaceView {
  readonly entries: readonly ToolSurfaceEntry[];
  /** A gateway process is announcing itself and these rows are its. */
  readonly live: boolean;
  /** Rows exist, but no live process claims them. */
  readonly stale: boolean;
  readonly publishedAt: number | null;
  /** True when no gateway has ever published for this component. */
  readonly neverPublished: boolean;
}

export const EMPTY_SURFACE: ToolSurfaceView = {
  entries: [],
  live: false,
  stale: false,
  publishedAt: null,
  neverPublished: true
};

/**
 * Reads the published inventory and narrows it by one tenant's exposure rows.
 *
 * The inventory itself is process-wide — every tenant of one gateway is offered
 * the same upstream tools — so the tenant only ever subtracts here.
 *
 * Rows are trusted only when the live `runtime_state` row names the same pid
 * that wrote them. Two gateways sharing a component — a dev and a staging
 * process on one box, both on the default store path — otherwise overwrite each
 * other, and a blend of two upstream sets is a surface nobody serves.
 */
export function toolSurfaceFor(server: LoadedServer, tenant: string): ToolSurfaceView {
  const store = storeFor(server);
  const rows = store.inventory(server.component);
  if (rows.length === 0) return EMPTY_SURFACE;

  const announced = store.runtimeState(server.component);
  const live = announced !== undefined && runtimeStateIsLive(announced) && announced.pid === rows[0]!.pid;
  const entries = toolSurface(rows, scopedFor(server, tenant).listDisabledTools());

  return {
    entries,
    live,
    stale: !live,
    publishedAt: rows[0]!.discovered_at,
    neverPublished: false
  };
}

/**
 * Whether this console may author a change to the surface right now.
 *
 * A tool name read from a stale inventory is the one input that must not be
 * trusted: writing an exposure row for a tool the running gateway does not
 * serve produces a row that looks exactly like protection and guards nothing.
 * The gateway's own admin API refuses this for the same reason, validating the
 * name against live inventory before it writes.
 */
export function surfaceWritable(view: ToolSurfaceView): { ok: true } | { ok: false; why: string } {
  if (view.neverPublished) {
    return {
      ok: false,
      why:
        "no gateway has published a tool surface for this component yet. Start the gateway once so it " +
        "can report what its upstreams offer, then this switch can name a tool that exists."
    };
  }
  if (!view.live) {
    return {
      ok: false,
      why:
        "no running gateway is announcing itself for this component, so the last published tool list " +
        "cannot be confirmed as current. Switching a tool off against a stale list would write a row " +
        "that looks like protection and guards nothing."
    };
  }
  return { ok: true };
}

/** The scope these entries were narrowed to, for a caller that has to say so. */
export function surfaceScope(server: LoadedServer, tenant: string): { component: string; tenant: string } {
  return scopeFor(server, tenant);
}
