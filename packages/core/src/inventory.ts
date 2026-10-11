import type { Effect } from "./policy.js";
import type { ToolExposureRow } from "./exposure.js";

/**
 * What a running gateway is actually serving, published so other processes can
 * read it.
 *
 * A gateway's tool surface does not exist on disk. It comes from each upstream's
 * MCP `tools/list` — the same call, and the same three fields, the agent itself
 * sees — and only the gateway process has made that call. So a console has two
 * ways to learn a gateway's tools: speak MCP to every upstream itself, which
 * means spawning child processes and opening sockets on a page load, or read
 * what the gateway already knows. This is the second.
 *
 * Keyed by `component` and not by tenant, deliberately, for the same reason
 * `runtime_state` is: the base tool set is a property of the process. Every
 * tenant of one gateway is offered the identical set, and `tools/list` narrows
 * it per caller only by the process-wide `hidden` flag and that tenant's
 * `tool_exposure` rows. Inventory is what the upstreams offer; exposure is what
 * a tenant may use. Joining the two is `toolSurface`.
 *
 * `pid` is carried because `runtime_state` upserts by component on a
 * last-to-start-wins basis. That is tolerable for a policy digest and not for a
 * tool list: two gateways sharing a config name but pointing at different
 * upstreams — a dev and a staging process on one box, both on the default
 * `store_path` — would otherwise overwrite each other's rows and a reader would
 * see a surface no single process serves. A reader compares this against the
 * live `runtime_state` row and ignores rows from any other process.
 */
export interface ToolInventoryRow {
  readonly component: string;
  readonly tool: string;
  readonly pid: number;
  /** The upstream server this tool came from, as named in the gateway config. */
  readonly upstream: string;
  /** Null when the gateway could not classify it; such a tool is refused. */
  readonly effect: Effect | null;
  readonly effect_source: string;
  /** The description as advertised to the model, after any rewriting. */
  readonly description: string;
  /** The upstream's own text, before rewriting, so the two can be compared. */
  readonly raw_description: string;
  /** The upstream's `inputSchema`, verbatim, as JSON. */
  readonly input_schema: string;
  /** 1 when gateway policy hides it from every tenant. */
  readonly hidden: number;
  /** JSON array of injection pattern ids found in the upstream's text. */
  readonly injection: string | null;
  readonly discovered_at: number;
}

export const TOOL_INVENTORY_SCHEMA = `
CREATE TABLE IF NOT EXISTS tool_inventory (
  component       TEXT NOT NULL,
  tool            TEXT NOT NULL,
  pid             INTEGER NOT NULL,
  upstream        TEXT NOT NULL,
  effect          TEXT,
  effect_source   TEXT NOT NULL,
  description     TEXT NOT NULL,
  raw_description TEXT NOT NULL,
  input_schema    TEXT NOT NULL,
  hidden          INTEGER NOT NULL,
  injection       TEXT,
  discovered_at   INTEGER NOT NULL,
  PRIMARY KEY (component, tool)
);
`;

/** What a gateway hands the store, before the store stamps it. */
export interface ToolInventoryInput {
  readonly tool: string;
  readonly upstream: string;
  readonly effect: Effect | null;
  readonly effectSource: string;
  readonly description: string;
  readonly rawDescription: string;
  readonly inputSchema: unknown;
  readonly hidden: boolean;
  readonly injection: readonly string[] | null;
}

/**
 * One tool as a reader should see it: what the gateway is serving, narrowed by
 * what this tenant may use.
 */
export interface ToolSurfaceEntry {
  readonly name: string;
  readonly upstream: string;
  readonly effect: Effect | null;
  readonly effectSource: string;
  /** What the model is told. */
  readonly description: string;
  /** What the upstream said, which differs when injection was rewritten. */
  readonly rawDescription: string;
  readonly inputSchema: unknown;
  /**
   * Hidden from every tenant by gateway policy — `on_injection: deny`. Distinct
   * from `disabled`, which is one tenant's switch and is reversible by them.
   */
  readonly hiddenByPolicy: boolean;
  readonly injection: readonly string[] | null;
  readonly disabled: { readonly reason: string; readonly setAt: number; readonly setBy: string } | null;
}

/**
 * Joins a tool surface against one tenant's exposure rows.
 *
 * The single implementation of "what is this tenant's tool surface", so a
 * gateway answering for itself from memory and a console reading what that
 * gateway published cannot answer the same question two different ways. The
 * two differ only in where the tools came from, which is why both entry points
 * below funnel into this one.
 */
export function toolSurfaceOf(
  tools: readonly ToolInventoryInput[],
  disabled: readonly ToolExposureRow[]
): ToolSurfaceEntry[] {
  const off = new Map(disabled.map((row) => [row.tool, row]));
  return tools.map((tool) => {
    const switchedOff = off.get(tool.tool);
    return {
      name: tool.tool,
      upstream: tool.upstream,
      effect: tool.effect,
      effectSource: tool.effectSource,
      description: tool.description,
      rawDescription: tool.rawDescription,
      inputSchema: tool.inputSchema,
      hiddenByPolicy: tool.hidden,
      injection: tool.injection,
      disabled: switchedOff
        ? { reason: switchedOff.reason, setAt: switchedOff.set_at, setBy: switchedOff.set_by }
        : null
    };
  });
}

/** The same join, for a reader that has the published rows rather than a gateway. */
export function toolSurface(
  inventory: readonly ToolInventoryRow[],
  disabled: readonly ToolExposureRow[]
): ToolSurfaceEntry[] {
  return toolSurfaceOf(inventory.map(rowToInput), disabled);
}

/*
 * A published row came out of the database as text some other process wrote,
 * so neither JSON field is trusted to parse. A field that cannot be read costs
 * itself, not the listing: a console that threw here would show nothing at all
 * because one upstream advertised something odd.
 */
function rowToInput(row: ToolInventoryRow): ToolInventoryInput {
  return {
    tool: row.tool,
    upstream: row.upstream,
    effect: row.effect,
    effectSource: row.effect_source,
    description: row.description,
    rawDescription: row.raw_description,
    inputSchema: parseSchema(row.input_schema),
    hidden: row.hidden === 1,
    injection: parseInjection(row.injection)
  };
}

function parseSchema(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return { type: "object" };
  }
}

function parseInjection(raw: string | null): readonly string[] | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((id): id is string => typeof id === "string") : null;
  } catch {
    return null;
  }
}
