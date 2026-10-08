import { readFileSync } from "node:fs";
import { scan, type ScanResult, type ScanTarget, type ScanTool } from "@hmcp/scanner";
import type { ToolDescriptor } from "@hmcp/server-runtime";
import type { LoadedServer } from "./server.js";

/**
 * Runs the scanner against a registered server.
 *
 * `scan` takes an in-memory target rather than a path, so the caller assembles
 * it. Results are cached against the source files' mtimes: a poll should not
 * re-run ten rules over an unchanged surface, but a hand-edited policy.yaml
 * should show up without restarting the console.
 */

function toScanTool(descriptor: ToolDescriptor): ScanTool {
  return {
    name: descriptor.name,
    description: descriptor.description,
    effect: descriptor.effect,
    method: descriptor.method,
    path: descriptor.path,
    inputSchema: descriptor.inputSchema,
    tenantParams: descriptor.tenantParams,
    hasPaginationCap: descriptor.paginationCap !== undefined
  };
}

const EMPTY: ScanResult = { findings: [], counts: { high: 0, medium: 0, low: 0 }, ok: true };

const cache = new Map<string, { key: string; result: ScanResult }>();

export function runScan(server: LoadedServer): ScanResult {
  if (!server.tools || !server.toolsPath) return EMPTY;

  const key = JSON.stringify(server.mtimes);
  const hit = cache.get(server.entry.id);
  if (hit && hit.key === key) return hit.result;

  const generation = server.tools.generation;
  const target: ScanTarget = {
    kind: "generated",
    file: server.toolsPath,
    policy: server.policy,
    tools: server.tools.tools.map(toScanTool),
    api: { title: server.tools.api.title, base_url: server.tools.api.base_url },
    // The generated tool text is the surface a model sees, so it is what the
    // injection and secret rules should read.
    sourceTexts: [{ path: server.toolsPath, text: readFileSync(server.toolsPath, "utf8") }],
    ...(generation?.has_security_schemes !== undefined
      ? {
          spec: {
            hasSecuritySchemes: generation.has_security_schemes,
            operationsWithoutSecurity: generation.operations_without_security
          }
        }
      : {})
  };

  const result = scan(target);
  cache.set(server.entry.id, { key, result });
  return result;
}

export function invalidateScan(id?: string): void {
  if (id) cache.delete(id);
  else cache.clear();
}
