import { RULES } from "./rules.js";
import { applyBaseline, sortFindings } from "./report.js";
import type { Baseline } from "./report.js";
import type { Finding, ScanResult, ScanTarget, Severity } from "./types.js";

export * from "./types.js";
export * from "./report.js";
export * from "./injection.js";
export { RULES } from "./rules.js";

export interface ScanOptions {
  readonly baseline?: Baseline | undefined;
  /** Rule ids to skip entirely. */
  readonly disable?: readonly string[];
}

/**
 * Runs every rule over one target. A rule that throws is reported as a finding
 * rather than aborting the scan - a scanner that fails silently is worse than
 * one that fails loudly.
 */
export function scan(target: ScanTarget, options: ScanOptions = {}): ScanResult {
  const disabled = new Set(options.disable ?? []);
  const findings: Finding[] = [];

  for (const rule of RULES) {
    if (disabled.has(rule.id)) continue;
    try {
      findings.push(...rule.run(target));
    } catch (err) {
      findings.push({
        ruleId: rule.id,
        severity: "medium",
        title: `Rule ${rule.id} failed to run`,
        message: `The ${rule.id} check could not complete: ${(err as Error).message}. This target was not fully scanned.`,
        fix: `Report this as a bug in hmcp-scan.`,
        location: { file: target.file }
      });
    }
  }

  const surviving = sortFindings(applyBaseline(findings, options.baseline));
  const counts: Record<Severity, number> = { high: 0, medium: 0, low: 0 };
  for (const f of surviving) counts[f.severity]++;

  return { findings: surviving, counts, ok: counts.high === 0 };
}
