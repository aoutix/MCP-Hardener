import { sha256 } from "@hmcp/core";
import type { Finding, ScanResult, Severity } from "./types.js";

/** Stable identity for a finding, so a baseline survives unrelated edits. */
export function fingerprint(finding: Finding): string {
  return sha256(finding.ruleId, "\n", finding.location.path ?? "", "\n", finding.title).slice(0, 16);
}

export interface Baseline {
  version: 1;
  accepted: { fingerprint: string; ruleId: string; path?: string; note?: string }[];
}

export function applyBaseline(findings: readonly Finding[], baseline: Baseline | undefined): Finding[] {
  if (!baseline) return [...findings];
  const accepted = new Set(baseline.accepted.map((a) => a.fingerprint));
  return findings.filter((f) => !accepted.has(fingerprint(f)));
}

export function makeBaseline(findings: readonly Finding[]): Baseline {
  return {
    version: 1,
    accepted: findings.map((f) => ({
      fingerprint: fingerprint(f),
      ruleId: f.ruleId,
      ...(f.location.path ? { path: f.location.path } : {}),
      note: f.title
    }))
  };
}

const SEVERITY_ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2 };

export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.ruleId.localeCompare(b.ruleId) ||
      (a.location.path ?? "").localeCompare(b.location.path ?? "")
  );
}

const ICON: Record<Severity, string> = { high: "✗", medium: "!", low: "·" };

/** Human-readable report for a terminal or a PR comment. */
export function toMarkdown(result: ScanResult, target: string): string {
  const lines: string[] = [];
  lines.push(`# hmcp scan: ${target}`);
  lines.push("");
  const { high, medium, low } = result.counts;
  if (result.findings.length === 0) {
    lines.push("No findings.");
    return lines.join("\n") + "\n";
  }
  lines.push(`**${high} high · ${medium} medium · ${low} low**`);
  lines.push("");
  lines.push("| | Rule | Where | Finding |");
  lines.push("| --- | --- | --- | --- |");
  for (const f of sortFindings(result.findings)) {
    const where = f.location.path ? `\`${f.location.path}\`` : f.location.file;
    lines.push(`| ${ICON[f.severity]} | ${f.ruleId} | ${where} | ${escapeCell(f.message)} |`);
  }
  lines.push("");
  lines.push("## Details");
  for (const f of sortFindings(result.findings)) {
    lines.push("");
    lines.push(`### ${ICON[f.severity]} ${f.ruleId} ${f.title} (${f.severity})`);
    if (f.location.path) lines.push(`**Where:** \`${f.location.path}\``);
    lines.push("");
    lines.push(f.message);
    lines.push("");
    lines.push(`**Fix:** ${f.fix}`);
  }
  return lines.join("\n") + "\n";
}

function escapeCell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\n+/g, " ");
}

/** Terse output for a build log. */
export function toText(result: ScanResult, target: string): string {
  const lines: string[] = [];
  for (const f of sortFindings(result.findings)) {
    lines.push(`${ICON[f.severity]} ${f.severity.padEnd(6)} ${f.ruleId}  ${f.location.path ?? f.location.file}`);
    lines.push(`         ${f.message}`);
    lines.push(`         fix: ${f.fix}`);
  }
  const { high, medium, low } = result.counts;
  lines.push("");
  lines.push(
    result.findings.length === 0
      ? `scan of ${target}: no findings`
      : `scan of ${target}: ${high} high, ${medium} medium, ${low} low`
  );
  return lines.join("\n") + "\n";
}

const SARIF_LEVEL: Record<Severity, string> = { high: "error", medium: "warning", low: "note" };

/** SARIF 2.1.0, for code scanning in CI. */
export function toSarif(result: ScanResult, target: string): string {
  const ruleIds = [...new Set(result.findings.map((f) => f.ruleId))].sort();
  const byId = new Map(result.findings.map((f) => [f.ruleId, f]));

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "hmcp-scan",
            informationUri: "https://github.com/hardened-mcp",
            rules: ruleIds.map((id) => ({
              id,
              name: byId.get(id)!.title.replace(/\s+/g, ""),
              shortDescription: { text: byId.get(id)!.title },
              defaultConfiguration: { level: SARIF_LEVEL[byId.get(id)!.severity] },
              properties: { tags: ["security", "mcp"] }
            }))
          }
        },
        results: sortFindings(result.findings).map((f) => ({
          ruleId: f.ruleId,
          level: SARIF_LEVEL[f.severity],
          message: { text: `${f.message} Fix: ${f.fix}` },
          partialFingerprints: { hmcpFingerprint: fingerprint(f) },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.location.file },
                region: { startLine: 1 }
              },
              logicalLocations: f.location.path ? [{ fullyQualifiedName: f.location.path }] : undefined
            }
          ]
        }))
      }
    ]
  };
  return JSON.stringify(sarif, null, 2) + "\n";
}
