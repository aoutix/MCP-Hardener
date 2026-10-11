import type { Effect, Policy } from "@hmcp/core";

export type Severity = "high" | "medium" | "low";

export interface Finding {
  readonly ruleId: string;
  readonly severity: Severity;
  readonly title: string;
  /** What is wrong, in terms of what an attacker or a mistake could do. */
  readonly message: string;
  /** What to change. */
  readonly fix: string;
  readonly location: {
    readonly file: string;
    /** Logical path within the file, e.g. `tools.get_pet.description`. */
    readonly path?: string;
  };
}

/** A tool as the scanner sees it, from either half of the project. */
export interface ScanTool {
  readonly name: string;
  readonly description: string;
  readonly effect?: Effect | undefined;
  readonly method?: string | undefined;
  readonly path?: string | undefined;
  readonly inputSchema?: unknown;
  readonly tenantParams?: readonly string[] | undefined;
  readonly hasPaginationCap?: boolean | undefined;
  /** Upstream server name, for gateway scans. */
  readonly server?: string | undefined;
}

export interface ScanTarget {
  /**
   * `upstream` scans a server we did not build, which is what the gateway does.
   *
   * `generated` remains for a target assembled from a declared tool surface
   * rather than discovered over MCP — the rules that need a policy and an API
   * block to say anything are gated on it.
   */
  readonly kind: "generated" | "upstream";
  readonly file: string;
  readonly policy?: Policy | undefined;
  readonly tools: readonly ScanTool[];
  readonly api?: { readonly title: string; readonly base_url: string } | undefined;
  /**
   * Untrusted text from a source document, scanned even where it never reached
   * the tool surface: a credential in a document is disclosed and needs
   * rotating whether or not anything advertised it.
   */
  readonly sourceTexts?: readonly { readonly path: string; readonly text: string }[] | undefined;
  /** Facts about a source document, where the target came from one. */
  readonly spec?:
    | {
        readonly hasSecuritySchemes: boolean;
        readonly operationsWithoutSecurity: readonly string[];
      }
    | undefined;
}

export interface Rule {
  readonly id: string;
  readonly severity: Severity;
  readonly title: string;
  readonly run: (target: ScanTarget) => Finding[];
}

export interface ScanResult {
  readonly findings: readonly Finding[];
  readonly counts: Readonly<Record<Severity, number>>;
  /** True when nothing high-severity survived the baseline. */
  readonly ok: boolean;
}
