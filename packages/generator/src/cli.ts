#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import { Command } from "commander";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { defaultPolicy, expandPath, loadPolicy, PolicyError, type Effect, type Policy } from "@hmcp/core";
import { scan, toMarkdown, toSarif, toText, type ScanTool } from "@hmcp/scanner";
import { parseSpec, SpecError } from "./parse.js";
import { checkBudget, curate } from "./curate.js";
import { emit } from "./emit.js";
import type { Manifest } from "./types.js";

const program = new Command();

program
  .name("hmcp-gen")
  .description("Generate a hardened MCP server from an OpenAPI or Swagger spec.")
  .version("0.1.0");

program
  .command("plan")
  .description("Inspect a spec and write a tool manifest for a human to review and edit.")
  .argument("<spec>", "path or URL to an OpenAPI 3 or Swagger 2 document")
  .option("-o, --out <file>", "manifest to write", "tools.manifest.yaml")
  .option("-p, --policy <file>", "policy file, used to detect tenant parameters")
  .option("--include <glob...>", "only consider tools matching these globs")
  .option("--exclude <glob...>", "drop tools matching these globs")
  .option("--tag <tag...>", "only consider operations carrying one of these tags")
  .option("--include-deprecated", "keep operations the spec marks deprecated", false)
  .option(
    "--enable <effect...>",
    'which effects to enable up front; defaults to "read" so writes are opt-in',
    ["read"]
  )
  .option("--base-url <url>", "override the upstream base URL")
  .action(async (specPath: string, options) => {
    await run(async () => {
      const policy = options.policy ? loadPolicy(options.policy as string) : undefined;
      const spec = await parseSpec(specPath);

      const result = curate(spec, {
        include: options.include as string[] | undefined,
        exclude: options.exclude as string[] | undefined,
        tags: options.tag as string[] | undefined,
        includeDeprecated: options.includeDeprecated as boolean,
        enableEffects: (options.enable as string[]).filter(isEffect),
        tenant: policy?.tenant,
        baseUrl: options.baseUrl as string | undefined,
        policyPath: options.policy as string | undefined
      });

      const outPath = resolve(options.out as string);
      writeFileSync(outPath, renderManifest(result.manifest), "utf8");

      const byEffect = countBy(result.manifest.tools, (t) => t.effect);
      const enabled = result.manifest.tools.filter((t) => t.enabled);
      const needingReview = result.manifest.tools.filter((t) => t.review);

      log(`${spec.title} ${spec.version} (${spec.originalFormat})`);
      log(`  ${spec.operations.length} operations in the spec`);
      log(
        `  ${result.manifest.tools.length} candidate tools: ` +
          `${byEffect["read"] ?? 0} read, ${byEffect["write"] ?? 0} write, ${byEffect["destructive"] ?? 0} destructive`
      );
      if (result.skipped.length > 0) log(`  ${result.skipped.length} operations skipped`);
      log(`  ${enabled.length} enabled, ${result.manifest.tools.length - enabled.length} left off`);

      if (!spec.hasSecuritySchemes) {
        log("");
        log("  note: the spec declares no security schemes, so no credential or tenant can be derived from it.");
      }

      if (needingReview.length > 0) {
        log("");
        log(`  ${needingReview.length} operation(s) need a human decision:`);
        for (const tool of needingReview) log(`    ${tool.name}: ${tool.review}`);
      }

      const tenantTools = result.manifest.tools.filter((t) => t.tenant_params?.length);
      if (tenantTools.length > 0) {
        log("");
        log(`  ${tenantTools.length} tool(s) are tenant-scoped; those parameters will be withheld from agents.`);
      }

      log("");
      log(`Wrote ${relative(process.cwd(), outPath)}.`);
      log(`Review it - turn on the tools an agent actually needs - then:`);
      log(`  hmcp-gen build -m ${relative(process.cwd(), outPath)} -p <policy.yaml> -o ./out`);
    });
  });

program
  .command("build")
  .description("Emit a hardened MCP server from a reviewed manifest, then scan the output.")
  .option("-m, --manifest <file>", "manifest from `hmcp-gen plan`", "tools.manifest.yaml")
  .option("-p, --policy <file>", "policy file; defaults to the built-in read-only policy")
  .option("-o, --out <dir>", "directory to write the server into", "./out")
  .option("-s, --spec <file>", "override the spec path recorded in the manifest")
  .option("--base-url <url>", "override the upstream base URL")
  .option(
    "--runtime <spec>",
    "dependency specifier for @hmcp/server-runtime in the generated package.json; " +
      "use a file: path to install it from a local checkout",
    "^0.1.0"
  )
  .option("--sarif <file>", "also write the scan as SARIF")
  .option("--scan-md <file>", "also write the scan as markdown")
  .option("--baseline <file>", "accept the findings recorded in this baseline file")
  .option("--write-baseline <file>", "record the current findings as an accepted baseline")
  .option("--no-scan", "skip the self-scan (not recommended)")
  .option("--allow-high", "emit even when the scan finds a high-severity problem")
  .action(async (options) => {
    await run(async () => {
      const manifestPath = resolve(options.manifest as string);
      if (!existsSync(manifestPath)) {
        throw new CliError(
          `no manifest at ${manifestPath}. Run "hmcp-gen plan <spec>" first and review what it produces.`
        );
      }
      const manifest = parseYaml(readFileSync(manifestPath, "utf8")) as Manifest;
      if (manifest?.version !== 1 || !Array.isArray(manifest.tools)) {
        throw new CliError(`${manifestPath} is not a tool manifest (expected version: 1 and a tools list).`);
      }

      const policyPath = (options.policy as string | undefined) ?? manifest.policy;
      const policy = policyPath ? loadPolicy(policyPath) : defaultPolicy();
      const policySource = policyPath ? readFileSync(expandPath(policyPath), "utf8") : stringifyYaml(policy);

      const specPath = (options.spec as string | undefined) ?? manifest.spec;
      const spec = await parseSpec(specPath);

      const budget = checkBudget(manifest, policy.tool_budget);
      if (!budget.ok) throw new CliError(budget.message!);

      const outDir = resolve(options.out as string);
      const result = emit({
        manifest,
        spec,
        policy,
        outDir,
        baseUrl: options.baseUrl as string | undefined,
        policySource,
        runtimeSpecifier: options.runtime as string | undefined,
        operationsWithoutSecurity: enabledWithoutSecurity(manifest, spec)
      });

      log(`Wrote ${result.files.length} files to ${relative(process.cwd(), outDir) || "."}:`);
      for (const file of result.files) log(`  ${file}`);
      log("");
      log(`${result.toolsFile.tools.length} tools exposed, upstream ${result.toolsFile.api.base_url}`);
      if (result.omitted.length > 0) {
        log(`${result.omitted.length} parameter(s) withheld from agents (see README.md).`);
      }

      if (options.scan === false) {
        log("");
        log("Self-scan skipped.");
        return;
      }

      const scanResult = scan(
        {
          kind: "generated",
          file: "tools.json",
          policy,
          tools: result.scanTools as ScanTool[],
          api: { title: result.toolsFile.api.title, base_url: result.toolsFile.api.base_url },
          sourceTexts: specTexts(spec, manifest),
          spec: {
            hasSecuritySchemes: spec.hasSecuritySchemes,
            operationsWithoutSecurity: enabledWithoutSecurity(manifest, spec)
          }
        },
        { baseline: readBaseline(options.baseline as string | undefined) }
      );

      log("");
      process.stdout.write(toText(scanResult, "generated server"));

      if (options.sarif) {
        writeFileSync(resolve(options.sarif as string), toSarif(scanResult, "generated server"), "utf8");
        log(`SARIF written to ${options.sarif}`);
      }
      if (options.scanMd) {
        writeFileSync(resolve(options.scanMd as string), toMarkdown(scanResult, "generated server"), "utf8");
        log(`Markdown report written to ${options.scanMd}`);
      }
      if (options.writeBaseline) {
        const { makeBaseline } = await import("@hmcp/scanner");
        writeFileSync(
          resolve(options.writeBaseline as string),
          JSON.stringify(makeBaseline(scanResult.findings), null, 2) + "\n",
          "utf8"
        );
        log(`Baseline written to ${options.writeBaseline}`);
      }

      if (!scanResult.ok && !options.allowHigh) {
        throw new CliError(
          `the generated server has ${scanResult.counts.high} high-severity finding(s). ` +
            `Fix the policy or the manifest and build again, or pass --allow-high if you have accepted the risk ` +
            `deliberately. The files were written, but do not ship them as they are.`
        );
      }
    });
  });

/**
 * Untrusted text from the spec for the enabled operations, including text the
 * generator did not carry into the output. A credential or an injection payload
 * in a spec is worth reporting even when it was dropped on the way through.
 */
function specTexts(
  spec: Awaited<ReturnType<typeof parseSpec>>,
  manifest: Manifest
): { path: string; text: string }[] {
  const enabled = new Set(manifest.tools.filter((t) => t.enabled).map((t) => `${t.method} ${t.path}`));
  const texts: { path: string; text: string }[] = [];

  for (const url of spec.servers) texts.push({ path: "spec.servers", text: url });

  for (const operation of spec.operations) {
    if (!enabled.has(`${operation.method} ${operation.path}`)) continue;
    const where = `spec.${operation.operationId}`;
    if (operation.summary) texts.push({ path: `${where}.summary`, text: operation.summary });
    if (operation.description) texts.push({ path: `${where}.description`, text: operation.description });
    for (const param of operation.parameters) {
      if (param.description) {
        texts.push({ path: `${where}.parameters.${param.name}.description`, text: param.description });
      }
    }
    if (operation.requestBody?.description) {
      texts.push({ path: `${where}.requestBody.description`, text: operation.requestBody.description });
    }
  }
  return texts;
}

function enabledWithoutSecurity(manifest: Manifest, spec: Awaited<ReturnType<typeof parseSpec>>): string[] {
  const enabled = new Set(manifest.tools.filter((t) => t.enabled).map((t) => `${t.method} ${t.path}`));
  return spec.operations
    .filter((op) => enabled.has(`${op.method} ${op.path}`) && op.security.length === 0)
    .map((op) => `${op.method} ${op.path}`);
}

/** Writes the manifest with a header explaining what a reviewer is deciding. */
function renderManifest(manifest: Manifest): string {
  const header = [
    "# Tool manifest produced by `hmcp-gen plan`.",
    "#",
    "# This is the curation step: every tool below is a candidate, and only the ones",
    "# with `enabled: true` become tools an agent can see. Writes are left off by",
    "# default - turn on what an agent genuinely needs, and no more.",
    "#",
    "# effect: read | write | destructive. It drives every policy default, so correct",
    "# it where the HTTP method misrepresents what the operation does (a POST /search",
    "# that only reads, for instance). A `review:` note marks the cases we could not",
    "# decide safely.",
    "#",
    "# tenant_params are withheld from the agent-facing schema and filled from the",
    "# credential at call time. Add any the generator missed.",
    "#",
    "# omit_params drops a parameter from the tool entirely.",
    ""
  ].join("\n");
  return header + stringifyYaml(manifest, { lineWidth: 100 });
}

function readBaseline(path: string | undefined) {
  if (!path) return undefined;
  const full = resolve(path);
  if (!existsSync(full)) throw new CliError(`no baseline file at ${full}`);
  return JSON.parse(readFileSync(full, "utf8")) as Parameters<typeof scan>[1] extends { baseline?: infer B }
    ? NonNullable<B>
    : never;
}

function isEffect(value: string): value is Effect {
  return value === "read" || value === "write" || value === "destructive";
}

function countBy<T>(items: readonly T[], key: (item: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of items) {
    const k = key(item);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

class CliError extends Error {}

function log(message: string): void {
  process.stdout.write(`${message}\n`);
}

/** Turns expected failures into a clear message and a non-zero exit. */
async function run(fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    if (err instanceof CliError || err instanceof SpecError || err instanceof PolicyError) {
      process.stderr.write(`\nerror: ${err.message}\n`);
      process.exit(1);
    }
    throw err;
  }
}

export type { Policy };

await program.parseAsync(process.argv);
