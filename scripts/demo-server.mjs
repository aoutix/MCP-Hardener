#!/usr/bin/env node
/*
 * Starts a generated server from inside this repo.
 *
 * A generated project's own `server.mjs` resolves `@hmcp/server-runtime` from
 * its own directory, which is correct for a server someone has installed and
 * wrong for the demo's, which is written into `.demo/` and never installed.
 * This bootstrap is the same ~15 lines run from the workspace root instead, so
 * the runtime resolves through `node_modules` without an install step.
 *
 * It is a development entry point, not part of what `hmcp-gen` emits.
 */
import { startFromFiles } from "@hmcp/server-runtime";

const dir = process.env["HMCP_SERVER_DIR"];
if (!dir) {
  process.stderr.write("[hmcp] HMCP_SERVER_DIR is required\n");
  process.exit(1);
}

try {
  await startFromFiles({
    toolsPath: `${dir}/tools.json`,
    policyPath: process.env["HMCP_POLICY"] ?? `${dir}/policy.yaml`,
    baseUrl: process.env["HMCP_BASE_URL"],
    cwd: dir
  });
} catch (err) {
  // stdio carries the protocol, so diagnostics go to stderr.
  process.stderr.write(`[hmcp] failed to start: ${err?.message ?? err}\n`);
  process.exit(1);
}
