#!/usr/bin/env node
/*
 * One command that brings the whole thing up with something to look at:
 * generates a server from the example spec, registers it alongside a gateway,
 * puts real rows in the approval queue and the audit log, then starts the
 * console and prints the URL.
 *
 *   npm run demo              set up if needed, then serve
 *   npm run demo -- --reset   throw the state away and build it again
 *   npm run demo -- --help    the rest of the flags
 *
 * Everything it writes lives in `.demo/` at the repo root and nothing it does
 * touches `~/.hmcp`. That matters: `~/.hmcp` is where a real console keeps its
 * registry, its approvals and an audit log of real calls, and a demo that
 * seeds fake approvals into it would be writing fiction into that record.
 *
 * The seeding drives the generated server over stdio MCP and calls its tools,
 * rather than writing rows into the store directly. It is slower and it is the
 * point: every row on the Approvals page got there through `decide()`, carries
 * a real argument binding, and has the audit records to match. A demo that
 * faked them would be demonstrating the UI and not the enforcement.
 */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { readFileSync } from "node:fs";
import { ApprovalStore, AuditLog, loadPolicy } from "@hmcp/core";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rel = (p) => relative(process.cwd(), p) || ".";

/* ------------------------------------------------------------------ options */

/*
 * The three opt-outs are spelled `--no-*` because that is how they read, but
 * `parseArgs` has no notion of a negated boolean — it would reject them as
 * unknown — so they are declared under the names they are typed with and
 * inverted below.
 */
let opts;
try {
  ({ values: opts } = parseArgs({
    options: {
      reset: { type: "boolean", default: false },
      port: { type: "string", default: "7777" },
      pending: { type: "string", default: "4" },
      "no-build": { type: "boolean", default: false },
      "no-console": { type: "boolean", default: false },
      "no-seed": { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false }
    }
  }));
} catch (err) {
  fail(`${err.message}\nRun with --help for the options.`);
}

opts.build = !opts["no-build"];
opts.console = !opts["no-console"];
opts.seed = !opts["no-seed"];

if (opts.help) {
  process.stdout.write(
    `hardened-mcp demo — generate, register, seed and serve, in one command.\n\n` +
      `  --reset           delete .demo/ and build it from scratch\n` +
      `  --port <n>        console port (default 7777)\n` +
      `  --pending <n>     pending approvals to top the queue up to (default 4)\n` +
      `  --no-seed         leave the approval queue and audit log alone\n` +
      `  --no-build        skip the build check, even if dist/ is missing\n` +
      `  --no-console      set the state up and stop, without serving\n\n` +
      `State lives in .demo/ and is disposable. ~/.hmcp is never touched.\n`
  );
  process.exit(0);
}

const port = Number(opts.port);
if (!Number.isInteger(port) || port < 1 || port > 65535) fail(`--port must be a port number, got "${opts.port}"`);
const wantPending = Number(opts.pending);
if (!Number.isInteger(wantPending) || wantPending < 0) fail(`--pending must be a count, got "${opts.pending}"`);

/* -------------------------------------------------------------------- paths */

const home = join(root, ".demo");
const paths = {
  home,
  registry: join(home, "servers.json"),
  store: join(home, "approvals.sqlite"),
  audit: join(home, "audit.jsonl"),
  manifest: join(home, "billing.manifest.yaml"),
  billingPolicy: join(home, "billing-policy.yaml"),
  billing: join(home, "billing"),
  gatewayPolicy: join(home, "gateway-policy.yaml"),
  gateway: join(home, "gateway.yaml")
};

const step = (n, name, detail) => process.stdout.write(`  ${n}/5  ${name.padEnd(10)} ${detail}\n`);
const note = (text) => process.stdout.write(`       ${text}\n`);

function fail(message) {
  process.stderr.write(`demo: ${message}\n`);
  process.exit(1);
}

/** Runs a command to completion, capturing output. Never throws on exit code. */
function run(command, args, env = {}) {
  return new Promise((done) => {
    const child = spawn(command, args, { cwd: root, env: { ...process.env, ...env } });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.on("error", (err) => done({ code: -1, out: String(err.message) }));
    child.on("close", (code) => done({ code, out }));
  });
}

process.stdout.write(`\nhardened-mcp demo\n`);
if (opts.reset && existsSync(paths.home)) {
  rmSync(paths.home, { recursive: true, force: true });
  note(`reset: removed ${rel(paths.home)}`);
}
mkdirSync(paths.home, { recursive: true });

/* ------------------------------------------------------------------ 1. build */

const builtPaths = [
  "packages/core/dist/index.js",
  "packages/runtime/dist/index.js",
  "packages/scanner/dist/index.js",
  "packages/generator/dist/cli.js",
  "packages/gateway/dist/cli.js",
  "packages/web/dist/cli.js",
  "packages/web/dist-ui/index.html"
];

const missing = builtPaths.filter((p) => !existsSync(join(root, p)));
if (missing.length > 0 && opts.build) {
  step(1, "build", `${missing.length} output(s) missing — building`);
  const built = await run("npm", ["run", "build"]);
  if (built.code !== 0) {
    process.stderr.write(built.out);
    fail("the build failed; fix that and run the demo again");
  }
  const still = builtPaths.filter((p) => !existsSync(join(root, p)));
  if (still.length > 0) fail(`the build reported success but ${still[0]} is still missing`);
} else if (missing.length > 0) {
  fail(`${missing[0]} is missing and --no-build was passed; run "npm run build"`);
} else {
  step(1, "build", "already built");
}

/* --------------------------------------------------------------- 2. generate */

/*
 * The demo's policy is the example's, with the three paths that decide *where
 * state lands* pointed into `.demo/` and the approval TTL widened. Rewritten
 * through the YAML parser rather than by text substitution so a change to the
 * example's formatting cannot silently stop redirecting the audit log.
 *
 * The TTL is the one rule worth knowing about: the example sets 180 seconds,
 * which is a sound thing for a real deployment to do and useless here, because
 * the rows expire while you are still reading the page they are on.
 */
function demoPolicy(sourcePath, outPath, { ttl }) {
  const policy = parseYaml(readFileSync(sourcePath, "utf8"));
  const wasTtl = policy.approvals?.ttl_seconds ?? "the default";
  policy.approvals = { ...policy.approvals, store_path: paths.store, ttl_seconds: ttl };
  policy.audit = { ...policy.audit, path: paths.audit };
  writeFileSync(
    outPath,
    `# Generated by scripts/demo.mjs from ${relative(root, sourcePath)}.\n` +
      `# Edit that file, not this one — this is rewritten on every run.\n` +
      `#\n` +
      `# Three changes from the original, and nothing else:\n` +
      `#   approvals.store_path  -> .demo/, so the demo cannot write into ~/.hmcp\n` +
      `#   audit.path            -> .demo/, for the same reason\n` +
      `#   approvals.ttl_seconds -> ${ttl}, was ${wasTtl}; seeded rows have to\n` +
      `#                            outlive the person reading the page they are on\n\n` +
      stringifyYaml(policy)
  );
  return policy;
}

const ttl = 60 * 60 * 8;
demoPolicy(join(root, "examples/billing/policy.yaml"), paths.billingPolicy, { ttl });

if (!existsSync(join(paths.billing, "tools.json")) || opts.reset) {
  const planned = await run("node", [
    "packages/generator/dist/cli.js",
    "plan",
    "examples/billing/openapi.yaml",
    "-p",
    paths.billingPolicy,
    "-o",
    paths.manifest,
    // Writes are off by default and the manifest is where a human turns them
    // on. The demo needs the write path populated, so it enables them here —
    // which is the one curation decision it makes on your behalf.
    "--enable",
    "read",
    "write"
  ]);
  if (planned.code !== 0) {
    process.stderr.write(planned.out);
    fail("hmcp-gen plan failed");
  }

  const built = await run("node", [
    "packages/generator/dist/cli.js",
    "build",
    "-m",
    paths.manifest,
    "-p",
    paths.billingPolicy,
    "-o",
    paths.billing,
    // So the emitted package.json points at this checkout rather than at a
    // version on npm, and the generated server is runnable after an install.
    "--runtime",
    `file:${join(root, "packages/runtime")}`
  ]);

  /*
   * A non-zero exit here is the example working as intended, not a failure.
   * `examples/billing` is a deliberately hostile spec — a live-looking Stripe
   * key and two prompt injections in its descriptions — so the self-scan finds
   * high-severity problems and refuses to bless the output. The files are
   * written anyway, which is what lets the demo carry on and what lets you see
   * the findings on the Protection page.
   */
  const findings = /(\d+) high, (\d+) medium/.exec(built.out);
  if (!existsSync(join(paths.billing, "tools.json"))) {
    process.stderr.write(built.out);
    fail("hmcp-gen build wrote no tools.json");
  }
  step(2, "generate", `billing → ${rel(paths.billing)}${findings ? ` · scan: ${findings[0]}` : ""}`);
  if (built.code !== 0) {
    note(`the build exited ${built.code}: the example spec is hostile on purpose and the scan says so.`);
    note(`the files were written regardless — see Protection in the console for each finding.`);
  }
} else {
  step(2, "generate", `billing already generated in ${rel(paths.billing)}`);
}

/* --------------------------------------------------------------- 3. register */

/*
 * Both kinds of server, because they are the two halves of the project and the
 * console renders them differently: a generated server has a tool surface the
 * console can show and switch off, while a gateway's surface belongs to its
 * upstreams and is discovered when it connects, so the console deliberately
 * declines to guess at it.
 *
 * Registering the gateway costs nothing offline — the console's gateway probe
 * stops at the config and never spawns an upstream.
 */
demoPolicy(join(root, "examples/gateway/policy.yaml"), paths.gatewayPolicy, { ttl });
const gatewayConfig = parseYaml(readFileSync(join(root, "examples/gateway/gateway.yaml"), "utf8"));
gatewayConfig.policy = paths.gatewayPolicy;
writeFileSync(
  paths.gateway,
  `# Generated by scripts/demo.mjs from examples/gateway/gateway.yaml, with the\n` +
    `# policy path pointed at the demo's copy. Rewritten on every run.\n\n` +
    stringifyYaml(gatewayConfig)
);

writeFileSync(
  paths.registry,
  JSON.stringify(
    {
      version: 1,
      servers: [
        {
          id: "billing",
          kind: "generated",
          label: "Billing",
          dir: paths.billing,
          added_at: new Date().toISOString()
        },
        {
          id: "notes",
          kind: "gateway",
          label: "Notes gateway",
          config_path: paths.gateway,
          added_at: new Date().toISOString()
        }
      ]
    },
    null,
    2
  ) + "\n"
);
step(3, "register", "billing (generated) · notes (gateway)");

/* ------------------------------------------------------------------- 4. seed */

/** One JSON-RPC conversation with a freshly spawned generated server. */
async function driveServer(calls) {
  const child = spawn(process.execPath, [join(root, "scripts/demo-server.mjs")], {
    cwd: root,
    env: {
      ...process.env,
      BILLING_ORG_ID: process.env["BILLING_ORG_ID"] ?? "org_demo",
      HMCP_SERVER_DIR: paths.billing,
      HMCP_POLICY: paths.billingPolicy,
      HMCP_ACTOR: process.env["HMCP_ACTOR"] ?? "demo"
    },
    stdio: ["pipe", "pipe", "pipe"]
  });

  let stderr = "";
  child.stderr.on("data", (d) => (stderr += d));

  const waiting = new Map();
  let buffer = "";
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    for (let nl = buffer.indexOf("\n"); nl >= 0; nl = buffer.indexOf("\n")) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      const settle = waiting.get(message.id);
      if (settle) {
        waiting.delete(message.id);
        settle(message);
      }
    }
  });

  const exited = new Promise((_, reject) =>
    child.on("close", (code) => {
      if (code !== 0 && waiting.size > 0) reject(new Error(stderr.trim() || `server exited ${code}`));
    })
  );

  let nextId = 1;
  const send = (method, params) => {
    const id = nextId++;
    return Promise.race([
      new Promise((settle) => {
        waiting.set(id, settle);
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      }),
      exited
    ]);
  };

  try {
    await send("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "hmcp-demo", version: "0" }
    });
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    for (const [name, args] of calls) await send("tools/call", { name, arguments: args });
  } finally {
    child.kill();
  }
}

if (opts.seed) {
  const policy = loadPolicy(paths.billingPolicy);
  const store = new ApprovalStore(paths.store, paths.billing);
  store.expireStale();
  const already = store.listPending(100).length;

  const memos = [
    "Acme Corp — October seats",
    "Northwind — annual renewal",
    "Globex — Q4 platform fee",
    "Initech — overage, 13 GB",
    "Umbrella — support retainer",
    "Soylent — migration, phase 2"
  ];
  const amounts = [2400, 18900, 47500, 650, 9900, 31200];

  const calls = [];
  for (let i = 0; i < Math.max(0, wantPending - already); i += 1) {
    calls.push([
      "create_invoice",
      { amount: amounts[i % amounts.length], currency: "usd", memo: memos[i % memos.length] }
    ]);
  }

  /*
   * A few calls that are *not* held, so the audit log shows the whole range of
   * verdicts rather than a column of identical holds. The reads are allowed and
   * then fail at the egress step, because the example's upstream host is
   * fictional — the decision is recorded before the request is built, which is
   * exactly the distinction the Protection page makes.
   */
  if (already === 0) {
    calls.push(
      // `list_customers` takes nothing: its pagination and tenant parameters
      // were both withheld from the agent-facing schema.
      ["list_customers", {}],
      ["get_invoice", { invoice_id: "in_demo_001" }],
      // Denied outright by the `no-transfers` rule.
      ["create_transfer", { amount: 5000, destination: "acct_demo" }],
      // Allowed by the rule but refused by its argument bounds, before a human
      // is ever asked: the cap is 50000.
      ["create_invoice", { amount: 90000, currency: "usd", memo: "over the amount cap" }],
      // Same, on the currency enum.
      ["create_invoice", { amount: 1200, currency: "eur", memo: "non-usd currency" }]
    );
  }

  if (calls.length > 0) {
    try {
      await driveServer(calls);
    } catch (err) {
      store.close();
      fail(`could not drive the generated server: ${err.message}`);
    }
  }

  /*
   * A standing grant, so the Pre-approvals page has something in it. Bounded at
   * 100 units deliberately: none of the seeded invoices match it, so they still
   * go to a human. That is the documented behaviour worth seeing — a grant whose
   * bounds reject the arguments is not a match, and a narrow pre-approval can
   * never *block* a call you would otherwise have been asked about.
   */
  let grants = store.listGrants({ activeOnly: true, limit: 10 }).length;
  if (grants === 0) {
    const grant = store.createGrant({
      tool_match: "create_invoice",
      effect: "write",
      constraints: { amount: { min: 1, max: 100 }, currency: { enum: ["usd"] } },
      max_uses: 5,
      reason: "trivial USD invoices during the demo, 5 uses",
      created_by: process.env["HMCP_ACTOR"] ?? "demo",
      expires_at: Date.now() + 7 * 24 * 60 * 60 * 1000
    });

    // appendStrict and withdraw-on-failure, mirroring what the console does:
    // the requirement is that no pre-approval exists unaudited.
    try {
      new AuditLog({
        config: policy.audit,
        actor: process.env["HMCP_ACTOR"] ?? "demo",
        component: "hmcp-web",
        cwd: paths.billing
      }).appendStrict({
        tool: grant.tool_match,
        effect: grant.effect,
        decision: "approve",
        rule_id: "standing_grant.create",
        reason:
          `standing grant ${grant.id} created by ${grant.created_by}: ${grant.reason} ` +
          `(matches ${grant.tool_match}, ${grant.max_uses} use(s), ` +
          `expires ${new Date(grant.expires_at).toISOString()})`,
        outcome: "completed",
        grant_id: grant.id,
        args_redacted: {
          tool_match: grant.tool_match,
          effect: grant.effect,
          constraints: { amount: { min: 1, max: 100 }, currency: { enum: ["usd"] } },
          max_uses: grant.max_uses,
          expires_at: grant.expires_at
        }
      });
      grants = 1;
    } catch (err) {
      store.revokeGrant(grant.id, "system");
      note(`the standing grant was withdrawn because it could not be audited: ${err.message}`);
    }
  }

  const pending = store.listPending(100).length;
  const total = store.list(200).length;
  store.close();

  const auditLines = existsSync(paths.audit)
    ? readFileSync(paths.audit, "utf8").split("\n").filter(Boolean).length
    : 0;
  step(
    4,
    "seed",
    `${pending} pending (${total} rows in all) · ${grants} standing grant · ${auditLines} audit records`
  );
} else {
  step(4, "seed", "skipped (--no-seed)");
}

/* ---------------------------------------------------------------- 5. console */

if (!opts.console) {
  step(5, "console", "skipped (--no-console)");
  process.stdout.write(
    `\nState is ready in ${rel(paths.home)}. Serve it with:\n` +
      `  BILLING_ORG_ID=org_demo node packages/web/dist/cli.js --registry ${rel(paths.registry)}\n\n`
  );
  process.exit(0);
}

step(5, "console", `starting on port ${port}`);
process.stdout.write("\n");

/*
 * `BILLING_ORG_ID` is not optional. The example policy sets `tenant.required`
 * sourced from that variable, so without it every tool is denied, the console
 * reports that tenant scoping resolved to nothing, and the server's reach
 * collapses to `locked` — correct behaviour that looks exactly like a bug.
 */
const consoleProcess = spawn(
  process.execPath,
  [join(root, "packages/web/dist/cli.js"), "--registry", paths.registry, "--port", String(port)],
  {
    cwd: root,
    env: {
      ...process.env,
      BILLING_ORG_ID: process.env["BILLING_ORG_ID"] ?? "org_demo",
      HMCP_ACTOR: process.env["HMCP_ACTOR"] ?? "demo"
    },
    stdio: "inherit"
  }
);

const stop = () => consoleProcess.kill();
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
consoleProcess.on("close", (code) => process.exit(code ?? 0));
