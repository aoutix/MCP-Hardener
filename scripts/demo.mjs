#!/usr/bin/env node
/*
 * One command that brings the whole thing up with something to look at:
 * registers a gateway over a real upstream MCP server, puts real rows in the
 * approval queue and the audit log, then starts the console and prints the URL
 * with the gateway still running behind it.
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
 * The seeding drives the gateway over stdio MCP and calls its tools, rather
 * than writing rows into the store directly. It is slower and it is the point:
 * every row on the Approvals page got there through `decide()`, carries a real
 * argument binding, and has the audit records to match. A demo that faked them
 * would be demonstrating the UI and not the enforcement.
 *
 * The gateway is then left running while the console serves, because a
 * gateway's tool surface is something a *live* process publishes. With nothing
 * running the console would correctly report that it cannot confirm the tool
 * list, and the kill switch would correctly refuse to write against it.
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
  gatewayPolicy: join(home, "gateway-policy.yaml"),
  gateway: join(home, "gateway.yaml")
};

const step = (n, name, detail) => process.stdout.write(`  ${n}/4  ${name.padEnd(10)} ${detail}\n`);
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
  "packages/scanner/dist/index.js",
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

/* ------------------------------------------------------------ demo policy */

/*
 * The demo's policy is the example's, with the two paths that decide *where
 * state lands* pointed into `.demo/` and the approval TTL widened. Rewritten
 * through the YAML parser rather than by text substitution so a change to the
 * example's formatting cannot silently stop redirecting the audit log.
 *
 * The TTL is the one rule worth knowing about: the example sets 300 seconds,
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

/* --------------------------------------------------------------- 2. register */

/*
 * One gateway, over an upstream MCP server that actually exists and can be
 * called. `mock-upstream.mjs` is the gateway tests' own fixture: a real MCP
 * server that deliberately advertises a tool whose description carries a
 * prompt-injection payload, and a delete tool that claims to be read-only.
 * Both are what the gateway is for, so the demo shows them rather than a
 * well-behaved stub.
 *
 * Registering costs nothing offline — the console's gateway probe stops at the
 * config and never spawns an upstream.
 */
demoPolicy(join(root, "examples/gateway/policy.yaml"), paths.gatewayPolicy, { ttl });
const gatewayConfig = parseYaml(readFileSync(join(root, "examples/gateway/gateway.yaml"), "utf8"));
gatewayConfig.policy = paths.gatewayPolicy;
gatewayConfig.upstreams = [
  {
    name: "notes",
    transport: "stdio",
    command: process.execPath,
    args: [join(root, "packages/gateway/test/fixtures/mock-upstream.mjs")],
    pass_env: []
  }
];
writeFileSync(
  paths.gateway,
  `# Generated by scripts/demo.mjs from examples/gateway/gateway.yaml, with the\n` +
    `# policy path and the upstream pointed at the demo's own. Rewritten on every run.\n\n` +
    stringifyYaml(gatewayConfig)
);

writeFileSync(
  paths.registry,
  JSON.stringify(
    {
      version: 1,
      servers: [
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
step(2, "register", "notes (gateway over a local MCP upstream)");

/* ------------------------------------------------------------------- 3. seed */

/**
 * One JSON-RPC conversation with a gateway over stdio.
 *
 * `keepAlive` leaves the child running and hands it back, which is how the
 * console step gets a gateway that is still announcing itself. A gateway's tool
 * surface is published by a live process, so a demo that killed it here would
 * show a console that cannot confirm its own tool list.
 */
async function driveGateway(calls, { keepAlive = false } = {}) {
  const child = spawn(
    process.execPath,
    [join(root, "packages/gateway/dist/cli.js"), "serve", "--config", paths.gateway],
    {
      cwd: root,
      env: { ...process.env, HMCP_ACTOR: process.env["HMCP_ACTOR"] ?? "demo" },
      stdio: ["pipe", "pipe", "pipe"]
    }
  );

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
      if (code !== 0 && waiting.size > 0) reject(new Error(stderr.trim() || `gateway exited ${code}`));
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

  let ok = false;
  try {
    await send("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "hmcp-demo", version: "0" }
    });
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    for (const [name, args] of calls) await send("tools/call", { name, arguments: args });
    ok = true;
  } finally {
    if (!keepAlive || !ok) child.kill();
  }
  return keepAlive && ok ? child : undefined;
}

if (opts.seed) {
  const policy = loadPolicy(paths.gatewayPolicy);
  const db = new ApprovalStore(paths.store, root);
  /*
   * The rows the gateway itself writes and reads: its component, and no tenant,
   * because the example policy configures none. Seeding into any other scope
   * would put rows in the database that the gateway cannot see and the console
   * would not show.
   */
  const store = db.scoped({ component: "gateway:hmcp-gateway", tenant: "" });
  db.expireStale();
  const already = store.listPending(100).length;

  const memos = [
    "Acme Corp — October seats",
    "Northwind — annual renewal",
    "Globex — Q4 platform fee",
    "Initech — overage, 13 GB",
    "Umbrella — support retainer",
    "Soylent — migration, phase 2"
  ];

  const calls = [];
  for (let i = 0; i < Math.max(0, wantPending - already); i += 1) {
    calls.push(["notes__create_note", { body: memos[i % memos.length] }]);
  }

  /*
   * A few calls that are *not* held, so the audit log shows the whole range of
   * verdicts rather than a column of identical holds.
   */
  if (already === 0) {
    calls.push(
      // Allowed outright by `allow-reads`.
      ["notes__get_note", { id: "n1" }],
      // Refused by `refuse-deletes`, despite the upstream claiming the tool is
      // read-only — a dishonest annotation the gateway does not take at face
      // value.
      ["notes__delete_note", { id: "n1" }],
      // No such tool. Refused identically to one that policy hides, so probing
      // cannot tell the two apart.
      ["notes__purge_everything", {}]
    );
  }

  if (calls.length > 0) {
    try {
      await driveGateway(calls);
    } catch (err) {
      db.close();
      fail(`could not drive the gateway: ${err.message}`);
    }
  }

  /*
   * A standing grant, so the Pre-approvals page has something in it. Bounded to
   * a body that none of the seeded notes match, so they still go to a human.
   * That is the documented behaviour worth seeing — a grant whose bounds reject
   * the arguments is not a match, and a narrow pre-approval can never *block* a
   * call you would otherwise have been asked about.
   */
  let grants = store.listGrants({ activeOnly: true, limit: 10 }).length;
  if (grants === 0) {
    const grant = store.createGrant({
      tool_match: "notes__create_*",
      effect: "write",
      constraints: { body: { maxLength: 8 } },
      max_uses: 5,
      reason: "very short notes during the demo, 5 uses",
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
        cwd: root
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
          constraints: { body: { maxLength: 8 } },
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
  db.close();

  const auditLines = existsSync(paths.audit)
    ? readFileSync(paths.audit, "utf8").split("\n").filter(Boolean).length
    : 0;
  step(
    3,
    "seed",
    `${pending} pending (${total} rows in all) · ${grants} standing grant · ${auditLines} audit records`
  );
} else {
  step(3, "seed", "skipped (--no-seed)");
}

/* ---------------------------------------------------------------- 4. console */

if (!opts.console) {
  step(4, "console", "skipped (--no-console)");
  process.stdout.write(
    `\nState is ready in ${rel(paths.home)}. Serve it with:\n` +
      `  node packages/web/dist/cli.js --registry ${rel(paths.registry)}\n\n` +
      `Start the gateway too, or the console will say it cannot confirm the tool list:\n` +
      `  node packages/gateway/dist/cli.js serve --config ${rel(paths.gateway)}\n\n`
  );
  process.exit(0);
}

/*
 * A gateway left running behind the console, because the tool surface the
 * console shows is something a live process publishes. Without this the
 * Functions page would correctly report that it cannot confirm what is being
 * served, and the kill switch would correctly refuse to write against an
 * unconfirmed list — both right, and both a confusing first impression.
 */
let gatewayProcess;
try {
  gatewayProcess = await driveGateway([], { keepAlive: true });
  step(4, "gateway", "running, publishing its tool surface");
} catch (err) {
  note(`the gateway could not be started, so the console will show no tools: ${err.message}`);
}

step(4, "console", `starting on port ${port}`);
process.stdout.write("\n");

const consoleProcess = spawn(
  process.execPath,
  [join(root, "packages/web/dist/cli.js"), "--registry", paths.registry, "--port", String(port)],
  {
    cwd: root,
    env: {
      ...process.env,
      HMCP_ACTOR: process.env["HMCP_ACTOR"] ?? "demo"
    },
    stdio: "inherit"
  }
);

const stop = () => {
  gatewayProcess?.kill();
  consoleProcess.kill();
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
consoleProcess.on("close", (code) => {
  gatewayProcess?.kill();
  process.exit(code ?? 0);
});
