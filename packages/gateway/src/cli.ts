#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { Command } from "commander";
import { PolicyError, TenantError } from "@hmcp/core";
import { toSarif, toText } from "@hmcp/scanner";
import { loadGatewayConfig } from "./config.js";
import { Gateway } from "./gateway.js";
import { serveHttp } from "./serve-http.js";

const program = new Command();

program
  .name("hmcp-gateway")
  .description("Policy gateway between an agent and the MCP servers it uses.")
  .version("0.1.0");

program
  .command("serve", { isDefault: true })
  .description("Run the gateway over stdio, or over HTTP with --http.")
  .option("-c, --config <file>", "gateway config", "gateway.yaml")
  .option("--http [port]", "serve over Streamable HTTP on this port instead of stdio")
  .option("--host <address>", "interface to bind when serving over HTTP", "127.0.0.1")
  .option(
    "--allow-host <name>",
    "a Host header this gateway will answer to; repeatable",
    (value: string, previous: string[]) => [...previous, value],
    [] as string[]
  )
  .action(async (options) => {
    await run(async () => {
      const { config, policy } = loadGatewayConfig(options.config as string);
      const gateway = new Gateway({ config, policy });

      let serving: Awaited<ReturnType<typeof serveHttp>> | undefined;
      const shutdown = async () => {
        if (serving) await serving.close();
        await gateway.close();
        process.exit(0);
      };
      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);

      if (options.http !== undefined) {
        /*
         * One process, many clients. Everything the gateway enforces is the
         * same -- these are the handlers the stdio path installs -- but the
         * posture around it is not: stdio is reachable only by whoever
         * spawned it, while this is a socket. It binds to loopback unless
         * told otherwise, and answers only to the host names it was given.
         */
        const port = options.http === true ? 7878 : Number(options.http);
        if (!Number.isInteger(port) || port < 0 || port > 65535) {
          throw new Error(`--http needs a port number, not ${JSON.stringify(options.http)}`);
        }
        await gateway.connectUpstreams();
        const allowHosts = options.allowHost as string[];
        serving = await serveHttp(gateway, {
          port,
          host: options.host as string,
          ...(allowHosts.length > 0 ? { allowedHosts: allowHosts } : {})
        });
        warn(`[hmcp-gateway] listening on http://${options.host}:${serving.port}/mcp`);
        if (options.host !== "127.0.0.1" && allowHosts.length === 0) {
          warn(
            `[hmcp-gateway] bound to ${options.host} but no --allow-host was given, so only ` +
              `requests addressed to localhost will be answered. Pass --allow-host <name> for the ` +
              `name clients will actually use.`
          );
        }
      } else {
        await gateway.start();
      }

      // stdio carries the protocol, so the startup summary goes to stderr.
      const inventory = gateway.inventory();
      const visible = inventory.filter((t) => !t.hidden);
      warn(
        `[hmcp-gateway] ${visible.length} of ${inventory.length} upstream tools exposed ` +
          `across ${config.upstreams.length} server(s); posture ${policy.defaults.mode}`
      );
      const unclassified = visible.filter((t) => t.effect === undefined);
      if (unclassified.length > 0) {
        warn(
          `[hmcp-gateway] ${unclassified.length} tool(s) are unclassified and will be ` +
            `${policy.defaults.on_unclassified === "deny" ? "refused" : "held for approval"}: ` +
            unclassified.map((t) => t.localName).join(", ")
        );
      }
      for (const entry of inventory) {
        if (!entry.injection) continue;
        warn(
          `[hmcp-gateway] ${entry.localName}: injection in the upstream description ` +
            `(${entry.injection.patternIds.join(", ")}) - ${entry.injection.action}`
        );
      }
    });
  });

program
  .command("tools")
  .description("List what the gateway would expose, and how it classified each tool.")
  .option("-c, --config <file>", "gateway config", "gateway.yaml")
  .option("--json", "emit JSON", false)
  .action(async (options) => {
    await run(async () => {
      const { config, policy } = loadGatewayConfig(options.config as string);
      const gateway = new Gateway({ config, policy });
      try {
        // Inspection needs the connect-and-classify phases only, not a stdio
        // session, so the inventory is built and then torn down.
        await gateway.connectUpstreams();
        const inventory = gateway.inventory();

        if (options.json) {
          log(
            JSON.stringify(
              inventory.map((t) => ({
                name: t.localName,
                server: t.upstream.spec.name,
                upstreamName: t.tool.name,
                effect: t.effect ?? null,
                effectSource: t.effectSource,
                hidden: t.hidden,
                injection: t.injection
              })),
              null,
              2
            )
          );
          return;
        }

        log(`${inventory.length} upstream tool(s):`);
        log("");
        for (const entry of inventory) {
          const effect = entry.effect ?? "unclassified";
          const flags = [
            entry.hidden ? "hidden" : null,
            entry.injection ? `injection:${entry.injection.action}` : null
          ].filter(Boolean);
          log(
            `  ${entry.localName.padEnd(40)} ${effect.padEnd(13)} (${entry.effectSource})` +
              (flags.length > 0 ? `  [${flags.join(", ")}]` : "")
          );
        }
      } finally {
        await gateway.close();
      }
    });
  });

program
  .command("scan")
  .description("Scan every upstream server's advertised tool surface.")
  .option("-c, --config <file>", "gateway config", "gateway.yaml")
  .option("--sarif <file>", "also write SARIF")
  .option("--allow-high", "exit 0 even when a high-severity finding is reported", false)
  .action(async (options) => {
    await run(async () => {
      const { config, policy } = loadGatewayConfig(options.config as string);
      const gateway = new Gateway({ config, policy });
      try {
        await gateway.connectUpstreams();
        const result = gateway.scanUpstreams();
        process.stdout.write(toText(result, "upstream MCP servers"));
        if (options.sarif) {
          writeFileSync(resolve(options.sarif as string), toSarif(result, "upstream MCP servers"), "utf8");
          log(`SARIF written to ${options.sarif}`);
        }
        if (!result.ok && !options.allowHigh) process.exitCode = 1;
      } finally {
        await gateway.close();
      }
    });
  });

function log(message: string): void {
  process.stdout.write(`${message}\n`);
}

function warn(message: string): void {
  process.stderr.write(`${message}\n`);
}

async function run(fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    if (err instanceof PolicyError || err instanceof TenantError || (err as Error)?.name === "EgressDenied") {
      warn(`\nerror: ${(err as Error).message}`);
      process.exit(1);
    }
    warn(`\nerror: ${(err as Error)?.message ?? String(err)}`);
    process.exit(1);
  }
}

await program.parseAsync(process.argv);
