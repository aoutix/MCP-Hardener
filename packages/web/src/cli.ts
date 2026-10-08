#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Command } from "commander";
import { defaultRegistryPath } from "@hmcp/core";
import { buildRoutes } from "./api.js";
import { createConsoleServer, loadOrCreateToken } from "./http.js";
import { closeStores } from "./model/server.js";

const here = dirname(fileURLToPath(import.meta.url));

const program = new Command()
  .name("hmcp-web")
  .description("Local review console: tools, approvals, pre-approvals, protection detail and the audit log.")
  .option("-p, --port <number>", "port to listen on", "7777")
  .option("-r, --registry <file>", "server registry", defaultRegistryPath())
  .option("--allow-origin <origin...>", "extra origin to accept, for running the Vite dev server")
  .action((options) => {
    const port = Number(options.port);
    const token = loadOrCreateToken();
    const actor = process.env["HMCP_ACTOR"] ?? process.env["USER"] ?? "console";

    const server = createConsoleServer({
      routes: buildRoutes({ registryPath: options.registry as string }),
      token,
      uiDir: join(here, "../dist-ui"),
      port,
      actor,
      allowOrigins: (options.allowOrigin as string[] | undefined) ?? []
    });

    // Loopback only. Anyone who can reach this port and read ~/.hmcp can
    // approve a write, so there is deliberately no flag to widen the bind.
    server.listen(port, "127.0.0.1", () => {
      process.stdout.write(`hmcp console on http://127.0.0.1:${port}/?t=${token}\n`);
      process.stdout.write(`registry: ${options.registry}\n`);
    });

    const shutdown = () => {
      closeStores();
      server.close(() => process.exit(0));
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  });

program.parse();
