import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { credentialFetch } from "./credential.js";
import { EgressDenied, type EgressGuard } from "@hmcp/core";
import type { Upstream } from "./config.js";

export interface UpstreamTool {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: unknown;
  readonly annotations:
    | { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; title?: string }
    | undefined;
}

/**
 * A connection to one upstream MCP server. HTTP upstreams are vetted by the
 * egress guard before a connection is opened, so the allowlist and the SSRF
 * checks apply to servers we did not build just as they do to a REST API.
 */
export class UpstreamConnection {
  readonly client: Client;
  private tools: UpstreamTool[] = [];

  private constructor(readonly spec: Upstream, client: Client) {
    this.client = client;
  }

  static async connect(spec: Upstream, egress: EgressGuard): Promise<UpstreamConnection> {
    const client = new Client(
      { name: "hmcp-gateway", version: "0.1.0" },
      // The gateway does not forward sampling or elicitation on the upstream's
      // behalf: an upstream server must not be able to prompt the human
      // through us, because the human's trust is in the gateway's prompts.
      { capabilities: {} }
    );

    if (spec.transport === "stdio") {
      const env: Record<string, string> = { ...spec.env };
      for (const name of spec.pass_env) {
        const value = process.env[name];
        if (value !== undefined) env[name] = value;
      }
      // A child process gets only what the config names, so the gateway's own
      // credentials are not handed to every upstream by default.
      await client.connect(
        new StdioClientTransport({
          command: spec.command,
          args: spec.args,
          env,
          ...(spec.cwd ? { cwd: spec.cwd } : {}),
          stderr: "pipe"
        })
      );
    } else {
      const check = egress.check(spec.url, "POST");
      if (!check.ok) {
        throw new EgressDenied(
          `upstream "${spec.name}" at ${spec.url} is not permitted by egress policy: ${check.reason}`,
          check.code ?? "refused"
        );
      }
      // Resolving here refuses an upstream URL that points into private space
      // before any connection is attempted.
      await egress.resolveVerified(new URL(spec.url).hostname);
      await client.connect(
        new StreamableHTTPClientTransport(new URL(spec.url), {
          requestInit: { headers: spec.headers },
          /*
           * One client for the process, with the headers decided at send time
           * rather than baked in here. This is what lets a caller's own
           * credential reach the upstream without the gateway ever storing
           * one, and it re-runs the egress check per request instead of only
           * at connect. Outside a tool call -- here, and for tool discovery
           * -- there is no credential in scope, so these requests carry the
           * configured headers and nothing else.
           */
          fetch: credentialFetch(spec, egress)
        })
      );
    }

    const connection = new UpstreamConnection(spec, client);
    await connection.refreshTools();
    return connection;
  }

  async refreshTools(): Promise<UpstreamTool[]> {
    const capabilities = this.client.getServerCapabilities();
    if (!capabilities?.tools) {
      this.tools = [];
      return this.tools;
    }
    const result = await this.client.listTools();
    this.tools = result.tools.map((tool) => ({
      name: tool.name,
      description: tool.description ?? "",
      inputSchema: tool.inputSchema,
      annotations: tool.annotations as UpstreamTool["annotations"]
    }));
    return this.tools;
  }

  listTools(): readonly UpstreamTool[] {
    return this.tools;
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
    return this.client.callTool({ name, arguments: args });
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}
