import { describe, expect, it } from "vitest";
import { UpstreamSchema } from "../src/config.js";
import { parseServers, type ClaudeServer } from "../src/client-config.js";
import { expandInterpolation, normalizeUpstreamName, planAdoption, type PlanOptions } from "../src/adopt-plan.js";

/**
 * Translating someone else's MCP config into gateway upstreams.
 *
 * Two properties carry most of the weight here. Every server is either adopted
 * or reported with a reason -- a server that quietly stops working after
 * adoption looks exactly like the gateway doing its job. And the upstream
 * names are stable across runs, because the name becomes the `<server>__`
 * prefix on every tool, and that prefix is the storage key for exposure rows,
 * approvals and binding hashes.
 */

function servers(raw: Record<string, unknown>): ReadonlyMap<string, ClaudeServer> {
  const { servers: parsed, malformed } = parseServers(raw);
  expect(malformed).toEqual([]);
  return parsed;
}

function plan(raw: Record<string, unknown>, options: Partial<PlanOptions> = {}) {
  return planAdoption(servers(raw), { gatewayEntryName: "hmcp", ...options });
}

function skipFor(result: ReturnType<typeof plan>, name: string) {
  const skip = result.skipped.find((s) => s.name === name);
  expect(skip, `expected ${name} to be skipped`).toBeDefined();
  return skip!;
}

describe("upstream names", () => {
  it("normalizes to what UpstreamSchema accepts", () => {
    expect(normalizeUpstreamName("My-Server")).toBe("my_server");
    expect(normalizeUpstreamName("server.one")).toBe("server_one");
    expect(normalizeUpstreamName("__weird__")).toBe("weird");
    expect(normalizeUpstreamName("Atlassian Jira")).toBe("atlassian_jira");
  });

  it("suffixes a collision instead of letting one server shadow another", () => {
    const result = plan({
      "my-server": { command: "node", args: ["a.js"] },
      my_server: { command: "node", args: ["b.js"] }
    });
    expect(result.upstreams.map((u) => u.upstream.name).sort()).toEqual(["my_server", "my_server_2"]);
  });

  it("assigns the same names whatever order the client's JSON was in", () => {
    // Stability matters because the name is a storage key: a prefix that
    // changed between runs would orphan every exposure row under it.
    const forward = plan({
      "my-server": { command: "node", args: ["a.js"] },
      my_server: { command: "node", args: ["b.js"] }
    });
    const backward = plan({
      my_server: { command: "node", args: ["b.js"] },
      "my-server": { command: "node", args: ["a.js"] }
    });
    const nameOf = (r: typeof forward) =>
      Object.fromEntries(r.upstreams.map((u) => [u.originalName, u.upstream.name]));
    expect(nameOf(forward)).toEqual(nameOf(backward));
  });

  it("gives a name with nothing usable in it a placeholder, and reports the mapping", () => {
    const result = plan({ "日本語": { command: "node" } });
    expect(result.upstreams[0]!.upstream.name).toBe("server_1");
    expect(result.nameMap.get("日本語")).toBe("server_1");
  });

  it("records every rename in nameMap and leaves unchanged names out of it", () => {
    const result = plan({ "my-server": { command: "node" }, plain: { command: "node" } });
    expect([...result.nameMap.entries()]).toEqual([["my-server", "my_server"]]);
  });

  it("honours --name, and refuses one that is not a legal upstream name", () => {
    const ok = plan({ "atlassian-jira": { command: "node" } }, { names: new Map([["atlassian-jira", "jira"]]) });
    expect(ok.upstreams[0]!.upstream.name).toBe("jira");

    const bad = plan({ a: { command: "node" } }, { names: new Map([["a", "Not-Legal"]]) });
    expect(skipFor(bad, "a").reason).toMatch(/not a legal upstream name/);
  });

  it("does not hand a new upstream a name the existing gateway already uses", () => {
    const result = plan({ notes: { command: "node" } }, { reservedNames: ["notes"] });
    expect(result.upstreams[0]!.upstream.name).toBe("notes_2");
  });
});

describe("transports it cannot proxy", () => {
  it("skips an SSE server rather than dropping it", () => {
    const result = plan({ legacy: { type: "sse", url: "https://x.example.com/sse" } });
    expect(result.upstreams).toEqual([]);
    expect(skipFor(result, "legacy").reason).toMatch(/SSE/);
    expect(skipFor(result, "legacy").remedy).toMatch(/Streamable HTTP/);
  });

  it("skips a url that will not parse", () => {
    const { servers: parsed } = parseServers({ broken: { type: "http", url: "not a url" } });
    const result = planAdoption(parsed, { gatewayEntryName: "hmcp" });
    expect(skipFor(result, "broken").reason).toMatch(/will not parse/);
  });
});

describe("secrets in HTTP headers", () => {
  const withToken = { tickets: { type: "http", url: "https://mcp.example.com/mcp", headers: { authorization: "Bearer ${TICKETS_TOKEN}" } } };

  it("skips an interpolated header, because gateway.yaml would ship the literal ${...}", () => {
    const result = plan(withToken);
    expect(result.upstreams).toEqual([]);
    const skip = skipFor(result, "tickets");
    expect(skip.reason).toMatch(/authorization header interpolates \$\{TICKETS_TOKEN\}/);
    expect(skip.remedy).toMatch(/--copy-env/);
  });

  it("resolves it under --copy-env and says a secret is now on disk", () => {
    const result = plan(withToken, { copyEnv: true, env: { TICKETS_TOKEN: "t-123" } });
    expect(result.upstreams[0]!.upstream).toMatchObject({
      transport: "http",
      headers: { authorization: "Bearer t-123" }
    });
    expect(result.secretsOnDisk).toBe(true);
  });

  it("skips rather than writing an empty credential when the variable is unset", () => {
    const result = plan(withToken, { copyEnv: true, env: {} });
    expect(skipFor(result, "tickets").reason).toMatch(/not set in this shell/);
  });

  it("passes a literal header through untouched", () => {
    const result = plan({
      tickets: { type: "http", url: "https://mcp.example.com/mcp", headers: { "x-api-version": "2" } }
    });
    expect(result.upstreams[0]!.upstream).toMatchObject({ headers: { "x-api-version": "2" } });
    expect(result.secretsOnDisk).toBe(false);
  });
});

describe("HTTP upstreams and the egress guard", () => {
  it("skips a loopback upstream by default, naming what stands in the way", () => {
    const result = plan({ figma: { type: "http", url: "http://127.0.0.1:3845/mcp" } });
    expect(result.upstreams).toEqual([]);
    const skip = skipFor(result, "figma");
    expect(skip.reason).toMatch(/block_private_ips/);
    expect(skip.remedy).toMatch(/--allow-local-http/);
  });

  it("treats localhost as loopback too, since it resolves to one", () => {
    const result = plan({ local: { type: "http", url: "http://localhost:3845/mcp" } });
    expect(skipFor(result, "local").reason).toMatch(/egress guard refuses/);
  });

  it("adopts it under --allow-local-http and flags that the guard is relaxed globally", () => {
    const result = plan({ figma: { type: "http", url: "http://127.0.0.1:3845/mcp" } }, { allowLocalHttp: true });
    expect(result.upstreams).toHaveLength(1);
    expect(result.egressNeedsLocalHttp).toBe(true);
    expect(result.upstreams[0]!.warnings.join(" ")).toMatch(/every HTTP upstream/);
  });

  it("seeds the hostname, not host:port, so the upstream may change ports", () => {
    const result = plan({ tickets: { type: "http", url: "https://mcp.example.com:8443/mcp" } });
    expect(result.egressAllow).toEqual(["mcp.example.com"]);
  });

  it("pins the port under --strict-egress", () => {
    const result = plan({ tickets: { type: "http", url: "https://mcp.example.com:8443/mcp" } }, { strictEgress: true });
    expect(result.egressAllow).toEqual(["mcp.example.com:8443"]);
  });

  it("does not ask for egress at all when every upstream is stdio", () => {
    const result = plan({ notes: { command: "node" } });
    expect(result.egressAllow).toEqual([]);
    expect(result.egressNeedsLocalHttp).toBe(false);
  });
});

describe("environment", () => {
  it("moves the value to the gateway's entry and forwards it by name", () => {
    // pass_env reads the *gateway's* environment, so a value that only ever
    // lived in the client config has to be carried onto the gateway's entry or
    // the upstream silently loses its credential.
    const result = plan({ github: { command: "npx", args: ["-y", "gh-mcp"], env: { GITHUB_TOKEN: "ghp_x" } } });
    expect(result.upstreams[0]!.upstream).toMatchObject({ pass_env: ["GITHUB_TOKEN"], env: {} });
    expect(result.gatewayEnv).toEqual({ GITHUB_TOKEN: "ghp_x" });
    expect(result.secretsOnDisk).toBe(false);
  });

  it("carries a ${VAR} across verbatim for the client to expand", () => {
    const result = plan({ github: { command: "node", env: { GITHUB_TOKEN: "${GH_PAT}" } } });
    expect(result.gatewayEnv).toEqual({ GITHUB_TOKEN: "${GH_PAT}" });
    expect(result.upstreams[0]!.upstream).toMatchObject({ pass_env: ["GITHUB_TOKEN"] });
  });

  it("lets two servers share a variable when the value is the same", () => {
    const result = plan({
      a: { command: "node", env: { SHARED: "same" } },
      b: { command: "node", env: { SHARED: "same" } }
    });
    expect(result.upstreams).toHaveLength(2);
    expect(result.gatewayEnv).toEqual({ SHARED: "same" });
  });

  it("skips rather than handing one server the other's credential", () => {
    // `pass_env` is a list of names and cannot rename, so one gateway entry
    // can carry exactly one value for API_KEY.
    const result = plan({
      alpha: { command: "node", env: { API_KEY: "key-a" } },
      beta: { command: "node", env: { API_KEY: "key-b" } }
    });
    expect(result.upstreams.map((u) => u.originalName)).toEqual(["alpha"]);
    const skip = skipFor(result, "beta");
    expect(skip.reason).toMatch(/different value than "alpha"/);
    expect(skip.remedy).toMatch(/--copy-env/);
  });

  it("gives each upstream its own env under --copy-env, which is what resolves the clash", () => {
    const result = plan(
      {
        alpha: { command: "node", env: { API_KEY: "key-a" } },
        beta: { command: "node", env: { API_KEY: "key-b" } }
      },
      { copyEnv: true }
    );
    expect(result.upstreams).toHaveLength(2);
    expect(result.gatewayEnv).toEqual({});
    expect(result.upstreams.map((u) => (u.upstream as { env: unknown }).env)).toEqual([
      { API_KEY: "key-a" },
      { API_KEY: "key-b" }
    ]);
    expect(result.secretsOnDisk).toBe(true);
  });
});

describe("the recursion guard", () => {
  it("catches the gateway by its entry name", () => {
    const result = plan({ hmcp: { command: "node", args: ["something.js"] } });
    expect(result.upstreams).toEqual([]);
    expect(skipFor(result, "hmcp").reason).toMatch(/the gateway itself/);
  });

  it("catches it by the command it runs, under any entry name", () => {
    const result = plan({ renamed: { command: "npx", args: ["-y", "hmcp-gateway@0.1.0", "serve"] } });
    expect(skipFor(result, "renamed").reason).toMatch(/the gateway itself/);
  });

  it("catches it by the config it points at", () => {
    const result = plan(
      { other: { command: "node", args: ["cli.js", "serve", "-c", "/abs/.hmcp/gateway.yaml"] } },
      { gatewayConfigPath: "/abs/.hmcp/gateway.yaml" }
    );
    expect(skipFor(result, "other").reason).toMatch(/the gateway itself/);
  });
});

describe("the plan is always schema-valid", () => {
  it("produces upstreams UpstreamSchema accepts", () => {
    // The translator and the schema must not be able to drift: a tightened
    // schema should fail here rather than mid-adoption in someone's terminal.
    const result = plan(
      {
        notes: { command: "node", args: ["n.js"], env: { TOKEN: "t" } },
        "My-Tickets": { type: "http", url: "https://mcp.example.com/mcp", headers: { "x-v": "2" } }
      },
      { allowLocalHttp: true }
    );
    expect(result.upstreams).toHaveLength(2);
    for (const { upstream } of result.upstreams) {
      expect(() => UpstreamSchema.parse(upstream)).not.toThrow();
    }
  });

  it("passes malformed client entries through so one report covers everything", () => {
    const { servers: parsed, malformed } = parseServers({ good: { command: "node" }, bad: "nope" });
    const result = planAdoption(parsed, { gatewayEntryName: "hmcp", malformed });
    expect(result.malformed.map((m) => m.name)).toEqual(["bad"]);
  });
});

describe("expandInterpolation", () => {
  it("expands ${VAR}", () => {
    expect(expandInterpolation("Bearer ${T}", { T: "x" })).toBe("Bearer x");
  });

  it("honours a ${VAR:-default}", () => {
    expect(expandInterpolation("${T:-fallback}", {})).toBe("fallback");
  });

  it("returns undefined for an unset variable with no default", () => {
    // Writing an empty credential would look like a configured one.
    expect(expandInterpolation("Bearer ${T}", {})).toBeUndefined();
  });

  it("treats an empty value as unset, so a default still applies", () => {
    expect(expandInterpolation("${T:-fallback}", { T: "" })).toBe("fallback");
  });
});
