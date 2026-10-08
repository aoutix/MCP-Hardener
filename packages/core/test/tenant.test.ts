import { describe, expect, it } from "vitest";
import { parsePolicy, requireTenant, resolveTenant, TenantError, tenantInjection } from "../src/index.js";

function tenantConfig(overrides: Record<string, unknown> = {}) {
  return parsePolicy({
    version: 1,
    tenant: { field: "org_id", source: { kind: "env", name: "HMCP_TENANT" }, ...overrides }
  }).tenant!;
}

describe("resolution", () => {
  it("reads a static value", () => {
    expect(resolveTenant(tenantConfig({ source: { kind: "static", value: "acme" } }))).toBe("acme");
  });

  it("reads an environment variable", () => {
    expect(resolveTenant(tenantConfig(), { env: { HMCP_TENANT: "acme" } })).toBe("acme");
    expect(resolveTenant(tenantConfig(), { env: {} })).toBeUndefined();
    expect(resolveTenant(tenantConfig(), { env: { HMCP_TENANT: "" } })).toBeUndefined();
  });

  it("reads a header case-insensitively", () => {
    const config = tenantConfig({ source: { kind: "header", name: "x-org-id" } });
    expect(resolveTenant(config, { headers: { "X-Org-Id": "acme" } })).toBe("acme");
    expect(resolveTenant(config, { headers: { "x-org-id": ["acme", "globex"] } })).toBe("acme");
    expect(resolveTenant(config, { headers: {} })).toBeUndefined();
  });

  it("reads a claim out of our own credential", () => {
    const payload = Buffer.from(JSON.stringify({ sub: "u1", org: "acme" })).toString("base64url");
    const token = `eyJhbGciOiJub25lIn0.${payload}.sig`;
    const config = tenantConfig({ source: { kind: "jwt-claim", name: "org", token_env: "TOKEN" } });
    expect(resolveTenant(config, { env: { TOKEN: token } })).toBe("acme");
    expect(resolveTenant(config, { env: { TOKEN: `Bearer ${token}` } })).toBe("acme");
    expect(resolveTenant(config, { env: { TOKEN: "not-a-jwt" } })).toBeUndefined();
    expect(resolveTenant(config, { env: {} })).toBeUndefined();
  });
});

describe("requireTenant", () => {
  it("fails loudly and actionably when a required tenant is missing", () => {
    expect(() => requireTenant(tenantConfig(), { env: {} })).toThrow(TenantError);
    expect(() => requireTenant(tenantConfig(), { env: {} })).toThrow(/could not be resolved from env "HMCP_TENANT"/);
  });

  it("permits an absent tenant only when the policy says the deployment is single-tenant", () => {
    expect(requireTenant(tenantConfig({ required: false }), { env: {} })).toBeUndefined();
  });
});

describe("injection", () => {
  it("builds server-side values for each configured target", () => {
    const config = tenantConfig({
      aliases: ["organization_id"],
      inject: ["path", "query", "body", "header"],
      header_name: "X-Org-Id"
    });
    const injection = tenantInjection(config, "acme");
    expect(injection.path).toEqual({ org_id: "acme", organization_id: "acme" });
    expect(injection.query).toEqual({ org_id: "acme" });
    expect(injection.body).toEqual({ org_id: "acme" });
    expect(injection.headers).toEqual({ "X-Org-Id": "acme" });
  });

  it("injects nothing into targets the policy did not name", () => {
    const injection = tenantInjection(tenantConfig({ inject: ["path"] }), "acme");
    expect(injection.query).toEqual({});
    expect(injection.body).toEqual({});
  });
});
