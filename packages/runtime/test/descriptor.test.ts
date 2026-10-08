import { describe, expect, it } from "vitest";
import { parseToolsFile } from "../src/index.js";

/**
 * The tools.json contract. The fields added for the console are additive and
 * defaulted, and the test that matters is that a file generated before they
 * existed still parses: a policy or console upgrade must not strand a server
 * that was generated last month.
 */

/** A tools.json exactly as the generator wrote them before the new fields. */
const legacy = {
  version: 1,
  generated_by: "hmcp-gen",
  api: { title: "Billing", version: "1.0.0", base_url: "https://api.example.com" },
  auth: { kind: "bearer", env: "BILLING_TOKEN" },
  tools: [
    {
      name: "list_invoices",
      description: "List invoices for the caller's organization.",
      effect: "read",
      method: "GET",
      path: "/orgs/{org_id}/invoices",
      inputSchema: {
        type: "object",
        properties: { limit: { type: "integer", minimum: 1, maximum: 50, default: 50 } },
        additionalProperties: false
      },
      bindings: { limit: { in: "query", name: "limit" } },
      bodyMode: "none",
      tenantParams: ["org_id"],
      paginationCap: { param: "limit", max: 50 },
      annotations: { readOnlyHint: true }
    }
  ]
};

describe("backward compatibility", () => {
  it("parses a tools.json written before the console fields existed", () => {
    const parsed = parseToolsFile(legacy);
    expect(parsed.tools).toHaveLength(1);
    expect(parsed.api.title).toBe("Billing");
  });

  it("defaults withheldParams to an empty array rather than undefined", () => {
    const tool = parseToolsFile(legacy).tools[0]!;
    expect(tool.withheldParams).toEqual([]);
    expect(tool.review).toBeUndefined();
    expect(tool.source).toBeUndefined();
  });

  it("leaves generation undefined when absent", () => {
    expect(parseToolsFile(legacy).generation).toBeUndefined();
  });
});

describe("the new fields", () => {
  const modern = {
    ...legacy,
    tools: [
      {
        ...legacy.tools[0],
        withheldParams: [
          { name: "org_id", in: "path", reason: "tenant-scoped; injected from the credential" },
          { name: "x-api-key", in: "header", reason: "credential or hop-by-hop header; set by the server, not the agent" }
        ],
        review: 'POST /pets/search looks like a read expressed as a POST.',
        source: { operationId: "listInvoices", summary: "List invoices.", deprecated: false }
      }
    ],
    generation: {
      spec_format: "openapi-3",
      has_security_schemes: true,
      operations_without_security: ["GET /orgs/{org_id}/customers"],
      skipped: [{ tool: "purge_audit_log", reason: "left off in the manifest" }]
    }
  };

  it("parses and round-trips through JSON", () => {
    const parsed = parseToolsFile(JSON.parse(JSON.stringify(modern)));
    const tool = parsed.tools[0]!;
    expect(tool.withheldParams).toHaveLength(2);
    expect(tool.withheldParams[0]).toEqual({
      name: "org_id",
      in: "path",
      reason: "tenant-scoped; injected from the credential"
    });
    expect(tool.review).toContain("looks like a read");
    expect(tool.source?.operationId).toBe("listInvoices");
    expect(parsed.generation?.skipped[0]!.tool).toBe("purge_audit_log");
  });

  it("accepts a withheld parameter with no location", () => {
    const tools = [{ ...legacy.tools[0], withheldParams: [{ name: "whatever", reason: "because" }] }];
    expect(parseToolsFile({ ...legacy, tools }).tools[0]!.withheldParams[0]!.in).toBeUndefined();
  });

  it("rejects a location that is not a real request location", () => {
    const tools = [{ ...legacy.tools[0], withheldParams: [{ name: "x", in: "elsewhere", reason: "r" }] }];
    expect(() => parseToolsFile({ ...legacy, tools })).toThrow(/withheldParams/);
  });
});

describe("the schema is still closed", () => {
  it("rejects an unknown key on a tool", () => {
    const tools = [{ ...legacy.tools[0], surpriseField: true }];
    expect(() => parseToolsFile({ ...legacy, tools })).toThrow();
  });

  it("rejects an unknown key at the file level", () => {
    expect(() => parseToolsFile({ ...legacy, surpriseField: true })).toThrow();
  });

  it("rejects an unknown key inside generation", () => {
    expect(() => parseToolsFile({ ...legacy, generation: { nope: 1 } })).toThrow();
  });
});
