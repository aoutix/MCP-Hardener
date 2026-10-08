import { describe, expect, it } from "vitest";
import { resolve } from "node:path";
import { parsePolicy } from "@hmcp/core";
import { assignToolNames, checkBudget, curate, inferEffect, parseSpec, toToolName } from "../src/index.js";
import type { Operation } from "../src/types.js";

const PETSTORE = resolve(import.meta.dirname, "../../../examples/petstore/openapi.yaml");
const BILLING = resolve(import.meta.dirname, "../../../examples/billing/openapi.yaml");

function operation(overrides: Partial<Operation> = {}): Operation {
  return {
    operationId: "op",
    method: "GET",
    path: "/things",
    summary: "",
    description: "",
    tags: [],
    deprecated: false,
    parameters: [],
    requestBody: null,
    security: [],
    servers: [],
    responseDescription: "",
    ...overrides
  };
}

describe("effect inference", () => {
  it("classifies by HTTP method, the only signal that is reliable across specs", () => {
    expect(inferEffect(operation({ method: "GET" })).effect).toBe("read");
    expect(inferEffect(operation({ method: "HEAD" })).effect).toBe("read");
    expect(inferEffect(operation({ method: "PUT" })).effect).toBe("write");
    expect(inferEffect(operation({ method: "PATCH" })).effect).toBe("write");
    expect(inferEffect(operation({ method: "POST" })).effect).toBe("write");
    expect(inferEffect(operation({ method: "DELETE" })).effect).toBe("destructive");
  });

  it("treats a POST that looks like a search as a write, and asks for confirmation", () => {
    const result = inferEffect(operation({ method: "POST", path: "/pets/search" }));
    expect(result.effect).toBe("write");
    expect(result.review).toMatch(/looks like a read expressed as a POST/);
  });

  it("does not guess a search into the read bucket", () => {
    for (const path of ["/search", "/v1/query", "/reports/export", "/items/lookup"]) {
      expect(inferEffect(operation({ method: "POST", path })).effect, path).toBe("write");
    }
  });

  it("honors an explicit x-hmcp-effect from the spec author", () => {
    const op = { ...operation({ method: "POST", path: "/pets/search" }), "x-hmcp-effect": "read" } as Operation;
    const result = inferEffect(op);
    expect(result.effect).toBe("read");
    expect(result.review).toBeUndefined();
  });
});

describe("tool naming", () => {
  it("snake-cases an operationId", () => {
    expect(toToolName("listPets")).toBe("list_pets");
    expect(toToolName("GetPetById")).toBe("get_pet_by_id");
    expect(toToolName("pets.list-all")).toBe("pets_list_all");
    expect(toToolName("")).toBe("operation");
  });

  it("resolves collisions deterministically, so regenerating gives the same names", () => {
    const ops = [
      operation({ operationId: "get", method: "GET", path: "/pets" }),
      operation({ operationId: "get", method: "GET", path: "/orders/{id}" })
    ];
    const first = assignToolNames(ops);
    const second = assignToolNames([...ops].reverse());
    expect(new Set(first.values()).size).toBe(2);
    for (const op of ops) expect(first.get(op)).toBe(second.get(op));
  });

  it("never produces a duplicate name", () => {
    const ops = Array.from({ length: 5 }, (_, i) =>
      operation({ operationId: "same", method: "GET", path: `/a${i}` })
    );
    const names = [...assignToolNames(ops).values()];
    expect(new Set(names).size).toBe(names.length);
  });
});

describe("curation", () => {
  it("enables only reads by default, so writes are opted into", async () => {
    const spec = await parseSpec(PETSTORE);
    const { manifest } = curate(spec);
    const enabled = manifest.tools.filter((t) => t.enabled);
    expect(enabled.every((t) => t.effect === "read")).toBe(true);
    expect(manifest.tools.some((t) => !t.enabled && t.effect === "destructive")).toBe(true);
  });

  it("drops deprecated operations unless asked to keep them", async () => {
    const spec = await parseSpec(PETSTORE);
    const withDeprecated = {
      ...spec,
      operations: [...spec.operations, operation({ operationId: "oldThing", deprecated: true })]
    };
    expect(curate(withDeprecated).manifest.tools.some((t) => t.name === "old_thing")).toBe(false);
    expect(curate(withDeprecated, { includeDeprecated: true }).manifest.tools.some((t) => t.name === "old_thing")).toBe(
      true
    );
  });

  it("applies include, exclude and tag filters", async () => {
    const spec = await parseSpec(PETSTORE);
    expect(curate(spec, { include: ["get_*"] }).manifest.tools.map((t) => t.name)).toEqual([
      "get_inventory",
      "get_pet"
    ]);
    expect(curate(spec, { exclude: ["delete_*", "purge_*"] }).manifest.tools.map((t) => t.name)).not.toContain(
      "delete_pet"
    );
    expect(curate(spec, { tags: ["store"] }).manifest.tools.map((t) => t.name).sort()).toEqual([
      "get_inventory",
      "purge_inventory"
    ]);
  });

  it("records tenant parameters when the policy names the boundary", async () => {
    const spec = await parseSpec(BILLING);
    const policy = parsePolicy({
      version: 1,
      tenant: { field: "org_id", source: { kind: "env", name: "ORG" } }
    });
    const { manifest } = curate(spec, { tenant: policy.tenant });
    expect(manifest.tools.every((t) => t.tenant_params?.includes("org_id"))).toBe(true);
  });

  it("records no tenant parameters when the policy declares none", async () => {
    const spec = await parseSpec(BILLING);
    const { manifest } = curate(spec);
    expect(manifest.tools.every((t) => t.tenant_params === undefined)).toBe(true);
  });

  it("sorts tools by name so a regenerated manifest diffs cleanly", async () => {
    const spec = await parseSpec(PETSTORE);
    const names = curate(spec).manifest.tools.map((t) => t.name);
    expect(names).toEqual([...names].sort());
  });
});

describe("tool budget", () => {
  it("passes when the enabled set is within budget", () => {
    const manifest = { version: 1 as const, spec: "s", api: { title: "t", version: "1", base_url: "u" }, tools: [] };
    expect(checkBudget(manifest, 10).ok).toBe(true);
  });

  it("fails with an actionable message when the budget is exceeded", () => {
    const manifest = {
      version: 1 as const,
      spec: "s",
      api: { title: "t", version: "1", base_url: "u" },
      tools: Array.from({ length: 5 }, (_, i) => ({
        name: `t${i}`,
        enabled: true,
        effect: "read" as const,
        operationId: `o${i}`,
        method: "GET",
        path: `/t${i}`,
        summary: ""
      }))
    };
    const result = checkBudget(manifest, 3);
    expect(result.ok).toBe(false);
    expect(result.message).toMatch(/5 tools are enabled but the budget is 3/);
    expect(result.message).toMatch(/--include/);
  });

  it("counts only enabled tools", () => {
    const manifest = {
      version: 1 as const,
      spec: "s",
      api: { title: "t", version: "1", base_url: "u" },
      tools: Array.from({ length: 5 }, (_, i) => ({
        name: `t${i}`,
        enabled: i < 2,
        effect: "read" as const,
        operationId: `o${i}`,
        method: "GET",
        path: `/t${i}`,
        summary: ""
      }))
    };
    expect(checkBudget(manifest, 3).ok).toBe(true);
  });
});

describe("spec parsing", () => {
  it("reads an OpenAPI 3 document", async () => {
    const spec = await parseSpec(PETSTORE);
    expect(spec.title).toBe("Petstore");
    expect(spec.originalFormat).toBe("openapi-3");
    expect(spec.servers).toEqual(["https://api.petstore.example.com/v1"]);
    expect(spec.hasSecuritySchemes).toBe(true);
    expect(spec.operations).toHaveLength(8);
  });

  it("merges path-level parameters into each operation", async () => {
    const spec = await parseSpec(PETSTORE);
    const getPet = spec.operations.find((o) => o.operationId === "getPet")!;
    expect(getPet.parameters.map((p) => p.name)).toContain("petId");
  });

  it("resolves $ref so downstream code never sees one", async () => {
    const spec = await parseSpec(PETSTORE);
    const createPet = spec.operations.find((o) => o.operationId === "createPet")!;
    expect(Object.keys(createPet.requestBody!.schema.properties ?? {})).toContain("name");
  });

  it("carries per-operation security overrides", async () => {
    const spec = await parseSpec(BILLING);
    const open = spec.operations.find((o) => o.operationId === "listCustomers")!;
    const closed = spec.operations.find((o) => o.operationId === "listInvoices")!;
    expect(open.security).toEqual([]);
    expect(closed.security).toEqual(["bearerAuth"]);
  });

  it("fails clearly on a document that is not a spec", async () => {
    await expect(parseSpec(resolve(import.meta.dirname, "../package.json"))).rejects.toThrow(/not valid OpenAPI|cannot parse/);
  });
});
