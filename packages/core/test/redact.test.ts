import { describe, expect, it } from "vitest";
import { findSecrets, redact, redactArgs } from "../src/index.js";

describe("key-based redaction", () => {
  it("removes values under secret-sounding keys", () => {
    const out = redactArgs({
      username: "alice",
      password: "hunter2",
      api_key: "whatever",
      apiKey: "whatever",
      client_secret: "x",
      refresh_token: "y",
      Authorization: "Basic abc",
      nested: { session_id: "s", keep: "visible" }
    });
    expect(out["username"]).toBe("alice");
    expect(out["password"]).toBe("[redacted:key]");
    expect(out["api_key"]).toBe("[redacted:key]");
    expect(out["apiKey"]).toBe("[redacted:key]");
    expect(out["client_secret"]).toBe("[redacted:key]");
    expect(out["refresh_token"]).toBe("[redacted:key]");
    expect(out["Authorization"]).toBe("[redacted:key]");
    expect((out["nested"] as Record<string, unknown>)["session_id"]).toBe("[redacted:key]");
    expect((out["nested"] as Record<string, unknown>)["keep"]).toBe("visible");
  });

  it("does not redact words that merely contain a secret-ish substring", () => {
    const out = redactArgs({ tokenizer: "bpe", passport_country: "NL", author: "alice" });
    expect(out["tokenizer"]).toBe("bpe");
    expect(out["passport_country"]).toBe("NL");
    expect(out["author"]).toBe("alice");
  });

  it("accepts extra key names from policy", () => {
    const out = redactArgs({ internal_ref: "abc" }, ["internal_ref"]);
    expect(out["internal_ref"]).toBe("[redacted:key]");
  });
});

describe("value-based redaction", () => {
  it("removes secret-shaped values whatever key they sit under", () => {
    const cases: [string, string][] = [
      ["sk_live_abcdefghijklmnopqrst", "stripe-key"],
      ["ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "github-token"],
      ["AKIAIOSFODNN7EXAMPLE", "aws-access-key"],
      ["xoxb-1234567890-abcdefghij", "slack-token"],
      ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk", "jwt"],
      ["-----BEGIN RSA PRIVATE KEY-----\nMIIE", "private-key"],
      ["https://admin:s3cret@internal.example.com/db", "basic-auth-url"],
      ["sk-ant-api03-abcdefghijklmnopqrstuvwx", "anthropic-key"]
    ];
    for (const [value, expected] of cases) {
      expect(redactArgs({ note: value })["note"], value).toBe(`[redacted:${expected}]`);
    }
  });

  it("leaves ordinary text alone", () => {
    const out = redactArgs({ note: "Create an invoice for 500 usd", id: "cust_12345" });
    expect(out["note"]).toBe("Create an invoice for 500 usd");
    expect(out["id"]).toBe("cust_12345");
  });

  it("truncates a very long string rather than logging it whole", () => {
    const out = redactArgs({ blob: "a".repeat(2000) }) as Record<string, string>;
    expect(out["blob"]!.length).toBeLessThan(600);
    expect(out["blob"]).toMatch(/truncated 1488 chars/);
  });
});

describe("robustness", () => {
  it("never mutates the input", () => {
    const input = { password: "hunter2", nested: { a: 1 } };
    const snapshot = JSON.stringify(input);
    redact(input);
    expect(JSON.stringify(input)).toBe(snapshot);
  });

  it("survives a cycle, because it sits on the path to the audit log", () => {
    const node: Record<string, unknown> = { name: "a" };
    node["self"] = node;
    expect(() => JSON.stringify(redact(node))).not.toThrow();
    expect(JSON.stringify(redact(node))).toContain("[redacted:circular]");
  });

  it("produces JSON-serializable output for exotic values", () => {
    const out = redact({
      when: new Date("2026-01-01T00:00:00Z"),
      big: 10n,
      fn: () => 1,
      sym: Symbol("s"),
      inf: Infinity,
      map: new Map([["k", "v"]]),
      set: new Set([1, 2]),
      undef: undefined
    });
    expect(() => JSON.stringify(out)).not.toThrow();
    const parsed = JSON.parse(JSON.stringify(out)) as Record<string, unknown>;
    expect(parsed["when"]).toBe("2026-01-01T00:00:00.000Z");
    expect(parsed["big"]).toBe("10");
    expect(parsed["inf"]).toBe("Infinity");
  });

  it("caps depth and array length", () => {
    let deep: unknown = "bottom";
    for (let i = 0; i < 40; i++) deep = { next: deep };
    expect(JSON.stringify(redact(deep))).toContain("[redacted:max-depth]");
    expect(JSON.stringify(redact(Array.from({ length: 500 }, (_, i) => i)))).toContain("truncated 400 items");
  });
});

describe("findSecrets", () => {
  it("reports what it found so the scanner can name it", () => {
    const hits = findSecrets("set Authorization: Bearer abcdefghijklmnopqrstuvwxyz and key AKIAIOSFODNN7EXAMPLE");
    expect(hits.map((h) => h.patternId).sort()).toEqual(["aws-access-key", "bearer-header"]);
  });

  it("returns nothing for clean prose", () => {
    expect(findSecrets("Returns the list of pets for the current organization.")).toEqual([]);
  });
});
