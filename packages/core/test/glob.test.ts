import { describe, expect, it } from "vitest";
import { anyGlobMatch, globMatch } from "../src/index.js";

describe("glob matching", () => {
  it("matches literals exactly", () => {
    expect(globMatch("get_pet", "get_pet")).toBe(true);
    expect(globMatch("get_pet", "get_pets")).toBe(false);
    expect(globMatch("get_pet", "x_get_pet")).toBe(false);
  });

  it("matches with * and ?", () => {
    expect(globMatch("get_*", "get_pet")).toBe(true);
    expect(globMatch("*_pet", "delete_pet")).toBe(true);
    expect(globMatch("*", "anything")).toBe(true);
    expect(globMatch("get_pet?", "get_pets")).toBe(true);
    expect(globMatch("get_pet?", "get_pet")).toBe(false);
  });

  it("matches brace alternatives, so one rule can cover a family of tools", () => {
    expect(globMatch("{get,list}_*", "get_invoice")).toBe(true);
    expect(globMatch("{get,list}_*", "list_invoices")).toBe(true);
    expect(globMatch("{get,list}_*", "create_invoice")).toBe(false);
    expect(globMatch("{delete,purge}_*", "purge_audit_log")).toBe(true);
  });

  it("does not let a regex metacharacter in a pattern widen the match", () => {
    expect(globMatch("get.pet", "getxpet")).toBe(false);
    expect(globMatch("get.pet", "get.pet")).toBe(true);
    expect(globMatch("a+", "aaa")).toBe(false);
    expect(globMatch("a+", "a+")).toBe(true);
    expect(globMatch("(get|delete)_pet", "get_pet")).toBe(false);
  });

  it("treats an unclosed brace as a literal rather than matching more than written", () => {
    expect(globMatch("{get,list", "get")).toBe(false);
    expect(globMatch("{get,list", "{get,list")).toBe(true);
  });

  it("anchors at both ends", () => {
    expect(globMatch("pet", "the_pet_tool")).toBe(false);
  });

  it("checks a list of patterns", () => {
    expect(anyGlobMatch(["get_*", "list_*"], "list_pets")).toBe(true);
    expect(anyGlobMatch(["get_*", "list_*"], "create_pet")).toBe(false);
    expect(anyGlobMatch([], "anything")).toBe(false);
  });
});
