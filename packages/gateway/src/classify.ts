import type { Effect, Policy } from "@hmcp/core";
import { globMatch } from "@hmcp/core";
import type { UpstreamTool } from "./upstream.js";

/**
 * Leading verbs that indicate what an upstream tool does, used only as a last
 * resort. Anything these do not match stays unclassified, which under the
 * default posture means denied - a new upstream tool is not reachable until
 * someone classifies it.
 *
 * Matched as the first *word* of a name, not as a literal prefix, because MCP
 * servers in the wild name tools every way at once: `delete_note`,
 * `delete-note`, `deleteNote`, `delete.note`. These were `delete_`-style
 * prefixes, which meant a server using any convention but snake_case got no
 * classification from its name at all -- and that is not merely a missed hint.
 * The name is what contradicts a `readOnlyHint`, so a kebab-case `delete-note`
 * claiming to be read-only was believed, which is exactly the thing this
 * function exists to refuse.
 */
const DESTRUCTIVE_VERBS = ["delete", "remove", "destroy", "purge", "drop", "truncate", "revoke", "wipe"];
const WRITE_VERBS = [
  "create",
  "update",
  "insert",
  "add",
  "set",
  "put",
  "patch",
  "post",
  "write",
  "send",
  "publish",
  "upload",
  "move",
  "rename",
  "assign",
  "approve",
  "cancel",
  "execute",
  "run",
  "invoke",
  "trigger",
  "toggle",
  "enable",
  "disable",
  "start",
  "stop",
  "reset"
];
const READ_VERBS = [
  "get",
  "list",
  "read",
  "fetch",
  "search",
  "find",
  "query",
  "describe",
  "show",
  "count",
  "echo",
  "preview"
];

export interface Classification {
  readonly effect: Effect | undefined;
  /** How the effect was decided, for the audit log and for `hmcp gateway tools`. */
  readonly source: "policy" | "annotation" | "name" | "unclassified";
}

/**
 * Decides what an upstream tool does.
 *
 * Policy rules win, because they are the only signal a human wrote. The MCP
 * annotation hints come next, but a `readOnlyHint` is a claim by the server
 * being gated, so it is trusted only to make a tool *more* restricted, never
 * less: a server cannot mark its own delete tool read-only to slip past the
 * read-only posture.
 */
export function classify(tool: UpstreamTool, localName: string, policy: Policy): Classification {
  const rule = policy.rules.find((r) => globMatch(r.match, localName));
  if (rule?.effect) return { effect: rule.effect, source: "policy" };

  const nameEffect = classifyByName(localName) ?? classifyByName(tool.name);
  const annotations = tool.annotations;

  if (annotations?.destructiveHint === true) return { effect: "destructive", source: "annotation" };

  if (annotations?.readOnlyHint === true) {
    // Honor the hint only when the name does not contradict it.
    if (nameEffect === undefined || nameEffect === "read") {
      return { effect: "read", source: "annotation" };
    }
    return { effect: nameEffect, source: "name" };
  }

  if (annotations?.readOnlyHint === false) {
    // The server says it mutates. Believe that, and take the worse of the two.
    return { effect: nameEffect === "destructive" ? "destructive" : "write", source: "annotation" };
  }

  if (nameEffect) return { effect: nameEffect, source: "name" };
  return { effect: undefined, source: "unclassified" };
}

function classifyByName(name: string): Effect | undefined {
  const first = firstWord(name);
  if (first === undefined) return undefined;
  if (DESTRUCTIVE_VERBS.includes(first)) return "destructive";
  if (WRITE_VERBS.includes(first)) return "write";
  if (READ_VERBS.includes(first)) return "read";
  return undefined;
}

/**
 * The first word of a tool name, under any of the conventions upstreams use.
 *
 * Separators and camelCase boundaries both become word breaks, so
 * `delete_note`, `delete-note`, `deleteNote` and `Delete.Note` all yield
 * `delete`.
 *
 * A `<server>__` namespace is dropped first. It is the gateway's own prefix,
 * not part of what the upstream called the tool, and reading a verb out of it
 * would let an upstream *named* `delete` turn every one of its reads
 * destructive.
 */
function firstWord(name: string): string | undefined {
  const local = name.includes("__") ? name.slice(name.lastIndexOf("__") + 2) : name;
  const spaced = local
    .replace(/[-._:\s]+/g, " ")
    // lower→upper and acronym→word boundaries, so `deleteNote` and `HTTPGet`
    // both split where a reader would split them.
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .trim()
    .toLowerCase();
  const first = spaced.split(" ").find((w) => w.length > 0);
  return first;
}
