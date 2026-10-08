import type { Effect, Policy } from "@hmcp/core";
import { globMatch } from "@hmcp/core";
import type { UpstreamTool } from "./upstream.js";

/**
 * Name shapes that indicate what an upstream tool does, used only as a last
 * resort. Anything these do not match stays unclassified, which under the
 * default posture means denied - a new upstream tool is not reachable until
 * someone classifies it.
 */
const DESTRUCTIVE_PREFIXES = ["delete_", "remove_", "destroy_", "purge_", "drop_", "truncate_", "revoke_", "wipe_"];
const WRITE_PREFIXES = [
  "create_",
  "update_",
  "insert_",
  "add_",
  "set_",
  "put_",
  "patch_",
  "post_",
  "write_",
  "send_",
  "publish_",
  "upload_",
  "move_",
  "rename_",
  "assign_",
  "approve_",
  "cancel_",
  "execute_",
  "run_",
  "invoke_"
];
const READ_PREFIXES = ["get_", "list_", "read_", "fetch_", "search_", "find_", "query_", "describe_", "show_", "count_"];

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
  const lower = name.toLowerCase();
  if (DESTRUCTIVE_PREFIXES.some((p) => lower.startsWith(p))) return "destructive";
  if (WRITE_PREFIXES.some((p) => lower.startsWith(p))) return "write";
  if (READ_PREFIXES.some((p) => lower.startsWith(p))) return "read";
  return undefined;
}
