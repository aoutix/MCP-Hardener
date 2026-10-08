/**
 * Minimal glob matcher for tool-name patterns in policy rules.
 *
 * `*` matches any run of characters, `?` matches one, and `{a,b}` matches any
 * one of the listed alternatives. Everything else is literal. Negation is not
 * supported on purpose: a rule either matches or it does not, and precedence
 * comes from rule order, which is visible in the audit log as a rule id.
 */
export function globToRegExp(pattern: string): RegExp {
  let out = "^";
  let depth = 0;

  for (const ch of pattern) {
    switch (ch) {
      case "*":
        out += ".*";
        break;
      case "?":
        out += ".";
        break;
      case "{":
        out += "(?:";
        depth++;
        break;
      case "}":
        if (depth > 0) {
          out += ")";
          depth--;
        } else {
          out += "\\}";
        }
        break;
      case ",":
        out += depth > 0 ? "|" : "\\,";
        break;
      default:
        out += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }

  // An unclosed brace is a typo. Closing it here would make the pattern match
  // more than its author wrote, so it is treated as a literal instead.
  if (depth > 0) {
    return new RegExp(`^${escapeAll(pattern)}$`);
  }
  return new RegExp(out + "$");
}

function escapeAll(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function globMatch(pattern: string, value: string): boolean {
  return globToRegExp(pattern).test(value);
}

export function anyGlobMatch(patterns: readonly string[], value: string): boolean {
  return patterns.some((p) => globMatch(p, value));
}
