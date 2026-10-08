/**
 * Prompt-injection detection for text that originates outside our trust
 * boundary: an OpenAPI description written by whoever owns the API, or a tool
 * description advertised by an upstream MCP server. Both end up in a model's
 * context, so both are attack surface.
 */

export interface InjectionPattern {
  readonly id: string;
  readonly label: string;
  readonly regex: RegExp;
}

export const INJECTION_PATTERNS: readonly InjectionPattern[] = [
  {
    id: "override-instructions",
    label: "attempts to override earlier instructions",
    regex: /\b(ignore|disregard|forget|override)\b[^.?!]{0,40}\b(previous|prior|above|earlier|all)\b[^.?!]{0,30}\b(instruction|prompt|rule|direction|context)/i
  },
  {
    id: "role-injection",
    label: "injects a conversation role",
    regex: /(^|\n)\s*(system|assistant|user|developer)\s*:/i
  },
  {
    id: "role-tag",
    label: "injects a role or instruction tag",
    regex: /<\/?\s*(system|assistant|developer|instructions?|im_start|im_end)\b/i
  },
  {
    id: "new-persona",
    label: "tries to redefine the agent",
    regex: /\byou (are|must|should|will) (now|instead|always)\b/i
  },
  {
    id: "secrecy",
    label: "asks the agent to conceal something from the user",
    regex: /\b(do not|don't|never)\b[^.?!]{0,30}\b(tell|inform|mention|show|reveal|disclose|notify)\b[^.?!]{0,30}\b(user|human|operator|owner)\b/i
  },
  {
    id: "exfiltration",
    label: "directs data somewhere else",
    regex: /\b(exfiltrat\w*|send|post|upload|forward|leak)\b[^.?!]{0,40}\b(to|at)\b[^.?!]{0,20}https?:\/\//i
  },
  {
    id: "credential-request",
    label: "asks for credentials or environment contents",
    regex: /\b(api[_\s-]?key|password|secret|token|credential|\.env|environment variable)s?\b[^.?!]{0,40}\b(include|provide|send|append|attach|pass|read)\b/i
  },
  {
    id: "tool-coercion",
    label: "instructs the agent about other tools",
    regex: /\b(before|after|instead of)\b[^.?!]{0,30}\b(calling|invoking|using|running)\b[^.?!]{0,30}\b(tool|function|this)\b/i
  },
  {
    id: "command-execution",
    label: "embeds a shell command",
    regex: /\b(curl|wget|bash\s+-c|sh\s+-c|powershell|Invoke-WebRequest)\b[^\n]{0,40}(https?:\/\/|\|)/i
  },
  {
    id: "image-beacon",
    label: "embeds a remote image, which can act as an exfiltration channel",
    regex: /!\[[^\]]*\]\(\s*https?:\/\//i
  },
  {
    id: "encoded-payload",
    label: "contains a long encoded blob",
    regex: /\b[A-Za-z0-9+/]{200,}={0,2}\b/
  },
  {
    id: "invisible-characters",
    label: "contains characters invisible to a human reviewer",
    regex: /[­​-‏‪-‮⁠-⁤⁦-⁩﻿]/
  },
  {
    id: "urgency",
    label: "uses urgency to pressure the agent past a check",
    regex: /\b(urgent|immediately|without (asking|confirming|approval)|no need to (ask|confirm)|skip (the )?(confirmation|approval|check))\b/i
  }
];

export interface InjectionHit {
  readonly patternId: string;
  readonly label: string
  readonly excerpt: string;
}

/** Finds injection attempts in untrusted text. */
export function findInjection(text: string): InjectionHit[] {
  if (!text) return [];
  const hits: InjectionHit[] = [];
  for (const pattern of INJECTION_PATTERNS) {
    const match = pattern.regex.exec(text);
    if (!match) continue;
    hits.push({
      patternId: pattern.id,
      label: pattern.label,
      excerpt: excerptAround(text, match.index, match[0].length, pattern.id)
    });
  }
  return hits;
}

function excerptAround(text: string, index: number, length: number, patternId: string): string {
  if (patternId === "invisible-characters") {
    const codePoint = text.codePointAt(index);
    return `U+${codePoint?.toString(16).toUpperCase().padStart(4, "0")} at offset ${index}`;
  }
  const start = Math.max(0, index - 20);
  const end = Math.min(text.length, index + length + 20);
  const snippet = text.slice(start, end).replace(/\s+/g, " ");
  return `${start > 0 ? "…" : ""}${snippet}${end < text.length ? "…" : ""}`;
}

/** Removes the characters a human cannot see, for use when sanitizing. */
export function stripInvisible(text: string): string {
  return text.replace(/[­​-‏‪-‮⁠-⁤⁦-⁩﻿]/g, "");
}
