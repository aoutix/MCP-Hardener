/**
 * Whether an upstream's name for a tool can be used safely.
 *
 * A tool name is not just text on a screen. It is the key the exposure switch,
 * every approval row and `bindingHash` are stored under, and it is the thing an
 * operator reads when deciding what to switch off. So two names that a human
 * cannot tell apart, but the database can, break the one promise the kill
 * switch makes: an upstream advertising both `delete_note` and
 * `delete_note​` shows a reviewer two identical rows, and switching one
 * off leaves the other live, callable, and reported as off.
 *
 * `normalizeTenantKey` already refuses this class of thing for tenants, with
 * the reasoning that "a key that can be spelled two ways is a key that can be
 * made to collide or to split". Tool names arrive from a server we do not
 * control, so they need it more, not less.
 *
 * The name is *refused* rather than normalised. Normalising would fold two
 * genuinely distinct upstream tools onto one key, which trades a visible
 * problem for a silent one — and an upstream whose tool cannot be named
 * unambiguously is in the same position as one whose tool cannot be
 * classified, which this gateway already declines to expose.
 */

/** Generous for a tool name, short of being a payload. */
const MAX_TOOL_NAME = 128;

/*
 * Characters a reviewer cannot see or cannot reliably read: C0 and C1 control
 * codes, the soft hyphen, the zero-width and bidirectional formatting
 * controls, the word joiner, the invisible maths operators, and the byte-order
 * mark. Bidirectional overrides matter twice over: they can make a name render
 * in an order its bytes do not have.
 */
// eslint-disable-next-line no-control-regex
const UNREADABLE = /[\u0000-\u001f\u007f-\u009f­͏؜​-‏‪-‮⁠-⁤⁦-⁩﻿]/;

/**
 * Why this name cannot be used, or `undefined` if it can.
 *
 * Deliberately not an allowlist of characters. Tool names in the wild are
 * snake_case, kebab-case, camelCase, dotted and occasionally non-Latin, and
 * refusing a legitimate Japanese tool name would be a bug rather than a
 * safeguard. What is refused is text that cannot be *read*: anything invisible,
 * anything that reorders what follows it, and anything that is not already in
 * its composed form.
 */
export function toolNameProblem(name: string): string | undefined {
  if (name.length === 0) return "it is empty";
  if (name.length > MAX_TOOL_NAME) {
    return `it is ${name.length} characters; the maximum is ${MAX_TOOL_NAME}`;
  }
  const bad = UNREADABLE.exec(name);
  if (bad) {
    const code = bad[0].codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0");
    return (
      `it contains U+${code} at offset ${bad.index}, which a reviewer cannot see. ` +
      `A name that renders identically to another one is a kill switch that appears to work and does not`
    );
  }
  if (name !== name.normalize("NFC")) {
    return (
      "it is not in Unicode composed (NFC) form, so the same name could be written a second way " +
      "and stored under a different key"
    );
  }
  if (name.trim() !== name) return "it begins or ends with whitespace, which is invisible in a listing";
  return undefined;
}

/**
 * What two names have to differ in for a human to be able to tell them apart.
 *
 * Case is folded and separators are dropped, so `delete_note`, `delete-note`
 * and `DeleteNote` share a key. That is deliberately more aggressive than
 * `toolNameProblem`: those three are each perfectly readable on their own, and
 * a reviewer scanning a list of forty tools should still never have to notice
 * that two rows differ only by a hyphen before switching the right one off.
 */
export function displayKey(name: string): string {
  return name.normalize("NFKC").toLowerCase().replace(/[-._\s]+/g, "");
}
