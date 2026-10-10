import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";

/**
 * HTTP primitives shared by every surface in this project that speaks HTTP.
 *
 * These began life in the review console and moved here when the gateway grew
 * an HTTP transport of its own. The gateway cannot import the console — that
 * is the wrong direction through the package graph — and a second copy of an
 * error type is how two surfaces come to disagree about what a 422 means.
 *
 * What is deliberately *not* here is the console's request pipeline: the
 * loopback-only gate, the "a mutating request must carry an Origin header"
 * rule, and the session-cookie plus double-submit CSRF check. Those are right
 * for a privileged browser surface on a developer's machine and wrong for an
 * MCP endpoint — an MCP client is not a browser, sends no Origin, carries no
 * cookie, and every one of its calls is a POST. Shared code that three of four
 * callers must disable is not shared code.
 */

/**
 * The cap on a request body this project will buffer.
 *
 * Sized for configuration and tool arguments, which is what every body here
 * actually is. A caller that needs to move bulk data is doing something this
 * layer is not for.
 */
export const MAX_BODY_BYTES = 256 * 1024;

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly detail?: unknown
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export const badRequest = (m: string, d?: unknown) => new HttpError(400, "bad-request", m, d);
export const notFound = (m: string) => new HttpError(404, "not-found", m);
export const conflict = (m: string) => new HttpError(409, "conflict", m);
export const unprocessable = (m: string, d?: unknown) => new HttpError(422, "unprocessable", m, d);

/**
 * Reads a JSON request body, refusing one that is too large.
 *
 * The cap is checked as the body arrives rather than afterwards, so an
 * oversized request is abandoned part-way instead of being buffered in full
 * and then rejected.
 */
export async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw badRequest(`request body exceeds ${MAX_BODY_BYTES} bytes`);
    chunks.push(chunk as Buffer);
  }
  if (size === 0) return undefined;
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw badRequest("request body is not valid JSON");
  }
}

/**
 * Compares two secrets without leaking their contents through timing.
 *
 * The length check short-circuits, so this reveals whether two values are the
 * same length. That is accepted: every secret compared here is a fixed-width
 * generated token, so the length carries nothing an attacker does not already
 * know from the format.
 */
export function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
