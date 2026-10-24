# @hmcp/core

The security-relevant half of [hardened-mcp](https://github.com/aoutix/MCP-Hardener):
policy schema, the decision engine, the enforcement pipeline, approvals and
standing grants, the tool inventory, the hash-chained audit log, redaction, and
the egress guard.

Everything a gateway enforces and everything the console describes comes from
here, so the two cannot drift apart. `decide()` is pure and synchronous on
purpose: if enforcement ever needed to reach the network to make a decision,
that would be a hole rather than a feature.

This is a library. You most likely want
[`hmcp-gateway`](https://www.npmjs.com/package/hmcp-gateway) instead.

MIT © Aditya Das
