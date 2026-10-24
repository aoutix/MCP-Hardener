# @hmcp/scanner

The [hardened-mcp](https://github.com/aoutix/MCP-Hardener) scanner rules, with
SARIF and markdown reporters.

Ten rules over a tool surface: a write reachable without approval, tenant
scoping not enforced, a list without a result ceiling, a secret in a tool
surface, prompt injection in tool text, an overly permissive input schema, an
egress target that is not permitted, an upstream API that declares no auth, a
tool set hard to review or tell apart, and an audit trail missing or weakened.

Pure: no I/O, no network. Driven by `hmcp-gateway scan`.

MIT © Aditya Das
