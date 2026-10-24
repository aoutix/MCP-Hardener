# @hmcp/web

The [hardened-mcp](https://github.com/aoutix/MCP-Hardener) review console.

```sh
npx @hmcp/web            # http://127.0.0.1:7777
```

Shows what each registered gateway exposes and why: how every tool was
classified, which descriptions were rewritten, what is switched off, what is
waiting for approval, and the audit log. Read-mostly, loopback only, and it
never speaks MCP itself — it reads what a running gateway published.

A gateway shows no tools until it has served at least once, and its tool list is
marked stale whenever no gateway process is alive.

MIT © Aditya Das
