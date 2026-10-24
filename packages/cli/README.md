# hmcp

Command line for [hardened-mcp](https://github.com/aoutix/MCP-Hardener).

```sh
hmcp pending              # writes a gateway is holding for a human
hmcp approve <id>         # release one, bound to its exact arguments
hmcp deny <id>
hmcp approvals            # what has been decided
hmcp audit tail           # every decision, allowed or refused
hmcp audit verify         # check the hash chain
hmcp policy               # what a policy actually says
```

This is the out-of-band approval channel: it works whether or not the connected
client supports in-client prompts.

MIT © Aditya Das
