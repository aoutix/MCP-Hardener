# hmcp-gateway

A policy gateway for MCP servers you did not write and do not control.

`hmcp-gateway` sits between an agent and its MCP servers. Point the agent at the
gateway instead of the server and a tool can be switched off, a write can be
held for a human and bound to its exact arguments, and every decision is
recorded in a hash-chained log — without touching either side.

## Adopting the servers you already have

```sh
npx hmcp-gateway adopt              # report what wrapping them would do
npx hmcp-gateway adopt --apply      # write the config and swap the client over
npx hmcp-gateway adopt --revert     # put the original entries back
```

`adopt` reads the MCP servers your client has configured, shows how each tool
would be classified and which ones would be refused, generates `gateway.yaml`
and `policy.yaml`, and replaces those entries with a single gateway entry. It
writes nothing without `--apply`.

## Running it directly

```sh
hmcp-gateway serve -c gateway.yaml        # stdio
hmcp-gateway serve -c gateway.yaml --http # Streamable HTTP on 127.0.0.1:7878
hmcp-gateway tools -c gateway.yaml        # what it would expose, and how it classified each tool
hmcp-gateway scan  -c gateway.yaml        # scan every upstream's advertised surface
hmcp-gateway exposure off <tool>          # withdraw one tool and refuse every call to it
```

Full documentation, including the policy schema and what the gateway does and
does not protect against, is in the [repository README](https://github.com/aoutix/MCP-Hardener#readme).

MIT © Aditya Das
