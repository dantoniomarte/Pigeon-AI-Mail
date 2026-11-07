# Pigeon Mail × any MCP client

`mcp-stdio.json` is the transport-agnostic descriptor: whatever your harness
calls its settings file, it needs these four facts.

```text
transport : stdio (JSON-RPC 2.0, newline-delimited, one object per line)
command   : pigeon
args      : ["mcp"]
env       : PIGEON_DB_PATH, PIGEON_MASTER_KEY_FILE
```

`PIGEON_LOG=warn` is included because MCP stdio is the protocol channel: any
`info`-level log line written to stdout would corrupt the stream. The server
already sends logs to stderr, so this is belt-and-braces.

## Mapping the descriptor to your client

| If your client expects… | Write |
|---|---|
| `mcpServers` map with `command`/`args`/`env` | copy the file as-is |
| a command **array** (`["pigeon","mcp"]`) | concatenate `command` + `args` |
| a shell string | `pigeon mcp` (no shell metacharacters are needed) |
| `env` as `[{name,value}]` pairs | convert each key/value |
| TOML tables | `[mcp_servers.pigeon-mail]` plus its `env` sub-table — see [`../codex/config.toml`](../codex/config.toml) |
| YAML | see [`../hermes/mcp.yaml`](../hermes/mcp.yaml) |

## Protocol smoke test (no client needed)

```bash
# 1. initialize — server info and capabilities
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  | pigeon mcp

# 2. tools/list — the 27 tools
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | pigeon mcp | python3 -c "import json,sys;[print(len(json.loads(l)['result']['tools']),'tools') for l in sys.stdin if l.strip()]"

# 3. tools/call — a real read
printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_messages","arguments":{"limit":5}}}' \
  | pigeon mcp
```

Protocol version negotiated: `2024-11-05`. Capabilities: `tools` only (no
resources, no prompts, no sampling).

## Environment

| Variable | Value |
|---|---|
| `PIGEON_DB_PATH` | `/var/lib/pigeon/pigeon.db` |
| `PIGEON_MASTER_KEY_FILE` | `/etc/pigeon/master.key` |
| `PIGEON_LOG` | `warn` for MCP (keeps stdout clean) |

Both files must be readable by the account that launches the server. The systemd
installer leaves the key at `0640 root:pigeon`.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Client reports “invalid JSON” from the server | something other than JSON-RPC reached stdout — set `PIGEON_LOG=warn` and check for `RUST_LOG` overrides |
| `initialize` works, `tools/list` is empty | a second process holds the SQLite write lock; check for a running `pigeon serve` |
| Every `tools/call` returns `isError: true` | usually the master key: `pigeon mcp` exits when it cannot unwrap the database |
| Server exits with status 1 immediately | run the binary by hand — the error chain is printed on stderr |
