# Pigeon Mail × opencode

opencode uses its own config shape (`mcp` → `type: "local"`, `command` as an
**array**, `environment` as an object) rather than the `mcpServers` map used by
Claude/Cursor. `mcp.json` here is a complete `opencode.json` you can copy, or
whose `mcp` block you can merge into an existing config.

## Where the file goes

| Scope | Path |
|---|---|
| User | `~/.config/opencode/opencode.json` (or `opencode.jsonc`) |
| Project | `<project>/opencode.json` |

```bash
# fresh start
mkdir -p ~/.config/opencode
cp mcp.json ~/.config/opencode/opencode.json

# existing config: merge only the "mcp" object, keep the rest
```

JSONC files allow comments — keep the file valid; opencode validates against the
schema named in `$schema`.

## Environment

| Variable | Value |
|---|---|
| `PIGEON_DB_PATH` | `/var/lib/pigeon/pigeon.db` |
| `PIGEON_MASTER_KEY_FILE` | `/etc/pigeon/master.key` |

opencode spawns the process itself, so `environment` is authoritative (your
shell exports are not inherited). Grant read access to the key with
`sudo usermod -aG pigeon "$USER"`. For a Pigeon instance on another machine use
a **remote** entry instead:

```json
"pigeon-mail": {
  "type": "remote",
  "url": "https://mail.example.com/mcp",
  "headers": { "Authorization": "Bearer ${PIGEON_API_KEY}" },
  "enabled": true
}
```

The REST API is reachable with the same key even without MCP — see
[`../remote/api-examples.md`](../remote/api-examples.md).

## Quick test

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | pigeon mcp | grep -o '"name"' | wc -l     # expect 25
```

In opencode, `/mcp` shows `pigeon-mail` as a connected local server with 25
tools.

## Troubleshooting

- **`command` must be an array** — `"command": "pigeon mcp"` is rejected;
  `["pigeon", "mcp"]` is correct.
- **Entry not loaded** — the object must be under the top-level `mcp` key, not
  under `mcpServers`.
- **Works in the shell, not in opencode** — use the absolute binary path in the
  array: `["/usr/local/bin/pigeon", "mcp"]`.
