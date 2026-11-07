# Pigeon Mail × Pi

Pi (and anything built on it) reads MCP servers from a `mcp.json` using the
standard `mcpServers` shape. `command` + `args` select stdio, `url` selects
streamable HTTP.

## Where the file goes

| Scope | Path |
|---|---|
| User (all projects) | `~/.pi/agent/mcp.json` |
| Project | `<project>/.pi/mcp.json` (only after project trust is granted) |

```bash
mkdir -p ~/.pi/agent
cp mcp.json ~/.pi/agent/mcp.json    # merge into the file if it already exists
```

Or register it from the CLI instead of copying:

```bash
pi mcp add pigeon-mail --env PIGEON_DB_PATH=/var/lib/pigeon/pigeon.db \
  --env PIGEON_MASTER_KEY_FILE=/etc/pigeon/master.key -- pigeon mcp
```

## Environment

`pigeon mcp` reads the same `PIGEON_*` variables as the server:

| Variable | Default | Note |
|---|---|---|
| `PIGEON_DB_PATH` | `/var/lib/pigeon/pigeon.db` | must be readable by the user running Pi |
| `PIGEON_MASTER_KEY_FILE` | `/etc/pigeon/master.key` | `0640 root:pigeon` — add your user to the `pigeon` group |
| `PIGEON_LOG` | `info,json` | set to `warn` to keep stdio clean |

Running as a normal user against the systemd install:

```bash
sudo usermod -aG pigeon "$USER"   # then log out and back in
```

## Quick test

```bash
# 1. the binary answers the handshake
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | pigeon mcp

# 2. the tool catalog is complete (expect 27 tools)
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | pigeon mcp | grep -o '"name"' | wc -l

# 3. inside Pi
pi      # then type: /mcp
```

## Troubleshooting

- **`server not listed`** — the file must be valid JSON and the `mcp.json` key
  must be `mcpServers`. Run `pi mcp list` and `/reload` after editing by hand.
- **`permission denied` on the master key** — the group membership only applies
  to new login sessions; check with `id -nG | tr ' ' '\n' | grep pigeon`.
- **The agent runs elsewhere** — it cannot open the server's database. Use
  [`../docker/`](../docker/) (same host, Compose) or
  [`../remote/`](../remote/) (HTTPS + `pk_…` key).
