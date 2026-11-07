# Pigeon Mail × Cursor

Cursor reads MCP servers from `mcp.json` (`mcpServers` → `command` / `args` /
`env`), either per project (`.cursor/mcp.json`) or for every workspace
(`~/.cursor/mcp.json`).

## Where the file goes

| Scope | Path |
|---|---|
| Project | `<project>/.cursor/mcp.json` (mention it in `.gitignore` if it holds a key) |
| Global | `~/.cursor/mcp.json` |

```bash
# global
mkdir -p ~/.cursor
cp mcp.json ~/.cursor/mcp.json

# or per project
mkdir -p .cursor && cp mcp.json .cursor/mcp.json
```

Then open Cursor → **Settings → MCP** and confirm `pigeon-mail` shows a green
dot. Reload the window (`Cmd/Ctrl+Shift+P` → “Reload Window”) after editing the
file by hand.

## Environment

| Variable | Value |
|---|---|
| `PIGEON_DB_PATH` | `/var/lib/pigeon/pigeon.db` |
| `PIGEON_MASTER_KEY_FILE` | `/etc/pigeon/master.key` |

Cursor launches the server as your user. For the systemd install add yourself to
the service group once — `sudo usermod -aG pigeon "$USER"` — and restart Cursor
after logging back in. On macOS with a remote Linux mail server, Cursor cannot
read the server's files: use [`../remote/`](../remote/) with `PIGEON_URL` +
`PIGEON_API_KEY` instead.

## Quick test

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | pigeon mcp
```

Inside Cursor: **Settings → MCP → pigeon-mail → tools** (27 tools), or ask the
agent *“use pigeon-mail to list my inbox”*.

## Troubleshooting

- **Red or missing entry** — usually a relative `command`. Use
  `/usr/local/bin/pigeon`.
- **“failed to start” with a permission error** — the master key is not readable
  by your user (see Environment above).
- **Tools listed but every call errors** — the database path points at a
  different install; compare with `sudo systemctl cat pigeon | grep PIGEON_`.
