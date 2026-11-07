# Pigeon Mail × Claude Desktop

Claude Desktop launches MCP servers as child processes and reads them from
`claude_desktop_config.json` (`mcpServers` → `command` / `args` / `env`).

## Where the file goes

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

```bash
# Linux
mkdir -p ~/.config/Claude
cp claude_desktop_config.json ~/.config/Claude/claude_desktop_config.json
```

If the file already exists, merge the `pigeon-mail` entry into its `mcpServers`
object — do not overwrite the other servers. Quit Claude Desktop **completely**
(menu → Quit, not just close the window) and reopen it; the config is read at
startup only.

## Environment

Claude Desktop starts the process with a minimal environment, so both paths must
be absolute and readable by the desktop user:

| Variable | Value |
|---|---|
| `PIGEON_DB_PATH` | `/var/lib/pigeon/pigeon.db` |
| `PIGEON_MASTER_KEY_FILE` | `/etc/pigeon/master.key` |

`/etc/pigeon/master.key` is `0640 root:pigeon`. Either add the desktop user to
the `pigeon` group (`sudo usermod -aG pigeon "$USER"`, then log out/in), or copy
the key to a path only that user can read (`chmod 600`) — never a world-readable
copy. Claude Desktop cannot read a remote host's database: for a server on
another machine use [`../remote/`](../remote/) (HTTPS + `pk_…` key) instead.

## Quick test

Claude Desktop gives no terminal output, so test the server first:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | PIGEON_DB_PATH=/var/lib/pigeon/pigeon.db \
    PIGEON_MASTER_KEY_FILE=/etc/pigeon/master.key pigeon mcp \
  | grep -o '"name"' | wc -l          # expect 25
```

Then in Claude Desktop the tools appear under the **pigeon-mail** connector in
the “Search and tools” menu. Ask: *“list my Pigeon inbox messages”*.

## Troubleshooting

- **No connector appears** — the JSON is invalid (trailing comma) or the app was
  not fully restarted. Claude Desktop logs live at
  `~/Library/Logs/Claude/mcp*.log` (macOS) and `~/.config/Claude/logs/` (Linux).
- **`command not found: pigeon`** — put the absolute path in `command`:
  `/usr/local/bin/pigeon`.
- **Handshake fails** — run the quick test above as the *same* user; a
  `permission denied` on the key is the usual cause.
