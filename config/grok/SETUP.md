# Pigeon Mail × Grok CLI

Grok CLI keeps its MCP servers in a `mcp.json` registry under its config
directory (`mcpServers` → `command` / `args` / `env` — the same shape Claude
Desktop and Cursor use).

## Where the file goes

| Scope | Path |
|---|---|
| User (default) | `~/.grok/mcp.json` |
| Project | `<project>/.grok/mcp.json` |

```bash
mkdir -p ~/.grok
cp mcp.json ~/.grok/mcp.json
```

Newer builds also accept the identical `mcpServers` block inside
`~/.grok/user-settings.json`; if your version documents that file, merge the
block there instead. Either way the JSON is the same — only the path differs.

## Environment

| Variable | Value |
|---|---|
| `PIGEON_DB_PATH` | `/var/lib/pigeon/pigeon.db` |
| `PIGEON_MASTER_KEY_FILE` | `/etc/pigeon/master.key` |

For the systemd install, grant the CLI user read access to the key once:
`sudo usermod -aG pigeon "$USER"` and start a new shell. If Grok CLI runs on a
different host than Pigeon, skip the filesystem path and use
[`../remote/`](../remote/) with `PIGEON_URL` + `PIGEON_API_KEY`.

## Quick test

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | pigeon mcp | grep -o '"name"' | wc -l     # expect 25
```

Then in Grok CLI, `/mcp` (or `grok mcp list`, depending on version) shows
`pigeon-mail` connected.

## Troubleshooting

- **Server listed as “failed”** — the CLI could not spawn `pigeon`; use the
  absolute path in `command`.
- **Empty tool list** — `tools/list` succeeded but the process then closed: most
  often the master key is unreadable, so MCP state fails to initialise.
- **Two config paths, one server** — pick one location. A project-level file
  shadows the user-level entry with the same name.
