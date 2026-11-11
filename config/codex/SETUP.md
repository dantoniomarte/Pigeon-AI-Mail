# Pigeon Mail × Codex CLI

Codex CLI reads MCP servers from `~/.codex/config.toml` as TOML tables:
`[mcp_servers.<name>]` with `command`, `args`, `env`, and optional timeouts.

## Where the file goes

```bash
mkdir -p ~/.codex
# merge the [mcp_servers.pigeon-mail] tables into the existing file
cat config.toml >> ~/.codex/config.toml
```

A per-project override lives in `<project>/.codex/config.toml` with the same
tables. Validate the result before starting Codex:

```bash
python3 -c "import tomllib,pathlib;print(list(tomllib.loads(pathlib.Path.home().joinpath('.codex/config.toml').read_text())['mcp_servers']))"
```

## Environment

| Variable | Value |
|---|---|
| `PIGEON_DB_PATH` | `/var/lib/pigeon/pigeon.db` |
| `PIGEON_MASTER_KEY_FILE` | `/etc/pigeon/master.key` |

The `[mcp_servers.pigeon-mail.env]` table is the *whole* environment the server
gets — Codex does not inherit your shell — so keep both entries. The desktop or
CLI user must be able to read the key: `sudo usermod -aG pigeon "$USER"`, then a
fresh login. On a different machine than the mail server, use
[`../remote/`](../remote/) (`PIGEON_URL` + `PIGEON_API_KEY`) instead.

## Quick test

```bash
# the same variables Codex will pass
PIGEON_DB_PATH=/var/lib/pigeon/pigeon.db \
PIGEON_MASTER_KEY_FILE=/etc/pigeon/master.key \
  pigeon mcp <<<'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | grep -o '"name"' | wc -l      # expect 27
```

Inside Codex: `/mcp` lists `pigeon-mail` and its 35 tools.

## Troubleshooting

- **`pigeon-mail` missing from `/mcp`** — the TOML is malformed or the table is
  nested under the wrong parent. `tool_timeout_sec` must stay under the parent
  table (before any deeper `[...]` header).
- **Server starts then exits** — run the quick test; a `permission denied` on
  `master.key` kills the process immediately.
- **`pigeon: command not found`** — Codex does not resolve your shell `PATH`;
  set `command = "/usr/local/bin/pigeon"`.
