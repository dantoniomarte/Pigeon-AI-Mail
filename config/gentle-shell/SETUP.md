# Pigeon Mail × Gentle Shell

Gentle Shell is a Pi-based terminal workspace, so it reads the same MCP entry
shape as Pi (`mcpServers` → `command` / `args` / `env`, plus `enabled`). The
`settings.json` here is the **MCP block** to merge into the shell's config.

## Where it goes

| Scope | Path |
|---|---|
| Gentle Shell config | `~/.gentle-shell/config.json` (merge the `mcpServers` object) |
| Pi agent (same feature, if you also use `pi`) | `~/.pi/agent/mcp.json` |

```bash
# Gentle Shell stores its settings as JSON; merge is safer than overwrite
python3 - <<'PY'
import json, pathlib
target = pathlib.Path.home() / ".gentle-shell" / "config.json"
add = json.loads(pathlib.Path("settings.json").read_text())
cfg = json.loads(target.read_text()) if target.exists() else {}
cfg.setdefault("mcpServers", {}).update(add["mcpServers"])
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps(cfg, indent=2) + "\n")
print("merged pigeon-mail into", target)
PY
```

From inside Gentle Shell you can also just run
`pi mcp add pigeon-mail --env PIGEON_DB_PATH=… --env PIGEON_MASTER_KEY_FILE=… -- pigeon mcp`
— it writes the same user-level entry.

## Environment

| Variable | Value |
|---|---|
| `PIGEON_DB_PATH` | `/var/lib/pigeon/pigeon.db` |
| `PIGEON_MASTER_KEY_FILE` | `/etc/pigeon/master.key` |

The key is `0640 root:pigeon`; add your user to the group
(`sudo usermod -aG pigeon "$USER"`) and start a new session. Running Gentle Shell
on a workstation while Pigeon lives on a server? Use
[`../remote/`](../remote/) — the shell entry then carries a `url` and an
`Authorization` header instead of filesystem paths.

## Quick test

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | pigeon mcp
```

Inside the shell: `/mcp` lists `pigeon-mail`; `/reload` picks up a config edited
outside the session.

## Troubleshooting

- **Entry replaced by a project config** — a `.pi/mcp.json` in the working
  directory shadows the user-level entry with the same name.
- **Broken JSON after a manual edit** — `python3 -m json.tool ~/.gentle-shell/config.json`.
- **Tools appear but calls fail** — the shell started before you joined the
  `pigeon` group; restart the session.
