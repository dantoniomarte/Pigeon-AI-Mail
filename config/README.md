# Pigeon Mail — agent & harness configuration

Ready-to-paste MCP/REST configuration for every major agent platform. Each
folder holds the **exact file format that platform expects** plus a `SETUP.md`
with the placement path, the environment variables and a one-line smoke test.

Every local (stdio) config points at the same thing:

```text
command: pigeon mcp
env:     PIGEON_DB_PATH=/var/lib/pigeon/pigeon.db
         PIGEON_MASTER_KEY_FILE=/etc/pigeon/master.key
```

`pigeon mcp` speaks JSON-RPC 2.0 over stdio, opens the same SQLite database and
master key the server does, and exposes the 33 tools listed in
[../docs/AGENTS.md](../docs/AGENTS.md). No API key to paste, no extra service.

## Pick your platform

| Platform | Folder | File to place |
|---|---|---|
| Pi (coding agent) | [`pi/`](pi/) | `mcp.json` → `~/.pi/agent/mcp.json` (or `.pi/mcp.json` per project) |
| Claude Desktop | [`claude/`](claude/) | `claude_desktop_config.json` → Claude's user config dir |
| Cursor | [`cursor/`](cursor/) | `mcp.json` → `~/.cursor/mcp.json` or `.cursor/mcp.json` |
| Codex CLI | [`codex/`](codex/) | `config.toml` → `~/.codex/config.toml` |
| Grok CLI | [`grok/`](grok/) | `mcp.json` → `~/.grok/mcp.json` |
| opencode | [`opencode/`](opencode/) | `mcp.json` → merge into `opencode.json` |
| Gentle Shell | [`gentle-shell/`](gentle-shell/) | `settings.json` → `~/.gentle-shell/config.json` |
| Hermes | [`hermes/`](hermes/) | `mcp.yaml` → Hermes agent config dir |
| Any MCP client | [`generic/`](generic/) | `mcp-stdio.json` — transport-agnostic descriptor |
| Docker (remote host) | [`docker/`](docker/) | `mcp-docker.json` — `docker exec -i … pigeon mcp` |
| Remote over HTTPS | [`remote/`](remote/) | `mcp-remote.json` + `api-examples.md` (REST, no MCP) |

## Three ways to reach Pigeon

| Mode | Needs | Use when |
|---|---|---|
| **stdio, local** (all folders above except `remote/`) | read access to the database *and* the master key | the agent runs on the mail server, or in a container that mounts both |
| **docker exec** (`docker/`) | membership in the `docker` group | the agent runs on the same host as a Compose deployment |
| **REST over HTTPS** (`remote/`) | `PIGEON_URL` + `PIGEON_API_KEY` (`pk_…`) | the agent runs anywhere else — no filesystem access needed |

An agent that only holds `PIGEON_URL` + `PIGEON_API_KEY` uses the HTTP API
directly (`config/remote/api-examples.md`); scopes, rate limits, sandbox keys
and the audit log are the same ones `pigeon mcp` uses.

## Environment variables that matter here

| Variable | Meaning |
|---|---|
| `PIGEON_DB_PATH` | SQLite file (`/var/lib/pigeon/pigeon.db` by default) |
| `PIGEON_MASTER_KEY_FILE` | 32-byte master key (`/etc/pigeon/master.key`, `0640 root:pigeon`) |
| `PIGEON_URL` | Base URL of the HTTP API, for the remote/REST path |
| `PIGEON_API_KEY` | `pk_…` API key, for the remote/REST path |

The master key is a **file**, never an environment value. An agent that can read
it can read every mailbox on the instance — see the security notes in
[../docs/AGENTS.md](../docs/AGENTS.md).

## Installer shortcut

`install.sh --agent <platform>` copies the selected folder and prints the
placement steps without running the full server install:

```bash
./install.sh --agent claude          # copies config/claude/ into ./pigeon-agent-config/claude/
./install.sh --agent pi --agent-dir ~/.config   # explicit destination
sudo ./install.sh --domain example.com --agent all
```
