# Pigeon Mail × Hermes

Hermes configures MCP servers from YAML. `mcp.yaml` declares the server under
`mcp.servers`, with `transport: stdio`, the `command`, its `args`, and the
`env` map the process receives.

## Where the file goes

| Scope | Path |
|---|---|
| User | `<hermes config dir>/mcp.yaml` (typically `~/.hermes/mcp.yaml`) |
| Project | `<project>/.hermes/mcp.yaml` |

```bash
mkdir -p ~/.hermes
cp mcp.yaml ~/.hermes/mcp.yaml    # merge the mcp.servers map if it already exists
```

Validate before starting the agent — a YAML tab or a duplicated key breaks the
whole document silently:

```bash
python3 -c "import yaml,sys;print(list(yaml.safe_load(open('mcp.yaml'))['mcp']['servers']))"
```

## Environment

| Variable | Value |
|---|---|
| `PIGEON_DB_PATH` | `/var/lib/pigeon/pigeon.db` |
| `PIGEON_MASTER_KEY_FILE` | `/etc/pigeon/master.key` |

The `env` block is the complete environment of the child process, so both paths
must be absolute and readable by the user Hermes runs as
(`sudo usermod -aG pigeon "$USER"`). When Pigeon runs on another host, switch the
entry to the remote transport:

```yaml
    pigeon-mail:
      transport: http
      url: https://mail.example.com/mcp
      headers:
        Authorization: "Bearer ${PIGEON_API_KEY}"
      enabled: true
```

## Quick test

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | pigeon mcp | grep -o '"name"' | wc -l     # expect 27
```

Then in Hermes, list connected servers (`/mcp` or the agent's tool panel) and
confirm `pigeon-mail` reports 33 tools.

## Troubleshooting

- **Server not listed** — the document needs the `mcp:` → `servers:` nesting;
  a top-level `pigeon-mail:` key is ignored.
- **Spawn error** — set an absolute `command: /usr/local/bin/pigeon`.
- **Handshake timeout** — raise `startup_timeout_seconds` on cold storage, and
  check the key is readable before blaming the timeout.
