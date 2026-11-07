# Pigeon Mail — agent integration guide

> This page is about connecting **your** agents and harnesses to Pigeon. It is
> not a set of instructions for contributors editing this repository — those live
> in [`../AGENTS.md`](../AGENTS.md).

Pigeon is built agent-first: the same store, master key, scopes and audit log are
reachable three ways. Pick the one that matches where your agent runs.

| Path | Transport | Credential | Agent runs on |
|---|---|---|---|
| **Local MCP** | JSON-RPC 2.0 over stdio | filesystem access to the DB + master key | the mail server (or a container that mounts both) |
| **Docker MCP** | stdio via `docker exec -i` | Docker socket membership | the Docker host |
| **REST** | HTTPS + `Authorization: Bearer pk_…` | an API key | anywhere |

Ready-to-paste config for each platform: [`../config/`](../config/) (Pi, Claude
Desktop, Cursor, Codex CLI, Grok CLI, opencode, Gentle Shell, Hermes, generic,
Docker, remote). This page is the reasoning behind those files.

---

## 1. Local MCP (stdio)

`pigeon mcp` is a stdio server: newline-delimited JSON-RPC 2.0, protocol
`2024-11-05`, capability `tools` only. It opens the same SQLite file and master
key the `pigeon serve` process uses — no API key, no extra daemon.

```json
{
  "mcpServers": {
    "pigeon-mail": {
      "command": "pigeon",
      "args": ["mcp"],
      "env": {
        "PIGEON_DB_PATH": "/var/lib/pigeon/pigeon.db",
        "PIGEON_MASTER_KEY_FILE": "/etc/pigeon/master.key"
      }
    }
  }
}
```

Verify before wiring any client:

```bash
# handshake
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | pigeon mcp

# catalog — 25 tools
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | pigeon mcp | grep -o '"name"' | wc -l

# one real call
printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_messages","arguments":{"limit":5}}}' \
  | pigeon mcp
```

The process acts as the bootstrap account (id 1): the organization and role rules
of the HTTP API apply unchanged, and every write lands in the audit log as
`mcp:agent`. MCP adds **no privilege** the API does not have.

Guards worth knowing:

- **stdout is the protocol channel.** Logs go to stderr; if a client reports
  “invalid JSON”, check that nothing else is writing to stdout (`PIGEON_LOG=warn`
  is the safe setting).
- **One key, one process.** The server needs read access to the master key
  (`0640 root:pigeon`); the usual fix is `sudo usermod -aG pigeon "$USER"` plus a
  fresh login session.
- **Version pinning.** `serverInfo.version` is the Pigeon version — use it to
  detect a client/server mismatch after an upgrade.

---

## 2. MCP from another host, same Docker daemon

When Pigeon runs in Compose, the agent can speak stdio to a process *inside* the
container. Nothing is copied out, and the key never leaves the host:

```json
{
  "mcpServers": {
    "pigeon-mail": {
      "command": "docker",
      "args": ["exec", "-i", "pigeon-pigeon-1",
               "/usr/local/bin/pigeon", "mcp"]
    }
  }
}
```

- `-i` is mandatory (stdin must be attached) — omit it and the transport gets EOF.
- The container name is `<compose-project>-<service>-<index>`; read yours from
  `docker ps --format '{{.Names}}'`.
- Docker group membership is root-equivalent on the host. Prefer the REST path
  when the agent is not fully trusted.
- `docker run --rm … pigeon mcp` without the `pigeon-data` volume and
  `secrets/` mount gives an empty database and no master key — always `exec`
  into the running service.

Full walkthrough: [`../config/docker/SETUP.md`](../config/docker/SETUP.md).

---

## 3. REST API without MCP

An agent that cannot speak MCP still gets the whole surface. The stdio tools are
thin wrappers around these endpoints, so scopes, rate limits and audit rows are
identical.

```bash
export PIGEON_URL="https://mail.example.com"
export PIGEON_API_KEY="pk_…"

curl -sS -X POST "$PIGEON_URL/v1/emails" \
  -H "Authorization: Bearer $PIGEON_API_KEY" -H "Content-Type: application/json" \
  -d '{"from":"agent@example.com","to":["carol@example.org"],
       "subject":"Report ready","text":"Nightly report attached."}'
```

Quick checks: `GET /healthz` (liveness), `GET /readyz` (store + master key),
`GET /v1/messages?limit=5` (needs `read`). Complete curl set, including the
per-tool endpoint map: [`../config/remote/api-examples.md`](../config/remote/api-examples.md).
Contract: [`openapi.yaml`](../openapi.yaml) · [`API.md`](API.md).

---

## Environment variables

### Local MCP / stdio

| Variable | Default | Meaning |
|---|---|---|
| `PIGEON_DB_PATH` | `/var/lib/pigeon/pigeon.db` | SQLite file (must be real disk — ADR 0002) |
| `PIGEON_MASTER_KEY_FILE` | `/etc/pigeon/master.key` | 32-byte master key, `0640 root:pigeon` |
| `PIGEON_LOG` | `info,json` | tracing filter; use `warn` for MCP so stdout stays clean |

The master key is **always a file**, never an environment value: an agent that
can read it can decrypt every mailbox on the instance.

### REST / remote

| Variable | Example | Meaning |
|---|---|---|
| `PIGEON_URL` | `https://mail.example.com` | API base URL (TLS terminated in front of `:8000`) |
| `PIGEON_API_KEY` | `pk_…` | bearer key; shown once at creation |

### Server-side (for reference)

`PIGEON_HTTP_ADDR` (`:8000`), `PIGEON_SMTP_IN_ADDR` (`:25`),
`PIGEON_SMTP_OUT_STARTTLS` (`required|pinned|opportunistic`), `PIGEON_WEBMAIL`
(`on|off`), `PIGEON_PUBLIC_IP`, `PIGEON_SMTP_HOSTNAME`. Full table:
[`ARCHITECTURE.md`](ARCHITECTURE.md#configuration-principal-env-vars) and
[`../.env.example`](../.env.example).

---

## The 25-tool catalog

Grouped as `tools/list` returns them. Every tool takes a JSON object; every
result is a text content block containing JSON.

### Messaging

| Tool | Agent use |
|---|---|
| `send_email` | `to`, `subject`, `text` required; optional `from`, `cc`, `html`, `tags`. Returns the email id + status. |
| `list_messages` | `limit` (≤500), `offset`. Metadata only — ids for follow-up reads. |
| `get_message` | `id` (`msg_…`) → body plus SPF/DKIM/DMARC verdicts. |
| `create_template` | `name` + `{{variables}}` in `subject`/`html`/`text`. |
| `manage_webhooks` | `action: list\|create\|delete`; events `sent, delivered, bounced, received`. |

### Organizations

| Tool | Agent use |
|---|---|
| `org_create` | `name` (≤100 chars); the agent's account becomes owner. One account = one organization. |
| `org_members` | `org_id` optional — omit for the agent's own organization. |
| `org_invite` | Mints a one-time token for an existing account; `role: admin\|member`, never owner. |
| `org_create_member` | Creates the mailbox **and** returns the one-time `bootstrap_token`. |

### Catch-all

| Tool | Agent use |
|---|---|
| `catchall_set` | `action: route` needs `target_email` in the routed domain; `discard` forbids it. |
| `catchall_list` | Every rule with action + target. |
| `catchall_delete` | Unknown local parts go back to `550`. |

### Drafts, folders

| Tool | Agent use |
|---|---|
| `draft_save` | Omit `draft_id` to create, pass it to upsert — how an agent keeps composing across turns. |
| `draft_list` / `draft_send` | Page drafts; send one (`drf_…`). Sending reuses the `POST /v1/emails` path. |
| `move_message` | `inbox\|sent\|spam\|trash`. |
| `mark_read` | `read: true` marks read, `false` unread. |

### Domains, suppressions, keys

| Tool | Agent use |
|---|---|
| `domain_add` | Returns the exact `A`/`MX`/`SPF`/`DKIM`/`DMARC` records to publish. |
| `domain_dns` | Same records for an already-managed domain. |
| `suppression_list` / `suppression_add` / `suppression_remove` | Never-mail-again list; `add` accepts ≤100 addresses, duplicates ignored. |
| `api_key_create` | `name` + `scopes: send\|read\|full`, optional `sandbox`. The `pk_…` value is shown **once**. |
| `api_key_list` | Metadata only (never key material, `last_used_at` included). |
| `api_key_revoke` | `key_id` (`key_…`); the next request with it is refused. |

### Agent-oriented examples

```text
# bootstrap a team, then route its unknown mail
tools/call org_create        {"name":"Acme Mail"}
       → {"org_id":1,"name":"Acme Mail","role":"owner"}

tools/call org_create_member {"org_id":1,"email":"founder@example.com",
                              "display_name":"Founder","role":"admin"}
       → {"account_id":2,"role":"admin","bootstrap_token":"…"}   # shown once

tools/call catchall_set      {"domain":"example.com","action":"route",
                              "target_email":"founder@example.com"}

# compose over several turns instead of sending blind
tools/call draft_save {"to":["customer@example.net"],"subject":"Welcome to Acme",
                       "text":"Thanks for signing up."}
       → {"draft_id":"drf_…"}
tools/call draft_send {"draft_id":"drf_…"}

# triage the inbox in one pass
tools/call list_messages  {"limit":20}
tools/call get_message    {"id":"msg_00000001"}
tools/call mark_read      {"message_id":"msg_00000001","read":true}
tools/call move_message   {"message_id":"msg_00000001","folder":"spam"}

# provision a narrow key for a CI agent and revoke it after the run
tools/call api_key_create  {"name":"ci-nightly","scopes":["send"],"sandbox":true}
       → {"id":"key_…","key":"pk_…"}     # once
tools/call api_key_revoke  {"key_id":"key_…"}
```

One-time values (`bootstrap_token`, invitation `token`, `pk_…`) are returned
exactly once — only their hashes are stored. A lost one is re-issued, never
recovered.

> Honest limit (v0.1): `send_email` and `draft_send` validate and accept the
> message, but the handoff to the delivery queue is wired with the binary
> integration — see [`ROADMAP.md`](ROADMAP.md).

---

## Security notes

**Scopes.** Keys and tools share one model: `send`, `read`, `full`. There is no
blanket “read means all GETs” — the tier is per operation (`x-scopes` in
`openapi.yaml`). `read` sees metadata and *sealed* blobs; only `full` decrypts
bodies. Give an agent `send` + `read`; keep `full` for interactive admin.

**Sandbox.** A sandbox key (`"sandbox": true`, or `PIGEON_SANDBOX=1`
instance-wide) accepts, stores and renders every send but never delivers and
never emits delivery webhooks. Inspect the generated MIME with
`GET /v1/emails/{id}?raw=true` (sandbox messages only). Use it for CI.

**2FA.** TOTP protects dashboard/webmail **sessions** (`POST /v1/auth/login`,
`403` + `mfa-required` is the challenge, not a failure). It does not apply to API
keys and a `full` key neither enrolls nor bypasses it: keys and sessions are
separate realms. Recovery codes work at login and at `2fa/disable`, so a lost
authenticator is never a lockout.

**What an agent can reach.** The stdio server reads the database and the master
key, so it can decrypt everything — the blast radius is the whole instance. Treat
filesystem access to `/etc/pigeon/master.key` as the highest privilege on the
box, and prefer the REST path (`send`/`read` key over TLS) for anything you would
not hand a shell on the server.

**Audit.** Every write is recorded; MCP-originated writes are attributed to
`mcp:agent`. Review the log before granting a broader key.

**Network.** Pigeon speaks plain HTTP on `:8000` — TLS belongs to the reverse
proxy in front. Never expose `:8000` directly. Rate limits are per key (10 req/s
sustained, burst 50; daily send quota, default 50,000) — one key per agent keeps
limits and revocation meaningful.

---

## Troubleshooting matrix

| Symptom | Likely cause | Fix |
|---|---|---|
| Client shows no server | invalid JSON/TOML/YAML in the config | validate the file (`json.tool`, `tomllib`, `yaml.safe_load`), restart the client fully |
| `command not found: pigeon` | harness does not inherit `PATH` | absolute path: `/usr/local/bin/pigeon` |
| stdio “invalid JSON” | logs on stdout | `PIGEON_LOG=warn` |
| `permission denied` on key | user not in group `pigeon` | `sudo usermod -aG pigeon "$USER"`, new login |
| `tools/list` empty | client connected to a different process | run the handshake by hand |
| REST `401` / `403` | bad key / narrow scope | compare with `x-scopes` in `openapi.yaml` |
| REST `429` / `402` | rate limit / quota | back off with `Retry-After`, batch sends |

Platform-specific placement and tests live in [`../config/`](../config/).
