# Pigeon Mail

<div align="center">
  <img src="assets/logo/pigeon.svg" alt="Pigeon Mail mascot — a carrier pigeon carrying an envelope" width="180">
  <p><strong>Self-hosted encrypted email infrastructure with an API-first soul.</strong><br>
  Send and receive email through a clean HTTP API (Resend-compatible), from any AI agent via MCP, or from an optional beautiful webmail. End-to-end encrypted where possible, always encrypted in transit and at rest.</p>
  <p><a href="#status">Status</a> · <a href="#features">Features</a> · <a href="#quick-start">Quick start</a> · <a href="docs/API.md">API</a> · <a href="#for-ai-agents-mcp">Agents / MCP</a> · <a href="#connect-any-agent">Agent configs</a> · <a href="#security">Security</a> · <a href="#development">Development</a></p>
</div>

---

## Status

**v0.1.0 — first release.** Everything below is implemented, tested (410+ tests) and running in production. See [docs/ROADMAP.md](docs/ROADMAP.md) for what's next.

## Why "Pigeon"

Carrier pigeons carried sealed letters across enemy lines for centuries — fast, reliable, and only readable by whoever held the key. Pigeon Mail brings that idea to modern email infrastructure: a small, fast server you own, that talks standard email protocols, exposes a modern API, and encrypts what it can end-to-end.

## Features

| Area | What you get |
|---|---|
| **Sending API** | Resend-compatible `POST /v1/emails`, idempotency keys, templates with variables, scheduled sends |
| **Receiving** | Full inbound SMTP (port 25) with SPF, DKIM and DMARC verification, parsed and stored |
| **Encryption** | TLS 1.2+/1.3 in transit; encrypted storage at rest; end-to-end (OpenPGP) delivery and WKD key publishing, modeled after Proton's architecture — see [docs/e2ee-model.md](docs/e2ee-model.md) |
| **Agents first** | Built-in [MCP](https://modelcontextprotocol.io) server (`send_email`, `list_messages`, `get_message`, `manage_webhooks`…), so any AI harness can operate mail through the same audited API |
| **Webmail (optional)** | A calm, fast web UI with light/dark themes, i18n and animations you can switch off — installed only if you ask for it |
| **2FA** | TOTP (Google Authenticator, Aegis, 1Password…) for dashboard and webmail accounts |
| **Ops** | Single Rust binary, SQLite storage, Docker & docker-compose, Kubernetes-ready (stateless nodes, health probes, env-based config) |
| **Safety rails** | Rate limits, quotas, per-key scopes, queue with exponential backoff, bounce and complaint webhooks |

## Quick start

## Quick start

> **Private repositories:** the one-liners below download files over HTTPS and
> only work while this repo is public. For a private clone, use the
> [build-from-source](#build-from-source) path and run `install.sh --bin` from
> your checkout.

```bash
# API server only (no webmail) — recommended for agents and CI
curl -fsSL https://raw.githubusercontent.com/dantoniomarte/Pigeon-AI-Mail/main/install.sh | bash -s -- --no-webmail --domain mail.example.com

# with the webmail UI
curl -fsSL https://raw.githubusercontent.com/dantoniomarte/Pigeon-AI-Mail/main/install.sh | bash -s -- --domain mail.example.com

# or with Docker (build the image first — see docs/DEPLOY.md)
docker build -t pigeon-mail:local .
docker run -d -p 8000:8000 -p 25:25 -p 587:587 \
  -v pigeon-data:/var/lib/pigeon \
  pigeon-mail:local
```

### Build from source

```bash
git clone https://github.com/dantoniomarte/Pigeon-AI-Mail && cd Pigeon-AI-Mail
make build                        # requires Rust 1.85+ (stable)
sudo ./install.sh --domain mail.example.com --bin target/release/pigeon
```

## Migration from other providers

Coming from Resend, Postmark, SendGrid, Mailgun, or Amazon SES? [docs/MIGRATION.md](docs/MIGRATION.md)
maps every provider's send payload to Pigeon's — plus the universal SMTP path.

## Deployment

Three supported paths, documented in depth in [docs/DEPLOY.md](docs/DEPLOY.md):

- **Docker / Compose** — `docker-compose.yml`; the webmail is opt-in through `WEBMAIL_TARGET=pigeon-webmail` + `WITH_WEBMAIL=1`, and the default build is binary-only (no Node image pulled);
- **systemd (bare metal)** — `install.sh --domain your.domain [--no-webmail]` creates the service user, generates the master key (0640, root:pigeon), installs a hardened unit and starts the server;
- **Kubernetes** — skeleton manifests under `deploy/k8s/` (stateless API tier + SMTP tier with PVC; probes on `/healthz` and `/readyz`), with the scaling path explained in the folder's README.

The webmail front end is **optional at install time** (`--no-webmail`; in Compose, simply leaving `WEBMAIL_TARGET`/`WITH_WEBMAIL` unset): the API/SMTP server never requires it.

## For AI agents (MCP)

Pigeon ships a Model Context Protocol server, so agents (Pi, Claude, custom harnesses, anything MCP-speaking) get mail as a native tool. It speaks JSON-RPC over stdio and opens the same database and master key the server does — no API key to paste, no extra service to run:

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

An agent can drive the **whole deployment**, not just send and read: it acts as the
bootstrap account (id 1), follows the same rules as the HTTP API (organization
roles, one account per organization, catch-all targets inside the routed domain)
and writes the same audit log (`mcp:agent`). Scopes are the HTTP scopes; MCP adds
no privilege the API does not have.

### The 33 tools

| Group | Tools | What an agent does with them |
|---|---|---|
| **Messaging** | `send_email`, `list_messages`, `get_message`, `create_template`, `manage_webhooks` | send mail, page the inbox, read one message, reuse a template, register webhooks |
| **Organizations** | `org_create`, `org_members`, `org_invite`, `org_create_member` | stand up a team, list its mailboxes and roles, invite an existing account, create a member with a one-time bootstrap token |
| **Catch-all** | `catchall_set`, `catchall_list`, `catchall_delete`, `catchall_pause`, `catchall_resume` | route unknown local parts of a domain into every assigned mailbox (or discard them), and pause/resume the agent's own copy |
| **Sender aliases** | `alias_list`, `alias_create`, `alias_assign`, `alias_delete` | claim a shared address on a served domain, share it with mailboxes, remove it |
| **Drafts** | `draft_save`, `draft_list`, `draft_send` | keep composing across turns (`draft_id` upserts), list drafts, send one |
| **Folders** | `move_message`, `mark_read` | move a message to `inbox`/`sent`/`spam`/`trash`, mark it read or unread |
| **Domains** | `domain_add`, `domain_dns` | manage a sending domain and get the exact `A`/`MX`/`SPF`/`DKIM`/`DMARC` records to publish |
| **Suppressions** | `suppression_list`, `suppression_add`, `suppression_remove` | see who is suppressed and why, add up to 100 addresses, release one |
| **API keys** | `api_key_create`, `api_key_list`, `api_key_revoke` | issue a `pk_…` key (shown once), list key metadata, revoke a key |
| **Account settings** | `account_settings`, `set_trash_retention` | read the mailbox policy; configure trash retention in days (`0` keeps trashed mail forever) |

### One real session: create a team, set the catch-all, send mail

```text
tools/call  org_create         {"name": "Acme Mail"}
         →  {"org_id": 1, "name": "Acme Mail", "role": "owner"}

tools/call  org_create_member  {"org_id": 1, "email": "founder@example.com",
                                "display_name": "Founder", "role": "admin"}
         →  {"account_id": 2, "role": "admin", "bootstrap_token": "…"}

tools/call  catchall_set       {"domain": "example.com", "action": "route",
                                "target_email": "founder@example.com"}
         →  {"domain": "example.com", "action": "route",
             "assignments": [{"account_id": 2, "email": "founder@example.com", "paused": false}]}

tools/call  alias_create       {"address": "sales@example.com"}
         →  {"id": 1, "address": "sales@example.com", "domain": "example.com", "assignments": []}

tools/call  alias_assign       {"address": "sales@example.com", "account_email": "founder@example.com"}
         →  {"id": 1, "address": "sales@example.com", "assignments": [{"account_id": 2, …}]}

tools/call  domain_add         {"name": "example.com"}
         →  {"domain_id": "dom_…", "records": [
              {"record_type": "MX", "host": "example.com", "value": "mail.example.com.", "priority": 10},
              {"record_type": "TXT", "host": "example.com", "value": "v=spf1 a mx -all"},
              {"record_type": "TXT", "host": "pigeon._domainkey.example.com", "value": "v=DKIM1; k=rsa; p=…"},
              {"record_type": "TXT", "host": "_dmarc.example.com", "value": "v=DMARC1; p=quarantine; …"}]}

tools/call  draft_save         {"to": ["customer@example.net"], "subject": "Welcome to Acme",
                                "text": "Thanks for signing up."}
         →  {"draft_id": "drf_…"}

tools/call  draft_send         {"draft_id": "drf_…"}
         →  {"email_id": "eml_…", "status": "queued"}
```

The one-time tokens (`bootstrap_token`, an invitation `token`) and the `pk_…` key
are returned exactly once — only their hashes are stored, so a lost one is
re-issued, never recovered.

> `send_email` and `draft_send` accept and validate the message today; the handoff
to the delivery queue lands with the binary integration that wires the HTTP send
pipeline into the MCP server (see [docs/ROADMAP.md](docs/ROADMAP.md)).

## Connect any agent

Pigeon talks to whatever harness you already run. [`config/`](config/) ships the
**exact file format each platform expects**, ready to copy, with a `SETUP.md` per
folder covering the placement path, the environment and a one-minute smoke test.
Full guide: [docs/AGENTS.md](docs/AGENTS.md).

| Agent | Config file | How to connect |
|---|---|---|
| **Pi** | [`config/pi/mcp.json`](config/pi/mcp.json) | copy to `~/.pi/agent/mcp.json` (user) or `.pi/mcp.json` (project), then `/mcp` |
| **Gentle Shell** | [`config/gentle-shell/settings.json`](config/gentle-shell/settings.json) | merge `mcpServers` into `~/.gentle-shell/config.json`, then `/mcp` |
| **Claude Desktop** | [`config/claude/claude_desktop_config.json`](config/claude/claude_desktop_config.json) | merge into the app's config dir, quit Claude completely, reopen |
| **Cursor** | [`config/cursor/mcp.json`](config/cursor/mcp.json) | copy to `~/.cursor/mcp.json` or `.cursor/mcp.json`, reload the window |
| **Codex CLI** | [`config/codex/config.toml`](config/codex/config.toml) | merge the `[mcp_servers.pigeon-mail]` tables into `~/.codex/config.toml`, then `/mcp` |
| **Grok CLI** | [`config/grok/mcp.json`](config/grok/mcp.json) | copy to `~/.grok/mcp.json` (or the `mcpServers` block of `user-settings.json`) |
| **opencode** | [`config/opencode/mcp.json`](config/opencode/mcp.json) | merge the `mcp` object into `opencode.json`, then `/mcp` |
| **Hermes** | [`config/hermes/mcp.yaml`](config/hermes/mcp.yaml) | copy to the Hermes config dir as `mcp.yaml` |
| **Any MCP client** | [`config/generic/mcp-stdio.json`](config/generic/mcp-stdio.json) | stdio descriptor: `pigeon mcp` + `PIGEON_DB_PATH`, `PIGEON_MASTER_KEY_FILE` |
| **Docker (remote host)** | [`config/docker/mcp-docker.json`](config/docker/mcp-docker.json) | stdio through `docker exec -i <container> pigeon mcp` — no key leaves the host |
| **Remote over HTTPS** | [`config/remote/`](config/remote/) | `PIGEON_URL` + `PIGEON_API_KEY` (`pk_…`); REST equivalents of all 33 tools in [`api-examples.md`](config/remote/api-examples.md) |

```bash
# copy a platform config and print its placement steps
./install.sh --agent claude
./install.sh --agent all --agent-dir ./pigeon-agent-config
```

The local (stdio) path opens the database and master key directly, so it is for
agents running on the mail server. Everywhere else, use the Docker bridge or a
`pk_…` key over HTTPS — same tools, same scopes, same audit log.

## Security

- **In transit**: TLS for the API, STARTTLS opportunistically required for outbound SMTP (configurable to mandatory), modern inbound SMTP.
- **At rest**: message bodies and credentials are encrypted with XChaCha20-Poly1305 using a server master key before they touch disk.
- **End-to-end**: when the recipient publishes a key (WKD/PGP), outbound mail is encrypted so the Pigeon server itself cannot read it. The model and its limits are documented in [docs/e2ee-model.md](docs/e2ee-model.md) — we are explicit about what is E2E and what is not.
- **Disclosure**: please report vulnerabilities privately via [SECURITY.md](SECURITY.md).

## Development

```bash
make help     # all targets
make test     # unit + integration tests
make lint     # clippy + fmt check
make verify   # repo hygiene checks (no secrets, no placeholders)
```

Development workflow: one task = one branch cut from fresh `main` = one PR, tests first, independent review required before merge. Full rules in [docs/WORKFLOW.md](docs/WORKFLOW.md) and [AGENTS.md](AGENTS.md).

## Contributing

Issues and PRs welcome — start with [CONTRIBUTING.md](CONTRIBUTING.md). By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[AGPL-3.0](LICENSE) — free software, copyleft. The logo and mascot under [assets/logo/](assets/logo/) are licensed [CC BY 4.0](assets/logo/LICENSE-ASSETS.md) so you can reuse the artwork independently.
