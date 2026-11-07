# Pigeon Mail

<div align="center">
  <img src="assets/logo/pigeon.svg" alt="Pigeon Mail mascot — a carrier pigeon carrying an envelope" width="180">
  <p><strong>Self-hosted encrypted email infrastructure with an API-first soul.</strong><br>
  Send and receive email through a clean HTTP API (Resend-compatible), from any AI agent via MCP, or from an optional beautiful webmail. End-to-end encrypted where possible, always encrypted in transit and at rest.</p>
  <p><a href="#status">Status</a> · <a href="#features">Features</a> · <a href="#quick-start">Quick start</a> · <a href="docs/API.md">API</a> · <a href="#for-ai-agents-mcp">Agents / MCP</a> · <a href="#security">Security</a> · <a href="#development">Development</a></p>
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

```bash
# API server only (no webmail) — recommended for agents and CI
curl -fsSL https://raw.githubusercontent.com/dantoniomarte/Pigeon-AI-Mail/main/install.sh | bash -s -- --no-webmail --domain mail.example.com

# with the webmail UI
curl -fsSL https://raw.githubusercontent.com/dantoniomarte/Pigeon-AI-Mail/main/install.sh | bash -s -- --domain mail.example.com

# or with Docker
docker run -d -p 8000:8000 -p 25:25 -p 587:587 \
  -v pigeon-data:/var/lib/pigeon \
  ghcr.io/dantoniomarte/pigeon-mail:latest
```

Build from source:

```bash
git clone https://github.com/dantoniomarte/Pigeon-AI-Mail && cd Pigeon-AI-Mail
make build   # requires Rust 1.85+ (stable)
```

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

### The 25 tools

| Group | Tools | What an agent does with them |
|---|---|---|
| **Messaging** | `send_email`, `list_messages`, `get_message`, `create_template`, `manage_webhooks` | send mail, page the inbox, read one message, reuse a template, register webhooks |
| **Organizations** | `org_create`, `org_members`, `org_invite`, `org_create_member` | stand up a team, list its mailboxes and roles, invite an existing account, create a member with a one-time bootstrap token |
| **Catch-all** | `catchall_set`, `catchall_list`, `catchall_delete` | route unknown local parts of a domain into a mailbox, or discard them |
| **Drafts** | `draft_save`, `draft_list`, `draft_send` | keep composing across turns (`draft_id` upserts), list drafts, send one |
| **Folders** | `move_message`, `mark_read` | move a message to `inbox`/`sent`/`spam`/`trash`, mark it read or unread |
| **Domains** | `domain_add`, `domain_dns` | manage a sending domain and get the exact `A`/`MX`/`SPF`/`DKIM`/`DMARC` records to publish |
| **Suppressions** | `suppression_list`, `suppression_add`, `suppression_remove` | see who is suppressed and why, add up to 100 addresses, release one |
| **API keys** | `api_key_create`, `api_key_list`, `api_key_revoke` | issue a `pk_…` key (shown once), list key metadata, revoke a key |

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
             "target_email": "founder@example.com"}

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
