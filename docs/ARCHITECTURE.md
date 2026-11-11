# Architecture

Pigeon Mail is a single static Rust binary that runs an encrypted email
server: an HTTP API, an ESMTP server, a queue-driven outbound delivery
worker and an MCP agent server, sharing one SQLite database. A React
webmail is compiled into the same binary and served when enabled.

## Crate map

```
                     ┌──────────────────────────────────────────────┐
  HTTP :8000 ───────▶│ pigeon-api (axum)                            │
  MCP stdio ────────▶│ pigeon-mcp (JSON-RPC)                        │
                     │        │  │                                  │
  Inbound :25 ──────▶│ pigeon-smtp ───▶ queue ──▶ outbound worker ──▶ MX
                     │        │         │                           │
                     │ store (SQLite WAL, Storage trait seam)         │
                     │        │                                       │
                     │ pigeon-crypto (XChaCha20 at-rest seal, TOTP,   │
                     │            Argon2id API keys)                  │
                     │ pigeon-dkim (DKIM rsa-sha256 signing)          │
                     │ pigeon-core (strict types, 12-factor config)   │
                     └──────────────────────────────────────────────┘
                              pigeon (binary: serve / keygen / mcp /
                                      unpin-peer-key; webmail bundle)
```

| Crate | Responsibility |
|---|---|
| `pigeon-core` | Strict, injection-proof types (addresses, folders, scopes) and 12-factor configuration |
| `pigeon-crypto` | XChaCha20-Poly1305 content sealing with domain-separated AAD, TOTP (RFC 6238), Argon2id API-key hashing, master-key wrapping of per-message content keys |
| `pigeon-dkim` | DKIM signing, `rsa-sha256` with RSA-2048 keys today (Ed25519/RFC 8463 planned); per-domain keys live sealed in the `dkim_keys` table and are unsealed per delivery |
| `store` | SQLite storage with WAL and an atomic id reservation; owns the `messages` schema and the `Storage` trait seam every other crate programs against |
| `pigeon-api` | The HTTP API surface (axum): sends, mailbox reads, exports, keys, aliases, catch-all rules, organizations, sessions/2FA, WKD; opens its own `api_*` schema in the same database file |
| `pigeon-smtp` | ESMTP server (inbound), opportunistic-STARTTLS outbound client, and the queue worker that claims jobs with a lease, retries with backoff and dead-letters |
| `pigeon-mcp` | The agent server: JSON-RPC over stdio exposing the 35-tool catalog; send/backup tools delegate to the same pipeline the HTTP API uses |
| `pigeon` | The binary: `serve` (API + SMTP + worker + webmail bundle), `keygen`, `mcp`, `unpin-peer-key` |

Two schemas live in one database file: the `messages` schema (every stored
mail, both directions, with sealed bodies) belongs to `store`, and the
`api_*` schema (lifecycle rows with wrapped content keys, drafts, sender
aliases, catch-all rules, webhooks, organizations, sessions, templates) is
managed by `pigeon-api`'s auxiliary connection. Rows are linked by
`message_id`; a crash between the two inserts leaves a row without a
lifecycle record, which readers skip and backups count.

## Request flows

**Send (HTTP or MCP)**: quota check → validation → identity (own address or
an assigned sender alias) → idempotency → render MIME (`pigeon-api/src/mime`)
→ decide payload protection → seal (layer 1 at-rest always; layer 3 OpenPGP
E2E when recipients publish keys) → insert message + lifecycle row → enqueue.

**Deliver**: the worker claims a job (lease, backoff, dead-letter), groups
recipients by MX, connects opportunistic STARTTLS, hands the MIME over, and
records per-domain verdicts so a retry only targets outstanding domains.

**Receive**: a remote MX connects to `:25` → ESMTP dialog (size and rate
limits, no open relay) → parse MIME → seal the body at rest → store →
inbound webhook event. Auth verdicts are recorded as `none`; SPF/DKIM/DMARC
evaluation is planned (see docs/ROADMAP.md).

## Security layers

Pigeon applies three independent layers, documented in
[docs/e2ee-model.md](e2ee-model.md):

1. **At-rest sealing** (always): every stored body is XChaCha20-Poly1305
   sealed with a per-message content key wrapped by the master key,
   domain-separated by account and message.
2. **Transport**: inbound STARTTLS advertised (plaintext accepted and
   logged); outbound opportunistic STARTTLS (peer certificate validation is
   planned).
3. **End-to-end OpenPGP** (layer 3): when every recipient publishes a key
   (WKD), the body part is sealed so only the keys can open it.

## The webmail

A React SPA under `web/`, built by the `pigeon-webmail` Docker target and
served by the binary. It speaks the same HTTP API, uses session cookies by
default (API keys work as a fallback), and ships 5 locales.
