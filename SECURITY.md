# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report privately via [GitHub Security Advisories](https://github.com/dantoniomarte/Pigeon-AI-Mail/security/advisories/new) ("Report a vulnerability"). You will get an acknowledgment within 48 hours and a status update at least every 7 days until resolution.

Please include: affected component (SMTP / HTTP API / MCP / webmail / installer), reproduction steps, impact assessment, and any proof-of-concept. If the report involves email deliverability or bypassing encryption or authentication (SPF/DKIM/DMARC, API keys, TOTP, OpenPGP sealing), mark it clearly — those are treated as high priority.

## Supported versions

| Version | Supported |
|---|---|
| latest release | ✅ |
| older releases | ❌ — upgrade |

## Security model in one page

- The HTTP API and MCP tools share one authorization model: scoped API keys (`pk_` prefix), hashed with Argon2id, audited on use.
- Dashboard/webmail accounts support TOTP second factor (RFC 6238); recovery codes are one-time.
- Storage encryption at rest: XChaCha20-Poly1305 (master key from env/secret file; KMS integration planned).
- End-to-end encryption follows the OpenPGP model described in [docs/e2ee-model.md](docs/e2ee-model.md) — including what it deliberately does **not** cover.
- SMTP hardening: command size/line limits, rate limits per connection and per domain, no open relay by construction, rDNS/SPF/DKIM/DMARC evaluation on inbound.

## Deployment guidance

Run behind a reverse proxy with TLS (Caddy/nginx) or terminate TLS at your load balancer. Never expose the master key env var to any other process. Set `PIGEON_MASTER_KEY` from a secret manager, not a shell profile.
