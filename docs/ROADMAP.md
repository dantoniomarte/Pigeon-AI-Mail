# Roadmap

Pigeon Mail is under active development. This page separates what ships
today from what is planned, so the claims stay verifiable.

## Shipped today

- **HTTP API**: sends (quota, idempotency, identity, OpenPGP sealing),
  mailbox reads with sealed-by-default bodies, backup exports (`.eml` per
  message, `.mbox` per folder, streamed), keys, sender aliases, catch-all
  rules, organizations with invitations, suppressions, templates, webhooks,
  TOTP sessions.
- **Inbound SMTP**: ESMTP on `:25` with STARTTLS advertised, size and rate
  limits, no open relay; mail parsed, sealed at rest, stored.
- **Outbound delivery**: queue with lease/backoff/dead-letter,
  per-recipient-domain MX groups, delivered-domain tracking across retries,
  opportunistic STARTTLS.
- **OpenPGP end-to-end**: WKD publish and discover, TOFU pinning,
  RFC 3156 seal-on-queue, per-domain plaintext overrides.
- **MCP server**: 35 tools over stdio, including real sends and backup
  exports; 11 platform configs under `config/`.
- **Webmail**: React SPA with 5 locales, session auth, bulk operations,
  backups.
- **Operations**: distroless Docker image, `install.sh`, Kubernetes
  skeletons.

## Planned

### Inbound authentication evaluation

SPF, DKIM and DMARC evaluation on inbound mail. Today the ingest records
verdicts as `none`; the webhook payloads and the message view already carry
the fields, so the evaluation slots in without a contract change.

> **Outbound DKIM signing ships today**: domains provision an RSA-2048 key
> (RFC 6376 `rsa-sha256`) through the API, stored sealed in the `dkim_keys`
> table, and the delivery worker signs every outbound message with its
> From-domain key. Ed25519 (`ed25519-sha256`, RFC 8463) remains planned.

### Submission port

`:587` with `AUTH` (per-account credentials) so local clients submit mail
without going through the API. No listener is bound today (compose files
should not publish the port yet); both the listener and the `AUTH` verb are
the remaining work.

### Outbound peer certificate validation

The outbound client uses opportunistic STARTTLS and currently accepts any
server certificate. Chain validation plus a per-domain `strict` mode
(certificate pinning) are planned; the per-domain override for plaintext
already exists.

### Webmail decryption of sealed mail

The webmail reads metadata today; decrypting layer-3 sealed bodies in the
browser needs a WebCrypto OpenPGP path and a per-session key decision.

### Mobile/responsive polish and accessibility pass

The webmail is responsive and keyboard-friendly; a dedicated accessibility
audit is planned.
