# Roadmap

Pigeon Mail is under active development. This page separates what ships
today from what is planned, so the claims stay verifiable.

## Shipped today

- **HTTP API**: sends (quota, idempotency, identity, OpenPGP sealing),
  mailbox reads with sealed-by-default bodies, backup exports (`.eml` per
  message, `.mbox` per folder, streamed), keys, sender aliases, catch-all
  rules, organizations with invitations, suppressions, templates, webhooks,
  TOTP sessions.
- **Inbound SMTP**: ESMTP on `:25` (STARTTLS not advertised: no TLS termination
  in v0.1, issue #99), size and rate limits, no open relay; mail parsed, sealed
  at rest, stored.
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

## Shipped in v0.1

### Inbound authentication evaluation (record mode)

SPF (RFC 7208), DKIM verification (via `pigeon-dkim`) and DMARC policy
evaluation (RFC 7489) run on every inbound message: the connecting peer's IP
is checked against the sender's SPF record, every `DKIM-Signature` header is
verified against the published key, and the DMARC alignment and policy are
evaluated for the `From:` domain. The verdicts (`spf=pass`, `dkim=pass`,
`dmarc=pass`, etc.) decorate the ingest log, the `email.received` event
origin and the `Authentication-Results` header (RFC 8601) on the stored copy.

DNS resolution is real: TXT (SPF/DMARC/DKIM keys), A and AAAA (the SPF `a`
mechanism) are resolved through `hickory-resolver` over the system
configuration. A resolver failure degrades to `none` verdicts — delivery is
never blocked by DNS.

**Record mode, not enforcement.** The published DMARC policy (`p=reject`,
`p=quarantine`) is **evaluated and surfaced**, not **applied**: a message
that fails DMARC is still accepted and delivered, with the fail verdict
recorded. Enforcement (refusing on `p=reject`, quarantining on
`p=quarantine`) is gated behind `PIGEON_SMTP_AUTH_ENFORCE` (default `false`)
and is tracked separately — see [issue #113](#) for the enforcement flag.

> **Outbound DKIM signing ships today**: domains provision an RSA-2048 key
> (RFC 6376 `rsa-sha256`) through the API, stored sealed in the `dkim_keys`
> table, and the delivery worker signs every outbound message with its
> From-domain key. Ed25519 (`ed25519-sha256`, RFC 8463) remains planned.

## Planned

### Inbound authentication enforcement

Apply the published DMARC policy instead of only recording it: `p=reject`
refuses the message at the SMTP level (`550 5.7.1`), `p=quarantine` delivers
to the spam folder, `p=none` keeps the current record-only behavior. Gated
behind `PIGEON_SMTP_AUTH_ENFORCE` (default `false`). The monitor-first,
enforce-later rollout is intentional: SPF/DKIM/DMARC have real false
positives (forwarding, mailing lists, misconfigured peers), so the cycle is
record verdicts for a few weeks, review the DMARC reports arriving at
`postmaster@`, and only then flip the flag.

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
