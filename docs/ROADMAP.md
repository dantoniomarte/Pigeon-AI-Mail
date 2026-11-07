# Roadmap

Status: **pre-release, active development.** Checkboxes are claims only when checked, and every item lands through a reviewed PR.

## Phase 0 — Foundations (in progress)

- [x] Repository bootstrap: governance, hygiene gate, license, branding
- [ ] Architecture decision records (language, storage, encryption model)
- [ ] End-to-end encryption model doc, modeled on Proton's public design

## Phase 1 — Core server (Rust)

- [x] Workspace: `pigeon-core` (config, errors, types), encrypted SQLite storage
- [ ] Inbound SMTP: ESMTP on :25, STARTTLS, limits, rate limiting, SPF/DKIM/DMARC evaluation
      — v0.1 ships the hand-rolled ESMTP server (`pigeon-smtp`), sealing and storage; the
      certificate lifecycle, rate limiting and mail authentication stay open (see below)
- [ ] Outbound SMTP: queue, exponential backoff, MX resolution, TLS, bounce handling
      — v0.1 ships MX resolution, opportunistic STARTTLS, the claim/sign/deliver worker,
      backoff and hard-bounce suppression; certificate verification stays open
- [ ] HTTP API (Resend-compatible `POST /v1/emails`), API keys with scopes, idempotency
- [ ] TOTP 2FA (RFC 6238) + recovery codes for dashboard accounts
- [ ] Health probes (`/healthz`, `/readyz`), env-based config, structured logs

### Phase 1 follow-ups opened by the HTTP API slice

The API crate (`pigeon-api`) plus the `pigeon` binary land before SMTPS/webmail, and
they leave three seams that the next PRs must close:

- [ ] Fold `pigeon-api`'s auxiliary SQL (`crates/pigeon-api/src/db.rs`) into the
      `Storage` trait. The trait has no read/admin surface yet (key list/patch/delete,
      queue cancel, email and message pagination, attachments, domains, webhooks,
      suppressions), and ADR 0002 wants one persistence seam; until then the API keeps
      a second connection to the same SQLite file and its own `api_*` tables.
- [ ] Document the two deployment variables the binary reads: `PIGEON_PUBLIC_IP`
      (the A record `/v1/domains/{id}/dns` must publish; without it the endpoint refuses
      to answer) and `PIGEON_LOG_FORMAT=json`.
- [ ] Align the `e2e` value: the API reports `tls_only` (the value `openapi.yaml`,
      `docs/API.md` and `docs/e2ee-model.md` all specify), so either the design note's
      `tls_no_key` spelling wins and the enum changes, or `tls_only` is confirmed.
- [ ] Domains: DNS verification (`?verify=now` currently only records the attempt) and
      RSA DKIM as an alternative to the Ed25519 key issued today (RFC 8463).
- [ ] Session realm: `POST /v1/auth/login` and the `2fa/*` endpoints answer `501` until
      the webmail dashboard ships.

### Phase 1 follow-ups opened by the SMTP slice

`crates/pigeon-smtp` lands the ESMTP engine, and it leaves the gaps below. They are
recorded here rather than in comments so the next slice can pick them up:

- [ ] **Inbound STARTTLS.** The server advertises `STARTTLS` and answers
      `454 4.7.0 TLS not available`: a self-signed certificate lifecycle (generation,
      renewal, operator override) is v0.2. Until then every inbound session is clear text
      and `PIGEON_SMTP_OUT_STARTTLS=required` clients refuse to deliver to us.
- [ ] **Outbound certificate verification.** The client completes a real TLS handshake but
      accepts any certificate (no CA bundle in the image, no pinning). Wire in
      `webpki-roots` plus per-domain pins, then remove `AcceptAnyServerCert`.
- [ ] **SPF/DKIM/DMARC evaluation inbound.** `pigeon-smtp` records `spf=none dkim=none
      dmarc=none` in the `email.received` event and logs them; nothing is verified yet.
      `pigeon-dkim` can verify as soon as domain key lookup over DNS TXT lands.
- [ ] **DKIM signing outbound.** `pigeon-dkim`'s key pair is in-memory only and there is no
      domain key store, so the `pigeon` binary runs the worker with no signer and logs that
      outbound mail is unsigned. `QueueWorker::new` already accepts a key.
- [ ] **Terminal `bounced` queue status.** `Storage::queue_fail` only reaches a terminal
      state through `max_attempts`, so a hard bounce is recorded (`email.bounced`), the
      recipient is suppressed, and the job is completed. A `status = 'bounced'` row would
      let operators see bounced jobs in the dead-letter listing.
- [ ] **Smarthost and submission.** `PIGEON_SMTP_OUT_ADDR` is interpreted as a smarthost
      (`host:port`) for outbound relay; a submission port (587, `AUTH`, per-account
      credentials) is still missing, so nothing can submit mail through us yet.
- [ ] **Account lookup for inbound mail.** Recipient → account resolution goes through
      `ApiDb::account_id_by_email`, and the wrapped content key is stored in `api_messages`.
      Both belong on the `Storage` trait with the rest of the auxiliary SQL.
- [ ] **Inbound rate limiting and concurrency caps.** Limits today are per session
      (size, recipients, line length, command count, timeouts). Per-IP connection and
      recipient-rate limits are not implemented.

## Phase 2 — Agents & automation

- [ ] Built-in MCP server (send, list, read, webhooks, templates)
- [ ] Webhooks: delivered / bounced / complained events with signed payloads
- [ ] Templates with variables, scheduled sending
- [ ] Client examples: curl, TypeScript, Python, MCP config

## Phase 3 — Encryption

- [ ] Storage-at-rest encryption (XChaCha20-Poly1305, master key management)
- [ ] OpenPGP end-to-end delivery when recipient publishes keys (WKD)
- [ ] Key rotation, export, recovery flows

## Phase 4 — Webmail (optional at install)

- [ ] Installer with `--no-webmail` option; Docker image variants
- [ ] Webmail UI: inbox, reading, compose, settings; light/dark; ES/EN/PT/FR/DE; animations toggle
- [ ] Visual test suite (multi-viewport screenshots, i18n checks, reduced motion)

## Phase 5 — Distribution-ready

- [ ] Helm chart / K8s manifests, multi-node docs (stateless API + shared storage path)
- [ ] Performance: async send pipeline benchmarks, memory profile
- [ ] First tagged release `v0.1.0` + install script + docs site

## Non-goals (for now)

- IMAP/JMAP server (Pigeon is API/MCP/webmail first)
- Calendar/contacts sync
- Marketing campaigns with tracking pixels (privacy-first: no open tracking)
