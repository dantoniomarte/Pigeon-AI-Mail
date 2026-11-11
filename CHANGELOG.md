# Changelog

All notable changes to Pigeon Mail are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

- Full OpenPGP end-to-end sealing (WKD publish/discover, TOFU pinning, per-domain plaintext overrides)
- Backup exports: one message as `.eml`, a whole folder or a selection as `.mbox` (API, webmail and MCP tools)
- Byte-faithful streaming folder backups (page-sized chunks, backpressure)
- MCP `send_email` and `manage_webhooks` connected to the real pipeline (quota, sealing, queueing, webhook store)
- MCP `export_message` / `export_folder` tools (catalog now 35)
- Webmail: bulk selection with delete/export, reader navigation, server-truth unread badges
- Public-repo overhaul: owner infrastructure scrubbed, false capability claims corrected, private-name gate CI-enforced, docs reconciled with the code

## [0.1.2] — 2026-11

### Added

- Outbound delivery to external providers works end to end (per-recipient-domain MX groups, delivered-domain tracking across retries) (#69)
- OpenPGP end-to-end sealing: WKD publish and discover, TOFU pinning, RFC 3156 seal-on-queue, e2e enum on the send surface (#70, #71)
- MX routing fix: sender-domain MX resolution no longer self-loops external mail (#69)
- Provider migration guide (Resend/Postmark/SendGrid/Mailgun/SES) (#68)
- Workflow docs translated to English (#66)

### Fixed

- Queue duplicate mail on retry (delivered-domain bookkeeping) (#71)

## [0.1.1] — 2026-11

### Added

- Sender aliases: a shared address several mailboxes send as and receive for (#65)
- Multi-recipient pausable catch-all (#65)

## [0.1.0] — 2026-11

### Added

- First public release: encrypted email server with agent-first controls
- Rust core crates: strict anti-injection types, XChaCha20 at-rest sealing, TOTP (RFC 6238), Argon2id API keys, Ed25519 DKIM signing, SQLite WAL storage with a `Storage` trait seam
- Full HTTP API (axum), ESMTP inbound (:25), outbound queue worker with lease/backoff/dead-letter
- MCP server: JSON-RPC over stdio, agent-first tool catalog
- React webmail: 5 languages, light/dark themes, session auth
- Installer (`install.sh`), distroless Docker image, Kubernetes skeletons, deployment guide
- Multi-agent compatibility configs for 11 platforms (#34)
- Session-cookie webmail auth with mandatory code on login (#35, #36)

### Fixed

- Webmail sign-out reachable on every screen size (#74)
