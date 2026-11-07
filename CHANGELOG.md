# Changelog

All notable changes to Pigeon Mail are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [v0.1.1] — 2026-11-07

### Added
- Mail folders (inbox/sent/spam/trash) with read/unread state, move, delete and empty-trash — backend endpoints and webmail UI.
- Email drafts: save, list, continue editing, send-from-draft.
- Multi-tenant organizations: members, invitations with one-time bootstrap tokens, catch-all routing (route/discard) in inbound SMTP.
- Admin Console in the webmail (members, roles, invitations, catch-all rules).
- 11 ready-to-use agent configs (`config/`) plus `install.sh --agent`.
- `install.sh --public-ip` (DNS guidance no longer 503s) and a DNS reality check after install.
- `GET /v1/auth/check` so the webmail can probe its HttpOnly session.

### Security
- Every login now requires a second factor (TOTP, recovery or bootstrap token) — the earlier email-only bootstrap issued sessions to anyone who knew the address.
- Row-action tap targets no longer sit invisible over touch clicks; email HTML is sanitized at the compose sinks.

### Fixed
- Webmail: login screen first (API key is the fallback), session-cookie auth for all data fetches, i18n completeness across 5 locales.

## [Unreleased]

### Added
- Repository bootstrap: governance docs (SECURITY, CONTRIBUTING, CoC), hygiene gate (`make verify`) in CI, AGPL-3.0 license, CC BY 4.0 logo assets, roadmap and workflow docs.
