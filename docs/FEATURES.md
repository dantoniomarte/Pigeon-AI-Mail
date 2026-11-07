# Feature parity & inspiration map

Pigeon Mail is its own product (self-hosted, encrypted-by-default, agent-first), but it is
**API-compatible with Resend** where it counts and borrows proven ideas from the open-source
alternatives studied in November 2026. This page records what we adopt, adapt, and reject.

## Sources studied

- **Resend** — official docs index (`resend.com/docs/llms.txt`), API reference, webhook taxonomy.
- **opensend.cc** (Apache-2.0) — self-hosted Resend-compatible API on Next.js/Convex/AWS SES:
  dashboard structure (api-keys, emails sent/receiving, suppressions, logs, metrics, webhooks
  with per-delivery view, MFA), installer-first distribution (`curl | sh`).
- **Postal** — full delivery platform: webhooks on delivery/bounce/complaint, IP pools,
  spam-filter integrations, dev mode that holds the queue, horizontal scaling.
- **Mailpit / MailHog** — developer SMTP sandbox + REST API (inspiration for sandbox mode).
- **Stalwart** — Rust all-in-one mail server (language precedent, ADR 0001).
- **Listmonk** — campaigns/newsletters (out of v1 scope).

## Resend-compatible API contract (v1)

| Resend feature | Pigeon v1 |
|---|---|
| `POST /emails` single send (`from, to, subject, html/text, cc, bcc, reply_to, headers, tags, attachments`) | ✅ same shape (`/v1/emails`) |
| `Idempotency-Key` header (24 h dedup), also via SMTP header | ✅ same semantics — dedup holds until the send completes plus 24 h (covers the scheduled horizon) |
| Batch send (up to 100 per call) | ✅ `POST /v1/emails/batch` |
| Scheduled send (`scheduled_at`) | ✅ |
| Custom headers, tags | ✅ |
| Attachments (base64), inline images | ✅ |
| Templates + variables | ✅ `/v1/templates` (API-first; no dashboard editor in v1) |
| Webhooks: `email.sent/delivered/delivery_delayed/bounced/failed/received` (+ signing secret, retries) | ✅ same event names + HMAC-SHA256 signature header, exponential retry |
| Get email / list emails, receiving: get content, list | ✅ |
| API keys with permission scopes | ✅ `pk_…` keys, scopes `send`/`read`/`full`, Argon2id at rest |
| Sandbox/test sending | ✅ per-key boolean flag `sandbox` (`PATCH /v1/account/keys/{id}`, or the `PIGEON_SANDBOX=1` environment default) — **not a scope**: accepted, stored, never delivered (Mailpit-style) |
| Suppressions (hard-bounce auto-add) | ✅ `/v1/suppressions`, auto-add on hard bounce |
| Domains: verify + DNS records guidance (SPF/DKIM/DMARC) | ✅ self-hosted variant: `GET /v1/domains/{id}/dns` returns the exact records to publish (we generate DKIM keys) |
| SMTP relay interface | ✅ submission on :587 with API-key AUTH (x-smtpapi idempotency header supported) |
| SDKs (15 langs), CLI, MCP server | ✅ MCP server built-in; TS/Py SDK examples; CLI `pigeon` |
| DMARC report analyzer, BIMI, open/click tracking, audiences/segments/broadcasts, automations, inboxes/threads | ❌ later phases — open/click tracking is a **deliberate non-goal** (privacy-first) |
| Webhook replay endpoint (re-deliver a stored event) | ❌ later phases — v1 exposes delivery events only; replay is a v0.2 candidate (see `docs/API.md`) |

## Adopted from alternatives

- From **opensend**: per-delivery webhook inspection, installer-first onboarding, MFA in the dashboard.
- From **Postal**: dev mode that holds the queue, clear bounce taxonomy feeding suppressions, scale-out story (we add the Storage-trait seam; see ADR 0002).
- From **Mailpit**: sandbox mode with full REST introspection for test suites.
- From **Stalwart**: single-binary Rust ops posture.

## Rejected on purpose

- Open/click tracking pixels (privacy-first; also a spam-filter liability).
- Marketing campaign editor (out of scope; use Listmonk on top of Pigeon's SMTP relay).
- Vendor lock-in formats: everything exportable (messages, keys, events).
