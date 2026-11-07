# Migrating to Pigeon Mail

Field-by-field equivalences for moving from a commercial email provider to
Pigeon. Everything here was verified against each provider's official API
reference (November 2026).

## The two universal paths

1. **SMTP** — every provider in this list offers SMTP, and Pigeon has a full
   SMTP stack (`:587` submission with AUTH, `:25` MX). Most applications can
   migrate by changing three settings: host, port, credentials. No code paths
   change.
2. **Resend-style JSON** — Pigeon's HTTP API is Resend-compatible: flat JSON,
   array recipients, `Idempotency-Key` header, attachments as base64 with
   `content_id` for inline images, tags, scheduled sends, templates with
   variables, webhooks. It is the closest format to Pigeon and the recommended
   integration for new code.

## Resend → Pigeon (drop-in)

The payloads are field-for-field identical; change the base URL and key prefix.

| Resend | Pigeon |
|---|---|
| `https://api.resend.com/emails` | `https://your-host/v1/emails` |
| `Authorization: Bearer re_…` | `Authorization: Bearer pk_…` |
| `from`, `to[]`, `subject`, `html`, `text`, `cc[]`, `bcc[]` | identical |
| `attachments[{filename, content, content_id}]` | identical |
| `tags[{name, value}]` | identical |
| `headers{}` | identical |
| `scheduled_at` | identical (ISO 8601) |
| `Idempotency-Key` header | identical |
| response `{id}` | `{id, status, e2e}` (`id` matches) |
| `POST /emails/batch` | `POST /v1/emails/batch` (per-index results) |
| Templates CRUD, webhooks, domains, suppressions | same paths under `/v1/…` |

Two documented deviations: Pigeon returns **202** on send (accepted ≠
delivered; track via `GET /v1/emails/{id}` or webhooks) and errors use
problem+json (RFC 7807).

## Postmark → Pigeon

`POST https://api.postmarkapp.com/email` → `POST https://your-host/v1/emails`

| Postmark | Pigeon |
|---|---|
| `From` | `from` |
| `To` (comma-separated string) | `to` (JSON array) |
| `Cc`, `Bcc` (comma-separated) | `cc`, `bcc` (arrays) |
| `Subject` | `subject` |
| `HtmlBody` | `html` |
| `TextBody` | `text` |
| `ReplyTo` | `reply_to` |
| `Headers: [{Name, Value}]` | `headers: {Name: Value}` |
| `Attachments: [{Name, Content, ContentType, ContentID}]` | `attachments: [{filename, content, content_id?}]` |
| `Tag` | `tags: [{name, value}]` |
| `MessageStream` | no equivalent (single transactional stream) |
| `TrackOpens`, `TrackLinks` | no equivalent (Pigeon does not track opens/clicks by design) |
| `Metadata` | `tags` (closest match) |
| `X-Postmark-Server-Token` header | `Authorization: Bearer pk_…` |
| response `{MessageID, ErrorCode, Message}` | 202 `{id, status}` |

Batch: `POST /email/batch` (array body) → `POST /v1/emails/batch`
(`{messages: [...]}` envelope, per-index results).

## SendGrid → Pigeon

`POST https://api.sendgrid.com/v3/mail/send` → `POST https://your-host/v1/emails`

SendGrid's nested `personalizations` shape flattens:

| SendGrid | Pigeon |
|---|---|
| `personalizations[].to[].email` | `to` (flat array) |
| `personalizations[].cc[].email` | `cc` (flat array) |
| `personalizations[].bcc[].email` | `bcc` (flat array) |
| `personalizations[].subject` | `subject` (one per message) |
| `personalizations[].custom_args` / `send_at` | `tags` / `scheduled_at` |
| `from.email`, `from.name` | `from` (`Name <addr>` format supported) |
| `subject` (root) | `subject` |
| `content: [{type: "text/plain", value}]` | `text` |
| `content: [{type: "text/html", value}]` | `html` |
| `reply_to.email` | `reply_to` |
| `attachments[{content, filename, content_id, type, disposition}]` | `attachments[{filename, content, content_id?}]` |
| `categories`, `custom_args` | `tags` |
| `mail_settings`, `tracking_settings` | no equivalent (no tracking by design) |
| `Authorization: Bearer SG.…` | `Authorization: Bearer pk_…` |
| response `202 {X-Message-Id}` | 202 `{id, status}` |

One SendGrid call with N personalizations = N Pigeon calls (or one batch with N
messages).

## Mailgun → Pigeon

`POST https://api.mailgun.net/v3/{domain}/messages` (multipart/form-data or
`application/x-www-form-urlencoded`) → `POST https://your-host/v1/emails` (JSON)

Mailgun's send endpoint is **not JSON** — a migration rewrites the call:

| Mailgun (form field) | Pigeon (JSON) |
|---|---|
| `from` | `from` |
| `to`, `cc`, `bcc` | `to[]`, `cc[]`, `bcc[]` |
| `subject` | `subject` |
| `text`, `html` | `text`, `html` |
| `o:tag` | `tags: [{name, value}]` |
| `o:deliverytime` | `scheduled_at` |
| `attachment` (multipart file) | `attachments: [{filename, content(base64)}]` |
| `h:Reply-To`, other `h:*` | `reply_to`, `headers{}` |
| `v:my-var` | `tags` (closest match) |
| Basic Auth `api:YOUR_KEY` | `Authorization: Bearer pk_…` |
| response `{id, message}` | 202 `{id, status}` |

MIME pass-through (`POST …/messages.mime`) has no direct equivalent; if you
send pre-built MIME, use Pigeon's SMTP path instead.

## Amazon SES → Pigeon (rewrite required — not drop-in)

**There is no endpoint-compatible path.** SES authenticates with
[SigV4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
(request signing with IAM credentials — not a static bearer token), nests the
payload under `Content`/`Destination`, and lives on region-scoped AWS hosts.
Pigeon does not implement the SES wire protocol.

`POST /v2/email/outbound-emails` → `POST https://your-host/v1/emails`

| SES v2 (nested) | Pigeon (flat) |
|---|---|
| `FromEmailAddress` | `from` |
| `Destination.ToAddresses[]` | `to` (flat array) |
| `Destination.CcAddresses[]` | `cc` |
| `Destination.BccAddresses[]` | `bcc` |
| `Content.Simple.Subject.Data` | `subject` |
| `Content.Simple.Body.Text.Data` | `text` |
| `Content.Simple.Body.Html.Data` | `html` |
| `Content.Simple.Attachments[{FileName, RawContent/base64, ContentId, ContentType}]` | `attachments[{filename, content, content_id?}]` |
| `Content.Simple.Headers[{Name, Value}]` | `headers{}` |
| `ReplyToAddresses[]` | `reply_to` |
| `EmailTags[{Name, Value}]` | `tags[{name, value}]` |
| `Content.Template.{Name,TemplateData}` | `template_id` + `variables` |
| `ConfigurationSetName` | no equivalent (per-account settings replace it) |
| IAM SigV4 signing | `Authorization: Bearer pk_…` |
| response `{MessageId}` | 202 `{id, status}` |

The mapping itself is mechanical — the work is replacing the AWS SDK call
(signature, retries, region logic) with a plain HTTPS POST. If the application
sends via the AWS SDK, budget an afternoon; if it already posts JSON over
HTTPS, it is a payload reshape.

Templates differ in shape too: SES templates live in SES with
`{{Handlebars}}`-style data; Pigeon templates store `{{variable}}` bodies and
take a `variables` object. Migration is a copy + syntax check.

## Webhooks

| Event | Resend | Postmark | SendGrid | Mailgun | SES | Pigeon |
|---|---|---|---|---|---|---|
| delivered | ✅ | ✅ | ✅ | ✅ | ✅ (SNS) | ✅ |
| bounced | ✅ | ✅ | ✅ | ✅ | ✅ (SNS) | ✅ |
| complained/spam | ✅ | ✅ | ✅ | ✅ | ✅ (SNS) | ✅ |
| failed | ✅ | ✅ | ✅ | ✅ | ✅ (SNS) | ✅ |
| opened / clicked | ✅ | ✅ | ✅ | ✅ | ✅ (SNS) | ❌ by design |
| inbound received | ✅ | ✅ | ✅ (Inbound Parse) | ✅ | ✅ (SNS) | ✅ |
| signature | HMAC | basic token verification | ECDSA/SVG | HMAC timestamp | SNS SigV4 | HMAC-SHA256 |

Pigeon covers the transactional set. Open/click tracking is intentionally
absent — a privacy-first mail server does not instrument recipients.

## Migrating a sending SDK

| You use today | Pigeon path |
|---|---|
| `resend-rs` / any Resend SDK | change base URL + key, keep the SDK |
| `postmark` crates/clients | rewrite the one POST (see table) |
| `sendgrid` crates/clients | flatten `personalizations` (see table) |
| Mailgun form posts | rebuild as JSON (see table) |
| `aws-sdk-sesv2` | replace the SDK call with a plain HTTPS POST (see table) |
| raw SMTP (any provider) | change host/port/credentials — nothing else |
