# Pigeon Mail — HTTP API reference

Base URL: `https://mail.<your-domain>` · All errors are RFC 7807 `application/problem+json` · All timestamps are ISO 8601 UTC.
Machine-readable contract: [`openapi.yaml`](../openapi.yaml) (this page and the spec are kept consistent; CI lints the YAML).

## Authentication

Two auth realms:

- **API keys** (`Authorization: Bearer pk_...`) — for machines, agents and apps.
- **Sessions** (`pigeon_session` cookie, HttpOnly/SameSite=Strict) — for the dashboard/webmail login (`POST /v1/auth/login`). **2FA protects sessions**, not API keys.

**Scopes** (API keys). There is no blanket "read means all GETs" rule; the tier is per operation:

| Scope | Grants |
|---|---|
| `send` | `POST /v1/emails`, `POST /v1/emails/batch`, cancel via `DELETE /v1/emails/{id}`, mailbox writes (folder/read `PATCH`, `DELETE` and empty-trash on `/v1/messages`), template create/update/delete, `POST /v1/templates/{id}/test-send`, draft save/update/delete/send. |
| `read` | Inbox and discovery GETs: emails (`/v1/emails*`, including sandbox raw MIME), messages, attachments, templates, drafts. Metadata and sealed blobs only. |
| `full` | The admin GETs — domains, webhooks, suppressions, keys — plus every write to those, plus **decrypted bodies** (`?sealed=false`). Account administration, including organizations, members, invitations and catch-all routing. |

The spec carries this per-operation in `x-scopes` on each path, so `read` on `/v1/domains` is a `403`, not a silent widening.

**Rate limits** (per key): 10 req/s sustained, burst 50; daily send quota per account (default 50,000). 429 responses carry `Retry-After` and the `X-RateLimit-*` headers; other responses expose them on the send endpoints. Exceeded → `429` problem type `rate-limited`; quota → `402` problem type `quota-exceeded`.

## Send email

### `POST /v1/emails`

Queues a message for delivery. Returns **202** (not 201, and not Resend's 200 — documented deviation): accepted ≠ delivered; the pipeline is at-least-once with retries. Track lifecycle via `GET /v1/emails/{id}` or webhooks.

**Request**

```json
{
  "from": "Dana <dana@pigeonmail.dev>",
  "to": ["carol@example.org", "dave@example.net"],
  "cc": [], "bcc": [],
  "reply_to": "support@pigeonmail.dev",
  "subject": "Invoice #2041 paid",
  "html": "<p>Thanks! Your renewal was processed.</p>",
  "text": "Thanks! Your renewal was processed.",
  "headers": { "X-Campaign": "nov-billing" },
  "attachments": [{ "filename": "receipt.pdf", "content": "<base64>", "content_id": "receipt" }],
  "tags": ["billing", "renewal"],
  "idempotency_key": "invoice-2041-paid-v1"
}
```

| Field | Rules |
|---|---|
| `from` | Required. A managed address of the caller's account, or any address on a verified domain. |
| `to`/`cc`/`bcc` | **Total recipients across the three ≤ 50.** Bcc is envelope-only and **never appears in the generated MIME** nor in any response. |
| `subject` | Required unless `template_id`. ≤ 998 chars. |
| `html` / `text` | At least one of both (or a template). |
| `headers` | Custom headers. **Server-set denylist**: `From, To, Cc, Bcc, Reply-To, Return-Path, Received, Message-ID, Date, Content-Type, Content-Transfer-Encoding, DKIM-Signature, Authentication-Results`. Names/values containing CR/LF → `422`. Unknown fields in the body → `422` (schemas are closed). |
| `attachments` | ≤ 10 per message, ≤ 25 MB decoded total (base64 request body ≤ 35 MB → `413` beyond); `content` is base64; `content_id` makes it inline (`cid:receipt`). |
| `tags` | ≤ 10, each `[a-z0-9-]{1,40}`. |
| `template_id` + `variables` | Render a stored template; `{{variables}}` substituted in subject/html/text. |
| `scheduled_at` | Future ISO 8601; message stays `scheduled` until then. |
| `idempotency_key` | ≤ 255 chars; also via `Idempotency-Key` header. **Dedup holds until the send completes plus 24 h** — so scheduled sends are covered for their whole horizon. A repeat returns `409` (problem type `idempotent-replay`) with the **original** email id in `id`. |

**Response 202**

```json
{ "id": "eml_9f2a44c1", "status": "queued", "e2e": "sealed" }
```

`e2e` reports the payload protection, aligned with [docs/e2ee-model.md](e2ee-model.md):

- `sealed` — OpenPGP to the recipient's published key (Pigeon↔Pigeon or WKD).
- `tls_only` — STARTTLS transport, no recipient key discovered (the e2ee model's "key discovery failure" case).
- `plaintext_override` — explicit per-domain plaintext override (always logged).

**Errors**: `422 validation` (field-level `errors[]`) · `402 quota-exceeded` (quota{limit,used,reset_at}) · `429 rate-limited` · `409 idempotent-replay` · `413` body too large.

### `POST /v1/emails/batch`

Request — the array is always wrapped in `items` (max 100):

```json
{ "items": [ { "from": "...", "to": ["a@b.c"], "subject": "...", "text": "..." } ] }
```

Response **202** — the array is always wrapped in `results`, one entry per submitted item, each carrying its `index`:

```json
{ "results": [ { "index": 0, "id": "eml_9f2a44c1", "status": "queued" },
               { "index": 1, "error": { "type": "validation", "title": "...", "status": 422 } } ] }
```

One invalid item never blocks the rest.

## Track & manage

### `GET /v1/emails/{id}`

```json
{ "id": "eml_9f2a44c1", "status": "sent", "created_at": "...", "last_event": "...",
  "from": "Dana <dana@pigeonmail.dev>", "to": ["carol@example.org"], "cc": [],
  "subject": "...", "tags": ["billing"], "sandbox": false,
  "mx": { "host": "mx1.example.org", "tls": "TLSv1.3" }, "e2e": "sealed" }
```

Lifecycle: `queued → scheduled → sending → sent | deferred {next_attempt_at, attempts} | bounced {code, reason, hard} | failed {reason} | cancelled`. Hard bounces auto-add the recipient to suppressions (removable via `/v1/suppressions`).

`?raw=true` returns `{id, mime}` — the exact generated MIME. **Only for sandbox-origin messages**: a sandbox key requesting a non-sandbox message gets `403`.

### `GET /v1/emails?limit≤100&offset&status&tag` — page `{items, page:{total, has_more, next_offset}}`. `DELETE /v1/emails/{id}` — cancels only while `queued`/`scheduled` (else `409 not-cancellable`).

## Receive (inbound)

### `GET /v1/messages?folder=inbox|sent|spam|trash&limit≤500&offset` — metadata page (never bodies). `folder` defaults to `inbox`; an unknown value is `422 validation`. Items carry `folder` and `read`, and the page carries `counts: {inbox, sent, spam, trash}` for the sidebar badges — one request renders the whole mailbox.

```json
{ "items": [ { "id": "msg_00000001", "from_addr": "carol@example.org", "subject": "...",
                "created_at": "...", "folder": "inbox", "read": true } ],
  "page": { "total": 1, "has_more": false, "next_offset": null },
  "counts": { "inbox": 1, "sent": 0, "spam": 0, "trash": 0 } }
```

### `PATCH /v1/messages/{id}` — `{folder?: inbox|sent|spam|trash, read?: bool}`, at least one member. Moves the message and/or flips read state and returns the updated metadata (`200`). Unknown id → `404`, unknown folder → `422 validation`.

### `DELETE /v1/messages/{id}` — permanent delete of the message and its lifecycle metadata (`204`). Moving to `trash` is a `PATCH`, not a delete.

### `POST /v1/messages/empty-trash` — purges the caller's trash, `200 {deleted: N}` (idempotent: an already-empty trash reports `0`).

Mailbox mutations (`PATCH`/`DELETE`/`empty-trash`) require scope `send`, matching cancel-email; the listing requires `read`.

### `GET /v1/messages/{id}`

Two views (oneOf):

- **Default (`?sealed=true`)** — `SealedMessageView`: metadata + auth verdicts + `sealed_body` ciphertext, **plus the attachment list** (`id`, `filename`, `size`). A `read` key can therefore see that a message carries `receipt.pdf` and how large it is, while the attachment content stays sealed until the caller holds scope `full`. No plaintext leaves the server.
- **`?sealed=false`** — `DecryptedMessageView` (text/html + attachments): **requires scope `full`** (`read` keys get `403 forbidden`). This is the credential/scope rule for plaintext.

### `GET /v1/messages/{id}/attachments/{aid}` — attachment bytes; sealed by default, decrypted with scope `full` (`?sealed=false`).

## Templates

`POST /v1/templates` {name (unique per account → `409` on dup), description ≤ 500, subject, html, text} · `GET /v1/templates` · `GET/PATCH/DELETE /v1/templates/{id}` (PATCH is partial; id/updated_at are server-owned) · `POST /v1/templates/{id}/test-send` {to≤5, variables}.

`description` is plain text and optional (empty → omitted from responses); it exists so the template picker can show *what a template is for* without opening it. **Templates are unlimited**: a name is unique per account and that is the only constraint — there is no count cap in the schema or in the store. Version history: v0.2 candidate.

## Drafts

Save an email now and continue it later. A draft is editable content, so it lives in its own table: rich-text `html`, `text`, recipient lists, tags and base64 `attachments` are stored as written, unsealed, and echoed back to their own account (including `bcc` — nothing has left yet).

| Method & path | Body | Result |
|---|---|---|
| `POST /v1/drafts` | `{from?, to?, cc?, bcc?, subject?, html?, text?, attachments?, tags?}` — every member optional | `201 {id: "drf_…", …}` |
| `GET /v1/drafts?limit&offset` | — | `200 {items: [Draft], page}` (newest save first) |
| `GET /v1/drafts/{id}` | — | `200 Draft` (bodies included) |
| `PATCH /v1/drafts/{id}` | any subset of the create body | `200 Draft`; present members replace, absent members are kept, `updated_at` is bumped |
| `DELETE /v1/drafts/{id}` | — | `204` |
| `POST /v1/drafts/{id}/send` | — | `202 SendAccepted` |

`POST /v1/drafts/{id}/send` is **not** a second send implementation: the draft's fields become the same request `POST /v1/emails` takes, so quota, validation (`422` + `errors[]`), sealing, attachment encryption and queueing behave identically. Attachment `content` is already base64 JSON and passes straight through. The draft is deleted only **after** the email was accepted — a failed send keeps the draft, and a `422` on send (for example a draft with no recipient) leaves it untouched.

Draft writes need scope `send`, listing needs `read`. Drafts are per account: an id from another account is a `404`, never a cross-account read.

## Domains

`GET /v1/domains` · `POST /v1/domains` {name} · `GET /v1/domains/{id}?verify=now` · `GET /v1/domains/{id}/dns` — records are **not** inlined on the domain object; a fresh `POST` returns the domain and you read the exact records to publish from the `/dns` introspection sub-resource, with **priority as a separate field** (never embedded in `value`):

| Type | Host | Value | Priority |
|---|---|---|---|
| A | `mail.<domain>` | your server IP | — |
| MX | `<domain>` | `mail.<domain>.` | 10 |
| TXT | `<domain>` | `v=spf1 a mx -all` | — |
| TXT | `<selector>._domainkey.<domain>` | DKIM public key (server-generated) | — |
| TXT | `_dmarc.<domain>` | `v=DMARC1; p=quarantine; rua=mailto:postmaster@<domain>` | — |

Verification: auto re-check every 15 min; `?verify=now` forces one.

## Webhooks

`POST /v1/webhooks` {url, events, secret?} — `secret` is **optional**: when omitted the server generates one (`whsec_` + 43 base64url chars); if you provide one it must be ≥ 32 chars of `[A-Za-z0-9_-]`. Events: `email.sent`, `email.delivered`, `email.delivery_delayed`, `email.bounced`, `email.failed`, `email.received`. **Secrets are returned exactly once at creation** and never on GET/list.

**Signature — verify with the timestamp (replay protection):**

```
X-Pigeon-Signature: sha256=<hex hmac-sha256("<timestamp>.<raw_body>", secret)>
X-Pigeon-Timestamp: 1699286400
```

Reject when `|now − timestamp| > 300 s`, or the MAC differs. Compare in **constant time**.

**Node verifier (compiles as-is):**

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyPigeon(rawBody: string, ts: string, sig: string, secret: string): boolean {
  const sent = Number(ts);
  if (!Number.isFinite(sent) || Math.abs(Date.now() / 1000 - sent) > 300) return false;
  const expect = "sha256=" + createHmac("sha256", secret).update(`${ts}.${rawBody}`).digest("hex");
  const a = Buffer.from(expect), b = Buffer.from(sig);
  return a.length === b.length && timingSafeEqual(a, b);
}
```

**Python:**

```python
import hmac, hashlib, time
def verify_pigeon(raw_body: str, ts: str, sig: str, secret: str) -> bool:
    try:
        sent = int(ts)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - sent) > 300: return False
    expect = "sha256=" + hmac.new(secret.encode(), f"{ts}.".encode() + raw_body.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, sig)
```

Retries: 10 attempts, exponential 1 min → 6 h, then dropped. Replay endpoint: v0.2 candidate (was mislabeled v1 in FEATURES; fixed there too).

Payloads are the `Event` schema (openapi) — field names match the internal contract (`from_addr`, `to` arrays where multiple, `auth` object); Resend-style mapping: `from_addr → from`. Sandbox sends **never** emit delivery webhooks.

## Account, keys, sessions & 2FA

**API keys** (scope `full`):

| Endpoint | Purpose |
|---|---|
| `POST /v1/account/keys` {name, scopes, sandbox?} | Create → `pk_...` shown **once**. |
| `GET /v1/account/keys` | List (metadata; never key material; shows last_used_at). |
| `PATCH /v1/account/keys/{id}` | `{revoked: true}` to revoke (compromised key), sandbox toggle, rename. |
| `DELETE /v1/account/keys/{id}` | Delete immediately (audited). |

**Dashboard/webmail sessions & 2FA** (session cookie realm):

| Endpoint | Purpose |
|---|---|
| `POST /v1/auth/login` {email, password, code?} | Session login. **Every login requires `code`**: a TOTP code (6/8 digits), a recovery code, or the invitation/bootstrap token. See the challenge below. |
| `POST /v1/auth/logout` | Revokes the session the request authenticated with. `204`. |
| `GET /v1/auth/check` | `204` when the session cookie is valid — the browser cannot read the HttpOnly cookie, so the webmail probes the server instead. |
| `POST /v1/account/2fa/enroll` {password} | Re-auth required; → `{secret_base32, otpauth_uri}`. |
| `POST /v1/account/2fa/activate` {code} | → 10 one-time recovery codes, shown once. |
| `POST /v1/account/2fa/verify` {code} | Step-up check for the current session → `200` valid; wrong code → `422`, `429` when limited. |
| `POST /v1/account/2fa/disable` {code} | Disable — **POST, never DELETE** (DELETE bodies are the first thing proxies and browsers drop). Requires a current valid code: TOTP **or** a recovery code. |

**The login challenge.** `POST /v1/auth/login` takes `{email, password, code?}` and has exactly two success shapes:

- `200` + `Set-Cookie: pigeon_session=…; HttpOnly; SameSite=Strict` — 2FA is not enrolled, or a valid `code` was supplied.
- **`403` with problem type `mfa-required`** — 2FA is enrolled and the `code` is missing or wrong. That 403 *is* the challenge, not a hard failure: the client re-posts the same body plus `code` (a 6- or 8-digit TOTP, or a one-time recovery code). Recovery codes are accepted at login **and** at `POST /v1/account/2fa/disable`, so a lost authenticator is never a lockout.

**Verify replays.** `POST /v1/account/2fa/verify` is where replay protection lives: `crypto` owns the stateless TOTP check, and the **service layer persists the last-used counter**, refusing a code that was already consumed in the same time step. Codes are rate-limited — 5 failures per 15 minutes → `429` — which bounds online brute force.

Holding a `full` API key does **not** grant or bypass 2FA enrollment — keys and sessions are separate realms.

**Bootstrap tokens (what an account with no 2FA can do with `code`).** When 2FA is *not* enrolled, a `code` in the login body is read as a **bootstrap/invitation token** — the one-time string returned by `POST /v1/orgs/{id}/members` or `POST /v1/orgs/{id}/invitations`:

- It is accepted only if it matches a **pending, unexpired** invitation addressed to that login's own address. Redemption burns it (one use), and a replay is `401 unauthorized`.
- A code that matches nothing is a **failed** login (`401`), never a silent success: the server does not answer "wrong code, but here is your session anyway".
- With **no** `code`, the login is rejected (`403 mfa-required`). Every login requires a second factor: a TOTP code, a recovery code, or the invitation/bootstrap token. (The earlier email-only bootstrap was a session-issuance hole — anyone who knew the address could log in — and was removed.)

## Organizations, members & invitations

A **multi-tenant** deployment groups accounts into organizations. **One account is one mailbox**: an organization groups mailboxes, it never merges them — every member keeps their own address, their own sealed mail and their own AI-agent connection (`POST /v1/account/keys`). The address stays globally unique (one address, one account).

Roles, inside one organization: `owner` (full control, including other owners), `admin` (members, invitations, display names — but **not** ownership), `member` (own mailbox only). An account with no organization is a **personal workspace**, and its single account is its own `owner`.

Every `/v1/orgs/{id}/…` operation requires the caller to be an `owner` or `admin` **of that organization** (`403` otherwise, and a non-member gets the same `403` for an existing and a nonexistent id, so the endpoints are not an existence oracle).

| Endpoint | Purpose |
|---|---|
| `POST /v1/orgs` {name} | Create an organization; the caller becomes its owner → `201`. |
| `GET /v1/orgs` | The organizations the caller belongs to, each with the caller's `role` (empty for a personal workspace). |
| `GET /v1/orgs/{id}/members` | Members (owner/admin of that organization). |
| `POST /v1/orgs/{id}/members` {email, display_name?, role?} | Create the account immediately (**no password**: v0.1 has no password realm) → `201 {member, bootstrap_token}`. The token is shown **once**. |
| `PATCH /v1/orgs/{id}/members/{account_id}` {role?, display_name?} | Change role/name. Demoting the **last owner** → `409` problem type `last-owner`. Only an owner may grant or take away `owner`. |
| `POST /v1/orgs/{id}/invitations` {email, role?} | Mint a one-time invitation token → `201 {invitation, token}`. **No mail is sent**: the admin delivers the token out of band. Re-inviting the same address replaces the pending token. |
| `GET /v1/orgs/{id}/invitations` | Pending and historical invitations; the token is never listed. |
| `DELETE /v1/orgs/{id}/invitations/{invitation_id}` | Revoke a pending token. |
| `POST /v1/invitations/accept` {token} | Redeem a token against the **caller's own** account: links it to the organization with the invited role and burns the token. Wrong address → `403`; replay/expired → `404`; already in another organization → `409`. |

Tokens are 32 OS-random bytes as unpadded base64url; only their Argon2id hash is stored, the expiry is seven days, and **ownership is never grantable by invitation** — promoting somebody is the `PATCH` above, which is visible in the member list.

Honest limits of this surface: accepting an invitation links an existing account rather than creating a mailbox (account creation is `POST /v1/orgs/{id}/members`, which returns the bootstrap token), there is no invitation email, and the cross-organization operator panel is a separate (next) surface — these endpoints are tenant-scoped.

## Catch-all routing

What the **inbound** SMTP server does with mail addressed to a local part no account holds. A rule is per **domain**, and with no rule the server keeps answering `550` (never an open relay).

| Endpoint | Purpose |
|---|---|
| `GET /v1/catchall` | Every rule (owner/admin). |
| `PUT /v1/catchall/{domain}` {action, target_account_id?} | Upsert. `route` requires a `target_account_id` **of that same domain**; `discard` forbids one. |
| `DELETE /v1/catchall/{domain}` | Remove the rule; unknown recipients go back to `550`. |

- **`route`** — the message is delivered into the target mailbox, sealed with **that account's** AAD, and its `email.received` event carries `via=catchall` so the owner can tell why it arrived.
- **`discard`** — the message is **accepted** (`250`) and dropped. That is the anti-enumeration answer: a `550` would tell the sender the address is fictional. The drop is logged.

Domain matching is case-insensitive and the rule is keyed by domain alone, so a second `PUT` for the same domain replaces the first.

## Suppressions

`GET /v1/suppressions` (page) · `POST /v1/suppressions` {addresses≤100, reason: manual|bounce|complaint} · `DELETE /v1/suppressions/{address}`. Hard bounces add automatically; removal is an explicit operator action.

## Health

`GET /healthz` — liveness, no auth. `GET /readyz` — store reachable **and** master key present.

## Sandbox

A key created with `sandbox: true` (or toggled via `PATCH /v1/account/keys/{id}`; environment-wide default `PIGEON_SANDBOX=1`) accepts, stores and renders every send **but never delivers and never emits delivery webhooks**. Introspect the exact MIME via `GET /v1/emails/{id}?raw=true` (sandbox messages only). Mailpit-style CI runs.

## For AI agents (MCP)

Same operations over the Model Context Protocol — same key, same scopes, same audit:

```json
{ "mcpServers": { "pigeon-mail": {
    "command": "pigeon", "args": ["mcp"],
    "env": { "PIGEON_URL": "https://mail.example.com", "PIGEON_API_KEY": "pk_..." } } } }
```

Tools: `send_email`, `list_messages`, `get_message`, `create_template`, `manage_webhooks`.

## Quickstart (curl)

```bash
curl -X POST https://mail.example.com/v1/emails \
  -H "Authorization: Bearer pk_..." \
  -H "Idempotency-Key: invoice-2041-paid-v1" \
  -H "Content-Type: application/json" \
  -d '{ "from": "Dana <dana@pigeonmail.dev>", "to": ["carol@example.org"],
        "subject": "Invoice #2041 paid", "text": "Thanks! Your renewal was processed." }'
```

Python: `requests.post(f"{url}/v1/emails", headers={"Authorization": f"Bearer {key}"}, json=payload)` — 202 → poll or webhook.
