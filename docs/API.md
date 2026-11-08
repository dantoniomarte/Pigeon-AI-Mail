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
| `send` | `POST /v1/emails`, `POST /v1/emails/batch`, cancel via `DELETE /v1/emails/{id}`, mailbox writes (folder/read `PATCH`, `DELETE`, empty-trash and purge-trash on `/v1/messages`), the account settings `PATCH` (trash retention), template create/update/delete, `POST /v1/templates/{id}/test-send`, draft save/update/delete/send. |
| `read` | Inbox and discovery GETs: emails (`/v1/emails*`, including sandbox raw MIME), messages, attachments, templates, drafts, account settings. Metadata and sealed blobs only. |
| `full` | The admin GETs — domains, webhooks, suppressions, keys — plus every write to those, plus **decrypted bodies** (`?sealed=false`). Account administration, including organizations, members, invitations, sender aliases and catch-all routing. |

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

`e2e` reports the payload protection **actually in force**, aligned with [docs/e2ee-model.md](e2ee-model.md) layer 3:

- `sealed` — the body (not the headers) is OpenPGP-sealed (RFC 4880) to the published key of **every**
  recipient, plus the sending account's own key so the sent copy stays readable. Keys are discovered
  before queueing: another Pigeon instance answers for its own accounts, and any domain publishing WKD keys
  is used the same way.
- `tls_only` — STARTTLS transport, no end-to-end seal. Either a recipient published no discoverable key,
  or every recipient is a local account of this instance (the message never leaves, so layer 1 at-rest
  sealing is what applies). A discovery failure **never blocks delivery**.
- `plaintext_override` — an operator explicitly exempted a recipient domain with
  `PIGEON_E2E_PLAINTEXT_DOMAINS` (comma-separated, empty by default). Always logged; never automatic.

Sealing is all-or-nothing per message: one unsealable recipient means the whole message goes `tls_only`
(there is no per-recipient copy in v1). The `e2e` value is stored on the email row and carried by the
lifecycle views and webhooks, so it cannot drift from what was actually sent.

Subject lines and headers stay in the clear in every case — SMTP routing needs them, which is the same
caveat Proton documents.

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

### `GET /v1/messages?folder=inbox|sent|spam|trash&limit≤500&offset&delivered_for` — metadata page (never bodies). `folder` defaults to `inbox`; an unknown value is `422 validation`. The folder follows the message's direction: mail this account sends is stored in `sent` when it is accepted by `POST /v1/emails`, and received mail — alias and catch-all copies included — is stored in `inbox`, which is why those keep a `delivered_for` marker instead of a folder of their own. Items carry `folder`, `read` and — for mail that arrived for a shared address — `delivered_for`, and the page carries `counts: {inbox, sent, spam, trash}` for the sidebar badges plus `delivered_for_counts: [{address, count}]` — one request renders the whole mailbox, shared addresses included. When `delivered_for` is present, the listing is pinned to the inbox and the `folder` parameter is ignored.

```json
{ "items": [ { "id": "msg_00000001", "from_addr": "carol@example.org", "subject": "...",
                "created_at": "...", "folder": "inbox", "read": true } ],
  "page": { "total": 1, "has_more": false, "next_offset": null },
  "counts": { "inbox": 1, "sent": 0, "spam": 0, "trash": 0 } }
```

### `PATCH /v1/messages/{id}` — `{folder?: inbox|sent|spam|trash, read?: bool}`, at least one member. Moves the message and/or flips read state and returns the updated metadata (`200`). Unknown id → `404`, unknown folder → `422 validation`.

### `DELETE /v1/messages/{id}` — permanent delete of the message and its lifecycle metadata (`204`). Moving to `trash` is a `PATCH`, not a delete.

### `POST /v1/messages/empty-trash` — purges the caller's trash, `200 {deleted: N}` (idempotent: an already-empty trash reports `0`).

### `POST /v1/messages/purge-trash` — the **retention** purge, on demand, `200 {deleted, trash_remaining}`.

Trashed mail is deleted automatically once it has been in the trash longer than the account's `trash_retention_days` (default **30**, `0` = keep forever; see [account settings](#account-keys-sessions--2fa)). The server runs that sweep every **6 hours**; this endpoint runs it immediately for the caller, so a user who just changed the setting — or an agent that moved mail to the trash — does not have to wait for the interval. It deletes only *expired* trash: fresher messages stay, other folders are untouched, and another account is never affected. A `0` retention deletes nothing.

Mailbox mutations (`PATCH`/`DELETE`/`empty-trash`/`purge-trash`) require scope `send`, matching cancel-email; the listing requires `read`.

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

**Account settings** (the mailbox policy that belongs to the account, not to a key). Both routes accept an API key *and* the webmail session cookie:

| Endpoint | Scope | Purpose |
|---|---|---|
| `GET /v1/account/settings` | `read` | `200 {trash_retention_days}` (default **30**). |
| `PATCH /v1/account/settings` {trash_retention_days} | `send` | `200` with the stored policy. Range `0..=365`: `0` = **keep trash forever**, `1`–`365` = days until the purge deletes it. Outside the range → `422 validation` (never a silent clamp: a clamped retention would delete mail nobody asked to delete). |

**Trash retention behavior.** The countdown starts when a message **enters** the trash (`PATCH /v1/messages/{id}` with `folder: trash`) and stops when it leaves it again, so restoring a message cancels its deletion. A message trashed before this feature existed has no start time and is never purged until it is moved to the trash again. Changing the setting applies to the whole trash on the next sweep: lowering `30` to `7` deletes what is already older than seven days.

**Dashboard/webmail sessions & 2FA** (session cookie realm):

| Endpoint | Purpose |
|---|---|
| `POST /v1/auth/login` {email, code?} | Session login. **Every login requires `code`**: a TOTP code (6/8 digits), a recovery code, or the invitation/bootstrap token. (`password` is accepted in the body but unused — v0.1 has no password realm.) See the challenge below. |
| `POST /v1/auth/logout` | Revokes the session the request authenticated with. `204`. |
| `GET /v1/auth/check` | `204` when the session cookie is valid — the browser cannot read the HttpOnly cookie, so the webmail probes the server instead. |
| `POST /v1/account/2fa/enroll` | Session-only re-auth (v0.1 has no password realm — the session *is* the re-auth); no body. → `{secret_base32, otpauth_uri}`. |
| `POST /v1/account/2fa/activate` {code} | → 10 one-time recovery codes, shown once. |
| `POST /v1/account/2fa/verify` {code} | Step-up check for the current session → `200` valid; wrong code → `422`, `429` when limited. |
| `POST /v1/account/2fa/disable` {code} | Disable — **POST, never DELETE** (DELETE bodies are the first thing proxies and browsers drop). Requires a current valid code: TOTP **or** a recovery code. |

**The login challenge.** `POST /v1/auth/login` takes `{email, code?}` (`password` accepted but ignored) and has exactly two success shapes:

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

## Sender aliases

A **sender alias** is a second address on a domain this deployment already serves (`sales@example.com`). It owns **no mailbox**: mail to it is copied into the inbox of **every** account assigned to it, and every assignee may **send as** it.

| Endpoint | Purpose |
|---|---|
| `GET /v1/aliases` | Aliases visible to the caller: an owner/admin sees every alias with its assignees, a member sees only their own. `?mine=1` always narrows to the caller's own list (what the compose From menu offers). Scope `send`. |
| `POST /v1/aliases` {address} | Claim a free address → `201`. Owner/admin only. |
| `DELETE /v1/aliases/{id}` | Delete the alias and every assignment to it. Owner/admin only. |
| `POST /v1/aliases/{id}/assign` {account_id} | Let one account send as the alias and receive a copy of its mail. Owner/admin only. |
| `POST /v1/aliases/{id}/unassign` {account_id} | Stop that account's sending and delivery. Owner/admin only. |

Rules:

- The address must parse, its domain must be **served** (an account on it, or a DKIM identity for it), and it must collide with neither an account address nor another alias: an alias that shadowed a mailbox would turn one delivery into copies for strangers. A collision is `409`, a bad/foreign address is `422`.
- Many-to-many: one account may hold several aliases, and one alias may be held by several accounts. Assigning the same pair twice is `409`.
- The collision is enforced in **both** directions: an existing account cannot become an alias (`422`), and an account can never be created on an alias address — `POST /v1/orgs/{id}/members` (and the installer) answer `409 conflict` instead, so a mailbox can never divert a shared address's mail.
- Mail to an alias is stored **in the inbox** of each assignee with `delivered_for = <alias>` (the message stays a normal inbox row; `?delivered_for=` filters it, and `GET /v1/messages` returns `delivered_for_counts` so a client can render one pseudo-folder per shared address). Its `email.received` event carries `via=alias delivered_for=<alias>`.
- Revoking an assignment stops future delivery and sending; mail already delivered keeps its marker and stays put.
- Sending: `POST /v1/emails`'s `from` must be the caller's own address **or** an alias assigned to it. Anything else is `403` problem type `from-not-allowed` — a distinct type because "issue another key" and "ask for that alias" are different fixes. Comparison is on the normalized address, so case cannot dodge the check.
- Every mutation is audited (`alias.create`, `alias.delete`, `alias.assign`, `alias.unassign`).

## Catch-all routing

What the **inbound** SMTP server does with mail addressed to a local part no account holds. A rule is per **domain**, it may have **several assignees**, each with its own pause switch, and with no rule the server keeps answering `550` (never an open relay).

Inbound resolution order: **exact account** → **sender alias** (copy to every holder) → **catch-all route** (copy to every non-paused assignee) → **discard** → `550`.

| Endpoint | Purpose |
|---|---|
| `GET /v1/catchall` | Rules with their assignees: an owner/admin sees all, a member sees the domains where they hold the catch-all (own row only). `?mine=1` narrows any role to the caller's own assignments. Scope `full`. |
| `PUT /v1/catchall/{domain}` {action} | The domain-level decision: `route` or `discard`. Re-putting replaces the action and **keeps** the assignees. |
| `DELETE /v1/catchall/{domain}` | Remove the rule and its assignments; unknown recipients go back to `550`. |
| `POST /v1/catchall/{domain}/assign` {account_id} | Give one mailbox of that domain a copy. Owner/admin only; assigning twice is `409`. |
| `DELETE /v1/catchall/{domain}/assign/{account_id}` | Stop one copy. Owner/admin only. |
| `PATCH /v1/catchall/{domain}/assignments/{account_id}` {paused} | The admin force: pause **or resume** somebody else's copy. Owner/admin only, audited as `catchall.force`. |
| `POST /v1/catchall/me/pause` {domain?} | Any member pauses their **own** copy (session or API key). `409` when they hold none; `domain` is required when they hold several. |
| `POST /v1/catchall/me/resume` {domain?} | Any member resumes their own copy. |

- **`route`** — the message is copied into **every non-paused assignee**, each sealed with **that account's** AAD, each marked `delivered_for = <the address the sender wrote>`, and each `email.received` event carries `via=catchall delivered_for=<address>`. A route rule whose assignees have all paused accepts the message and stores nothing (like `discard`): a configured catch-all must not turn a member's pause into a delivery failure for the sender.
- **`discard`** — the message is **accepted** (`250`) and dropped. That is the anti-enumeration answer: a `550` would tell the sender the address is fictional. The drop is logged.
- A `route` rule with zero assignees also accepts and drops unknown-address mail (the same anti-enumeration behavior as an all-paused rule): the domain is configured to take catch-all mail, so the sender must not learn that nobody is listening yet.
- The `paused` flag is per `(domain, account)`: one member's holiday switch never silences the shared inbox, and the admin force exists so somebody who paused and never came back cannot silence it either.

Domain matching is case-insensitive and the rule is keyed by domain alone, so a second `PUT` for the same domain replaces the first without forgetting who was receiving the mail.

## Suppressions

`GET /v1/suppressions` (page) · `POST /v1/suppressions` {addresses≤100, reason: manual|bounce|complaint} · `DELETE /v1/suppressions/{address}`. Hard bounces add automatically; removal is an explicit operator action.

## WKD — publishing your users' keys

Two unauthenticated endpoints serve the public key of an address **of this instance** (see
[docs/e2ee-model.md](e2ee-model.md) layer 3). They answer for accounts only: a sender alias has several
owners and publishes nothing.

### `GET /.well-known/pigeon-pgp?email=<address>`

The Pigeon-to-Pigeon key directory. `200` with `Content-Type: application/pgp-keys` and the armored
certificate; `404 not-found` for an address this instance does not serve; `422 validation` for a missing or
malformed `email`.

The key is created **on first need** (first publication request or first sealed send), so an existing
account may answer `404` once and `200` afterwards.

Both WKD routes are **rate limited per source address** (unauthenticated, so there is no key to throttle):
5 requests/second sustained with a bounded burst. Above it the answer is `429 rate-limited` with
`Retry-After`, the same problem type and headers the authenticated API uses.

### `GET /.well-known/openpgpkey/{domain}/hu/{hash}`

Advanced WKD (draft-koch-openpgp-webkey-service): the same certificate in **binary**, keyed by
`z-base-32(SHA-1(lowercased local part))`, for a domain this instance serves. A wrong hash and a foreign
domain both answer `404`, so the endpoint cannot be used to enumerate addresses of other domains.

Outbound discovery tries, in order: `/.well-known/pigeon-pgp` on the recipient's domain, then the advanced
path on `openpgpkey.<domain>`, then the advanced path on `<domain>` itself. The first key seen for an
address is **pinned** (trust on first use); a later different key is reported and the pinned key keeps being
used — never silently rotated. Each lookup is bounded by a 10-second wall-clock deadline, and a lookup that
fails simply downgrades the message to `tls_only`: discovery never blocks delivery.

If a peer reports that they rotated their key while this server keeps sealing to the old one, the fix is the
operator command `pigeon unpin-peer-key <address>` (audited as `pgp.unpin`), which clears the pin so the next
lookup re-runs trust on first use. It is a **trust reset**: verify the new fingerprint out of band first.
See [docs/e2ee-model.md](e2ee-model.md) "Key rotation and the pin" for the symptom, the confirmation steps and
the tradeoff.

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

Tools (33 in total): `send_email`, `list_messages`, `get_message`, `create_template`, `manage_webhooks`; the organization group (`org_create`, `org_members`, `org_invite`, `org_create_member`); catch-all (`catchall_set`, `catchall_list`, `catchall_delete`, `catchall_pause`, `catchall_resume`); sender aliases (`alias_list`, `alias_create`, `alias_assign`, `alias_delete`); drafts, folders, domains, suppressions and API keys; plus `account_settings` and `set_trash_retention` so an agent can read and change the trash retention (`days: 0` keeps trashed mail forever) without going through the HTTP API.

The MCP actor is the deployment's bootstrap account, so `send_email`'s `from` follows the same rule as the HTTP send (`from-not-allowed` for anything that is neither that account nor one of its aliases), and `catchall_pause`/`catchall_resume` only ever touch the actor's own row.

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

> **`from` is checked.** The address must be the calling account's own address or a
> sender alias assigned to it (`GET /v1/aliases?mine=1` lists yours); anything else
> is `403` problem type `from-not-allowed`. To send on behalf of a group address,
> an owner/admin creates the alias (`POST /v1/aliases`) and assigns the sender to it
> — that is the supported "send as" path, and it also makes inbound mail to that
> address land in the assignees' inboxes.
