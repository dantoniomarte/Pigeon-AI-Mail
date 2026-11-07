# Pigeon Mail — REST examples for agents (no MCP)

Everything the MCP tools do, over plain HTTPS with a `pk_…` key. Use this when a
harness cannot speak MCP, or when the agent runs on another machine.

```bash
export PIGEON_URL="https://mail.example.com"
export PIGEON_API_KEY="pk_…"          # never commit it
export H_AUTH="Authorization: Bearer $PIGEON_API_KEY"
export H_JSON="Content-Type: application/json"
```

Errors are RFC 7807 `application/problem+json`
(`{"type","title","status","detail"}`). Full contract:
[`../../openapi.yaml`](../../openapi.yaml) · [`../../docs/API.md`](../../docs/API.md).

## Tool → endpoint map (all 25)

| MCP tool | HTTP |
|---|---|
| `send_email` | `POST /v1/emails` |
| `list_messages` | `GET /v1/messages?folder=inbox` |
| `get_message` | `GET /v1/messages/{id}` (`?sealed=false` needs `full`) |
| `create_template` | `POST /v1/templates` |
| `manage_webhooks` | `GET`/`POST /v1/webhooks`, `DELETE /v1/webhooks/{id}` |
| `org_create` | `POST /v1/orgs` |
| `org_members` | `GET /v1/orgs/{id}/members` |
| `org_invite` | `POST /v1/orgs/{id}/invitations` |
| `org_create_member` | `POST /v1/orgs/{id}/members` |
| `catchall_set` | `PUT /v1/catchall/{domain}` |
| `catchall_list` | `GET /v1/catchall` |
| `catchall_delete` | `DELETE /v1/catchall/{domain}` |
| `draft_save` | `POST /v1/drafts` (create) / `PATCH /v1/drafts/{id}` (update) |
| `draft_list` | `GET /v1/drafts` |
| `draft_send` | `POST /v1/drafts/{id}/send` |
| `move_message` | `PATCH /v1/messages/{id}` `{"folder":"spam"}` |
| `mark_read` | `PATCH /v1/messages/{id}` `{"read":true}` |
| `domain_add` | `POST /v1/domains` |
| `domain_dns` | `GET /v1/domains/{id}/dns` |
| `suppression_list` | `GET /v1/suppressions` |
| `suppression_add` | `POST /v1/suppressions` |
| `suppression_remove` | `DELETE /v1/suppressions/{address}` |
| `api_key_create` | `POST /v1/account/keys` |
| `api_key_list` | `GET /v1/account/keys` |
| `api_key_revoke` | `PATCH /v1/account/keys/{id}` `{"revoked":true}` |

Scope per row follows [`../../docs/API.md`](../../docs/API.md): sending and
mailbox writes need `send`, inbox/discovery GETs need `read`, admin surfaces and
decrypted bodies need `full`.

## Messaging

```bash
# send (202 accepted ≠ delivered); idempotency makes a retry safe
curl -sS -X POST "$PIGEON_URL/v1/emails" -H "$H_AUTH" -H "$H_JSON" \
  -H "Idempotency-Key: invoice-2041-paid-v1" \
  -d '{"from":"Dana <dana@example.com>","to":["carol@example.org"],
       "subject":"Invoice #2041 paid","text":"Thanks! Your renewal was processed."}'
# → {"id":"eml_9f2a44c1","status":"queued","e2e":"sealed"}

# list the inbox (metadata only, never bodies)
curl -sS -H "$H_AUTH" "$PIGEON_URL/v1/messages?folder=inbox&limit=20"

# read one message (sealed view; add ?sealed=false with a full key for plaintext)
curl -sS -H "$H_AUTH" "$PIGEON_URL/v1/messages/msg_00000001"

# lifecycle of a send
curl -sS -H "$H_AUTH" "$PIGEON_URL/v1/emails/eml_9f2a44c1"

# batch (≤100 items; one invalid item never blocks the rest)
curl -sS -X POST "$PIGEON_URL/v1/emails/batch" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"items":[{"from":"a@example.com","to":["b@example.net"],
        "subject":"Hi","text":"Hello"}]}'
```

## Drafts (compose across turns)

```bash
curl -sS -X POST "$PIGEON_URL/v1/drafts" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"to":["customer@example.net"],"subject":"Welcome","text":"Thanks for signing up."}'
# → {"id":"drf_…"}

curl -sS -X PATCH "$PIGEON_URL/v1/drafts/drf_…" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"text":"Thanks for signing up — here is your first step."}'

curl -sS -X POST "$PIGEON_URL/v1/drafts/drf_…/send" -H "$H_AUTH"
```

## Folders

```bash
curl -sS -X PATCH "$PIGEON_URL/v1/messages/msg_00000001" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"folder":"spam"}'
curl -sS -X PATCH "$PIGEON_URL/v1/messages/msg_00000001" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"read":true}'
```

## Domains, catch-all, suppressions

```bash
# add a domain, then read the exact records to publish
curl -sS -X POST "$PIGEON_URL/v1/domains" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"name":"example.com"}'
curl -sS -H "$H_AUTH" "$PIGEON_URL/v1/domains/dom_…/dns"

# route unknown local parts into a mailbox (or discard them)
curl -sS -X PUT "$PIGEON_URL/v1/catchall/example.com" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"action":"route","target_account_id":2}'

# suppressions
curl -sS -H "$H_AUTH" "$PIGEON_URL/v1/suppressions"
curl -sS -X POST "$PIGEON_URL/v1/suppressions" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"addresses":["bounce@example.net"],"reason":"manual"}'
curl -sS -X DELETE "$PIGEON_URL/v1/suppressions/bounce@example.net" -H "$H_AUTH"
```

## Organizations and API keys

```bash
curl -sS -X POST "$PIGEON_URL/v1/orgs" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"name":"Acme Mail"}'
curl -sS -H "$H_AUTH" "$PIGEON_URL/v1/orgs/1/members"
curl -sS -X POST "$PIGEON_URL/v1/orgs/1/invitations" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"email":"new@example.com","role":"member"}'

# keys (scope full); the pk_ value is returned exactly once
curl -sS -X POST "$PIGEON_URL/v1/account/keys" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"name":"agent-ci","scopes":["send","read"],"sandbox":true}'
curl -sS -H "$H_AUTH" "$PIGEON_URL/v1/account/keys"
curl -sS -X PATCH "$PIGEON_URL/v1/account/keys/key_…" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"revoked":true}'
```

## Webhooks (receive events instead of polling)

```bash
curl -sS -X POST "$PIGEON_URL/v1/webhooks" -H "$H_AUTH" -H "$H_JSON" \
  -d '{"url":"https://agent.example.com/pigeon","events":["email.received","email.bounced"]}'
```

Verify deliveries with `X-Pigeon-Signature` / `X-Pigeon-Timestamp`
(HMAC-SHA256 over `"<timestamp>.<raw_body>"`, 300 s window, constant-time
compare). Reference verifiers in Node and Python: [`../../docs/API.md`](../../docs/API.md#webhooks).

## Health and readiness

```bash
curl -sS "$PIGEON_URL/healthz"   # liveness, no auth
curl -sS "$PIGEON_URL/readyz"    # store reachable + master key present
```

## Python (same contract)

```python
import os, requests

url = os.environ["PIGEON_URL"].rstrip("/")
h = {"Authorization": f"Bearer {os.environ['PIGEON_API_KEY']}"}

r = requests.post(f"{url}/v1/emails", headers=h, json={
    "from": "agent@example.com", "to": ["carol@example.org"],
    "subject": "Report ready", "text": "The nightly report is attached.",
}, timeout=30)
r.raise_for_status()            # 202 → queued
print(r.json()["id"])
```
