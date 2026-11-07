# Pigeon Mail × remote agents (HTTPS + API key)

Use this path when the agent runs **somewhere other than the mail server**: a
laptop, CI, a hosted sandbox, another cluster. It needs no filesystem access — a
`pk_…` API key over HTTPS is enough.

```text
PIGEON_URL=https://mail.example.com
PIGEON_API_KEY=pk_…
```

## What v0.1 ships

| Path | Status |
|---|---|
| REST API over HTTPS (`/v1/…`) | **shipped** — full surface, see [`api-examples.md`](api-examples.md) |
| MCP over HTTP (`mcp-remote.json`) | registration ready; the HTTP mount point is on the roadmap — use the REST API meanwhile |
| MCP over stdio (`../generic/`, `../docker/`) | **shipped** |

Because the stdio server opens the database and master key locally, it cannot
serve a remote host. A remote agent therefore calls the same audited HTTP API the
stdio tools wrap: identical scopes, rate limits, sandbox keys and audit rows.
[`api-examples.md`](api-examples.md) has the curl equivalents of the 27 tools.

## 1. Create the key

On the server (or any machine that can reach the API):

```bash
curl -sS -X POST https://mail.example.com/v1/account/keys \
  -H 'Content-Type: application/json' \
  -d '{"name":"agent-laptop","scopes":["send","read"]}'
# → {"id":"key_…","key":"pk_…"}   ← shown once, only the hash is stored
```

Pick the narrowest scope your agent needs:

| Scope | Grants |
|---|---|
| `send` | send, cancel, mailbox writes (`PATCH`/`DELETE` messages), templates, drafts |
| `read` | inbox and discovery GETs — metadata and sealed blobs only |
| `full` | admin GETs (domains, webhooks, suppressions, keys), account administration, **decrypted bodies** |

Add `"sandbox": true` for CI keys: sends are accepted, stored and rendered but
never delivered.

## 2. Wire the agent

Set both variables in the agent's own environment (never in a committed file):

```bash
export PIGEON_URL="https://mail.example.com"
export PIGEON_API_KEY="pk_…"
```

If your client supports MCP over HTTP, copy [`mcp-remote.json`](mcp-remote.json)
into its server list. Otherwise give the agent the REST base URL and
`Authorization: Bearer $PIGEON_API_KEY`, and point it at
[`api-examples.md`](api-examples.md) as its tool reference.

## 3. Quick test

```bash
curl -sS "$PIGEON_URL/healthz"                       # liveness, no auth
curl -sS "$PIGEON_URL/readyz"                        # store + master key
curl -sS -H "Authorization: Bearer $PIGEON_API_KEY" \
  "$PIGEON_URL/v1/messages?limit=5"                  # needs scope read
```

`401` means the key is wrong or revoked, `403` means the scope is too narrow for
that operation (`x-scopes` in [`../../openapi.yaml`](../../openapi.yaml)).

## 4. Security notes

- **TLS is the transport's job.** Pigeon speaks plain HTTP on `:8000`; put
  Caddy/nginx/Traefik in front. Never expose `:8000` directly to the internet.
- **No 2FA on keys.** TOTP protects dashboard/webmail *sessions*, not API keys —
  treat a `pk_…` value as a bearer credential: rotate it with
  `PATCH /v1/account/keys/{id}` (`{"revoked": true}`) and audit `last_used_at`.
- **`full` keys can read plaintext.** Anything with `full` can decrypt stored
  bodies (`?sealed=false`). Give agents `send` + `read` and keep `full` for
  interactive administration.
- **Rate limits are per key** (10 req/s sustained, burst 50; daily quota). A
  shared key couples every agent to one budget — issue one key per agent so
  revocation and limits stay meaningful.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `401 unauthorized` | revoked/typo'd key, or the `Authorization: Bearer ` prefix is missing |
| `403 forbidden` | scope too narrow for that endpoint — check `x-scopes` in `openapi.yaml` |
| `429 rate-limited` | retry after `Retry-After`; batch with `POST /v1/emails/batch` (≤100 items) |
| `402 quota-exceeded` | daily send quota reached; `quota.reset_at` carries the reset time |
| `502`/connection reset | reverse proxy not forwarding `Host`/`X-Forwarded-*`, or `:8000` behind a firewall |
