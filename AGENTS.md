# Agent instructions

Guidance for AI agents working on this repository.

## What this project is

Pigeon Mail: a self-hosted encrypted email server in Rust — HTTP API (axum),
ESMTP inbound, queue-driven outbound delivery, an MCP agent server and a
React webmail, sharing one SQLite database. AGPL-3.0. Public repo:
`dantoniomarte/Pigeon-AI-Mail`.

## Map

| Path | What lives there |
|---|---|
| `crates/pigeon-core` | Strict types (addresses, folders, scopes) + 12-factor config |
| `crates/pigeon-crypto` | XChaCha20 content sealing, TOTP, Argon2id API keys |
| `crates/pigeon-dkim` | Ed25519 DKIM signing |
| `crates/store` | SQLite WAL storage, `Storage` trait seam, `messages` schema |
| `crates/pigeon-api` | axum HTTP API + `api_*` schema (drafts, aliases, webhooks, orgs, sessions) |
| `crates/pigeon-smtp` | ESMTP inbound, outbound client, queue worker |
| `crates/pigeon-mcp` | JSON-RPC stdio agent server (35 tools) |
| `crates/pigeon` | Binary: `serve` / `keygen` / `mcp` / `unpin-peer-key` |
| `web/` | React webmail (Vite + vitest), served by the binary |
| `docs/` | API, architecture, deployment, security, e2ee model, roadmap |
| `openapi.yaml` | The API contract (CI-linted) |

## Rules

1. **Work in an isolated worktree on a new branch** cut from a freshly synced
   `main` (`git worktree add ../<repo>-worktrees/<task> -b feat/<task> main`);
   never work or commit in another session's worktree.
2. **One task = one branch = one PR**, squash-merged; the branch is deleted
   after merge.
3. **Tests first**, and verify a new test with a mutation: if it stays green
   with the code broken, the test is worthless. Run the FULL workspace suite
   before declaring green — filtered runs mask cross-target breakage.
4. **One SQLite dialect** (this project has no Postgres); new SQL is tested
   against SQLite from day one.
5. **Never commit secrets or private data**; the private-name gate
   (`scripts/check_private_names.py`, run by `scripts/verify-clean.sh`) fails
   any tracked file containing a blocked name.
6. **Never verify destructive flows against production data**: synthesize
   isolated data with per-step error handling, or verify in tests only.
7. **PRs carry a complete body** (symptom, cause, change, verification) and
   an independent review before merge.
8. **Generated artifacts are in English** (code, comments, commit messages,
   docs, tests).
9. **Public claims must be verifiable**: every capability statement in
   README/docs must be true of the current tree; planned features live in
   docs/ROADMAP.md, not in feature tables.

## Commands

```sh
cargo test --workspace          # full Rust suite
cargo fmt && cargo clippy --all-targets
cd web && npm ci && npx vitest run && npm run build
scripts/verify-clean.sh          # secrets + private-name gate (pre-merge)
```
