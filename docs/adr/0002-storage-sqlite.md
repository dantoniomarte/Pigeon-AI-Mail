# ADR 0002: Storage — encrypted SQLite first, abstraction for scale

- Status: Accepted
- Date: 2026-11-06

## Context

Pigeon must run on a small VPS with zero external dependencies (no Postgres, no Redis) yet be **Kubernetes-ready** for multi-node load distribution (owner requirement: "compatible and ready", not fully implemented).

## Decision

1. **SQLite** (via `rusqlite`, bundled) is the first storage engine. One file, WAL mode, `synchronous=FULL` for queue durability.
2. All persistence goes through a `Storage` trait (`store` crate): `messages`, `queue`, `api_keys`, `accounts`, `webhooks`, `audit`. A future `store-pg`/`store-s3` backend implements the same trait without touching business code.
3. **At-rest encryption is applied inside the storage layer, always**: message bodies and attachments are encrypted with XChaCha20-Poly1305 (per-message content key wrapped by the account key) before SQL `INSERT`. The database file alone is not enough to read mail (see ADR 0003).
4. Queue semantics: at-least-once delivery with idempotency keys on send; `claimed_at`/`claim_token` columns make the queue safe for **multiple worker processes**, which is the seam for horizontal scale (API nodes stateless, one or more workers share the store — file-lock-safe queue claims on SQLite; native distributed mode comes with a shared-DB backend).

## Consequences

- Vertical scale is enough for the target (10⁵–10⁶ msgs/day on 2 vCPU).
- True multi-node write scale requires the shared-DB backend — the trait boundary is the migration path, documented in ARCHITECTURE.md.
- SQLite file must live on a real disk (not tmpfs) in k8s; manifests mount a PVC and docs say when to switch backends.
