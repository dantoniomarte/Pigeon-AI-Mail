# ADR 0001: Core server language is Rust

- Status: Accepted
- Date: 2026-11-06
- Deciders: project owner (delegated to agent), based on research

## Context

Pigeon Mail is a self-hosted email server: long-running network daemon holding SMTP (in/out), an HTTP API, and an MCP server. The owner's hard requirements: lowest latency, efficiency on small servers, safety above all (it handles credentials and private mail), and a single distributable artifact.

## Decision

Implement the core server in **Rust** (edition 2021+, stable ≥ 1.85) with async I/O on **Tokio**, HTTP via **axum**, SMTP as a hand-rolled ESMTP state machine over `tokio` (no heavy monolithic SMTP framework), crypto via RustCrypto (`chacha20poly1305`, `argon2`, `ed25519`/OpenPGP via `rpgp`), storage via `rusqlite` (SQLite bundled).

## Rationale (from research, 2026-11)

1. **No GC → predictable tail latency.** Go's GC pauses and Node's event-loop jitter are the classic tail-latency tax; Rust frees memory deterministically. Discord's move of a latency-sensitive service from Go to Rust documented stable p99 under load — the exact profile of an SMTP pipeline that must not stall under queue bursts.
2. **Memory safety without runtime.** A mail server is a hostile-input parser (SMTP conversations, MIME, headers). Rust's type system eliminates buffer overflows / use-after-free at compile time — the bug classes behind most mail-server CVEs.
3. **Single static binary.** Rust cross-compiles to a small static binary (musl) — ideal for the installer, Docker scratch images, and small VPS targets. No JVM/.NET/Node runtime to install.
4. **Precedent.** Stalwart Mail Server (Rust, ~6k★) proves the modern all-Rust mail server stack is production-viable; `rpgp` is a pure-Rust OpenPGP implementation (audited, used in production).

## Alternatives considered

- **Go** — excellent ecosystem (Postal, Mailpit are Go), simpler for teams; rejected because GC pauses and larger runtime footprint conflict with the latency/memory goals, and static analysis gives weaker guarantees for the parser-heavy core.
- **Node/TypeScript** — fastest to build, richest MCP ecosystem; rejected for the core (latency, memory, parser safety) but kept for the optional webmail frontend.
- **C/C++** — top raw performance; rejected: memory-safety risk is unacceptable for a credential/mail-handling public daemon.

## Consequences

- Slower iteration than Go/TS; mitigated by the small surface (single binary, few crates) and mandatory test-first workflow.
- Team must maintain safe-subset discipline: `unsafe` requires a justification comment and review escalation.
- Webmail stays TypeScript (React); MCP server ships inside the core binary (JSON-RPC over stdio) — no extra language runtime for agents.
