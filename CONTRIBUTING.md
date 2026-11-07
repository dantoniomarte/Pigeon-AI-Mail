# Contributing to Pigeon Mail

Thanks for helping build self-hosted encrypted mail infrastructure. A few rules keep the project healthy.

## Ground rules

1. **One task = one branch = one PR.** Cut branches from a fresh `main`. Never push to `main`.
2. **Tests first.** Every bug fix starts with a failing test that reproduces it; every feature ships with tests covering its observable behavior. CI runs the full suite.
3. **Independent review.** Every PR includes an `## Independent review` section — findings from someone (or some agent) other than the author. No self-approved merges.
4. **Small PRs win.** Target ≤ ~400 changed lines per PR; split bigger work into stacked PRs.
5. **Hygiene is enforced.** `make verify` (repo hygiene: no secrets, no placeholders, no private references) must pass. Install the pre-push hook: `make install-hooks`.

## Dev environment

- Rust stable ≥ 1.85 (`rustup`), `cargo fmt` + `cargo clippy`.
- Node 20+ only if you touch the optional webmail (`web/`).
- No real mail servers needed: the SMTP suites run against an in-process server on an ephemeral port.

## Commit style

Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`…). Squash merge — your PR body is the changelog entry, so write it for humans.

## Security

Never commit credentials, keys, or live email content. Vulnerabilities go through [SECURITY.md](SECURITY.md), not issues.

## Code of Conduct

By participating you agree to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
