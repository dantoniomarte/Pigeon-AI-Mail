# Workflow

## The cycle

```
reproduce the bug → failing test → fix (green) → new branch → PR
→ independent review → merge (squash) → verified deploy
```

## Rules

1. **Branch from a fresh `main`**, never from a stale local main or another
   branch: create an isolated worktree on a new branch cut from a freshly
   synced `main`, for example
   `git worktree add ../<repo>-worktrees/<task> -b feat/<task> main`.
2. **One task = one branch = one PR**, with its test and its doc in the same
   commit; squash-merged and deleted after merge.
3. **Tests first**, and verify the test with a mutation: if it stays green with
   the code broken, the test is worthless.
4. **One SQL dialect**: this project is SQLite-only; new queries are tested
   against SQLite from day one.
5. **PR with a complete body**: symptom, cause, change, verification + an
   `## Independent review` section written by a reviewer other than the
   author (for agent-authored changes, a different agent).
6. **Never verify destructive flows against production data**: synthesize
   isolated data with per-step error handling, or verify in tests only.
7. **Public claims are verifiable**: a capability statement in README or
   docs must be true of the current tree; planned work belongs in
   docs/ROADMAP.md.
8. **Cleanup**: remove the worktree (`git worktree remove <path>`) after the
   merge, and delete merged branches locally and on the remotes.

## Consult before merging (no exceptions)

- `scripts/verify-clean.sh` passes (secrets, private names, placeholders).
- The full workspace test suite is green (Rust + webmail), not a filtered
  subset.
- `cargo fmt --check` and `cargo clippy --all-targets` are clean.
- `openapi.yaml` stays valid: CI lints the spec on every PR.
