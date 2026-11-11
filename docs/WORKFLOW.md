# Workflow (template — condensed)

## The cycle

```
reproduce the bug → failing test → fix (green) → new branch → PR
→ independent review → merge (squash) → verified deploy
```

## Rules

1. **Branch from a fresh `origin/main`**, never from a stale local main or
   another branch: create an isolated worktree on a new branch cut from a
   freshly synced `origin/main`, for example
   `git worktree add ../<repo>-worktrees/<task> -b feat/<task> origin/main`.
2. **One commit per logical change**, with its test and its doc in the same
   commit.
3. **Tests first**, and verify the test with a mutation: if it stays green with
   the code broken, the test is worthless.
4. **Postgres first** (when applicable): new SQL without a test against
   Postgres is not tested.
5. **PR with a complete body**: symptom, cause, change, verification + an
   `## Independent review` section (a different agent from the author).
6. **Squash merge** with the PR-lane CI green; the full suite runs on `main`
   before deploy.
7. **Cleanup**: remove the worktree (`git worktree remove <path>`) after the
   merge.
8. **Push order — Gitea first, then GitHub**: after merging, `git push origin
   main` (Gitea, the primary) and only then `git push github main`. Gitea's
   `main` accepts pushes from whitelisted users (force-push stays blocked), so
   both remotes must end every merge at the same commit — never leave the
   mirror behind.
9. **Never verify destructive flows against production data**: synthesize
   isolated data with per-step error handling, or verify in tests only.

## Consult before merging (no exceptions)

Hard-to-reverse changes: billing, authentication/permissions, stored data,
secrets.
