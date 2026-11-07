# Agent instructions (template — applies to every project)

## Session isolation — MANDATORY

Before writing the first file of a new task:

1. If you are already in a worktree created for this task, continue there.
2. Otherwise, create an isolated worktree on a new branch, always from a freshly
   synced `origin/<default-branch>` — for example
   `git worktree add ../<repo>-worktrees/<task> -b feat/<task> origin/main` — and
   work exclusively there.
3. Never work, commit, or switch branches in the main checkout or in worktrees
   this session did not create. If `git status` shows files you did not create,
   report them.
4. Each session opens, merges, and deploys only the PRs it opened itself.
5. After merging a PR, remove its worktree (`git worktree remove <path>`) to
   clean up.

## Independent review before merge

Every PR carries a `## Independent review` section in its body, written by an
agent other than the one that authored the change. Without that artifact, the
PR is not ready to merge.

## Workflow conventions

- 1 task = 1 branch (cut from a fresh `origin/main`) = 1 PR.
- Merge is squash (1 commit per PR); the branch is deleted afterward.
- Tests first, with a mutation check to prove the test can fail.
- If the project uses Postgres: every new SQL query is tested against Postgres
  from day one.
