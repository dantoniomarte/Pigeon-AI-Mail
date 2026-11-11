#!/usr/bin/env bash
# verify-clean.sh — public-repo hygiene gate.
#
# Scope: this gate scans TRACKED files only (git grep), so gitignored local
# directories (work notes, designs, scratch) never produce false positives.
# It does not inspect git history: a private string committed once and removed
# later still lives in history — green means "what is tracked now is clean",
# which is exactly what CI checkout and pre-push publish.
#
# Failure discipline: a git grep FATAL error (exit >= 2) is never treated as
# "clean" — the gate exits 2 instead. Only exit 1 (no match) passes a check.
#
# Private-infrastructure names are deliberately NOT hard-coded here: this file
# ships in a public repository. They are loaded at runtime from
# scripts/hygiene.private.patterns (gitignored, local only, one extended
# regex per line). CI has no such file and skips only that check. The
# ':!…' pathspec excluding that file is defense-in-depth (it is normally not
# enumerated by git grep at all, but stays correct if someone force-adds it).
set -euo pipefail
TOP="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$TOP" ] || [ ! -d "$TOP" ]; then
  echo "✗ verify-clean must run inside a git repository" >&2
  exit 2
fi
cd "$TOP"

fail=0
patterns_file='scripts/hygiene.private.patterns'

# run_grep <args...>: 0 = matched, 1 = no match, >=2 = fatal (gate failure).
run_grep() {
  local rc=0
  git grep "$@" || rc=$?
  case "$rc" in
    0|1) return "$rc" ;;
    *) echo "✗ git grep failed (exit $rc) — gate cannot verify; failing closed" >&2
       exit 2 ;;
  esac
}

# 1) Private project names / infrastructure — enforced EVERYWHERE. The
#    blocked names are committed only as salted digests, so this repository
#    never carries the names themselves; the checker is a single fast
#    python3 pass over the tracked files. A local (gitignored) patterns
#    file may extend the list with live regexes.
if ! python3 scripts/check_private_names.py; then
  fail=1
fi
# 1b) Optional live regexes from the local (gitignored) patterns file.
if [ -f "$patterns_file" ]; then
  pattern_index=0
  while IFS= read -r pattern || [ -n "$pattern" ]; do
    case "$pattern" in ''|'#'*) continue ;; esac
    pattern_index=$((pattern_index + 1))
    if run_grep -iIn -E "$pattern" -- . ':!scripts/hygiene.private.patterns'; then
      echo "✗ forbidden private reference (pattern #$pattern_index from $patterns_file)" >&2
      fail=1
    fi
  done < "$patterns_file"
fi

# 2) Template placeholders that must be gone before merge.
#    '*Makefile' basename-matches nested Makefiles too (crates/*/Makefile).
if run_grep -In 'PROYECTO:' -- '*.md' '*.yml' '*Makefile'; then
  echo "✗ template placeholders (PROYECTO:) still present" >&2; fail=1
fi

# 3) Obvious live secrets.
SECRET_PATTERN='sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY'
if run_grep -In -E "$SECRET_PATTERN" -- .; then
  echo "✗ possible secret material found" >&2; fail=1
fi

# 4) Required community files exist.
for f in README.md LICENSE SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md CHANGELOG.md; do
  [ -f "$f" ] || { echo "✗ missing required file: $f" >&2; fail=1; }
done

if [ "$fail" -eq 0 ]; then
  echo "✓ repo hygiene OK"
fi
exit "$fail"
