#!/usr/bin/env python3
"""Private-name gate: fail if any tracked file contains a blocked name.

The blocked names are committed only as salted SHA-256 digests
(scripts/private-names.sha256) — this repository never carries the names
themselves. Salted hashing prevents bulk confirmation: a digest only matches
if the guessed name is exact, so the file leaks no list.

Runs as a single process (no per-token forks) over every tracked file.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

SALT = "pigeon-private-2026-11"
DIGESTS = Path("scripts/private-names.sha256")
TOKEN_RE = r"[A-Za-z0-9.@_-]{4,}"


def main() -> int:
    if not DIGESTS.exists():
        print(f"✗ {DIGESTS} missing — the private-name gate cannot run", file=sys.stderr)
        return 2
    blocked: set[str] = set()
    for line in DIGESTS.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            blocked.add(line.split()[0])
    if not blocked:
        print("✗ no digests found — refusing to run a vacuous gate", file=sys.stderr)
        return 2

    try:
        files = subprocess.run(
            ["git", "ls-files", "-z"],
            capture_output=True,
            check=True,
        ).stdout.split(b"\0")
    except subprocess.CalledProcessError:
        print("✗ not inside a git repository — nothing to gate", file=sys.stderr)
        return 2

    token_re = re_compile()
    matched: list[str] = []
    for raw in files:
        if not raw:
            continue
        path = raw.decode("utf-8", "surrogateescape")
        if path.startswith("scripts/private-names"):
            continue
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for token in set(token_re.findall(text)):
            # Hash the token AND every dot-suffix: a committed apex digest
            # (foo.example.com) then covers www.foo.example.com and every
            # other subdomain, without enumerating them.
            suffixes = token.split(".")
            for position in range(len(suffixes)):
                candidate = ".".join(suffixes[position:])
                digest = hashlib.sha256((SALT + candidate).encode()).hexdigest()
                if digest in blocked:
                    matched.append(digest)

    if matched:
        for digest in sorted(set(matched)):
            print(f"✗ blocked private name present (digest {digest[:16]}…)", file=sys.stderr)
        return 1
    print("✓ private-name gate clean")
    return 0


def re_compile():
    import re

    return re.compile(TOKEN_RE)


if __name__ == "__main__":
    sys.exit(main())
