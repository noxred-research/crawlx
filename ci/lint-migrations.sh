#!/usr/bin/env bash
# Keeps the three engine migration directories in lock step and published migrations immutable.
#
# PostgreSQL migrations live in crates/crawlx-storage/migrations/, SQLite and MariaDB in its
# sqlite/ and mariadb/ subdirectories. Below version 0047 the SQLite and MariaDB directories
# hold consolidated baselines instead of one file per PostgreSQL migration.
#
# Rules:
#   1. Every version >= 0047 exists in all three directories under the same file name.
#   2. No version number appears twice within one directory.
#   3. A migration that exists on the base ref is never modified, renamed or deleted.
#   4. A migration added after the base ref has a version above every published version.
#
# The base ref defaults to origin/main. Set MIGRATIONS_BASE_REF to another ref, or to `none`
# to skip rules 3 and 4 explicitly (for example in a checkout without the base branch).
set -euo pipefail
cd "$(dirname "$0")/.."
base="${MIGRATIONS_BASE_REF:-origin/main}"
if [ "$base" != "none" ] && ! git rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
  echo "lint-migrations: base ref '$base' is not available; fetch it or set MIGRATIONS_BASE_REF=none" >&2
  exit 2
fi
MIGRATIONS_BASE="$base" python3 - <<'PY'
import os, re, subprocess, sys
from pathlib import Path

root = Path("crates/crawlx-storage/migrations")
dirs = {"postgres": root, "sqlite": root / "sqlite", "mariadb": root / "mariadb"}
first_lock_step = 47
name_re = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")
bad = 0

def report(msg):
    global bad
    print(f"lint-migrations: {msg}")
    bad += 1

versions = {}
for engine, d in dirs.items():
    seen = {}
    for p in sorted(d.glob("*.sql")):
        m = name_re.match(p.name)
        if not m:
            report(f"{p}: file name must be NNNN_lowercase_words.sql")
            continue
        v = int(m.group(1))
        if v in seen:
            report(f"{engine}: version {v:04} appears twice ({seen[v]}, {p.name})")
        seen[v] = p.name
    versions[engine] = {v: n for v, n in seen.items() if v >= first_lock_step}

all_versions = sorted(set().union(*(set(v) for v in versions.values())))
for v in all_versions:
    names = {e: versions[e].get(v) for e in dirs}
    missing = [e for e, n in names.items() if n is None]
    if missing:
        present = next(n for n in names.values() if n)
        report(f"{present}: missing in {', '.join(missing)} (every change ships all three engines)")
    elif len(set(names.values())) != 1:
        report(f"version {v:04} has different names per engine: {names}")

base = os.environ["MIGRATIONS_BASE"]
if base != "none":
    def git(*args):
        return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout
    published = [p for p in git("ls-tree", "-r", "--name-only", base, "--", str(root)).splitlines()
                 if p.endswith(".sql")]
    changed = git("diff", "--name-status", "--no-renames", base, "--", *published).splitlines()
    for line in changed:
        status, path = line.split("\t", 1)
        report(f"{path}: published migration {'deleted' if status == 'D' else 'modified'}; add a new migration instead")
    published_max = max((int(Path(p).name[:4]) for p in published if name_re.match(Path(p).name)), default=0)
    published_set = set(published)
    for engine, d in dirs.items():
        for p in sorted(d.glob("*.sql")):
            m = name_re.match(p.name)
            if m and str(p) not in published_set and int(m.group(1)) <= published_max:
                report(f"{p}: new migration version must be above the published maximum {published_max:04}")

if bad:
    sys.exit(1)
print(f"lint-migrations: ok ({len(all_versions)} lock-step versions)")
PY
