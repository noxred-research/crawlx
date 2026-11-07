#!/usr/bin/env bash
# Static source gates.
#
#  1. `.click()` / `dispatchEvent(` script strings only in the synthetic module
#     (`crates/crawlx-browser/src/context/synthetic*.rs`) and the hooks engine
#     (`crates/crawlx-browser/src/hooks.rs`). Non-test Rust and JS/TS sources are scanned;
#     comment lines are skipped so docs may name the forbidden calls.
#  2. `sqlx` is a regular dependency of `crawlx-storage` only, and no
#     non-test Rust source outside `crawlx-storage` names `sqlx::`. Dev-dependencies and
#     `tests/` files may use it for assertions.
#  3. `crawlx inspect traffic` / `coverage` read through `TrustedCorpus`: the CLI
#     inspect module must reference it and must not name the `traffic_events` /
#     `action_contexts` tables in SQL.
#  4. The CDP surface catalog names every adapter command/event exactly once.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0

# --- 1. synthetic input outside the synthetic module ------------------------------------
hits=$(grep -rn -E '\.click\(\)|dispatchEvent\(' crates bench \
  --include='*.rs' --include='*.js' --include='*.mjs' --include='*.ts' \
  --exclude-dir=node_modules --exclude-dir=fixtures --exclude-dir=target \
  | grep -v -E '^crates/[^/]+/(tests|benches)/' \
  | grep -v -E '^crates/crawlx-browser/src/context/synthetic[^/]*\.rs:' \
  | grep -v -E '^crates/crawlx-browser/src/hooks\.rs:' \
  | grep -v -E '^[^:]+:[0-9]+:\s*(//|\*|/\*|#)' || true)
if [ -n "$hits" ]; then
  echo "synthetic input (.click()/dispatchEvent) outside crawlx-browser's synthetic module:"
  echo "$hits"
  fail=1
fi

# --- 2. sqlx outside crawlx-storage -----------------------------------------------------
python3 - <<'PY' || fail=1
import json, subprocess, sys
meta = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--no-deps"]))
bad = 0
for p in meta["packages"]:
    for d in p["dependencies"]:
        if d["name"] == "sqlx" and d["kind"] is None and p["name"] != "crawlx-storage":
            print(f"sqlx is a regular dependency of {p['name']} (only crawlx-storage may run SQL)")
            bad += 1
sys.exit(1 if bad else 0)
PY
hits=$(grep -rn --include='*.rs' -E '\bsqlx::' crates \
  | grep -v -E '^crates/crawlx-storage/' \
  | grep -v -E '^crates/[^/]+/(tests|benches)/' \
  | grep -v -E '^[^:]+:[0-9]+:\s*//' || true)
if [ -n "$hits" ]; then
  echo "sqlx used outside crawlx-storage:"
  echo "$hits"
  fail=1
fi

# --- 3. inspect traffic/coverage through TrustedCorpus ----------------------------------
inspect=crates/crawlx-cli/src/inspect.rs
if ! grep -q 'TrustedCorpus' "$inspect"; then
  echo "$inspect does not read through TrustedCorpus"
  fail=1
fi
hits=$(grep -n -E 'FROM\s+(traffic_events|action_contexts)\b' "$inspect" || true)
if [ -n "$hits" ]; then
  echo "$inspect queries lane-bearing tables directly instead of TrustedCorpus:"
  echo "$hits"
  fail=1
fi

# --- 4. CDP surface source/catalog synchronization --------------------------------------
python3 - <<'PY' || fail=1
import collections, pathlib, re, sys
catalog = pathlib.Path("cdp-surface.toml").read_text()
listed = re.findall(r'^\s*name\s*=\s*"([^"]+)"\s*$', catalog, re.MULTILINE)
duplicates = sorted(name for name, count in collections.Counter(listed).items() if count > 1)
used = set()
for source in sorted(pathlib.Path("crates/crawlx-browser/src").rglob("*.rs")):
    for line in source.read_text().splitlines():
        if not line.lstrip().startswith("//"):
            used.update(re.findall(r'"([A-Z][A-Za-z0-9]*\.[a-z][A-Za-z0-9]*)"', line))
missing = sorted(used - set(listed))
stale = sorted(set(listed) - used)
for label, names in [("duplicate catalog entries", duplicates),
                     ("adapter names missing from catalog", missing),
                     ("unused catalog entries", stale)]:
    if names:
        print(f"CDP surface {label}: {names}")
sys.exit(1 if duplicates or missing or stale else 0)
PY

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "lint-static: ok"
