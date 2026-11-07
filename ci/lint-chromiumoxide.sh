#!/usr/bin/env bash
# Gate: chromiumoxide is a direct dependency of crawlx-browser only, and the resolved
# chromiumoxide version is the one pinned in chromium-pin.toml.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
import json, subprocess, sys, tomllib

meta = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1"]))
workspace = set(meta["workspace_members"])
by_id = {p["id"]: p for p in meta["packages"]}
bad = 0

direct = sorted(
    by_id[pid]["name"]
    for pid in workspace
    if any(d["name"] == "chromiumoxide" for d in by_id[pid]["dependencies"])
)
if direct != ["crawlx-browser"]:
    print(f"lint-chromiumoxide: chromiumoxide must be a direct dependency of crawlx-browser only, found {direct}")
    bad += 1

# Transitive reachability through workspace crates (a workspace crate that re-depends on
# chromiumoxide through another non-workspace crate would still be a backend leak).
resolve = {n["id"]: n for n in meta["resolve"]["nodes"]}
def reaches_chromiumoxide_outside_browser(pid, seen):
    for dep in resolve[pid]["deps"]:
        did = dep["pkg"]
        if did in seen:
            continue
        seen.add(did)
        name = by_id[did]["name"]
        if name == "chromiumoxide":
            return True
        if did in workspace:
            continue  # workspace edges are checked by ci/lint-deps.sh against layering.toml
        if reaches_chromiumoxide_outside_browser(did, seen):
            return True
    return False
for pid in sorted(workspace):
    name = by_id[pid]["name"]
    if name == "crawlx-browser":
        continue
    if reaches_chromiumoxide_outside_browser(pid, set()):
        print(f"lint-chromiumoxide: {name} reaches chromiumoxide without going through crawlx-browser")
        bad += 1

resolved = sorted({p["version"] for p in meta["packages"] if p["name"] == "chromiumoxide"})
if len(resolved) != 1:
    print(f"lint-chromiumoxide: expected exactly one resolved chromiumoxide, found {resolved}")
    bad += 1
pin = tomllib.load(open("chromium-pin.toml", "rb"))["chromium"].get("chromiumoxide", "")
pinned = pin.lstrip("=").strip()
if not pin.startswith("=") or not pinned:
    print(f"lint-chromiumoxide: chromium-pin.toml chromiumoxide must be an exact '=X.Y.Z' requirement, found {pin!r}")
    bad += 1
elif resolved and resolved != [pinned]:
    print(f"lint-chromiumoxide: resolved chromiumoxide {resolved} != pinned {pinned}")
    bad += 1

if bad:
    sys.exit(1)
print(f"lint-chromiumoxide: ok (crawlx-browser -> chromiumoxide {pinned})")
PY
