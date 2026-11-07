#!/usr/bin/env bash
# Enforces layering edges, no anyhow in libraries, thiserror in every library.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
python3 - <<'PY' || fail=1
import json, subprocess, sys, tomllib
meta = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--no-deps"]))
allowed = tomllib.load(open("ci/layering.toml", "rb"))["edges"]
names = {p["name"] for p in meta["packages"]}
bad = 0
for p in meta["packages"]:
    deps = [d["name"] for d in p["dependencies"] if d["name"] in names and d["kind"] is None]
    for d in deps:
        if d not in allowed.get(p["name"], []):
            print(f"layering: {p['name']} -> {d} not allowed"); bad += 1
    if p["name"] != "crawlx-cli":
        for d in p["dependencies"]:
            if d["name"] == "anyhow" and d["kind"] is None:
                print(f"anyhow in library crate {p['name']}"); bad += 1
        if not any(d["name"] == "thiserror" for d in p["dependencies"]):
            print(f"{p['name']} does not depend on thiserror"); bad += 1
sys.exit(1 if bad else 0)
PY
exit $fail
