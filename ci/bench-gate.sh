#!/usr/bin/env bash
# Criterion regression gate: runs the benches of the listed crates, saves the
# `current` Criterion baseline, then compares every benchmark's median and p95 against the
# committed baseline in bench/baselines/criterion.json.
#
#   ci/bench-gate.sh            run benches, compare, exit 1 on > 10% median regression or a
#                               missed absolute gate (p95 above `max_p95_ns`)
#   ci/bench-gate.sh --record   run benches and rewrite the committed baseline from this run
#   ci/bench-gate.sh --compare  skip `cargo bench`; compare the existing `current` baseline
#   ci/bench-gate.sh --record-existing
#                               skip `cargo bench`; rewrite the committed baseline from the
#                               existing `current` baselines (after running benches by hand)
#
# Regression policy (planning default): > 10% median regression fails; 5–10% is reported as a
# warning for a tracking issue. Shared CI runners produce trend data; the gate is authoritative
# only on the reference runner recorded in the baseline file.
set -euo pipefail
cd "$(dirname "$0")/.."

# crate:bench pairs; `cargo bench -p crate` alone would also run the libtest harness of the
# library target, which rejects Criterion's `--save-baseline`.
BENCHES=(
  crawlx-url:canonicalize
  crawlx-state:fingerprint
  crawlx-state:cluster_decision
  crawlx-strategies:arbiter
  crawlx-scheduler:lease_memory
  crawlx-graph:best_path
  crawlx-url:sitemap_frontier
  crawlx-policy:scope_robots
  crawlx-extract:extract
  crawlx-elements:identity
  crawlx-forms:partitions
  crawlx-model:decide
  crawlx-observe:network_tracker
  crawlx-state:split
  crawlx-strategies:utility
  crawlx-scheduler:lease_pg
  crawlx-storage:journal
  crawlx-storage:artifact_key
)
MODE="${1:-gate}"
BASELINE="bench/baselines/criterion.json"
# Honors CARGO_TARGET_DIR and `build.target-dir` from .cargo/config.toml alike.
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"

if [[ "$MODE" != "--compare" && "$MODE" != "--record-existing" ]]; then
  for pair in "${BENCHES[@]}"; do
    cargo bench -p "${pair%%:*}" --bench "${pair##*:}" -- --save-baseline current --noplot
  done
fi

python3 - "$MODE" "$BASELINE" "$TARGET_DIR/criterion" <<'PY'
import json, os, platform, sys, datetime

mode, baseline_path, root = sys.argv[1], sys.argv[2], sys.argv[3]
FAIL_PCT, WARN_PCT = 10.0, 5.0

def load_runs():
    """benchmark id -> (median_ns, p95_ns) from every `current` Criterion baseline."""
    runs = {}
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath) != "current" or "estimates.json" not in filenames:
            continue
        bench_id = os.path.relpath(os.path.dirname(dirpath), root).replace(os.sep, "/")
        with open(os.path.join(dirpath, "estimates.json")) as f:
            est = json.load(f)
        median = est["median"]["point_estimate"]
        p95 = median
        sample = os.path.join(dirpath, "sample.json")
        if os.path.exists(sample):
            with open(sample) as f:
                s = json.load(f)
            per_iter = sorted(t / i for t, i in zip(s["times"], s["iters"]) if i)
            if per_iter:
                p95 = per_iter[min(len(per_iter) - 1, int(round(0.95 * (len(per_iter) - 1))))]
        runs[bench_id] = (median, p95)
    return runs

runs = load_runs()
if not runs:
    print(f"bench-gate: no Criterion results under {root}", file=sys.stderr)
    sys.exit(1)

baseline = {"version": 1, "runner": {}, "gates": {}, "benchmarks": {}}
if os.path.exists(baseline_path):
    with open(baseline_path) as f:
        baseline = json.load(f)

if mode in ("--record", "--record-existing"):
    baseline["runner"] = {
        "recorded_on": datetime.date.today().isoformat(),
        "machine": platform.machine(),
        "platform": platform.platform(),
        "cpu": baseline.get("runner", {}).get("cpu") or platform.processor() or "unknown",
    }
    baseline["benchmarks"] = {k: {"median_ns": round(m, 1), "p95_ns": round(p, 1)} for k, (m, p) in sorted(runs.items())}
    os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
    with open(baseline_path, "w") as f:
        json.dump(baseline, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"bench-gate: recorded {len(runs)} benchmarks into {baseline_path}")
    sys.exit(0)

failed, warned = [], []
print(f"{'benchmark':60} {'median':>12} {'baseline':>12} {'delta':>8}  {'p95':>12}")
for bench_id, (median, p95) in sorted(runs.items()):
    ref = baseline.get("benchmarks", {}).get(bench_id)
    gate = baseline.get("gates", {}).get(bench_id)
    delta = ""
    if ref:
        pct = (median - ref["median_ns"]) / ref["median_ns"] * 100.0
        delta = f"{pct:+.1f}%"
        if pct > FAIL_PCT:
            failed.append(f"{bench_id}: median {median:.0f} ns vs baseline {ref['median_ns']:.0f} ns ({pct:+.1f}%)")
        elif pct > WARN_PCT:
            warned.append(f"{bench_id}: {pct:+.1f}% (open a tracking issue)")
    else:
        warned.append(f"{bench_id}: no committed baseline (run ci/bench-gate.sh --record)")
    if gate and p95 > gate["max_p95_ns"]:
        failed.append(f"{bench_id}: p95 {p95:.0f} ns exceeds the MAIN target {gate['max_p95_ns']:.0f} ns ({gate.get('note', '')})")
    print(f"{bench_id:60} {median:12.0f} {(ref or {}).get('median_ns', float('nan')):12.0f} {delta:>8}  {p95:12.0f}")

for w in warned:
    print(f"warning: {w}")
for f_ in failed:
    print(f"FAIL: {f_}")
sys.exit(1 if failed else 0)
PY
