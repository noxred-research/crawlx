#!/usr/bin/env bash
# Mutation-score gate: reads a cargo-mutants `outcomes.json` and
# fails unless at least MIN_CAUGHT_PERCENT of the viable mutants were caught.
#
#   ci/mutants-gate.sh [--report-only] [DIR]   DIR defaults to mutants.out
#
# "Viable" = caught + missed + timeout (unviable mutants do not compile and are excluded;
# timeouts count as caught: the mutation changed behaviour enough to hang the suite).
# Surviving (missed) mutants are listed so a reviewer can turn each into a test.
set -euo pipefail
cd "$(dirname "$0")/.."

MIN_CAUGHT_PERCENT="${MIN_CAUGHT_PERCENT:-95}"
MODE=gate
if [[ "${1:-}" == "--report-only" ]]; then
  MODE=report
  shift
fi
DIR="${1:-mutants.out}"
FILE="$DIR/outcomes.json"
if [[ ! -f "$FILE" ]]; then
  echo "mutants-gate: $FILE not found (run cargo mutants first)" >&2
  exit 1
fi

MODE="$MODE" MIN="$MIN_CAUGHT_PERCENT" FILE="$FILE" python3 - <<'PY'
import json, os, sys

data = json.load(open(os.environ["FILE"]))
outcomes = data.get("outcomes", [])
counts = {"CaughtMutant": 0, "MissedMutant": 0, "Timeout": 0, "Unviable": 0}
missed = []
for o in outcomes:
    scenario = o.get("scenario")
    if not isinstance(scenario, dict) or "Mutant" not in scenario:
        continue  # the baseline
    summary = o.get("summary")
    if summary in counts:
        counts[summary] += 1
    if summary == "MissedMutant":
        missed.append(scenario["Mutant"].get("name") or json.dumps(scenario["Mutant"]))

caught = counts["CaughtMutant"] + counts["Timeout"]
viable = caught + counts["MissedMutant"]
score = 100.0 * caught / viable if viable else 0.0
print(f'mutants-gate: {os.environ["FILE"]}')
print(f'  caught {counts["CaughtMutant"]}, timeout {counts["Timeout"]}, missed {counts["MissedMutant"]}, unviable {counts["Unviable"]}')
print(f'  score {score:.1f}% of {viable} viable mutants (gate >= {os.environ["MIN"]}%)')
for line in sorted(missed):
    print(f'  missed: {line}')
if os.environ["MODE"] == "report":
    sys.exit(0)
if viable == 0:
    print("mutants-gate: no viable mutants; nothing to gate", file=sys.stderr)
    sys.exit(1)
sys.exit(0 if score >= float(os.environ["MIN"]) else 1)
PY
