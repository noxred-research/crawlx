#!/usr/bin/env bash
# Release-gate checklist: evaluates the checklist of docs/ops/release-gates.md from the
# evidence under bench/out and the repository, writes bench/out/release-checklist.json and
# bench/out/release-checklist.md, prints the checklist and exits with the verdict:
#
#   0  every applicable item passed (or carries a valid waiver)
#   1  the release is blocked: at least one item failed or is unmeasured
#   2  usage error or a malformed waiver
#
#   ci/release-gate.sh                         check the release
#   ci/release-gate.sh --model-tier-changed    the model tier changes in this release
#   ci/release-gate.sh --today 2026-12-01      judge waivers and the restore drill on that date
#
# Any further argument goes to `release-gate check`. Suite results (cargo deny, the
# safety-matrix suites, ci/bench-gate.sh, ...) are put into the evidence directory first with
# `cargo run -p crawlx-bench --bin release-gate -- record --id ID -- COMMAND...`.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bench/out
exec cargo run -p crawlx-bench --bin release-gate -- check \
  --evidence bench/out \
  --out bench/out/release-checklist.json \
  --markdown bench/out/release-checklist.md \
  "$@"
