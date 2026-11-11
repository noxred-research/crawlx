#!/usr/bin/env bash
# Flake handling for CI (docs/ops/flaky-tests.md): chains the `flake-report` subcommands.
#
#   ci/flake-gate.sh filter [--only]         nextest filterset for ci/quarantine.toml on stdout:
#                                            excludes the quarantined tests (PR suites), or with
#                                            --only selects just them (nightly)
#   ci/flake-gate.sh record SUITE JUNIT...   append one suite run to the history
#   ci/flake-gate.sh gate [--release]        quarantine tests with 3 flake events in 14 days,
#                                            fail on a test quarantined for more than 14 days,
#                                            write bench/out/flake-report.json and the issue
#                                            bodies; --release also fails unless the PR-suite
#                                            flake rate over 30 days is below 1%
#
# Environment: FLAKE_HISTORY (default bench/out/flake-history.json), FLAKE_DATE (YYYY-MM-DD,
# default today UTC), FLAKE_REPORT (a prebuilt flake-report binary; default: cargo run).
# Exit: 0 ok, 1 a gate failed, 2 usage or input error.
set -euo pipefail
cd "$(dirname "$0")/.."

HISTORY="${FLAKE_HISTORY:-bench/out/flake-history.json}"
QUARANTINE=ci/quarantine.toml
OUT=bench/out/flake-report.json
MARKDOWN=bench/out/flake-issues.md
DATE_ARGS=()
if [[ -n "${FLAKE_DATE:-}" ]]; then
  DATE_ARGS=(--date "$FLAKE_DATE")
fi

report() {
  if [[ -n "${FLAKE_REPORT:-}" ]]; then
    "$FLAKE_REPORT" "$@"
  else
    cargo run -q -p crawlx-bench --bin flake-report -- "$@"
  fi
}

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

cmd="${1:-}"
[[ -n "$cmd" ]] || usage
shift

case "$cmd" in
  filter)
    case "${1:-}" in
      "") report filter --file "$QUARANTINE" ;;
      --only) report filter --file "$QUARANTINE" --only ;;
      *) usage ;;
    esac
    ;;
  record)
    [[ $# -ge 2 ]] || usage
    suite="$1"
    shift
    report record --history "$HISTORY" --suite "$suite" "${DATE_ARGS[@]}" --junit "$@"
    ;;
  gate)
    release=()
    case "${1:-}" in
      "") ;;
      --release) release=(--release-gate) ;;
      *) usage ;;
    esac
    report quarantine --history "$HISTORY" --file "$QUARANTINE" "${DATE_ARGS[@]}"
    status=0
    report check --file "$QUARANTINE" "${DATE_ARGS[@]}" || status=$?
    report report --history "$HISTORY" --out "$OUT" --markdown "$MARKDOWN" \
      --quarantine "$QUARANTINE" "${DATE_ARGS[@]}" "${release[@]}" || status=$?
    exit "$status"
    ;;
  *) usage ;;
esac
