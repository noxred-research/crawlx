#!/usr/bin/env bash
# Wire-level differential (VAL, PREC, CLAMP, PERSIST, CANCEL, RESUME/LEASE, WH, ZDR):
# run the scenarios of `wire-scenarios.json` against the unmodified upstream self-host at the
# pinned commit, capture the raw exchanges, replay the same scenarios against the crawlx compat
# facade (crates/crawlx-bench/tests/wire_facade.rs) and score both under the ledger.
#
#   bench/differential/run-wire.sh [FAMILY|all] [OUT_DIR]
#
# FAMILY is a `wire-*` id of `wire-scenarios.json` (default `all`). The exit code is 0 when every
# family reaches its `expect`ed verdict, 1 when one does not, 2 on setup errors.
#
# Environment (same names as run.sh):
#   UPSTREAM_COMMIT   pinned commit (default c31e88c07afe941bfd8aebde61684eeba042abb5)
#   UPSTREAM_SRC      the upstream checkout (default bench/differential/.upstream-src); only used to
#                      build the restart command of the PERSIST/RESUME scenarios
#   UPSTREAM_PORT     host port of the upstream API (default 3002)
#   UPSTREAM_URL      the running API (default http://127.0.0.1:$UPSTREAM_PORT)
#   GYM_PORT           host port of the gym (default 4100); GYM_HOST the name the containers use (gym.test)
#   RESTART_CMD        shell command restarting the upstream API and its workers (default:
#                      docker compose -p crawlx-differential ... restart api)
#   SKIP_UPSTREAM=1   offline replay: compare the committed captures/<family>.json with the facade only
#   PROMOTE=1          copy each fresh capture to bench/differential/captures/<family>.json and each
#                      scorecard to bench/out/differential/<family>.scorecard.md
set -euo pipefail
cd "$(dirname "$0")/../.."

SELECT="${1:-all}"
OUT="${2:-bench/differential/out}"
UPSTREAM_COMMIT="${UPSTREAM_COMMIT:-c31e88c07afe941bfd8aebde61684eeba042abb5}"
UPSTREAM_SRC="${UPSTREAM_SRC:-bench/differential/.upstream-src}"
UPSTREAM_PORT="${UPSTREAM_PORT:-3002}"
UPSTREAM_URL="${UPSTREAM_URL:-http://127.0.0.1:$UPSTREAM_PORT}"
GYM_PORT="${GYM_PORT:-4100}"
GYM_HOST="${GYM_HOST:-gym.test}"
SPEC="bench/differential/wire-scenarios.json"
CAPTURES="bench/differential/captures"
EVIDENCE="bench/out/differential"
RESTART_CMD="${RESTART_CMD:-PORT=$UPSTREAM_PORT docker compose -p crawlx-differential --env-file bench/differential/upstream.env -f $UPSTREAM_SRC/docker-compose.yaml -f bench/differential/docker-compose.upstream.yaml restart api}"
mkdir -p "$OUT"
OUT="$(realpath "$OUT")"   # the facade test runs from the crate directory

cargo build -p crawlx-bench --bins
TARGET_DIR="${CARGO_TARGET_DIR:-$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')}"
GYM_BIN="$TARGET_DIR/debug/gym-server"
DIFF_BIN="$TARGET_DIR/debug/crawlx-differential"

IDS=$(python3 - "$SPEC" "$SELECT" <<'PY'
import json, sys
ids = [f["id"] for f in json.load(open(sys.argv[1]))["families"]]
select = sys.argv[2]
if select == "all":
    print("\n".join(ids))
elif select in ids:
    print(select)
else:
    sys.exit(f"unknown wire family `{select}`; known: {', '.join(ids)}")
PY
)
expect_of() { python3 - "$SPEC" "$1" <<'PY'
import json, sys
fam = next(f for f in json.load(open(sys.argv[1]))["families"] if f["id"] == sys.argv[2])
print(fam.get("expect", "pass"))
PY
}
test_name_of() { echo "$1" | tr '-' '_'; }

cleanup() {
  if [[ -n "${GYM_PID:-}" ]]; then kill "$GYM_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

SUMMARY="$OUT/wire-summary.md"
{
  echo "# Wire differential run"
  echo
  echo "| family | verdict | expect | findings |"
  echo "|---|---|---|---:|"
} >"$SUMMARY"
overall=0
for id in $IDS; do
  expect=$(expect_of "$id")
  fc_capture="$OUT/$id.upstream.json"
  if [[ -n "${SKIP_UPSTREAM:-}" ]]; then
    fc_capture="$(realpath "$CAPTURES/$id.json")"
  else
    if curl -fsS "http://127.0.0.1:$GYM_PORT/robots.txt" >/dev/null 2>&1; then
      echo "run-wire.sh: port $GYM_PORT is already served; set GYM_PORT to a free port" >&2
      exit 2
    fi
    "$GYM_BIN" --bind "0.0.0.0:$GYM_PORT" --claim-origin d2 >"$OUT/gym-$id.log" 2>&1 &
    GYM_PID=$!
    for _ in $(seq 1 50); do
      curl -fsS "http://127.0.0.1:$GYM_PORT/robots.txt" >/dev/null 2>&1 && break
      sleep 0.2
    done
    "$DIFF_BIN" wire capture --spec "$SPEC" --family "$id" --api "$UPSTREAM_URL" \
      --origin "http://$GYM_HOST:$GYM_PORT" --gym-ledger "http://127.0.0.1:$GYM_PORT/__gym/ledger" \
      --sink-bind 0.0.0.0:0 --sink-origin "http://$GYM_HOST:{port}" --restart-cmd "$RESTART_CMD" \
      --commit "$UPSTREAM_COMMIT" --out "$fc_capture"
    kill "$GYM_PID" 2>/dev/null || true
    wait "$GYM_PID" 2>/dev/null || true
    unset GYM_PID
  fi
  # the facade side runs in process inside the test, which compares it with `fc_capture`
  mkdir -p "$OUT/scorecards" "$OUT/crawlx"
  set +e
  CRAWLX_WIRE_UPSTREAM="$fc_capture" CRAWLX_WIRE_RECORD="$OUT/crawlx" CRAWLX_WIRE_SCORECARDS="$OUT/scorecards" \
    cargo test -p crawlx-bench --test wire_facade "$(test_name_of "$id")_" -- --test-threads=1 >"$OUT/$id.test.log" 2>&1
  code=$?
  set -e
  card="$OUT/scorecards/$id.scorecard.md"
  verdict=$(sed -n 's/^Verdict: \*\*\([A-Za-z]*\)\*\*.*/\1/p' "$card" 2>/dev/null | tr 'A-Z' 'a-z' || true)
  findings=$(grep -c '^- ' "$card" 2>/dev/null || true)
  echo "| $id | ${verdict:-none} | $expect | ${findings:-0} |" >>"$SUMMARY"
  if [[ "$verdict" != "$expect" ]]; then
    echo "run-wire.sh: family $id reached ${verdict:-no verdict}, expected $expect (test exit $code, $OUT/$id.test.log)" >&2
    overall=1
  fi
  if [[ -n "${PROMOTE:-}" && -z "${SKIP_UPSTREAM:-}" && -s "$card" ]]; then
    mkdir -p "$CAPTURES" "$EVIDENCE"
    cp "$fc_capture" "$CAPTURES/$id.json"
    cp "$card" "$EVIDENCE/$id.scorecard.md"
  fi
done
cat "$SUMMARY"
exit "$overall"
