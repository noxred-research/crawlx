#!/usr/bin/env bash
# Differential run: crawl gym fixtures through the unmodified upstream
# self-host at the pinned commit, export each result as data, crawl the same fixture with the
# same request through crawlx, and score both with `crawlx-differential`.
#
#   bench/differential/run.sh [FAMILY|all] [OUT_DIR]
#
# FAMILY is an id of `families.json` (default `s1`); `all` runs every family. The exit code is 0
# when every family reaches its `expect`ed verdict (a `block` that names an `open` residual
# is allowed), 1 when one does not, 2 on setup errors.
#
# Environment:
#   UPSTREAM_COMMIT   pinned commit (default c31e88c07afe941bfd8aebde61684eeba042abb5)
#   UPSTREAM_REPO     git URL (default https://github.com/firecrawl/firecrawl.git; wire-compat: pinned dependency checkout URL)
#   UPSTREAM_SRC      the upstream checkout (default bench/differential/.upstream-src, git-ignored).
#                      Must stay outside crates/; a shared checkout such as
#                      $HOME/.cache/upstream-checkout works well. Its HEAD must equal UPSTREAM_COMMIT.
#   UPSTREAM_PORT     host port of the upstream API (default 3002)
#   UPSTREAM_URL      use an already running API (no compose, no checkout), e.g. http://127.0.0.1:3102
#   GYM_PORT           host port of the gym fixture server (default 4100)
#   GYM_HOST           hostname the containers use for the gym (default gym.test, see the compose override)
#   KEEP_STACK=1       do not tear the upstream stack down afterwards
#   SKIP_UPSTREAM=1   offline replay: reuse the committed bench/differential/captures/<family>.json
#                      instead of crawling through upstream (what `cargo test -p crawlx-bench --test
#                      differential` does for the families it covers)
#   PROMOTE=1          copy each fresh export to bench/differential/captures/<family>.json
#                      and each scorecard to bench/out/differential/<family>.scorecard.md
#
# Requires docker compose v2 (unless UPSTREAM_URL or SKIP_UPSTREAM is set), git, python3 and a
# Rust toolchain. Not part of the PR gate (ci.yml job `differential-nightly`, schedule only).
set -euo pipefail
cd "$(dirname "$0")/../.."

SELECT="${1:-s1}"
OUT="${2:-bench/differential/out}"
UPSTREAM_COMMIT="${UPSTREAM_COMMIT:-c31e88c07afe941bfd8aebde61684eeba042abb5}"
UPSTREAM_REPO="${UPSTREAM_REPO:-https://github.com/firecrawl/firecrawl.git}" # wire-compat: pinned dependency checkout URL
UPSTREAM_SRC="${UPSTREAM_SRC:-bench/differential/.upstream-src}"
UPSTREAM_PORT="${UPSTREAM_PORT:-3002}"
GYM_PORT="${GYM_PORT:-4100}"
GYM_HOST="${GYM_HOST:-gym.test}"
CAPTURES="bench/differential/captures"
EVIDENCE="bench/out/differential"
FAMILIES="bench/differential/families.json"
COMPOSE=(docker compose -p crawlx-differential --env-file bench/differential/upstream.env
  -f "$UPSTREAM_SRC/docker-compose.yaml" -f bench/differential/docker-compose.upstream.yaml)
mkdir -p "$OUT"

cargo build -p crawlx-bench --bins
TARGET_DIR="${CARGO_TARGET_DIR:-$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')}"
GYM_BIN="$TARGET_DIR/debug/gym-server"
DIFF_BIN="$TARGET_DIR/debug/crawlx-differential"

# family ids to run, and one field of a family
family_ids() {
  python3 - "$FAMILIES" "$SELECT" <<'PY'
import json, sys
families = json.load(open(sys.argv[1]))["families"]
ids = [f["id"] for f in families]
select = sys.argv[2]
if select == "all":
    print("\n".join(ids))
elif select in ids:
    print(select)
else:
    sys.exit(f"unknown family `{select}`; known: {', '.join(ids)}")
PY
}
family_field() { # id field [default]
  python3 - "$FAMILIES" "$1" "$2" "${3:-}" <<'PY'
import json, sys
fam = next(f for f in json.load(open(sys.argv[1]))["families"] if f["id"] == sys.argv[2])
value = fam.get(sys.argv[3], sys.argv[4])
print(json.dumps(value) if isinstance(value, (dict, list)) else value)
PY
}
IDS=$(family_ids)

cleanup() {
  if [[ -n "${GYM_PID:-}" ]]; then kill "$GYM_PID" 2>/dev/null || true; fi
  if [[ -n "${STACK_UP:-}" && -z "${KEEP_STACK:-}" ]]; then
    PORT="$UPSTREAM_PORT" "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

API="${UPSTREAM_URL:-http://127.0.0.1:$UPSTREAM_PORT}"
if [[ -z "${SKIP_UPSTREAM:-}" ]]; then
  # 1. The unmodified pinned upstream checkout (AGPL-3.0; outside crates/, never committed).
  if [[ -z "${UPSTREAM_URL:-}" ]]; then
    if [[ ! -d "$UPSTREAM_SRC/.git" ]]; then
      git init -q "$UPSTREAM_SRC"
      git -C "$UPSTREAM_SRC" remote add origin "$UPSTREAM_REPO"
    fi
    if ! git -C "$UPSTREAM_SRC" cat-file -e "$UPSTREAM_COMMIT^{commit}" 2>/dev/null; then
      git -C "$UPSTREAM_SRC" fetch -q --depth 1 origin "$UPSTREAM_COMMIT"
    fi
    if [[ "$(git -C "$UPSTREAM_SRC" rev-parse HEAD 2>/dev/null)" != "$UPSTREAM_COMMIT" ]]; then
      git -C "$UPSTREAM_SRC" checkout -q --detach "$UPSTREAM_COMMIT"
    fi
  fi

  # 2. The gym starts per family (below): its robots.txt belongs to the first fixture an origin
  # serves, so a family must meet a fresh gym, like the in-process crawlx run does.
  if curl -fsS "http://127.0.0.1:$GYM_PORT/robots.txt" >/dev/null 2>&1; then
    echo "run.sh: port $GYM_PORT is already served; set GYM_PORT to a free port" >&2
    exit 2
  fi

  # 3. Upstream stack: only the API and its dependencies (the FoundationDB services of the
  # Compose file are for an optional queue backend).
  if [[ -z "${UPSTREAM_URL:-}" ]]; then
    PORT="$UPSTREAM_PORT" "${COMPOSE[@]}" build api playwright-service nuq-postgres # wire-compat: service names of the upstream Compose file
    PORT="$UPSTREAM_PORT" "${COMPOSE[@]}" up -d --wait api
    STACK_UP=1
  fi
  for _ in $(seq 1 60); do
    curl -fsS "$API/" >/dev/null 2>&1 && break
    sleep 2
  done
fi

# 4. Per family: export through upstream, crawl with crawlx, score.
overall=0
SUMMARY="$OUT/summary.md"
{
  echo "# Differential run"
  echo
  echo "| family | verdict | expect | open | attempted (upstream/crawlx) | findings |"
  echo "|---|---|---|---|---:|---:|"
} >"$SUMMARY"
for id in $IDS; do
  fixture=$(family_field "$id" fixture)
  request=$(family_field "$id" request '{}')
  expect=$(family_field "$id" expect warn)
  open=$(family_field "$id" open "")
  host=$(family_field "$id" host "$GYM_HOST")
  seed_path=$(family_field "$id" seed_path "")
  if [[ -z "$seed_path" ]]; then
    seed_path=$(python3 -c "import json,sys;print(json.load(open('crates/crawlx-bench/fixtures/$fixture/manifest.json'))['url_path'])")
  fi
  claim=$(family_field "$id" claim_origin "")
  aliases=$(python3 - "$FAMILIES" "$id" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
fam = next(f for f in data["families"] if f["id"] == sys.argv[2])
print(" ".join(fam.get("aliases") or data.get("fixture_hosts", {}).get(fam["fixture"], [])))
PY
)
  if [[ "$claim" != "True" ]]; then claim=""; fi
  export_file="$OUT/$id.upstream.json"
  if [[ -n "${SKIP_UPSTREAM:-}" ]]; then
    export_file="$CAPTURES/$id.json"
  else
    # Gym fixture server on all interfaces, reachable from the containers as $host (and the
    # other names of the fixture, see docker-compose.upstream.yaml). A fixture that owns the
    # origin's robots.txt is claimed up front.
    gym_args=(--bind "0.0.0.0:$GYM_PORT")
    if [[ -n "$claim" ]]; then gym_args+=(--claim-origin "$fixture"); fi
    "$GYM_BIN" "${gym_args[@]}" >"$OUT/gym.log" 2>&1 &
    GYM_PID=$!
    for _ in $(seq 1 50); do
      curl -fsS "http://127.0.0.1:$GYM_PORT/robots.txt" >/dev/null 2>&1 && break
      sleep 0.2
    done
    python3 bench/differential/upstream_export.py --api "$API" --origin "http://$host:$GYM_PORT" \
      --seed-path "$seed_path" --request "$request" --family "$id" --commit "$UPSTREAM_COMMIT" \
      --gym-ledger "http://127.0.0.1:$GYM_PORT/__gym/ledger" --out "$export_file"
    kill "$GYM_PID" 2>/dev/null || true
    wait "$GYM_PID" 2>/dev/null || true
    unset GYM_PID
  fi
  compare=$(family_field "$id" compare admission)
  extra=()
  if [[ "$compare" == cardinality ]]; then extra+=(--cardinality-only); fi
  if [[ -n "$claim" ]]; then extra+=(--claim-origin); fi
  if [[ "$host" != "$GYM_HOST" || -n "$claim" ]]; then
    extra+=(--host "$host" --seed-path "$seed_path")
    for a in $aliases; do extra+=(--alias "$a"); done
  fi
  set +e
  "$DIFF_BIN" \
    --upstream "$export_file" \
    --upstream-origin "http://$host:$GYM_PORT" \
    --fixture "$fixture" \
    --request "@$export_file" \
    ${extra[@]+"${extra[@]}"} \
    --trailing-slash keep \
    --save-crawlx "$OUT/$id.crawlx.json" \
    --divergences bench/differential/divergences.toml \
    --label "$id" \
    --out "$OUT/$id.scorecard.md"
  code=$?
  set -e
  verdict=$(sed -n 's/^Verdict: \*\*\([A-Za-z]*\)\*\*.*/\1/p' "$OUT/$id.scorecard.md" | tr 'A-Z' 'a-z')
  findings=$(grep -c '^- ' "$OUT/$id.scorecard.md" || true)
  attempted=$(sed -n 's/^| attempted URLs | \([0-9]*\) | \([0-9]*\) |.*/\1 \/ \2/p' "$OUT/$id.scorecard.md")
  echo "| $id | $verdict | $expect | ${open:--} | $attempted | $findings |" >>"$SUMMARY"
  ok=1
  if [[ "$verdict" != "$expect" ]]; then ok=0; fi
  if [[ "$verdict" == "block" && -n "$open" && "$expect" == "block" ]]; then ok=1; fi
  if [[ "$ok" == 0 ]]; then
    echo "run.sh: family $id reached $verdict, expected $expect (exit $code)" >&2
    overall=1
  fi
  if [[ -n "${PROMOTE:-}" && -z "${SKIP_UPSTREAM:-}" ]]; then
    mkdir -p "$CAPTURES" "$EVIDENCE"
    cp "$export_file" "$CAPTURES/$id.json"
    cp "$OUT/$id.scorecard.md" "$EVIDENCE/$id.scorecard.md"
  fi
done
cat "$SUMMARY"
exit "$overall"
