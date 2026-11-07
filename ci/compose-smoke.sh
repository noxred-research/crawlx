#!/usr/bin/env bash
# Compose smoke test for docker/docker-compose.yml.
#
# Always (needs only the `docker compose` plugin, not a daemon):
#   * `docker compose -f docker/docker-compose.yml config -q`, bare and with every profile.
#
# With CRAWLX_COMPOSE_UP=1, the daemon and live-stack prerequisites are required.
# The stack starts under a throwaway project and is torn down with `down -v`:
#   1. docker/init-compose.sh writes secrets and an env file into a temp dir;
#   2. the api, worker and gym images are built (CRAWLX_COMPOSE_BUILD=0 reuses the
#      `crawlx-smoke/*:smoke` images of an earlier run) and `up -d --wait` brings up postgres,
#      migrate, api, worker, minio, minio-init and the `smoke`-profile gym until healthy;
#   3. readiness/liveness answer, an unauthenticated crawl is refused, a worker has registered
#      (`crawlx admin status` through the `ops`-profile admin service);
#   4. a static crawl of the gym's `s1` site runs through POST /v1/crawls and its pages come back
#      with markdown the API read from the artifact volume it shares with the worker.
#
# Private-network egress is denied by default (SSRF policy), and the gym answers on a
# private bridge address. The sanctioned way in is an authorization record: this
# script inserts one into `authorization_records` that names the gym origin and authorizes
# exactly the gym's address (`authorizedNetworks`), and the crawl asks for it with
# `safety.allowPrivateNetworks` + `safety.authorizationRecordRef`. Admission checks the record
# (window, tenant, seed origin) and the worker's egress policy then exempts only that network.
# Nothing in docker/docker-compose.yml changes for this; no worker setting is relaxed.
#
# Usage: [CRAWLX_COMPOSE_UP=1] [CRAWLX_COMPOSE_BUILD=0] [CRAWLX_COMPOSE_TIMEOUT=600] ci/compose-smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE_FILE=docker/docker-compose.yml
TIMEOUT="${CRAWLX_COMPOSE_TIMEOUT:-600}"
say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  if [ "${CRAWLX_COMPOSE_UP:-0}" = 1 ]; then
    die "the requested live stack requires the docker compose plugin"
  fi
  say "skipping: the docker compose plugin is not available"
  exit 0
fi

docker compose -f "$COMPOSE_FILE" config -q
docker compose -f "$COMPOSE_FILE" --profile smoke --profile ops config -q
say "compose config: ok"

if [ "${CRAWLX_COMPOSE_UP:-0}" != 1 ]; then
  say "skipping the live stack: CRAWLX_COMPOSE_UP=1 is not set"
  exit 0
fi
if ! docker info >/dev/null 2>&1; then
  die "the requested live stack requires a reachable docker daemon (docker info failed)"
fi
command -v curl >/dev/null 2>&1 || die "curl is required for the live stack"
command -v python3 >/dev/null 2>&1 || die "python3 is required for the live stack"

workdir="$(mktemp -d)"
project="crawlx-smoke-$$"
api_port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"

docker/init-compose.sh "$workdir" >/dev/null
{
  # local image names: never shadow or pull the registry tags
  echo "CRAWLX_REGISTRY=crawlx-smoke"
  echo "CRAWLX_TAG=smoke"
  echo "CRAWLX_API_PORT=$api_port"
} >>"$workdir/.env"

compose() {
  docker compose -p "$project" -f "$COMPOSE_FILE" --env-file "$workdir/.env" --profile smoke "$@"
}

cleanup() {
  local rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ]; then
    compose ps -a >&2 || true
    compose logs --no-color --tail 60 >&2 || true
  fi
  compose --profile ops down -v --remove-orphans >&2 || true
  rm -rf "$workdir"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "${CRAWLX_COMPOSE_BUILD:-1}" != 0 ]; then
  say "building images (api, worker, gym)"
  compose build
fi
say "starting the stack as project $project (api on 127.0.0.1:$api_port)"
compose up -d --wait --no-build --wait-timeout "$TIMEOUT"

key_spec="$(sed -n 's/^CRAWLX_API_KEY_SPEC=//p' "$workdir/.env" | tr -d '"')"
api_key="${key_spec#*=}"
base="http://127.0.0.1:$api_port"

say "probes"
curl -fsS --max-time 10 "$base/v0/health/readiness" >/dev/null || die "readiness probe failed"
curl -fsS --max-time 10 "$base/v0/health/liveness" >/dev/null || die "liveness probe failed"
status="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -X POST "$base/v1/crawls" \
  -H 'content-type: application/json' -d '{"seedUrl":"https://example.test/"}')"
[ "$status" = 401 ] || die "an unauthenticated crawl must be refused with 401, got $status"

say "worker registration"
deadline=$((SECONDS + 90))
while :; do
  admin_status="$(compose --profile ops run --rm -T admin status 2>&1 || true)"
  if grep -Eq '^workers: [1-9]' <<<"$admin_status"; then break; fi
  [ "$SECONDS" -lt "$deadline" ] || die "no worker registered within 90 s (crawlx admin status): $(tail -n 5 <<<"$admin_status")"
  sleep 3
done

say "authorizing the gym network"
gym_id="$(compose ps -q gym)"
[ -n "$gym_id" ] || die "the gym container is not running"
gym_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$gym_id")"
[ -n "$gym_ip" ] || die "the gym container has no address"
record_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
record_body="$(python3 - "$gym_ip" <<'EOF'
import json, sys
print(json.dumps({
    "title": "compose smoke: the gym network",
    "authorizer": {
        "name": "Compose Smoke",
        "role": "operator",
        "organization": "crawlx CI",
        "contact": "ci@crawlx.invalid",
        "attestsOwnershipOrControl": True,
    },
    "origins": ["http://gym:8090"],
    "authorizedNetworks": [sys.argv[1] + "/32"],
    "profileCap": "authorized_security_test",
    "permittedRiskClasses": [],
    "approvalRequired": [],
    "testAccounts": [],
    "emergencyContact": "ci@crawlx.invalid",
    "evidence": {"kind": "compose_smoke", "artifactId": None, "digest": "00" * 32},
}))
EOF
)"
key_prefix="$(printf '%s' "$api_key" | cut -c9-16)"
compose exec -T postgres psql -U crawlx -d crawlx -v ON_ERROR_STOP=1 \
  -v rec="$record_id" -v body="$record_body" -v prefix="$key_prefix" -f - >/dev/null <<'SQL'
WITH k AS (
    SELECT tenant_id, key_id, now() - interval '5 minutes' AS valid_from, now() + interval '1 day' AS valid_to
    FROM api_keys WHERE prefix = :'prefix'
)
-- the worker reads `body` as stored (no column merge, unlike the API), so the body is a complete
-- serialized AuthorizationRecord: every required field, identity, tenant, version and
-- window included. `POST /v1/crawls` refuses a record whose ownership was never verified, and this
-- row skips the verifying route, so `verified_at` is set here (the operator is the CI harness).
INSERT INTO authorization_records
    (record_id, tenant_id, version, body, body_digest, valid_from, valid_to, created_by, verified_at)
SELECT :'rec'::uuid, tenant_id, 1,
       :'body'::jsonb || jsonb_build_object('id', :'rec', 'tenant', tenant_id, 'version', 1,
                                            'validFrom', valid_from, 'validTo', valid_to),
       decode(repeat('00', 32), 'hex'), valid_from, valid_to, key_id, valid_from
FROM k;
SQL
[ "$(compose exec -T postgres psql -U crawlx -d crawlx -Atc \
  "SELECT count(*) FROM authorization_records WHERE record_id = '$record_id'")" = 1 ] \
  || die "the bootstrap key's tenant has no row to attach the authorization record to"

say "crawling the gym through POST /v1/crawls"
request="$(python3 - "$record_id" <<'EOF'
import json, sys
print(json.dumps({
    "seedUrl": "http://gym:8090/s1/",
    "mode": "static",
    "limits": {"urls": 5},
    "safety": {"allowPrivateNetworks": True, "authorizationRecordRef": sys.argv[1]},
}))
EOF
)"
created="$workdir/created.json"
status="$(curl -sS --max-time 30 -o "$created" -w '%{http_code}' -X POST "$base/v1/crawls" \
  -H "authorization: Bearer $api_key" -H 'content-type: application/json' -d "$request")"
case "$status" in 200 | 201 | 202) ;; *) die "crawl creation answered $status: $(cat "$created")" ;; esac
run_id="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["id"])' "$created")"

deadline=$((SECONDS + TIMEOUT))
run_status=""
until [ "$run_status" = completed ] || [ "$run_status" = failed ] || [ "$run_status" = cancelled ]; do
  [ "$SECONDS" -lt "$deadline" ] || die "crawl $run_id did not finish within ${TIMEOUT}s (last status: ${run_status:-none})"
  sleep 2
  run_status="$(curl -fsS --max-time 10 -H "authorization: Bearer $api_key" "$base/v1/crawls/$run_id" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["status"])')"
done
[ "$run_status" = completed ] || die "crawl $run_id ended as $run_status"

pages="$workdir/pages.json"
curl -fsS --max-time 30 -H "authorization: Bearer $api_key" "$base/v1/crawls/$run_id/pages?include=markdown" >"$pages"
python3 - "$pages" <<'EOF' || die "the crawl returned no page with markdown"
import json, sys
doc = json.load(open(sys.argv[1]))
items = doc.get("data") or doc.get("pages") or doc.get("items") or []
pages = [p for p in items if "gym:8090" in json.dumps(p.get("url") or p.get("metadata") or {})]
assert pages, f"no gym page in {sorted(doc)}"
with_markdown = [p for p in pages if (p.get("markdown") or "").strip()]
assert with_markdown, "pages carry no markdown: the API cannot read the worker's artifacts"
print(f"ok: {len(pages)} pages, {len(with_markdown)} with markdown")
EOF
say "compose smoke: ok"
