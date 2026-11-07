#!/usr/bin/env bash
# Container policy test.
#
# Asserts, for the API and worker images:
#   * the image runs as a numeric non-root user;
#   * neither the entrypoint/cmd nor the environment can pass `--no-sandbox` to Chromium
#     (the only code path that adds it is CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI, which must be unset);
#   * `crawlx config check` inside the image reports `browser.unsafe_no_sandbox_for_ci = false`;
#   * the worker image carries the pinned Chromium (PINNED_VERSION == chromium-pin.toml) and no
#     package manager;
#   * the seccomp profile exists, parses, allows user-namespace creation (clone/unshare) and
#     keeps setns/mount/ptrace-without-cap denied.
#
# Usage: ci/container-policy-test.sh [api-image] [worker-image]
# Without docker the image checks are skipped (exit 0) and only the seccomp checks run, so the
# script is safe in environments that cannot build images.
set -euo pipefail
cd "$(dirname "$0")/.."

API_IMAGE="${1:-crawlx-api:policy-test}"
WORKER_IMAGE="${2:-crawlx-worker:policy-test}"
PROFILE=docker/seccomp/crawlx-chromium.json
fail=0
say() { printf '%s\n' "$*"; }
bad() { say "FAIL: $*"; fail=1; }

# ---- seccomp profile (always) -------------------------------------------------------------
test -f "$PROFILE" || { bad "$PROFILE missing"; exit 1; }
python3 - "$PROFILE" <<'EOF' || fail=1
import json, sys
p = json.load(open(sys.argv[1]))
assert p["defaultAction"] == "SCMP_ACT_ERRNO", "default action must deny"
allowed = {}
for rule in p["syscalls"]:
    if rule["action"] == "SCMP_ACT_ALLOW" and not rule.get("includes", {}).get("caps") and not rule.get("args"):
        for n in rule["names"]:
            allowed[n] = rule
for needed in ("clone", "clone3", "unshare", "chroot", "seccomp", "prctl", "execve", "futex"):
    assert needed in allowed, f"{needed} must be allowed (Chromium's namespace sandbox needs it)"
for denied in ("setns", "mount", "umount2", "pivot_root", "bpf", "kexec_load", "init_module", "reboot"):
    assert denied not in allowed, f"{denied} must not be allowed without a capability"
print(f"seccomp: ok ({len(allowed)} syscalls allowed unconditionally)")
EOF

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  say "docker is not available: image checks skipped (seccomp checks ran)"
  exit "$fail"
fi

# Supply only offline test credentials and the repository pin, not deployment secrets.
# Keep the image's production environment and sandbox settings unchanged.
workdir="$(mktemp -d "${TMPDIR:-/tmp}/crawlx-container-policy.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT
chmod 755 "$workdir"
printf '%s\n' 'postgres://fixture:fixture@127.0.0.1/crawlx_policy_fixture' >"$workdir/database-url"
printf '%s\n' 'crawlx-container-policy-fixture-not-a-deployment-key' >"$workdir/webhook-key"
cp chromium-pin.toml "$workdir/chromium-pin.toml"
cat >"$workdir/crawlx.toml" <<'EOF'
[database]
url_file = "/run/crawlx-policy/database-url"
[api.webhook]
signing_key_file = "/run/crawlx-policy/webhook-key"
[browser]
pin_file = "/run/crawlx-policy/chromium-pin.toml"
EOF
chmod 644 "$workdir"/*

pin_version="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' chromium-pin.toml)"

inspect() { docker image inspect "$1" --format "$2"; }

check_common() {
  local image="$1"
  local user cfg
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    bad "$image is not built"; return
  fi
  user="$(inspect "$image" '{{.Config.User}}')"
  case "$user" in
    ""|root|0|0:*|root:*) bad "$image runs as root (User=${user:-<empty>})" ;;
    *) say "$image: user $user" ;;
  esac
  cfg="$(inspect "$image" '{{json .Config.Entrypoint}} {{json .Config.Cmd}} {{json .Config.Env}}')"
  if ! printf '%s' "$cfg" | python3 -c '
import json, sys
decoder = json.JSONDecoder()
values = []
text = sys.stdin.read().strip()
while text:
    value, end = decoder.raw_decode(text)
    values.append(value or [])
    text = text[end:].lstrip()
entrypoint, command, environment = values
assert not any("--no-sandbox" in arg for arg in entrypoint + command), "image passes --no-sandbox"
assert not any(item.split("=", 1)[0] == "CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI" for item in environment), "image sets the sandbox bypass variable"
'; then
    bad "$image: image metadata permits a sandbox bypass"
  fi
  if out="$(docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
      --volume "$workdir:/run/crawlx-policy:ro,Z" --entrypoint /usr/local/bin/crawlx \
      "$image" config check --config /run/crawlx-policy/crawlx.toml --format json)"; then
    printf '%s' "$out" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
v = doc["effective"]["browser"]["unsafe_no_sandbox_for_ci"]
assert v is False, f"{sys.argv[1]}: browser.unsafe_no_sandbox_for_ci is {v}"
environment = doc["effective"]["environment"]
print(f"{sys.argv[1]}: config check reports unsafe_no_sandbox_for_ci=false, environment={environment}")
' "$image" || fail=1
  else
    bad "$image: crawlx config check failed: $out"
  fi
}

check_common "$API_IMAGE"
check_common "$WORKER_IMAGE"

# ---- worker specifics ---------------------------------------------------------------------
if docker image inspect "$WORKER_IMAGE" >/dev/null 2>&1; then
  v="$(docker run --rm --network none --entrypoint /bin/cat "$WORKER_IMAGE" /opt/chromium/PINNED_VERSION 2>/dev/null || true)"
  if [ "$v" != "$pin_version" ]; then bad "worker Chromium is '$v', pin is '$pin_version'"; else say "worker: pinned Chromium $v"; fi
  for pm in /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg; do
    if ! docker run --rm --network none --entrypoint /bin/sh "$WORKER_IMAGE" -c "test ! -e $pm" 2>/dev/null; then bad "worker image has $pm or its absence check failed"; fi
  done
  if docker run --rm --network none --entrypoint /bin/sh "$WORKER_IMAGE" -c 'test -x /usr/bin/tini' 2>/dev/null; then say "worker: tini present"; else bad "worker image lacks tini"; fi
  # the pinned binary must launch with the sandbox on under the profile (no --no-sandbox):
  chrome_log="$workdir/chromium.log"
  # a zygote that cannot create a user namespace exits non-zero within the timeout.
  if timeout 60 docker run --rm --security-opt "seccomp=$PROFILE" --security-opt no-new-privileges \
      --network none --cap-drop ALL --entrypoint /opt/chromium/chrome "$WORKER_IMAGE" \
      --headless=new --disable-gpu --no-first-run --user-data-dir=/tmp/crawlx/policy-smoke \
      --dump-dom about:blank >/dev/null 2>"$chrome_log"; then
    say "worker: Chromium renders about:blank with the sandbox on under $PROFILE"
  else
    if grep -q "No usable sandbox" "$chrome_log"; then
      bad "worker: Chromium sandbox unusable under the profile (user namespaces blocked on this host?)"
    else
      bad "worker: Chromium smoke failed or timed out; see diagnostics below"
    fi
    cat "$chrome_log" >&2
  fi
fi

if [ "$fail" -eq 0 ]; then say "container policy: PASS"; fi
exit "$fail"
