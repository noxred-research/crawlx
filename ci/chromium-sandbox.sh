#!/usr/bin/env bash
# Lets the pinned Chromium start with its sandbox ON on a GitHub-hosted runner, and proves it.
#
# Ubuntu 24.04 runners restrict unprivileged user namespaces through AppArmor
# (kernel.apparmor_restrict_unprivileged_userns=1). Chrome for Testing has no AppArmor
# profile, so its sandbox cannot start ("No usable sandbox!") and every browser launch fails.
# crawlx never runs Chromium with --no-sandbox outside an explicit CI opt-in; instead of
# opting in, this script lifts the restriction for the job and then launches the binary
# named by CRAWLX_CHROMIUM_PATH exactly as the harness does, without --no-sandbox. A launch
# that still fails stops the job here with Chromium's own message rather than surfacing later
# as an unexplained FatalError run or "no proposals reached the kernel".
#
#   CRAWLX_CHROMIUM_PATH=$(ci/fetch-chromium.sh) ci/chromium-sandbox.sh
set -euo pipefail

chrome="${CRAWLX_CHROMIUM_PATH:?set CRAWLX_CHROMIUM_PATH (ci/fetch-chromium.sh prints it)}"

restrict=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
if [ -e "$restrict" ] && [ "$(cat "$restrict")" != 0 ]; then
  echo "unprivileged user namespaces are restricted by AppArmor; lifting that for this job" >&2
  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >&2
fi

profile="$(mktemp -d)"
trap 'rm -rf "$profile"' EXIT
if ! output="$("$chrome" --headless=new --disable-gpu --user-data-dir="$profile" --dump-dom about:blank 2>&1)"; then
  printf '%s\n' "$output" >&2
  echo "error: $chrome cannot start with its sandbox enabled on this runner" >&2
  exit 1
fi
echo "sandboxed launch ok: $("$chrome" --version)" >&2
