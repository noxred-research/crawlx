#!/usr/bin/env bash
# Fetches the Chrome for Testing build pinned in chromium-pin.toml and prints the
# absolute path of its `chrome` binary on stdout, so callers can
#   CRAWLX_CHROMIUM_PATH=$(ci/fetch-chromium.sh)
# Everything else goes to stderr.
#
# The archive is downloaded to .cache/chromium/<version>/ (override: CRAWLX_CHROMIUM_CACHE),
# verified against the pinned sha256 before it is unpacked, and a `.sha256` stamp records the
# verified digest so later runs skip the network. A digest mismatch is fatal and leaves no
# unpacked tree behind.
#
#   ci/fetch-chromium.sh                download if needed, print the binary path
#   ci/fetch-chromium.sh --check-only   report the cache state; never touch the network
set -euo pipefail
cd "$(dirname "$0")/.."

check_only=0
case "${1:-}" in
  "") ;;
  --check-only) check_only=1 ;;
  *) echo "usage: $0 [--check-only]" >&2; exit 2 ;;
esac

# version<TAB>url<TAB>sha256 from the pin; python keeps the parsing identical to lint-deps.sh.
IFS=$'\t' read -r version url sha256 < <(python3 - <<'PY'
import sys, tomllib
pin = tomllib.load(open("chromium-pin.toml", "rb"))["chromium"]
for key in ("version", "download_url", "sha256"):
    if not pin.get(key):
        print(f"chromium-pin.toml: chromium.{key} is missing or empty", file=sys.stderr)
        sys.exit(1)
if len(pin["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in pin["sha256"].lower()):
    print("chromium-pin.toml: chromium.sha256 is not a 64-character hex digest", file=sys.stderr)
    sys.exit(1)
print("\t".join((pin["version"], pin["download_url"], pin["sha256"].lower())))
PY
)

cache_root="${CRAWLX_CHROMIUM_CACHE:-.cache/chromium}"
mkdir -p "$cache_root"
cache_root="$(cd "$cache_root" && pwd -P)"
dir="$cache_root/$version"
stamp="$dir/.sha256"

find_binary() {
  # Chrome for Testing unpacks to chrome-linux64/chrome; accept any depth in case the layout moves.
  find "$dir" -type f -name chrome -perm -u+x -print -quit 2>/dev/null
}

cached_binary() {
  [[ -f "$stamp" ]] || return 1
  [[ "$(tr -d '[:space:]' < "$stamp")" == "$sha256" ]] || return 1
  local bin
  bin="$(find_binary)"
  [[ -n "$bin" ]] || return 1
  printf '%s\n' "$bin"
}

if bin="$(cached_binary)"; then
  echo "fetch-chromium: cached $version at $bin (sha256 verified)" >&2
  printf '%s\n' "$bin"
  exit 0
fi

if (( check_only )); then
  if [[ -f "$stamp" ]]; then
    echo "fetch-chromium: $dir has stamp $(tr -d '[:space:]' < "$stamp") but the pin is $sha256 (or the binary is missing); run without --check-only to refresh" >&2
  else
    echo "fetch-chromium: $version is not cached under $cache_root" >&2
  fi
  exit 1
fi

command -v curl >/dev/null || { echo "fetch-chromium: curl is required" >&2; exit 1; }
command -v unzip >/dev/null || { echo "fetch-chromium: unzip is required" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "fetch-chromium: sha256sum is required" >&2; exit 1; }

tmp="$(mktemp -d "$cache_root/.download.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

echo "fetch-chromium: downloading $version from $url" >&2
curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/chrome.zip" "$url"

# Never unpack an archive whose digest is not the pinned one.
if ! (cd "$tmp" && echo "$sha256  chrome.zip" | sha256sum -c --quiet - >&2); then
  echo "fetch-chromium: sha256 mismatch for $url" >&2
  echo "fetch-chromium:   expected $sha256" >&2
  echo "fetch-chromium:   actual   $(sha256sum "$tmp/chrome.zip" | cut -d' ' -f1)" >&2
  echo "fetch-chromium: refusing to unpack; fix chromium-pin.toml or the mirror" >&2
  exit 1
fi

rm -rf "$dir"
mkdir -p "$tmp/unpacked"
unzip -q "$tmp/chrome.zip" -d "$tmp/unpacked"
chrome="$(find "$tmp/unpacked" -type f -name chrome -print -quit)"
if [[ -z "$chrome" ]]; then
  echo "fetch-chromium: archive has no 'chrome' binary" >&2
  exit 1
fi
chmod u+x "$chrome"
mv "$tmp/unpacked" "$dir"
printf '%s\n' "$sha256" > "$stamp"

bin="$(find_binary)"
if [[ -z "$bin" ]]; then
  echo "fetch-chromium: unpacked tree under $dir has no executable 'chrome'" >&2
  exit 1
fi
echo "fetch-chromium: installed $version at $bin" >&2
printf '%s\n' "$bin"
