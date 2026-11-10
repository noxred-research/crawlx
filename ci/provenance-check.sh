#!/usr/bin/env bash
# Clean-room provenance scan.
#
# Fails when a file under crates/ contains
#   * an AGPL license header or an upstream copyright line (R1: no AGPL source, copied or
#     translated);
#   * an upstream-internal identifier from the denylist below on a non-comment line (a
#     translated module keeps its names; comments may describe behavior);
#   * the upstream product name outside lines marked `wire-compat` (R8: names an external
#     client needs verbatim, such as headers, key prefixes and robots product tokens, keep
#     the exact string and carry the marker on the same line).
# The token-shingle similarity job against the pinned AGPL tree (R4) runs in the nightly
# `differential-nightly` job because it needs the upstream checkout; this scan is the PR gate.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# 1. License headers and copyright lines.
if grep -rnIE 'GNU Affero|AGPL-3\.0|Affero General Public|SPDX-License-Identifier: *AGPL|Copyright .*(Mendable|Sideguide|Firecrawl)' crates/ --include='*.rs' --include='*.toml' --include='*.sql' --include='*.md'; then # wire-compat: detection data (copyright holders of the upstream)
  echo "provenance: AGPL license header or upstream copyright found under crates/" >&2
  fail=1
fi

# 2. Upstream-internal identifiers (word-bounded, non-comment lines only).
DENY='scrapeURL|WebCrawler|NuQ|nuq|scrape-worker|addScrapeJob|getScrapeQueue|crawlToCrawler|StoredCrawl|lockURL|finishCrawl|scrapeQueue|SCRAPE_HTTP_ERROR|BLOCKLISTED_URL|supabase' # wire-compat: detection data (denylist of upstream-internal identifiers)
hits=$(grep -rnIE "\\b($DENY)\\b" crates/ --include='*.rs' | grep -vE '^[^:]+:[0-9]+:\s*//' || true)
if [[ -n "$hits" ]]; then
  echo "$hits"
  echo "provenance: upstream-internal identifier on a non-comment line" >&2
  fail=1
fi

# 3. The upstream product name outside marked wire strings. Every name an external client or
#    program needs verbatim (HTTP header names, the key prefix, robots product tokens, SDK
#    package names) keeps the exact string and carries the marker `wire-compat` on the same
#    line; all other prose, identifiers, routing values and file names are neutral. Checks 1
#    and 2 still apply to every file.
NAME='firecrawl' # wire-compat: detection data (the upstream product name)
hits=$(grep -rnIi "$NAME" crates/ --include='*.rs' | grep -v 'wire-compat' || true)
if [[ -n "$hits" ]]; then
  echo "$hits"
  echo "provenance: upstream product name outside lines marked wire-compat" >&2
  fail=1
fi

if [[ $fail -eq 0 ]]; then
  echo "provenance: ok"
fi
exit $fail
