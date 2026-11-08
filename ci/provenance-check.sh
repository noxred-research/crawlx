#!/usr/bin/env bash
# Clean-room provenance scan.
#
# Fails when a file under crates/ contains
#   * an AGPL license header or Firecrawl copyright line (R1: no AGPL source, copied or
#     translated);
#   * a Firecrawl-internal identifier from the denylist below on a non-comment line (a
#     translated module keeps its names; comments may describe behavior);
#   * the word "firecrawl" outside the places that legitimately name the compatibility
#     surface: paths containing `compat` or `differential`, test files, `openapi.rs`, the
#     `/compat/firecrawl` mount path, and comments (R8: factual "Firecrawl-compatible").
# The token-shingle similarity job against the pinned AGPL tree (R4) runs in the nightly
# `differential-nightly` job because it needs the upstream checkout; this scan is the PR gate.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# 1. License headers and copyright lines.
if grep -rnIE 'GNU Affero|AGPL-3\.0|Affero General Public|SPDX-License-Identifier: *AGPL|Copyright .*(Mendable|Sideguide|Firecrawl)' crates/ --include='*.rs' --include='*.toml' --include='*.sql' --include='*.md'; then
  echo "provenance: AGPL license header or Firecrawl copyright found under crates/" >&2
  fail=1
fi

# 2. Firecrawl-internal identifiers (word-bounded, non-comment lines only).
DENY='scrapeURL|WebCrawler|NuQ|nuq|scrape-worker|addScrapeJob|getScrapeQueue|crawlToCrawler|StoredCrawl|lockURL|finishCrawl|scrapeQueue|SCRAPE_HTTP_ERROR|BLOCKLISTED_URL|supabase'
hits=$(grep -rnIE "\\b($DENY)\\b" crates/ --include='*.rs' | grep -vE '^[^:]+:[0-9]+:\s*//' || true)
if [[ -n "$hits" ]]; then
  echo "$hits"
  echo "provenance: Firecrawl-internal identifier on a non-comment line" >&2
  fail=1
fi

# 3. "firecrawl" outside the compatibility surface. `admin.rs`/`admin_ops.rs` carry the
#    strangler flag (`tenants.engine = crawlx|firecrawl|shadow`), a routing value.
#    The surface extends beyond `compat*` paths: the scrape service and Firecrawl
#    document/metadata shapes (`scrape_service*`, `scrape/`, `scrape.rs`, `firecrawl_meta.rs`,
#    `diff.rs`), the facade's webhook payloads and `fc-` keys (`webhooks.rs`, `auth.rs`,
#    `config.rs`, `lib.rs`), the intel endpoints (`intel/`), the MCP server (`mcp*`), the
#    `/parse` HTML path and the OpenAI-compatible client naming the `firecrawl` tool set;
#    `ops.rs`/`config_check.rs` carry the `--firecrawl-keys` flag and its env name; `robots.rs`
#    and `url_plane.rs` name the public `FirecrawlAgent` robots product token (an alias the
#    facade honours so sites' robots rules for Firecrawl apply to facade runs); the `d2` gym
#    fixture serves a robots.txt with that group so the differential exercises it;
#    `migration_inspect.rs` names Firecrawl as one `crawlx source-import` dialect (the
#    upstream version and request-field mapping a user migrates from).
#    Each is a wire-shape or naming reference; checks 1 and 2 still apply to every file.
SURFACE='compat|differential|scrape_service|/scrape/|scrape\.rs|firecrawl_meta\.rs|diff\.rs|webhooks\.rs|auth\.rs|intel/|/mcp|parse/html\.rs|llm/openai\.rs|openapi_schemas/|policy/src/robots\.rs|worker/src/url_plane\.rs|gym/fixtures/d2\.rs|worker/src/robots_gate\.rs|cli/src/migration_inspect\.rs'
hits=$(grep -rnIi 'firecrawl' crates/ --include='*.rs' \
  | grep -vE "^[^:]*($SURFACE)[^:]*:" \
  | grep -vE '^[^:]*/tests/[^:]*:' \
  | grep -vE '^[^:]*(openapi|admin|admin_ops|config|config_check|ops|lib)\.rs:' \
  | grep -vE '^[^:]+:[0-9]+:\s*//' \
  | grep -v '/compat/firecrawl' || true)
if [[ -n "$hits" ]]; then
  echo "$hits"
  echo "provenance: 'firecrawl' outside compat/differential/tests/openapi/comments" >&2
  fail=1
fi

if [[ $fail -eq 0 ]]; then
  echo "provenance: ok"
fi
exit $fail
