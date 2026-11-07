#!/usr/bin/env bash
# Clean-room provenance: scan against the unmodified, pinned upstream checkout.
# FIRECRAWL_TREE is required; sources never enter the repository or report output.
# SHINGLE_THRESHOLD overrides the documented engineering default (40), not a legal finding.
# SHINGLE_MAX_DOC_FREQ overrides the idiom filter (default 5; 0 = off); see tools/provenance/shingle.py.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--self-test" && $# -eq 1 ]]; then
  exec python3 -B -m unittest discover -s tools/provenance/tests -v
fi
if [[ $# -ne 0 ]]; then
  echo "usage: ci/shingle-scan.sh [--self-test]" >&2
  exit 2
fi
: "${FIRECRAWL_TREE:?set FIRECRAWL_TREE to the pinned upstream checkout}"
FIRECRAWL_COMMIT="${FIRECRAWL_COMMIT:-c31e88c07afe941bfd8aebde61684eeba042abb5}"
actual=$(git -C "$FIRECRAWL_TREE" rev-parse HEAD)
if [[ "$actual" != "$FIRECRAWL_COMMIT" ]]; then
  echo "shingle-scan: upstream HEAD $actual does not match pin $FIRECRAWL_COMMIT" >&2
  exit 2
fi
exec python3 -B tools/provenance/shingle.py \
  --crawlx-tree crates --upstream-tree "$FIRECRAWL_TREE" \
  --threshold "${SHINGLE_THRESHOLD:-40}" --max-doc-freq "${SHINGLE_MAX_DOC_FREQ:-5}"
