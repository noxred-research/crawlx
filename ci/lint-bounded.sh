#!/usr/bin/env bash
# Cross-task communication uses bounded channels. Fails when any non-test Rust
# source under crates/ names `unbounded_channel` (tokio, futures or std flavours). Test code
# (`tests/` directories, `benches/`, `#[cfg(test)]` modules are not parsed; only whole test
# files are exempt) may use unbounded channels for harness plumbing.
set -euo pipefail
cd "$(dirname "$0")/.."
hits=$(grep -rn --include='*.rs' -E '\bunbounded(_channel)?\s*\(' crates \
  | grep -v -E '^crates/[^/]+/(tests|benches)/' \
  | grep -v -E '^\S+:\s*//' || true)
if [ -n "$hits" ]; then
  echo "unbounded channels are banned outside tests:"
  echo "$hits"
  exit 1
fi
echo "lint-bounded: ok"
