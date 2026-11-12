## crawlx vendored patch

This directory vendors the published `lru` 0.13.0 crate from crates.io (package SHA-256
`227748d55f2f0ab4735d87fd623798cb6b664512fe979705f829c9f81c934465`, the checksum the workspace
lockfile pinned before this directory was selected). The original MIT license stays in
`LICENSE`; the upstream readme is `README.upstream.md`. Registry cache markers are not vendored.
The workspace selects this directory through `[patch.crates-io]` for dependents that require
`lru ^0.13` (the pinned TLS-profile HTTP client, whose connection pool calls `iter_mut`).

This is a local backport, not an upstream release. Upstream 0.16.3 fixed `IterMut` creating a
`&mut K` to each key while the cache's key index still points at it, which violates the
aliasing rules (advisory GHSA-rhfx-m35p-ff5j). `IterMut::next` and `next_back` here now take a
shared reference to the key, exactly as upstream does; the item type was already `(&K, &mut V)`.
The dependent cannot move to an `lru` release with the fix without a newer toolchain than the
workspace pins. `iter_mut_keeps_keys_shared_and_values_mutable` in `src/lib.rs` covers the path.
