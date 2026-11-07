# Third-party notices

crawlx itself is licensed under [AGPL-3.0-only](LICENSE). This file lists third-party
material that is stored inside this repository: vendored Rust crates and embedded
resources. Their licenses are separate from the crawlx license and are not changed by it.

This inventory was compiled from the repository tree and each item's own metadata. It
is not legal advice.

## Vendored Rust crates

Both crates replace their crates.io counterparts through `[patch.crates-io]` in `Cargo.toml`
and are excluded from the workspace member list. Each carries local modifications,
summarized below.

| Directory | Crate | Version | License (from `Cargo.toml`) | Upstream | License files present |
| --- | --- | --- | --- | --- | --- |
| `vendor/hickory-resolver/` | `hickory-resolver` | 0.26.3 | `MIT OR Apache-2.0` | <https://github.com/hickory-dns/hickory-dns> | `LICENSE-MIT` (Copyright (c) 2015 The Hickory DNS Developers; Copyright (c) 2017 Google LLC.) and `LICENSE-APACHE` |
| `vendor/pdf-loader/lopdf-0.46.0/` | `lopdf` | 0.46.0 | `MIT` | <https://github.com/J-F-Liu/lopdf> | `LICENSE` (Copyright (c) 2016 Junfeng Liu) |

Notes:

- `hickory-resolver` is dual-licensed; either license may be chosen. Its Apache-2.0 text
  ships without a separate `NOTICE` file, and the vendored tree contains none.
- Local changes to `hickory-resolver` restore failover and TCP retry behavior on the
  security-fixed release; unsafe code is denied except in the two unchanged Apple and
  Android system-DNS modules.
- Local changes to `lopdf` add loader and content budgets. Only the patched crate is
  vendored; its upstream integration tests that need omitted assets are not part of
  the tree.

Findings: every vendored directory contains the license text(s) named by its
`Cargo.toml` `license` field. No missing license file was found.

## Embedded non-Rust resources

| Path | Material | License / terms | Notice |
| --- | --- | --- | --- |
| `crates/crawlx-cli/schemas/tei-p5-4.10.2.rng` | TEI P5 `tei_all` RELAX NG schema 4.10.2, unmodified, embedded for `crawlx extract` TEI validation | BSD-2-Clause (elected from the TEI Consortium's license options) | `crates/crawlx-cli/schemas/NOTICE` (full license text, source URL and SHA-256). The `xmllint`/libxml2 validator (MIT) is operator-installed and not redistributed. |
| `crates/crawlx-policy/data/public_suffix_list.dat` | Public Suffix List, version 2026-01-16, commit `944fb53321606f08740f04ef7c386f64df34ff76` | MPL-2.0 (stated in the file header) | The file header carries the license notice. Obtain the source from <https://publicsuffix.org/list/>. |
| `crates/crawlx-model/data/lid176-onnx-v1.json` | Provenance manifest for the fastText lid.176 language-identification model (ONNX conversion by Tigre Gotico Lda; original by Meta/Facebook Research), pinned by SHA-256 | Model weights: CC-BY-SA-3.0, independent of the crawlx source license | The manifest records source, revision, attribution and digests. The weights themselves are not stored in this repository; they are an operator-provisioned resource and keep their own license if distributed. |

The following data files are authored for this repository and are covered by the crawlx
license: `crates/crawlx-extract/data/blocklist.txt`,
`crates/crawlx-extract/data/technologies.json`,
`crates/crawlx-extract/data/secret_validators.json`,
`crates/crawlx-policy/data/cdn_hosts.txt` and
`crates/crawlx-browser/data/consent_block.txt`. They name third-party hosts and products
as data only and copy no third-party filter list or catalog.

Test fixtures under `crates/*/tests/fixtures/` and `crates/crawlx-bench/fixtures/` are
authored or generated for tests; `crates/crawlx-fetch/tests/fixtures/selfsigned.{crt,key}`
is a throwaway test certificate and key.

Search result for other notice files: outside `vendor/` and the TEI `NOTICE`, no
`NOTICE`, `LICENSE` or `COPYING` file exists under `crates/` or `docs/`. The only other
license files in a development working tree are the project `LICENSE` and a bundled
Chrome for Testing cache under `.cache/` (git-ignored; downloaded, not part of the source
release).

## Chromium patches

`ci/chromium-patches/` holds patch files for a locally built Chromium
(`ci/build-chromium.py`). Added files carry the Chromium Authors' BSD-style notice. The
`0004-bundled-hunspell-dictionaries.patch` file records license evidence for bundled
dictionaries (SCOWL and others, under GPL/LGPL/MPL terms). No Chromium binary is
distributed with a source release. Review those licenses before publishing any Chromium
build or container image that contains it.

## Cargo dependencies

Dependencies fetched from crates.io are not vendored, so their license texts are not
stored here. Their licenses are governed by [`deny.toml`](deny.toml), which allows only
the listed permissive licenses and is enforced in CI by `cargo deny check`. To produce
the current inventory for the locked dependency set, run:

```
cargo deny list
cargo about generate   # requires cargo-about and an about.hbs template
```

Neither output is committed. This file does not list individual dependencies.
