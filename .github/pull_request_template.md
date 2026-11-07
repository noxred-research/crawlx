## Summary

<!-- What changes and why. Link the issue. -->

## Checks

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace` (tests added or updated for the change)
- [ ] `ci/lint-deps.sh` and `ci/provenance-check.sh`
- [ ] Docs and `CHANGELOG.md` updated for behavior, configuration, API or schema changes

## Safety impact

<!-- Does this change what the crawler may fetch, click, submit or store? -->

- [ ] No change to safety profiles, the safety kernel, egress/SSRF policy, robots handling,
      authorization records or rate limits.
- [ ] Or: the change is described above, `docs/design/safety-model.md` is updated, and tests
      cover both the allowed and the refused case.

## Secrets and data

- [ ] No secrets, credentials, tokens or real personal data in code, tests, fixtures or logs.
- [ ] Test fixtures that need provider-shaped tokens build them at runtime from split parts.
- [ ] No new logging of page content or credentials; ZDR and retention behavior unchanged, or
      documented in `docs/design/data-and-secrets.md`.

## Clean-room checklist (Firecrawl compatibility layer)

Required for every PR that touches `crawlx-url`, `crawlx-policy`, `crawlx-extract`,
`crawlx-api` (`compat` routes) or `crawlx-bench/src/differential`; tick N/A otherwise.

- [ ] **R1 Behavior, not code.** No Firecrawl AGPL source (`apps/api`, including
      `apps/api/native/`) was copied, mechanically translated or reproduced with renamed
      identifiers. The behavior implemented comes from documentation, black-box runs of the
      pinned commit, the MIT SDK types or the RFCs.
- [ ] **R2 Spec/implementation separation.** I did not open the AGPL file for the module I
      implemented in this PR during implementation, or this PR only adds test vectors.
- [ ] **R3 Provenance.** New differential corpus entries and `divergences.toml` entries record
      their source (documentation URL, black-box run id, SDK type or RFC). No AGPL source lines
      are quoted.
- [ ] **R5 Dependencies.** No AGPL/GPL-family dependency was added; the `firecrawl` SDK crate
      appears, if at all, only as a `dev-dependency` of the compat test crate.
- [ ] **R6 Test-service isolation.** Any Firecrawl self-host use stays in
      `bench/differential/` (unmodified pinned commit, separate containers, never shipped).
- [ ] **R7 Independent fixtures.** No Firecrawl test fixtures were copied; new fixtures are
      authored here or come from a permissively licensed source recorded in the manifest.
- [ ] **R8 Naming.** User-facing text says "Firecrawl-compatible" factually; no Firecrawl
      branding.
- [ ] N/A: this PR does not touch the compatibility boundary.
