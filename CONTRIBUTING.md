# Contributing to crawlx

Thank you for considering a contribution. This guide covers how the project is organized,
what a change must satisfy, and how a pull request is reviewed.

By contributing you agree that your contribution is licensed under the project license,
[GNU AGPL version 3 only](LICENSE) (`AGPL-3.0-only`). There is no contributor license
agreement and no DCO sign-off requirement. Do not submit code you do not have the right to
license under the AGPL, and do not copy code from projects whose licenses are incompatible
(see [clean-room rules](#clean-room-rules-for-the-firecrawl-compatibility-layer)).

Security vulnerabilities are **not** reported through issues or pull requests; follow
[SECURITY.md](SECURITY.md). Everyone taking part in the project is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Choose your path

| If you want to | Start here |
| --- | --- |
| Report a bug or request a feature | Open an issue with the matching form; search existing issues first |
| Ask how to use or deploy crawlx | The [docs](docs/README.md), then the question form |
| Fix a typo or improve documentation | A pull request against `docs/` or the README; no issue needed |
| Change crawler behavior | Open an issue first, then follow the [contribution flow](#contribution-flow) |
| Pick something to work on | The [roadmap](docs/roadmap.md) |
| Run the crawler locally to develop | [Development setup](#development-setup) and the [walkthrough](docs/walkthrough.md) |
| Operate or deploy crawlx | [Operations](docs/ops/README.md) and the [runbooks](docs/ops/runbooks.md) |

## Where to start

- Read the [documentation index](docs/README.md), in particular the
  [architecture](docs/design/architecture.md) and the [safety model](docs/design/safety-model.md).
- Crate boundaries are enforced: the allowed dependency edges between workspace crates are in
  [`ci/layering.toml`](ci/layering.toml) and are checked by `ci/lint-deps.sh`.
- Open an issue before starting a large change so the approach can be agreed first. Small fixes
  and documentation corrections can go straight to a pull request.

## Development setup

- Rust toolchain: the version in [`rust-toolchain.toml`](rust-toolchain.toml); `rustup` installs it
  automatically.
- Build: `cargo build --workspace`.
- PostgreSQL tests: set `CRAWLX_TEST_DATABASE_URL` (for example
  `postgres://crawlx@127.0.0.1:54329/crawlx_test`). These tests skip when it is unset.
- Browser tests: set `CRAWLX_CHROMIUM_PATH` to a Chromium binary. `export
  CRAWLX_CHROMIUM_PATH=$(ci/fetch-chromium.sh)` downloads the pinned Chrome for Testing build
  and verifies its checksum. These tests skip when the variable is unset.
  `CRAWLX_ALLOW_UNPINNED=1` lets a differing Chromium build run and records `pinned = false`.

## Checks to run before opening a pull request

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
ci/lint-deps.sh
ci/lint-public.sh
```

Also run `ci/provenance-check.sh` when you touch `crawlx-url`, `crawlx-policy`,
`crawlx-extract`, the `crawlx-api` compatibility routes or the Firecrawl differential harness.

## Coding standards

All Rust follows the workspace lints in [`Cargo.toml`](Cargo.toml), [`clippy.toml`](clippy.toml) and
[`rustfmt.toml`](rustfmt.toml). On top of those:

- **No `unsafe`.** The workspace sets `unsafe_code = "forbid"`. Do not add exceptions.
- **Errors.** Library crates use `thiserror` with typed error enums, lowercase messages without
  trailing punctuation, `#[source]` chains, and an `# Errors` section on public fallible
  functions. `anyhow` is allowed only in `crawlx-cli`. No `unwrap`, `panic!`, `dbg!` or `todo!`
  in non-test code; `expect` needs a justification.
- **Ownership.** Prefer borrowing to cloning, `&[T]` to `&Vec<T>`, and `&str` to `&String`. Avoid
  `clone()` to appease the borrow checker.
- **Async.** Never hold a lock across `.await`. Channels are bounded. Long-lived tasks take a
  cancellation token and are spawned through a `JoinSet` or the worker `Supervisor`. Blocking or
  CPU-heavy work goes through `spawn_blocking` or the worker CPU pool.
- **Numeric safety.** Use `try_from` for narrowing conversions and explicit
  `checked_`/`saturating_`/`wrapping_` arithmetic where overflow is possible.
- **Collections on decision and hashing paths.** Use `BTreeMap`/`BTreeSet` or sorted `Vec`, not
  `HashMap`/`HashSet`, wherever iteration order can reach a decision, a hash or a persisted
  ordering. A lookup-only hash map that is never iterated may use `#[allow]` with a reason.
- **Public API.** Document every public item and add a `//!` module comment. Mark builders and
  result-returning constructors `#[must_use]`. Mark public enums and structs that will grow
  `#[non_exhaustive]`.
- **Logging.** Use structured `tracing` fields. Never log secrets, credentials, cookies, tokens
  or page content; see [data and secrets](docs/design/data-and-secrets.md).
- **Trait objects.** `async_trait` is used for the dyn-compatible traits in `crawlx-core`
  (`BrowserContext`, repositories) because they must be object-safe. `panic = "unwind"` stays in
  release builds so the worker supervisor can turn task panics into typed failures. Document any
  further deliberate exception where it occurs.

## Determinism

Crawls must be reproducible from a seed.

- No `rand::thread_rng` and no `rand::random`; both are disallowed by clippy. Derive every RNG from
  `crawlx_core::seed::CrawlSeed`.
- `crawlx-state`, `crawlx-graph`, `crawlx-strategies` and `crawlx-forms` never read wall time;
  callers pass timestamps in.
- Hashes and orderings that feed decisions use stable, versioned encodings.

## Tests

- Tests are deterministic and use no external network. Use loopback fixtures, `wiremock`, or the
  CrawlerGym fixture server from `crawlx-bench`.
- PostgreSQL and Chromium tests read `CRAWLX_TEST_DATABASE_URL` and `CRAWLX_CHROMIUM_PATH` and skip
  when those are absent.
- Test modules start with
  `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`.
- A behavior change needs a test that fails without it. A bug fix needs a regression test.
- Do not put provider-format token literals (cloud, payment, chat or source-hosting API keys) in
  tests. Secret-detector fixtures build the value at runtime from split parts, with a comment that
  it is a synthetic canary, so secret scanners do not flag the repository.

## Documentation

Update the relevant page under [`docs/`](docs/README.md) and add a [`CHANGELOG.md`](CHANGELOG.md)
entry under `[Unreleased]` for user-visible behavior, configuration, API or schema changes. The
generated risk matrix in [`docs/design/safety-matrix.md`](docs/design/safety-matrix.md) is
produced by `crates/crawlx-safety/tests/matrix_doc.rs`; regenerate it with
`CRAWLX_BLESS=1 cargo test -p crawlx-safety --test matrix_doc` after a profile change and do not
edit it by hand.

## Database migrations

Migrations are forward-only and run by `crawlx migrate`. Never edit a migration that has been
released; add a new one. Follow expand-then-contract: a release ships only backward-compatible
changes, and removals ship at least one release later.

## Clean-room rules for the Firecrawl compatibility layer

crawlx offers a Firecrawl-compatible API facade. Firecrawl's server is AGPL-licensed, and this
project must not become a derivative of it. Changes that touch `crawlx-url`, `crawlx-policy`,
`crawlx-extract`, the `crawlx-api` compatibility routes or the differential harness must follow
the checklist in the pull request template: implement behavior from public documentation,
black-box observation, the MIT-licensed SDK types and RFCs; never copy or mechanically translate
Firecrawl server source; do not copy its test fixtures; keep any self-hosted Firecrawl used for
comparison inside `bench/differential/`; and add no AGPL/GPL-family dependency.

## Contribution flow

1. Fork the repository and create a branch from `main` whose name describes the change.
2. Reproduce the current behavior before editing, and add or update tests for the successful
   path and the relevant failures.
3. Make focused commits. A pull request should do one thing, with the smallest change that
   satisfies the tests.
4. Run the [checks](#checks-to-run-before-opening-a-pull-request) locally.
5. Open a pull request and fill in the template: why the change is needed, what behavior
   changed, the exact checks you ran, and any safety, configuration, migration or deployment
   impact.
6. A code owner reviews the pull request. Expect requests for tests, documentation, or a
   narrower scope. Do not bypass a failing check; fix it, or describe an unrelated failure
   precisely enough for a reviewer to reproduce it.

Keep credentials, local environment files, raw user data and generated secrets out of commits
and pull requests.

### Continuous integration for external pull requests

GitHub Actions workflows run only for pull requests from code owners. For a pull request from
a fork, a maintainer runs the checks above (and the relevant suites with PostgreSQL, Redis and
Chromium) and reports the result on the pull request. A green local run from you speeds this up;
it does not replace the maintainer's run. Dependency-update pull requests are handled the same way.

## Getting help

- Questions: the [docs](docs/README.md), then the question issue form.
- Bugs and feature ideas: the matching issue form.
- Security: [SECURITY.md](SECURITY.md), never a public issue.
- Conduct concerns: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Conduct

Be respectful and assume good faith. Discussions stay technical. Maintainers may close issues or
pull requests that are abusive, off-topic or unsafe to run. The full policy is in the
[Code of Conduct](CODE_OF_CONDUCT.md).
