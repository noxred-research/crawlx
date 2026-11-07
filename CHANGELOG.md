# Changelog

All notable changes to crawlx are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
project is pre-1.0; minor versions may contain breaking changes.

## [Unreleased]

## [0.1.0] - 2026-11-07

First public source release. Distribution is the GitHub repository and the tagged
source archive; no binaries, container images or crates.io packages are published.
Production qualification is still in progress.

### Added

- A 21-crate Rust workspace with public design documentation (`docs/design/`) and
  enforced crate layering (`ci/layering.toml`).
- URL and content plane: scope and robots admission, URL canonicalization and
  query-parameter classification, static fetching with bounded acquisition (attempts,
  requests, bytes, deadline), content extraction to Markdown, metadata and links, and
  Firecrawl-compatible scrape, crawl, map, search, extract and parse behavior over a
  `/compat/firecrawl/v2` facade.
- Bounded source discovery: HTML, RSS/Atom/JSON Feed, sitemaps, category pages and
  opt-in conventional paths and external providers, with offline development replay.
- Katana-derived crawl options: scope fields, strategies, similarity filters, rate
  limits, custom field extraction, secret detection, JavaScript endpoint mining
  (`off|regex|ast|both`) and templated, JSONL and wordlist output.
- Native response cache modes (`read_write`, `bypass`, `disabled`, `read_only`,
  `write_only`), validator checks, and `crawlx replay-response`.
- Scoped adaptive extraction descriptors with tenant isolation and ZDR-aware retention.
- Browser plane on a pinned Chromium (CDP): accessibility-tree discovery, versioned
  semantic element identity, observation epochs, reversible state clustering, a
  probabilistic enablement graph, interaction strategies, form handling, and an action
  intent journal with unknown-outcome reconciliation after crashes.
- Independent hard safety kernel with the `read_only`, `test_environment` and
  `authorized_security_test` profiles, SSRF and egress controls, and authorization
  records with a create, verify, revoke and offline-sign lifecycle.
- Zero-data-retention mode and secret boundaries, including redaction in
  logs, traffic metadata and exports, and operator-controlled captcha solver key
  references.
- Persistence on PostgreSQL (migrations through `0044_artifact_custody_trigger_schema.sql`,
  tenant row-level security) and filesystem or S3-compatible artifact storage.
- Encrypted artifact custody: retained Content and Sensitive artifacts are
  sealed under per-artifact data keys wrapped by AWS KMS (`CRAWLX_ARTIFACT_KMS_KEY_ID`) or
  an operator key file (`CRAWLX_ARTIFACT_KEY_FILE`), and published only after an
  epoch-checked recheck against the run-wide secret registry. CAPTCHA tokens are
  registered run-wide before delivery to the page.
- Process-wide HTML parse-memory budget (`CRAWLX_PARSE_MEMORY_BYTES`, default 4 GiB for the
  worker): every parse charges `input bytes x 500` without waiting; the factor is the
  measured worst case (364 bytes per input byte) plus margin, enforced by
  `crawlx-extract/tests/parse_memory_ceiling.rs`. Worker and API containers carry explicit
  memory limits.
- Scheduler and worker processes with leases, session actors, checkpoints and
  `crawlx worker --recover`; REST/SSE API with OpenAPI schemas and API-key scopes.
- `crawlx` command-line interface: `crawl`, `serve`, `worker`, `migrate`, `inspect`,
  `replay`, `replay-response`, `extract`, `authz`, `mcp` (Firecrawl MCP tools over
  stdio), `healthcheck` and configuration checks.
- Optional ONNX ranker support (`crawlx-model`, `onnx` feature), a typed-decision HTTP
  adapter for an external decision service, language identification, and
  OpenTelemetry/Prometheus telemetry.
- Test and benchmark infrastructure: CrawlerGym fixtures, chaos and fault-injection
  suites, fuzz targets, a Firecrawl differential harness, a Playwright/Patchright
  actionability oracle, and milestone gates.
- Docker, Docker Compose, Helm, Kubernetes and systemd deployment files, alert rules
  and operations runbooks.

### Security

- Dependencies patched for seven RustSec advisories without suppressions (calamine,
  ctutils, Hickory DNS, quick-xml, rustls-webpki, webpki-roots); Hickory is minimally
  vendored to keep negative-response failover behavior.

### Known limitations

- Strategies gated by milestone gate G1 (`state_novelty`, `enablement`) and
  `dynamic.system1Mode` values above `shadow` (G3) are disabled unless the operator
  provisions gate keys (`CRAWLX_GATE_KEYS_FILE`) and signed gate files. The gates are
  unchanged and fail closed. The default `dynamic.strategies` is `interaction_bfs` and
  `event_driven`, so a dynamic crawl runs without gate keys; a request that lists a
  G1-gated strategy without G1 is rejected at admission (`profile_conflict`, before a run
  is created), not mid-run.
- HTML parsing memory is bounded by a measured per-input-byte ceiling (500 bytes charged
  per input byte) and a process parse budget, not by fully fallible allocation. At the
  default 4 GiB budget (`CRAWLX_PARSE_MEMORY_BYTES`) the largest HTML a worker parses is
  about 8 MiB; larger pages fail terminally. Raise the budget together with the container
  memory limit.
- Encrypted artifact custody: every Content and
  Sensitive artifact a worker retains is sealed before it reaches the object store and is
  published only if the run's secret registry did not change since the bytes were checked, so
  a CAPTCHA token registered while an upload is in flight can never be published or read
  back. The cutover fails closed where it is not yet fenced. Raw presigned object-store URLs
  are refused for sealed artifacts (the API serves decrypted bytes instead), retained browser
  profiles are unavailable, and the run-wide secret authority lives at most 24 hours per run
  with no mid-run renewal: after it expires, durable content writes of that run fail closed.
  The registry holds at most 256 values and 1 MiB per run; exceeding it fails CAPTCHA
  delivery closed. PostgreSQL workers need `CRAWLX_ARTIFACT_KMS_KEY_ID` or
  `CRAWLX_ARTIFACT_KEY_FILE` plus `CRAWLX_SECRET_REDIS_URL` (a persistence-free Redis); the
  API needs only the key provider. Secrets known at run start (request controls, role
  credentials, the solver key) keep their existing per-producer scans and are not registered
  run-wide. A local in-process `crawlx crawl` seals its artifacts under a process-lifetime key:
  its `pages/*.md`, `metadata.json` and `report.json` are the readable output, and the sealed
  objects under `artifacts/` are not readable after the process exits.
- Browser background traffic: the stock pinned Chromium (Chrome-for-Testing
  155.0.8059.84) attempts unsolicited Google background-service requests
  (`accounts.google.com`, `redirector.gvt1.com`, `content-autofill.googleapis.com`,
  `android.clients.google.com`). Where the run's egress policy excludes them (a bounded scope
  or an operator blocklist entry) the egress proxy denies each one before any connection and
  logs it, so no foreign host is dialed, but the attempts are not prevented.
  Zero-attempt isolation needs a patched, self-hosted Chromium (post-release; the source
  build exists under `ci/build-chromium.py`). See
  [data and secrets](docs/design/data-and-secrets.md#chromium-background-traffic).

[Unreleased]: https://github.com/noxred-research/crawlx/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/noxred-research/crawlx/releases/tag/v0.1.0
