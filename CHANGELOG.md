# Changelog

All notable changes to crawlx are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
project is pre-1.0; minor versions may contain breaking changes.

## [Unreleased]

### Added

- Optional [ProxyX](https://github.com/noxred-research/proxyx) pool gateway as the upstream of the
  `basic` and `enhanced` proxy tiers (`[fetch.proxyx]`, `--fetch-proxyx-*`, `CRAWLX_FETCH_PROXYX_*`):
  a typed, locally validated username (kind, country, city, provider, ttl, rotation), one sticky
  exit identity per run (`sid` derived from the run id, separate per tier, `rotation = each` for a
  fresh identity per tunnel), `CONNECT`-only transport that tunnels plain `http://` targets too on
  both the fetch plane and the browser plane, the pool session id and exit IP recorded as connection
  evidence (`connection.proxyRoute = "proxyx_pool"`, `poolSession`, `poolExitIp`), typed gateway
  refusals (`proxy_refused` for terminal causes, `unreachable` for transient ones) and bounded,
  asynchronous block feedback to the control API (`429`, challenges, repeated `403`, resets; honors
  `Retry-After`; never blocks a fetch). The org key is an `env://` or `file://` reference or a
  literal, redacted everywhere; the gateway and control hosts stay under the egress policy. New
  metrics `crawlx.proxyx.block_signals` and `crawlx.proxyx.tunnel_refusals`.

### Changed: neutral names (breaking)

Features, identifiers, files, configuration and documentation now use neutral names. Every
integration keeps working; only exact strings that existing clients or services send or expect
(headers, the `fc-` key prefix, route shapes, MCP tool names, provider API fields) are unchanged.
Rename these in deployments and scripts:

| Area | Old | New |
|---|---|---|
| API mount | `/compat/<name>/v2` | `/compat/v2` |
| Prefixed keys | `compat.<name>Keys`, `--<name>-keys`, `CRAWLX_COMPAT_<NAME>_KEYS` | `compat.prefixedKeys`, `--compat-keys`, `CRAWLX_COMPAT_KEYS` |
| Tenant engine | `crawlx admin engine --set <name>` | `--set upstream` (migration `0045` rewrites stored rows) |
| LLM settings | the provider-named `*_BASE_URL` and `*_API_KEY` variables, `MODEL_NAME`, `MODEL_EMBEDDING_NAME`, the local model server's `*_BASE_URL` | `CRAWLX_LLM_BASE_URL`, `CRAWLX_LLM_API_KEY`, `CRAWLX_LLM_MODEL`, `CRAWLX_EMBEDDING_MODEL`, `CRAWLX_LOCAL_LLM_BASE_URL` |
| Transcription | the provider-named `*_TRANSCRIBE_ENDPOINT`, `TRANSCRIBE_MODEL_NAME` | `CRAWLX_TRANSCRIBE_ENDPOINT`, `CRAWLX_TRANSCRIBE_MODEL` |
| Search | provider values for the metasearch and hosted search backends; their `*_ENDPOINT`/`*_ENGINES`/`*_CATEGORIES`/`*_API_KEY`/`*_ENGINE` variables | `metasearch`, `serp`; `CRAWLX_SEARCH_ENDPOINT`, `CRAWLX_SEARCH_ENGINES`, `CRAWLX_SEARCH_CATEGORIES`, `CRAWLX_SEARCH_API_KEY`, `CRAWLX_SEARCH_API_ENGINE` |
| Captcha | provider value for the task-based solver | `task-api` |
| Compatibility flags | `--<name>-defaults` / config key | `--compat-defaults` / `compat-defaults`; default wordlist directory `field_wordlists` |
| Source import | product-named `source` ids | input-format ids: `python-spider`, `js-actor`, `py-actor`, `go-collector`, `compat-api`, `adaptive-py`, `llm-py`, `seedlist-batch`, `topology-stream`, `bean-config`, `browser-yaml`, `text-precision`, `news-article`, `surface-flags`; inventory row ids `TP-`, `NA-`, `SR-` |
| Request identity / pacing dialects | product-named values | `js_actor_3_18`, `py_actor_1_11`, `python_spider_2_19`, `go_collector_2_2`; `latency-target-v1`, `adaptive-concurrency-v1` |
| NLP capability | `punkt_model` | `sentence_model` |
| Discovery connectors | provider-named values | `news_search`, `trends_search`, `web_archive_index` |
| Delivery sinks | product-named `kind` values | `search_update`, `search_index`, `stream_rest_v2`, `queue_http_v1`, `object_json_upload` |
| Secrets | `aws-sm://` references | `cloud-sm://` |
| Object store | `CRAWLX_S3_SSE=aws_kms` | `cloud_kms` (`kms` and the S3 wire label stay accepted) |
| Differential harness | product-named flags, env variables and files | `--upstream`, `--upstream-origin`, `UPSTREAM_*`, `CRAWLX_UPSTREAM_URL`, `bench/differential/*upstream*` |

The extraction-import report no longer carries a `sourceUrl`. `ci/lint-public.sh` fails on
third-party product names outside the documented exceptions.

### Changed

- `EgressConfig::proxy_for` is replaced by `route_for` (a `TierRoute`: direct, URL or pool);
  `build_fetcher`, `build_fetcher_with_capture` and `serve_proxy` take the run id that keys the sticky
  identity; `ProxyRoutes` gains the `basic_pool` and `enhanced_pool` fields.

- Dependencies moved to rand 0.10 / rand_chacha 0.10, sqlx 0.9, redis 1.8, quick-xml 0.42,
  sha1/sha2 0.11 with hmac 0.13, html5ever 0.40 / scraper 0.29, oxc 0.156 and criterion 0.8.
- Seeded sampling changed with rand 0.10: for the same `--seed`, retry and backoff jitter, scheduler
  and frontier shuffle order, and the synthetic TLS ClientHello ordering differ from 0.1.0. Runs stay
  deterministic per seed within this version; a seed recorded with 0.1.0 does not reproduce the same
  sampled values. Journaled actions and recorded-path replay are unaffected.
- Container base images are pinned by digest.
- `robots.txt` `Crawl-delay` (capped at 10 seconds) now paces the origin for runs that obey robots:
  once the robots.txt answer is recorded and on every allowed URL, the run's `OriginGovernor` keeps
  spacing at or above `max(politeness.delayMs, Crawl-delay)` for HTTP and browser effects, across
  back-off and decay. Only an explicit value (including `0`) changes the floor; a refetch that drops
  the directive keeps the earlier one. A run that overrides robots does not apply it itself, and
  other workers are only held back on the start that directly follows a floored start (process-wide
  cap, deployment admission). Known limitation: the URL plane waits on the floor in process (up to
  10 s), so rows behind it in the leased batch wait too (a `429` cooldown instead defers later rows
  of that origin), and the acquisition budget counts the wait.
  ([#35](https://github.com/noxred-research/crawlx/issues/35), contributed in
  [#37](https://github.com/noxred-research/crawlx/pull/37))

### Security

- CI only runs for code owners; a `required` aggregate check fails for pull requests the workflow
  gate refuses. Secrets moved into environments (`gate-keys` deploys from `main` only and needs a
  code owner's approval). Private-rule hits of the public-tree lint no longer print rule names or
  matching text.
- Every SQL string built at runtime is audited and marked for sqlx 0.9's injection check; values stay
  bound parameters.

### Documentation

- Positioning and intended use: the README, docs index, `SECURITY.md`, `CONTRIBUTING.md` and
  `CODE_OF_CONDUCT.md` now state that crawlx is for security research and authorized testing only, and
  describe the optional AI/LLM features and their guardrails.
- README redesign with banner, animated terminal demo, install options, quick starts, output examples and
  an architecture diagram; reference material moved to `docs/reference.md`, with a local-run
  `docs/walkthrough.md` and a `docs/roadmap.md`.
- `SECURITY.md` gains response-time targets, safe-harbor terms, scope lists and release verification;
  new `CODE_OF_CONDUCT.md`; YAML issue forms for bugs, feature requests and questions.

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
  compatibility-API scrape, crawl, map, search, extract and parse behavior under
  `/compat/v2`.
- Bounded source discovery: HTML, RSS/Atom/JSON Feed, sitemaps, category pages and
  opt-in conventional paths and external providers, with offline development replay.
- Surface-discovery crawl options: scope fields, strategies, similarity filters, rate
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
  sealed under per-artifact data keys wrapped by cloud KMS (`CRAWLX_ARTIFACT_KMS_KEY_ID`) or
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
  `replay`, `replay-response`, `extract`, `authz`, `mcp` (MCP tools over
  stdio), `healthcheck` and configuration checks.
- Optional ONNX ranker support (`crawlx-model`, `onnx` feature), a typed-decision HTTP
  adapter for an external decision service, language identification, and
  OpenTelemetry/Prometheus telemetry.
- Test and benchmark infrastructure: CrawlerGym fixtures, chaos and fault-injection
  suites, fuzz targets, an upstream differential harness, a reference-driver
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
  155.0.8059.84) attempts unsolicited browser-vendor background-service requests
  (`accounts.google.com`, `redirector.gvt1.com`, `content-autofill.googleapis.com`,
  `android.clients.google.com`). Where the run's egress policy excludes them (a bounded scope
  or an operator blocklist entry) the egress proxy denies each one before any connection and
  logs it, so no foreign host is dialed, but the attempts are not prevented.
  Zero-attempt isolation needs a patched, self-hosted Chromium (post-release; the source
  build exists under `ci/build-chromium.py`). See
  [data and secrets](docs/design/data-and-secrets.md#chromium-background-traffic).

[Unreleased]: https://github.com/noxred-research/crawlx/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/noxred-research/crawlx/releases/tag/v0.1.0
