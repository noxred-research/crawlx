# Changelog

All notable changes to crawlx are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
project is pre-1.0; minor versions may contain breaking changes.

## [Unreleased]

### Fixed: PostgreSQL rejected actions finished with scripted-scroll fidelity

The `action_fidelity` enum lacked `scripted_scroll`, so finishing an action whose receipt reported a forced scroll failed on PostgreSQL (migration `0046`). A property test now stores random action kinds and receipt fidelities through the journal and requires `lane`/`fidelity` to be present and consistent on every stored row, on the in-memory store and on PostgreSQL.

### Fixed: `lane_chromium` no longer ends on a 20 s wall clock

The link-fixture lane regression ran into its harness deadline on slower hosts, so whether the `url_plane` fallback navigations appeared depended on machine speed. The run now ends on its interaction budget and the test states the contract: every non-`url_plane` action is on the trusted lane and every `url_plane` navigation follows a trusted click on the same route and element.

### Added: release-gate checklist computed by CI

`release-gate` (`crawlx_bench::release_gate`, `ci/release-gate.sh`) evaluates the release-gate checklist from evidence files with per-item `pass | fail | unmeasured | waived | not_applicable`, writes a JSON and markdown report and exits 1 unless every applicable item passes. Only performance rows accept an expiring waiver with an owner and reason; `release-gate record` captures suite results. The `release-checklist` CI job runs it on demand and weekly. See `docs/ops/release-gates.md`.

### Added: flake rerun and quarantine tooling

`.config/nextest.toml` (profiles `ci`, `nightly`) reruns a failing test once to classify it. `flake-report` (`crawlx_bench::flake`) records flaky tests from the junit output, quarantines a test to the nightly-only suite after 3 flake events in 14 days (`ci/quarantine.toml`), fails the check when a quarantine outlives 14 days, and writes the 30-day flake rate to `bench/out/flake-report.json` for the release gate. See `docs/ops/flaky-tests.md`.

### Added: network-fault schedules for load and chaos runs

`netfault` is a standard tool: a `FaultSchedule` text spec (`latency=50ms@0s..10s,blackhole@12s..15s,reset@20s,refuse@25s..27s`) with seeded generation, `Proxy::run_schedule`, the `netfault` binary, and `load --fault`, `--fault-seed` and `--allow-errors-during-fault`, which split per-route results into in-fault and out-of-fault windows. Latency-only schedules keep the p99 gate and zero errors; connection kills may only fail requests inside their windows.

### Added: storage Criterion benches

`action_journal_insert`, `transition_write_batch` (in-memory and PostgreSQL) and `artifact_key_derive` are registered in `ci/bench-gate.sh` with committed baselines; a registry test keeps every `crawlx-storage` bench in the gate.

### Added: browser-plane throughput in crawl-bench

`crawl-bench` has `hybrid` and `browser-only` profiles (Chromium required; skipped with a message without it), new `interactions` and `pps` columns, and a table of each profile's pages per second relative to `static` on the same target.

### Added: test coverage for recorded audit gaps

Mid-transaction PostgreSQL statement failures recovered through `unknown` and reconcile, and a cancelled outcome transaction; CDP-versus-proxy capture parity on per-epoch and background views; Standard-versus-Stealth discovery parity over G01–G30 within 1 pp; named oracle-comparator tests; HTTP 422 `profile_conflict` for stealth under `read_only`; crawl-level OTLP exporter failure (unreachable and silent collector); the V2 and dual identity checks pinned by a registry test and run by name in CI; `crawlx_bench::query_identity` with a session-value artifact grep gate and the G12 gate metrics; API coverage against an offline recount; run-twice determinism of the G24 value partitions; an adversarial-label fixture; a browser-free G25 `wrong_element_actions` gate; the production arbiter over the production safety kernel; recorded `deferred_reason` for every deferred crawl-maze target with the second-click reveals, hash router and denied destructive click guarded in the manifest and both runs.

### Added: object-storage profiles

`CRAWLX_S3_PROFILE` (`standard`, `compatible`, `edge`, `self-hosted`; default `standard`, the previous behavior) selects per-service defaults and capabilities for the S3 backend: endpoint requirement, signing region (`auto` on `edge`), addressing style, plain-`http` policy, server-side encryption, object lock and checksum mode. `CRAWLX_S3_CHECKSUM`, `CRAWLX_S3_OBJECT_LOCK`, `CRAWLX_S3_ALLOW_HTTP` and `CRAWLX_S3_ALLOW_KMS` are new; the existing `CRAWLX_S3_*` variables override profile defaults. A configuration the profile cannot serve (encryption or object lock on `edge`, `kms` on `compatible` without the opt-in, a missing endpoint, plain `http` to an untrusted host, `when_supported` checksums outside `standard`) is a typed `S3ConfigError` when the configuration is built, never a silent downgrade. Uploads larger than one `PutObject` (5 GiB) are refused with a typed error. See [docs/ops/object-storage.md](docs/ops/object-storage.md).

### Changed: S3 configuration is validated and stricter

`S3Blobs::new` and `S3Blobs::with_credentials` return `Result<_, S3ConfigError>` and validate the configuration. `S3Config` gains `profile`, `checksum`, `object_lock`, `allow_http` and `allow_kms`; `S3Config::from_lookup`, `from_lookup_for_bucket` and `from_env_for_bucket` build a validated configuration from an environment lookup. `CRAWLX_S3_PATH_STYLE` and the other boolean variables now reject an unrecognized value instead of reading it as false, and `CRAWLX_S3_KMS_KEY_ID` without `CRAWLX_S3_SSE=kms` is an error instead of being ignored.

### Added: streaming feed rows with a durable cursor

`crawlx_url::feed_stream::FeedRowStream` streams XML item rows and CSV records through a fixed buffer with declarative templates (namespaced elements and attributes, CSV quoting, header mapping), typed per-row outcomes and a resumable `StreamCursor` (byte offset, row index, prefix digest). `DOCTYPE` and entity declarations are never expanded. See [docs/reference.md](docs/reference.md#feed-rows-exporters-storefront-recipes-and-link-options).

### Added: exact-byte item exporters with explicit CSV and XML policies

`crawlx_extract::item_export::write_item_with` fixes field order for JSON, JSONL, CSV and XML items and makes the CSV formula policy (`PrefixEscape` or `Reject`), forbidden XML scalar policy (`Reject` or `Replace`) and XML text mode (`Escaped` or `Cdata`) explicit, with explicit CSV columns for missing fields.

### Added: declarative storefront recipe

`crawlx_extract::recipe::StorefrontRecipeV1` emits one item per variant from locally supplied collection JSON with decimal-string prices (floating point prices are a typed fault), source ids and pagination as a `DiscoveryIntentV1` that the extractor never fetches.

### Added: link extractor options

`crawlx_extract::link_options::LinkOptions` adds allow/deny regexes, allow/deny domains, tag and attribute lists, CSS/XPath restriction, canonical form, unique and nofollow handling to link extraction; deny always wins over allow.

### Added: one parser pipeline for markup and documents

`ParserPipelineV1` (ordered `detect`, `decode_input`, `parse`, `select`, `metadata`, `quality`, `transform`, `project` stages, explicit per-format routes, input/node/depth/operation/child/output limits) is executed by `crawlx_extract::pipeline::ParserPipeline::run`, the single entry that routes HTML to the page extractor and PDF, Office, EPUB, text and CSV to the document parser and returns one `PipelineOutput` with per-stage counts. Limits refuse instead of truncating, an unrouted format is refused, and the pipeline digest is part of the output record version (`parser_pipeline_v1/<digest>`). See [docs/reference.md](docs/reference.md#parser-pipeline).

### Added: list discovery, URL substring filters and a ranking-only language hint

`scope.sources: ["url_list"]` with `scope.discovery.urlList` crawls an inline list of up to 10000 credential-free HTTP(S) URLs: bounded count and bytes, fragments dropped, duplicates removed in stable order, one `listed_url` intent per URL, no file path and no network in the core type, every URL still scope-, robots- and egress-checked. `scope.discovery.urlLanguageHint` orders candidates by URL language markers (`language_rank`) and never admits, denies or labels content. The settings importer translates the precision-text `--url-filter` to escaped literal `scope.urlInclude` patterns (explicit scope denies still win, the filter only narrows, the seed is exempt), accepts an inline manifest `urlList`, and reports every option without a native mapping with its pinned inventory rows in `features` (`input-file`, `urls-from-file` and `urls-from-stdin` are `external_required`).

### Added: authored extraction corpus with gold spans and measured per-family floors

`crates/crawlx-extract/tests/corpus/` holds 18 original pages in four families (article body, boilerplate, metadata, link discovery) with UTF-8 byte-span gold files and a `manifest.json` (license `authored-for-this-repo`, SHA-256 per file). `cargo test -p crawlx-extract --test corpus` verifies the digests and spans, runs the real extractor, computes token-level precision, recall and F1 per family and fails below floors set from the measured values.

### Added: CSS pseudo-element projections, nested item groups and typed transforms

CSS selectors accept a trailing `::text` or `::attr(name)` on each comma-separated selector; any other pseudo-element fails admission as `unsupported selector syntax` instead of matching nothing. Item recipes gain a `group` projection with nested `fields` evaluated relative to each base element, `next_sibling`/`previous_sibling` sources, per-instance outcomes (`groups`, defaults marked `defaulted`) and recursive privacy projection, plus the `attributes` projection and the `clean`, `regex`, `builtin`, `json_parse` and `limit` transforms. `crawlx_extract::handlers` exposes the same operations as typed text and attribute handlers with identical output. See [docs/reference](docs/reference.md#static-selectors-item-recipes-handlers-and-regex-extraction).

### Added: versioned built-in regex patterns and one regex admission gate

`crawlx_extract::regex_builtins` provides versioned built-in pattern names (`email.v1`, `url.v1`, `uuid.v1`, and others) and custom patterns on the linear-time engine. Backreferences and look-around are rejected at admission with typed errors (also for `extract.customFields`), and compiled size, capture groups, input bytes and match counts are bounded.

### Added: bounded element search, similarity and selector generation

`crawlx_extract::find` adds tag/attribute/text/regex search, ancestor and sibling traversal, deterministic `find_similar` ranking, generated CSS/XPath paths and abstaining outcomes for ambiguous answers, all under the shared selector operation budget.

### Added: byte decoding with diagnostics and a comment/CDATA-aware text view

`crawlx_extract::decode::decode` selects an encoding by byte-order mark, declared charset or early `meta`, and records the choice and the first 64 malformed sequences. `markup_text` separates cleaned text from collected comments and CDATA payloads and reports the digest of the decoded source. `ExtractOptions::decode` makes `Extractor::extract_bytes` use it (declared charset or the `Content-Type` charset) and report `Document::decode`; `ExtractOptions::markup` keeps comments and/or CDATA payloads in `Document::markup` without changing the cleaned text. Both are absent by default and leave the document and its serialized form unchanged.

### Added: `selectors.readMoreBase`

An optional policy field chooses whether relative read-more targets resolve against the document base (default) or the acquired page URL. Omission leaves the serialized policy and its digest unchanged; the extractor still issues no request.

### Added: opt-in content outputs (variants, fit content, citations, tables, link and media scores)

`ExtractOptions::outputs` adds `Document::outputs` without changing any existing field. It returns the raw input, the cleaned whole page, fit HTML/Markdown from two deterministic, versioned, budgeted filters (`pruning_v1` from text density, link density, tag and class hints; `bm25_v1` against a caller query with fixed-point arithmetic) and citation-style Markdown whose `⟨n⟩` markers resolve to retained references and `Document::links` positions. `targetElements` narrows text, Markdown and HTML while links and assets keep the declared `discoveryScope` (whole page by default). `tables` reports each table as data, layout or ambiguous with its score components and, for data tables, exact normalized rows with spans repeated and merged headers joined. `linkMedia` scores links, images and audio/video with intrinsic and contextual components kept apart, classifies links as internal, subdomain or external, and creates preview intents (`PreviewIntentV1`, refused for private, loopback, link-local, local and credentialed targets at creation) for a worker to fulfil; `link_media::project_head` projects fetched head bytes under the intent's byte budget. The extractor never fetches. See [docs/reference.md](docs/reference.md#content-outputs-variants-fit-content-tables-and-link-scores).

### Added: certificate evidence, independent body limits and per-request response controls in the fetch plane

Every live `Fetcher` response carries `FetchEvidence` (`FetchResponse::evidence()`): the leaf certificate fingerprint (SHA-256), validity period and self-issued flag read from the request's own TLS connection under a 32 KiB bound (`certificateEvidence: observed`), or the reason none was observed (`not_tls`, `not_reported`, `too_large`, `malformed`); absence is never reported as a successful check, and observation is separate from the verification mode. Tested on loopback TLS in both transports, with no second socket. Body reading is now bounded three independent ways: decoded bytes (default 8 MiB), wire bytes (`FetchConfig::max_wire_bytes`, `FetchOptions::max_wire_bytes`) and a decoded-per-wire expansion ratio (`FetchConfig::max_expansion_ratio`, default 250, never disabled) that refuses a decompression bomb with `FetchError::BodyLimit`; `0` is a zero-byte cap, never unlimited, and no cap exceeds 64 MiB. `gzip`, `deflate` and `br` are decoded by `crawlx_fetch::codec` (also `decode_bytes` for bytes already in memory), the original wire bytes keep a blake3 digest in the evidence, a corrupt or truncated stream is `FetchError::BodyDecode`, and `FetchOptions::oversize = Reject` refuses a response whose `Content-Length` exceeds the cap before reading its body. `FetchResponse::text()` decodes strictly in the selected encoding (override, byte-order mark, `Content-Type` charset, `<meta>`/XML declaration, UTF-8) and records where it came from; invalid bytes are an error unless `text_lossy()` is asked for. `FetchOptions::declaration` maps a declared MIME type, text encoding and allowed or denied HTTP error statuses onto the request: an allowed `429` is delivered and not retried but still reaches the governor, so it never bypasses a cooldown. `FetchOptions::preflight` adds a `HEAD` before the `GET` that passes the same egress check, admission and request allowance on every hop. `FetchConfig::read_timeout` adds an idle body timeout separate from the connect and whole-request timeouts. `CachedValidators` binds ETag/Last-Modified to a cache scope (never offered to another tenant or principal, withheld for `no-store`, `Vary: *` and zero-data-retention content) and `interpret_revalidation` accepts a `304` only when it agrees with the validator that was sent.

### Added: robots decision on every media, feed and read-more hop; private networks only through authorized scope

`RobotsCache::evaluate_hop(HopKind, &Url)` gives media, feed, read-more and redirect hops the same verdict as a page (an unknown origin asks for its `robots.txt` and is never allowed). `EgressPolicy::with_authorized_private_networks` is the only way admission grants private access: exactly the record's authorized networks, and an empty list grants nothing.

### Fixed: a `429`/`503` cooldown is demonstrated to hold back every worker on the origin

`crates/crawlx-fetch/tests/cooldown_pg.rs` runs two governors over one PostgreSQL origin admission store (skipped without `CRAWLX_TEST_DATABASE_URL`): a cooldown published by one worker is visible to the other before it leases work, delays its next start on that origin only, does not occupy run-global capacity while waiting, and expires.

### Added: scheduled retention sweeper

`crawlx admin sweep-retention --every <duration>` keeps the retention sweeper running: one pass at start, then one per interval (at least one second), until SIGINT or SIGTERM. Passes never overlap and missed ticks are not replayed, a pass in flight is dropped on cancellation (a sweep is resumable) and one longer than an hour counts as a failure, a failed pass is logged (error text only), counted in `crawlx.retention.sweep.failures` and retried on the next tick. `--passes <n>` bounds the run. The loop is `crawlx_storage::retention::run_sweep_loop` (also `RetentionSweeper::run_loop`), tested with a paused clock and with cancellation. See [docs/ops](docs/ops/README.md#scheduled-retention-sweeper).

### Added: CLI list, configuration and diagnostics rows

`--resolvers` accepts files of resolvers with commas, white space, `#` comments and repeats (at most 8 distinct, entries validated with the flag named). `--known-files` accepts `all`, `robotstxt` and `sitemapxml` and visits each file once. `crawl --cache-mode` sets the response-cache mode; `crawl --print-config` prints every seed's admitted, redacted request with a configuration digest and exits without crawling. The pprof listener serves `/debug/pprof/` and a text form of the memory summary (`/debug/pprof/heap?debug=1`). `crawlx extract --list` prints discovery only; `--backup-dir` writes exclusive owner-only copies outside the source tree and `--zero-retention` refuses every disk sink. `source-import` of a Go-collector-style manifest accepts an exported `env`, reports every supported variable with its effective source, refuses unsafe or unlimited values with a complete report, and returns a `configDigest` for convertible imports. Exit codes, stream separation and the update policy are documented in [docs/ops](docs/ops/README.md#exit-codes-streams-and-diagnostics).

`crawlx config features` prints a versioned feature manifest for the `crawl` flag set: per baseline row the flags, compatibility spellings, policy (including intentional security deviations) and exercising tests, kept honest by a test that fails on a missing flag, spelling or test.

### Added: extracted-content dedupe and pre-acquisition URL exclusion

`extract.content.dedupe` removes repeated normalized blocks from the selected output (first occurrence kept, repeats retained when opted out), records distinct raw, page, main and comment digests with their normalization and a similarity fingerprint, and adds a `duplicate_main` quality stage over the normalized title and body (SHA-256) that rejects ingestion of the same content at a second URL while keeping both acquisitions and their exact origins. A bounded, caller-scoped hash cache (tenant, run namespace, role, extractor/policy/normalization versions; deterministic eviction; no clock or global state) backs both stages. `extract.content.excludedUrls` drops URLs by substring or pattern before any request, with the reason code `url_excluded` distinct from `author_excluded`. Challenge validation is covered by tests that keep keyword-only pages and articles about interstitials valid while a structural 200 challenge is excluded with its signals.

### Added: markdown normalization metrics in the differential scorer

`bench/differential/sdk_shape_diff.py` reports the block-level F1 and the ordered-subsequence ratio of
the normalized markdown of every page both systems returned (new `markdown_metrics.py`, standard library
only, with offline tests). `docs/design/crawl-model.md` lists the test files that exercise each acceptance
case (shared 429 cooldown, login expiry, trust failure, DNS rebind, at-most-once actions, cancellation
lease release) and the one known gap.

### Added: pool gateway upstream for the proxy tiers

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

### Added

- Compatibility API shape residuals: the crawl status carries a `warning` string (pages the site's
  robots.txt disallowed, pointing at the `robotsBlocked` list; a stopped crawl that found at most
  one page) and, while the crawl runs, `expiresAt` and a `next` link; `POST /compat/v2/map`
  answers the `id` of its run and lists URLs without the trailing slash of non-root paths; the
  `html` format is a document (`<!DOCTYPE html><html lang="…">`, body); compat routes answer
  cross-origin preflights and carry `Access-Control-Allow-Origin`, `ETag` (a matching
  `If-None-Match` answers `304`) and `X-Response-Time`; a compat `409` echoes the caller's
  `x-request-id`; `changeTracking` ignores the `src` of `<iframe>` tags when it compares markdown.
- `compat.mode` (`strict`, the default, or `native_defaults`; environment variable
  `CRAWLX_COMPAT_MODE`): `strict` keeps every query string of a compat crawl that leaves
  `ignoreQueryParameters` unset and signs native webhook deliveries twice (`Crawlx-Signature` and
  the compat signature header); `native_defaults` uses the native query policy and
  `Crawlx-Signature` only.
- A compat crawl or scrape produces `admission` (API) and, per page, `fetch`, `extract` and
  `persist` (worker) spans carrying `crawl_id`.
- Compat WebSocket watchers close a client that does not accept a frame within
  `Settings::ws_send_timeout` (30 s, code 1008) and document their frame contract.
- Golden construct matrix for header and HTML endpoint discovery (one fixture per construct with
  the exact expected output; `cargo test -p crawlx-extract --test endpoint_matrix`) and
  behavioral vectors for the JavaScript miner (`--test endpoint_js_vectors`). They pinned and fixed:
  every URL of a `ping` list is an endpoint, `applet archive` is split on commas, a `Link` header
  target may contain commas, `Refresh` and `meta refresh` accept a bare target (`0; /next`),
  `data-hx-*` attributes are read like `hx-*`, `<form method=dialog>` and `formmethod=dialog`
  produce no endpoint, a button's `formmethod` is honored (non-GET stays metadata only), a relative
  `<base href>` resolves against the page instead of against itself, regex-mined text in an HTML
  page resolves against its `<base>`, and JSON/JavaScript slash escapes (`\/`, `\u002f`) are decoded
  before regex mining while a match that keeps another backslash is dropped (a `\\host\x` string
  used to switch the host).
- `endpoints::discover_report` and `discover_html_report` return a `DiscoveryReport`: the endpoints
  plus a typed `UnresolvedEndpoint` (matcher, method, kind `variable|call|member|expression`, byte
  span, script origin, `partial`) for each URL expression of a request site that the AST pass cannot
  resolve statically, instead of dropping the site or guessing silently. The list is bounded by
  `DiscoveryOptions::max_unresolved` (default 1000) with an overflow count; scripts are still never
  executed. Case conversions (`toLowerCase`) are no longer treated as transparent.
- The JavaScript AST pass no longer aborts the process (stack overflow) on a hostile script with a
  million nested brackets, prefix operators, `x=x=…`, `?:` or `=>` chains or a very long `a+a+…`
  chain: it refuses scripts that exceed a lexical nesting bound and stops its own traversal at a
  fixed depth; regex mining still runs in `both` mode.
- Unit tests for the browser crash-loop alerts (`deploy/alerts/crawlx-rules.test.yaml`, run with
  `promtool test rules`): the per-worker rule fires above 0.2 crashes/min for ten minutes, the
  fleet-wide rule pages above 25 % of workers, and an occasional crash alerts on neither. The
  telemetry catalog tests now pin the name, type, bounded labels and exported name of the
  measurement metrics (identity, key coverage, traffic capture, revalidation, round-robin roles,
  form partitions, trusted corpus) and assert that each moves in the registry.

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
