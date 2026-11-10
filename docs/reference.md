# Reference: crawl options and runtime behaviors

Detailed behavior of options that the [README](../README.md) only summarizes. Run
`crawlx <command> --help` for the authoritative flag list of the build you have.

Contents: [bounded source discovery](#bounded-source-discovery) ·
[response cache and development replay](#native-response-cache-and-development-replay) ·
[adaptive extraction descriptors](#scoped-adaptive-extraction-descriptors) ·
[MCP server](#mcp-server) · [Firecrawl-compatible clients](#firecrawl-compatible-clients) ·
[Katana-style flags](#katana-style-crawl-flags) · [JavaScript endpoint mining](#javascript-endpoint-mining) ·
[wordlists](#wordlists-and-stored-fields) · [captcha solving](#captcha-solving) ·
[proxy tiers and the ProxyX pool gateway](#deployment-proxy-tiers-and-the-proxyx-pool-gateway)

## Bounded source discovery

Native JSON requests can opt into source discovery without changing ordinary crawl defaults:

```json
{
  "scope": {
    "sources": ["html", "feeds", "sitemap", "categories", "conventional"],
    "maxKnownUrls": 100000,
    "discovery": {
      "version": 1,
      "mode": "explore",
      "conventionalPaths": ["/feed", "/rss"],
      "maxSourceDocuments": 16,
      "maxFeedBytes": 2097152,
      "maxEntries": 1000,
      "maxNesting": 32,
      "maxSourceDepth": 5,
      "maxCategoryLinks": 32,
      "maxFocusedLinks": 64,
      "minSitemapArticles": 1,
      "sufficientMainChars": 300,
      "readMoreHops": 0,
      "mediaProbes": 0
    }
  }
}
```

`feeds` parses declared RSS 2.0, RDF/RSS 1.0, Atom and JSON Feed 1.0/1.1 sources. Parsing is offline; links and publisher/date/title hints are not authorization or verified article facts. DTDs, external entities, excessive nesting and oversized sources are refused. Conventional paths are requested only when explicitly listed. Empty `sources` keeps legacy HTML/sitemap behavior; non-legacy sources require `discovery`.

Sitemap candidates, including namespace-checked hreflang variants, pass normal scope and robots admission. Discovery-enabled exploration acquires bounded sitemaps before focused HTML fallback. `probe` records actual selected article length/quality and insufficiency reasons. Category/domain heuristics never expand scope. Source requests and cursor advances commit together under the parent lease; a changed source representation cannot silently continue an old cursor.

`readMoreHops` and `mediaProbes` are opt-in worker acquisitions. Read-more follows explicit article intents, records separate original/final URLs and child artifacts, and stops on cycles or its hop allowance. Media probes inspect at most `mediaHeaderBytes` (at most 65536) and refuse dimensions above `maxMediaPixels`; they never decode a full image. Sitemap traversal, redirects, read-more and media work share the primary page's `acquisition.maxAttempts`, `maxNetworkRequests`, byte allowance and deadline. Configure sufficient shared allowance when enabling several auxiliary stages; a stage does not receive fresh retries.

Choose teaser links with `extract.content.selectors.readMore`, for example `[{"kind":"xpath","expression":"//a[@class='teaser']/@href"}]`; these selectors only produce parser references. The worker's independent `readMoreHops` policy controls acquisition. ZDR source discovery also requires the protected worker request-identity key; missing key is `CapabilityUnavailable`, never a public-seed-derived correlation fallback. ZDR source cursor receipts use the shared volatile retention boundary.

External providers have no built-in endpoint or fallback. Add `scope.discovery.connectors` with explicit `provider` (`google_news`, `google_trends`, `internet_archive`), authorized `endpoint`, and CDX `archiveBase` when needed. Enable the corresponding source (`google_news`, `google_trends`, `archive`). News accepts RSS/Atom and recorded `garturlres` results; trends accepts daily-trends JSON or RSS; archive accepts a CDX JSON table. Archive provenance keeps original URL, replay URL, capture time and optional recorded original status separate from the provider's HTTP status. Missing providers return `ProviderUnavailable`.

Cache-only/development replay never requests robots, sitemap, provider, conventional, media or read-more resources. Missing retained responses return `cache_miss`; explicit external-provider requests fail as `ProviderForbiddenInReplay`. Reprocessed artifacts record current robots as unobserved, not approved. These are source/runtime contracts, not a claim of upstream service availability or live-provider certification.

## Native response cache and development replay

Native requests use `cache: {"schemaVersion": 1, "mode": "read_write", "maxAgeMs": 172800000, "freshness": "retained", "developmentReplay": false}`. The scrape facade also accepts this explicit extension. Without it, existing `maxAge`, `minAge`, `lockdown` and `storeInCache` behavior remains in force.

| Mode | Read retained response | Write reusable response | Fetch on miss |
| --- | --- | --- | --- |
| `read_write` | Yes, within age and retention | Yes | Yes |
| `bypass` | No | Yes | Yes |
| `disabled` | No | No | Yes |
| `read_only` | Yes, within age and retention | No | **Never** |
| `write_only` | No | Yes | Yes |

`developmentReplay: true` overrides the mode with offline reads and no reusable writes. Replay records the source run, source fetch time and zero current target requests. `freshness: head` requires the same retained ETag or Last-Modified validator; `conditional_get` requires a matching owned body and `304`. A changed validator invalidates the entry. These requests use the checked fetcher, global pacing and the same parent attempt/request/byte/deadline allowance as the ensuing fetch. Read-only and development replay never send either validator request.

Cache identity includes the authenticated API-key principal, acquisition policy, registered HTTP implementation revision, validator, representation and request/extraction route identity. Local runs without a trusted principal cannot read another run's cache. Credential-bearing reuse requires the operator's protected `CRAWLX_REQUEST_IDENTITY_KEY` (64 hexadecimal digits): tenant-derived keyed correlation covers resolved headers and cookies, not public unkeyed credential hashes. Missing keys make credential-bearing results uncacheable; cache-only requests fail explicitly. Mutable browser profiles, unobserved browser builds and protocol delegates do not claim reusable cache capability.

Missing retained content is `stored_body_unavailable` (`STORED_BODY_UNAVAILABLE` on the facade), not permission to fetch during offline replay. ZDR never creates a durable response cache. For an exact existing local artifact, use `crawlx replay-response RUN --frontier ID --tenant TENANT --identity SAVED_DIGEST --database-url URL --artifacts-dir DIRECTORY`; supply `--principal API_KEY_ID` for an API-owned source. This command reads committed retained content only and emits base64 JSON with explicit rendition/provenance. Existing `crawlx replay` remains browser-action replay.

## Scoped adaptive extraction descriptors

`PUT /v1/crawls/{id}/adaptive-selectors/{selector_id}` captures structure from a committed page's retained HTML. Its body supplies `page`, static selector-document `node`, `source`, `schema`, optional `expiresAt`, `threshold`, `runnerUpMargin` and `maxCandidates`. The server supplies tenant, principal and acquired origin. `GET` uses the same page/source/schema namespace. `POST .../{selector_id}/relocate` accepts `page`, `source`, `schema` and returns `recovered`, `ambiguous` or `not_found`. An ambiguous response contains no selected node. Static document nodes are never browser action locators.

Descriptors contain only bounded structural features, not page text, IDs or attribute values. PostgreSQL migration `0030_adaptive_selectors.sql` enforces tenant RLS, run ownership and fixed source-retention expiry. ZDR stores only lookup metadata durably; payloads use the existing shared volatile delivery buffer, whose original TTL never renews on update. HTML reads check ownership, sensitivity, expiry, byte bounds and artifact fixity before bounded CPU evaluation.

## MCP server

`crawlx mcp` is a Model Context Protocol server over stdio (newline-delimited JSON-RPC 2.0; revision 2025-03-26, downgrading to 2024-11-05). It offers the Firecrawl MCP tools (`firecrawl_scrape`, `firecrawl_map`, `firecrawl_search`, `firecrawl_crawl`, `firecrawl_check_crawl_status`, `firecrawl_extract`, `firecrawl_extract_status`, `firecrawl_parse`, `firecrawl_agent`, `firecrawl_agent_status`) as a thin client of a crawlx API's `/compat/firecrawl/v2` facade: `--api-url` (`CRAWLX_API_URL`, then `FIRECRAWL_API_URL`, default `http://127.0.0.1:8080`), `--api-key` (`CRAWLX_API_KEY`, then `FIRECRAWL_API_KEY`; sent as `Authorization: Bearer`, never logged), `--timeout-ms` (per HTTP request, default 120000), `--poll-interval-ms` / `--poll-timeout-ms` (waiting on extract and agent jobs). API errors come back as `isError` tool results; results are cut at 1 MiB. Client config: `{"mcpServers": {"crawlx": {"command": "crawlx", "args": ["mcp"], "env": {"CRAWLX_API_URL": "http://127.0.0.1:8080", "CRAWLX_API_KEY": "…"}}}}`.

`firecrawl_parse` reads the file path it is given on the machine running `crawlx mcp` and uploads the bytes to the API, so point `--api-url` only at an API you trust.

## Firecrawl-compatible clients

Firecrawl's own clients use the same facade: `crawlx serve --firecrawl-keys --api-key acme=fc-<32 hex>` accepts an `fc-` key on `/compat/firecrawl`, and the Python and Node SDKs, the `firecrawl` CLI and LangChain's loader run against it in `cargo test -p crawlx-cli --test sdk_python` (installs the packages from PyPI and npm, skips when they are unreachable). Base URLs per client (the Python SDK drops a path prefix and needs a `/v2/*` rewrite), the endpoints each integration calls and what does not work (`/v1`-only tools such as Flowise): [`docs/integrations.md`](integrations.md).

## Katana-style crawl flags

The Katana-style flags map onto the request: scope (`--field-scope fqdn|rdn|dn|none`, `--crawl-scope`/`--crawl-out-scope` URL regexes, `--exclude-hosts`, `--strategy`, `--max-pages-per-host`, `--known-files`, `--extension-match`/`--extension-filter`/`--no-default-ext-filter`, `--no-js-endpoints`), filters (`--filter-similar[-threshold|-budget]`, `--content-similar off|simhash|tfidf|bm25` with `-distance|-threshold|-budget`, `--filter-page-type`), rate limits (`--rate-limit[-minute]`, `--host-rate-limit[-minute]`, `--concurrency`), fetch (`--max-response-size`, `--timeout` seconds, `--retries`, `--no-redirects`, `--proxy`), extraction (`--custom-field-config` YAML/JSON in katana's `field-config.yaml` shape, `--detect-secrets`, `--form-extraction`/`--no-form-extraction`), browser (`--page-hooks`, `--page-load-strategy`, `--dom-wait-time` seconds) and output (`--display-out-scope`, `--jsonl` writing `results.jsonl`, `--field`/`--output-template` printing one line per value, `--store-fields DIR` wordlists). With `--request <json>` the flags override the file's fields. `crawlx worker --cdp-ws-url ws://… [--no-incognito]` attaches to a running Chrome instead of launching one.

## JavaScript endpoint mining

JavaScript endpoint mining uses `extract.javascript.mode=off|regex|ast|both`
in native request JSON (or `[crawl.extract.javascript]` with `mode = "ast"` in
TOML configuration). Native requests default to `both`. `crawlx crawl
--javascript-mode MODE` selects the exact miners; `--js-crawl` selects regex,
`--jsluice` selects AST, and combining those two switches selects both.
Explicit `--javascript-mode` conflicts with those switches and
`--no-js-endpoints`. Higher-priority command-line selections replace YAML
JavaScript switches as a group and override request-body configuration.
Off keeps structural HTML links, script sources and header discovery.
Regex never parses JavaScript; AST never runs regex, including after malformed
or oversized source. Both retains the existing regex fallback when AST parsing
fails or exceeds its 4 MiB bound. Selecting AST or both without the `js-ast`
feature returns an explicit unavailable error, never a silent regex fallback.
The standalone extractor's unspecified default follows its compiled miners
(both with `js-ast`, regex without it).

## Wordlists and stored fields

`crawlx crawl` and `crawlx export` accept `--store-field qurl,key` (comma-separated,
repeatable) to select wordlist fields independently of `--field` and `--output-template`.
`--store-fields DIR` retains its directory meaning; `--store-field-dir DIR` is an alias.
Without an explicit selector, directory-only usage keeps the displayed/template fields.
With a selector but no directory, crawl writes under `<--output>/katana_field`; export
writes `katana_field` beside `--out`, otherwise beside the source report, otherwise under
the standard `./crawlx-out` output directory for database runs. Templates do not add fields
to an explicit stored list. Valid custom field names read retained `metadata.custom_fields`;
missing custom values produce no wordlist entries. Wordlists retain their per-host sanitized
filenames and append only first-seen values.
Explicit wordlists use the JSONL page-admission rules: URL/extension filters, page-type
exclusions and DSL conditions. Regexes are evaluated against the URL for this admission,
not display/template values. A missing template field suppresses display lines but does
not suppress selected wordlists. Directory-only legacy storage still requires an emitted
display line. Text display retains its existing per-line filtering.

## Captcha solving

Captcha solving is opt-in: `--captcha-solver-provider capsolver` (`-csp` / `-captcha-solver-provider`, or `CAPTCHA_SOLVER_PROVIDER`) requires a key. Use `--captcha-solver-key-ref env://MY_CAPTCHA_KEY` or `file:///run/secrets/captcha-key`; `--captcha-solver-key` (`-csk` / `-captcha-solver-key`, or `CAPTCHA_SOLVER_KEY`) keeps a literal key only in process memory behind a transient resolver reference. Explicit key references override ambient keys. A key without a provider does not enable solving, and unknown providers fail. YAML configuration uses these long flag names. JSON requests use `crawl.captcha` with `provider`, `key_ref`, `endpoint`, `timeout_seconds` and `poll_interval_ms`; TOML wraps the request in `[crawl]`, so solver settings use `[crawl.crawl.captcha]`. Neither request serialization nor argument debugging includes a literal key.

The endpoint defaults to `https://api.capsolver.com/`; `--captcha-solver-endpoint` accepts HTTPS or explicit HTTP IP-loopback fixture endpoints only. `--captcha-solver-timeout-seconds` defaults to 120 and bounds the entire solve, including response bodies; `--captcha-solver-poll-interval-ms` defaults to 1000. Task creation is never retried. Task mappings follow [Katana's MIT-licensed CapSolver integration](https://github.com/projectdiscovery/katana/blob/main/pkg/engine/headless/captcha/capsolver/capsolver.go). Tests use local fixtures; external provider availability and account access are not verified.

Captcha configuration requires an enabled browser plane; static-only crawls reject it. Callback delivery passes through the safety kernel as an `Unclassified` action, so the default `read_only` profile refuses delivery. Use `--profile test_environment` only for controlled targets you are authorized to test; configuring a solver never bypasses action admission.

Supported widgets are reCAPTCHA v2/v3 and Enterprise variants, Turnstile, and hCaptcha. The browser fills each detected widget's response fields and invokes only its recorded callback or v3 promise resolver; it does not submit a form. Direct form submission during callback delivery is refused. Each widget gets at most one billed attempt per document, including ambiguous failures. Callback delivery has a separate ten-second bound and observes crawl cancellation. Keys and tokens are redacted from observations, console output, traffic metadata, page HTML/JSON, and storage exports. Full response-body capture, screenshots, PDFs, and raw DOM artifacts are refused with solving enabled because binary or opaque content cannot be safely redacted.

Tests use controlled fixtures, not a live provider: `cargo test -p crawlx-browser --test captcha_transport`, `cargo test -p crawlx-browser --test captcha_widgets` (needs the pinned Chromium) and `cargo test -p crawlx-safety --test captcha`. An authorized operator smoke command is `CAPTCHA_SOLVER_PROVIDER=capsolver CAPTCHA_SOLVER_KEY=... crawlx crawl https://controlled.example.test/challenge --mode dynamic --profile test_environment --limit-urls 1`; it needs a real provider account and a controlled target you are authorized to test.

## Deployment proxy tiers and the ProxyX pool gateway

A scrape selects a proxy tier per job (`proxy: basic | enhanced | auto`). The operator decides
what each tier is, in configuration, never in the request:

- a plain proxy URL (`fetch.basic_proxy_url`, `fetch.enhanced_proxy_url`, or the flags and
  `CRAWLX_FETCH_BASIC_PROXY_URL` / `CRAWLX_FETCH_ENHANCED_PROXY_URL`), `http`, `https`, `socks5` or
  `socks5h`; or
- a [ProxyX](https://github.com/noxred-research/proxyx) pool: an optional upstream with sticky
  identities per crawl, country, city and pool-kind selection, and block feedback. A tier is a URL
  or a pool, never both.

`enhanced` and `auto` fail before any request when no enhanced route (URL or pool) is configured.
Without a scrape job only the request's own `fetch.proxy` applies, as for the plain tiers.

```toml
[fetch.proxyx]
gateway_url = "http://pool-gateway.internal:8080"  # the CONNECT listener; port defaults to 8080
control_url = "http://pool-gateway.internal:8081"  # optional, enables block feedback; port defaults to 8081
org_key     = "env://PROXYX_POOL_ORG_KEY"          # env://NAME, file:///absolute/path or the key itself

[fetch.proxyx.basic]       # presence routes the basic tier through the pool; an empty table takes the org policy
kind = "rotating"          # static | rotating
country = "fr"             # two letters
city = "paris"             # needs country
provider = "oxylabs_res"   # a provider id without `-`
ttl = "10m"                # 30s, 10m, 2h, 1d or seconds
rotation = "sticky"        # sticky (default, one identity per crawl) | each (fresh identity per tunnel)

[fetch.proxyx.enhanced]
kind = "static"
```

| Setting | Environment | Flag |
|---|---|---|
| gateway | `CRAWLX_FETCH_PROXYX_GATEWAY_URL` or `CRAWLX_FETCH__PROXYX__GATEWAY_URL` | `--fetch-proxyx-gateway-url` |
| control API | `CRAWLX_FETCH_PROXYX_CONTROL_URL` or `CRAWLX_FETCH__PROXYX__CONTROL_URL` | `--fetch-proxyx-control-url` |
| org key | `CRAWLX_FETCH_PROXYX_ORG_KEY` or `CRAWLX_FETCH__PROXYX__ORG_KEY` | `--fetch-proxyx-org-key-ref` (a reference, never the key) |
| basic selector | `CRAWLX_FETCH_PROXYX_BASIC="kind=rotating,cc=fr"` or `CRAWLX_FETCH__PROXYX__BASIC__KIND` and the other fields | `--fetch-proxyx-basic "kind=rotating,cc=fr"` |
| enhanced selector | `CRAWLX_FETCH_PROXYX_ENHANCED` or `CRAWLX_FETCH__PROXYX__ENHANCED__…` | `--fetch-proxyx-enhanced` |

Each field resolves flag, then environment, then file. A flag or environment selector replaces the
whole selector of the tier; an empty value selects the pool with the org's policy. The flags are on
`crawl`, `serve` and `worker`. `crawlx config check` validates the shape of the section and prints
`<redacted>` for the org key and both URLs. The org key reference supports `env://` and `file://`
(the file must be a regular file of at most 64 KiB that is not world-readable); `vault://` and
`aws-sm://` references are not resolved for this key.

How a crawl uses the pool:

- **Identity.** The gateway reads the proxy username as `px` plus `-key-value` pairs. crawlx builds
  it from the selector and validates the grammar locally (values `[a-z0-9_]`, `city` needs
  `country`, `rotation = each` carries no `sid`, at most 128 bytes). With sticky rotation every
  tunnel of a run sends `sid-cx_<tier>_<run id>`, so one run keeps one exit identity and its `basic`
  and `enhanced` tiers lease different units. When the id does not fit the 128-byte budget it is
  replaced by a prefix of its hash, never truncated.
- **Transport.** The gateway accepts HTTP `CONNECT` only. crawlx tunnels plain `http://` targets
  too and sends them in origin form over the tunnel. The fetch plane and the browser plane both go
  through a loopback adapter that applies the egress policy to every target; the gateway host and
  the control host are egress-checked like any upstream proxy, so a gateway on a private address
  needs `egress.deployment_allowlist`.
- **Evidence.** The acquisition result of a pool-routed fetch records `connection.proxyRoute =
  "proxyx_pool"`, `connection.poolSession` and `connection.poolExitIp` (the values the gateway
  returned in `X-ProxyX-Pool-Session` and `X-ProxyX-Exit-IP`), and `proxyUsed` as for any tier. The
  org key and the username are never stored.
- **Refusals.** A refused tunnel is `HTTP/1.1 <status> <cause>`. `auth_required`, `org_disabled`,
  `org_blocked`, `option_denied`, `port_not_allowed`, `destination_denied` and `org_budget` fail the
  page as `proxy_refused` (HTTP 502, `SCRAPE_PROXY_REFUSED`); the other causes (`org_capacity`,
  `cache_empty`, `no_healthy_ip`, `cache_unavailable`, `source_limited`, `lease_timeout`,
  `provider_timeout`, `provider_unavailable`, `provider_auth`, `upstream_error`) fail it as
  `unreachable`. `crawlx.proxyx.tunnel_refusals{reason}` counts them.
- **Block feedback.** With a control URL, a `429`, a challenge (`cf-mitigated: challenge`, a
  `/sorry/` redirect or a known challenge page on a `403`/`503`), the second consecutive plain `403`
  on a target, and a reset after the tunnel opened are posted to `POST /v1/block-signals`. The queue
  is bounded (1024 events); a full queue drops and counts the event; batches of at most 500 are
  posted by a background task that honors `Retry-After` on `429`, retries `5xx` a few times and
  counts the rest as failed. It never blocks a fetch. `crawlx.proxyx.block_signals{outcome}` counts
  `sent`, `ignored`, `dropped` and `failed`. The browser plane reports no signals.
