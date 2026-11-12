# Reference: crawl options and runtime behaviors

Detailed behavior of options that the [README](../README.md) only summarizes. Run
`crawlx <command> --help` for the authoritative flag list of the build you have.

Contents: [crawl order](#crawl-order) · [bounded source discovery](#bounded-source-discovery) ·
[response cache and development replay](#native-response-cache-and-development-replay) ·
[adaptive extraction descriptors](#scoped-adaptive-extraction-descriptors) ·
[MCP server](#mcp-server) · [compatibility clients](#compatibility-clients) ·
[compatibility flags](#compatibility-crawl-flags) · [JavaScript endpoint mining](#javascript-endpoint-mining) ·
[wordlists](#wordlists-and-stored-fields) · [captcha solving](#captcha-solving) ·
[proxy tiers and the ProxyX pool gateway](#deployment-proxy-tiers-and-the-proxyx-pool-gateway)

## Crawl order

Breadth-first (BFS) is the native default on every crawl entry path. It selects
shallower URLs first, with discovery order breaking ties. Depth-first (DFS)
selects the deepest pending URL first, with the most recently discovered URL
breaking ties. `priority` instead ranks URLs by depth and their attack-surface
score. An explicit request priority takes precedence over these orderings.

Select an order with native API JSON `{"scope":{"strategy":"depth_first"}}`,
`crawlx crawl URL --strategy dfs` (or `depth-first`), or a JSON `--config` /
`--request` file containing the same `scope.strategy` field. TOML configuration
uses `[crawl.scope]` with `strategy = "depth_first"`; YAML flag configuration
uses `strategy: dfs`. BFS accepts `bfs`, `breadth_first` and `breadth-first`;
DFS accepts `dfs`, `depth_first` and `depth-first`. Serialized requests retain
the canonical `breadth_first`, `depth_first` or `priority` value.

The explicit, opt-in `--compat-defaults` preset uses depth-first rather than
the native breadth-first default. An explicit strategy overrides that preset.

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

Streamed XML feed evidence uses bounded `reverse_batch_chain_v1` artifacts. Source-authored hints receive generic and run-scoped secret redaction before the worker attaches each generated `previous` artifact reference. The complete envelope still passes canonical secret approval and run-scoped checks; generated digests remain intact without exempting source-authored hexadecimal values.

Sitemap candidates, including namespace-checked hreflang variants, pass normal scope and robots admission. Discovery-enabled exploration acquires bounded sitemaps before focused HTML fallback. `probe` records actual selected article length/quality and insufficiency reasons. Category/domain heuristics never expand scope. Source requests and cursor advances commit together under the parent lease; a changed source representation cannot silently continue an old cursor.

`readMoreHops` and `mediaProbes` are opt-in worker acquisitions. Read-more follows explicit article intents, records separate original/final URLs and child artifacts, and stops on cycles or its hop allowance. Media probes inspect at most `mediaHeaderBytes` (at most 65536) and refuse dimensions above `maxMediaPixels`; they never decode a full image. Sitemap traversal, redirects, read-more and media work share the primary page's `acquisition.maxAttempts`, `maxNetworkRequests`, byte allowance and deadline. Configure sufficient shared allowance when enabling several auxiliary stages; a stage does not receive fresh retries.

The scrape `audio` and `video` formats download referenced media under auxiliary-resource admission, not frontier page-extension selection. Authorization origins and prefixes, explicit host/path/URL denials, robots rules and egress checks still apply to every download and redirect.

Choose teaser links with `extract.content.selectors.readMore`, for example `[{"kind":"xpath","expression":"//a[@class='teaser']/@href"}]`; these selectors only produce parser references. The worker's independent `readMoreHops` policy controls acquisition. ZDR source discovery also requires the protected worker request-identity key; missing key is `CapabilityUnavailable`, never a public-seed-derived correlation fallback. ZDR source cursor receipts use the shared volatile retention boundary.

External providers have no built-in endpoint or fallback. Add `scope.discovery.connectors` with explicit `provider` (`news_search`, `trends_search`, `web_archive_index`), authorized `endpoint`, and CDX `archiveBase` when needed. Enable the corresponding source (`news_search`, `trends_search`, `archive`). News accepts RSS/Atom and recorded `garturlres` results; trends accepts daily-trends JSON or RSS; archive accepts a CDX JSON table. Archive provenance keeps original URL, replay URL, capture time and optional recorded original status separate from the provider's HTTP status. Missing providers return `ProviderUnavailable`.

Cache-only/development replay never requests robots, sitemap, provider, conventional, media or read-more resources. Missing retained responses return `cache_miss`; explicit external-provider requests fail as `ProviderForbiddenInReplay`. Reprocessed artifacts record current robots as unobserved, not approved. These are source/runtime contracts, not a claim of upstream service availability or live-provider certification.

`scope.discovery.articleMemo` defaults to `{"enabled":false,"maxEntries":20000}`. Enable it to suppress already-seen article candidates only after current scope, robots and authorization admission. The ledger keeps opaque hashes scoped to tenant, run, source, role/request credentials and effective policy. Capacity applies across all scopes in the run, with a hard ceiling of 100000 entries and deterministic oldest-record eviction. Entries are recorded only after successful frontier append. A crash between append and memo recording can repeat a proposal; the frontier's existing identity still prevents duplicate accepted requests.

`scope.discovery.categoryCache` defaults to `{"enabled":true,"ttlSeconds":86400}`. Its key also pins the source representation. Worker-clock expiry is exclusive: an entry is unavailable at its exact deadline. TTL can be 1–604800 seconds and cannot extend source/artifact retention. Setting `enabled:false` bypasses both cache reads and writes. Category URLs pass existing privacy/artifact gates and remain proposals, never cached permission. ZDR stores all seen/category hashes and references only in volatile custody; a durable run-only generation fences reset without retaining content-derived metadata.

Authenticated `DELETE /v1/crawls/{id}/source-memo` requires `crawls:write` and ownership of the run. It clears all seen/category scopes and returns `{"reset":true,"frontierUnchanged":true}` with `Cache-Control: private, no-store`. Reset permits fresh memo admission but does not erase queued/completed frontier requests, rewind source cursors or change request identities. The settings importer maps `memorize_articles`/`memoize_articles`, `max_file_memo`/`MAX_FILE_MEMO`, and `disable_category_cache`; it explicitly refuses legacy `use_cached_categories` and imperative `clean_memo_cache`. Conversion never performs a reset.


### List discovery, URL substring filters and the language hint

`scope.sources: ["url_list"]` with `scope.discovery.urlList: {"urls": [...]}` crawls a caller-supplied list. The list is inline, at most 10000 URLs of at most 4096 bytes each and 4 MiB in total. Every entry is a credential-free HTTP(S) URL without surrounding whitespace; a blank, padded, non-HTTP(S), credentialed or unparseable entry refuses the whole list instead of being skipped. Fragments are dropped, exact duplicates are removed and first-seen order is kept. Resolution (`UrlListSourceV1::resolve`) is pure: it yields one `listed_url` discovery intent per unique URL and the sorted known-URL set, and refuses a list with more unique URLs than `maxKnownUrls`. Reading a file or standard input is the caller's job; the type holds no path. A listed URL is only a candidate: scope, robots, authorization and checked egress apply to it like any discovered URL. The `url_list` source and the inline list must be configured together (`SourceDiscoveryPolicyV1::validate_sources`).

`scope.discovery.urlLanguageHint` (an ISO 639-1 code, optionally with a region such as `pt-BR`) orders candidates: `SourceDiscoveryPolicyV1::language_rank` returns `1` for a URL whose language markers all name the hinted language, `-1` when they all name another language and `0` otherwise. Markers are the first host label of a host with three or more labels, the first path segment, and the `lang`, `language`, `hl`, `locale` and `lng` query values. The hint never admits or denies a URL and is not evidence of the language of the content behind it; the extraction `targetLanguage` quality gate stays the only language decision. Omitting the field leaves the serialized policy unchanged.

The settings importer translates the precision-text `--url-filter` (CLI dialect) to `scope.urlInclude`: each substring becomes an escaped literal pattern, so it matches that text anywhere in the normalized URL (case-sensitive; scheme and host are lowercase). Composition with scope is the native one for any include pattern: explicit denies (`urlExclude`, `excludePaths`, host scope, `excludeHosts`), robots, authorization and egress run unchanged and always win; the filter only narrows, so a candidate must also match one substring; the crawl seed is exempt. At most 64 non-blank substrings of at most 256 bytes are accepted, and regular-expression syntax is not interpreted. With a discovery mode and a target language the importer also sets the language hint above. A manifest may carry an inline `urlList` array (up to 10000 entries, outside the generic 256-entry array bound); it becomes the list source and, without a `url` option, its first URL is the seed. It cannot be combined with another discovery mode in one import. `input-file`, `urls-from-file` and `urls-from-stdin` are reported as `external_required`: the caller reads the file or standard input and supplies the entries as `urlList`. Every other option without a complete native mapping is reported with its pinned inventory rows in `features`, never accepted silently.

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

Acquisition-service and HTTP identity-profile selections never enter the reusable native response cache: a cache-only request that selects one fails explicitly rather than reading a warm entry. The native cache key also includes these selectors as defense in depth. No profile cache-hit behavior is measured or claimed.

Missing retained content is `stored_body_unavailable` (`STORED_BODY_UNAVAILABLE` on the facade), not permission to fetch during offline replay. ZDR never creates a durable response cache. For an exact existing local artifact, use `crawlx replay-response RUN --frontier ID --tenant TENANT --identity SAVED_DIGEST --database-url URL --artifacts-dir DIRECTORY`; supply `--principal API_KEY_ID` for an API-owned source. This command reads committed retained content only and emits base64 JSON with explicit rendition/provenance. Existing `crawlx replay` remains browser-action replay.

## Scoped adaptive extraction descriptors

`PUT /v1/crawls/{id}/adaptive-selectors/{selector_id}` captures structure from a committed page's retained HTML. Its body supplies `page`, static selector-document `node`, `source`, `schema`, optional `expiresAt`, `threshold`, `runnerUpMargin` and `maxCandidates`. The server supplies tenant, principal and acquired origin. `GET` uses the same page/source/schema namespace. `POST .../{selector_id}/relocate` accepts `page`, `source`, `schema` and returns `recovered`, `ambiguous` or `not_found`. An ambiguous response contains no selected node. Static document nodes are never browser action locators.

Descriptors contain only bounded structural features, not page text, IDs or attribute values. PostgreSQL migration `0030_adaptive_selectors.sql` enforces tenant RLS, run ownership and fixed source-retention expiry. ZDR stores only lookup metadata durably; payloads use the existing shared volatile delivery buffer, whose original TTL never renews on update. HTML reads check ownership, sensitivity, expiry, byte bounds and artifact fixity before bounded CPU evaluation.

## Static selectors, item recipes, handlers and regex extraction

These are extraction-only, share one operation budget per document and never fetch or evaluate code.

- **CSS pseudo-elements.** A CSS selector in `selectors` or an item field may end each comma-separated selector with `::text` (the direct text nodes of every match) or `::attr(name)` (that attribute; the name may be quoted). Any other pseudo-element, or one placed mid-selector, fails admission with `unsupported selector syntax`; it is never an empty match. Include/exclude rules still require elements, so a projection there is rejected. XPath text, attribute and comment node tests give the same node kinds.
- **Item groups.** Field projection `group` selects base elements and evaluates its nested `fields` relative to each one (XPath context node, CSS descendants). `cardinality` decides object versus array of objects. A nested field's `source` may be `next_sibling` or `previous_sibling`, optionally restricted by a selector evaluated relative to the base's parent; no matching sibling means a missing value. Nesting is at most four levels and 256 fields per recipe. Each instance's outcomes are kept in the field's `groups`; defaults are marked `defaulted` per instance and a missing required nested field makes the item invalid. Final privacy projection recurses into `groups`.
- **Typed transforms.** `clean`, `regex` (`pattern`, `group`, `all`), `builtin` (`name`, `all`), `json_parse` and `limit`, plus the `attributes` projection (all attributes of an element as an object). The handler types in `crawlx_extract::handlers` use the same functions, so a handler chain and a recipe give identical output. JSON input is capped at 1 MiB and parse errors never echo input.
- **Regex.** One admission gate for recipes, custom fields, search and handlers: linear-time engine only, at most 512 bytes, 33 capture groups and 1 MiB compiled size; backreferences and look-around fail with a typed error before compilation. Extraction scans at most 8 MiB and keeps at most 1000 matches per pattern (`truncated` when more existed). Built-in names are versioned (`email.v1`; a bare name resolves to the newest revision): `currency`, `date_iso`, `date_like`, `email`, `hashtag`, `hex_color`, `ipv4`, `ipv6_full`, `mention`, `number`, `percentage`, `phone_like`, `sha256_hex`, `time_like`, `url`, `us_zip`, `uuid`. A changed pattern gets a new revision rather than an edit.
- **Element search.** `crawlx_extract::find` offers `find_all`/`find_first`/`filter` by tag, attribute, text and admitted regex, ancestor/sibling/child traversal, `find_similar` (fixed-point structural score, ties in document order), generated CSS and XPath paths, and abstaining outcomes (`Ambiguous`) where a single answer is required.
- **Decoding and markup text.** `crawlx_extract::decode::decode` picks an encoding from a byte-order mark, then the declared charset, then an early `meta` declaration, then UTF-8, and records the choice and up to 64 malformed sequences (offset and length) instead of hiding replacements. `markup_text` returns the cleaned text next to separately collected comments and CDATA payloads and the digest of the decoded source; comments never enter the cleaned text. In the extractor, `ExtractOptions::decode` (optional `declaredCharset`, else the `Content-Type` charset) routes `extract_bytes` through that decoder and fills `Document::decode`; `ExtractOptions::markup` (`comments`, `cdata`) fills `Document::markup` with the retained entries (at most 10,000 entries and 1 MiB) and the digest of the decoded source. The cleaned `Document` text is the same either way, and with both options absent extraction is byte-identical to before.
- **CDATA limit.** In HTML (outside foreign content) the tokenizer ends a CDATA section at its first `>`; a payload containing `>` is therefore reported as a comment, not as CDATA.
- **Read-more references.** `selectors.readMore` (union selectors allowed) yields unresolved `read_more_reference` intents; `selectors.readMoreBase` is `document` (default, honors a `base` element) or `page` (the acquired URL). Omitting it leaves the serialized policy and digest unchanged. The extractor issues no request; only the worker may follow a reference, under scope, robots and budgets.

## Extracted-content dedupe and URL exclusion

Both live on the native extraction policy (`extract.content`) and are omitted by default; omission leaves the serialized policy, its digest and every envelope unchanged.

`dedupe` (`blocks`, `content`, `minBlockChars`, default 16) records a `dedupe` report on the document envelope and enables up to two independent stages. The report holds separate `raw`, `page`, `main` and optional `comment` digests with the `normalization` (`dedupe_text_v1`: Unicode lowercase alphanumeric words, punctuation and whitespace runs removed) and `domain` that produced them, a 64-bit `mainSimhash` from the URL plane's similarity engine, block counts, and the exact scheme/host/port `origin`. The same main text under different page chrome has the same `main` and a different `raw` digest.

`blocks: true` removes a block (a paragraph, quote, list item, heading or table) from every output when its normalized text was already admitted, in document order, so the first occurrence is the one kept; blocks shorter than `minBlockChars` normalized characters are never compared. With `blocks: false` a repeated block is retained. `content: true` is a quality stage that runs after every other gate: the SHA-256 of the normalized title and body is admitted into the cache scope, and a later document with the same hash is rejected from ingestion with the quality reason `duplicate_main`. Its acquisition, text and origin stay recorded, `duplicateSameOrigin` states whether the first sighting had the identical origin, and `http`/`https` and `www` variants are never merged. A document rejected for any other reason is not admitted.

Comparison across documents needs a `DedupeHandle` on `ExtractOptions` (library use): a shared `DedupeCache` plus a `DedupeScope` of tenant, run/source namespace and role label. Entries are partitioned by that scope, the extractor id, the policy digest and the normalization version, hold 32-byte hashes and counts only (never paragraph text), are bounded (1 to 262,144 entries, least-recently-admitted eviction by a logical counter, no clock, no global state), and are admitted in call order: concurrent callers that need a reproducible result call in their ordered-commit sequence. Re-extracting the same page in one scope is a repeat; give a retry its own namespace. Without a handle only repeats inside one document are removed and no content duplicates are reported.

Content dedupe never bypasses URL admission. A sibling of a non-root seed needs `scope.crawlEntireDomain` or matching `scope.includePaths` before its acquisition can be retained and marked `duplicate_main`. An extraction-excluded seed also suppresses automatic sitemap and robots-path discovery; it must not trigger those requests before its refusal.

Leased runs use `ContentDedupeClaimV1` in the request result transaction, not a local-cache checkpoint as shared authority. Both normalized title/body SHA-256 and the report's distinct main digest are required. The hash-only registry partitions claims by tenant, run, role/session representation, extractor, policy and normalization; the first successful commit owns the canonical frontier ID and storage record time. Later commits persist `duplicate_main` receipts and reject accepted-item, state-delta and outbox publication atomically while keeping acquisition and immutable rendition evidence. Failed transactions consume no claim. `DigestRegistryRepo::digest_outcome` reads the exact frontier receipt, including after a worker restart. Registry rows contain no text, URLs, role labels or artifact references, are permitted in ZDR, and are erased with the owning run. Pure parse quality remains separate from the final ingestion rejection; no rejected article artifact is fabricated from an earlier accepted serialization.


`excludedUrls` (`substrings`, case-insensitive; `patterns`, regular expressions with the path-filter size and nesting limits; at most 256 rules of 512 bytes each per list) is compiled by `crawlx_url::UrlExclusionFilter` and evaluated by `crawlx_url::PreFetchGate::decide` (in front of the scope filter) before any request, robots lookup or DNS resolution: a match yields `PreFetchDecision::UrlExcluded` with the reason code `url_excluded` and the matching rule, and the URL costs zero target requests. This reason is separate from path-scope reasons and from the content-quality reason `author_excluded`, which applies only after a page was acquired and rejects its ingestion while the acquisition and its content evidence stay recorded.

Acquisition validation classifies a challenge page by structure (a challenge form or stage element with too little real content around it, or an authoritative challenge response header), never by words: an article that discusses interstitial pages or captchas passes, a keyword-only page passes, and a genuine 200 interstitial is excluded with the signals `challenge_structure_present` and `challenge_missing_expected_content`. Structural evidence exists only on the parsed document, so the HTTP crawl plane decides after parsing and before any page, item, link or dedupe claim is stored. Exclusion does not depend on `validation.onContentMismatch`: a challenge classified on a success-status HTTP response fails the URL as `content_validation_failed` (crawl) or `unsupported_content` (scrape) under the default `report` action as well as under `fail`, and no page is stored. `report` keeps compatibility documents only for other rejected content (wrong MIME, selector or length mismatch). Rendered browser pages record the same classification as evidence. Validation selects no fetch backend and changes no session.

## Content outputs: variants, fit content, tables and link scores

`ExtractOptions::outputs` (`ContentOutputOptions`, library use; every field is off by default and an absent option leaves `Document` unchanged) adds a `Document::outputs` report built from the one parse of the acquired page. Nothing is fetched.

**Variants.** `rawHtml` returns the input as acquired. `cleanedHtml` is the whole page after the element filter (scripts, styles, hidden elements and `excludeTags` removed) and before content selection. `Document::html`/`markdown` stay the selected content (main content, `includeTags` or `targetElements`). `fit` (a `FitFilter`) adds `fitHtml` and `fitMarkdown`, the selected content after filtering, plus a `fit` report (strategy id, kept and dropped blocks, operations spent). `citations` (`selected`, `cleaned` or `fit`) adds `markdownWithCitations`: each link becomes its text followed by `⟨n⟩` (links to one URL share a number) and a reference list `⟨n⟩ url: text` closes the Markdown. Every `citations[]` entry keeps its `index`, `url`, `text` and `linkIndex`, the position of the matching entry in `Document::links` (`null` for targets the list does not hold, such as `mailto:`). A privacy projection that rewrote the main text withholds the derived markup variants (`withheld: true`); other text outputs go through the same projection as the Markdown.

**Fit filters.** Both are integer-only and deterministic, never call a model and fail closed with a typed error when `maxOperations` (default 2 000 000) is spent. A *block* is a leaf block element; containers whose blocks are all dropped go with them.

- `{"strategy":"pruning"}` (`pruning_v1`): per block, permille components from text density, inverse link density, a tag prior, a class/id hint (whole-word boilerplate and content tokens, ARIA roles) and text length, weighted 300/250/150/150/150. Blocks under `thresholdPermille` (default 480) or with fewer than `minWords` words are dropped. Navigation, footer, aside and hinted containers are vetoed as a whole unless their aggregate score clears the threshold.
- `{"strategy":"bm25","query":"…"}` (`bm25_v1`): the blocks of the page form the corpus; blocks scoring under `thresholdMilli` (default 250) against the query are dropped. Tokenization is Unicode word segmentation, lower-cased, with a fixed stop list; the inverse document frequency uses a fixed-point `log2`, so scores are identical on every platform. `k1Milli` (default 1200), `bMilli` (750), `minWords` and `maxOperations` are the other parameters; a query without scoring terms is refused.

**Target elements and discovery scope.** `targetElements` (at most 64 CSS selectors of 1024 bytes; a malformed selector fails with `InvalidSelector`) narrows text, Markdown and HTML like `includeTags`. `discoveryScope` declares what `Document::links`/`assets` hold: `whole_page` (default, so narrowing the content never narrows discovery) or `selected` (only what the selected content references).

**Tables.** `tables: true` analyses every table of the selected content (`table_rules_v1`). Spans repeat the spanning cell's collapsed text into every slot they cover, fully empty rows are dropped, leading `thead`/all-`th` rows are header rows merged per column with ` / `. Each table reports its `kind`, its score components (shape, row consistency, header evidence, link share, nesting and block cells, fill, cell length) and, for data tables only, `header` and `rows`. A single-cell, empty, link-bar or nested-table-bearing table is `layout` (its nested tables are reported on their own with `parent`); a table whose evidence is weak (one row or column without header, header only, ragged rows, prose cells) is `ambiguous` and reports no rows. At most 256 tables are reported (`truncated` otherwise).

**Link and media scores.** `linkMedia` (`link_media_score_v1`) scores each link, image and audio/video element with *intrinsic* components (anchor text quality, URL shape, `rel` hints; alt text, declared dimensions, format) and *contextual* components (region such as main, navigation, footer; container link density; document position; heading proximity; figure context) kept separate, plus a combined mean and an `internal`/`subdomain`/`external` class against the page host. `maxPreviews` (default 0, at most 32) turns the best-scoring links into `PreviewIntentV1` requests for the worker to fulfil under its own scope, robots, egress and byte budget; targets that are private, loopback, link-local, local names or carry credentials are refused when the intent is created and listed in `refusedPreviews`. `link_media::project_head` projects the head bytes a worker fetched for an intent into title, description, language, canonical, image, site name and robots flags, reading at most the intent's budget and nothing after `</head>`.

## Parser pipeline

`ParserPipelineV1` (`crawlx_core::extraction`) is the one contract for turning bytes into content, and `crawlx_extract::pipeline::ParserPipeline::run` is its only executor. Static fetches, the scrape engine, settled dynamic DOMs, replayed bodies and uploads call the same entry and get one result type, `PipelineOutput`. Stages are fixed and ordered: `detect`, `decode_input`, `parse`, `select`, `metadata`, `quality`, `transform`, `project`; every run returns one record per stage (status `completed`, `pass_through` or `not_applicable`, with input/output counts and no content). Version one accepts exactly that list.

Format routing is explicit. `routes` maps each detected format name to `html` (the page extractor, which needs the page URL and honors the native content policy and quality gates) or `document` (the document parser for PDF, Office, EPUB, text, CSV and, for uploads, HTML without a page URL). The default routes every text-bearing format and sends `html` to the page extractor; `ParserPipelineV1::for_uploads()` sends it to the document parser. A detected format with no route is refused, never parsed by a fallback. Image formats are routed only when a caller adds them and supplies an OCR engine.

Limits narrow the underlying parsers' limits and refuse rather than truncate: `maxInputBytes` (checked before parsing), `maxNodes` (markup nodes or container entries), `maxDepth` (markup nesting, at most 512), `maxOperations` (the content policy's operation budget; a larger request is refused), `maxChildren` (links plus images, plus pages for documents) and `maxOutputBytes` (text, Markdown and cleaned HTML together). Page, slide and sheet counts keep the document parser's soft truncation with a warning. The pipeline digest and `record_version()` (`parser_pipeline_v1/` and 16 hex digits) identify stage order, routes and limits and are carried on every output, so a change of any limit or route changes the record version. Transport decoding (content-encoding, charset negotiation) happens before the pipeline; a byte-order mark selects UTF-8/UTF-16 and other invalid UTF-8 is replaced and reported in `warnings`.

## Feed rows, exporters, storefront recipes and link options

**Streaming feed rows** (`crawlx_url::feed_stream`). `FeedRowStream` reads any `Read` through one fixed chunk buffer and yields typed rows from XML item elements or CSV records, so memory is bounded by `StreamLimits` (`max_row_bytes` 64 KiB, `max_nesting` 64, `read_chunk` 8 KiB), not by the source size; `stats()` reports the peak bytes held. A `FeedTemplate` is declarative: for XML an item element plus fields that read an element's trimmed text or one attribute, each named by namespace URI and local name (prefix aliases are irrelevant; first occurrence wins; `required` makes a missing or empty value a malformed row); for CSV a delimiter, quote byte, a header row (optionally mapped column by column, unmapped columns dropped) or positional column names, and required fields. RFC 4180 quoting, doubled quotes, embedded line breaks, CRLF and a leading byte-order mark are handled; blank lines are skipped. `FeedTemplate::rss_items()` and `atom_entries()` are ready-made XML templates. A malformed row (misplaced quote, unterminated quote, wrong column count, missing required field, undefined entity, invalid UTF-8 in CSV, a row over `max_row_bytes`) is a `RowOutcome::Malformed(RowFault)` and the stream continues; broken XML structure (including invalid UTF-8), a `DOCTYPE`, a non-UTF-8 XML declaration, one XML event larger than `max_row_bytes`, nesting past the limit and I/O errors end the stream with a single `Err`. Only owned bytes are read: there is no entity table, DTD processing or resolver, so declared entities cannot read files or reach the network, and an undeclared entity never expands.

Every row carries a `StreamCursor` (byte offset, row index and a BLAKE3 digest of the consumed prefix) with a short text form (`fs1:<offset>:<rows>:<digest>`). `FeedRowStream::resume` over the same source yields exactly the rows after the cursor; the prefix is parsed again without retaining rows and the offset and digest are checked at the cursor's row boundary, so a changed or shorter prefix fails with `CursorMismatch` while a source that only grew keeps resuming correctly.

**Item exporters** (`crawlx_extract::item_export`). `write_item_with` writes one item as JSON, JSONL, CSV or XML with fixed rules: JSON object members and XML fields are in sorted key order, Unicode is written as UTF-8, CSV columns are sorted or an explicit `csv_columns` list (a field the item lacks is an empty unquoted cell, an empty string is `""`, `null` is `"null"`, nested values are quoted JSON), and every limit and policy check happens before the first byte. Policies are options, not defaults hidden in code: `csv_formula` is `PrefixEscape` (default; a cell a spreadsheet would run as a formula gets a leading `'`) or `Reject`; `xml_control` is `Reject` (default) or `Replace` (U+FFFD) for scalars XML 1.0 cannot represent; `xml_text` is `Escaped` (default) or `Cdata` (`]]>` is split across two sections; strings containing a carriage return stay entity-escaped; field names are always escaped). `serialize::write_item` is the default-option shorthand. The item exporters' command-line wiring lives outside this crate.

**Storefront recipes** (`crawlx_extract::recipe`). A `StorefrontRecipeV1` (plain JSON, digest-pinned with `compile_pinned`) maps locally supplied collection or product JSON to one item per variant: bounded dotted field paths (`a.b[0].c`), field kinds `id` (string or integer, emitted as string), `text`, `bool`, `decimal` and `minor_units` (integer minor units converted with integer arithmetic). A JSON floating point number in a decimal field is a typed fault, so prices are always decimal strings. Faults are per variant or product (`RecipeRejection`) and processing continues. Pagination is an explicit output: after each page the recipe may emit one `DiscoveryIntentV1` (`read_more_reference`) from a body field or an incremented page parameter; it must stay on the page's origin and is never fetched by the extractor. `extract_pages` merges separately supplied bodies in order and drops items that repeat an earlier id tuple. The recipe has no write path and no expression language.

**Link options** (`crawlx_extract::link_options`). `LinkOptions` compiles to a `LinkFilter`: `allow`/`deny` regexes on the absolute URL (linear-time engine, bounded program size), `allow_domains`/`deny_domains` (host and subdomains), `tags` and `attrs` to scan, `restrict_css` and `restrict_xpath` regions (unioned), `canonicalize` (fragment dropped, query pairs sorted), `unique` and `nofollow` (`Keep` or `Skip`). Order per occurrence: resolve against the effective base, keep `http`/`https`, drop the fragment, canonicalize, deny, allow, nofollow, de-duplicate; a link that matches an allow rule and a deny rule is rejected. Rules the engine cannot run safely (backreferences, look-around) are refused when the filter is compiled.

## MCP server

`crawlx mcp` is a Model Context Protocol server over stdio (newline-delimited JSON-RPC 2.0; revision 2025-03-26, downgrading to 2024-11-05). It offers ten tools (`firecrawl_scrape`, `firecrawl_map`, `firecrawl_search`, `firecrawl_crawl`, `firecrawl_check_crawl_status`, `firecrawl_extract`, `firecrawl_extract_status`, `firecrawl_parse`, `firecrawl_agent`, `firecrawl_agent_status`; the names are wire strings that existing agent clients call) as a thin client of a CrawlX API's `/compat/v2` routes: `--api-url` (`CRAWLX_API_URL`, default `http://127.0.0.1:8080`), `--api-key` (`CRAWLX_API_KEY`; sent as `Authorization: Bearer`, never logged), `--timeout-ms` (per HTTP request, default 120000), `--poll-interval-ms` / `--poll-timeout-ms` (waiting on extract and agent jobs). API errors come back as `isError` tool results; results are cut at 1 MiB. Client config: `{"mcpServers": {"crawlx": {"command": "crawlx", "args": ["mcp"], "env": {"CRAWLX_API_URL": "http://127.0.0.1:8080", "CRAWLX_API_KEY": "…"}}}}`. <!-- wire-compat -->

Existing client environment variables are also read as a fallback: `FIRECRAWL_API_URL` (after `CRAWLX_API_URL`) and `FIRECRAWL_API_KEY` (after `CRAWLX_API_KEY`). <!-- wire-compat -->

The parse tool (`firecrawl_parse`) reads the file path it is given on the machine running `crawlx mcp` and uploads the bytes to the API, so point `--api-url` only at an API you trust. <!-- wire-compat -->

## Compatibility clients

Existing client libraries and command-line clients that speak the compatible v2 routes use the same API: `crawlx serve --compat-keys --api-key acme=fc-<32 hex>` accepts an `fc-` key on `/compat`, and Python and Node client libraries, a command-line client and a document-loader integration run against it in `cargo test -p crawlx-cli --test sdk_python` (installs the packages from PyPI and npm, skips when they are unreachable). Base URLs per client (the Python client drops a path prefix and needs a `/v2/*` rewrite), the endpoints each integration calls and what does not work (tools that only speak the `/v1` routes): [`docs/integrations.md`](integrations.md).

Shape details of the compatibility API: `GET /compat/v2/crawl/{id}` adds `warning` when pages were robots-blocked or a stopped crawl found at most one page, and answers `expiresAt` while the crawl runs; `next` links only to another available page of stored results, otherwise it is null, including for running crawls. Poll the status route again to wait for more results. `POST /compat/v2/map` returns the `id` of its run; the `html` format is a full document; every `/compat/` answer has `Access-Control-Allow-Origin: *`, `X-Response-Time` and (for buffered bodies) a weak `ETag`. `compat.mode` (`CRAWLX_COMPAT_MODE`) is `strict` by default: a crawl that leaves `ignoreQueryParameters` unset keeps every query string and native webhooks are signed with both `Crawlx-Signature` and the compat signature header; `native_defaults` switches to the native query policy and `Crawlx-Signature` only.

## Compatibility crawl flags

The compatibility flags (a short-flag CLI dialect) map onto the request: scope (`--field-scope fqdn|rdn|dn|none`, `--crawl-scope`/`--crawl-out-scope` URL regexes, `--exclude-hosts`, `--strategy`, `--max-pages-per-host`, `--known-files`, `--extension-match`/`--extension-filter`/`--no-default-ext-filter`, `--no-js-endpoints`), filters (`--filter-similar[-threshold|-budget]`, `--content-similar off|simhash|tfidf|bm25` with `-distance|-threshold|-budget`, `--filter-page-type`), rate limits (`--rate-limit[-minute]`, `--host-rate-limit[-minute]`, `--concurrency`), fetch (`--max-response-size`, `--timeout` seconds, `--retries`, `--no-redirects`, `--proxy`), extraction (`--custom-field-config` YAML/JSON list of field definitions, `--detect-secrets`, `--form-extraction`/`--no-form-extraction`), browser (`--page-hooks`, `--page-load-strategy`, `--dom-wait-time` seconds) and output (`--display-out-scope`, `--jsonl` writing `results.jsonl`, `--field`/`--output-template` printing one line per value, `--store-fields DIR` wordlists). With `--request <json>` the flags override the file's fields. `crawlx worker --cdp-ws-url ws://… [--no-incognito]` attaches to a running Chrome instead of launching one.

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

### Structural discovery matrix and unresolved expressions

Header and HTML discovery is pinned by a golden construct matrix
(`crates/crawlx-extract/tests/fixtures/endpoints/matrix`, one fixture per
construct, run by `cargo test -p crawlx-extract --test endpoint_matrix`): the
`Content-Location`, `Link`, `Location` and `Refresh` headers; anchors and
`area` (including every URL of a `ping` list); `link`; frames, iframes and
`srcdoc`; scripts; image variants and `srcset`; `video`, `audio`, `source`,
`track` and `poster`; applets (comma-separated `archive`), objects and embeds;
SVG `href` and `xlink:href`; table, cell and body backgrounds; `cite`
attributes; `<base>`; forms; `meta refresh`; and `hx-*` / `data-hx-*`
attributes. Relative references resolve against the first `<base href>`; header
targets and script files resolve against the response's final URL. Entity-escaped
attribute values and backslash-escaped JavaScript strings are decoded before
resolution. Only GET endpoints without a body are fetch candidates: forms with
another method, `formmethod` buttons and `hx-post`/`hx-put`/`hx-patch` are
recorded as metadata and never submitted, and `method=dialog` forms produce no
endpoint. Binary bodies (declared or sniffed) are never mined; their headers
still are.

The AST miner never executes script text. When the URL position of a request
site (`fetch`, `Request`, client methods, `xhr.open`, `location`, `history`,
`window.open`, `WebSocket`, `EventSource`, `new URL`) holds an expression it
cannot resolve (a variable that is not a single constant, a call, a member
access, a conditional), `discover_report` returns a typed
`UnresolvedEndpoint` next to the endpoints: the matcher (`source`), the known
`method`, the `kind` (`variable`, `call`, `member`, `expression`), the byte
`span` inside the script text named by `origin` (`script_file`,
`inline_script`, `event_handler`, `nested_handler`), and `partial`, which is
true when an endpoint with a `:name` placeholder or a dropped unknown prefix was
still emitted. `DiscoveryOptions::max_unresolved` (default 1000) bounds the
list; the overflow is counted in `unresolved_dropped`. `discover_with` and
`discover_html` keep returning endpoints only. The behavioral vectors for the
JavaScript pass (strings, concatenation, templates, request sites, handlers,
parse failure, size cap, code that would loop or throw if it were run) are in
`crates/crawlx-extract/tests/fixtures/endpoints/js` and run with
`cargo test -p crawlx-extract --test endpoint_js_vectors`. Besides the 4 MiB
size cap, the AST pass refuses a script that nests more than 128 brackets,
prefix operators or right-associative operators (`=`, `=>`, `?:`, `**`) in
one statement, so hostile input cannot overflow the parser's stack.

## Wordlists and stored fields

`crawlx crawl` and `crawlx export` accept `--store-field qurl,key` (comma-separated,
repeatable) to select wordlist fields independently of `--field` and `--output-template`.
`--store-fields DIR` retains its directory meaning; `--store-field-dir DIR` is an alias.
Without an explicit selector, directory-only usage keeps the displayed/template fields.
With a selector but no directory, crawl writes under `<--output>/field_wordlists`; export
writes `field_wordlists` beside `--out`, otherwise beside the source report, otherwise under
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

Captcha solving is opt-in: `--captcha-solver-provider task-api` (`-csp` / `-captcha-solver-provider`, or `CAPTCHA_SOLVER_PROVIDER`; `task-api` is a task-based captcha-solving HTTP API) requires a key. Use `--captcha-solver-key-ref env://MY_CAPTCHA_KEY` or `file:///run/secrets/captcha-key`; `--captcha-solver-key` (`-csk` / `-captcha-solver-key`, or `CAPTCHA_SOLVER_KEY`) keeps a literal key only in process memory behind a transient resolver reference. Explicit key references override ambient keys. A key without a provider does not enable solving, and unknown providers fail. YAML configuration uses these long flag names. JSON requests use `crawl.captcha` with `provider`, `key_ref`, `endpoint`, `timeout_seconds` and `poll_interval_ms`; TOML wraps the request in `[crawl]`, so solver settings use `[crawl.crawl.captcha]`. Neither request serialization nor argument debugging includes a literal key.

The endpoint defaults to the provider's standard HTTPS API endpoint; `--captcha-solver-endpoint` accepts HTTPS or explicit HTTP IP-loopback fixture endpoints only. `--captcha-solver-timeout-seconds` defaults to 120 and bounds the entire solve, including response bodies; `--captcha-solver-poll-interval-ms` defaults to 1000. Task creation is never retried. Task mappings follow an MIT-licensed upstream's integration; see [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Tests use local fixtures; external provider availability and account access are not verified.

Captcha configuration requires an enabled browser plane; static-only crawls reject it. Callback delivery passes through the safety kernel as an `Unclassified` action, so the default `read_only` profile refuses delivery. Use `--profile test_environment` only for controlled targets you are authorized to test; configuring a solver never bypasses action admission.

Supported widgets are checkbox (v2) and score-based (v3) widgets with their enterprise variants, and two further challenge-widget families (A and B). The browser fills each detected widget's response fields and invokes only its recorded callback or v3 promise resolver; it does not submit a form. Direct form submission during callback delivery is refused. Each widget gets at most one billed attempt per document, including ambiguous failures. Callback delivery has a separate ten-second bound and observes crawl cancellation. Keys and tokens are redacted from observations, console output, traffic metadata, page HTML/JSON, and storage exports. Full response-body capture, screenshots, PDFs, and raw DOM artifacts are refused with solving enabled because binary or opaque content cannot be safely redacted.

Tests use controlled fixtures, not a live provider: `cargo test -p crawlx-browser --test captcha_transport`, `cargo test -p crawlx-browser --test captcha_widgets` (needs the pinned Chromium) and `cargo test -p crawlx-safety --test captcha`. An authorized operator smoke command is `CAPTCHA_SOLVER_PROVIDER=task-api CAPTCHA_SOLVER_KEY=... crawlx crawl https://controlled.example.test/challenge --mode dynamic --profile test_environment --limit-urls 1`; it needs a real provider account and a controlled target you are authorized to test.

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
  `org_blocked`, `option_denied`, `port_not_allowed`, `destination_denied`, `provider_auth` and `org_budget` fail the
  page as `proxy_refused` (HTTP 502, `SCRAPE_PROXY_REFUSED`); the other causes (`org_capacity`,
  `cache_empty`, `no_healthy_ip`, `cache_unavailable`, `source_limited`, `lease_timeout`,
  `provider_timeout`, `provider_unavailable`, `upstream_error`) fail it as
  `unreachable`. `crawlx.proxyx.tunnel_refusals{reason}` counts them.
- **Block feedback.** With a control URL, a `429`, a challenge (`cf-mitigated: challenge`, a
  `/sorry/` redirect or a known challenge page on a `403`/`503`), the second consecutive plain `403`
  on a target, and a reset after the tunnel opened are posted to `POST /v1/block-signals`. The queue
  is bounded (1024 events); a full queue drops and counts the event; batches of at most 500 are
  posted by a background task that honors `Retry-After` on `429`, retries `5xx` a few times and
  counts the rest as failed. It never blocks a fetch. `crawlx.proxyx.block_signals{outcome}` counts
  `sent`, `ignored`, `dropped` and `failed`. The browser plane reports no signals.

## Fixture ground truth and coverage counts

The run resource's `coverageSummary` and `/coverage` use the same action-context coverage
definition. Trusted exercise counts include distinct discovered keys, not raw execution rows.
Repeated exercises and exercises without a discovered key cannot inflate that count.

`groundTruth` is `null` on ordinary runs: runtime coverage never infers fixture completeness.
Fixture hosts can register a trusted `resources::FixtureGroundTruthSource` with
`AppStateBuilder::fixture_ground_truth`. The source is server-side, keyed by run id; it is
not an HTTP request field. Run ownership is checked before looking up fixture evidence.

`FixtureGroundTruth::from_manifest` accepts fixture-manifest JSON, the run's stealth profile,
and independently recorded trusted exercise labels. It filters non-actionable, unsupported
and profile-ineligible controls, deduplicates labels and intersects them with eligible controls.
The API computes `{fixture, keys, recall}` from that evidence; an empty truth set has recall
`1.0`. Fixture evidence is separate from the crawler's own coverage ledger.

## Streaming generic item export

By default, `crawlx dataset-export` reads UTF-8 JSONL objects from standard input and writes one
stream to standard output. `--format` accepts `json`, `jsonl` (the default), `csv`
or `xml`. JSON uses one array, CSV writes one header, and XML uses one versioned
`items` root. The exporter holds one bounded input row, not the complete dataset.
`--max-row-bytes` defaults to 1 MiB and cannot exceed 16 MiB.

CSV freezes the first object's sorted fields unless `--csv-fields` declares an
ordered projection. Missing cells are empty; undeclared fields fail when columns
were inferred. Spreadsheet formula prefixes are escaped. XML rejects invalid
control characters and escapes text. Executable object formats are not accepted.
Stdin export errors identify the one-based input row, including parser, row-size,
schema and serializer refusals. The error does not echo that row's content.
An error can leave partial output; publish a redirected file only after successful
completion. Redirecting content to a file is an operator retention choice, not a
zero-retention guarantee. Article-oriented `extract` formats remain separate.

Paired `--run ID --dataset NAME` selects authenticated committed-item export
instead of stdin. `--page-size` bounds keyset metadata pages to 1–1000 records.
Only `json_object_v1` and `document_item_v1` stores use the generic serializers.
Artifact reads bind the selected run and committed artifact identifier, enforce
content limits and reject redirects, including object-store redirects. Use the
article export path for article schemas. Export a terminal run for a fixed item
set; keyset iteration of a running run can include later commits.

## Offline archive QA difference evidence

`crawlx archive qa INPUT --tenant TENANT --out NEW_DIRECTORY --baseline PRIOR_DIRECTORY
--diff-images` retains optional screenshot difference PNGs alongside ordinary replay
captures. The retained report's `differences` map binds page ordinal and screenshot phase
to normal sensitive artifact references. Images inherit tenant, run, expiry and erasure
controls; JSON output never embeds image bytes. Zero-data-retention refuses the operation
before reading the archive or baseline.

`--diff-images` requires `--baseline`. Without a baseline, QA still reports
comparisons as unevaluated and exits `2`; it does not invent successful comparisons.
Create the parent of `--out` first. The output itself must be a new directory.

Black pixels mean equal decoded samples. Color channels show absolute differences,
including alpha changes; magenta marks pixels outside one image's dimensions. Missing or
truncated pairs produce no difference image and never become successful comparisons.
The existing measured-distance thresholds and QA exit codes remain unchanged: `0` means
all requested comparisons passed, `1` means a measured mismatch, and `2` means missing
baseline evidence. Each difference PNG is limited to 16 MiB, with 64 MiB total and
16,777,216 pixels per canvas.

The isolated replay listener supports authenticated single HTTP byte ranges on retained
successful resources. Closed, open-ended and suffix ranges return exact `206` bodies and
stored-byte digests; unsatisfiable ranges return `416`. Multiple or malformed ranges are
ignored, and `HEAD` never sends body bytes. Since URL mapping changes representation
bytes, origin validators cannot satisfy `If-Range`; those requests receive full content.
No request can use range selection to fetch a missing live resource.

## Exporting retained runs

`crawlx archive export RUN --tenant TENANT --database-url URL --artifacts-dir DIRECTORY
--out capture.wacz` reads a run from the database and decrypts sealed content through its
catalog. Configure its original artifact key provider. `--format warc` instead writes
a new bundle directory with its adjacent index and publication manifest.
Create the destination's parent directory first; existing outputs are never replaced.
`inspect` and `verify` accept either format and check fixity without live requests.

The local `report.json` input supports approved legacy plaintext artifacts, not
process-lifetime encrypted output from a file-only `crawlx crawl`. That process key
is gone when the crawl exits. Use a database run and a durable artifact key provider
when archives must be exported later. A markdown-only export has no HTML replay
entry point; retain HTML or decoded response bodies in the source run for replay.

`crawlx archive import INPUT --out NEW_FILE` validates and retains a local copy.
For a revisit whose baseline lives elsewhere, supply `--tenant TENANT
--dependency-root DIRECTORY --dependency relative.warc --dependency-sha256 SHA256`.
Repeat dependency files and their whole-file pins in matching order. Import
materializes an approved dependency closure into a self-contained WACZ.
No archive record URI grants filesystem access or a network fallback.

## Worker parser and extraction controls

Static page bodies, settled browser DOMs and retained-body replay use the shared versioned
parser pipeline. Page metadata records the parser record version and digest under
`parserPipeline`. Upload parsing uses the same pipeline with document routing for HTML.

Native `fetch.preflight` selects a bounded HEAD preflight through the checked fetcher;
`fetch.declaration` supplies MIME, charset and HTTP-status declarations, and
`fetch.oversize` selects `truncate` or `refuse`. Requests, redirects and preflights consume
the parent acquisition allowance when an acquisition policy is active.

`extract.content.excludedUrls` applies substring and regex exclusions before robots,
DNS or target requests. Denials use `url_excluded`, independently of post-acquisition
author-quality rejection. Content dedupe uses a bounded hash cache partitioned by tenant,
run and request representation. `endpointDiscovery` retains bounded unresolved expression
kinds and spans, not script source.

Local cache checks do not mutate committed state. A staged hash admission is recorded only
after successful page publication; failed commits cannot poison retries. Local resume
checkpoints preserve bounded hash-only scope, recency and eviction state under the existing
retention policy. Durable workers isolate block dedupe to each document and use the
transactional digest registry for cross-document decisions, so process-local cache order
cannot change the main hash or suppress an otherwise eligible candidate.

`extract.outputs`, `extract.decode` and `extract.markup` select the extractor's content
variants, byte-decoding diagnostics and retained comments or CDATA. Scrape requests expose
the same selectors as `outputs`, `decode` and `markup`; selected results appear in the
response's `outputs` object. These are content-bearing results and follow the existing
retention and secret-redaction rules. Preview intents do not grant network authority:
the worker rechecks URL scope, robots and checked acquisition on every followed hop.

Offline `crawlx extract` (and `crawlx corpus` and `crawlx protocol`) honour the same three
options. `--extract-config FILE` takes a JSON object of at most 64 KiB with the request's
`outputs`, `decode` and `markup` members; `outputs` is validated before any input is read
and unknown members are refused rather than ignored. Positional JSON arrays are refused
even when their entries match those three members. The results appear in the document's
`outputs`, `decode` and `markup` members, produced by the same extractor entry and options
an online run uses. `--request FILE` stays the native content policy
(`extract.content`), including `selectors.readMore` and `selectors.readMoreBase`; the
`--base-url` is the page base for `readMoreBase: "page"`, and no reference is ever fetched.

## Archive rollover and metadata-only requests

`output.archive.rolloverBytes` and `crawlx archive export --rollover-bytes` set an
optional hard encoded-byte limit for each WARC file inside WACZ. The limit must be
positive and no larger than `maxBytes`. A compressed record never splits between
files; an oversized individual record fails before package publication. CDXJ rows
name each actual file and file-relative range. The total archive bound still includes
all files, indexes, package metadata and ZIP overhead. Omitting rollover preserves
the original single-file layout and serialized configuration. Rollover with plain
WARC output is refused, not ignored.

Native request append and neutral request import accept anonymous, bodyless `HEAD`
requests on the static and hybrid HTTP queue. Checked redirects preserve `HEAD`.
The worker records a body-free `head_response` receipt instead of a page or item.
Metadata-only completion does not populate the GET-resume cache or claim a retained
response body. Volatile events retain their existing expiry; hydration does not renew
that lifetime or substitute durable content hashes for volatile references.

## Admitted write requests

Native request append also accepts `POST`, `PUT`, `PATCH` and `DELETE` on the static and
hybrid HTTP queue. A write batch holds only writes, acts as the `anonymous` principal and is
recorded in the audit trail under the calling API key; each write may carry a `body` (exactly one of `text`, `json` or
`base64`, at most 1 MiB, with an optional `mediaType`). Bodies are retained as
credential-bearing artifacts and referenced by a tenant-keyed digest, never stored in queue
JSON or listed by the metadata endpoints. Intake needs the operator request identity key (the
worker needs the same key to verify a body before sending it) and a run that is not `read_only`
and has orchestration attempt limits. Imports stay `GET`/`HEAD`.

Identity covers method, target, body digest, media type and principal: an identical write
dedupes, a different body, media type or principal does not. A write that names a role
principal is refused when the worker reaches it (`write_principal_unavailable`): a role acts
through its strict HTTP session, which writes do not use.

Queueing grants nothing. When the worker reaches a write it decides it with the same profile
table, `safety.destructiveActions` option and authorization-record narrowing the safety kernel
applies to observed traffic (`DELETE` is destructive, the other methods are persistent writes).
`read_only` refuses with `write_read_only`; other denials are `write_denied`. A class the
table gates on a reviewer (every `DELETE`, and any class the record lists in `approvalRequired`)
is sent only when the request carries `approval: {"riskClass": ...}`, which the API accepts only
from a key that also holds `approvals:decide`; without it the row is `write_approval_required`.
An approval never lifts a denial and cannot be reused for another body or target.

A write is journaled and sent at most once. After the verdict the worker verifies the retained
body (length and keyed digest), durably reserves one effect against the request's
`attempts.maxTotalEffects` (never refunded), commits a `request.write_intent` event, and only
then sends. The send is a single dispatch: no retry whatever the status, no redirect following,
no replay. The answer is recorded as a `request.write_outcome` event (status, content type,
size; no content). A row leased again after an earlier holder journaled its intent is never sent
again: that holder may have sent it before dying, so it ends `write_outcome_unknown` (counted in
`unknown_outcome`), as does a transport failure after dispatch. A missing or altered body ends
`write_body_unavailable` or `write_body_mismatch`. Resubmitting a write is a new request.

## Bounded browser evidence

`capture.browser` is opt-in and requires a browser-enabled crawl. Its `xhr` selector accepts
`urlPatterns` (`*` wildcard), `maxRecords` (1–5,000), and `maxBytes` (1–8,388,608).
The response projection preserves status, redacted headers, issuing page, capture order,
body artifact references and body-state reasons. It does not imply body retention:
`capture.responseBodies` and the response sink still decide which bodies may be stored.

`diagnostics` uses the same record and byte bounds for network and console metadata.
Unavailable console capture is distinct from an available but empty console. The stealth
profile never enables forbidden runtime domains to obtain console messages. Console
messages retain at most 4,096 UTF-8 bytes each. Projections report dropped records rather
than implying complete capture.
Byte budgets count serialized records and console strings, excluding fixed projection and
event envelopes; diagnostic network records and console messages share one byte budget.

`mhtml` and `pdf` retain generated browser representations through the policy sink.
MHTML is not original HTTP evidence; its completeness remains unknown even when the
browser reports no missing resources. Encoded image geometry comes from the actual
image. Full-page clipping remains explicit. `phaseResources` retains separate initial
and final rendered text and screenshots around session exploration, with observation
and epoch provenance. Evidence appears in `browser.evidence` events; bounded metadata
projections appear in `browser.projection` events.

`downloads` accepts at most 32 explicit `{url, maxBytes, timeoutMs}` requests.
URLs must be HTTP(S), without credentials or fragments; byte limits are 1–16,777,216,
and deadlines are 1–120,000 ms. Downloads use bounded in-memory response interception,
not caller-selected host paths. Filename traversal, oversize responses, policy refusal
and cancellation fail closed. Native browser downloads remain denied.
The retained final URL must match an explicit download entry; redirects do not widen
that allowlist.

Durable browser evidence is refused under zero-data retention. Encoded captures require
source privacy approval before capture and typed artifact approval before persistence.
Secret-bearing or uninspectable sources cannot silently become approved binary evidence.

CDP cannot recover the initial service-worker script request that precedes worker-target
attachment. Projections report `unavailableBeforeTargetAttachment`; selecting the proxy
preserves its wire observation. Worker-origin attribution and stream frames still come
from native CDP supplements, explicitly labelled separately from proxy observations.
Browser robots checks cover visited main-frame documents, not embedded frames or
subresources. Independent checked egress still governs those network requests.


## Safe dataset imports and resumable feed sources

`crawlx dataset-import inspect FILE` reports the bounded JSON export's provenance,
possible omissions and explicit backend or destructive-policy conflicts without
contacting a service. `dataset-import apply FILE` requires an API key, `--run`,
`--request-id`, `--fence` and `--state-version` for an existing admitted, leased
request. The authenticated API checks run ownership and current authorization,
then commits dataset/KV references under that live fence. Imports do not create a
second storage authority, load an exported filesystem layout, purge shared work or
deserialize executable object graphs. Arbitrary JSON objects use the declared
`json_object_v1` schema, not an extractor-specific article schema.

`crawlx feed-import FILE --format csv|xml --run ID --source ID --cursor-file FILE`
streams URL proposals into an existing open producer. CSV uses the `url` column
unless `--url-field` selects another; XML uses `item` rows unless `--item-element`
selects another, with optional `--namespace`. `--batch-size` is bounded to 1–128
and cannot exceed the run's queue limit. The server advances the pinned loader
cursor with each frontier batch; the local checkpoint is replaced only after
acknowledgment. Retrying a lost acknowledgment uses the same batch receipt.
Changed source representations or template policies cannot silently resume the
old cursor. Every proposed URL still needs normal worker scope, authorization,
robots and checked-egress admission before acquisition.

## Protocol capability reporting and archive operations reports

`crawlx protocol --probe` reports bounded local operator registrations without opening
target or service sockets. `networkProbed` and `liveAttested` remain false: a configured
capability is not proof of service health. With no registry, the delegate list is empty.
The opt-in `native_ftp` registration supports anonymous passive file reads with checked
control and data peers, finite reply/body/deadline bounds and cancellation. Target and
passive ports require explicit approval. Authenticated transfer, directory recursion,
persistent sessions and real encrypted-file-transfer interoperability remain unsupported
or unverified; no direct-network fallback is enabled.

`GET /v1/crawls/{id}/reports` lists the 21 operational reports with their source, scope,
supported filters, `notRecorded` and `withheld` fields and, for reports with measured
facts, a `facts` object (role `primary` or `companion`, default fact class, cursor names,
whether `crossRun` applies; `null` otherwise). It also lists `instrumentedFacts`,
`factCursors` and `maxFactsPerPage`. `GET /v1/crawls/{id}/reports/{report}` returns
authenticated, tenant-scoped retained facts as JSON or finite JSONL. `limit` is `1..64` and
bounds source rows (or, for fact-history reports, facts) scanned, including nonmatches.
Follow `next` even for an empty result page. Aggregates cover that scanned page, not the
whole run; pagination does not freeze concurrently changing state.

Raw URLs, hosts, event payloads, exception text and diagnostic text remain withheld.
Identity filters use the returned digests. `notRecorded` distinguishes missing
instrumentation from deliberately `withheld` data. It is the baseline of what a report
does not record; a returned page drops a field from it only when a fact on that very page
proves the field, and unmeasured fact fields stay `null`. Legacy runs without report facts
have none. Unsupported filters reject rather than approximating absent facts: each report
accepts only the filters its inventory entry lists, plus `after`, `limit` and `format`.
Reports obey ordinary retention and reject zero-data-retention content access.

The OpenAPI document mirrors this contract: one query schema per report in
`x-report-query-schemas`, finite fact, row, page and inventory schemas, and
`x-max-lines` of 129 for JSONL (at most 64 rows, 64 companion facts and one envelope).

## Dataset feed selection, batching and compression

Each declared feed binds an approved destination identifier, source dataset and
versioned serializer. `itemFilter.all` is an ordered conjunction of at most 16
value predicates: `{"kind":"present","field":"title"}` or
`{"kind":"equals","field":"keep","value":true}`. Equality values are bounded JSON
scalars, not executable expressions. Generic items expose their approved top-level
fields; article filters expose `title`, `text` and `comments`.

An HTTP-family destination is also checked against the run's egress policy at send time:
its port must be 80, 443 or the seed URL's port, and with an authorization record its
origin must lie inside the signed target. A registered destination outside that policy
is never sent to; its receipt stays `pending` and retries with backoff, and the worker
logs `provider_egress_policy_denied` (or `provider_egress_port_denied`).

`parameters.csvColumns` declares at most 64 unique CSV columns in wire order.
`parameters.jsonIndent` selects JSON indentation from zero through eight spaces.
Parameters used with a different serializer fail admission.
`batching:"per_request"` preserves immediate bounded delivery by default.
`batching:"terminal"` combines committed records into bounded immutable batches at
run finalization. `maxBatchItems` is always a cap, never an implicit delay.
Finalization seals dataset acceptance before scanning stable ordinals. Before writing
another artifact, a retry looks up the exact run, feed and idempotency key and reuses
the complete staged manifest, including its original `ArtifactId` and expiry. Changed
bytes or source ranges fail; expired, revoked or missing source custody never renews
the manifest or silently allocates a replacement.
Terminal batches are sealed artifacts. Finalization first claims the run's fenced
finalizer (one owner, an expiry, and a fence that rises on every claim), writes every
artifact as that producer and renews the claim while it works. A second worker sees the
claim as busy until it expires or is released; an expired owner can no longer write.
The claim survives a cancellation request or a reached deadline, because those are why
the run finalizes; purge, expiry and a revoked authorization record still revoke it.
Imported `json_object_v1` datasets use terminal JSON, JSONL, CSV or XML feeds.

`emptyPolicy:"skip"` is the default. `emptyPolicy:"emit"` emits a valid empty
serialized document at finalization if that destination selected no items. Its
manifest explicitly has an empty source kind; it does not invent accepted ordinals.
The final status and terminal delivery intents share the storage transaction.
TEI refuses `emit` because its schema requires a real document; use `skip` instead.

`compression` accepts `none` (default), `gzip`, `bzip2` or `xz`. Fixed compiled
codecs run on the shared bounded CPU pool after plaintext privacy approval.
Compressed output and codec state have independent hard bounds; manifests name
the actual compressed artifact and byte length. Terminal batching compresses the
completed batch once. Custom executable postprocessors are not accepted.
Zero-retention feeds retain their original volatile deadline and never acquire a
durable spool merely because a codec or destination was selected.
Structured search, stream and queue sinks refuse pre-compressed feeds before acquisition.
Workers advertise compressed-byte support separately from destination existence and ZDR
permission. API admission requires all three on one fresh worker and returns
`acquisition_capability_unavailable` when that combination is unavailable; direct worker
validation uses `feed_compression_unsupported_for_sink`.
Transport-level `Content-Encoding` is separate from feed compression.

## Approved declarative browser recipes

`crawlx flow-import inspect FLOW --id ID --version N` reports one disposition per
recorded source step without executing the source. `convert` emits a candidate only
when every required step maps exactly. Supported inputs are initial navigation, an
exact desktop initial viewport, targeted change and a single primary click.
Scripts, custom drivers or arguments, pre-page-script initialization and unsupported
viewport changes fail explicitly; conversion never grants tenant approval.

An operator registers bounded native recipes through `CRAWLX_RECIPE_REGISTRY` and
`CRAWLX_RECIPE_APPROVAL_KEY_REF`. Sign the registry with
`crawlx flow-import sign-registry REGISTRY --key-ref env://KEY_NAME`.
Local `env://` and `file://` key references require 32–4096 key bytes.
HMAC-SHA256 verifies the canonical registry payload in constant time, binding the
recipe pins, tenant approvals, approval ID and operator legal-review attestation.
No recipe code is downloaded or evaluated.

Scrape requests select an approved immutable reference with
`archiveBehavior: {id, version, digest, phase: "post_navigation"}`.
Admission verifies tenant, digest and timing before browser allocation. Execution
uses ordinary native actions, fresh locators, safety checks and the intent journal;
the first required failure or cancellation stops the recipe. Literal input values
do not enter recipe event summaries. Zero-data-retention refuses recipe execution
and content-bearing provenance.

Limits are 1 MiB per registry, 32 registrations, 256 approved tenants per
registration, 64 KiB per recipe and 50 native steps. Generic recipe support is not
evidence of site-specific behavior equivalence or a legal approval decision.

## Exported exchange fidelity

JSONL records include additive `fidelity` facts for request/response bodies and raw
representations. Availability is `available`, `unavailable` or `omitted`; omitted fields
remain distinct from evidence the capture backend could not provide. Representation,
redaction, binary UTF-8 loss and truncation come from producer facts. Unknown facts stay
unknown, including legacy rows without those facts.

Stored exchange files label reconstructed sections and unavailable payloads explicitly.
They are diagnostic representations, not original wire evidence. Missing HTTP status
does not become a successful response. Stored filenames use exclusive creation and
numbering, so repeated or concurrent exports cannot overwrite existing exchanges.
The ordinary field selector can remove `fidelity` as well as existing record fields.

## Operator-selected encrypted DNS

Worker and local crawl deployment configuration can select an HTTPS DNS endpoint:

```toml
[fetch.resolver_https]
endpoint = "https://resolver.example/dns-query"
bootstrap_pins = ["203.0.113.53"]
deadline_ms = 5000
max_response_bytes = 16384
max_records = 128
max_cname_depth = 8
```

The endpoint and pins above illustrate configuration shape; operators must supply
their own approved endpoint and actual bootstrap addresses. Environment equivalents
use `CRAWLX_FETCH__RESOLVER_HTTPS__` followed by the uppercase field name; pin lists
use TOML array syntax. `config check` validates the same settings. Incomplete or
invalid settings fail rather than falling back to unchecked resolution.

The provider connection uses approved bootstrap pins, checked address policy, TLS,
actual peer validation, redirect refusal and finite response/deadline limits.
Returned addresses still pass the ordinary per-run checked-resolution boundary.
Tenant request metadata cannot choose a DNS endpoint or weaken egress policy.
Plain HTTP is reserved for explicitly authorized owned-loopback fixtures.
Endpoint userinfo, query strings and fragments are forbidden; provider transport errors
remove URLs before entering diagnostics.

## Dynamic page records

Dynamic-only runs publish page records from settled browser observations, not from a
second HTTP fetch of the observed page. The observation epoch must still match when
the actor reads response metadata; intervening navigation refuses that publication.
Browser-discovered navigation URLs remain browser work rather than static fetch proposals.

Each publication claims only its observed frontier row with a fenced lease. Competing
publishers cannot claim the same row, and unrelated pending rows are not leased or charged.
Rendered HTML uses the shared parser, scoped dedupe and content-retention sinks. XHR
relations and discovered endpoint outcomes attach to the resulting page record.
The receipt-only claim verifies its originating live session fence, observation epoch
and immutable capture-time marker; it never permits another target dispatch. An
observation captured before the exploration deadline, including validated completed-login
credit, may finish publication after that deadline or during graceful worker drain.
New dispatch and observations captured after the deadline remain forbidden. A dedicated
local hard-stop token, durable cancellation, purge, stale fence or expired source custody
still refuses publication; graceful drain is not treated as hard cancellation.


Same-URL DOM changes append new observed renditions instead of rewriting terminal records.
The first rendition remains canonical for each role. Committed renditions appear in
frontier order, including content revealed by later actions. `dynamic.maxPageRevisits`
defaults to 8 and accepts 0–128 additional renditions per URL and role. Zero keeps only
the initial rendition. Storage enforces the cap across sessions and reports
`revisit_cap_reached` rather than silently dropping later observations.

## Strict sessions, resource retirement and admission

Native session identity binds tenant, run, principal, acquisition policy, actual browser
build, egress, profile and generation beneath the existing scheduler fence. A missing,
expired, unhealthy or colliding binding never falls back to another cookie jar.
`orchestration.attempts.maxSessionRotations` explicitly permits a finite number of
anonymous health/usage replacements; its default is zero. Replacement requires confirmed
cleanup, reconciled writes, unchanged identity and the original expiry ceiling.
Authenticated sessions and retained profiles never rotate implicitly.

Run-specific configuration refusal ends the affected run with `fatal_error`; the worker
continues serving unrelated runs. A local run rejected during account or session-context
admission is also finalized, rather than remaining queued for another worker.

`BrowserPool` retires processes after 1,000 context admissions, one hour of age or five
minutes idle by default. `PoolRetirement` configures finite operator bounds before the
pool is shared. Retirement stops new contexts but drains live actors first. Confirmed
owned-process death returns capacity. Inaccessible attached resources stay charged;
the pool never kills an unrelated attached browser to manufacture free capacity.

The Rust `NamedHttpSessions` API explicitly registers names under an existing granted
binding. Each name owns a lazy HTTP client, connection pool and bounded cookie jar.
Names, principals, generations and fences must match exactly. URL requests with a strict
generation use the explicitly registered `default` session and retain ordinary scope,
robots, authorization, effect, redirect and byte admission. Local static runs use the
same real coordinator lease as leased workers. Usage is reserved before transport and
survives cancellation; 401/403 affect health, while 429 remains governor feedback.
Learned cookies enter the existing run secret registry before content publication.
Cookie bytes remain volatile: a lost used jar cannot restart as an empty successful
session, and no implicit registration restores or extends its lifetime.

Strict ProxyX routes share one observed pin across HTTP and browser transports for the
same generation. A route-keyed commitment to the observed session and exit is stored
under the existing PostgreSQL session fence; a changed pin fails before tunnel delivery.
Changing the configured tier requires an explicit new approved session slot; anonymous
health replacement preserves the existing route identity.
Portable schema migration `0047` is also supplied for SQLite and MariaDB.
Checked resolved addresses additionally share a process-wide physical-target connection
cap across host aliases, ports and proxies. Origin pacing and deployment-origin admission
remain independent hard limits; physical grouping cannot grant additional traffic.

Adaptive runtime admission records CPU, memory, async timer lag, queue, spool, browser
and store observations. Missing sensors stay unknown. A measured timer lag of at least
100 ms narrows adaptive dispatch on the next sample without cancelling an active mutation.
Growth still requires five healthy ticks and never exceeds the existing hard ceiling.
`runtime.task` events report bounded elapsed time and observed process RSS before/after
each admitted URL task. These are process observations, not per-request allocation claims.

Run teardown invokes the traffic exporter's bounded shutdown directly. Its configured
drain deadline includes queued batches, stalled requests and retries; an unbounded flush
cannot precede that deadline.

## Sensitive archive evidence custody

Archives containing approved retained screenshot evidence remain sensitive. Package,
shard, adjacent-index, manifest and record content requires `artifacts:read_sensitive`;
ordinary crawl-read permission does not grant screenshot access. Progress metadata
remains redacted.

Source descriptors bind artifact ownership, digest, class, media type and deadline.
Archive custody narrows to the earliest approved source deadline and never lengthens
sensitive retention. Commit, publication and later content reads recheck live source
authority. Source expiry, revocation or changed authority fails closed, including after
publication. Ordinary content-only archives retain their existing access contract.
This narrow producer-approved screenshot path does not authorize arbitrary binary
capture, profile storage or general binary archive import/replay.

## Browser popup accounting

`dynamic.maxTabs` bounds admitted tabs. The target graph also permits at most one
unaccepted pending popup while the actor performs journaled admission or eviction.
Further targets are rejected and sent for closure instead of accumulating in that graph.
Chromium creates a popup before reporting its target event, so this is an admitted-tab
plus one-quarantine accounting bound, not a claim that the browser can prevent every
transient target allocation before notification.

## Committed archival payload deduplication

`output.archive.dedupe` accepts `none` (default), `collection` or `tenant`. Collection
mode reuses committed earlier payloads within the same export; tenant mode can also
use an eligible published export. The default is omitted from serialized configuration
and preserves existing specification hashes.

Deduplication preserves every chronological capture and its record identity. A
revisit must resolve to a committed payload with matching principal, request/policy,
representation, redaction, MIME and retention context. Failed uploads, expired sources,
foreign tenants and sensitive source packages never become ordinary content baselines.
Indexed lookup is bounded and deterministic. Source erasure or authority changes
invalidate dependent content; omission and incomplete-capture reporting stay explicit.

## Anonymous staging and recoverable WARC bundle publication

Archive members, index spill runs, pages, capture facts, import rewrites and package
scratch data use held anonymous file descriptors. Process death releases those
sources without leaving named plaintext scratch files. Unsupported filesystem
capabilities fail closed; untrusted imports gain no filesystem or magic-link authority.

WACZ remains one atomically published file. Multi-file WARC output uses a new
directory with an exclusive `.incomplete` sentinel. Each file is created without
overwrite and synced; the fixity manifest is written last. The sentinel is removed
only after successful completion and directory sync. Readers, import and
`crawlx archive verify` refuse a sentinel-bearing or incomplete native bundle.

A private per-user state journal, mode `0600`, records publication ownership; it is
not stored in the output directory. Startup recovery and `admin sweep-retention`
act only on proven owned crash leftovers, never active or foreign publications.
A missing, partial, invalid or mismatched manifest causes rollback of the owned
uncommitted directory. A complete manifest with every listed length and digest
matching rolls forward by removing the sentinel and syncing the directory.
An absent journal requires no writable home or new state files during startup.

## Safe single-page commands and immutable configuration

`crawlx scrape URL` accepts GET or HEAD. `--output-format html|markdown|json`
(`--output` alias) selects output; `--css`, `--xpath`, `--regex`, `--regex-builtin NAME`
(a built-in pattern such as `email` or `email.v1`, reporting its own capture group) or
`--extraction FILE` select bounded extraction. GET JSON output requires extraction before network I/O.
HEAD returns body-free JSON metadata and refuses body extraction or non-JSON output.
An extraction file is declarative JSON, for example:

```json
{"type":"css","expression":"h1::text"}
```

`{"type":"builtin","name":"email"}` selects a regex built-in the same way.

`crawlx shell URL` uses one admitted acquisition, then accepts `css EXPRESSION`,
`xpath EXPRESSION`, `regex PATTERN`, `builtin NAME`, `item INLINE_ITEM_LOADER_JSON` and `quit`.
Robots requests are separate admission traffic; permitted redirects share the
acquisition allowance. No REPL command adds network access, code evaluation or
process execution. The stored page is capped at 1 MiB; each command at 64 KiB;
session input and output at 1 MiB each; the session at 128 commands.

Configuration precedence is defaults, `--tenant-config`, `--config`, `--request`,
then explicit flags. Tenant defaults select method/output/extraction only, never
crawl authority. Native crawl overrides are restricted to supported typed sections;
they cannot replace the explicit URL. Unknown fields, forbidden types and unsupported
aliases fail explicitly. Each run owns its normalized immutable configuration.

## Reviewed lifecycle and rule recipes

An optional versioned `extensionRecipe` contains finite `startRequests`, the reviewed
request/parse/item pipeline, closed `actorActions` and ordered HTML/sitemap rules.
The immutable id/revision pin covers every setting and rule position. CSS/XPath
restrictions and bounded URL expressions select the first exact registered handler;
global deny predicates take precedence. Nested sitemaps and language alternates
remain proposals requiring ordinary authorization, scope, robots, checked egress
and acquisition budgets. Actor recipes additionally require operator-registry approval
and execute through the safety kernel and action journal.

Typed lifecycle results distinguish continue, annotations, skips and failures.
Header policies run before body consumption. Error, skipped/failed, terminal,
checkpoint and close callbacks preserve their ordered attempt receipts and sticky
policy denial. Accepted-item references use bounded backpressure, not a lossy
diagnostic channel. No arbitrary callback, dynamic loader, eval or raw browser handle
is accepted.

## Operational facts, queue advice and offline migration

History records typed measured processor durations, DNS outcomes, alerts, wire bytes
and counted losses under the existing tenant/run/fence authority. Missing facts remain
unknown; retained and withheld values remain distinct. Bounded filtered keysets are
not silently presented as whole-run aggregates. URL link graphs use separate versioned
policy/model pins and privacy-safe handles, never browser action-graph identities.
Advisory queue partitions and fairness only narrow the existing governor. Adaptive
revisits use injected time and committed representation baselines; failed index or
delivery work cannot mark an item delivered.

`source-import inspect` and `source-import convert` accept bounded declarative JSON,
including `neutral-export-v1`. Input is limited to 1 MiB, nesting depth 20 and 1000
seeds; the normalized output, including every configuration, recipe, cloned command and
report row, is capped at 16 MiB and checked before anything is written, so a conversion
never emits partial output or truncated seeds. Every setting receives an explicit disposition.
Checkpoint exports preserve native producer epochs, keyed source identity, cursor
transitions and transactional retry receipts. Source code, executable callbacks,
unsafe object graphs and undocumented binary formats are not executed or guessed.
The authenticated `POST /v1/crawls/{id}/requests/import` API accepts `format: "checkpoint_export_v1"`; the checkpoint export owns cursor transitions, so omit outer `expectedCursor` and `nextCursor`.
Pinned differential contracts check URL, schema and item-count assertions. Independent
source-runtime parity, licensed resources and unavailable reference services remain
`external_required`.

## Optional bounded model content

`contentStrategy` selects `nativeV1` or explicit `modelV1` table/content extraction.
Native omission does not call a provider. Model selection requires external-processing
consent, finite output-token and response-byte caps and prompt/output privacy
projection; ZDR refuses this strategy. `modelContent` is generated output, not native
source evidence, and never supplies navigation or action authority. Missing, refusing,
over-limit or unsupported providers fail explicitly rather than returning native
success for a requested model result.

## Acquisition selectors and operator services

`fetch.identityProfile` selects the hexadecimal digest of the installed pinned
Chromium-derived profile. It requires native static acquisition and rejects conflicting
headers, user-agent, TLS overrides, preflight and acquisition-service selection.
The profile binds its build, session generation, transport and cache identity.
Unsupported protocol or generation transitions fail closed. This profile does not
claim exact wire equivalence with Chromium; provenance and transitive notice hashes
are recorded in `identity-profile-provenance.json`, with distribution approval still
`external_required`.
Owned wire fixtures observe ordered TLS and HTTP/2 fields. The pinned Chromium
reference has additional post-quantum signature algorithms, extensions and compression
behavior that this native profile does not provide. HTTP/3, rotating routes and
exact-wire requests fail closed; no JavaScript or challenge-bypass equivalence is claimed.

`fetch.acquisitionService` selects an operator-registry id, never a tenant endpoint.
The existing registry accepts `acquisitionServices` containing `endpoint`, `audience`,
`buildDigest`, `guardDigest`, `capabilities`, `credentialRef`, `maxConcurrency` and
optional `caPem` and `serviceNetworks`. The registry is capped at 64 KiB and 16
services; ids are at most 128 characters. The service backend cannot mix with other
backends or fall back silently. Tenant approval and external-processing consent
remain mandatory; ZDR additionally requires declared zero retention.
This version performs one read-only target request. Redirects, subresources, custom
headers/cookies/user-agent, validators, preflight and prebody callbacks are refused,
not silently discarded. Target and gateway status remain separate; a missing legacy
final URL remains unavailable. `serviceNetworks` constrains service connectivity,
never target authorization or private-network checks. Live credentials, service
deployment and independent guard acceptance remain external requirements.

## Local interactive profile control

The data-free loopback UI shell needs no bearer credential; every control command
still requires authentication, exact Origin/Host checks and the shared local worker
registry. The API and worker must share that registry instance; this is not remote
browser control. Manual mode uses a fresh incognito context, skips automatic login
and checkpoint/profile restoration, and has its own cancellation token.
Commands re-verify the live binding generation, fence and authorization through an
actor round trip. Inputs use fresh observation, keyed proposals, safety decisions,
durable approval when required and the action journal. Finish exports bounded
structured storage, commits encrypted custody, confirms actor shutdown and only
then acknowledges the committed generation. Unproven screencast frames stay suppressed.

This control requires library embedding: share `InteractiveProfiles` with the API
state builder and the local worker. Separate `crawlx serve` and `crawlx worker`
processes do not provide this registry. Their interactive endpoints refuse the
operation explicitly; they never return unproven screencast pixels.

## Retained-source reparse

`crawlx reparse` operates on an approved retained source and the original tenant,
principal and retention scope. A completed run still requires its original frozen
secret-registry snapshot; expired or lost authority fails closed. Output records new
parser provenance and explicit loss/truncation outcomes. It does not refetch, navigate,
or persist replacement crawl results; its machine-readable output declares
`networkRequests: 0` and `persisted: false`.

Retained browser profiles are selected with `dynamic.browserProfile` (`name`,
`saveChanges`, `generation`; CLI `--browser-profile`, `--browser-profile-discard`,
`--browser-profile-generation`). Generation `0` starts a new namespace and is refused
when one already exists; `N` restores exactly generation `N` or fails, never an empty
fallback. With `saveChanges`, a normal session end commits generation `N + 1`.
Retained profiles require a non-ZDR run, operator retained-profile approval,
PostgreSQL, the run secret authority and durable artifact keys (`CRAWLX_ARTIFACT_KEY_FILE`
or a key service; in-memory keys are refused). A profile is confined to the seed origin.
Restored web storage is verified after the first navigation; a commit is refused when it
was not, and a page that rewrites its storage before that check fails the session closed.
The compatibility scrape body carries no generation and always starts a new namespace.

Terminal archive exports require a frozen-epoch source proof. They seal even after the
live secret registry is lost and do not claim a final-epoch rescan. Terminal runs without
settled authority fail closed; there is no plaintext fallback.

Authenticated API and CLI operator evidence, login-flow and archive replay saves remain in
custody mode `ReadOnly`: `SecretFree` and retention-gated plaintext writes. They read sealed
artifacts through the catalog. Worker producers and terminal archive exports are encrypted;
this documented operator-input boundary introduces no API producer leases.

Operational report percentiles describe only the filtered page returned by the
query, not the whole run. A DNS observation does not imply a scheduled recheck.
URL graph persistence requires the stable protected request-identity key; absent
that key, graph evidence is unavailable rather than using unkeyed URL hashes.

## Measured report history

Workers record typed, fenced report facts under the producing request or session lease:
DNS outcome and duration, processor stage identity, version, outcome and monotonic
duration, measured wire bytes, allowlisted alert severity/code/context, counted
observation loss and pipeline checkpoints. Facts carry opaque URL and host keys only; raw
URLs, hostnames, headers, payloads and error text are never stored. Missing measurements
stay `null` and appear under `notRecorded`; intentionally hidden fields stay `withheld`.
Retained runs store facts until the run's fixed retention deadline; ZDR runs keep them only
in the volatile delivery buffer and never expose them through reports or cross-run history.

The `hostKey` returned by `hosts` and `frontier` is the same identity used by DNS
facts and by newly recorded URL-attempt wire, processor, pipeline and alert facts.
Use it unchanged in their `hostKey` filters. DNS facts identify the host actually
resolved; other attempt facts identify the requested URL's host. Older facts that
did not record a host remain unassociated; no historical measurement is invented.

Reports `history`, `wire_history`, `processor_history`, `pipeline_history`,
`host_dns_health` and `alert_log` page facts with `after`/`next`; their rows have
`rowType` `fact` (a repository `sequence` and the typed `fact`), their `source` is
`report_history` and their `aggregationScope` is `facts_page`. Legacy reports such as
`frontier`, `hosts`, `processor_failures`, `error_log`, `mime_status`, `uri_log`, `events` and
`crawl_log` keep their source rows and add a companion fact page (`facts`, at most 64
entries; `rowType` `companion_fact` lines in JSONL) with its own `factsAfter`/`factNext`
cursor and an optional `factKind` (default: the report's own class). `history` accepts
`kind`; the other fact-history reports have a fixed class and reject it.

Filter allowlists: `history` takes `kind`, `urlKey`, `hostKey`, `since`, `until`,
`minDurationUs`, `maxDurationUs`, `minWireBytes`, `maxWireBytes` and `crossRun`;
`wire_history` the same without `kind` and `crossRun`; `processor_history` and
`host_dns_health` only `urlKey`, `hostKey`, `since`, `until`, `minDurationUs`,
`maxDurationUs`; `pipeline_history` and `alert_log` only `urlKey`, `hostKey`, `since`,
`until`. Companion reports add `factsAfter` and `factKind` to their source filters. Fact
filters apply before the 64-row limit. For fact-history reports `since` and `until` are both
inclusive; legacy page and event sources keep `until` exclusive. `crossRun=true` on
`history` returns the caller tenant's retained timeline only. `factsPage` gives per-kind
count, exact nearest-rank p50/p95 and checked wire sums for the returned page only. `threads`
remains unavailable: no live thread facts are measured.

Index and completion checkpoints succeed only when every delivery outbox row of the request
is acknowledged under its fence, in the same transaction; a failed delivery never reports
completion, and only a later genuine acknowledgement recovers it.

## URL graph and advisory scheduling

The URL graph is separate from browser action state and from the frontier. Edges and
anchors use keyed per-tenant/run handles; ranks are bounded, deterministic and bound to the
graph policy and model digests, so a policy or model change invalidates them. Graphs are
retained-only and expire with the run.

Advisory host, operator-domain and checked-address partitions add bounded per-queue quotas
and round-robin fairness in front of the shared origin governor; they only narrow dispatch
and never replace robots, scope, authorization or governor limits. Scheduling never changes lease
ownership: a row of the held batch whose queue is not yet eligible stays leased to its worker,
which waits in place (cancellable by the cancel and drain tokens, re-reading the lease, budget and
authorization at least once per lease heartbeat period) and is never returned to `pending`; only
lease expiry, a drain hand-back or the failure paths release it. Domain grouping uses only
operator-supplied suffixes, never inferred public suffixes. Drain accounting records actual
in-flight overrun, keeping unknown drop times distinct. Adaptive revisit policies derive the
next interval from measured change, unchanged and error outcomes within finite minimum and
maximum bounds; hard denials never schedule a revisit. Metadata inheritance copies only a
bounded public label, never routes, headers, principals or cookies.

## Scope, local resume and acquisition controls

Host scope is not path scope. Unless `scope.crawlEntireDomain` is true or
`scope.includePaths` selects other paths, a non-root seed stays under its seed path.
For example, a crawl seeded at `/docs/` does not fetch `/blog/`. Configure the JSON
request with `"scope":{"crawlEntireDomain":true}` to explore sibling paths; host,
exclude, robots, authorization and egress rules still apply. `--no-scope` disables
only host scope, not these other rules. Include patterns narrow discovered URLs;
the seed can be acquired to discover links without becoming an output page.

`--resume FILE` saves pending URLs and visited progress when an in-memory crawl
stops at its URL limit, deadline or cancellation. Invoke the same seed and policy
again with that file, raising the stopping limit when needed. Finished progress
deletes the file. Multiple seeds use one versioned envelope, skipping seeds that
already finished. Resume restores URL progress, not browser state or response-cache
bodies; it does not recover the sealed objects of a prior ephemeral artifact store.

Native JSON `fetch` options also accept these bounded acquisition controls:

```json
{
  "fetch": {
    "preflight": {"maxContentLength": 1048576, "contentTypes": ["text/html"]},
    "declaration": {"contentType": "text/html", "charset": "utf-8",
                    "statuses": {"allow": [404], "deny": [500]}},
    "maxResponseBytes": 1048576,
    "oversize": "refuse"
  }
}
```

Preflight sends a bodyless HEAD before GET and refuses a declared length or MIME
outside its bounds. It shares the GET acquisition allowance. `oversize` is
`truncate` (default) or `refuse`; truncation marks the bounded prefix. Response
declarations select decoding and status treatment; they never authorize a URL.
`crawlx scrape URL --method HEAD` emits body-free JSON metadata; body extraction
requires GET. A redirect must remain inside the admitted scope, even for HEAD.

HTML above 1 MiB normally uses a resource-limited parser helper. A helper failure
is separate from the fetch byte cap and from the shared parser admission budget.
Operators can set `CRAWLX_PARSER_HELPER_ADDRESS_SPACE_BYTES` (default 512 MiB),
`CRAWLX_PARSER_HELPER_CPU_SECONDS` (10) and `CRAWLX_PARSER_HELPER_TIMEOUT_MS`
(15000). Debug executables can need more address space than release executables.
Increase only the required limit within the container's total memory budget;
concurrent helpers add their address-space ceilings to parent memory.

## Reproducing the crawl maze

Build `crawlx`, `gym-server` and `crawl-maze-score`, then run
`gym-server --bind 127.0.0.1:0 --claim-origin g32`. Create the local authorization
record from the walkthrough with the printed origin and run:

```sh
crawlx crawl http://127.0.0.1:PORT/g32/ --mode static \
  --authorization-record authz.local.json --allow-private-networks \
  --known-files all --no-default-ext-filter --seed 20261019 --output maze-out
curl http://127.0.0.1:PORT/__gym/ledger > maze-ledger.json
crawl-maze-score --ledger maze-ledger.json --json
```

The static reference in `bench/baselines/crawl-maze.json` measures 66/66 static-plane
targets and 83/91 targets overall. The remaining eight require body-bearing actions
that static read-only crawling must not submit. Score server requests, not page
counts: plain-text `.found` responses can be requested without yielding HTML pages.
The scorer returns exit 1 when any of the 91 targets remain missing; that does not
mean the static plane missed an expected static target.
