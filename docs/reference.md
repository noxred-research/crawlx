# Reference: crawl options and runtime behaviors

Detailed behavior of options that the [README](../README.md) only summarizes. Run
`crawlx <command> --help` for the authoritative flag list of the build you have.

Contents: [bounded source discovery](#bounded-source-discovery) ·
[response cache and development replay](#native-response-cache-and-development-replay) ·
[adaptive extraction descriptors](#scoped-adaptive-extraction-descriptors) ·
[MCP server](#mcp-server) · [compatibility clients](#compatibility-clients) ·
[compatibility flags](#compatibility-crawl-flags) · [JavaScript endpoint mining](#javascript-endpoint-mining) ·
[wordlists](#wordlists-and-stored-fields) · [captcha solving](#captcha-solving) ·
[proxy tiers and the pool gateway](#deployment-proxy-tiers-and-the-pool-gateway)

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

External providers have no built-in endpoint or fallback. Add `scope.discovery.connectors` with explicit `provider` (`news_search`, `trends_search`, `web_archive_index`), authorized `endpoint`, and CDX `archiveBase` when needed. Enable the corresponding source (`news_search`, `trends_search`, `archive`). News accepts RSS/Atom and recorded `garturlres` results; trends accepts daily-trends JSON or RSS; archive accepts a CDX JSON table. Archive provenance keeps original URL, replay URL, capture time and optional recorded original status separate from the provider's HTTP status. Missing providers return `ProviderUnavailable`.

Cache-only/development replay never requests robots, sitemap, provider, conventional, media or read-more resources. Missing retained responses return `cache_miss`; explicit external-provider requests fail as `ProviderForbiddenInReplay`. Reprocessed artifacts record current robots as unobserved, not approved. These are source/runtime contracts, not a claim of upstream service availability or live-provider certification.

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

`excludedUrls` (`substrings`, case-insensitive; `patterns`, regular expressions with the path-filter size and nesting limits; at most 256 rules of 512 bytes each per list) is compiled by `crawlx_url::UrlExclusionFilter` and evaluated by `crawlx_url::PreFetchGate::decide` (in front of the scope filter) before any request, robots lookup or DNS resolution: a match yields `PreFetchDecision::UrlExcluded` with the reason code `url_excluded` and the matching rule, and the URL costs zero target requests. This reason is separate from path-scope reasons and from the content-quality reason `author_excluded`, which applies only after a page was acquired and rejects its ingestion while the acquisition and its content evidence stay recorded.

Acquisition validation classifies a challenge page by structure (a challenge form or stage element with too little real content around it, or an authoritative challenge response header), never by words: an article that discusses interstitial pages or captchas passes, a keyword-only page passes, and a genuine 200 interstitial is excluded with the signals `challenge_structure_present` and `challenge_missing_expected_content`. Validation selects no fetch backend and changes no session.

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

Shape details of the compatibility API: `GET /compat/v2/crawl/{id}` adds `warning` when pages were robots-blocked or a stopped crawl found at most one page, and answers `expiresAt` and `next` while the crawl runs; `POST /compat/v2/map` returns the `id` of its run; the `html` format is a full document; every `/compat/` answer has `Access-Control-Allow-Origin: *`, `X-Response-Time` and (for buffered bodies) a weak `ETag`. `compat.mode` (`CRAWLX_COMPAT_MODE`) is `strict` by default: a crawl that leaves `ignoreQueryParameters` unset keeps every query string and native webhooks are signed with both `Crawlx-Signature` and the compat signature header; `native_defaults` switches to the native query policy and `Crawlx-Signature` only.

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

## Deployment proxy tiers and the pool gateway

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
