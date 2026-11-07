# crawlx-worker: the library surface

`crawlx-worker` is the crawl engine as a library: the lease loop, the URL plane (static fetch
discovery), the browser plane, the Session Actors and the output layer. The `crawlx` CLI, the
HTTP API and the test-suites all sit on the items below, so they are the supported embedding
surface (katana's `types.Options` + `OnResult` equivalent).

| katana library | crawlx |
|---|---|
| `types.Options` | [`CreateCrawl`](https://docs.rs/crawlx-core) (what to crawl: scope, limits, fetch, extract, dynamic, output; the same JSON as `POST /v1/crawls`) plus [`WorkerConfig`] (operator-level: egress, launch options, artifacts directory, traffic export, form AI, secret validators) |
| `runner.NewCrawlerRunner` / `ExecuteCrawling` | [`run_local_with`] over a [`LocalRun`] |
| `OnResult(output.Result)` | the [`RunReport`] returned by the run (`pages`, `page_contents`, `failures`, `resume`) fed to an [`output::Exporter`], which renders katana's `-jsonl` records, `-f`/`-ot` text lines and applies every output filter |
| `-resume` | `RunReport::resume` and [`LocalRun::with_resume`] |
| `KATANA_TRAFFIC_*` | [`katana::traffic_export`] |

## Run a crawl

```rust,no_run
use crawlx_core::config::CrawlMode;
use crawlx_core::CreateCrawl;
use crawlx_storage::MemoryStore;
use crawlx_worker::{run_local_with, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let artifacts = std::env::temp_dir().join("crawlx-artifacts");
let mut crawl = CreateCrawl::new("https://example.com/".parse()?);
crawl.mode = CrawlMode::Static; // URL plane only, no browser
crawl.limits.urls = 100;

let cfg = WorkerConfig {
    artifacts_dir: artifacts.clone(),
    ..WorkerConfig::default()
};
let stores = Stores::over_memory(Arc::new(MemoryStore::new()), &artifacts).await?;
let report = run_local_with(LocalRun::new(crawl, cfg).with_stores(stores)).await?;

println!("{} pages, {} failed URLs", report.pages.len(), report.failures.len());
# Ok(())
# }
```

* `CreateCrawl` is validated like the API validates a request; every field is documented in
  `crawlx-core::config`.
* `WorkerConfig::default()` is production-shaped (system DNS, egress policy on). Tests point
  `egress.resolver` at a `StaticResolver` and set `safety.allow_private_networks`.
* `LocalRun` also takes an existing `Stores` (share one `MemoryStore` with an API in tests),
  a `CancellationToken` (`with_cancel`), secrets, strategies and a browser backend.
  On cancellation, the local runner drains active sessions and cancels planned sessions
  that never acquired a lease before returning. Drained sessions retain their existing
  terminal status or recoverable checkpoint state; unstarted sessions need no recovery.
* `RunReport` is the whole outcome: `pages` (one `PageRecord` per stored page, metadata
  included), `page_contents` (Markdown, HTML and, with `output.captureRaw`, the raw HTTP text
  per URL), `failures` (frontier rows that ended `failed` or `unreachable`, sorted by URL),
  `resume`, `diagnostics`, `counters` and the browser-plane ledgers.

## Resume a stopped run (`-resume`)

A run that stops before its frontier is exhausted (page limit, duration limit, cancellation)
returns `RunReport::resume: Option<ResumeState>`: the canonical URLs it visited and the
admitted URLs it did not fetch. The state is deterministic JSON
([`katana::resume::ResumeState::to_json`]); feed it back with `LocalRun::with_resume` and the
new run skips the visited URLs and starts from the pending ones. A finished run has
`resume == None`.

## Turn pages into output (`OnResult`)

```rust
use crawlx_worker::output::{Dsl, ExportFormat, Exporter};
use crawlx_worker::UrlFailure;

// katana: `-jsonl -mdc 'status_code == 404'`
let exporter = Exporter {
    format: ExportFormat::Jsonl,
    match_condition: Some(Dsl::parse("status_code == 404")?),
    ..Exporter::default()
};
let failures = [
    UrlFailure::new("https://example.com/gone", 1, "http_404"),
    UrlFailure::new("https://example.com/down", 1, "timeout"),
];
let mut out = Vec::new();
let stats = exporter.export_failures(&failures, &mut out)?;
assert_eq!(stats.lines, 1);
let line = String::from_utf8(out)?;
assert!(line.contains(r#""error":"http_404""#) && line.contains(r#""status_code":404"#));
# Ok::<(), Box<dyn std::error::Error>>(())
```

For the pages of a report use `Exporter::export_pages_with(report.pages.iter(), load, out)`
where `load` maps a page to its [`output::PageText`] (body and raw text, usually from
`report.page_contents`); `Exporter::record_with` gives the single record for a callback-style
`OnResult`.

Per-host wordlists use `Exporter::store_fields: Some(StoreFields::new(directory))`.
Set `stored_field_selection: Some(Field::parse_list("qurl,key")?)` to store only those
fields, independently of displayed fields or template references. `None` retains the
display/template fields (or `url` by default); `Some(Vec::new())` stores no fields.
Custom names use the same validation and metadata lookup as display fields. A valid
custom name missing from a page produces no wordlist value.
An explicit selection uses the same page-admission checks as JSONL (URL regexes,
extensions, excluded page types and DSL conditions), even when a template renders no
values. Display lines still use their existing per-line filters. Without an explicit
selection, wordlists retain the legacy requirement that at least one display line survives.

### The JSONL record

One line per page, shaped like katana's `output.Result`:

```text
{"timestamp", "request": {method, endpoint, body, headers, tag, attribute, source,
                          custom_fields, raw},
 "response": {status_code, headers, body, content_length, technologies, raw, forms,
              xhr_requests, stored_response_path, knowledgebase, extra,
              page_type, custom_fields, secrets},
 "error"}
```

* `request.custom_fields` is where katana puts custom regex field values. crawlx also keeps
  them under `response.custom_fields` for existing consumers; both hold the same data.
* `page_type` and `secrets` (kind, location and keyed hash, never a value; `validation` when
  secret validation ran) are crawlx's flat fields; `knowledgebase`
  (`{PageType, Forms, secrets, endpoints}`) is the katana shape of the same data and is
  present only with `Exporter::knowledge_base` (the `extract.knowledgeBase` setting).
* `body` appears only with `Exporter::include_body` (the body is not part of the page row);
  `raw` only when the run captured it (`output.captureRaw`) and the caller supplied it.
  `omit_raw` / `omit_body` (`-or` / `-ob`) remove them; `exclude_fields` (`-eof`) removes any
  field named by [`output::field_names`] (the `-lof` list). A name that exists in `request`
  and `response` (`body`, `headers`, `raw`, `custom_fields`) is removed from both.
* `error` is set on records of failed URLs ([`output::Exporter::export_failures`]).
* `response.extra` is for embedders (katana's `Response.Extra`): crawlx never fills it.

### Filters

Applied in this order, as in katana's `Write`: extension (`-em`, `-ef`), then match
(`-mr`, `-mdc`: kept when a match regex hits **or** the condition holds), then filter
(`-fr`, `-fdc`: dropped when a filter regex hits **or** the condition holds), then
`filter_page_types` (`-fpt`: the page type, compared case-insensitively, is dropped from the
output only; the page was still crawled and stored). `-mr`/`-fr` lists come from
[`output::expand_patterns`] (comma separated, or the lines of an existing file).

### Conditions (`-mdc` / `-fdc`)

[`output::Dsl`] parses katana's expression language over the JSONL record:

```rust
use crawlx_worker::output::{Dsl, Record};

let record = Record::from_failure("https://example.com/admin/", Some(403), "http_403");
let condition = Dsl::parse(r#"contains(url, "admin") && status_code != 200 || len(error) == 0"#)?;
assert!(condition.eval(&record));
assert!(Dsl::parse("status_code ==").is_err()); // errors carry the byte position
# Ok::<(), Box<dyn std::error::Error>>(())
```

Literals `"text"`, `'text'`, numbers, `true`/`false`; operators `||`, `&&`, `==`, `!=`,
infix `contains`, `<`, `<=`, `>`, `>=`, `!` and parentheses (`&&` binds tighter than `||`;
both short-circuit); functions `contains`, `contains_any`, `contains_all`, `starts_with`,
`ends_with`, `regex(pattern, input)`, `len`, `to_lower`, `to_upper`. Variables are dotted
JSONL paths (`request.method`, `response.headers.content-type`) or katana's bare names
(`status_code`, `endpoint`, `url`, `technologies`, `page_type`, `content_type`). Regexes use
the linear-time `regex` crate with a size bound. As in katana, a condition that cannot be
evaluated (unknown variable, type mismatch) is `false`: a match condition does not match, a
filter condition does not filter. See the module documentation of `output::dsl` for the
details.

### Files

* **`-o FILE` and `-ncb`**: [`output::TextFile::create(path, no_clobber)`]. With `no_clobber`
  an existing non-empty file is never touched; the next free `name<N>.ext` is used
  (katana applies the same numbering rule to its `-srd` directory only).
* **`-sr` / `-srd`**: [`output::StoredResponses::new(dir, no_clobber)`] writes
  `<dir>/<host>/<sha1(url)>.txt` (URL, raw request, raw response) and one
  `<file> <url> (<status>)` line per file in `<dir>/index.txt`; set
  `Exporter::stored_responses` and the record's `response.stored_response_path` points at the
  file. Without a captured raw text the request and response are rebuilt from the recorded
  headers and body.
* **`-elog`**: [`output::write_error_log(path, &report.failures, no_clobber)`] writes one JSON
  line per failed URL (`timestamp`, `endpoint`, `error`, `depth`, `status_code`).

## Traffic export (`KATANA_TRAFFIC_*`)

Set `WorkerConfig::traffic_export` and every URL-plane exchange (and, in a browser run, every
browser-plane exchange) is POSTed to a collector as batched JSON:

```rust,no_run
use crawlx_worker::katana::traffic_export::{TrafficExportConfig, TrafficExporter};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
// CRAWLX_TRAFFIC_ENDPOINT, CRAWLX_TRAFFIC_TOKEN (both required), CRAWLX_TRAFFIC_ATTRIBUTES,
// CRAWLX_TRAFFIC_ALLOW_INSECURE, CRAWLX_TRAFFIC_INCLUDE_CREDENTIALS
if let Some(config) = TrafficExportConfig::from_env(&|key| std::env::var(key).ok())? {
    let exporter = TrafficExporter::new(config)?; // inside a Tokio runtime
    // exporter.record(exchange) never blocks; flush() and shutdown() wait for the collector
    exporter.flush().await;
    exporter.shutdown().await;
    println!("{:?}", exporter.stats());
}
# Ok(())
# }
```

The endpoint must be `https` (plain `http` only to a loopback host or with
`ALLOW_INSECURE=1`); the bearer token is sent as `Authorization: Bearer`, never followed through
a redirect or an `HTTP_PROXY`, and never printed by `Debug`; credential headers are dropped
unless `INCLUDE_CREDENTIALS=1`. The sender batches on size or interval, retries `429`/`5xx`,
and drops (and counts) events when its bounded queue is full. Details: module documentation of
`katana::traffic_export`.

## Stability

The items named in this document are the embedding API: they are documented, their errors are
typed (`thiserror`), and public structs that grow are `#[non_exhaustive]` (construct them with
their `new`/builder methods or `..Default::default()`). Everything else in the crate is
engine internals shared with the CLI and API and may change between releases.

[`CreateCrawl`]: https://docs.rs/crawlx-core
[`WorkerConfig`]: crate::WorkerConfig
[`run_local_with`]: crate::run_local_with
[`LocalRun`]: crate::LocalRun
[`LocalRun::with_resume`]: crate::LocalRun::with_resume
[`RunReport`]: crate::RunReport
[`output::Exporter`]: crate::output::Exporter
[`output::PageText`]: crate::output::PageText
[`output::field_names`]: crate::output::field_names
[`output::Exporter::export_failures`]: crate::output::Exporter::export_failures
[`output::expand_patterns`]: crate::output::expand_patterns
[`output::Dsl`]: crate::output::Dsl
[`output::TextFile::create(path, no_clobber)`]: crate::output::TextFile::create
[`output::StoredResponses::new(dir, no_clobber)`]: crate::output::StoredResponses::new
[`output::write_error_log(path, &report.failures, no_clobber)`]: crate::output::write_error_log
[`katana::traffic_export`]: crate::katana::traffic_export
[`katana::resume::ResumeState::to_json`]: crate::katana::resume::ResumeState::to_json
