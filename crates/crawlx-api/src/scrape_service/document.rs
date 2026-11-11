//! A stored scrape page as the compat `data` object (`ScrapeResponse.data`), and the credits
//! the page costs.

use crate::routes::pages::{content, default_include, page_doc, read_content};
use crate::state::AppState;
use base64::Engine as _;
use chrono::Duration as ChronoDuration;
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::{CrawlRun, PageRecord};
pub use crawlx_core::scrape::credits_for;
use crawlx_core::scrape::page_credits;
use crawlx_core::scrape::{ActionResults, BlobRef, CacheState, JobKind, ScrapeDocument, ScrapeOptions};
use crawlx_core::{ArtifactRef, Timestamp};
use crawlx_storage::PRESIGN_MAX_TTL;
use serde_json::{json, Map, Value};

/// A run that started no later than this after it was created did not queue: the worker's
/// lease loop polls for queued runs every 250 ms, so a shorter wait is pick-up latency.
const QUEUE_PICKUP_GRACE: ChronoDuration = ChronoDuration::seconds(1);

/// The compat job id of `page`: the run id of a scrape run, `{run}.{frontier}` for the pages
/// of crawl and batch runs.
#[must_use]
pub fn scrape_id(run: &CrawlRun, page: &PageRecord) -> String {
    match run.config.scrape.as_ref().map(|j| j.kind) {
        Some(JobKind::Scrape) => run.id.to_string(),
        _ => format!("{}.{}", run.id, page.frontier_id),
    }
}

/// A link to artifact `r` of `run`: a presigned object-store URL when the store offers one,
/// otherwise the API's artifact endpoint under `base`.
async fn artifact_url(state: &AppState, run: &CrawlRun, r: &ArtifactRef, base: &str) -> String {
    let api_link = format!("{base}/v1/crawls/{}/artifacts/{}", run.id, r.id);
    if run.config.retention.mode == RetentionMode::Zdr {
        return api_link;
    }
    match state.repos.artifacts.presign(r, PRESIGN_MAX_TTL).await {
        Ok(Some(url)) => url.into(),
        Ok(None) => api_link,
        Err(e) => {
            tracing::debug!(error = %e, artifact = %r.id, "presign failed; serving through the api");
            api_link
        }
    }
}

/// Inline text of a blob (`rawHtml`): the text when it fits `inline_max_bytes`, otherwise a
/// link the caller reports in `metadata.crawlx`.
async fn blob_text(state: &AppState, run: &CrawlRun, b: &BlobRef, base: &str) -> (Value, Option<String>) {
    match read_content(state, run, &b.artifact).await {
        Some(bytes) if bytes.len() <= state.settings.inline_max_bytes => {
            (Value::String(String::from_utf8_lossy(&bytes).into_owned()), None)
        }
        Some(_) => (
            Value::Null,
            Some(artifact_url(state, run, &b.artifact, base).await),
        ),
        None => (Value::Null, None),
    }
}

async fn action_results(state: &AppState, run: &CrawlRun, a: &ActionResults, base: &str) -> Value {
    let mut screenshots = Vec::with_capacity(a.screenshots.len());
    for s in &a.screenshots {
        screenshots.push(artifact_url(state, run, &s.artifact, base).await);
    }
    let mut pdfs = Vec::with_capacity(a.pdfs.len());
    for p in &a.pdfs {
        pdfs.push(artifact_url(state, run, &p.artifact, base).await);
    }
    let mut virtual_rows = Vec::with_capacity(a.virtual_rows.len());
    for report in &a.virtual_rows {
        let (text, link) = blob_text(state, run, report, base).await;
        let value = text
            .as_str()
            .and_then(|text| serde_json::from_str::<Value>(text).ok());
        virtual_rows.push(json!({"rendition": value, "url": link}));
    }
    let mut result = json!({
        "screenshots": screenshots,
        "scrapes": a.scrapes,
        "javascriptReturns": a.javascript_returns,
        "pdfs": pdfs,
    });
    if !virtual_rows.is_empty() {
        result["virtualRows"] = Value::Array(virtual_rows);
    }
    result
}

/// How a request was answered from a stored scrape instead of a fresh fetch.
pub(crate) struct CacheHit {
    /// RFC 3339 time of the stored scrape that was served.
    pub cached_at: String,
    /// The options of the request (it shapes the document like the stored scrape's options, but
    /// `lockdown` prices it).
    pub options: ScrapeOptions,
}

/// The compat `data` object of `page`, a page of `run`: the requested formats, `metadata`
/// (`sourceURL`, `url`, `statusCode`, `contentType`, `error`, the page's `<meta>` values,
/// `numPages`/`totalPages`, `cacheState`, `cachedAt`, `scrapeId`, `creditsUsed`, `proxyUsed`,
/// `concurrencyLimited`, `concurrencyQueueDurationMs`) and
/// `warning`. Pages of runs that carry no scrape job (plain crawls) keep the native page
/// document. Blobs are resolved: text up to `inline_max_bytes` inline (larger values are
/// linked from `metadata.crawlx`), `rawBase64` inline, screenshots and PDFs as URLs.
pub async fn compat_document(state: &AppState, run: &CrawlRun, page: &PageRecord, base_url: &str) -> Value {
    render(state, run, page, base_url, None).await.0
}

/// As [`compat_document`], marking the document as served from the stored scrape `hit`.
pub(crate) async fn render(
    state: &AppState,
    run: &CrawlRun,
    page: &PageRecord,
    base: &str,
    hit: Option<&CacheHit>,
) -> (Value, u64) {
    let (Some(job), Some(mut doc)) = (
        &run.config.scrape,
        ScrapeDocument::from_page_metadata(&page.metadata),
    ) else {
        return (page_doc(state, run, page, &default_include(run)).await, 1);
    };
    if let Some(h) = hit {
        doc.cache_state = CacheState::Hit;
        doc.cached_at = Some(h.cached_at.clone());
    }
    let o = hit.map_or(&job.options, |h| &h.options);
    let mut data = Map::new();
    let mut refs = Map::new();

    if o.wants("markdown") {
        let (v, link) = content(state, run, page.markdown.as_ref()).await;
        if page.markdown.is_some() {
            data.insert("markdown".to_owned(), v);
        }
        if let Some(l) = link {
            refs.insert("markdownRef".to_owned(), Value::String(l));
        }
    }
    if o.wants("html") {
        let (v, link) = content(state, run, page.html.as_ref()).await;
        if page.html.is_some() {
            data.insert("html".to_owned(), v);
        }
        if let Some(l) = link {
            refs.insert("htmlRef".to_owned(), Value::String(l));
        }
    }
    if let (true, Some(b)) = (o.wants("rawHtml"), &doc.raw_html) {
        let (v, link) = blob_text(state, run, b, base).await;
        data.insert("rawHtml".to_owned(), v);
        if let Some(l) = link {
            refs.insert("rawHtmlRef".to_owned(), Value::String(l));
        }
    }
    if let (true, Some(b)) = (o.wants("rawBase64"), &doc.raw_base64) {
        if let Some(bytes) = read_content(state, run, &b.artifact).await {
            data.insert(
                "rawBase64".to_owned(),
                Value::String(base64::engine::general_purpose::STANDARD.encode(bytes)),
            );
        }
    }
    if o.wants("links") {
        data.insert("links".to_owned(), json!(page.links));
    }
    if let Some(images) = &doc.images {
        data.insert("images".to_owned(), json!(images));
    }
    if let Some(b) = &doc.screenshot {
        data.insert(
            "screenshot".to_owned(),
            Value::String(artifact_url(state, run, &b.artifact, base).await),
        );
    }
    if let (true, Some(b)) = (o.wants("audio"), &doc.audio) {
        data.insert(
            "audio".to_owned(),
            Value::String(artifact_url(state, run, &b.artifact, base).await),
        );
    }
    if let (true, Some(b)) = (o.wants("video"), &doc.video) {
        data.insert(
            "video".to_owned(),
            Value::String(artifact_url(state, run, &b.artifact, base).await),
        );
    }
    if let (true, Some(t)) = (o.wants("audio") || o.wants("video"), &doc.transcript) {
        // additive to the compat API's shape: the speech-to-text of the returned media
        data.insert("transcript".to_owned(), json!(t));
    }
    if let Some(s) = &doc.summary {
        data.insert("summary".to_owned(), json!(s));
    }
    if let Some(v) = &doc.json {
        data.insert("json".to_owned(), v.clone());
    }
    if let Some(a) = doc.answer.as_ref().or(doc.query.as_ref()) {
        // the `question` and `query` formats share the compat API's `answer` field
        data.insert("answer".to_owned(), json!(a));
    }
    if let Some(h) = &doc.highlights {
        // The compat API documents `highlights` as one string of selected source text
        data.insert("highlights".to_owned(), Value::String(h.join("\n\n")));
    }
    if let Some(a) = &doc.attributes {
        data.insert("attributes".to_owned(), json!(a));
    }
    if let Some(b) = &doc.branding {
        data.insert("branding".to_owned(), b.clone());
    }
    if let Some(c) = &doc.change_tracking {
        data.insert("changeTracking".to_owned(), json!(c));
    }
    if let Some(a) = &doc.actions {
        data.insert("actions".to_owned(), action_results(state, run, a, base).await);
    }
    if let Some(p) = &doc.pages {
        data.insert("pages".to_owned(), json!(p));
    }
    if let Some(b) = &doc.blocks {
        data.insert("blocks".to_owned(), b.clone());
    }
    if let (true, Some(outputs)) = (
        o.outputs.is_some() || o.decode.is_some() || o.markup.is_some(),
        doc.outputs.take(),
    ) {
        data.insert("outputs".to_owned(), outputs);
    }
    if let Some(w) = &doc.warning {
        data.insert("warning".to_owned(), json!(w));
    }

    let mut meta: Map<String, Value> = doc.meta.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    if let Some(provenance) = page.metadata.get("developmentReplay") {
        meta.insert("developmentReplay".to_owned(), provenance.clone());
    }
    if !meta.contains_key("title") {
        if let Some(t) = &page.title {
            meta.insert("title".to_owned(), json!(t));
        }
    }
    meta.insert("sourceURL".to_owned(), json!(doc.source_url));
    meta.insert("url".to_owned(), json!(doc.final_url));
    meta.insert("statusCode".to_owned(), json!(doc.status_code));
    if let Some(ct) = doc.content_type.as_ref().or(page.content_type.as_ref()) {
        meta.insert("contentType".to_owned(), json!(ct));
    }
    if let Some(e) = &doc.error {
        meta.insert("error".to_owned(), json!(e));
    }
    if let Some(n) = doc.num_pages {
        meta.insert("numPages".to_owned(), json!(n));
    }
    if let Some(n) = doc.total_pages {
        meta.insert("totalPages".to_owned(), json!(n));
    }
    meta.insert(
        "cacheState".to_owned(),
        json!(match doc.cache_state {
            CacheState::Hit => "hit",
            CacheState::Miss => "miss",
        }),
    );
    if let Some(at) = &doc.cached_at {
        meta.insert("cachedAt".to_owned(), json!(at));
    }
    meta.insert("scrapeId".to_owned(), json!(scrape_id(run, page)));
    let credits = page_credits(o, &doc, run.config.retention.mode == RetentionMode::Zdr);
    meta.insert("creditsUsed".to_owned(), json!(credits));
    meta.insert("proxyUsed".to_owned(), json!(doc.proxy_used));
    insert_queue_wait(&mut meta, run, hit.is_some());
    if !refs.is_empty() {
        meta.insert("crawlx".to_owned(), Value::Object(refs));
    }
    data.insert("metadata".to_owned(), Value::Object(meta));
    (Value::Object(data), credits)
}

/// How long a run waited in the admission queue: from its creation (`queued_at`) to the moment a
/// worker started it. `None` while it has not started and for a wait of [`QUEUE_PICKUP_GRACE`]
/// or less, which is the worker's polling latency, not queueing.
fn queue_wait(created: Timestamp, started: Option<Timestamp>) -> Option<ChronoDuration> {
    started
        .map(|started| started - created)
        .filter(|wait| *wait > QUEUE_PICKUP_GRACE)
}

/// `metadata.concurrencyLimited` and, when limited, `concurrencyQueueDurationMs`: whether `run`
/// waited in the admission queue (`queued` until a worker leased it) and for how long
/// ([`queue_wait`]). A document served from a stored scrape (`from_cache`) never waited: the
/// request created no run.
fn insert_queue_wait(meta: &mut Map<String, Value>, run: &CrawlRun, from_cache: bool) {
    let waited = if from_cache {
        None
    } else {
        queue_wait(run.created_at, run.started_at)
    };
    meta.insert("concurrencyLimited".to_owned(), json!(waited.is_some()));
    if let Some(w) = waited {
        meta.insert(
            "concurrencyQueueDurationMs".to_owned(),
            json!(w.num_milliseconds()),
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::hash::Digest;
    use crawlx_core::scrape::{FormatSpec, ParserSpec};

    fn doc(status: u16) -> ScrapeDocument {
        ScrapeDocument::new(
            "https://a.test/".into(),
            "https://a.test/".into(),
            status,
            Digest::of("t", b""),
        )
    }

    #[test]
    fn only_a_wait_beyond_the_pick_up_latency_counts_as_queueing() {
        let created = chrono::DateTime::parse_from_rfc3339("2026-10-28T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let after = |ms: i64| Some(created + ChronoDuration::milliseconds(ms));
        assert_eq!(queue_wait(created, None), None, "not started yet");
        assert_eq!(queue_wait(created, after(0)), None);
        assert_eq!(queue_wait(created, after(250)), None, "one worker poll");
        assert_eq!(queue_wait(created, after(1_000)), None, "the grace itself");
        assert_eq!(
            queue_wait(created, after(1_001)),
            Some(ChronoDuration::milliseconds(1_001))
        );
        assert_eq!(
            queue_wait(created, after(90_000)).map(|w| w.num_milliseconds()),
            Some(90_000)
        );
        assert_eq!(queue_wait(created, after(-5)), None, "clock skew is no wait");
    }

    fn opts(formats: Vec<FormatSpec>) -> ScrapeOptions {
        ScrapeOptions {
            formats,
            ..ScrapeOptions::default()
        }
    }

    #[test]
    fn credits_follow_the_compat_price_list() {
        let md = opts(vec![FormatSpec::Markdown]);
        assert_eq!(page_credits(&md, &doc(200), false), 1);
        assert_eq!(page_credits(&md, &doc(200), true), 2, "zero data retention +1");
        let llm = opts(vec![
            FormatSpec::Markdown,
            FormatSpec::Json {
                schema: None,
                prompt: None,
            },
            FormatSpec::Question { question: "q".into() },
            FormatSpec::Highlights { query: "h".into() },
            FormatSpec::Query {
                prompt: "p".into(),
                mode: crawlx_core::scrape::QueryMode::Freeform,
            },
            FormatSpec::Summary,
        ]);
        assert_eq!(
            page_credits(&llm, &doc(200), false),
            17,
            "1 + 4 formats x 4; summary is free"
        );
        let mut pdf = doc(200);
        pdf.num_pages = Some(7);
        assert_eq!(
            page_credits(&md, &pdf, false),
            7,
            "a PDF costs 1 credit per parsed page"
        );
        assert_eq!(
            page_credits(&llm, &doc(404), false),
            1,
            "error pages carry no format extras"
        );
        let lock = ScrapeOptions {
            lockdown: true,
            ..ScrapeOptions::default()
        };
        let mut hit = doc(200);
        hit.cache_state = CacheState::Hit;
        assert_eq!(page_credits(&lock, &hit, true), 5, "lockdown hit: 5 credits");
        assert_eq!(page_credits(&lock, &doc(200), true), 1, "lockdown miss: 1 credit");
        let off = ScrapeOptions {
            parsers: Vec::new(),
            ..ScrapeOptions::default()
        };
        assert_eq!(
            page_credits(&off, &pdf, false),
            1,
            "parsers: [] returns the PDF unparsed for 1 credit"
        );
        let only_image = ScrapeOptions {
            parsers: vec![ParserSpec::Image],
            ..ScrapeOptions::default()
        };
        assert_eq!(page_credits(&only_image, &pdf, false), 1);
    }

    #[test]
    fn media_formats_are_billed_only_when_the_file_was_delivered() {
        use crawlx_core::scrape::BlobRef;
        let both = opts(vec![FormatSpec::Markdown, FormatSpec::Audio, FormatSpec::Video]);
        assert_eq!(
            page_credits(&both, &doc(200), false),
            1,
            "no media found: the page costs its base credit"
        );
        let blob = BlobRef {
            artifact: crawlx_core::ArtifactRef {
                id: crawlx_core::ArtifactId::new(),
                digest: Digest::of("t", b"media"),
            },
            content_type: "audio/mpeg".into(),
            size: 5,
        };
        let mut audio = doc(200);
        audio.audio = Some(blob.clone());
        assert_eq!(page_credits(&both, &audio, false), 5, "audio delivered: 1 + 4");
        let mut all = audio.clone();
        all.video = Some(blob);
        assert_eq!(page_credits(&both, &all, false), 9, "audio and video: 1 + 4 + 4");
        assert_eq!(
            page_credits(&opts(vec![FormatSpec::Markdown]), &all, false),
            1,
            "a media file that was not requested is not billed"
        );
    }
}
