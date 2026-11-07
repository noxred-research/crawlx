//! The `audio` and `video` scrape formats through real runs: `run_local_with` over in-memory
//! stores, a fixture HTTP site on 127.0.0.1 that serves media, and a scripted LLM that
//! transcribes. Every test asserts the stored result (`PageRecord` + `metadata["scrape"]` +
//! artifacts) and the frontier rows.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use authorization_fixture::run_authorized_local_with as run_local_with;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use crawlx_core::config::{CrawlMode, HostScope, RetentionMode, SitemapMode};
use crawlx_core::repo::{FrontierEntry, FrontierStatus, PageRecord};
use crawlx_core::scrape::{BlobRef, FormatSpec, JobKind, ScrapeDocument, ScrapeJob, ScrapeOptions};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_model::llm::{LlmError, LlmExtractor, MockLlm};
use crawlx_storage::artifacts::{ArtifactBlobs, FsBlobs};
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::sync::{Arc, Mutex};
use url::Url;

// ---- the fixture site ---------------------------------------------------------------------

/// Deterministic payload of `len` bytes after `magic`.
fn payload(magic: &[u8], len: usize) -> Vec<u8> {
    let mut bytes = magic.to_vec();
    bytes.extend((0..len).map(|i| u8::try_from(i % 251).unwrap()));
    bytes
}

fn mp3() -> Vec<u8> {
    payload(b"ID3\x03\x00\x00\x00\x00\x00\x00", 2_048)
}

fn ogg() -> Vec<u8> {
    payload(b"OggS\x00\x02", 1_536)
}

fn mp4() -> Vec<u8> {
    payload(b"\x00\x00\x00\x18ftypmp42", 3_000)
}

fn html(body: impl Into<String>) -> axum::response::Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body.into()).into_response()
}

fn page(title: &str, markup: &str) -> axum::response::Response {
    html(format!(
        "<!doctype html><html><head><title>{title}</title></head><body><main><h1>{title}</h1>\
         <p>Words of {title}.</p></main>{markup}</body></html>"
    ))
}

fn media(content_type: &'static str, bytes: Vec<u8>) -> axum::response::Response {
    ([(header::CONTENT_TYPE, content_type)], bytes).into_response()
}

struct Site {
    base: String,
    hits: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
    fn count(&self, path: &str) -> usize {
        self.hits.lock().unwrap().iter().filter(|p| *p == path).count()
    }
}

async fn record(
    axum::extract::State(hits): axum::extract::State<Arc<Mutex<Vec<String>>>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    hits.lock().unwrap().push(req.uri().path().to_owned());
    next.run(req).await
}

/// A listener on its own port, serving only `/a.mp3`; used as the media host the egress policy
/// refuses (the policy admits the seed's port, not this one).
async fn start_other_port() -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/a.mp3", get(|| async { media("audio/mpeg", mp3()) }))
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site {
        base: format!("http://{addr}"),
        hits,
        task,
    }
}

async fn start(other: Option<&Site>) -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let denied_page = format!(
        r#"<audio src="{}"></audio>"#,
        other.map_or_else(|| "http://127.0.0.1:1/a.mp3".to_owned(), |o| o.url("/a.mp3"))
    );
    let app = Router::new()
        .route("/media/ep.mp3", get(|| async { media("audio/mpeg", mp3()) }))
        .route("/media/ep.ogg", get(|| async { media("audio/ogg", ogg()) }))
        .route("/media/clip.mp4", get(|| async { media("video/mp4", mp4()) }))
        .route(
            "/media/octet.mp3",
            get(|| async { media("application/octet-stream", mp3()) }),
        )
        .route(
            "/media/not-audio.mp3",
            get(|| async { html("<html><body>sign in to listen</body></html>") }),
        )
        .route(
            "/media/missing.mp3",
            get(|| async { (StatusCode::NOT_FOUND, "gone").into_response() }),
        )
        .route(
            "/podcast",
            get(|| async {
                page(
                    "Podcast",
                    r#"<audio controls><source src="/media/ep.ogg" type="audio/ogg">
                       <source src="/media/ep.mp3" type="audio/mpeg"></audio>"#,
                )
            }),
        )
        .route(
            "/ogg-only",
            get(|| async { page("Ogg", r#"<audio src="/media/ep.ogg"></audio>"#) }),
        )
        .route(
            "/watch",
            get(|| async {
                page(
                    "Watch",
                    r#"<meta property="og:video" content="/media/clip.mp4">
                       <meta property="og:video:type" content="video/mp4">
                       <a href="/media/ep.mp3">download the audio</a>"#,
                )
            }),
        )
        .route(
            "/video-only",
            get(|| async {
                page(
                    "Video",
                    r#"<video controls src="/media/clip.mp4" poster="/p.jpg"></video>"#,
                )
            }),
        )
        .route("/none", get(|| async { page("Silent", "") }))
        .route(
            "/dead",
            get(|| async { page("Dead", r#"<audio src="/media/missing.mp3"></audio>"#) }),
        )
        .route(
            "/wrong-type",
            get(|| async { page("Wrong", r#"<audio src="/media/not-audio.mp3"></audio>"#) }),
        )
        .route(
            "/octet",
            get(|| async { page("Octet", r#"<a href="/media/octet.mp3">episode</a>"#) }),
        )
        .route(
            "/denied",
            get(move || {
                let markup = denied_page.clone();
                async move { page("Denied", &markup) }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site {
        base: format!("http://{addr}"),
        hits,
        task,
    }
}

// ---- the rig --------------------------------------------------------------------------------

struct Spec {
    seed: String,
    options: ScrapeOptions,
    llm: Option<Arc<MockLlm>>,
    media_max: Option<usize>,
    zdr: bool,
}

impl Spec {
    fn new(seed: String, formats: Vec<FormatSpec>) -> Self {
        Self {
            seed,
            options: ScrapeOptions {
                formats,
                ..ScrapeOptions::default()
            },
            llm: None,
            media_max: None,
            zdr: false,
        }
    }
    fn llm(mut self, llm: &Arc<MockLlm>) -> Self {
        self.llm = Some(Arc::clone(llm));
        self
    }
    fn media_max(mut self, bytes: usize) -> Self {
        self.media_max = Some(bytes);
        self
    }
    fn zdr(mut self) -> Self {
        self.zdr = true;
        self
    }
}

struct Done {
    report: RunReport,
    stores: Stores,
}

impl Done {
    async fn frontier(&self) -> Vec<FrontierEntry> {
        self.stores.frontier.list(self.report.run_id).await.unwrap()
    }
    async fn row(&self, path: &str) -> FrontierEntry {
        self.frontier()
            .await
            .into_iter()
            .find(|e| e.url.url.path() == path)
            .unwrap_or_else(|| panic!("no frontier row for {path}"))
    }
    fn page(&self, path: &str) -> &PageRecord {
        self.report
            .pages
            .iter()
            .find(|p| p.url.url.path() == path)
            .unwrap_or_else(|| panic!("no page row for {path}"))
    }
    fn doc(&self, path: &str) -> ScrapeDocument {
        ScrapeDocument::from_page_metadata(&self.page(path).metadata)
            .unwrap_or_else(|| panic!("{path} carries no scrape document"))
    }
    async fn blob(&self, blob: &BlobRef) -> Vec<u8> {
        self.stores.artifacts.get(&blob.artifact).await.unwrap()
    }
}

async fn go(dir: &tempfile::TempDir, spec: Spec) -> Done {
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let job = ScrapeJob::new(JobKind::Scrape, spec.options.clone());
    let mut crawl = CreateCrawl::new(Url::parse(&spec.seed).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_028);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files = Vec::new();
    crawl.scope.host_scope = HostScope::None;
    crawl.scope.max_discovery_depth = 0;
    if spec.zdr {
        crawl.retention.mode = RetentionMode::Zdr;
    }
    crawl.scrape = Some(job);
    let mut cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
            ..EgressConfig::default()
        },
        llm: spec.llm.map(|l| l as Arc<dyn LlmExtractor>),
        ..WorkerConfig::default()
    };
    if let Some(max) = spec.media_max {
        cfg.media_max_bytes = max;
    }
    let report = run_local_with(LocalRun::new(crawl, cfg).with_stores(stores.clone()))
        .await
        .unwrap();
    Done { report, stores }
}

fn audio() -> Vec<FormatSpec> {
    vec![FormatSpec::Audio]
}

fn warning(doc: &ScrapeDocument) -> String {
    doc.warning.clone().unwrap_or_default()
}

// ---- a media URL is the file ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_direct_audio_url_is_stored_byte_for_byte() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let done = go(&dir, Spec::new(site.url("/media/ep.mp3"), audio())).await;

    assert_eq!(done.row("/media/ep.mp3").await.status, FrontierStatus::Succeeded);
    let page = done.page("/media/ep.mp3");
    assert_eq!(
        (page.status, page.content_type.as_deref()),
        (200, Some("audio/mpeg"))
    );
    assert!(page.markdown.is_none());
    let doc = done.doc("/media/ep.mp3");
    let blob = doc.audio.as_ref().expect("audio blob");
    assert_eq!((blob.content_type.as_str(), blob.size), ("audio/mpeg", 2_058));
    assert_eq!(done.blob(blob).await, mp3(), "the bytes round-trip exactly");
    assert!(doc.video.is_none());
    assert!(
        warning(&doc).starts_with("transcription_unavailable:"),
        "no transcribing endpoint: {:?}",
        doc.warning
    );
    assert!(!warning(&doc).contains("audio_not_mp3"), "MP3 needs no note");
    assert!(doc.transcript.is_none() && doc.llm_tokens == 0);
}

#[tokio::test]
async fn a_media_body_is_unsupported_content_unless_audio_or_video_is_requested() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let done = go(
        &dir,
        Spec::new(site.url("/media/ep.mp3"), vec![FormatSpec::Markdown]),
    )
    .await;
    let row = done.row("/media/ep.mp3").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Failed, Some("unsupported_content"))
    );
}

#[tokio::test]
async fn an_octet_stream_with_a_media_extension_counts_as_media() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let done = go(&dir, Spec::new(site.url("/media/octet.mp3"), audio())).await;
    let doc = done.doc("/media/octet.mp3");
    assert_eq!(done.blob(doc.audio.as_ref().unwrap()).await, mp3());
}

#[tokio::test]
async fn a_direct_video_url_serves_video_and_is_the_container_of_the_audio() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let both = go(
        &dir,
        Spec::new(
            site.url("/media/clip.mp4"),
            vec![FormatSpec::Audio, FormatSpec::Video],
        ),
    )
    .await;
    let doc = both.doc("/media/clip.mp4");
    let video = doc.video.as_ref().expect("video blob");
    assert_eq!((video.content_type.as_str(), video.size), ("video/mp4", 3_012));
    assert_eq!(both.blob(video).await, mp4());
    let audio = doc.audio.as_ref().expect("the video file answers audio");
    assert_eq!(
        audio.artifact, video.artifact,
        "one stored file serves both formats"
    );
    assert!(
        warning(&doc).contains("audio_not_extracted:"),
        "{:?}",
        doc.warning
    );

    let only_video = go(
        &dir,
        Spec::new(site.url("/media/clip.mp4"), vec![FormatSpec::Video]),
    )
    .await;
    let doc = only_video.doc("/media/clip.mp4");
    assert!(doc.audio.is_none() && doc.video.is_some());
    assert!(!warning(&doc).contains("audio_not_extracted"));
}

#[tokio::test]
async fn a_video_format_on_an_audio_url_warns_video_not_found() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let done = go(
        &dir,
        Spec::new(site.url("/media/ep.mp3"), vec![FormatSpec::Video]),
    )
    .await;
    assert_eq!(done.row("/media/ep.mp3").await.status, FrontierStatus::Succeeded);
    let doc = done.doc("/media/ep.mp3");
    assert!(doc.video.is_none() && doc.audio.is_none());
    assert!(warning(&doc).contains("video_not_found:"), "{:?}", doc.warning);
}

// ---- media a page references ------------------------------------------------------------------------------------

#[tokio::test]
async fn an_audio_source_of_an_html_page_is_downloaded_and_the_mp3_is_preferred() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let done = go(
        &dir,
        Spec::new(
            site.url("/podcast"),
            vec![FormatSpec::Markdown, FormatSpec::Audio],
        ),
    )
    .await;
    assert_eq!(done.row("/podcast").await.status, FrontierStatus::Succeeded);
    let doc = done.doc("/podcast");
    let blob = doc.audio.as_ref().expect("audio blob");
    assert_eq!(blob.content_type, "audio/mpeg");
    assert_eq!(done.blob(blob).await, mp3());
    assert_eq!(
        site.count("/media/ep.ogg"),
        0,
        "the first source is not fetched when an MP3 exists"
    );
    let markdown = done
        .stores
        .artifacts
        .get(done.page("/podcast").markdown.as_ref().unwrap())
        .await
        .unwrap();
    assert!(String::from_utf8(markdown).unwrap().contains("Words of Podcast"));
}

#[tokio::test]
async fn audio_that_is_not_mp3_is_returned_as_is_with_a_warning() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let done = go(&dir, Spec::new(site.url("/ogg-only"), audio())).await;
    let doc = done.doc("/ogg-only");
    let blob = doc.audio.as_ref().unwrap();
    assert_eq!(blob.content_type, "audio/ogg");
    assert_eq!(done.blob(blob).await, ogg());
    assert!(
        warning(&doc).contains("audio_not_mp3: the audio is audio/ogg"),
        "{:?}",
        doc.warning
    );
}

#[tokio::test]
async fn og_video_is_picked_for_video_and_a_link_for_audio() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let done = go(&dir, Spec::new(site.url("/watch"), vec![FormatSpec::Video])).await;
    let doc = done.doc("/watch");
    assert_eq!(done.blob(doc.video.as_ref().unwrap()).await, mp4());
    assert!(doc.audio.is_none());
    assert_eq!(
        site.count("/media/ep.mp3"),
        0,
        "only the requested format is downloaded"
    );

    let both = go(
        &dir,
        Spec::new(site.url("/watch"), vec![FormatSpec::Audio, FormatSpec::Video]),
    )
    .await;
    let doc = both.doc("/watch");
    assert_eq!(both.blob(doc.audio.as_ref().unwrap()).await, mp3());
    assert_eq!(both.blob(doc.video.as_ref().unwrap()).await, mp4());
    assert!(!warning(&doc).contains("not_found"), "{:?}", doc.warning);
}

#[tokio::test]
async fn a_video_element_answers_audio_as_its_container() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let done = go(&dir, Spec::new(site.url("/video-only"), audio())).await;
    let doc = done.doc("/video-only");
    let blob = doc.audio.as_ref().expect("audio from the video file");
    assert_eq!(blob.content_type, "video/mp4");
    assert_eq!(done.blob(blob).await, mp4());
    assert!(doc.video.is_none(), "video was not requested");
    assert!(
        warning(&doc).contains("audio_not_extracted:"),
        "{:?}",
        doc.warning
    );
}

#[tokio::test]
async fn an_octet_stream_link_with_a_media_extension_is_downloaded() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let done = go(&dir, Spec::new(site.url("/octet"), audio())).await;
    assert_eq!(done.blob(done.doc("/octet").audio.as_ref().unwrap()).await, mp3());
}

// ---- nothing usable: a warning, never a failed page ------------------------------------------------------------------

#[tokio::test]
async fn a_page_without_media_warns_and_is_still_returned() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let done = go(
        &dir,
        Spec::new(
            site.url("/none"),
            vec![FormatSpec::Markdown, FormatSpec::Audio, FormatSpec::Video],
        ),
    )
    .await;
    assert_eq!(done.row("/none").await.status, FrontierStatus::Succeeded);
    let doc = done.doc("/none");
    assert!(doc.audio.is_none() && doc.video.is_none() && doc.transcript.is_none());
    let w = warning(&doc);
    assert!(
        w.contains("audio_not_found: the page references no audio file"),
        "{w}"
    );
    assert!(
        w.contains("video_not_found: the page references no video file"),
        "{w}"
    );
    assert!(!w.contains("transcription"), "nothing to transcribe: {w}");
    assert!(done.page("/none").markdown.is_some());
}

#[tokio::test]
async fn dead_and_non_media_downloads_are_warnings() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let dead = go(&dir, Spec::new(site.url("/dead"), audio())).await;
    assert_eq!(dead.row("/dead").await.status, FrontierStatus::Succeeded);
    let w = warning(&dead.doc("/dead"));
    assert!(w.starts_with("audio_not_found:") && w.contains("HTTP 404"), "{w}");

    let wrong = go(&dir, Spec::new(site.url("/wrong-type"), audio())).await;
    let w = warning(&wrong.doc("/wrong-type"));
    assert!(
        w.starts_with("audio_not_found:") && w.contains("not a media file, content type text/html"),
        "{w}"
    );
    assert!(wrong.doc("/wrong-type").audio.is_none());
}

#[tokio::test]
async fn a_file_beyond_the_media_limit_is_not_stored_and_warns() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    // referenced file: the fetcher cuts it at the limit
    let referenced = go(&dir, Spec::new(site.url("/podcast"), audio()).media_max(1_000)).await;
    assert_eq!(referenced.row("/podcast").await.status, FrontierStatus::Succeeded);
    let doc = referenced.doc("/podcast");
    assert!(doc.audio.is_none());
    let w = warning(&doc);
    assert!(
        w.starts_with("media_too_large: the audio file ") && w.contains("is larger than the 1000 byte limit"),
        "{w}"
    );
    // the page itself is the file
    let direct = go(
        &dir,
        Spec::new(site.url("/media/clip.mp4"), vec![FormatSpec::Video]).media_max(1_000),
    )
    .await;
    assert_eq!(
        direct.row("/media/clip.mp4").await.status,
        FrontierStatus::Succeeded
    );
    let doc = direct.doc("/media/clip.mp4");
    assert!(doc.video.is_none());
    assert!(
        warning(&doc).starts_with("media_too_large: the video file "),
        "{:?}",
        doc.warning
    );
}

#[tokio::test]
async fn a_media_host_the_egress_policy_refuses_is_a_warning_not_a_failure() {
    let other = start_other_port().await;
    let (site, dir) = (start(Some(&other)).await, tempfile::tempdir().unwrap());
    let done = go(&dir, Spec::new(site.url("/denied"), audio())).await;
    assert_eq!(done.row("/denied").await.status, FrontierStatus::Succeeded);
    let doc = done.doc("/denied");
    assert!(doc.audio.is_none());
    let w = warning(&doc);
    assert!(
        w.starts_with("audio_not_found:") && w.contains("egress denied"),
        "{w}"
    );
    assert_eq!(other.count("/a.mp3"), 0, "a refused host is never contacted");
}

// ---- transcripts -------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_transcribing_llm_fills_the_transcript_and_charges_tokens() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let llm = Arc::new(MockLlm::scripted(vec![]).with_transcript("Welcome to the show."));
    let done = go(
        &dir,
        Spec::new(site.url("/watch"), vec![FormatSpec::Audio, FormatSpec::Video]).llm(&llm),
    )
    .await;
    let doc = done.doc("/watch");
    assert_eq!(doc.transcript.as_deref(), Some("Welcome to the show."));
    assert!(doc.llm_tokens > 0, "the transcript's tokens are charged");
    assert!(doc.warning.is_none(), "{:?}", doc.warning);
    let calls = llm.transcriptions();
    assert_eq!(calls.len(), 1, "one transcription, of the audio file");
    assert_eq!(
        (calls[0].file_name.as_str(), calls[0].content_type.as_str()),
        ("ep.mp3", "audio/mpeg")
    );
    assert_eq!(calls[0].audio, mp3());
}

#[tokio::test]
async fn a_video_only_request_transcribes_the_video_file() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let llm = Arc::new(MockLlm::scripted(vec![]).with_transcript("clip words"));
    let done = go(
        &dir,
        Spec::new(site.url("/media/clip.mp4"), vec![FormatSpec::Video]).llm(&llm),
    )
    .await;
    assert_eq!(
        done.doc("/media/clip.mp4").transcript.as_deref(),
        Some("clip words")
    );
    let calls = llm.transcriptions();
    assert_eq!(
        (
            calls[0].file_name.as_str(),
            calls[0].content_type.as_str(),
            calls[0].audio.as_slice()
        ),
        ("clip.mp4", "video/mp4", mp4().as_slice())
    );
}

#[tokio::test]
async fn without_a_transcribing_endpoint_the_page_says_so() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let llm = Arc::new(MockLlm::scripted(vec![]));
    let done = go(&dir, Spec::new(site.url("/podcast"), audio()).llm(&llm)).await;
    let doc = done.doc("/podcast");
    assert!(doc.audio.is_some() && doc.transcript.is_none());
    let w = warning(&doc);
    assert!(
        w.starts_with("transcription_unavailable:") && w.contains("llm.transcribeEndpoint"),
        "{w}"
    );
    assert!(llm.transcriptions().is_empty());
}

#[tokio::test]
async fn a_failing_transcription_is_a_warning_and_the_audio_is_kept() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let llm = Arc::new(MockLlm::scripted(vec![]).with_transcript_error(LlmError::Status { status: 502 }));
    let done = go(&dir, Spec::new(site.url("/podcast"), audio()).llm(&llm)).await;
    assert_eq!(done.row("/podcast").await.status, FrontierStatus::Succeeded);
    let doc = done.doc("/podcast");
    assert_eq!(done.blob(doc.audio.as_ref().unwrap()).await, mp3());
    assert!(doc.transcript.is_none());
    assert_eq!(
        warning(&doc),
        "transcription_failed: LLM endpoint returned HTTP 502"
    );
}

#[tokio::test]
async fn zero_data_retention_delivers_volatile_media_and_transcript_without_durable_objects() {
    let (site, dir) = (start(None).await, tempfile::tempdir().unwrap());
    let llm = Arc::new(MockLlm::scripted(vec![]).with_transcript("ephemeral words"));
    let done = go(&dir, Spec::new(site.url("/podcast"), audio()).llm(&llm).zdr()).await;
    let doc = done.doc("/podcast");
    let audio = doc.audio.as_ref().expect("authorized volatile audio delivery");
    assert_eq!(done.blob(audio).await, mp3());
    assert!(doc.not_cacheable);
    assert!(
        !warning(&doc).contains("not retained under the run's retention policy"),
        "{:?}",
        doc.warning
    );
    assert_eq!(doc.transcript.as_deref(), Some("ephemeral words"));
    assert_eq!(done.row("/podcast").await.status, FrontierStatus::Succeeded);
    let durable = FsBlobs::open(dir.path()).await.unwrap();
    assert!(
        durable.list("").await.unwrap().is_empty(),
        "ZDR media and page content must never reach the filesystem artifact backend"
    );
    let calls = llm.transcriptions();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].audio, mp3());
}
