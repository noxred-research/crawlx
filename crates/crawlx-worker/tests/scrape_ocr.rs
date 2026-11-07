//! OCR in scrape runs (`WorkerConfig::ocr`): the `image` parser and PDF `mode: auto|ocr|fast`
//! through real runs over in-memory stores and a fixture site, with Tesseract reading generated
//! scans. Without an engine the documents keep the `ocr_unavailable` warning. The OCR tests skip
//! (printing why) without the `tesseract` binary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

#[path = "../../crawlx-extract/tests/support/scan.rs"]
mod scan;

use authorization_fixture::run_authorized_local_with as run_local_with;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use crawlx_core::config::{CrawlMode, HostScope, SitemapMode};
use crawlx_core::repo::{FrontierStatus, PageRecord};
use crawlx_core::scrape::{JobKind, ParserSpec, PdfMode, ScrapeDocument, ScrapeJob, ScrapeOptions};
use crawlx_core::CreateCrawl;
use crawlx_extract::parse::ocr::{Ocr, OcrBackend, OcrConfig, OcrError};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use scan::PageKind;
use std::sync::Arc;
use url::Url;

fn engine() -> Option<Arc<Ocr>> {
    let config = OcrConfig {
        backend: OcrBackend::Tesseract,
        ..OcrConfig::default()
            .apply_env(&|k| (k == "TESSDATA_PREFIX").then(|| std::env::var(k).ok()).flatten())
            .unwrap()
    };
    match Ocr::shared(&config) {
        Ok(e) => e,
        Err(e @ OcrError::Unavailable { .. }) => {
            eprintln!("skipping: {e}");
            None
        }
        Err(e) => panic!("{e}"),
    }
}

fn lines() -> scan::Gray {
    scan::render_lines(&["HELLO WORLD", "SCANNED INVOICE"], 8).0
}

async fn site() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let png = scan::png(&lines());
    let page = scan::on_page(&lines(), 1224, 1584, 100, 150);
    let pdf = scan::pdf(&[PageKind::Scan {
        img: &page,
        rotate: 0,
    }]);
    let app = Router::new()
        .route(
            "/scan.png",
            get(move || {
                let png = png.clone();
                async move { ([(header::CONTENT_TYPE, "image/png")], png).into_response() }
            }),
        )
        .route(
            "/scan.pdf",
            get(move || {
                let pdf = pdf.clone();
                async move { ([(header::CONTENT_TYPE, "application/pdf")], pdf).into_response() }
            }),
        );
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), task)
}

struct Done {
    report: RunReport,
    stores: Stores,
    _dir: tempfile::TempDir,
}

impl Done {
    fn page(&self, path: &str) -> &PageRecord {
        self.report
            .pages
            .iter()
            .find(|p| p.url.url.path() == path)
            .unwrap_or_else(|| panic!("no page row for {path}"))
    }
    fn doc(&self, path: &str) -> ScrapeDocument {
        ScrapeDocument::from_page_metadata(&self.page(path).metadata).unwrap()
    }
    async fn markdown(&self, path: &str) -> String {
        let artifact = self.page(path).markdown.as_ref().expect("markdown artifact");
        String::from_utf8(self.stores.artifacts.get(artifact).await.unwrap()).unwrap()
    }
}

async fn go(url: &str, options: ScrapeOptions, ocr: Option<Arc<Ocr>>) -> Done {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(Url::parse(url).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_028);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files = Vec::new();
    crawl.scope.host_scope = HostScope::None;
    crawl.scope.max_discovery_depth = 0;
    crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, options));
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
            ..EgressConfig::default()
        },
        ocr,
        ..WorkerConfig::default()
    };
    let report = run_local_with(LocalRun::new(crawl, cfg).with_stores(stores.clone()))
        .await
        .unwrap();
    Done {
        report,
        stores,
        _dir: dir,
    }
}

fn pdf_mode(mode: PdfMode) -> ScrapeOptions {
    ScrapeOptions {
        parsers: vec![ParserSpec::Pdf {
            mode,
            max_pages: None,
            pages: true,
            blocks: false,
            page_markers: false,
        }],
        ..ScrapeOptions::default()
    }
}

fn warning(doc: &ScrapeDocument) -> String {
    doc.warning.clone().unwrap_or_default()
}

#[tokio::test]
async fn without_an_engine_scans_keep_the_ocr_unavailable_warning() {
    let (base, _task) = site().await;
    let img = go(&format!("{base}/scan.png"), ScrapeOptions::default(), None).await;
    assert!(
        warning(&img.doc("/scan.png")).contains("ocr_unavailable"),
        "{:?}",
        img.doc("/scan.png").warning
    );
    assert_eq!(img.markdown("/scan.png").await, "");
    let pdf = go(&format!("{base}/scan.pdf"), ScrapeOptions::default(), None).await;
    assert!(
        warning(&pdf.doc("/scan.pdf")).contains("ocr_unavailable"),
        "{:?}",
        pdf.doc("/scan.pdf").warning
    );
}

#[tokio::test]
async fn the_image_parser_reads_an_image_url() {
    let Some(ocr) = engine() else {
        return;
    };
    let (base, _task) = site().await;
    let done = go(&format!("{base}/scan.png"), ScrapeOptions::default(), Some(ocr)).await;
    let row = done.stores.frontier.list(done.report.run_id).await.unwrap();
    assert_eq!(row[0].status, FrontierStatus::Succeeded);
    assert_eq!(
        scan::words(&done.markdown("/scan.png").await),
        "HELLO WORLD SCANNED INVOICE"
    );
    let doc = done.doc("/scan.png");
    assert!(!warning(&doc).contains("ocr_unavailable"), "{:?}", doc.warning);
    assert_eq!(doc.content_type.as_deref(), Some("image/png"));
}

#[tokio::test]
async fn a_parsers_list_without_image_still_refuses_images() {
    let Some(ocr) = engine() else {
        return;
    };
    let (base, _task) = site().await;
    let options = ScrapeOptions {
        parsers: vec![ParserSpec::pdf()],
        ..ScrapeOptions::default()
    };
    let done = go(&format!("{base}/scan.png"), options, Some(ocr)).await;
    let rows = done.stores.frontier.list(done.report.run_id).await.unwrap();
    assert_ne!(rows[0].status, FrontierStatus::Succeeded);
}

#[tokio::test]
async fn scanned_pdf_pages_are_read_in_auto_and_ocr_modes() {
    let Some(ocr) = engine() else {
        return;
    };
    let (base, _task) = site().await;
    for mode in [PdfMode::Auto, PdfMode::Ocr] {
        let done = go(&format!("{base}/scan.pdf"), pdf_mode(mode), Some(ocr.clone())).await;
        let doc = done.doc("/scan.pdf");
        assert_eq!(
            scan::words(&done.markdown("/scan.pdf").await),
            "HELLO WORLD SCANNED INVOICE",
            "{mode:?}"
        );
        assert!(
            !warning(&doc).contains("ocr_unavailable"),
            "{mode:?}: {:?}",
            doc.warning
        );
        assert_eq!(doc.num_pages, Some(1));
        let pages = doc.pages.as_ref().unwrap();
        assert_eq!(scan::words(&pages[0].markdown), "HELLO WORLD SCANNED INVOICE");
    }
}

#[tokio::test]
async fn fast_mode_never_runs_the_engine() {
    let Some(ocr) = engine() else {
        return;
    };
    let (base, _task) = site().await;
    let done = go(&format!("{base}/scan.pdf"), pdf_mode(PdfMode::Fast), Some(ocr)).await;
    assert_eq!(done.markdown("/scan.pdf").await.trim(), "");
    assert!(
        warning(&done.doc("/scan.pdf")).contains("fast"),
        "{:?}",
        done.doc("/scan.pdf").warning
    );
}
