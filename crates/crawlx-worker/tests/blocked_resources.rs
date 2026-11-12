//! End-to-end rule blocking: a dynamic crawl with `dynamic.blockRules` publishes an archive whose
//! manifest names every blocked resource with the kind of rule that blocked it. Real Chromium
//! runs only when `CRAWLX_CHROMIUM_PATH` is set.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::authorization::run_authorized_local_with;
use crawlx_core::archive::ArchiveConfigV1;
use crawlx_core::archive_catalog::{ArchiveExportState, ArchiveReadV1};
use crawlx_core::block_rules::BlockRulesV1;
use crawlx_core::browser_capture::BrowserEvidenceConfig;
use crawlx_core::config::CrawlMode;
use crawlx_core::{Clock, CreateCrawl, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use parking_lot::Mutex;
use std::sync::Arc;

const PAGE: &str = r#"<!doctype html><title>Rules fixture</title>
<h1>rules</h1>
<img src="/blocked/a.svg"><img src="/allowed/b.svg"><img src="/allowed/tracker.svg">
<iframe src="/embed"></iframe>"#;

const SVG: &str =
    r#"<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1"/></svg>"#;

struct Outcome {
    /// `(reason, path of the target)` of every omission a rule caused, sorted.
    blocked: Vec<(String, String)>,
    /// Paths the fixture server was asked for.
    requested: Vec<String>,
}

async fn run(rules: impl FnOnce(u16) -> BlockRulesV1) -> Option<Outcome> {
    let executable = std::env::var_os("CRAWLX_CHROMIUM_PATH")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
        let log = Arc::clone(&log);
        async move {
            let path = uri.path().to_owned();
            log.lock().push(path.clone());
            match path.as_str() {
                "/" => ([("content-type", "text/html")], PAGE.to_owned()),
                "/embed" => (
                    [("content-type", "text/html")],
                    "<!doctype html><p>embedded</p>".to_owned(),
                ),
                p if p.ends_with(".svg") => ([("content-type", "image/svg+xml")], SVG.to_owned()),
                _ => ([("content-type", "text/plain")], "not found".to_owned()),
            }
        }
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(format!("http://127.0.0.1:{port}/").parse().unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.seed = Some(26_111_201);
    // retained phase text gives the archive its records; the rules are what is under test
    let mut evidence = BrowserEvidenceConfig::default();
    evidence.phase_resources = true;
    crawl.capture.browser = evidence;
    crawl.output.archive = Some(ArchiveConfigV1::default());
    crawl.dynamic.block_rules = Some(rules(port));
    crawl.safety.profile = crawlx_core::SafetyProfile::TestEnvironment;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.limits.states = 2;
    crawl.limits.interactions = 1;
    crawl.limits.duration_seconds = 30;
    let mut config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            extra_allow: vec!["127.0.0.1/32".parse().unwrap()],
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    config.launch.executable = executable.into();
    config.launch.allow_unpinned = true;
    let report = run_authorized_local_with(LocalRun::new(crawl, config).with_stores(stores.clone()))
        .await
        .unwrap();
    server.abort();
    let run = stores.runs.get(report.run_id).await.unwrap();
    let ArchiveReadV1::Available(export) = stores
        .archives
        .get(run.tenant, run.id.0, SystemClock.now())
        .await
        .unwrap()
    else {
        panic!("the archive was not published");
    };
    assert_eq!(export.state, ArchiveExportState::Published);
    let mut blocked: Vec<(String, String)> = export
        .manifest
        .unwrap()
        .omissions
        .into_iter()
        .filter(|omission| omission.reason.starts_with("blocked_by_"))
        .map(|omission| {
            let target = omission.target.expect("a blocked resource names its target");
            (
                omission.reason,
                url::Url::parse(&target).unwrap().path().to_owned(),
            )
        })
        .collect();
    blocked.sort();
    let requested = seen.lock().clone();
    Some(Outcome { blocked, requested })
}

fn pair(reason: &str, path: &str) -> (String, String) {
    (reason.to_owned(), path.to_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn url_frame_and_text_rules_each_leave_an_omission_per_blocked_resource() {
    let Some(outcome) = run(|_| {
        let mut rules = BlockRulesV1::default();
        rules.urls = vec!["*/blocked/*".to_owned()];
        rules.frames = vec!["*/embed".to_owned()];
        rules.text = vec!["tracker".to_owned()];
        rules
    })
    .await
    else {
        return;
    };
    assert_eq!(
        outcome.blocked,
        vec![
            pair("blocked_by_frame_rule", "/embed"),
            pair("blocked_by_text_rule", "/allowed/tracker.svg"),
            pair("blocked_by_url_rule", "/blocked/a.svg"),
        ]
    );
    // exactly the blocked resources were kept off the network
    for path in ["/blocked/a.svg", "/embed", "/allowed/tracker.svg"] {
        assert!(
            !outcome.requested.iter().any(|seen| seen == path),
            "{path} was requested"
        );
    }
    assert!(outcome.requested.iter().any(|seen| seen == "/allowed/b.svg"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_only_rules_leave_an_omission_for_everything_not_allowed() {
    let Some(outcome) = run(|_| {
        let mut rules = BlockRulesV1::default();
        rules.allow_only = vec!["*/allowed/*".to_owned(), "*/favicon.ico".to_owned()];
        rules
    })
    .await
    else {
        return;
    };
    assert_eq!(
        outcome.blocked,
        vec![
            pair("blocked_by_allow_only_rule", "/blocked/a.svg"),
            pair("blocked_by_allow_only_rule", "/embed"),
        ]
    );
    assert!(
        outcome.requested.iter().any(|seen| seen == "/"),
        "the visited page itself loads"
    );
    assert!(outcome.requested.iter().any(|seen| seen == "/allowed/b.svg"));
    assert!(!outcome.requested.iter().any(|seen| seen == "/blocked/a.svg"));
}
