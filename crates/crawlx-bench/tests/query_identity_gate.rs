//! G12 `query-identity` gate without a browser: a real worker crawl of the fixture whose links
//! carry a session value, scored by [`QueryIdentityMetrics`] (merge count, tracking
//! duplicates) and grepped for the session value in every artifact the run produced.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine as _;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::query_identity::{ArtifactScan, QueryIdentityMetrics, ResourceFamily, SessionValueGate};
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_core::config::{CrawlMode, OutputFormat, SafetyProfile};
use crawlx_core::repo::FrontierStatus;
use crawlx_core::url::ParamClass;
use crawlx_worker::{run_local_with, LocalRun};
use std::collections::BTreeSet;
use std::path::Path;

/// The session value the fixture injects into `invoice?id=3&sessionid=...`.
const SESSION_VALUE: &str = "g12_session_canary_7d91e8c4";

async fn gym() -> GymHandle {
    GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap()
}

fn session_gate() -> SessionValueGate {
    let mut gate = SessionValueGate::new(&[SESSION_VALUE]);
    for engine in [
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        for shift in 0..3_usize {
            let mut padded = vec![b'\0'; shift];
            padded.extend_from_slice(SESSION_VALUE.as_bytes());
            let encoded = engine.encode(&padded);
            // Match embedded base64 whatever the alignment of the surrounding bytes.
            let lead = [0, 2, 3][shift];
            gate = gate.with_pattern(
                format!("{SESSION_VALUE} (base64 shift {shift})"),
                encoded.as_bytes()[lead..encoded.len() - 4].to_vec(),
            );
        }
    }
    gate
}

async fn scan_dir(gate: &SessionValueGate, root: &Path, scan: &mut ArtifactScan) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let mut entries = tokio::fs::read_dir(dir).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if entry.file_type().await.unwrap().is_dir() {
                pending.push(entry.path());
            } else {
                let bytes = tokio::fs::read(entry.path()).await.unwrap();
                scan.inspect(gate, &entry.path().display().to_string(), &bytes);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g12_crawl_has_no_merge_no_tracking_duplicate_and_no_session_value_anywhere() {
    let gate = session_gate();
    let gym = gym().await;
    gym.reset(12);
    let manifest = FixtureManifest::embedded("g12").unwrap();

    // The gate can fire: the live fixture page carries the session value in a link.
    let served = reqwest::get(manifest.entry_url(&gym.base_url))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert!(
        gate.find(&served).is_some(),
        "the fixture must inject the session value, or the grep gate proves nothing"
    );

    let mut request = crawl_request(&manifest, &gym.base_url, 12, SafetyProfile::ReadOnly).unwrap();
    request.mode = CrawlMode::Static;
    request.dynamic.enabled = false;
    request.output.formats.push(OutputFormat::Html);
    request.limits.urls = 40;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = crawlx_worker::Stores::open(&cfg).await.unwrap();
    let report = run_local_with(authorize_fixture(
        LocalRun::new(request, cfg).with_stores(stores.clone()),
    ))
    .await
    .unwrap();
    assert!(report.status.is_terminal(), "{:?}", report.status);

    // (b) G12 gate metrics from the frontier rows.
    let frontier = stores.frontier.list(report.run_id).await.unwrap();
    let expected_ids: BTreeSet<String> = ["1", "2", "3", "4", "5"].map(str::to_owned).into();
    let metrics = QueryIdentityMetrics::from_frontier(
        &frontier,
        &ResourceFamily {
            path: "/g12/invoice",
            id_param: "id",
            expected_ids: &expected_ids,
        },
    );
    assert_eq!(metrics.resources, 5);
    assert!(metrics.passed(), "{metrics:?}\n{frontier:#?}");
    assert!(
        metrics.checks().iter().all(|c| c.passed),
        "{:?}",
        metrics.checks()
    );
    assert!(
        frontier.iter().all(|row| row.url.params.iter().all(|param| {
            !matches!(param.class, ParamClass::Tracking | ParamClass::Session) || param.value.is_none()
        })),
        "tracking and session parameters must carry no value"
    );
    assert!(
        frontier
            .iter()
            .any(|row| { row.status == FrontierStatus::Succeeded && row.url.url.path() == "/g12/invoice" }),
        "the invoices must be fetched, not only enumerated: {frontier:?}"
    );

    // (a) the grep gate over EVERY artifact of the run.
    let mut scan = ArtifactScan::default();
    // Persisted rows (pages, events, frontier, ledger, journal, ...) as the database would hold them.
    let memory = stores.memory.as_ref().expect("runs on the memory store");
    scan.inspect(&gate, "memory dump", memory.dump_run(report.run_id).as_bytes());
    // Frontier rows serialized as JSON.
    scan.inspect(
        &gate,
        "frontier json",
        serde_json::to_string(&frontier).unwrap().as_bytes(),
    );
    // The report as JSON, and the page contents the report carries outside the JSON.
    scan.inspect(
        &gate,
        "report json",
        serde_json::to_string(&report).unwrap().as_bytes(),
    );
    for content in &report.page_contents {
        for (kind, body) in [
            ("html", &content.html),
            ("markdown", &content.markdown),
            ("raw", &content.raw),
        ] {
            if let Some(body) = body {
                scan.inspect(
                    &gate,
                    &format!("page content {kind} {}", content.url),
                    body.as_bytes(),
                );
            }
        }
    }
    // Stored page artifacts, decoded.
    for page in &report.pages {
        for artifact in page.html.iter().chain(page.markdown.iter()) {
            let bytes = stores.artifacts.get(artifact).await.unwrap();
            scan.inspect(&gate, &format!("page artifact {}", page.url.url), &bytes);
        }
    }
    // Everything on disk under the artifact directory.
    scan_dir(&gate, dir.path(), &mut scan).await;
    assert!(
        scan.checked >= 4 + report.pages.len() as u64,
        "the scan must inspect real run output: {scan:?}"
    );
    assert!(scan.leaks.is_empty(), "session value leaked: {:#?}", scan.leaks);
    assert!(scan.is_clean());
    gym.shutdown().await;
}
