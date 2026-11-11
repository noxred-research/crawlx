//! Two runs with the same seed against the same scripted app produce the same action sequence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

/// A hub page with a menu that reveals more controls, plus three leaf pages.
fn app() -> FakeScript {
    let mut hub = FakePage::new("https://example.test/").title("Hub");
    for i in 0..6 {
        let key = format!("tab{i}");
        let revealed = FakeAxSpec::button(format!("item{i}"), format!("Item {i}"));
        hub = hub
            .node(FakeAxSpec::button(key.clone(), format!("Tab {i}")))
            .on_click(&key, vec![FakeEffect::Reveal(vec![revealed])])
            .on_click(&format!("item{i}"), vec![FakeEffect::Nothing]);
    }
    for (key, name, to) in [("a", "Alpha", "/a"), ("b", "Beta", "/b"), ("c", "Gamma", "/c")] {
        hub = hub
            .node(FakeAxSpec::link(key, name, to))
            .on_click(key, vec![FakeEffect::Navigate(to.to_owned())]);
    }
    let mut script = FakeScript::new().page(hub);
    for (path, title) in [("a", "Alpha"), ("b", "Beta"), ("c", "Gamma")] {
        let mut leaf = FakePage::new(&format!("https://example.test/{path}")).title(title);
        leaf = leaf
            .node(FakeAxSpec::link("home", "Home", "/"))
            .on_click("home", vec![FakeEffect::Navigate("/".to_owned())]);
        for i in 0..3 {
            let key = format!("{path}{i}");
            leaf = leaf
                .node(FakeAxSpec::button(key.clone(), format!("{title} action {i}")))
                .on_click(&key, vec![FakeEffect::Nothing]);
        }
        script = script.page(leaf);
    }
    script
}

async fn once(seed: u64) -> (Vec<String>, Vec<(String, String)>) {
    once_with_trace(seed, None).await
}

async fn once_with_trace(
    seed: u64,
    action_trace: Option<Arc<crawlx_worker::action_trace::ActionTrace>>,
) -> (Vec<String>, Vec<(String, String)>) {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(
        FakeBackend::builder()
            .script(app())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store, dir.path()).await.unwrap();
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        action_trace,
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.seed = Some(seed);
    crawl.limits.interactions = 40;
    crawl.limits.states = 100;
    let report = run_local_with(
        LocalRun::new(crawl, cfg)
            .with_backend(backend.clone())
            .with_stores(stores),
    )
    .await
    .unwrap();
    let performed = backend
        .context_handles()
        .iter()
        .flat_map(|h| h.performed_keys())
        .collect();
    let journal = report
        .actions
        .iter()
        .map(|a| (a.key.id().to_string(), a.strategy.clone()))
        .collect();
    (performed, journal)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_seed_same_action_sequence() {
    let first = once(20_261_019).await;
    assert!(
        first.0.len() >= 10,
        "too few actions to mean anything: {:?}",
        first.0
    );
    for _ in 0..4 {
        let again = once(20_261_019).await;
        assert_eq!(first.0, again.0, "performed actions differ between runs");
        assert_eq!(first.1, again.1, "journals differ between runs");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_seed_same_sequence_under_load() {
    // contending runs must not change what a run decides
    let baseline = once(7).await;
    let (a, b, c) = tokio::join!(once(7), once(7), once(7));
    for r in [a, b, c] {
        assert_eq!(baseline.0, r.0);
        assert_eq!(baseline.1, r.1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_evidence_does_not_change_effective_browser_or_journal_trace() {
    let baseline = once(7).await;
    let trace = Arc::new(crawlx_worker::action_trace::ActionTrace::default());
    let recorded = once_with_trace(7, Some(Arc::clone(&trace))).await;
    assert_eq!(
        serde_json::to_vec(&baseline).unwrap(),
        serde_json::to_vec(&recorded).unwrap(),
        "evidence collection changed effective action order or journal decisions",
    );
    let steps = trace.take();
    assert_eq!(steps.len(), recorded.0.len());
    assert!(steps.iter().all(|step| step.step.parameters_digest.is_some()));
}
