//! `event_driven` through the worker: what a click just exposed is acted on first.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, StrategyName};
use crawlx_core::{CreateCrawl, SafetyProfile};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

/// A page with a menu button whose click reveals two items; the items do nothing.
fn menu_app() -> FakeScript {
    let mut page = FakePage::new("https://example.test/").title("Menu");
    for (key, name) in [("a", "Alpha"), ("b", "Bravo"), ("c", "Charlie")] {
        page = page
            .node(FakeAxSpec::button(key, name))
            .on_click(key, vec![FakeEffect::Nothing]);
    }
    page = page.node(FakeAxSpec::button("menu", "Menu")).on_click(
        "menu",
        vec![FakeEffect::Reveal(vec![
            FakeAxSpec::button("export", "Export data"),
            FakeAxSpec::button("import", "Import data"),
        ])],
    );
    FakeScript::new().page(page)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_controls_an_action_revealed_are_tried_right_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FakeBackend::new(menu_app()));
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.seed = Some(7);
    crawl.safety.profile = SafetyProfile::TestEnvironment;
    crawl.limits.interactions = 30;
    crawl.dynamic.strategies = vec![StrategyName::InteractionBfs, StrategyName::EventDriven];
    let report = run_local_with(
        LocalRun::new(crawl, cfg)
            .with_backend(backend.clone())
            .with_stores(stores),
    )
    .await
    .unwrap();
    let performed: Vec<String> = backend
        .context_handles()
        .iter()
        .flat_map(|h| h.performed_keys())
        .collect();
    let menu = performed
        .iter()
        .position(|k| k == "click:menu")
        .unwrap_or_else(|| panic!("the menu was clicked: {performed:?}"));
    assert!(
        matches!(
            performed.get(menu + 1).map(String::as_str),
            Some("click:export" | "click:import")
        ),
        "the revealed item is next: {performed:?}"
    );
    assert!(
        report.actions.iter().any(|a| a.strategy == "event_driven"),
        "a revealed control was chosen on the strength of the event: {:?}",
        report
            .actions
            .iter()
            .map(|a| a.strategy.clone())
            .collect::<Vec<_>>()
    );
}
