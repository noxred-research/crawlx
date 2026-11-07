//! Shadow System 1 decisions land in `model_decisions` over PostgreSQL (skipped without
//! `CRAWLX_TEST_DATABASE_URL`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, StrategyName, System1Mode};
use crawlx_core::repo::{ModelDecisionKind, ModelDecisionRepo, RunRepo};
use crawlx_core::{CreateCrawl, SystemClock, TenantId};
use crawlx_fetch::StaticResolver;
use crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys;
use crawlx_storage::{FsArtifactStore, Pg, PgConfig};
use crawlx_worker::{
    run_local_with, EgressConfig, EngineConfig, LocalRun, ModelConfig, Stores, WorkerConfig,
};
use std::sync::Arc;

#[tokio::test]
async fn shadow_decisions_round_trip_through_model_decisions() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("t_worker_{}", uuid::Uuid::now_v7().simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
    let artifacts = FsArtifactStore::open(dir.path(), runs, Arc::new(SystemClock))
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let mut stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), TenantId::new());
    stores.checkpoint_keys = Arc::new(MemoryCheckpointKeys::new().unwrap());

    let mut home = FakePage::new("https://example.test/").title("Home");
    for (key, name, to) in [("a", "Alpha", "/a"), ("b", "Bravo", "/b"), ("c", "Charlie", "/c")] {
        home = home
            .node(FakeAxSpec::link(key, name, to))
            .on_click(key, vec![FakeEffect::Navigate(to.to_owned())]);
    }
    let mut script = FakeScript::new().page(home);
    for (path, title) in [("a", "A"), ("b", "B"), ("c", "C")] {
        script = script.page(
            FakePage::new(&format!("https://example.test/{path}"))
                .title(title)
                .node(FakeAxSpec::link("h", "Home", "/"))
                .on_click("h", vec![FakeEffect::Navigate("/".into())]),
        );
    }
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.limits.interactions = 8;
    crawl.dynamic.strategies = vec![StrategyName::InteractionBfs, StrategyName::System1];
    crawl.dynamic.system1_mode = System1Mode::Shadow;
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        model: Some(ModelConfig {
            engine: EngineConfig::Mock,
            mode: System1Mode::Shadow,
        }),
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let backend = Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(SystemClock))
            .build(),
    );
    let report = run_local_with(
        LocalRun::new(crawl, cfg)
            .with_backend(backend)
            .with_stores(stores),
    )
    .await
    .unwrap();

    let rows = ModelDecisionRepo::list(&pg, report.run_id).await.unwrap();
    assert!(!rows.is_empty(), "the shadow decisions were stored");
    let sessions = RunRepo::list_sessions(&pg, report.run_id).await.unwrap();
    for r in &rows {
        assert_eq!(r.kind, ModelDecisionKind::Rank);
        assert_eq!(r.mode, System1Mode::Shadow);
        assert_eq!(r.provider, "mock");
        assert_eq!(r.session, Some(sessions[0].id));
        assert!(r.output["shortlist"].as_array().is_some_and(|s| s.len() >= 2));
        assert_ne!(r.prompt_digest.0, [0_u8; 32]);
        assert!(r.latency_ms.is_some());
    }
    // recording a decision twice is a no-op
    ModelDecisionRepo::record(&pg, &rows[0]).await.unwrap();
    assert_eq!(
        ModelDecisionRepo::list(&pg, report.run_id).await.unwrap().len(),
        rows.len()
    );
    pg.drop_schema().await.unwrap();
}
