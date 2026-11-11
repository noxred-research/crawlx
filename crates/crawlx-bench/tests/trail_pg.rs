//! `verify_trail` over PostgreSQL: a fake-backend worker run leaves a clean trail, and a
//! deleted `transitions` row is reported. Skipped without `CRAWLX_TEST_DATABASE_URL`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/authorization.rs"]
mod authorization;

use crawlx_bench::trail::{verify_trail, TrailStore, TrailViolation};
use crawlx_bench::worker_exec::authorize_fixture;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::ActionStatus;
use crawlx_core::repo::{ActionJournal, RunRepo};
use crawlx_core::{CreateCrawl, SystemClock, TenantId};
use crawlx_fetch::StaticResolver;
use crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys;
use crawlx_storage::{FsArtifactStore, Pg, StoreConfig};
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

#[tokio::test]
async fn pg_trail_is_clean_after_a_run_and_reports_a_deleted_transition() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("t_trail_{}", uuid::Uuid::now_v7().simple())),
            ..StoreConfig::default()
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
    let mut stores = Stores::over_durable(
        crawlx_worker::DurableStore::Postgres(pg.clone()),
        Arc::new(artifacts),
        TenantId::new(),
    );
    stores.checkpoint_keys = Arc::new(MemoryCheckpointKeys::new().unwrap());
    let artifacts = Arc::clone(&stores.artifacts);

    let mut home = FakePage::new("https://example.test/").title("Home");
    for (key, name, to) in [("a", "Alpha", "/a"), ("b", "Bravo", "/b")] {
        home = home
            .node(FakeAxSpec::link(key, name, to))
            .on_click(key, vec![FakeEffect::Navigate(to.to_owned())]);
    }
    let mut script = FakeScript::new().page(home);
    for (path, title) in [("a", "A"), ("b", "B")] {
        script = script.page(
            FakePage::new(&format!("https://example.test/{path}"))
                .title(title)
                .node(FakeAxSpec::link("h", "Home", "/"))
                .on_click("h", vec![FakeEffect::Navigate("/".into())]),
        );
    }
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.limits.interactions = 6;
    // This fixture persists authorization through the real PostgreSQL lifecycle.
    // Select its reference explicitly; authorize_fixture does not invent one.
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let backend = Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(SystemClock))
            .build(),
    );
    let local = authorize_fixture(
        LocalRun::new(crawl, cfg)
            .with_backend(backend)
            .with_stores(stores),
    );
    authorization::register_verified_record(&pg, local.authorization.as_ref().unwrap()).await;
    let report = run_local_with(local).await.unwrap();

    let clean = verify_trail(
        report.run_id,
        TrailStore::Database {
            store: &crawlx_worker::DurableStore::Postgres(pg.clone()),
            artifacts: Some(artifacts.as_ref()),
        },
    )
    .await
    .unwrap();
    assert!(clean.is_clean(), "{clean}");
    assert!(clean.checked["actions"] > 0, "{clean}");
    assert!(clean.checked["transitions"] > 0, "{clean}");

    // inject: drop the transition of one succeeded action
    let victim = ActionJournal::list(&pg, report.run_id, Some(ActionStatus::Succeeded))
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("a succeeded action");
    sqlx::query("DELETE FROM transitions WHERE action_id = $1")
        .bind(victim.id.0)
        .execute(pg.pool())
        .await
        .unwrap();
    let dirty = verify_trail(
        report.run_id,
        TrailStore::Database {
            store: &crawlx_worker::DurableStore::Postgres(pg.clone()),
            artifacts: Some(artifacts.as_ref()),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        dirty.violations,
        vec![TrailViolation::SucceededWithoutTransition { action: victim.id }],
        "{dirty}"
    );
    pg.drop_schema().await.unwrap();
}
