//! Attach admission records verified authorization without retaining endpoint credentials.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use crawlx_browser::fake::FakeScript;
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::repo::CrawlRun;
use crawlx_core::{AuthorizationRecordId, CreateCrawl, SafetyProfile};
use crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys;
use crawlx_storage::MemoryStore;
use crawlx_worker::{
    AuthorizationGuard, Gates, RunContext, StaticAuthorizationSource, Stores, WorkerConfig, WorkerError,
};
use serde_json::json;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const ENDPOINT: &str = "ws://127.0.0.1:9/devtools/browser/attach-fixture?token=ATTACH_SENTINEL_SECRET";
const TOKEN: &str = "ATTACH_SENTINEL_SECRET";

struct Fixture {
    _dir: tempfile::TempDir,
    stores: Stores,
    run: CrawlRun,
    cfg: WorkerConfig,
    backend: Arc<FakeBackend>,
}

impl Fixture {
    async fn new(profile: SafetyProfile) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
            .await
            .unwrap();
        stores.checkpoint_keys = Arc::new(MemoryCheckpointKeys::new().unwrap());
        let mut crawl = CreateCrawl::new("https://example.test/".parse().unwrap());
        crawl.mode = CrawlMode::Dynamic;
        crawl.seed = Some(7);
        crawl.safety.profile = profile;
        crawl.safety.authorization_record_ref = Some(AuthorizationRecordId::new());
        let record = authorization_fixture::verified_record(&crawl, stores.tenant);
        let stores = stores.with_authorization_source(Arc::new(StaticAuthorizationSource::new(record)));
        let run = crawlx_storage::testkit::crawl_run(stores.tenant, crawl);
        stores.runs.create(&run, None).await.unwrap();
        let cfg = WorkerConfig {
            artifacts_dir: dir.path().to_path_buf(),
            cdp_ws_url: Some(ENDPOINT.parse().unwrap()),
            gates: Gates::from_status(crawlx_core::gates::GateStatus::ALL),
            ..WorkerConfig::default()
        };
        Self {
            _dir: dir,
            stores,
            run,
            cfg,
            backend: Arc::new(
                FakeBackend::builder()
                    .script(FakeScript::new())
                    .clock(Arc::new(crawlx_core::SystemClock))
                    .build(),
            ),
        }
    }

    async fn build(&self, authorization: Option<Arc<AuthorizationGuard>>) -> Result<RunContext, WorkerError> {
        RunContext::build(
            &self.run,
            &self.cfg,
            self.stores.clone(),
            Some(self.backend.clone()),
            None,
            CancellationToken::new(),
            None,
            authorization,
        )
        .await
    }

    async fn assert_no_admission(&self) {
        let events = self.stores.events.list_after(self.run.id, 0, 100).await.unwrap();
        assert!(events.iter().all(|event| event.kind != "browser.attach.admitted"));
        assert!(self.backend.context_handles().is_empty());
        assert!(!serde_json::to_string(&events).unwrap().contains(TOKEN));
    }
}

#[tokio::test]
async fn admitted_attach_records_exact_authorization_without_endpoint_or_token() {
    for profile in [
        SafetyProfile::TestEnvironment,
        SafetyProfile::AuthorizedSecurityTest,
    ] {
        for incognito in [true, false] {
            let mut fixture = Fixture::new(profile).await;
            fixture.cfg.incognito = incognito;
            let guard = authorization_fixture::admit(&fixture.stores, &fixture.run, &fixture.cfg).await;
            let record_id = guard.record_id();
            assert_eq!(
                fixture.run.config.safety.authorization_record_ref,
                Some(record_id)
            );
            let context = fixture.build(Some(guard)).await.unwrap();
            let events = fixture
                .stores
                .events
                .list_after(fixture.run.id, 0, 100)
                .await
                .unwrap();
            let admitted: Vec<_> = events
                .iter()
                .filter(|event| event.kind == "browser.attach.admitted")
                .collect();
            assert_eq!(admitted.len(), 1);
            assert_eq!(
                admitted[0].payload,
                json!({
                    "authorizationRecordId": record_id,
                    "safetyProfile": profile,
                    "defaultContext": !incognito,
                })
            );
            let retained = json!({
                "run": fixture.stores.runs.get(fixture.run.id).await.unwrap(),
                "events": events,
            })
            .to_string();
            assert!(!retained.contains(ENDPOINT));
            assert!(!retained.contains(TOKEN));
            assert!(fixture.backend.context_handles().is_empty());
            context.cancel.cancel();
        }
    }
}

#[tokio::test]
async fn read_only_attach_refuses_before_admission_even_with_verified_authorization() {
    let fixture = Fixture::new(SafetyProfile::ReadOnly).await;
    let guard = authorization_fixture::admit(&fixture.stores, &fixture.run, &fixture.cfg).await;
    assert!(matches!(
        fixture.build(Some(guard)).await,
        Err(WorkerError::PolicyDenied(message))
            if message == "browser attach requires test_environment or authorized_security_test"
    ));
    fixture.assert_no_admission().await;
}

#[tokio::test]
async fn attach_without_authorization_guard_refuses_before_admission() {
    for profile in [
        SafetyProfile::TestEnvironment,
        SafetyProfile::AuthorizedSecurityTest,
    ] {
        let mut fixture = Fixture::new(profile).await;
        // No reference ensures this exercises attach admission, not missing-record admission.
        fixture.run.config.safety.authorization_record_ref = None;
        assert!(matches!(
            fixture.build(None).await,
            Err(WorkerError::PolicyDenied(message))
                if message == "browser attach requires active authorization"
        ));
        fixture.assert_no_admission().await;
    }
}
