//! Katana `-crawl-duration` excludes the time a login takes: a recorded login that outlasts
//! `limits.durationSeconds` must not leave the run without any exploration budget.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, Role};
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::{ActionJournal, EventRepo};
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::{CoreError, CreateCrawl, SafetyProfile};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::collections::BTreeMap;
use std::sync::Arc;

struct FixedSecrets;

#[async_trait]
impl SecretResolver for FixedSecrets {
    async fn resolve(&self, r: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        if r.0 == "env://TEST_ADMIN" {
            Ok(SecretOr::secret("alice:Sup3r-secret-pw".to_owned()))
        } else {
            Err(CoreError::CredentialUnavailable(r.0.clone()))
        }
    }
}

fn site() -> FakeScript {
    let login = FakePage::new("https://example.test/")
        .title("Sign in")
        .node(
            FakeAxSpec::textbox("user", "Username")
                .attr("type", "text")
                .attr("autocomplete", "username")
                .attr("crawlx:form", "login"),
        )
        .node(
            FakeAxSpec::textbox("pw", "Password")
                .attr("type", "password")
                .attr("autocomplete", "current-password")
                .attr("crawlx:form", "login"),
        )
        .node(
            FakeAxSpec::button("go", "Sign in")
                .attr("type", "submit")
                .attr("crawlx:form", "login"),
        )
        .on_click(
            "go",
            vec![
                FakeEffect::SetStorage(BTreeMap::from([("sid".to_owned(), "abc".to_owned())])),
                FakeEffect::Navigate("https://example.test/home".into()),
            ],
        );
    FakeScript::new()
        .page(login)
        .page(
            FakePage::new("https://example.test/home")
                .title("Home")
                .node(FakeAxSpec::link("rep", "Reports", "/reports"))
                .on_click("rep", vec![FakeEffect::Navigate("/reports".into())]),
        )
        .page(
            FakePage::new("https://example.test/reports")
                .title("Reports")
                .node(FakeAxSpec::link("home", "Dashboard", "/home"))
                .on_click("home", vec![FakeEffect::Navigate("/home".into())]),
        )
}

/// A recorded login that sleeps 3.4 s before it clicks "Sign in".
const SLOW_LOGIN: &str = r##"recorded:{"steps":[
  {"action":"navigate","value":"https://example.test/"},
  {"action":"fill","selector":"#user","value":"{{username}}"},
  {"action":"fill","selector":"[type=\"password\"]","value":"{{password}}"},
  {"action":"wait","value":"3.4s"},
  {"action":"click","selector":"aria/Sign in"},
  {"action":"waitvisible","selector":"aria/Reports","value":"2s"}
]}"##;

async fn run(duration_seconds: u32) -> (RunReport, Arc<FakeBackend>, Vec<serde_json::Value>) {
    let dir = tempfile::tempdir_in("/data").unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.safety.profile = SafetyProfile::TestEnvironment;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.safety.respect_robots_txt = false;
    crawl.seed = Some(20_261_020);
    crawl.limits.interactions = 20;
    crawl.limits.states = 50;
    crawl.limits.urls = 50;
    crawl.limits.duration_seconds = duration_seconds;
    crawl.roles = vec![Role {
        name: "admin".into(),
        credential_ref: Some(CredentialRef("env://TEST_ADMIN".into())),
        login_plan: Some(SLOW_LOGIN.to_owned()),
        replica_base_url: None,
    }];
    let backend = Arc::new(FakeBackend::new(site()));
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let mut authorization = common::authorization::verified_record(&crawl, stores.tenant);
    authorization.robots_override_acknowledged = true;
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let report = run_local_with(
        LocalRun::new(crawl, cfg)
            .with_backend(backend.clone())
            .with_stores(stores)
            .with_authorization(authorization)
            .with_secrets(Arc::new(FixedSecrets)),
    )
    .await
    .unwrap();
    let actions = store.list(report.run_id, None).await.unwrap();
    assert!(
        actions.iter().any(|action| {
            action.strategy != crawlx_worker::login::LOGIN_STRATEGY
                && action.status == crawlx_core::counters::ActionStatus::Succeeded
        }),
        "no successful exploration action after login: {actions:?}"
    );
    let budgets = store
        .list_after(report.run_id, 0, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "session.budget")
        .map(|event| event.payload)
        .collect();
    (report, backend, budgets)
}

#[tokio::test]
async fn login_time_is_not_charged_to_the_crawl_duration() {
    // Login outlasts the 3 s execution budget. Keep enough exploration time for
    // native effect spacing; eventual deadline completion remains legitimate.
    let (report, backend, budgets) = run(3).await;
    let initial = budgets.first().unwrap();
    let credited = budgets.last().unwrap();
    let credit_ms = credited["login_credit_ms"].as_u64().unwrap();
    assert!(credit_ms >= 3400, "{budgets:?}");
    assert_eq!(credited["login_allowance_ms"], 0);
    let initial_deadline: crawlx_core::Timestamp =
        serde_json::from_value(initial["deadline"].clone()).unwrap();
    let credited_deadline: crawlx_core::Timestamp =
        serde_json::from_value(credited["deadline"].clone()).unwrap();
    let credited_time = credited_deadline - initial_deadline;
    // Durable credit uses whole milliseconds; the measured deadline retains
    // sub-millisecond precision.
    assert_eq!(
        u64::try_from(credited_time.num_milliseconds()).unwrap(),
        credit_ms
    );
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    let handle = &backend.context_handles()[0];
    assert!(
        handle.navigations().iter().any(|u| u.contains("/reports")),
        "the explored session reached the page behind the login: {:?}",
        handle.navigations()
    );
}
