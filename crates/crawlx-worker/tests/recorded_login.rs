//! On the browser plane: recorded login replay through the Session Actor,
//! fallback to `builtin:form`, logout exclusion, page-hooks discovery into the frontier and
//! attach-mode admission. All over `FakeBackend` + `MemoryStore`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, Role};
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::{EventRepo, FrontierStatus};
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::{CoreError, CreateCrawl, SafetyProfile};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::replay::{ReplayMode, ReplayPlan, ReplayRunner, StepVerdict};
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig, WorkerError};
use std::collections::BTreeMap;
use std::sync::Arc;

const PASSWORD: &str = "Sup3r-secret-pw";

struct FixedSecrets;

#[async_trait]
impl SecretResolver for FixedSecrets {
    async fn resolve(&self, r: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        if r.0 == "env://TEST_ADMIN" {
            Ok(SecretOr::secret(format!("alice:{PASSWORD}")))
        } else {
            Err(CoreError::CredentialUnavailable(r.0.clone()))
        }
    }
}

fn cfg(dir: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

fn crawl(mode: CrawlMode, profile: SafetyProfile, mutate: impl FnOnce(&mut CreateCrawl)) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    c.mode = mode;
    c.safety.profile = profile;
    c.seed = Some(20_261_020);
    c.limits.interactions = 20;
    c.limits.states = 50;
    c.limits.urls = 50;
    mutate(&mut c);
    if c.roles.iter().any(|role| role.credential_ref.is_some()) {
        c.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    }
    c
}

fn admin_role(plan: &str) -> Role {
    Role {
        name: "admin".into(),
        credential_ref: Some(CredentialRef("env://TEST_ADMIN".into())),
        login_plan: Some(plan.to_owned()),
        replica_base_url: None,
    }
}

/// Login page whose "Sign in" button sets a session cookie and navigates home; the home page
/// links to `/logout` and `/reports`.
fn login_site(with_submit: bool) -> FakeScript {
    let mut login = FakePage::new("https://example.test/")
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
        );
    if with_submit {
        login = login
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
    }
    FakeScript::new()
        .page(login)
        .page(
            FakePage::new("https://example.test/home")
                .title("Home")
                .node(FakeAxSpec::link("out", "Log out", "/logout"))
                .node(FakeAxSpec::link("rep", "Reports", "/reports"))
                .on_click("out", vec![FakeEffect::Navigate("/logout".into())])
                .on_click("rep", vec![FakeEffect::Navigate("/reports".into())]),
        )
        .page(
            FakePage::new("https://example.test/reports")
                .title("Reports")
                .node(FakeAxSpec::link("home", "Dashboard", "/home"))
                .on_click("home", vec![FakeEffect::Navigate("/home".into())]),
        )
        .page(FakePage::new("https://example.test/logout").title("Logged out"))
}

const RECORDED: &str = r##"recorded:{"steps":[
  {"action":"navigate","value":"https://example.test/"},
  {"action":"fill","selector":"#user","value":"{{username}}"},
  {"action":"fill","selector":"[type=\"password\"]","value":"{{password}}"},
  {"action":"click","selector":"aria/Sign in"},
  {"action":"waitvisible","selector":"aria/Reports","value":"2s"}
]}"##;

async fn run(
    script: FakeScript,
    crawl: CreateCrawl,
) -> (RunReport, Arc<FakeBackend>, Arc<MemoryStore>, Stores) {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FakeBackend::new(script));
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let report = run_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(backend.clone())
            .with_stores(stores.clone())
            .with_secrets(Arc::new(FixedSecrets)),
    )
    .await
    .unwrap();
    (report, backend, store, stores)
}

async fn login_events(store: &MemoryStore, run: crawlx_core::CrawlRunId) -> Vec<serde_json::Value> {
    EventRepo::list_after(store, run, 0, 10_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "session.login")
        .map(|e| e.payload)
        .collect()
}

#[tokio::test]
async fn recorded_login_replays_through_the_actor_and_excludes_logout() {
    let c = crawl(CrawlMode::Dynamic, SafetyProfile::TestEnvironment, |c| {
        c.roles = vec![admin_role(RECORDED)];
    });
    let (report, backend, store, stores) = run(login_site(true), c).await;
    let events = login_events(&store, report.run_id).await;
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?} {events:?}",
        report.terminal_reason
    );
    let ok = events
        .iter()
        .find(|e| e["ok"] == true)
        .unwrap_or_else(|| panic!("{events:?}"));
    assert_eq!(ok["plan"], "recorded");
    assert_eq!(ok["fallback"], false);
    assert_eq!(ok["sessionChanged"], true);
    assert_eq!(ok["terminalVisible"], true);
    // the click step was a kernel-adjudicated, journaled action on the trusted lane
    let login_actions: Vec<_> = report.actions.iter().filter(|a| a.strategy == "login").collect();
    assert!(!login_actions.is_empty(), "{:?}", report.actions);
    assert!(login_actions
        .iter()
        .all(|a| a.status == crawlx_core::counters::ActionStatus::Succeeded
            && a.lane == Some(crawlx_core::TrustLane::TrustedUi)));
    // every journaled step carries the kernel verdict it was admitted under
    let verdicts: std::collections::BTreeSet<_> = login_actions.iter().map(|a| a.safety_decision).collect();
    assert_eq!(verdicts.len(), login_actions.len());
    let _ = &stores;
    // the credentials went in as native typing; the secret is nowhere in the stored run
    let handle = &backend.context_handles()[0];
    assert!(handle.performed_keys().iter().any(|k| k == "type:pw"));
    assert!(handle.performed_keys().iter().any(|k| k == "type:user"));
    let dump = format!("{events:?}{:?}{:?}", report.actions, report.states);
    assert!(!dump.contains(PASSWORD));
    assert!(!dump.contains("#pw"));
    // an authenticated session never navigates to /logout
    assert!(!handle.navigations().iter().any(|u| u.contains("/logout")));
    assert!(!report
        .actions
        .iter()
        .any(|a| a.key.action_kind == crawlx_core::ActionKind::Navigate
            && a.strategy != "login"
            && handle.navigations().iter().any(|u| u.contains("/logout"))));
}

#[tokio::test]
async fn replay_restores_recorded_login_once_and_stops_on_login_denial() {
    let dir = tempfile::tempdir().unwrap();
    let crawl = crawl(CrawlMode::Dynamic, SafetyProfile::TestEnvironment, |crawl| {
        crawl.roles = vec![admin_role(RECORDED)];
    });
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let record = common::authorization::verified_record(&crawl, stores.tenant);
    let stores =
        stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
    let source = run_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(Arc::new(FakeBackend::new(login_site(true))))
            .with_stores(stores.clone())
            .with_secrets(Arc::new(FixedSecrets)),
    )
    .await
    .unwrap();
    assert_eq!(source.status, RunStatus::Completed, "{source:?}");
    let target = source
        .actions
        .iter()
        .find(|action| {
            action.strategy != "login"
                && action.status == crawlx_core::counters::ActionStatus::Succeeded
                && action.key.action_kind == crawlx_core::ActionKind::Click
        })
        .expect("authenticated exploration action");
    let plan = ReplayPlan::load(&stores, source.run_id, target.id).await.unwrap();
    assert!(plan.steps.iter().all(|step| step.action.strategy != "login"));
    let login = source
        .actions
        .iter()
        .find(|action| action.strategy == "login")
        .unwrap();
    assert!(matches!(
        ReplayPlan::load(&stores, source.run_id, login.id).await,
        Err(WorkerError::Config(message)) if message.contains("not replay targets")
    ));

    let backend = Arc::new(
        FakeBackend::builder()
            .script(login_site(true))
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let replay = ReplayRunner::run(
        cfg(dir.path()),
        plan.clone(),
        ReplayMode::Reproduce,
        Some(backend.clone()),
        Some(Arc::new(FixedSecrets)),
    )
    .await
    .unwrap();
    assert!(replay.ok, "{replay:?}");
    assert!(replay
        .steps
        .iter()
        .any(|step| step.action == target.id && step.verdict == StepVerdict::Executed));
    let contexts = backend.context_handles();
    assert_eq!(contexts.len(), 1);
    let keys = contexts[0].performed_keys();
    for expected in ["type:user", "type:pw", "click:go", "click:rep"] {
        assert_eq!(
            keys.iter().filter(|key| key.as_str() == expected).count(),
            1,
            "{keys:?}"
        );
    }
    assert!(contexts[0]
        .navigations()
        .iter()
        .any(|url| url.ends_with("/reports")));

    // The live target changed into a password-change form. Authentication must still
    // go through the kernel, and its denial must not trigger builtin-form fallback.
    let denied_site = FakeScript::new().page(
        FakePage::new("https://example.test/")
            .title("Change password")
            .node(
                FakeAxSpec::textbox("user", "Username")
                    .attr("autocomplete", "username")
                    .attr("crawlx:form", "account"),
            )
            .node(
                FakeAxSpec::textbox("pw", "Password")
                    .attr("type", "password")
                    .attr("autocomplete", "current-password")
                    .attr("crawlx:form", "account"),
            )
            .node(
                FakeAxSpec::textbox("new", "New password")
                    .attr("type", "password")
                    .attr("autocomplete", "new-password")
                    .attr("crawlx:form", "account"),
            )
            .node(
                FakeAxSpec::button("go", "Sign in")
                    .attr("type", "submit")
                    .attr("crawlx:form", "account"),
            )
            .on_click(
                "go",
                vec![FakeEffect::SetStorage(BTreeMap::from([(
                    "credential_changed".to_owned(),
                    "yes".to_owned(),
                )]))],
            ),
    );
    let denied_backend = Arc::new(
        FakeBackend::builder()
            .script(denied_site)
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let error = ReplayRunner::run(
        cfg(dir.path()),
        plan,
        ReplayMode::Reproduce,
        Some(denied_backend.clone()),
        Some(Arc::new(FixedSecrets)),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, WorkerError::Session(crawlx_worker::SessionError::LoginFailed(message))
            if message.contains("denied")),
        "{error:?}"
    );
    let contexts = denied_backend.context_handles();
    assert_eq!(contexts.len(), 1);
    let keys = contexts[0].performed_keys();
    assert!(!keys.iter().any(|key| key == "click:go"), "{keys:?}");
    for expected in ["type:user", "type:pw"] {
        assert_eq!(
            keys.iter().filter(|key| key.as_str() == expected).count(),
            1,
            "{keys:?}"
        );
    }
    assert!(!contexts[0].storage().contains_key("credential_changed"));
    assert!(!contexts[0]
        .navigations()
        .iter()
        .any(|url| url.ends_with("/reports")));
}

#[tokio::test]
async fn recorded_login_failure_falls_back_to_builtin_form() {
    // the recorded flow clicks a control the page does not have; builtin:form must still log in
    let flow = r##"recorded:{"steps":[{"action":"click","selector":"#missing"}]}"##;
    let c = crawl(CrawlMode::Dynamic, SafetyProfile::TestEnvironment, |c| {
        c.roles = vec![admin_role(flow)];
    });
    let (report, _, store, _) = run(login_site(true), c).await;
    let events = login_events(&store, report.run_id).await;
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?} {events:?} {:?}",
        report.terminal_reason,
        report.sessions
    );
    assert!(events
        .iter()
        .any(|e| e["ok"] == false && e["plan"] == "recorded" && e["reason"] == "selector_not_found"));
    assert!(
        events
            .iter()
            .any(|e| e["ok"] == true && e["plan"] == "builtin:form" && e["fallback"] == true),
        "{events:?}"
    );
}

#[tokio::test]
async fn page_hooks_feed_the_frontier_in_hybrid_mode_only_when_enabled() {
    let site = || {
        FakeScript::new().page(
            FakePage::new("https://example.test/")
                .title("Home")
                .discovered("/api/items", "fetch")
                .discovered("https://other.test/x", "pushState"),
        )
    };
    let on = crawl(CrawlMode::Hybrid, SafetyProfile::ReadOnly, |c| {
        c.dynamic.page_hooks = true;
    });
    let (report, _, _, stores) = run(site(), on).await;
    let frontier = stores.frontier.list(report.run_id).await.unwrap();
    let items = frontier
        .iter()
        .find(|f| f.url.url.path() == "/api/items")
        .unwrap_or_else(|| panic!("{frontier:?}"));
    assert_eq!(items.status, FrontierStatus::Pending);
    assert_eq!(items.depth, 1);
    let other = frontier
        .iter()
        .find(|f| f.url.url.host_str() == Some("other.test"))
        .unwrap();
    assert_eq!(other.status, FrontierStatus::PolicyBlocked);
    assert_eq!(other.denial_reason.as_deref(), Some("external"));

    let off = crawl(CrawlMode::Hybrid, SafetyProfile::ReadOnly, |_| {});
    let (report, _, _, stores) = run(site(), off).await;
    let frontier = stores.frontier.list(report.run_id).await.unwrap();
    assert!(
        frontier.iter().all(|f| f.url.url.path() != "/api/items"),
        "{frontier:?}"
    );
}

#[tokio::test]
async fn attach_mode_is_admitted_only_for_test_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let mut worker = cfg(dir.path());
    worker.cdp_ws_url = Some(url::Url::parse("ws://127.0.0.1:9222/devtools/browser/x").unwrap());
    let site = FakeScript::new().page(FakePage::new("https://example.test/").title("Home"));
    let denied = run_local_with(
        LocalRun::new(
            crawl(CrawlMode::Dynamic, SafetyProfile::ReadOnly, |_| {}),
            worker.clone(),
        )
        .with_backend(Arc::new(FakeBackend::new(site.clone()))),
    )
    .await;
    assert!(matches!(denied, Err(WorkerError::PolicyDenied(_))), "{denied:?}");
    let report = run_local_with(
        LocalRun::new(
            crawl(CrawlMode::Dynamic, SafetyProfile::TestEnvironment, |_| {}),
            worker,
        )
        .with_backend(Arc::new(FakeBackend::new(site))),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    // non-incognito without attach mode is a configuration error
    let mut plain = cfg(dir.path());
    plain.incognito = false;
    let err = run_local_with(
        LocalRun::new(
            crawl(CrawlMode::Dynamic, SafetyProfile::TestEnvironment, |_| {}),
            plain,
        )
        .with_backend(Arc::new(FakeBackend::new(
            FakeScript::new().page(FakePage::new("https://example.test/")),
        ))),
    )
    .await;
    assert!(matches!(err, Err(WorkerError::Config(_))), "{err:?}");
}

#[tokio::test]
async fn recorded_authentication_cannot_submit_password_changes_or_unproven_login_forms() {
    for password_change in [false, true] {
        let password = FakeAxSpec::textbox("current", "Password")
            .attr("type", "password")
            .attr("crawlx:form", "account");
        let password = if password_change {
            password.attr("autocomplete", "current-password")
        } else {
            password
        };
        let mut page = FakePage::new("https://example.test/").node(password);
        if password_change {
            page = page.node(
                FakeAxSpec::textbox("new", "New password")
                    .attr("type", "password")
                    .attr("autocomplete", "new-password")
                    .attr("crawlx:form", "account"),
            );
        }
        page = page
            .node(
                FakeAxSpec::button("save", "Continue")
                    .attr("type", "submit")
                    .attr("crawlx:form", "account"),
            )
            .on_click(
                "save",
                vec![FakeEffect::SetStorage(BTreeMap::from([(
                    "credential_changed".into(),
                    "yes".into(),
                )]))],
            );
        let flow = r##"recorded:{"steps":[{"action":"click","selector":"#save"}]}"##;
        let crawl = crawl(CrawlMode::Dynamic, SafetyProfile::TestEnvironment, |crawl| {
            crawl.roles = vec![admin_role(flow)];
        });
        let (report, backend, store, _) = run(FakeScript::new().page(page), crawl).await;
        assert_eq!(report.status, RunStatus::Failed);
        assert!(login_events(&store, report.run_id).await.iter().any(|event| {
            event["plan"] == "recorded" && event["ok"] == false && event["reason"] == "denied"
        }));
        for handle in backend.context_handles() {
            assert!(!handle.performed_keys().iter().any(|key| key == "click:save"));
            assert!(!handle.storage().contains_key("credential_changed"));
        }
    }
}
