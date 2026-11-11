//! Exploration driver, sessions and run planning over `FakeBackend` + `MemoryStore`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, Role};
use crawlx_core::counters::{ActionStatus, RunStatus, TerminalReason};
use crawlx_core::repo::EventRepo;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::{CoreError, CreateCrawl, SafetyProfile, TrustLane};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::sync::Arc;

fn nav(key: &str, name: &str, to: &str) -> (FakeAxSpec, (String, Vec<FakeEffect>)) {
    (
        FakeAxSpec::link(key, name, to),
        (key.to_owned(), vec![FakeEffect::Navigate(to.to_owned())]),
    )
}

fn page(url: &str, title: &str, links: &[(&str, &str, &str)]) -> FakePage {
    let mut p = FakePage::new(url).title(title);
    for (key, name, to) in links {
        let (node, (k, effects)) = nav(key, name, to);
        p = p.node(node).on_click(&k, effects);
    }
    p
}

/// Three pages, each linking to the others.
fn three_page_app() -> FakeScript {
    FakeScript::new()
        .page(page(
            "https://example.test/",
            "Home",
            &[
                ("products", "Products", "/products"),
                ("about", "About", "/about"),
            ],
        ))
        .page(page(
            "https://example.test/products",
            "Products",
            &[("home", "Home", "/"), ("about", "About us", "/about")],
        ))
        .page(page(
            "https://example.test/about",
            "About",
            &[
                ("home", "Home page", "/"),
                ("products", "Our products", "/products"),
            ],
        ))
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

fn dynamic_crawl(mutate: impl FnOnce(&mut CreateCrawl)) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    c.mode = CrawlMode::Dynamic;
    c.seed = Some(20_261_019);
    c.limits.interactions = 60;
    c.limits.states = 100;
    mutate(&mut c);
    c
}

async fn run(script: FakeScript, crawl: CreateCrawl) -> (RunReport, Arc<FakeBackend>, Arc<MemoryStore>) {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let report = run_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(backend.clone())
            .with_stores(stores),
    )
    .await
    .unwrap();
    (report, backend, store)
}

#[tokio::test]
async fn popup_policy_journals_rejections_and_eviction_before_admitting_newcomer() {
    let script = FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .node(FakeAxSpec::button("open", "Open windows"))
                .on_click(
                    "open",
                    vec![
                        FakeEffect::OpenTab("https://example.test/old".to_owned()),
                        FakeEffect::OpenTab("https://example.test/keep".to_owned()),
                        FakeEffect::OpenBlankThenNavigate {
                            url: "https://example.test/new".to_owned(),
                            delay_ms: 500,
                        },
                        FakeEffect::OpenTab("https://external.test/window".to_owned()),
                        FakeEffect::OpenDownload("https://example.test/report.csv".to_owned()),
                    ],
                ),
        )
        .page(FakePage::new("https://example.test/old"))
        .page(FakePage::new("https://example.test/keep"))
        .page(FakePage::new("https://example.test/new"));
    let (report, _, _) = run(
        script,
        dynamic_crawl(|c| {
            c.dynamic.max_tabs = 3;
            c.safety.profile = SafetyProfile::TestEnvironment;
        }),
    )
    .await;
    let policy: Vec<_> = report
        .actions
        .iter()
        .filter(|a| a.strategy == "tab_policy")
        .collect();
    let close = |url: &str| {
        policy
            .iter()
            .position(|a| {
                a.key.action_kind == crawlx_core::ActionKind::CloseTab
                    && a.key.element == crawlx_worker::driver::tab_element(url)
                    && a.status == ActionStatus::Succeeded
            })
            .unwrap_or_else(|| panic!("missing close for {url}: {policy:?}"))
    };
    let external = close("https://external.test/window");
    let download = close("https://example.test/report.csv");
    let eviction = close("https://example.test/old");
    let admitted = policy
        .iter()
        .position(|a| {
            a.key.action_kind == crawlx_core::ActionKind::SwitchTab
                && a.key.element == crawlx_worker::driver::tab_element("https://example.test/new")
        })
        .unwrap();
    assert!(external < eviction && download < eviction && eviction < admitted);
    assert!(policy.iter().all(|a| a.strategy_version == 2));
    assert!(policy
        .iter()
        .filter(|a| a.status == ActionStatus::Succeeded)
        .all(|a| a.lane == Some(TrustLane::Diagnostic)));
}

#[tokio::test]
async fn explores_a_three_page_app_and_the_ledger_shows_the_keys_exercised() {
    let (report, backend, _) = run(three_page_app(), dynamic_crawl(|_| {})).await;
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    assert!(
        matches!(
            report.terminal_reason,
            Some(TerminalReason::FrontierExhausted | TerminalReason::LimitReached)
        ),
        "{:?}",
        report.terminal_reason
    );
    // every link of every page was exercised through trusted native input
    let performed: usize = backend
        .context_handles()
        .iter()
        .map(|h| h.performed().len())
        .sum();
    assert!(performed >= 6, "performed {performed}");
    let exercised: Vec<_> = report.ledger.iter().filter(|l| l.trusted_exercised > 0).collect();
    assert!(
        exercised.len() >= 6,
        "ledger: {} rows, {} exercised",
        report.ledger.len(),
        exercised.len()
    );
    let succeeded: Vec<_> = report
        .actions
        .iter()
        .filter(|a| a.status == ActionStatus::Succeeded)
        .collect();
    assert!(succeeded.len() >= 6);
    assert!(succeeded.iter().all(|a| a.lane == Some(TrustLane::TrustedUi)));
    // three pages = three state clusters
    let clusters: std::collections::BTreeSet<_> = report.states.iter().map(|s| s.cluster).collect();
    assert_eq!(clusters.len(), 3, "states: {}", report.states.len());
    assert!(report.counters.interactions.invariants_hold());
    assert!(report.counters.states.invariants_hold());
    // the session's browser build is recorded
    assert!(report.sessions.iter().all(|s| s.browser.is_some()));
    assert!(report.sessions.iter().all(|s| s.status.is_terminal()));
}

#[tokio::test]
async fn observe_only_never_performs_an_action() {
    let (report, backend, _) = run(three_page_app(), dynamic_crawl(|c| c.dynamic.observe_only = true)).await;
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.terminal_reason, Some(TerminalReason::FrontierExhausted));
    assert!(report.actions.is_empty());
    assert!(backend.context_handles().iter().all(|h| h.performed().is_empty()));
    // every page was navigated to and observed
    let clusters: std::collections::BTreeSet<_> = report.states.iter().map(|s| s.cluster).collect();
    assert_eq!(clusters.len(), 3);
    assert!(report.states.len() >= 3);
    assert_eq!(report.counters.interactions.attempted, 0);
}

#[tokio::test]
async fn observe_only_denies_action_queries_before_navigation_but_keeps_resource_and_view_queries() {
    use crawlx_core::repo::{FrontierRepo, FrontierStatus};
    use std::collections::BTreeSet;

    let script = FakeScript::new()
        .page(page(
            "https://example.test/",
            "Home",
            &[
                ("resource", "Invoice", "/invoice?id=2"),
                ("view", "Sorted invoice", "/invoice?id=2&sort=asc"),
                ("delete", "Delete invoice", "/invoice?id=2&action=delete"),
            ],
        ))
        .page(FakePage::new("https://example.test/invoice?id=2").title("Invoice"))
        .page(FakePage::new("https://example.test/invoice?id=2&sort=asc").title("Sorted invoice"))
        .page(FakePage::new("https://example.test/invoice?action=delete&id=2").title("Deleted"));
    let (report, backend, store) =
        run(script, dynamic_crawl(|crawl| crawl.dynamic.observe_only = true)).await;
    assert_eq!(report.status, RunStatus::Completed);
    assert!(report.actions.is_empty());
    let navigations: BTreeSet<_> = backend
        .context_handles()
        .iter()
        .flat_map(|handle| handle.navigations())
        .collect();
    assert!(navigations.contains("https://example.test/invoice?id=2"));
    assert!(navigations.contains("https://example.test/invoice?id=2&sort=asc"));
    assert!(
        navigations.iter().all(|url| !url.contains("action=delete")),
        "{navigations:?}"
    );
    let frontier = FrontierRepo::list(store.as_ref(), report.run_id).await.unwrap();
    assert!(frontier.iter().any(|row| {
        row.status == FrontierStatus::PolicyBlocked
            && row.denial_reason.as_deref() == Some("action_bearing_query")
            && row
                .url
                .url
                .query_pairs()
                .any(|(name, value)| name == "action" && value == "delete")
    }));
}

#[tokio::test]
async fn the_interaction_budget_ends_the_run_with_limit_reached() {
    let (report, backend, _) = run(three_page_app(), dynamic_crawl(|c| c.limits.interactions = 2)).await;
    assert_eq!(report.terminal_reason, Some(TerminalReason::LimitReached));
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.counters.interactions.attempted, 2);
    let performed: usize = backend
        .context_handles()
        .iter()
        .map(|h| h.performed().len())
        .sum();
    assert_eq!(performed, 2);
}

#[tokio::test]
async fn the_state_budget_ends_the_run_with_limit_reached() {
    let (report, _, _) = run(three_page_app(), dynamic_crawl(|c| c.limits.states = 2)).await;
    assert_eq!(report.terminal_reason, Some(TerminalReason::LimitReached));
}

#[tokio::test]
async fn zero_interactions_means_observe_only() {
    let (report, backend, _) = run(three_page_app(), dynamic_crawl(|c| c.limits.interactions = 0)).await;
    assert!(report.actions.is_empty());
    assert!(backend.context_handles().iter().all(|h| h.performed().is_empty()));
}

#[tokio::test]
async fn read_only_denies_destructive_controls_and_journals_the_denial() {
    let script = FakeScript::new()
        .page(
            page("https://example.test/", "Home", &[("next", "Next", "/other")])
                .node(FakeAxSpec::button("del", "Delete everything"))
                .on_click("del", vec![FakeEffect::Remove(vec!["next".to_owned()])]),
        )
        .page(page(
            "https://example.test/other",
            "Other",
            &[("home", "Home", "/")],
        ));
    let (report, backend, _) = run(script, dynamic_crawl(|_| {})).await;
    let performed: Vec<_> = backend
        .context_handles()
        .iter()
        .flat_map(|h| h.performed_keys())
        .collect();
    assert!(
        performed.iter().all(|k| !k.contains("del")),
        "the delete control was never performed: {performed:?}"
    );
    assert!(report.counters.interactions.policy_blocked >= 1);
    assert!(report.counters.interactions.invariants_hold());
    // the denial is in the journal with a safety decision
    let denied: Vec<_> = report
        .actions
        .iter()
        .filter(|a| a.status == ActionStatus::Proposed)
        .collect();
    assert!(
        !denied.is_empty(),
        "denied actions stay `proposed` with hold=denied"
    );
}

#[tokio::test]
async fn round_robin_orders_sessions_r1n1_r2n1_r1n2_r2n2() {
    let crawl = dynamic_crawl(|c| {
        c.dynamic.observe_only = true;
        c.runs_per_role = 2;
        c.roles = ["r1", "r2"]
            .iter()
            .map(|n| Role {
                name: (*n).to_owned(),
                credential_ref: None,
                login_plan: None,
                replica_base_url: None,
            })
            .collect();
    });
    let (report, _, store) = run(three_page_app(), crawl).await;
    assert_eq!(report.status, RunStatus::Completed);
    let events = EventRepo::list_after(store.as_ref(), report.run_id, 0, 1000)
        .await
        .unwrap();
    let order: Vec<String> = events
        .iter()
        .filter(|e| e.kind == "session")
        .map(|e| {
            format!(
                "{}n{}",
                e.payload["role"].as_str().unwrap(),
                e.payload["runIndex"]
            )
        })
        .collect();
    assert_eq!(order, vec!["r1n1", "r2n1", "r1n2", "r2n2"]);
    assert!(report.sessions.iter().all(|s| s.status.is_terminal()));
}

struct FixedSecrets;

#[async_trait]
impl SecretResolver for FixedSecrets {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        match reference.0.as_str() {
            "env://TEST_ADMIN" => Ok(SecretOr::secret("admin:Sup3r-secret-pw".to_owned())),
            other => Err(CoreError::CredentialUnavailable(other.to_owned())),
        }
    }
}

#[tokio::test]
async fn a_role_with_a_credential_logs_in_before_exploring() {
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
            vec![FakeEffect::Navigate("https://example.test/home".into())],
        );
    let script = FakeScript::new()
        .page(login)
        .page(page(
            "https://example.test/home",
            "Home",
            &[("rep", "Reports", "/reports")],
        ))
        .page(page(
            "https://example.test/reports",
            "Reports",
            &[("home", "Dashboard", "/home")],
        ));
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let crawl = dynamic_crawl(|c| {
        c.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
        c.roles = vec![Role {
            name: "admin".into(),
            credential_ref: Some(CredentialRef("env://TEST_ADMIN".into())),
            login_plan: Some("builtin:form".into()),
            replica_base_url: None,
        }];
    });
    let report = common::authorization::run_authorized_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(backend.clone())
            .with_secrets(Arc::new(FixedSecrets)),
    )
    .await
    .unwrap();
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    let handle = &backend.context_handles()[0];
    assert!(handle.performed_keys().iter().any(|k| k == "type:user"));
    assert!(handle.performed_keys().iter().any(|k| k == "type:pw"));
    assert!(
        handle.navigations().iter().any(|u| u.ends_with("/reports"))
            || handle.current_url().contains("/reports")
            || report.states.iter().any(|s| s.url.url.path() == "/reports")
    );
    // the credential is nowhere in the stored run
    let dump = format!("{:?}{:?}{:?}", report.actions, report.states, report.ledger);
    assert!(!dump.contains("Sup3r"));
}

#[tokio::test]
async fn an_unresolvable_credential_fails_the_role_not_the_process() {
    let script = FakeScript::new().page(page("https://example.test/", "Home", &[]));
    let dir = tempfile::tempdir().unwrap();
    let crawl = dynamic_crawl(|c| {
        c.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
        c.roles = vec![Role {
            name: "ghost".into(),
            credential_ref: Some(CredentialRef("env://NOPE".into())),
            login_plan: None,
            replica_base_url: None,
        }];
    });
    let report = common::authorization::run_authorized_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(Arc::new(
                FakeBackend::builder()
                    .script(script)
                    .clock(Arc::new(crawlx_core::SystemClock))
                    .build(),
            ))
            .with_secrets(Arc::new(FixedSecrets)),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Failed);
    assert_eq!(report.terminal_reason, Some(TerminalReason::FatalError));
    assert!(report
        .sessions
        .iter()
        .all(|s| s.status == crawlx_core::repo::SessionStatus::Failed));
}

#[tokio::test]
async fn safety_profile_is_threaded_into_the_kernel() {
    // test_environment allows the plain button read_only would deny
    let script = FakeScript::new().page(
        page("https://example.test/", "Home", &[])
            .node(FakeAxSpec::button("b", "Details"))
            .on_click("b", vec![FakeEffect::Nothing]),
    );
    let (ro, ..) = run(script.clone(), dynamic_crawl(|_| {})).await;
    let (te, backend, _) = run(
        script,
        dynamic_crawl(|c| c.safety.profile = SafetyProfile::TestEnvironment),
    )
    .await;
    assert_eq!(
        ro.counters.interactions.attempted, 0,
        "{:?}",
        ro.counters.interactions
    );
    assert!(te.counters.interactions.attempted >= 1);
    assert!(backend
        .context_handles()
        .iter()
        .any(|h| !h.performed().is_empty()));
}

#[tokio::test]
async fn destructive_controls_are_parked_for_approval_not_executed() {
    let script = FakeScript::new()
        .page(
            page("https://example.test/", "Home", &[("next", "Next", "/other")])
                .node(FakeAxSpec::button("del", "Delete project"))
                .on_click("del", vec![FakeEffect::Nothing]),
        )
        .page(page(
            "https://example.test/other",
            "Other",
            &[("home", "Home", "/")],
        ));
    let (report, backend, store) = run(
        script,
        dynamic_crawl(|c| {
            c.safety.profile = SafetyProfile::TestEnvironment;
            c.safety.destructive_actions = crawlx_core::config::DestructiveActions::Approval;
        }),
    )
    .await;
    let performed: Vec<_> = backend
        .context_handles()
        .iter()
        .flat_map(|h| h.performed_keys())
        .collect();
    assert!(performed.iter().all(|k| !k.contains("del")), "{performed:?}");
    let events = EventRepo::list_after(store.as_ref(), report.run_id, 0, 1000)
        .await
        .unwrap();
    assert!(
        events.iter().any(|e| e.kind == "approval_required"),
        "{:?}",
        events.iter().map(|e| &e.kind).collect::<Vec<_>>()
    );
    assert!(report.counters.interactions.policy_blocked >= 1);
    assert!(report.counters.interactions.invariants_hold());
}

#[tokio::test]
async fn a_browser_crash_mid_action_is_reconciled_and_never_re_executed_blindly() {
    // clicking "Products" always kills the target: the action goes intended -> unknown ->
    // reconciled, the session recovers (rung 1) and exploration continues until the budget ends it
    let script = three_page_app().crash_on(crawlx_browser::fake::action_key(
        crawlx_core::identity::ActionKind::Click,
        "products",
    ));
    let (report, _backend, _) = run(script, dynamic_crawl(|c| c.limits.interactions = 12)).await;
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    assert!(
        report.counters.interactions.unknown_outcome >= 1,
        "{:?}",
        report.counters.interactions
    );
    assert!(report.counters.interactions.invariants_hold());
    // no action is left `intended`; unknown ones were reconciled
    assert!(report.actions.iter().all(|a| a.status != ActionStatus::Intended));
    assert!(report.actions.iter().all(|a| a.status != ActionStatus::Unknown));
    let reconciled: Vec<_> = report
        .actions
        .iter()
        .filter(|a| a.status == ActionStatus::Reconciled)
        .collect();
    assert!(!reconciled.is_empty());
    assert!(reconciled.iter().all(|a| a.reconcile_resolution.is_some()));
}

#[tokio::test]
async fn an_unactionable_control_is_cooled_down_instead_of_looping_or_burning_the_budget() {
    // "About" is always obscured: every attempt is dropped at revalidation
    let script = three_page_app().obscured("about");
    let (report, backend, _) = run(script, dynamic_crawl(|c| c.limits.interactions = 200)).await;
    assert_eq!(report.status, RunStatus::Completed);
    // dropped actions are `abandoned`, bounded by the cooldown, and never charged to the budget
    let c = report.counters.interactions;
    assert!(c.abandoned >= 1, "{c:?}");
    assert!(
        c.abandoned < 40,
        "the dropped control must not be retried in a hot loop: {c:?}"
    );
    assert!(c.invariants_hold());
    // the other controls were still exercised
    let performed: usize = backend
        .context_handles()
        .iter()
        .map(|h| h.performed().len())
        .sum();
    assert!(performed >= 2, "performed {performed}");
    assert!(report.terminal_reason == Some(TerminalReason::FrontierExhausted));
}
