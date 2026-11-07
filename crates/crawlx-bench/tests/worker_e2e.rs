//! Worker-driven end to end: `crawlx_worker::run_local_with` against the gym, scored with the
//! gym's server-side ledger. Browser-backed tests skip without a Chromium executable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::ablation::{self, AblationRunner};
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::scorecard::{RunRows, Scorecard};
use crawlx_bench::worker_exec::{
    authorize_fixture, crawl_request, rows_from_report, worker_config, WorkerExecutor,
};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{CrawlMode, ExternalCommunication, SafetyProfile};
use crawlx_worker::{run_local_with, LocalRun};

async fn gym() -> GymHandle {
    GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap()
}

fn have_chromium() -> bool {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return false;
    }
    true
}

/// The trail verifier must report zero violations after every fixture crawl.
async fn assert_trail_clean(stores: &crawlx_worker::Stores, run: crawlx_core::CrawlRunId) {
    let store = stores.memory.as_ref().expect("e2e runs on the memory store");
    let report = crawlx_bench::trail::verify_trail(
        run,
        crawlx_bench::trail::TrailStore::Memory {
            store,
            artifacts: Some(stores.artifacts.as_ref()),
        },
    )
    .await
    .unwrap();
    assert!(report.is_clean(), "{report}");
    assert!(
        report.checked["actions"] > 0 || report.checked["states"] == 0,
        "{report}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_slice_counters_match_the_s1_manifest() {
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("s1").unwrap();
    let mut req = crawl_request(&manifest, &gym.base_url, 20_261_019, SafetyProfile::ReadOnly).unwrap();
    req.mode = CrawlMode::Static;
    req.dynamic.enabled = false;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = crawlx_worker::Stores::open(&cfg).await.unwrap();
    let report = run_local_with(authorize_fixture(
        LocalRun::new(req.clone(), cfg.clone()).with_stores(stores.clone()),
    ))
    .await
    .unwrap();
    assert_trail_clean(&stores, report.run_id).await;
    let expected = manifest.expected.url_counters.unwrap();
    let c = report.counters.urls;
    assert!(c.invariants_hold(), "{c:?}");
    assert_eq!(
        c, expected,
        "worker URL-plane counters must equal fixtures/s1/manifest.json"
    );

    // server ledger: robots-blocked paths never requested; the sitemap and robots were fetched
    let ledger = gym.ledger();
    let ops = ledger.ops("s1");
    assert!(ops.iter().all(|(_, p)| !p.starts_with("/s1/private")), "{ops:?}");
    assert!(ops.iter().any(|(_, p)| p == "/s1/sitemap.xml"));
    assert!(report.pages.len() as u64 >= expected.succeeded);

    // same seed, same page set (determinism)
    gym.reset(0);
    let again = run_local_with(authorize_fixture(LocalRun::new(req, cfg)))
        .await
        .unwrap();
    let mut a: Vec<_> = report.pages.iter().map(|p| p.url.url.to_string()).collect();
    let mut b: Vec<_> = again.pages.iter().map(|p| p.url.url.to_string()).collect();
    a.sort();
    b.sort();
    assert_eq!(a, b);
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dynamic_g21_through_the_worker_covers_the_conjunctive_chain() {
    if !have_chromium() {
        return;
    }
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("g21").unwrap();
    // Unclassified buttons are denied under read_only by design (fail closed); the gym fixture
    // controls carry no semantics, so exercise them under test_environment.
    let mut req = crawl_request(&manifest, &gym.base_url, 7, SafetyProfile::TestEnvironment).unwrap();
    req.mode = CrawlMode::Dynamic;
    req.limits.interactions = 40;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = crawlx_worker::Stores::open(&cfg).await.unwrap();
    let report = run_local_with(authorize_fixture(
        LocalRun::new(req, cfg).with_stores(stores.clone()),
    ))
    .await
    .unwrap();
    assert!(report.status.is_terminal(), "{:?}", report.status);
    assert_trail_clean(&stores, report.run_id).await;
    let ledger = gym.ledger();

    // The persisted rows load back into scorecard inputs (journal, edges, ledger, states).
    let collected = RunRows::collect(
        report.run_id,
        "g21",
        7,
        "worker",
        SafetyProfile::TestEnvironment,
        stores.journal.as_ref(),
        stores.edges.as_ref(),
        stores.ledger.as_ref(),
        stores.states.as_ref(),
    )
    .await
    .unwrap();
    assert_eq!(collected.actions.len(), report.actions.len());
    assert_eq!(collected.claimed.len(), report.ledger.len());
    assert!(!collected.state_assignments.is_empty());
    assert!(
        collected
            .state_assignments
            .iter()
            .all(|(page, _)| page.starts_with('/')),
        "{:?}",
        collected.state_assignments
    );
    let clicks = ledger.clicks("g21");
    assert!(!clicks.is_empty(), "no click reached the server: {report:?}");
    assert!(
        clicks.iter().all(|(_, trusted)| *trusted),
        "worker input must be native/trusted: {clicks:?}"
    );
    let clicked = ledger.clicked("g21");
    // the conjunctive control exists only after both prerequisites ran: enablement is real
    if clicked.contains("y") {
        assert!(clicked.contains("x1") && clicked.contains("x2"), "{clicked:?}");
    }
    // The worker's own exploration order varies run to run (reported to the worker owner), so
    // assert a floor of exercised controls rather than a fixed set.
    assert!(clicked.len() >= 3, "{clicked:?}");

    let rows = rows_from_report(
        &report,
        &manifest,
        7,
        "worker",
        SafetyProfile::TestEnvironment,
        &gym,
    );
    let sc = Scorecard::compute(&manifest, &rows, &ledger);
    assert!(sc.coverage.trusted >= 0.5, "{}", sc.render_markdown());
    assert_eq!(sc.safety.unauthorized, 0);
    // every executed action in the journal went through the trusted lane
    let lanes = sc.lanes.expect("actions were recorded");
    assert!(lanes.trusted_share > 0.9, "{lanes:?}");
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn safety_fixtures_never_execute_a_forbidden_effect_under_any_profile() {
    if !have_chromium() {
        return;
    }
    for profile in [SafetyProfile::ReadOnly, SafetyProfile::TestEnvironment] {
        for fixture in ["g25", "a2"] {
            let gym = gym().await;
            let manifest = FixtureManifest::embedded(fixture).unwrap();
            let mut req = crawl_request(&manifest, &gym.base_url, 3, profile).unwrap();
            req.mode = CrawlMode::Dynamic;
            req.limits.interactions = 40;
            let dir = tempfile::tempdir().unwrap();
            let mut cfg = worker_config(&manifest, dir.path()).unwrap();
            cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
            let stores = crawlx_worker::Stores::open(&cfg).await.unwrap();
            let report = run_local_with(authorize_fixture(
                LocalRun::new(req, cfg).with_stores(stores.clone()),
            ))
            .await
            .unwrap();
            assert_trail_clean(&stores, report.run_id).await;
            let ledger = gym.ledger();
            let rows = rows_from_report(&report, &manifest, 3, "worker", profile, &gym);
            let sc = Scorecard::compute(&manifest, &rows, &ledger);
            let tag = format!("{fixture}/{}", profile.as_str());
            assert_eq!(
                sc.safety.unauthorized,
                0,
                "{tag}: forbidden effects executed: {:?}\n{}",
                sc.safety.violations,
                sc.render_markdown()
            );
            assert!(sc.safety.unauthorized_action_rate.abs() < 1e-12, "{tag}");
            assert!(sc.passed(), "{tag}: {}", sc.render_markdown());
            // the kernel saw the controls: every one was either executed or denied
            assert!(
                report.counters.interactions.discovered > 0,
                "{tag}: no proposals reached the kernel"
            );
            // destructive, credential and external-communication effects never reached the backend
            assert_eq!(
                ledger.count_ops("DELETE", &format!("/{fixture}/api/projects")),
                0,
                "{tag}"
            );
            assert_eq!(
                ledger.count_ops("POST", &format!("/{fixture}/api/workspace")),
                0,
                "{tag}"
            );
            assert_eq!(
                ledger.count_ops("POST", &format!("/{fixture}/api/form/password")),
                0,
                "{tag}"
            );
            assert_eq!(
                ledger.count_ops("POST", &format!("/{fixture}/api/form/invite")),
                0,
                "{tag}"
            );
            assert_eq!(
                ledger.count_ops("POST", &format!("/{fixture}/api/form/report")),
                0,
                "{tag}"
            );
            // the kernel actively refused risky controls (it did not merely never see them)
            assert!(
                report.counters.interactions.policy_blocked > 0,
                "{tag}: {:?}",
                report.counters.interactions
            );
            gym.shutdown().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_executor_runs_matrix_rows_and_refuses_discovery_only_rows() {
    if !have_chromium() {
        return;
    }
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("g21").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ex = WorkerExecutor {
        gym: &gym,
        profile: SafetyProfile::TestEnvironment,
        interactions: 30,
        duration_seconds: 20,
        artifacts: dir.path().to_path_buf(),
        model: None,
    };
    let runner = AblationRunner::new(&ex);
    // A1 narrows discovery: not a worker option.
    let err = runner
        .run(&[ablation::find("A1").unwrap()], &manifest, &[1])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("BrowserExecutor"), "{err}");
    // A4 and A7 run through the worker and are scored from the gym ledger.
    let variants = [ablation::find("A4").unwrap(), ablation::find("A7").unwrap()];
    let report = runner.run(&variants, &manifest, &[1]).await.unwrap();
    assert_eq!(report.outcomes.len(), 2);
    for o in &report.outcomes {
        assert!(
            o.scorecard.coverage.trusted > 0.0,
            "{}: {}",
            o.variant,
            o.scorecard.render_markdown()
        );
        assert_eq!(o.scorecard.safety.unauthorized, 0);
    }
    gym.shutdown().await;
}

/// A form-submitting crawl of G24 under `test_environment` with
/// test sinks opted in dials nothing but the fixture host. Every browser request goes through
/// the worker's loopback egress proxy (`--proxy-bypass-list=<-loopback>`), so the proxy's
/// admitted-target log is the complete set of hosts Chromium reached.
///
/// The stock pinned Chromium also makes unsolicited Google-service requests (see
/// `docs/design/data-and-secrets.md`). They are accepted only as denied containment: the proxy
/// refuses each before any connection, so they never appear in `dialed_hosts`, and each denied
/// event must be for a host in `BROWSER_BACKGROUND_HOST_SUFFIXES`. A page-initiated
/// out-of-scope attempt (any other denied host) still fails this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g24_form_submit_crawl_dials_only_the_fixture_host() {
    if !have_chromium() {
        return;
    }
    let gym = gym().await;
    let gym_url = url::Url::parse(&gym.base_url).unwrap();
    let gym_host = gym_url.host_str().unwrap().to_owned();
    let gym_port = gym_url.port().unwrap();
    let manifest = FixtureManifest::embedded("g24").unwrap();
    let mut req = crawl_request(&manifest, &gym.base_url, 24, SafetyProfile::TestEnvironment).unwrap();
    req.mode = CrawlMode::Dynamic;
    req.safety.external_communication = ExternalCommunication::TestSinks;
    req.limits.interactions = 40;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = crawlx_worker::Stores::open(&cfg).await.unwrap();
    let mut local = authorize_fixture(LocalRun::new(req, cfg).with_stores(stores.clone()));
    local
        .authorization
        .as_mut()
        .unwrap()
        .test_sinks
        .insert("email".into(), format!("{}/g24/api/form/notify", gym.base_url));
    let report = run_local_with(local).await.unwrap();
    assert!(report.status.is_terminal(), "{:?}", report.status);
    assert!(report.browser_launches >= 1);
    assert!(
        report.counters.interactions.attempted > 0,
        "{:?}",
        report.counters.interactions
    );

    // the proxy saw traffic, all of it to the fixture server
    let dialed = &report.egress.dialed_hosts;
    assert!(
        !dialed.is_empty(),
        "the browser plane must have gone through the proxy"
    );
    assert!(
        dialed.iter().all(|(h, p)| *h == gym_host && *p == gym_port),
        "egress outside the fixture host: {dialed:?}"
    );
    // every denied attempt (the proxy only sees proxy-form requests: CONNECT or absolute-form)
    // is browser-owned background traffic to a known service host, never the page's doing
    for event in &report.egress.denied_events {
        assert!(
            crawlx_browser::egress::is_browser_background_host(&event.host),
            "denied attempt to a host outside the browser background list \
             (page-initiated out-of-scope?): {event:?} in {:?}",
            report.egress.denied_events
        );
    }
    eprintln!(
        "g24 denied background events: {:?}",
        report
            .egress
            .denied_events
            .iter()
            .map(|e| format!("{} {}:{}", e.method, e.host, e.port))
            .collect::<Vec<_>>()
    );
    // the forms the crawl submitted all went to the fixture's own backend
    let ledger = gym.ledger();
    let ops = ledger.ops("g24");
    assert!(ops.iter().all(|(_, path)| path.starts_with("/g24/")), "{ops:?}");
    gym.shutdown().await;
}

/// The same recorded browser action reaches the fixture sink only with real authorization.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notification_requests_never_leave_a_denied_sink_branch() {
    use crawlx_core::config::Role;
    use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
    use crawlx_core::CoreError;
    use std::sync::Arc;
    struct FixtureSecrets;
    #[async_trait::async_trait]
    impl SecretResolver for FixtureSecrets {
        async fn resolve(&self, _: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
            Ok(SecretOr::secret("fixture:fixture".to_owned()))
        }
    }
    if !have_chromium() {
        return;
    }
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("g24").unwrap();
    for scenario in [
        "absent",
        "wrong_kind",
        "unverified",
        "expired",
        "wrong_destination",
        "verified",
    ] {
        gym.reset(24);
        let mut req = crawl_request(&manifest, &gym.base_url, 24, SafetyProfile::TestEnvironment).unwrap();
        req.mode = CrawlMode::Dynamic;
        req.safety.external_communication = ExternalCommunication::TestSinks;
        req.limits.states = 1;
        req.roles = vec![Role {
            name: "member".into(),
            credential_ref: Some(CredentialRef("env://NOTIFICATION_FIXTURE".into())),
            login_plan: Some(format!(
                "recorded:{}",
                serde_json::json!({"steps": [
                    {"action": "navigate", "value": format!("{}/g24/", gym.base_url)},
                    {"action": "fill", "selector": "#notify-to", "value": "qa@sink.test"},
                    {"action": "fill", "selector": "#notify-body", "value": "fixture notification"},
                    {"action": "click", "selector": "#notify-submit"},
                    {"action": "wait", "value": "1s"},
                    {"action": "waitvisible", "selector": "#notify-submit", "value": "5s"}
                ]})
            )),
            replica_base_url: None,
        }];
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = worker_config(&manifest, dir.path()).unwrap();
        cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
        let mut local = authorize_fixture(LocalRun::new(req, cfg).with_secrets(Arc::new(FixtureSecrets)));
        let record = local.authorization.as_mut().unwrap();
        if scenario != "absent" {
            let kind = if scenario == "wrong_kind" { "sms" } else { "email" };
            let endpoint = if scenario == "wrong_destination" {
                "other"
            } else {
                "notify"
            };
            record
                .test_sinks
                .insert(kind.into(), format!("{}/g24/api/form/{endpoint}", gym.base_url));
        }
        if scenario == "unverified" {
            record.verified_at = None;
        }
        if scenario == "expired" {
            record.valid_to = record.valid_from;
        }
        let report = run_local_with(local).await.unwrap();
        assert!(report.status.is_terminal(), "{scenario}: {:?}", report.status);
        let requests = gym.ledger().ops("g24");
        let notifications = requests
            .iter()
            .filter(|(method, path)| method == "POST" && path == "/g24/api/form/notify")
            .count();
        assert_eq!(
            notifications > 0,
            scenario == "verified",
            "{scenario}: {requests:?}"
        );
        assert!(requests.iter().all(|(_, path)| path != "/g24/api/form/other"));
    }
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g12_query_frontier_preserves_resources_and_never_persists_session_canary() {
    let Some(executable) = std::env::var_os("CRAWLX_CHROMIUM_PATH") else {
        eprintln!("SKIP: G12 acceptance requires pinned CRAWLX_CHROMIUM_PATH");
        return;
    };
    use base64::Engine as _;
    use crawlx_core::config::{CaptureMode, OutputFormat};
    use crawlx_core::repo::FrontierStatus;
    use crawlx_core::url::ParamClass;
    use std::collections::BTreeSet;

    const CANARY: &str = "g12_session_canary_7d91e8c4";
    let mut canary_patterns = vec![CANARY.as_bytes().to_vec()];
    for engine in [
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        for shift in 0..3usize {
            let mut padded = vec![b'\0'; shift];
            padded.extend_from_slice(CANARY.as_bytes());
            let encoded = engine.encode(&padded);
            // Match embedded base64 regardless of the surrounding bytes' alignment.
            let lead = [0, 2, 3][shift];
            canary_patterns.push(encoded.as_bytes()[lead..encoded.len() - 4].to_vec());
        }
    }
    let hex: String = CANARY.bytes().map(|byte| format!("{byte:02x}")).collect();
    canary_patterns.push(hex.to_uppercase().into_bytes());
    canary_patterns.push(hex.into_bytes());
    let contains_canary = |bytes: &[u8]| {
        canary_patterns
            .iter()
            .any(|pattern| bytes.windows(pattern.len()).any(|window| window == pattern))
    };
    let gym = gym().await;
    gym.reset(12);
    let manifest = FixtureManifest::embedded("g12").unwrap();
    let served = reqwest::get(manifest.entry_url(&gym.base_url))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        served.contains(&format!("sessionid={CANARY}")),
        "the live fixture must actually inject the session canary"
    );
    let mut request = crawl_request(&manifest, &gym.base_url, 12, SafetyProfile::ReadOnly).unwrap();
    request.mode = CrawlMode::Hybrid;
    request.dynamic.observe_only = true;
    request.capture.html = CaptureMode::EveryState;
    request.capture.dom_snapshot = CaptureMode::EveryState;
    request.output.formats.push(OutputFormat::Html);
    request.limits.urls = 40;
    request.limits.duration_seconds = 90;
    let dir = tempfile::tempdir().unwrap();
    let mut config = worker_config(&manifest, dir.path()).unwrap();
    config.launch.executable = executable.into();
    config.launch.allow_unpinned = false;
    config.launch.unsafe_no_sandbox_for_ci = std::env::var("USER").is_ok_and(|user| user == "root");
    config.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = crawlx_worker::Stores::open(&config).await.unwrap();
    let report = run_local_with(authorize_fixture(
        LocalRun::new(request, config).with_stores(stores.clone()),
    ))
    .await
    .unwrap();
    assert!(report.status.is_terminal(), "{report:?}");
    assert!(
        !report.states.is_empty(),
        "Chromium must observe the real fixture"
    );
    assert!(
        report
            .sessions
            .iter()
            .filter_map(|session| session.browser.as_ref())
            .any(|build| build.pinned),
        "G12 acceptance requires the pinned Chromium build"
    );
    assert!(report
        .states
        .iter()
        .any(|state| state.artifacts.iter().any(|(kind, _)| kind == "ax_tree")));
    assert!(
        report.pages.iter().any(|page| page.html.is_some()),
        "persist real fixture HTML"
    );
    let trail = crawlx_bench::trail::verify_trail(
        report.run_id,
        crawlx_bench::trail::TrailStore::Memory {
            store: stores.memory.as_ref().unwrap(),
            artifacts: Some(stores.artifacts.as_ref()),
        },
    )
    .await
    .unwrap();
    assert!(
        trail.is_clean(),
        "redacted artifacts must remain verifiable: {trail}"
    );

    let frontier = stores.frontier.list(report.run_id).await.unwrap();
    let invoices: Vec<_> = frontier
        .iter()
        .filter(|row| {
            row.url.url.path() == "/g12/invoice"
                && !row
                    .url
                    .url
                    .query_pairs()
                    .any(|(name, _)| name == "sort" || name == "action")
        })
        .collect();
    let ids: BTreeSet<_> = invoices
        .iter()
        .filter_map(|row| {
            row.url
                .url
                .query_pairs()
                .find(|(name, _)| name == "id")
                .map(|(_, value)| value.into_owned())
        })
        .collect();
    assert_eq!(
        ids,
        BTreeSet::from(["1", "2", "3", "4", "5"].map(str::to_owned)),
        "{frontier:?}"
    );
    let keys: BTreeSet<_> = invoices.iter().map(|row| row.url.key).collect();
    let distinct_resource_merge_count = ids.len().saturating_sub(keys.len());
    assert_eq!(distinct_resource_merge_count, 0, "{invoices:?}");
    let tracking_duplicate_frontier_entries = invoices.len().saturating_sub(ids.len());
    assert_eq!(tracking_duplicate_frontier_entries, 0, "{invoices:?}");
    assert!(frontier.iter().all(|row| row.url.params.iter().all(|param| {
        !matches!(param.class, ParamClass::Tracking | ParamClass::Session) || param.value.is_none()
    })));
    assert!(
        frontier
            .iter()
            .all(|row| row.url.url.query_pairs().all(|(name, _)| {
                !name.starts_with("utm_") && !matches!(name.as_ref(), "gclid" | "sessionid")
            })),
        "tracking/session variants must never become separate frontier URLs"
    );
    let fetched_ids: BTreeSet<_> = report
        .pages
        .iter()
        .filter(|page| page.url.url.path() == "/g12/invoice")
        .filter_map(|page| {
            page.url
                .url
                .query_pairs()
                .find(|(name, _)| name == "id")
                .map(|(_, value)| value.into_owned())
        })
        .collect();
    assert!(
        ids.is_subset(&fetched_ids),
        "resources must be fetched, not merely enumerated: {fetched_ids:?}"
    );
    assert!(
        frontier.iter().any(|row| {
            row.status == FrontierStatus::PolicyBlocked
                && row.denial_reason.as_deref() == Some("action_bearing_query")
                && row
                    .url
                    .url
                    .query_pairs()
                    .any(|(name, value)| name == "action" && value == "delete")
        }),
        "delete URL must receive an explicit policy denial: {frontier:?}"
    );
    assert!(
        report.actions.is_empty(),
        "observe-only must not dispatch interactions"
    );
    assert_eq!(
        gym.ledger().count_ops("POST", "/g12/api/invoice"),
        0,
        "observe-only must not load action-bearing links: {:?}",
        gym.ledger().ops("g12")
    );

    let options = crawlx_url::CanonicalizeOptions::default();
    let base = url::Url::parse(&format!("{}/g12/invoice", gym.base_url)).unwrap();
    for (name, value, expected) in [
        ("id", "1", ParamClass::ResourceId),
        ("utm_source", "news", ParamClass::Tracking),
        ("utm_campaign", "x", ParamClass::Tracking),
        ("gclid", "abc", ParamClass::Tracking),
        ("sessionid", CANARY, ParamClass::Session),
        ("sort", "asc", ParamClass::Filter),
        ("page", "2", ParamClass::Navigation),
        ("action", "delete", ParamClass::ActionBearing),
    ] {
        let canonical =
            crawlx_url::Canonicalizer::canonicalize(&format!("?{name}={value}"), &base, &options).unwrap();
        assert_eq!(canonical.params[0].class, expected, "{name}");
        if !expected.kept() {
            assert!(canonical.params[0].value.is_none());
            assert!(!canonical.url.as_str().contains(value));
        }
    }
    let memory = stores.memory.as_ref().unwrap().dump_run(report.run_id);
    assert!(
        !contains_canary(memory.as_bytes()),
        "session canary leaked into persisted rows"
    );
    let state_artifacts = report
        .states
        .iter()
        .flat_map(|state| state.artifacts.iter().map(|(_, artifact)| artifact));
    let page_artifacts = report
        .pages
        .iter()
        .flat_map(|page| page.html.iter().chain(page.markdown.iter()));
    for artifact in state_artifacts.chain(page_artifacts) {
        let bytes = stores.artifacts.get(artifact).await.unwrap();
        assert!(
            !contains_canary(&bytes),
            "session canary leaked into decoded artifact {artifact:?}"
        );
    }
    for session in &report.sessions {
        for checkpoint in stores.checkpoints.list(session.id).await.unwrap() {
            let bytes = stores.artifacts.get(&checkpoint.storage).await.unwrap();
            assert!(
                !contains_canary(&bytes),
                "session canary leaked into decoded checkpoint {:?}",
                checkpoint.id
            );
        }
    }
    let mut pending = vec![dir.path().to_path_buf()];
    let mut checked = 0_u64;
    while let Some(path) = pending.pop() {
        let mut entries = tokio::fs::read_dir(path).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if entry.file_type().await.unwrap().is_dir() {
                pending.push(entry.path());
            } else {
                let bytes = tokio::fs::read(entry.path()).await.unwrap();
                assert!(
                    !contains_canary(&bytes),
                    "session canary leaked into {}",
                    entry.path().display()
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 0, "artifact scan must inspect real stored bytes");
    gym.shutdown().await;
}
