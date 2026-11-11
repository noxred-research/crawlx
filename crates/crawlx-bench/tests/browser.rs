//! Browser-backed ground-truth tests against the gym. Skipped (with a message) when no Chromium
//! executable is installed (`CRAWLX_CHROMIUM_PATH` or the usual locations).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::ablation;
use crawlx_bench::driver::{self, DriverConfig};
use crawlx_bench::gym::manifest::{ExpectedClass, FixtureManifest};
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::oracle::verdict_of;
use crawlx_bench::scorecard::Scorecard;
use crawlx_browser::launch::find_executable;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::browser::{BrowserBackend, ContextConfig};
use crawlx_core::config::LaunchProfile;
use crawlx_core::ids::SessionId;
use crawlx_core::observation::{ObservationSpec, QuiescencePolicy};
use crawlx_core::traffic::{Fidelity, TrustLane};
use crawlx_elements::{CandidateDiscovery, DiscoveryConfig, Rung};
use crawlx_fetch::{EgressProxy, StaticResolver};
use crawlx_policy::egress::EgressPolicy;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, SemaphorePermit};

/// Chromium instances running at once. Every test launches its own browser, so an unbounded
/// parallel `cargo test` starves page timers and the egress proxy; a few at a time keeps the
/// timing-sensitive assertions meaningful (CI additionally runs with `--test-threads 1`).
static BROWSER_SLOTS: Semaphore = Semaphore::const_new(2);

/// How long a test waits for something the browser or proxy does asynchronously (a click
/// reaching the server ledger, a denial reaching the proxy). Generous on purpose: it bounds only
/// the failure case, a passing wait returns as soon as the condition holds.
const WAIT_BUDGET: Duration = Duration::from_secs(45);

async fn browser_slot() -> SemaphorePermit<'static> {
    BROWSER_SLOTS
        .acquire()
        .await
        .expect("the semaphore is never closed")
}

async fn gym() -> GymHandle {
    GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap()
}

async fn launch(profile: LaunchProfile, proxy: Option<u16>) -> Option<ChromiumBackend> {
    let Some(exe) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return None;
    };
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe;
    cfg.launch_profile = profile;
    cfg.allow_unpinned = true;
    cfg.egress_proxy_port = proxy;
    match ChromiumBackend::launch(cfg.clone()).await {
        Ok(b) => Some(b),
        Err(first) => {
            eprintln!(
                "warning: launch failed ({first}); retrying once with --no-sandbox (CI containers only)"
            );
            cfg.unsafe_no_sandbox_for_ci = true;
            Some(ChromiumBackend::launch(cfg).await.expect("chromium must launch"))
        }
    }
}

fn canonical(url: &str) -> crawlx_core::url::CanonicalUrl {
    Canonicalizer::canonicalize_url(&url::Url::parse(url).unwrap(), &CanonicalizeOptions::default()).unwrap()
}

/// Poll `cond` every 50 ms until it holds or [`WAIT_BUDGET`] has elapsed.
async fn eventually(mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + WAIT_BUDGET;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g01_real_chromium_clicks_land_in_the_server_ledger() {
    let _slot = browser_slot().await;
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let gym = gym().await;
    gym.reset(7);
    let manifest = FixtureManifest::embedded("g01").unwrap();
    let variant = ablation::find("A2").unwrap();
    let cfg = DriverConfig {
        max_actions: 60,
        ..DriverConfig::default()
    };
    let rows = driver::run_variant(&backend, &variant, &manifest, &gym.base_url, 7, &cfg)
        .await
        .unwrap();
    let ledger = gym.ledger();
    assert!(
        eventually(|| ledger.clicked("g01").len() >= 38).await,
        "ledger clicks: {:?}",
        ledger.clicked("g01")
    );
    let clicks = ledger.clicks("g01");
    assert!(
        clicks.iter().all(|(_, trusted)| *trusted),
        "native pointer input must be trusted: {clicks:?}"
    );
    // both a semantic button and a delegated div button were exercised by the real browser
    let clicked = ledger.clicked("g01");
    assert!(clicked.contains("c01"), "{clicked:?}");
    assert!(
        clicked.contains("c21"),
        "div button reached only through listener/cursor evidence: {clicked:?}"
    );

    let sc = Scorecard::compute(&manifest, &rows, &ledger);
    assert!(sc.coverage.trusted >= 0.95, "{}", sc.render_markdown());
    assert!(sc.targets.overall.recall >= 0.95, "{}", sc.render_markdown());
    assert_eq!(sc.safety.unauthorized, 0);
    assert!(sc.lanes.unwrap().trusted_share > 0.99);
    // every ground-truth control discovered through its expected mechanism family
    assert!(
        sc.targets.by_mechanism["cursor"].recall >= 0.8,
        "{}",
        sc.render_markdown()
    );
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g29_every_denied_destination_is_blocked_by_the_egress_proxy() {
    let _slot = browser_slot().await;
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("g29").unwrap();
    // The authorized fixture network is loopback on the gym port; everything else stays denied.
    let mut policy = EgressPolicy::new(false);
    policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
    policy.extra_ports.push(gym.port);
    let resolver = StaticResolver::new().with("rebind.gym.test", ["10.0.0.5".parse::<IpAddr>().unwrap()]);
    let proxy = EgressProxy::serve(Arc::new(policy), Arc::new(resolver))
        .await
        .unwrap();
    let Some(backend) = launch(LaunchProfile::Standard, Some(proxy.port())).await else {
        return;
    };
    let mut cfg = ContextConfig::new(SessionId::new());
    cfg.egress_proxy_port = Some(proxy.port());
    let mut ctx = backend.new_context(cfg).await.unwrap();
    let nav = ctx
        .navigate(&canonical(&manifest.entry_url(&gym.base_url)))
        .await
        .unwrap();
    assert_eq!(
        nav.status,
        Some(200),
        "the authorized gym page itself loads through the proxy"
    );

    let wanted: Vec<(String, u16)> = manifest
        .expected
        .denied_destinations
        .iter()
        .map(|d| (d.host.clone(), d.port))
        .collect();
    let all_seen = |proxy: &crawlx_fetch::EgressProxyHandle| {
        let events = proxy.denied_events();
        wanted.iter().all(|(h, p)| {
            events.iter().any(|e| {
                e.port == *p
                    && (e.host.trim_matches(|c| c == '[' || c == ']') == h
                        || e.ip.is_some_and(|ip| ip.to_string() == *h))
            })
        })
    };
    // Several fixture destinations share one host:port (fetch and img to the metadata address),
    // so every distinct pair being seen does not yet mean every denial has been counted.
    let expected_denials = u64::try_from(wanted.len()).unwrap();
    let ok = eventually(|| all_seen(&proxy) && proxy.denials() >= expected_denials).await;
    let events = proxy.denied_events();
    let missing: Vec<_> = wanted
        .iter()
        .filter(|(h, p)| {
            !events.iter().any(|e| {
                e.port == *p
                    && (e.host.trim_matches(|c| c == '[' || c == ']') == h
                        || e.ip.is_some_and(|ip| ip.to_string() == *h))
            })
        })
        .collect();
    assert!(
        ok,
        "destinations never denied by the proxy: {missing:?}\nevents: {events:#?}"
    );
    assert!(
        proxy.denials() >= expected_denials,
        "denials: {}",
        proxy.denials()
    );

    // Ground truth on the server side: the redirect endpoint was hit (allowed, same origin) and
    // nothing else of the lab ever reached a backend; no probe connected anywhere it should not.
    let ledger = gym.ledger();
    assert!(ledger.count_ops("GET", "/g29/redirect") >= 2);
    let ops = ledger.ops("g29");
    assert!(
        ops.iter()
            .all(|(m, p)| m == "GET" && (p == "/g29/" || p.starts_with("/g29/redirect"))),
        "{ops:?}"
    );
    ctx.close().await.unwrap();
    proxy.shutdown().await;
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g27_native_verdicts_match_the_manifest_truth() {
    let _slot = browser_slot().await;
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("g27").unwrap();
    let mut ctx = backend
        .new_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    ctx.navigate(&canonical(&manifest.entry_url(&gym.base_url)))
        .await
        .unwrap();
    ctx.settle(crawlx_core::observation::QuiescencePolicy::default())
        .await
        .unwrap();
    let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
    let found = CandidateDiscovery::discover(
        &bundle,
        &DiscoveryConfig {
            max_rung: Rung::Listener,
            include_disabled: true,
            include_hidden: true,
            ..DiscoveryConfig::default()
        },
    );
    let mut mismatches = Vec::new();
    for c in manifest.controls.iter().filter(|c| c.frame == "main") {
        let dom_id = c.selector.trim_start_matches('#');
        let cand = found
            .iter()
            .find(|f| f.descriptor.attributes.get("id").map(String::as_str) == Some(dom_id));
        let (verdict, detail) = match cand {
            None => (
                ExpectedClass::NotActionable,
                "absent from the observation".to_owned(),
            ), // hidden or removed
            Some(cand) => {
                let rv = ctx
                    .revalidate(&cand.descriptor.locator, ctx.current_epoch())
                    .await
                    .unwrap();
                (verdict_of(&rv), format!("{rv:?}"))
            }
        };
        let (want, got) = (c.expected.as_str(), verdict.as_str());
        if verdict != c.expected {
            mismatches.push(format!("{}: want {want}, crawlx says {got} ({detail})", c.id));
        }
    }
    // `c-scrolled` sits inside a nested `overflow:auto` container: revalidation scrolls that
    // container with wheel events at its own centre, so it matches the manifest.
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    let scrolled = found
        .iter()
        .find(|f| f.descriptor.attributes.get("id").map(String::as_str) == Some("c-scrolled"))
        .expect("c-scrolled is discovered");
    let receipt = ctx
        .perform(BrowserAction::Click {
            target: scrolled.descriptor.locator.clone(),
            button: PointerButton::Left,
            modifiers: Modifiers::default(),
        })
        .await
        .unwrap();
    assert_eq!(
        (receipt.fidelity, receipt.lane),
        (Fidelity::NativePointer, TrustLane::TrustedUi),
        "wheel scrolling keeps the click on the trusted lane"
    );
    let ledger = gym.ledger();
    assert!(eventually(|| ledger.clicked("g27").contains("c-scrolled")).await);
    assert!(manifest
        .controls
        .iter()
        .any(|c| c.expected == ExpectedClass::NotActionable));
    ctx.close().await.unwrap();
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g31_closed_shadow_controls_and_the_webdriver_probe_per_launch_profile() {
    let _slot = browser_slot().await;
    let manifest = FixtureManifest::embedded("g31").unwrap();
    let mut found_by_profile: Vec<(LaunchProfile, BTreeSet<String>, String)> = Vec::new();
    for profile in [LaunchProfile::Standard, LaunchProfile::Stealth] {
        let Some(backend) = launch(profile, None).await else {
            return;
        };
        let gym = gym().await;
        let mut cfg = ContextConfig::new(SessionId::new());
        cfg.launch_profile = profile;
        let mut ctx = backend.new_context(cfg).await.unwrap();
        ctx.navigate(&canonical(&manifest.entry_url(&gym.base_url)))
            .await
            .unwrap();
        ctx.settle(crawlx_core::observation::QuiescencePolicy::default())
            .await
            .unwrap();
        let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
        let cands = CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default());
        let ids: BTreeSet<String> = cands
            .iter()
            .filter_map(|c| c.descriptor.attributes.get("id").cloned())
            .filter(|id| manifest.control(id).is_some())
            .collect();
        let ledger = gym.ledger();
        assert!(eventually(|| ledger.probes("g31").contains_key("webdriver")).await);
        let probe = ledger.probes("g31")["webdriver"].clone();
        found_by_profile.push((profile, ids, probe));
        ctx.close().await.unwrap();
        gym.shutdown().await;
    }
    let (_, standard, standard_probe) = &found_by_profile[0];
    let (_, stealth, stealth_probe) = &found_by_profile[1];
    assert_eq!(standard_probe, "true", "standard profile is automation-visible");
    assert_ne!(stealth_probe, "true", "stealth hides navigator.webdriver");
    let always: BTreeSet<String> = manifest
        .controls
        .iter()
        .filter(|c| !c.stealth_only)
        .map(|c| c.id.clone())
        .collect();
    assert_eq!(always.len(), 5);
    assert!(
        always.is_subset(standard),
        "closed-root controls must be found under standard: {standard:?}"
    );
    assert!(
        manifest.controls.iter().all(|c| stealth.contains(&c.id)),
        "all six under stealth: {stealth:?}"
    );
    assert!(
        !standard.contains("c6"),
        "the webdriver-gated control is stealth-only"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d1_spa_controls_are_found_the_ticker_never_blocks_idle_and_metadata_requests_are_denied() {
    let _slot = browser_slot().await;
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("d1").unwrap();
    let mut policy = EgressPolicy::new(false);
    policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
    policy.extra_ports.push(gym.port);
    let proxy = EgressProxy::serve(Arc::new(policy), Arc::new(StaticResolver::new()))
        .await
        .unwrap();
    let Some(backend) = launch(LaunchProfile::Standard, Some(proxy.port())).await else {
        return;
    };
    gym.reset(20_261_019);
    let variant = ablation::find("A7").unwrap();
    let cfg = DriverConfig {
        max_actions: 14,
        egress_proxy_port: Some(proxy.port()),
        settle: QuiescencePolicy {
            hard_timeout_ms: 4_000,
            ..QuiescencePolicy::default()
        },
        ..DriverConfig::default()
    };
    let rows = driver::run_variant(&backend, &variant, &manifest, &gym.base_url, 20_261_019, &cfg)
        .await
        .unwrap();
    let ledger = gym.ledger();
    assert!(
        eventually(|| ledger.clicked("d1").len() >= 3).await,
        "{:?}",
        ledger.clicked("d1")
    );

    // Quiescence is measured, not assumed: the scorecard reports the settle-timeout rate. The
    // 250 ms ticker and the `aria-live` status line mutate the DOM continuously; the observer
    // classifies them as volatile targets and leaves them out of the mutation-idle window
    // (<= 2%), so settles end on their idle windows and the settle-timeout rate stays low.
    assert!(!rows.settles.is_empty());
    let sc = Scorecard::compute(&manifest, &rows, &ledger);
    let rate = sc.quiescence_timeout_rate.expect("settles were recorded");
    let timeouts = rows.settles.iter().filter(|s| s.settle_timeout).count();
    assert!((rate - timeouts as f64 / rows.settles.len() as f64).abs() < 1e-12);
    assert!(
        rate <= 0.02,
        "quiescence timeout rate {rate} ({timeouts} of {} settles) exceeds the 2% target: {:?}",
        rows.settles.len(),
        rows.settles
    );
    assert!(
        rows.settles.iter().any(|s| s.excluded_volatile_targets >= 1),
        "the ticker must be reported as an excluded volatile target: {:?}",
        rows.settles
    );
    assert!(
        rows.settles.iter().all(|s| s.network_idle),
        "WebSocket-like ticker traffic must never block network idle"
    );

    // the menu hides its items until opened: revealed items only exist after `menu-btn` ran
    let clicked = ledger.clicked("d1");
    for item in ["menu-profile", "menu-help", "menu-logout"] {
        if clicked.contains(item) {
            assert!(
                clicked.contains("menu-btn"),
                "{item} reached without opening the menu: {clicked:?}"
            );
        }
    }
    let discovered: BTreeSet<String> = rows.discovered.iter().filter_map(|d| d.control.clone()).collect();
    assert!(
        discovered.contains("menu-btn") && discovered.contains("nav-home"),
        "{discovered:?}"
    );

    // the browser-initiated metadata-address requests of the page are blocked and listed
    let metadata = proxy
        .denied_events()
        .into_iter()
        .filter(|e| e.host == "169.254.169.254")
        .count();
    assert!(
        metadata >= 2,
        "fetch and img to the metadata address must both be denied: {:?}",
        proxy.denied_events()
    );
    assert!(ledger.ops("d1").iter().all(|(m, _)| m == "GET" || m == "POST"));
    proxy.shutdown().await;
    gym.shutdown().await;
}

/// G25 uses the production actor and kernel, but holds proposals in this test so the
/// intervening CDP mutation/navigation is deterministic rather than scheduler-dependent.
async fn freshness_actor(
    backend: Arc<ChromiumBackend>,
    gym: &GymHandle,
    stores: crawlx_worker::Stores,
    dir: &std::path::Path,
) -> (
    Arc<crawlx_worker::RunContext>,
    crawlx_worker::actor::SessionHandle,
) {
    use crawlx_core::repo::{CrawlRun, CrawlSession, SessionStatus};
    use crawlx_core::{Clock, CrawlRunId, PrincipalId, SystemClock};
    use crawlx_worker::{RunContext, StateAnalyzer};
    let mut crawl =
        crawlx_core::CreateCrawl::new(url::Url::parse(&format!("{}/stale-rerender/", gym.base_url)).unwrap());
    crawl.mode = crawlx_core::config::CrawlMode::Dynamic;
    crawl.safety.profile = crawlx_core::SafetyProfile::TestEnvironment;
    crawl.safety.allow_private_networks = true;
    crawl.seed = Some(25);
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: stores.tenant,
        status: crawlx_core::counters::RunStatus::Running,
        terminal_reason: None,
        config_digest: crawl.digest().unwrap(),
        seed: crawl.effective_seed(),
        config: crawl.clone(),
        policy_version: 1,
        counters: Default::default(),
        created_at: SystemClock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    let session = CrawlSession {
        id: SessionId::new(),
        run: run.id,
        kind: crawlx_core::repo::SessionKind::Browser,
        role: PrincipalId("anonymous".into()),
        run_index: 1,
        schedule_slot: 0,
        status: SessionStatus::Running,
        browser: None,
        action_seq: 0,
    };
    stores
        .runs
        .create_sessions(std::slice::from_ref(&session))
        .await
        .unwrap();
    let manifest = FixtureManifest::embedded("stale-rerender").unwrap();
    let mut config = crawlx_bench::worker_exec::worker_config(&manifest, dir).unwrap();
    config.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let context = Arc::new(
        RunContext::build(
            &run,
            &config,
            stores.clone(),
            Some(backend),
            None,
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
        )
        .await
        .unwrap(),
    );
    let session_config = context.session_config(&session);
    let pooled = context
        .pool
        .acquire(session_config.context.clone(), session_config.exclusive_browser)
        .await
        .unwrap();
    let analyzer = Arc::new(StateAnalyzer::new(
        run.id,
        session.id,
        context.clusters.clone(),
        stores.artifacts.clone(),
        context.clock.clone(),
        crawl.capture,
        (&context.controls, &context.captcha_secrets),
    ));
    let handle =
        crawlx_worker::actor::SessionActor::spawn(session_config, context.services(), analyzer, 25, pooled)
            .await
            .unwrap();
    handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            context.seed_url().unwrap(),
            0,
            None,
        ))
        .await
        .unwrap();
    (context, handle)
}

async fn freshness_proposal(
    context: &crawlx_worker::RunContext,
    handle: &crawlx_worker::actor::SessionHandle,
    control: &str,
) -> crawlx_safety::AdmittedAction {
    use crawlx_core::identity::{ActionContextKey, ActionKind, InputClass, ResourceContext};
    use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
    use crawlx_core::repo::SafetyContext;
    use crawlx_elements::{IdentityResolver, InMemoryIdentityIndex, MatchWeights};
    let bundle = handle
        .observe(crawlx_observe::spec::after_action())
        .await
        .unwrap();
    let session = context
        .stores
        .runs
        .list_sessions(context.run)
        .await
        .unwrap()
        .remove(0);
    let analyzed = crawlx_worker::StateAnalyzer::new(
        context.run,
        session.id,
        context.clusters.clone(),
        context.stores.artifacts.clone(),
        context.clock.clone(),
        context.crawl.capture.clone(),
        (&context.controls, &context.captcha_secrets),
    )
    .analyze(&bundle)
    .await;
    context.stores.states.put_state(&analyzed.state).await.unwrap();
    let candidate = CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default())
        .into_iter()
        .find(|candidate| {
            candidate
                .descriptor
                .attributes
                .get("id")
                .is_some_and(|id| id == control)
        })
        .unwrap_or_else(|| panic!("missing {control}"));
    let resolved = IdentityResolver::with_destination(bundle.url.url.clone(), Default::default())
        .resolve(
            &candidate.descriptor,
            &InMemoryIdentityIndex::new(),
            &MatchWeights::default(),
        )
        .unwrap();
    let proposal = ActionProposal {
        key: ActionContextKey {
            principal: session.role.clone(),
            route_template: bundle.route.template.clone(),
            element: resolved.hash,
            action_kind: ActionKind::Click,
            input_class: InputClass::none(),
            resource_context: ResourceContext::None,
            state_cluster: analyzed.state.cluster,
        },
        action: BrowserAction::Click {
            target: candidate.descriptor.locator.clone(),
            button: PointerButton::Left,
            modifiers: Modifiers::default(),
        },
        epoch: bundle.epoch,
        strategy: "g25_acceptance",
        strategy_version: 1,
        confidence: 1.0,
        expected: ExpectedEffect::default(),
        hinted_risk: None,
        model_decision: None,
        summary: format!("click {control}"),
    };
    let safety = SafetyContext {
        profile: context.crawl.safety.profile,
        has_test_sinks: false,
        destructive_approval_allowed: false,
        principal: session.role,
        seed_origin: context.seed_origin(),
        in_scope: true,
        target: crawlx_strategies::frontier::target_facts(&candidate, &bundle),
        form_hint: None,
    };
    match context.kernel.adjudicate(proposal, &safety) {
        crawlx_safety::Adjudication::Allow(action) => action,
        other => panic!("fixture star action must be admitted: {:?}", other.verdict()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g25_rerender_and_navigation_drop_stale_proposals_without_wrong_server_effects() {
    use crawlx_core::counters::ActionStatus;
    use crawlx_core::page_op::{PageOp, PageOpResult};
    use crawlx_worker::actor::{DropReason, ShutdownReason};
    let Some(executable) = std::env::var_os("CRAWLX_CHROMIUM_PATH") else {
        eprintln!("SKIP: G25 acceptance requires pinned CRAWLX_CHROMIUM_PATH");
        return;
    };
    let _slot = browser_slot().await;
    let mut launch = LaunchConfig::new();
    launch.executable = executable.into();
    launch.allow_unpinned = false;
    launch.unsafe_no_sandbox_for_ci = std::env::var("USER").is_ok_and(|user| user == "root");
    let backend = Arc::new(ChromiumBackend::launch(launch).await.unwrap());
    assert!(
        backend.build_info().pinned,
        "G25 acceptance requires the pinned Chromium build"
    );
    let gym = gym().await;
    gym.reset(25);
    let dir = tempfile::tempdir().unwrap();
    let stores = crawlx_worker::Stores::open(
        &crawlx_bench::worker_exec::worker_config(
            &FixtureManifest::embedded("stale-rerender").unwrap(),
            dir.path(),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let (context, handle) = freshness_actor(backend, &gym, stores, dir.path()).await;
    handle
        .page_op(PageOp::EvaluateScript {
            script: "document.getElementById('delay').value = '0'".into(),
        })
        .await
        .unwrap();
    let mut drops = Vec::new();
    for timer in [false, true] {
        let proposal = freshness_proposal(&context, &handle, "star-1").await;
        let script = if timer {
            // Await an actual timer-driven DOM replacement; no elapsed-time guess proves this race.
            r#"new Promise(resolve => {
                const list = document.getElementById('list');
                const before = [...list.querySelectorAll('button[id^="star-"]')].map(n => n.id);
                const observer = new MutationObserver(() => {
                    observer.disconnect();
                    document.getElementById('delay').value = '0';
                    resolve({before, after: [...list.querySelectorAll('button[id^="star-"]')].map(n => n.id)});
                });
                observer.observe(list, {childList: true});
                document.getElementById('delay').value = '1';
                window.dispatchEvent(new Event('pointermove'));
            })"#
        } else {
            r#"(() => {
                const list = document.getElementById('list');
                const before = [...list.querySelectorAll('button[id^="star-"]')].map(n => n.id);
                document.getElementById('rerender-now').click();
                return {before, after: [...list.querySelectorAll('button[id^="star-"]')].map(n => n.id)};
            })()"#
        };
        let PageOpResult::Json(order) = handle
            .page_op(PageOp::EvaluateScript {
                script: script.into(),
            })
            .await
            .unwrap()
        else {
            panic!("rerender must return order evidence")
        };
        assert_ne!(
            order["before"], order["after"],
            "fixture must reorder actual targets"
        );
        let outcome = handle
            .execute(proposal, QuiescencePolicy::default())
            .await
            .unwrap();
        assert_eq!(outcome.status, ActionStatus::Proposed, "{outcome:?}");
        assert!(
            matches!(
                outcome.dropped,
                Some(DropReason::StaleEpoch | DropReason::NotActionable | DropReason::IdentityChanged)
            ),
            "every rerender drop must be classified: {outcome:?}"
        );
        assert!(outcome.receipt.is_none());
        drops.push(outcome);
    }
    let proposal = freshness_proposal(&context, &handle, "star-1").await;
    // This calls the real CDP Page.navigate through the actor after proposal creation.
    handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical(&format!("{}/stale-rerender/?navigation=2", gym.base_url)),
            0,
            None,
        ))
        .await
        .unwrap();
    let outcome = handle
        .execute(proposal, QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(outcome.dropped, Some(DropReason::StaleEpoch), "{outcome:?}");
    assert_eq!(outcome.status, ActionStatus::Proposed);
    assert!(outcome.receipt.is_none());
    drops.push(outcome);
    assert_eq!(drops.len(), 3);
    assert!(drops.iter().all(|outcome| outcome.dropped.is_some()));
    assert_eq!(gym.ledger().count_ops("POST", "/stale-rerender/api/projects"), 0);
    assert_eq!(
        gym.ledger().count_ops("DELETE", "/stale-rerender/api/projects"),
        0
    );
    assert!(gym.ledger().effects("stale-rerender").is_empty());

    handle
        .page_op(PageOp::EvaluateScript {
            script: "document.getElementById('delay').value = '0'".into(),
        })
        .await
        .unwrap();
    let replanned = freshness_proposal(&context, &handle, "star-1").await;
    let succeeded = handle
        .execute(replanned, QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(succeeded.status, ActionStatus::Succeeded, "{succeeded:?}");
    assert!(succeeded.dropped.is_none());
    assert_eq!(succeeded.receipt.as_ref().unwrap().lane, TrustLane::TrustedUi);
    let ledger = gym.ledger();
    assert!(eventually(|| ledger.effects("stale-rerender").len() == 1).await);
    let effects = ledger.effects("stale-rerender");
    let wrong_element_actions = effects
        .iter()
        .filter(|(_, effect, resource, _)| effect != "star:applied" || resource != "1")
        .count();
    assert_eq!(wrong_element_actions, 0, "{effects:?}");
    assert_eq!(
        effects.len(),
        1,
        "one real successful effect makes the zero gate nonvacuous"
    );
    assert!(ledger
        .clicks("stale-rerender")
        .contains(&("star-1".to_owned(), true)));
    let state: serde_json::Value = reqwest::get(format!("{}/stale-rerender/api/stars", gym.base_url))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        state["stars"],
        serde_json::json!({"1": 1}),
        "server state must match the one intended native action"
    );
    assert_eq!(state["removed"], serde_json::json!([]));
    handle.shutdown(ShutdownReason::Completed).await.unwrap();
    gym.shutdown().await;
}
