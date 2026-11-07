//! System 1 and the LLM planner through the worker: wiremock stands in for the decision service and
//! the planner endpoint, `FakeBackend` for the browser, `MemoryStore` for storage.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, LlmPlannerMode, StrategyName, System1Mode};
use crawlx_core::counters::ActionStatus;
use crawlx_core::repo::{ModelDecisionKind, ModelDecisionRecord, ModelDecisionRepo};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_worker::{
    run_local_with, EgressConfig, EngineConfig, LocalRun, ModelConfig, PlannerConfig, RunReport, Stores,
    WorkerConfig,
};
use serde_json::{json, Value};
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// A decision service that puts `0.8` on the option at `favoured` (or the first when the question
/// offers fewer) and spreads the rest.
struct DecisionService {
    favoured: usize,
}

impl Respond for DecisionService {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        let q = &body["questions"][0];
        let options: Vec<u64> = q["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_u64().unwrap())
            .collect();
        let fav = if self.favoured < options.len() {
            self.favoured
        } else {
            0
        };
        let others = f64::from(u32::try_from(options.len() - 1).unwrap().max(1));
        let probs: Vec<Value> = options
            .iter()
            .enumerate()
            .map(|(i, o)| json!({"option": o, "p": if i == fav { 0.8 } else { 0.15 / others }}))
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({
            "answers": [{"kind": "choice", "id": q["id"], "probs": probs, "none": 0.05}]
        }))
    }
}

/// A decision service that is never sure: probabilities spread evenly with `none` highest, so the
/// confidence gate abstains on every call.
struct UnsureDecisionService;

impl Respond for UnsureDecisionService {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        let q = &body["questions"][0];
        let options: Vec<u64> = q["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_u64().unwrap())
            .collect();
        let each = 0.4 / f64::from(u32::try_from(options.len()).unwrap().max(1));
        let probs: Vec<Value> = options.iter().map(|o| json!({"option": o, "p": each})).collect();
        ResponseTemplate::new(200).set_body_json(json!({
            "answers": [{"kind": "choice", "id": q["id"], "probs": probs, "none": 0.6}]
        }))
    }
}

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

/// One page of fourteen distinct buttons: enough eligible keys for System 1 to run in advisory
/// mode (it needs a shortlist of at least twelve).
fn button_app() -> FakeScript {
    const NAMES: [&str; 14] = [
        "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliet", "Kilo",
        "Lima", "Mike", "November",
    ];
    let mut p = FakePage::new("https://example.test/").title("Buttons");
    for (i, name) in NAMES.iter().enumerate() {
        let key = format!("b{i}");
        p = p
            .node(FakeAxSpec::button(key.clone(), *name))
            .on_click(&key, vec![FakeEffect::Nothing]);
    }
    FakeScript::new().page(p)
}

fn worker_cfg(dir: &std::path::Path) -> WorkerConfig {
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

fn crawl(mutate: impl FnOnce(&mut CreateCrawl)) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    c.mode = CrawlMode::Dynamic;
    c.seed = Some(20_261_019);
    c.limits.interactions = 40;
    c.limits.states = 100;
    mutate(&mut c);
    c
}

struct Outcome {
    report: RunReport,
    performed: Vec<String>,
    decisions: Vec<ModelDecisionRecord>,
}

async fn run(script: FakeScript, crawl: CreateCrawl, cfg: impl FnOnce(&mut WorkerConfig)) -> Outcome {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FakeBackend::new(script));
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let mut worker = worker_cfg(dir.path());
    cfg(&mut worker);
    let report = run_local_with(
        LocalRun::new(crawl, worker)
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
    let decisions = store.list(report.run_id).await.unwrap();
    Outcome {
        report,
        performed,
        decisions,
    }
}

fn decision_model(server: &MockServer, mode: System1Mode) -> ModelConfig {
    ModelConfig {
        engine: EngineConfig::DecisionHttp {
            base_url: server.uri(),
            api_key_env: None,
            timeout_ms: 1500,
        },
        mode,
    }
}

async fn decision_server(favoured: usize) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(DecisionService { favoured })
        .mount(&server)
        .await;
    server
}

fn with_system1(mode: System1Mode) -> impl FnOnce(&mut CreateCrawl) {
    move |c| {
        c.safety.profile = crawlx_core::SafetyProfile::TestEnvironment;
        c.dynamic.strategies = vec![StrategyName::InteractionBfs, StrategyName::System1];
        c.dynamic.system1_mode = mode;
    }
}

#[tokio::test]
async fn model_authority_without_g3_is_refused_before_a_local_run_starts() {
    for mode in [System1Mode::Advisory, System1Mode::Active] {
        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(FakeBackend::new(button_app()));
        let mut worker = worker_cfg(dir.path());
        worker.gates = crawlx_worker::Gates::none();
        worker.model = Some(ModelConfig {
            engine: EngineConfig::Mock,
            mode,
        });
        let err =
            run_local_with(LocalRun::new(crawl(with_system1(mode)), worker).with_backend(backend.clone()))
                .await
                .unwrap_err();
        assert!(err.to_string().contains("G3"), "{err}");
        assert!(backend.context_handles().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_mode_records_decisions_and_never_changes_what_the_crawl_does() {
    let server = decision_server(1).await;
    let shadow = run(three_page_app(), crawl(with_system1(System1Mode::Shadow)), |w| {
        w.model = Some(decision_model(&server, System1Mode::Shadow));
    })
    .await;
    // the control: the same crawl with System 1 listed but no model configured
    let control = run(three_page_app(), crawl(with_system1(System1Mode::Shadow)), |_| {}).await;

    assert!(
        !server.received_requests().await.unwrap().is_empty(),
        "the model was asked"
    );
    assert!(!shadow.decisions.is_empty(), "shadow decisions are recorded");
    assert!(control.decisions.is_empty());
    for d in &shadow.decisions {
        assert_eq!(d.kind, ModelDecisionKind::Rank);
        assert_eq!(d.mode, System1Mode::Shadow);
        assert_eq!(d.provider, "decision-http");
        assert!(d.session.is_some());
        assert!(d.confidence.is_some_and(|p| (0.0..=1.0).contains(&p)));
        let shortlist = d.output["shortlist"].as_array().unwrap();
        assert!(shortlist.len() >= 2);
        assert_eq!(d.output["probs"].as_array().unwrap().len(), shortlist.len());
    }
    // shadow never influences selection: no action is attributed to the model and the browser
    // saw exactly what it sees without a model
    assert!(shadow.report.actions.iter().all(|a| a.model_decision.is_none()));
    assert!(shadow.report.actions.iter().all(|a| a.strategy != "system1"));
    assert_eq!(shadow.performed, control.performed);
    assert_eq!(
        shadow
            .report
            .actions
            .iter()
            .map(|a| a.key.id())
            .collect::<Vec<_>>(),
        control
            .report
            .actions
            .iter()
            .map(|a| a.key.id())
            .collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advisory_mode_lets_the_model_pick_among_safe_candidates() {
    let server = decision_server(3).await;
    let out = run(button_app(), crawl(with_system1(System1Mode::Advisory)), |w| {
        w.model = Some(decision_model(&server, System1Mode::Advisory));
    })
    .await;
    assert!(!out.decisions.is_empty());
    assert!(out.decisions.iter().all(|d| d.mode == System1Mode::Advisory));
    let influenced: Vec<_> = out
        .report
        .actions
        .iter()
        .filter(|a| a.model_decision.is_some())
        .collect();
    assert!(
        !influenced.is_empty(),
        "the gate accepted the model's choice at least once"
    );
    for a in &influenced {
        assert_eq!(a.strategy, "system1");
        assert_eq!(a.status, ActionStatus::Succeeded);
        let d = out
            .decisions
            .iter()
            .find(|d| Some(d.id) == a.model_decision)
            .expect("the action points at a recorded decision");
        // the model's pick is what ran: option 3 of the shortlist of that round
        assert_eq!(
            d.output["selected"].as_str().unwrap(),
            a.key.id().to_string(),
            "the executed key is the one the gate accepted"
        );
        assert_eq!(d.output["shortlist"][3].as_str().unwrap(), a.key.id().to_string());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_cannot_exceed_the_workers_ceiling() {
    let server = decision_server(3).await;
    let out = run(button_app(), crawl(with_system1(System1Mode::Advisory)), |w| {
        w.model = Some(decision_model(&server, System1Mode::Shadow));
    })
    .await;
    assert!(!out.decisions.is_empty());
    assert!(out.decisions.iter().all(|d| d.mode == System1Mode::Shadow));
    assert!(out.report.actions.iter().all(|a| a.model_decision.is_none()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_mock_engine_needs_no_network() {
    let out = run(button_app(), crawl(with_system1(System1Mode::Shadow)), |w| {
        w.model = Some(ModelConfig {
            engine: EngineConfig::Mock,
            mode: System1Mode::Shadow,
        });
    })
    .await;
    assert!(!out.decisions.is_empty());
    assert!(out.decisions.iter().all(|d| d.provider == "mock"));
}

/// Every flushed System 1 record is one `crawlx.model.requests`, one latency observation and
/// one shortlist-size observation; the `mock`/`advisory` label pair is used by this test
/// only, so its request deltas are exact (latency and shortlist size share labels with
/// other tests of this binary and are lower bounds).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn model_calls_are_counted_and_timed() {
    let m = Metrics::global();
    let ok = &[
        ("provider", "mock"),
        ("model", "mock-v1"),
        ("mode", "advisory"),
        ("outcome", "ok"),
    ];
    let abstain = &[
        ("provider", "mock"),
        ("model", "mock-v1"),
        ("mode", "advisory"),
        ("outcome", "abstain"),
    ];
    let abstentions = &[("provider", "mock"), ("model", "mock-v1"), ("mode", "advisory")];
    let latency = &[("provider", "mock"), ("model", "mock-v1")];
    let shortlist = &[("mode", "advisory")];
    let read = || {
        (
            m.counter(names::MODEL_REQUESTS).get(ok),
            m.counter(names::MODEL_REQUESTS).get(abstain),
            m.counter(names::MODEL_ABSTENTIONS).get(abstentions),
            m.histogram(names::MODEL_LATENCY)
                .snapshot(latency)
                .map_or(0, |s| s.count),
            m.histogram(names::MODEL_SHORTLIST_SIZE)
                .snapshot(shortlist)
                .map_or(0, |s| s.count),
        )
    };
    let before = read();
    let out = run(button_app(), crawl(with_system1(System1Mode::Advisory)), |w| {
        w.model = Some(ModelConfig {
            engine: EngineConfig::Mock,
            mode: System1Mode::Advisory,
        });
    })
    .await;
    let after = read();
    let total = u64::try_from(out.decisions.len()).unwrap();
    let abstained = u64::try_from(
        out.decisions
            .iter()
            .filter(|d| d.output["selected"].is_null())
            .count(),
    )
    .unwrap();
    assert!(total > 0);
    assert_eq!(after.0 - before.0, total - abstained, "ok requests");
    assert_eq!(after.1 - before.1, abstained, "abstain requests");
    assert_eq!(after.2 - before.2, abstained, "abstentions");
    assert!(after.3 - before.3 >= total, "latency observations");
    assert!(after.4 - before.4 >= total, "shortlist observations");
    assert!(
        m.gauge(names::MODEL_BREAKER_STATE)
            .get(&[("provider", "mock")])
            .is_none(),
        "the mock engine has no breaker"
    );
}

/// A model that never clears the gate abstains on every call: each call is a request with
/// `outcome = abstain` and an abstention. The crawl still completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abstentions_are_counted() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(UnsureDecisionService)
        .mount(&server)
        .await;
    let m = Metrics::global();
    let abstentions = &[
        ("provider", "decision-http"),
        ("model", "decision-http"),
        ("mode", "shadow"),
    ];
    let abstain = &[
        ("provider", "decision-http"),
        ("model", "decision-http"),
        ("mode", "shadow"),
        ("outcome", "abstain"),
    ];
    let before = (
        m.counter(names::MODEL_ABSTENTIONS).get(abstentions),
        m.counter(names::MODEL_REQUESTS).get(abstain),
        m.gauge(names::MODEL_BREAKER_STATE)
            .get(&[("provider", "decision-http")]),
    );
    let out = run(three_page_app(), crawl(with_system1(System1Mode::Shadow)), |w| {
        w.model = Some(decision_model(&server, System1Mode::Shadow));
    })
    .await;
    let after = (
        m.counter(names::MODEL_ABSTENTIONS).get(abstentions),
        m.counter(names::MODEL_REQUESTS).get(abstain),
        m.gauge(names::MODEL_BREAKER_STATE)
            .get(&[("provider", "decision-http")]),
    );
    assert!(!out.decisions.is_empty());
    assert!(
        out.decisions.iter().all(|d| d.output["selected"].is_null()),
        "every call abstained"
    );
    let n = u64::try_from(out.decisions.len()).unwrap();
    // other tests of this binary drive `decision-http`/`shadow` too: the deltas are lower bounds
    assert!(after.0 - before.0 >= n, "abstentions {before:?} -> {after:?}");
    assert!(after.1 - before.1 >= n, "abstain requests");
    // the breaker gauge of the `decision-http` provider is set from the engine's real breaker; the
    // failing-model test of this binary may have opened its own engine's breaker meanwhile
    assert!(
        after.2.is_some_and(|v| [0.0, 1.0, 2.0].contains(&v)),
        "the decision-http breaker state is reported (before: {:?}, after: {:?})",
        before.2,
        after.2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_model_never_stops_the_crawl() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let baseline = run(three_page_app(), crawl(with_system1(System1Mode::Shadow)), |_| {}).await;
    let out = run(three_page_app(), crawl(with_system1(System1Mode::Shadow)), |w| {
        w.model = Some(decision_model(&server, System1Mode::Shadow));
    })
    .await;
    assert!(out.decisions.is_empty());
    assert_eq!(out.report.status, baseline.report.status);
    assert_eq!(
        out.report.actions.len(),
        baseline.report.actions.len(),
        "failed model calls contribute nothing"
    );
}

fn planner_cfg(server: &MockServer) -> PlannerConfig {
    PlannerConfig {
        base_url: server.uri(),
        api_key_env: None,
        timeout_ms: 1500,
    }
}

async fn planner_server(plan: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(plan))
        .mount(&server)
        .await;
    server
}

fn with_planner(c: &mut CreateCrawl) {
    c.dynamic.llm_planner = LlmPlannerMode::StalledOnly;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planner_proposals_run_through_the_normal_path_and_only_target_candidates() {
    let server = planner_server(r#"{"version":1,"steps":[{"op":"click","target":0}]}"#).await;
    let out = run(three_page_app(), crawl(with_planner), |w| {
        w.planner = Some(planner_cfg(&server));
    })
    .await;
    let requests = server.received_requests().await.unwrap();
    assert!(
        !requests.is_empty(),
        "the planner is consulted once deterministic recovery is exhausted"
    );
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let candidates = body["candidates"].as_array().unwrap();
    assert!(!candidates.is_empty());
    assert!(body["max_steps"].as_u64().unwrap() <= 20);

    let planned: Vec<_> = out
        .report
        .actions
        .iter()
        .filter(|a| a.strategy == "llm_planner")
        .collect();
    assert!(!planned.is_empty(), "the planner's step was executed");
    // through the actor: journaled, trusted lane, and the browser accepted the target
    for a in &planned {
        assert_eq!(a.status, ActionStatus::Succeeded, "{a:?}");
        assert_eq!(a.lane, Some(crawlx_core::TrustLane::TrustedUi));
        assert!(a.safety_decision.0.as_u128() != 0, "the kernel adjudicated it");
    }
    // every planned target is a control that exists on the page it ran on
    let nodes: std::collections::BTreeSet<&str> = ["products", "about", "home"].into_iter().collect();
    assert!(
        out.performed
            .iter()
            .filter_map(|k| k.strip_prefix("click:"))
            .all(|n| nodes.contains(n)),
        "{:?}",
        out.performed
    );
    assert!(out.report.counters.interactions.invariants_hold());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plan_that_names_a_non_candidate_is_discarded_and_nothing_runs() {
    let server = planner_server(r#"{"version":1,"steps":[{"op":"click","target":99}]}"#).await;
    let baseline = run(three_page_app(), crawl(|_| {}), |_| {}).await;
    let out = run(three_page_app(), crawl(with_planner), |w| {
        w.planner = Some(planner_cfg(&server));
    })
    .await;
    assert!(!server.received_requests().await.unwrap().is_empty());
    assert!(out.report.actions.iter().all(|a| a.strategy != "llm_planner"));
    assert_eq!(
        out.performed, baseline.performed,
        "an invalid plan changes nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_planner_endpoint_the_planner_mode_is_inert() {
    let baseline = run(three_page_app(), crawl(|_| {}), |_| {}).await;
    let out = run(three_page_app(), crawl(with_planner), |_| {}).await;
    assert_eq!(out.performed, baseline.performed);
    assert_eq!(out.report.terminal_reason, baseline.report.terminal_reason);
}
