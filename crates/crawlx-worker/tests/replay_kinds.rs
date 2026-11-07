//! Replay of every action kind the driver records, plus recorded failures that changed the page.
//!
//! The first local G1 run replayed 0/10 paths on G02 (`step 8 select -> NotReproducible`) and
//! on G03 (`step 29 hover -> Diverged`): the replay rebuilt only click, keyboard activation,
//! hover, navigation and typing, and it left out the `Select` that failed on an open custom
//! combobox after toggling it shut, so every later state differed from the recorded one.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, SafetyProfile, StrategyName};
use crawlx_core::counters::{ActionStatus, RunStatus};
use crawlx_core::{ActionKind, CreateCrawl, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::driver::discovered_url_element;
use crawlx_worker::replay::{ReplayMode, ReplayPlan, ReplayReport, ReplayRunner, StepVerdict};
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::collections::BTreeSet;
use std::sync::Arc;

const HOME: &str = "https://example.test/";
/// A URL the page's scripts fetch; the driver navigates to it without any link to click.
const LIVE: &str = "https://example.test/live";

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

fn backend(script: FakeScript) -> Arc<FakeBackend> {
    Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(SystemClock))
            .build(),
    )
}

/// A control whose action reveals a one-button confirmation, so every kind changes the page.
fn reveals(page: FakePage, kind: ActionKind, key: &str, shown: &str) -> FakePage {
    let marker = format!("{key}-done");
    page.on(
        kind,
        key,
        vec![FakeEffect::Reveal(vec![FakeAxSpec::button(marker, shown)])],
    )
}

/// One page with a `<select>`, a slider, a checkbox, a text field, a scrollable region and a
/// menu; a link that opens a popup tab; and a custom combobox whose `Select` fails after it
/// toggled the widget shut (the g03 failure on Chromium).
fn app() -> FakeScript {
    let page = FakePage::new(HOME)
        .title("Widgets")
        .node(FakeAxSpec::new("colour", "combobox").name("Colour").tag("select"))
        .node(
            FakeAxSpec::new("volume", "slider")
                .name("Volume")
                .tag("input")
                .attr("max", "10"),
        )
        .node(FakeAxSpec::checkbox("remember", "Remember me"))
        .node(FakeAxSpec::textbox("email", "Email").attr("type", "email"))
        .node(FakeAxSpec::new("news", "feed").name("News").focusable())
        .node(FakeAxSpec::button("actions", "Actions").attr("aria-haspopup", "menu"))
        .node(FakeAxSpec::new("fruit", "combobox").name("Fruit"))
        .node(FakeAxSpec::button("help", "Help"))
        .on_click(
            "help",
            vec![FakeEffect::OpenTab("https://example.test/help".to_owned())],
        )
        .discovered(LIVE, "fetch");
    let page = reveals(page, ActionKind::Select, "colour", "Colour chosen");
    let page = reveals(page, ActionKind::SetRange, "volume", "Volume set");
    let page = reveals(page, ActionKind::SetChecked, "remember", "Remembered");
    let page = reveals(page, ActionKind::Type, "email", "Email entered");
    let page = reveals(page, ActionKind::Scroll, "news", "More news");
    let page = reveals(page, ActionKind::Hover, "actions", "Menu open");
    let page = reveals(page, ActionKind::Select, "fruit", "Fruit menu shut");
    FakeScript::new()
        .page(page)
        .page(FakePage::new("https://example.test/help").title("Help"))
        .page(FakePage::new(LIVE).title("Live"))
        .fail_action_after_effects("select:fruit", "no visible option matches Index(1)")
}

struct Recorded {
    stores: Stores,
    report: RunReport,
    dir: tempfile::TempDir,
}

async fn record() -> Recorded {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(HOME).unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.safety.profile = SafetyProfile::TestEnvironment;
    crawl.dynamic.page_hooks = true;
    // The recorded path needs every action family, including the G1-gated strategies
    // (opt-in since the default set runs without gate keys); `cfg` grants all gates.
    crawl.dynamic.strategies = vec![
        StrategyName::InteractionBfs,
        StrategyName::EventDriven,
        StrategyName::StateNovelty,
        StrategyName::Enablement,
    ];
    crawl.seed = Some(20_261_028);
    crawl.limits.interactions = 120;
    crawl.limits.states = 300;
    let browser = backend(app());
    let report = run_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(browser)
            .with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    Recorded { stores, report, dir }
}

async fn replay(rec: &Recorded, mode: ReplayMode, script: FakeScript) -> (ReplayPlan, ReplayReport) {
    let last = rec
        .report
        .actions
        .iter()
        .rfind(|a| a.status == ActionStatus::Succeeded)
        .expect("the crawl recorded a succeeded action");
    let plan = ReplayPlan::load(&rec.stores, rec.report.run_id, last.id)
        .await
        .unwrap();
    let out = ReplayRunner::run(
        cfg(rec.dir.path()),
        plan.clone(),
        mode,
        Some(backend(script)),
        None,
    )
    .await
    .unwrap();
    (plan, out)
}

fn kinds(plan: &ReplayPlan) -> BTreeSet<ActionKind> {
    plan.steps.iter().map(|s| s.action.key.action_kind).collect()
}

/// `seq kind status` of every step, for assertion messages.
fn path(plan: &ReplayPlan) -> Vec<String> {
    plan.steps
        .iter()
        .map(|s| {
            format!(
                "{} {:?} {:?}",
                s.action.seq, s.action.key.action_kind, s.action.status
            )
        })
        .collect()
}

/// A replay logs in, so its scratch store seals what it retains and is removed when the
/// replay ends; nothing is left under `<artifacts_dir>/replay`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_leaves_no_scratch_artifacts_behind() {
    let rec = record().await;
    let before: Vec<_> = std::fs::read_dir(rec.dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let (_, out) = replay(&rec, ReplayMode::Verify, app()).await;
    assert!(out.ok, "{:#?}", out.steps);
    assert!(
        !rec.dir.path().join("replay").exists(),
        "the replay scratch directory must not persist under the artifacts dir"
    );
    let after: Vec<_> = std::fs::read_dir(rec.dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        before, after,
        "the replay must not add entries to the artifacts dir"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_recorded_kind_replays_to_matched() {
    let rec = record().await;
    let (plan, out) = replay(&rec, ReplayMode::Verify, app()).await;
    let recorded = kinds(&plan);
    for kind in [
        ActionKind::Select,
        ActionKind::SetRange,
        ActionKind::SetChecked,
        ActionKind::Type,
        ActionKind::Scroll,
        ActionKind::Hover,
        ActionKind::Click,
        ActionKind::Navigate,
        ActionKind::SwitchTab,
        ActionKind::CloseTab,
    ] {
        assert!(
            recorded.contains(&kind),
            "the crawl never recorded {kind:?}: {recorded:?}"
        );
    }
    // a hook-discovered URL and a reset to a known route name no element on the page
    let navigates_to_live = discovered_url_element(LIVE);
    assert!(
        plan.steps.iter().any(|s| {
            s.action.key.action_kind == ActionKind::Navigate && s.action.key.element == navigates_to_live
        }),
        "the crawl never navigated to the discovered URL: {:#?}",
        path(&plan)
    );
    assert!(out.ok, "{:#?}", out.steps);
    assert_eq!(out.steps.len(), plan.steps.len());
    assert!(
        out.steps.iter().all(|s| matches!(
            s.verdict,
            StepVerdict::Matched { .. } | StepVerdict::FailedAsRecorded { .. }
        )),
        "{:#?}",
        out.steps
    );

    let (_, reproduced) = replay(&rec, ReplayMode::Reproduce, app()).await;
    assert!(reproduced.ok, "{:#?}", reproduced.steps);
}

#[tokio::test]
async fn legacy_before_state_refuses_replay_without_an_after_state_before_browser_acquisition() {
    let rec = record().await;
    let target = rec
        .report
        .actions
        .iter()
        .find(|action| action.status == ActionStatus::Succeeded)
        .unwrap();
    let mut plan = ReplayPlan::load(&rec.stores, rec.report.run_id, target.id)
        .await
        .unwrap();
    assert!(!plan.steps.is_empty());
    for step in &mut plan.steps {
        step.recorded_after = None;
        step.recorded_before.signature.version = crawlx_core::state::StateSignature::VERSION - 1;
    }
    for mode in [ReplayMode::Verify, ReplayMode::Reproduce] {
        let browser = backend(app());
        let error = ReplayRunner::run(
            cfg(rec.dir.path()),
            plan.clone(),
            mode,
            Some(browser.clone()),
            None,
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("replay state signature version mismatch"));
        assert_eq!(
            browser.contexts_created(),
            0,
            "version refusal precedes login/navigation"
        );
    }
    // The loader independently validates the exact journal before_state against storage,
    // not the optional after-state or a caller-supplied current algorithm version.
    let mut source = rec.stores.clone();
    let states = Arc::new(MemoryStore::new());
    let run = source.runs.get(rec.report.run_id).await.unwrap();
    crawlx_core::repo::RunRepo::create(states.as_ref(), &run, None)
        .await
        .unwrap();
    let sessions = source.runs.list_sessions(run.id).await.unwrap();
    crawlx_core::repo::RunRepo::create_sessions(states.as_ref(), &sessions)
        .await
        .unwrap();
    crawlx_core::repo::StateRepo::put_state(states.as_ref(), &plan.steps[0].recorded_before)
        .await
        .unwrap();
    source.states = states;
    let error = ReplayPlan::load(&source, rec.report.run_id, target.id)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("replay state signature version mismatch"));
}

/// The failed `Select` on the "Fruit" combobox changed the page (the widget was toggled shut)
/// before the browser gave up. The recorded run went on from that page; a replay that skips
/// the failed action never shows it, and the step that follows has nothing to act on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_action_that_changed_the_page_is_part_of_the_path() {
    let rec = record().await;
    let (plan, out) = replay(&rec, ReplayMode::Verify, app()).await;
    let failed: Vec<_> = plan
        .steps
        .iter()
        .filter(|s| s.action.status == ActionStatus::Failed)
        .collect();
    assert!(
        !failed.is_empty(),
        "no failed select on the path: {:#?}",
        path(&plan)
    );
    assert_eq!(failed[0].action.key.action_kind, ActionKind::Select);
    let replayed = out
        .steps
        .iter()
        .find(|s| s.action == failed[0].action.id)
        .expect("the failed step was replayed");
    assert!(
        matches!(replayed.verdict, StepVerdict::FailedAsRecorded { .. }),
        "{replayed:?}"
    );
    assert!(out.ok, "{:#?}", out.steps);
    // the follow-through click on the control the failed select revealed is on the path too
    assert!(
        plan.steps
            .iter()
            .skip_while(|s| s.action.status != ActionStatus::Failed)
            .skip(1)
            .any(|s| s.action.key.action_kind == ActionKind::Click),
        "{:#?}",
        path(&plan)
    );
}

/// A target that never stabilizes must terminate without executing it or later path steps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_staleness_stops_replay_without_browser_effects() {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let script = FakeScript::new().page(
        FakePage::new(HOME)
            .node(FakeAxSpec::button("open", "Open"))
            .on_click(
                "open",
                vec![FakeEffect::Reveal(vec![FakeAxSpec::button("done", "Done")])],
            ),
    );
    let mut crawl = CreateCrawl::new(url::Url::parse(HOME).unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.safety.profile = SafetyProfile::TestEnvironment;
    crawl.limits.interactions = 3;
    crawl.limits.duration_seconds = 30;
    let source = run_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(backend(script.clone()))
            .with_stores(stores.clone()),
    )
    .await
    .unwrap();
    let target = source
        .actions
        .iter()
        .rfind(|action| action.status == ActionStatus::Succeeded)
        .unwrap();
    let plan = ReplayPlan::load(&stores, source.run_id, target.id).await.unwrap();
    let browser = backend(script.stale("open").stale("done"));
    let report = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ReplayRunner::run(
            cfg(dir.path()),
            plan.clone(),
            ReplayMode::Verify,
            Some(browser.clone()),
            None,
        ),
    )
    .await
    .expect("persistent stale reconstruction must be bounded")
    .unwrap();
    assert!(!report.ok);
    assert!(
        matches!(
            report.steps.as_slice(),
            [step] if step.action == plan.steps[0].action.id
                && matches!(step.verdict, StepVerdict::Dropped { reason: "stale_epoch" })
        ),
        "{:#?}",
        report.steps
    );
    for context in browser.context_handles() {
        assert!(
            context.performed().is_empty(),
            "a stale replay must not execute an effect"
        );
    }
    assert_eq!(browser.open_contexts(), 0);
}
