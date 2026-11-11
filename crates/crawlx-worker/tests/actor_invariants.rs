//! Session Actor invariants over `FakeBackend`: one writer per context
//! under interleaved senders, a mailbox that parks senders instead of growing, and a
//! cancellation that hands every browser permit and context back.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{proposal_for, rig, Rig};
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, Role};
use crawlx_core::counters::{PlaneCounters, RunStatus};
use crawlx_core::identity::ActionKind;
use crawlx_core::observation::{DomSelector, QuiescencePolicy};
use crawlx_core::repo::{CrawlRun, StateRepo};
use crawlx_core::{ActionId, Clock, CrawlRunId, CreateCrawl, SafetyProfile, SystemClock};
use crawlx_observe::spec;
use crawlx_safety::Adjudication;
use crawlx_scheduler::{CheckpointReason, RunPlanner, Scheduler};
use crawlx_worker::run::run_session;
use crawlx_worker::{DriverConfig, RunContext, SessionError, StateAnalyzer, Stores, WorkerConfig};
use futures::future::join_all;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

fn two_page_site() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .node(FakeAxSpec::link("about", "About", "/about"))
                .on_click("about", vec![FakeEffect::Navigate("/about".into())]),
        )
        .page(
            FakePage::new("https://example.test/about")
                .title("About")
                .node(FakeAxSpec::link("home", "Home", "/"))
                .on_click("home", vec![FakeEffect::Navigate("/".into())]),
        )
}

// ---- 1. single writer under interleaved senders ---------------------------------------

/// Commands per property case, a million-message contention workload.
const COMMANDS: usize = 1_000_000;
/// Concurrent senders sharing one actor handle.
const SENDERS: usize = 8;

/// A mailbox command as a sender issues it (`Shutdown` excluded: it ends the actor).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cmd {
    Observe,
    StorageDigest,
    Revalidate,
    ResolveSelector,
    NavigateHome,
    NavigateAbout,
    Execute,
    Checkpoint,
    Reconcile,
}

fn cmd() -> impl Strategy<Value = Cmd> {
    prop_oneof![
        40 => Just(Cmd::Observe),
        20 => Just(Cmd::StorageDigest),
        12 => Just(Cmd::Revalidate),
        8 => Just(Cmd::ResolveSelector),
        5 => Just(Cmd::NavigateHome),
        5 => Just(Cmd::NavigateAbout),
        6 => Just(Cmd::Execute),
        2 => Just(Cmd::Checkpoint),
        2 => Just(Cmd::Reconcile),
    ]
}

/// The rig plus a lock serialising state analysis across senders.
struct Shared {
    rig: Rig,
    analysis: tokio::sync::Mutex<()>,
}

impl std::ops::Deref for Shared {
    type Target = Rig;
    fn deref(&self) -> &Rig {
        &self.rig
    }
}

/// Replies one sender collected.
#[derive(Default, Clone, Copy, Debug)]
struct Tally {
    /// Commands the actor answered (`Ok` or any error other than `ActorGone`).
    replies: usize,
    /// Commands that came back `Ok`.
    ok: usize,
}

impl Tally {
    fn note<T>(&mut self, c: Cmd, res: &Result<T, SessionError>) {
        assert!(
            !matches!(res, Err(SessionError::ActorGone)),
            "the actor went away under {c:?}"
        );
        self.replies += 1;
        self.ok += usize::from(res.is_ok());
    }
}

/// One sender: issues `cmds` in order over the shared handle and tallies the replies.
async fn sender(r: Arc<Shared>, cmds: Vec<Cmd>) -> Tally {
    let handle = r.handle.clone();
    let analyzer = StateAnalyzer::new(
        r.run,
        r.session,
        r.rc.clusters.clone(),
        r.stores.artifacts.clone(),
        r.rc.clock.clone(),
        r.rc.crawl.capture.clone(),
        (&r.rc.controls, &r.rc.captcha_secrets),
    );
    let seed_origin = r.rc.seed_origin();
    let profile = r.rc.crawl.safety.profile;
    let mut t = Tally::default();
    let mut last = handle.observe(spec::cheap()).await.expect("initial observation");
    for c in cmds {
        match c {
            Cmd::Observe => {
                let res = handle.observe(spec::cheap()).await;
                if let Ok(b) = &res {
                    last = Arc::clone(b);
                }
                t.note(c, &res);
            }
            Cmd::StorageDigest => t.note(c, &handle.storage_digest().await),
            Cmd::Revalidate => match last.ax.nodes.first() {
                Some(n) => t.note(c, &handle.revalidate(n.locator.clone()).await),
                None => t.note(c, &handle.observe(spec::cheap()).await),
            },
            Cmd::ResolveSelector => t.note(c, &handle.resolve_selector(DomSelector::css("a")).await),
            Cmd::NavigateHome => t.note(
                c,
                &handle
                    .navigate(crawlx_core::request::RequestEnvelopeV1::get(
                        common::canonical("https://example.test/"),
                        0,
                        None,
                    ))
                    .await,
            ),
            Cmd::NavigateAbout => t.note(
                c,
                &handle
                    .navigate(crawlx_core::request::RequestEnvelopeV1::get(
                        common::canonical("https://example.test/about"),
                        0,
                        None,
                    ))
                    .await,
            ),
            Cmd::Execute => {
                let bundle = match handle.observe(spec::after_action()).await {
                    Ok(b) => b,
                    Err(e) => {
                        t.note::<()>(c, &Err(e));
                        continue;
                    }
                };
                // `attach` (in-memory index) and `put_state` (store) are two steps; senders
                // serialise them so one sender cannot see a cluster another has not stored yet
                let state = {
                    let _serial = r.analysis.lock().await;
                    let state = analyzer.analyze(&bundle).await.state;
                    r.store.put_state(&state).await.unwrap();
                    state
                };
                let name = if bundle.url.url.path() == "/about" {
                    "Home"
                } else {
                    "About"
                };
                let (p, sc) = proposal_for(
                    &bundle,
                    name,
                    ActionKind::Click,
                    state.cluster,
                    &r.principal,
                    &seed_origin,
                    profile,
                );
                let admitted = match r.rc.kernel.adjudicate(p, &sc) {
                    Adjudication::Allow(a) => a,
                    other => panic!("expected allow, got {:?}", other.verdict()),
                };
                t.note(c, &handle.execute(admitted, QuiescencePolicy::default()).await);
            }
            Cmd::Checkpoint => t.note(c, &handle.checkpoint(CheckpointReason::PreMutation).await),
            Cmd::Reconcile => t.note(c, &handle.reconcile(ActionId::new()).await),
        }
    }
    t
}

/// What one case observed: the tally, clicks the fake performed, the per-context and the
/// backend-wide in-flight high-water marks.
#[derive(Debug)]
struct Observed {
    tally: Tally,
    performed: usize,
    per_context: usize,
    backend: usize,
}

async fn drive(cmds: Vec<Cmd>) -> Observed {
    let r = Arc::new(Shared {
        rig: rig(two_page_site(), SafetyProfile::ReadOnly).await,
        analysis: tokio::sync::Mutex::new(()),
    });
    let per = cmds.len().div_ceil(SENDERS);
    let mut set = JoinSet::new();
    for chunk in cmds.chunks(per) {
        set.spawn(sender(Arc::clone(&r), chunk.to_vec()));
    }
    let mut tally = Tally::default();
    while let Some(t) = set.join_next().await {
        let t = t.unwrap();
        tally.replies += t.replies;
        tally.ok += t.ok;
    }
    let handles = r.backend.context_handles();
    let per_context = handles.iter().map(|h| h.max_in_flight()).max().unwrap_or(0);
    let performed = handles.iter().map(|h| h.performed().len()).sum();
    r.handle
        .shutdown(crawlx_worker::ShutdownReason::Graceful)
        .await
        .unwrap();
    Observed {
        tally,
        performed,
        per_context,
        backend: r.backend.max_in_flight(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1,
        max_shrink_iters: 0,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. ProptestConfig::default()
    })]

    /// One million commands from eight interleaved
    /// senders over one actor; the context's in-flight gauge never sees two entries at once
    /// and every command receives a reply.
    #[test]
    fn no_two_performs_overlap_across_1e6_interleaved_commands(
        cmds in proptest::collection::vec(cmd(), COMMANDS)
    ) {
        // Keep all million commands and eight interleaved senders, but advance browser
        // admission's 500 ms floor virtually instead of spending hours in real time.
        let rt = tokio::runtime::Builder::new_current_thread()
            .start_paused(true)
            .enable_all()
            .build()
            .unwrap();
        let o = rt.block_on(drive(cmds));
        eprintln!("{o:?}");
        prop_assert_eq!(o.tally.replies, COMMANDS, "every command is answered");
        // most commands succeed (stale epochs, unknown ids and parked states are the rest)
        prop_assert!(o.tally.ok * 10 >= COMMANDS * 8, "too few Ok replies: {:?}", o.tally);
        prop_assert!(o.performed > 0, "no click reached the browser");
        prop_assert_eq!(o.per_context, 1, "two context entries overlapped");
        prop_assert_eq!(o.backend, 1, "two entries overlapped across the backend");
    }
}

// ---- 2. bounded mailbox parks the sender -------------------------------------------------

/// Backpressure: with the actor parked on a held `perform`, exactly `mailbox` sends
/// are accepted, the next one stays `Pending`, the bound never grows, and releasing the step
/// completes every send.
#[tokio::test]
async fn mailbox_backpressure_blocks_sender_without_growth() {
    let r = rig(two_page_site(), SafetyProfile::ReadOnly).await;
    let bound = r.handle.mailbox_bound();
    assert_eq!(bound, crawlx_worker::actor::MAILBOX);
    assert_eq!(r.handle.mailbox_capacity(), bound);

    // an admitted click, then park the actor inside the browser step
    let bundle = r.handle.observe(spec::after_action()).await.unwrap();
    let state = StateAnalyzer::new(
        r.run,
        r.session,
        r.rc.clusters.clone(),
        r.stores.artifacts.clone(),
        r.rc.clock.clone(),
        r.rc.crawl.capture.clone(),
        (&r.rc.controls, &r.rc.captcha_secrets),
    )
    .analyze(&bundle)
    .await
    .state;
    r.store.put_state(&state).await.unwrap();
    let (p, c) = r.proposal(&bundle, "About", state.cluster);
    let admitted = r.admit(p, &c);
    r.backend.hold_performs();
    let parked = {
        let handle = r.handle.clone();
        tokio::spawn(async move { handle.execute(admitted, QuiescencePolicy::default()).await })
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while r.backend.performs_held() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the actor parks on the held perform");

    // fill the mailbox: each send is accepted on its first poll, then waits for its reply
    let mut filling = Vec::with_capacity(bound);
    for i in 0..bound {
        let mut fut = Box::pin(r.handle.storage_digest());
        assert!(futures::poll!(&mut fut).is_pending());
        assert_eq!(r.handle.mailbox_capacity(), bound - i - 1);
        assert_eq!(r.handle.mailbox_bound(), bound, "the bound never grows");
        filling.push(fut);
    }
    assert_eq!(r.handle.mailbox_capacity(), 0);

    // the next sender is parked, not buffered
    let mut extra = Box::pin(r.handle.storage_digest());
    assert!(futures::poll!(&mut extra).is_pending());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut extra)
            .await
            .is_err(),
        "a full mailbox parks the sender"
    );
    assert_eq!(r.handle.mailbox_capacity(), 0);
    assert_eq!(r.handle.mailbox_bound(), bound);
    assert_eq!(r.backend.performs_held(), 1, "the actor is still parked");

    // release the browser step: the actor drains the mailbox and every send completes
    r.backend.release_performs();
    let out = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .expect("drained in time")
        .unwrap()
        .unwrap();
    assert_eq!(out.status, crawlx_core::counters::ActionStatus::Succeeded);
    let digests = tokio::time::timeout(Duration::from_secs(5), join_all(filling))
        .await
        .expect("drained in time");
    assert!(digests.iter().all(Result::is_ok), "{digests:?}");
    extra.await.unwrap();
    assert_eq!(r.handle.mailbox_capacity(), bound);
    assert_eq!(r.handle.mailbox_bound(), bound);
    assert_eq!(r.backend.max_in_flight(), 1);
}

// ---- 3. cancellation returns permits and closes contexts ------------------------------

/// Buttons on the long page; each is a distinct action-context key, so a session has this
/// many clicks of work before it could exhaust (far more than the test runs before cancel).
const LONG_PAGE_BUTTONS: usize = 600;

/// A page with hundreds of untried disclosure controls (admitted under `read_only`), so no
/// session exhausts before cancellation.
fn long_site() -> FakeScript {
    let mut page = FakePage::new("https://example.test/").title("Long");
    for i in 0..LONG_PAGE_BUTTONS {
        // Identity normalization strips digits: "Show 0" and "Show 1" would collapse.
        // Alphabetic names and durable attributes keep every disclosure distinct.
        let key = format!(
            "b{}{}",
            char::from(b'a' + u8::try_from(i / 26).unwrap()),
            char::from(b'a' + u8::try_from(i % 26).unwrap())
        );
        page = page
            .node(
                FakeAxSpec::button(&key, format!("Show {key}"))
                    .attr("data-testid", &key)
                    .attr("aria-expanded", "false"),
            )
            .on_click(&key, vec![FakeEffect::Nothing]);
    }
    FakeScript::new().page(page)
}

/// Cancellation test: three sessions of one run explore concurrently, each holding
/// a browser permit and an open context; after `cancel()` every permit is back in the pool
/// and every fake context is closed within 5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_releases_permits_and_closes_contexts_within_5s() {
    const SESSIONS: usize = 3;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(crawlx_storage::MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.limits.interactions = 100_000;
    crawl.limits.states = 100_000;
    crawl.roles = (0..SESSIONS)
        .map(|i| Role {
            name: format!("role{i}"),
            credential_ref: None,
            login_plan: None,
            replica_base_url: None,
        })
        .collect();
    // This standalone fixture needs the same explicit, verified robots override as rig_core.
    crawl.safety.respect_robots_txt = false;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.normalize().unwrap();
    let mut record = common::authorization::verified_record(&crawl, stores.tenant);
    record.robots_override_acknowledged = true;
    let stores =
        stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: stores.tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: SystemClock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    stores
        .runs
        .create_sessions(&RunPlanner::sessions(run.id, &crawl))
        .await
        .unwrap();
    stores
        .runs
        .set_status(run.id, RunStatus::Running, None)
        .await
        .unwrap();
    let run = stores.runs.get(run.id).await.unwrap();

    let fake = Arc::new(
        FakeBackend::builder()
            .script(long_site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let cancel = CancellationToken::new();
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        contexts_per_browser: 4,
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let guard = common::authorization::admit(&stores, &run, &cfg).await;
    let rc = Arc::new(
        RunContext::build(
            &run,
            &cfg,
            stores.clone(),
            Some(fake.clone()),
            None,
            cancel.clone(),
            None,
            Some(guard),
        )
        .await
        .unwrap(),
    );
    let scheduler = Scheduler::new(store.clone());
    let worker = cfg.worker_id;
    let mut sessions = JoinSet::new();
    // Sessions start one after another, as leases are granted in practice: a session's first
    // state must be stored before the next one attaches to the same cluster (the in-memory
    // cluster index and the store are updated in two steps).
    for n in 1..=SESSIONS {
        let lease = scheduler
            .lease_in_run(run.id, worker, true)
            .await
            .unwrap()
            .expect("a parallel-role lease");
        sessions.spawn(run_session(
            Arc::clone(&rc),
            scheduler.clone(),
            lease,
            std::future::ready(Ok(Vec::new())),
            DriverConfig::default(),
            None,
        ));
        // the session holds a permit and an open context and is acting on it
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(end) = sessions.try_join_next() {
                    panic!("a session ended before cancellation: {end:?}");
                }
                let handles = fake.context_handles();
                if handles.len() == n && handles.iter().all(|h| !h.performed().is_empty()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "session {n} is exploring: contexts={} performed={:?}",
                fake.context_handles().len(),
                fake.context_handles()
                    .iter()
                    .map(|h| h.performed().len())
                    .collect::<Vec<_>>()
            )
        });
    }
    let capacity = rc.pool.context_capacity();
    assert_eq!(capacity, cfg.contexts_per_browser, "one shared fake process");
    assert_eq!(rc.pool.available_contexts(), capacity - SESSIONS);
    assert_eq!(fake.open_contexts(), SESSIONS);

    cancel.cancel();
    let ends = tokio::time::timeout(Duration::from_secs(5), async {
        let mut ends = Vec::new();
        while let Some(end) = sessions.join_next().await {
            ends.push(end.unwrap());
        }
        ends
    })
    .await
    .expect("every session ended within 5 s of cancellation");
    assert_eq!(ends.len(), SESSIONS);
    assert!(
        ends.iter()
            .all(|e| e.terminal == crawlx_core::counters::TerminalReason::Cancelled),
        "{ends:?}"
    );
    assert_eq!(
        rc.pool.available_contexts(),
        capacity,
        "every browser permit is back"
    );
    assert_eq!(fake.open_contexts(), 0, "every context is closed");
    assert!(fake.context_handles().iter().all(|h| h.closed()));
    assert_eq!(
        rc.pool.context_capacity(),
        capacity,
        "the pool did not grow or shrink"
    );
}
