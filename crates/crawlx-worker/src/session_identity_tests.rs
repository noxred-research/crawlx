#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crawlx_core::identity_profile::IdentityProfileV1;
use crawlx_core::repo::CrawlRun;
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, CreateCrawl};

async fn fixture(
    identity_profile: Option<Digest>,
) -> (tempfile::TempDir, Arc<RunContext>, SessionLease, Arc<Fetcher>) {
    let dir = tempfile::tempdir().unwrap();
    let now = chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(now));
    let memory = Arc::new(crawlx_storage::MemoryStore::with_clock(Arc::clone(&clock)));
    let stores = crate::Stores::over_memory(memory, dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = crawlx_core::config::CrawlMode::Static;
    crawl.fetch.identity_profile = identity_profile;
    let mut rotation = crawlx_core::orchestration::OrchestrationConfigV1::default();
    rotation.attempts.max_session_rotations = 1;
    crawl.orchestration = Some(rotation);
    let run = CrawlRun {
        id: crawlx_core::CrawlRunId::new(),
        tenant: stores.tenant,
        status: crawlx_core::counters::RunStatus::Running,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: crawlx_core::counters::PlaneCounters::default(),
        created_at: now,
        started_at: Some(now),
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    stores
        .runs
        .create_sessions(&crawlx_scheduler::RunPlanner::sessions(run.id, &crawl))
        .await
        .unwrap();
    let cfg = crate::WorkerConfig {
        artifacts_dir: dir.path().to_owned(),
        ..Default::default()
    };
    let mut rc = RunContext::build(
        &run,
        &cfg,
        stores,
        None,
        None,
        tokio_util::sync::CancellationToken::new(),
        None,
        None,
    )
    .await
    .unwrap();
    rc.clock = clock;
    let rc = Arc::new(rc);
    let lease = crawlx_scheduler::Scheduler::new(Arc::clone(&rc.stores.leases))
        .lease_in_run(rc.run, rc.worker, false)
        .await
        .unwrap()
        .unwrap();
    let (fetcher, _) = crate::run::build_fetcher(
        &crawl,
        run.id,
        run.seed,
        &cfg,
        rc.controls.clone(),
        None,
        Arc::clone(&rc.origin_governor),
    )
    .unwrap();
    (dir, rc, lease, fetcher)
}

fn binding(rc: &RunContext, lease: &SessionLease, build: Digest, policy: Digest) -> SessionBindingV1 {
    let digest = Digest::of("fixture/session", b"identity");
    // The run's approved route authority; production refuses any other egress identity.
    let egress = rc.egress.route_for(&rc.crawl).unwrap().egress_digest();
    let identity = SessionIdentityV1::new(
        rc.stores.tenant,
        &lease.session,
        digest,
        build,
        egress,
        policy,
        None,
    );
    SessionBindingV1::new(
        identity,
        lease.fencing_token,
        rc.clock.now() + chrono::Duration::minutes(10),
    )
}

#[tokio::test]
async fn coherent_session_binds_exactly_the_installed_profile_build_and_policy() {
    let profile = IdentityProfileV1::pinned_chromium();
    let installed = profile.digest().unwrap();
    let (_dir, rc, lease, fetcher) = fixture(Some(installed)).await;
    register_http_session(&rc, &lease, &fetcher).await.unwrap();

    register_bound_http_session(
        &rc,
        &lease,
        &fetcher,
        binding(&rc, &lease, profile.backend_build_digest(), installed),
    )
    .unwrap();
    let ordinary = Digest::of("fixture/session", b"ordinary-client");
    for (build, policy) in [
        (ordinary, ordinary),
        (profile.backend_build_digest(), ordinary),
        (ordinary, installed),
    ] {
        assert!(
            register_bound_http_session(&rc, &lease, &fetcher, binding(&rc, &lease, build, policy)).is_err(),
            "a binding that is not the exact coherent identity never falls back to ordinary transport"
        );
    }
}

#[tokio::test]
async fn uninstalled_profile_digest_never_registers_a_session() {
    let (_dir, rc, lease, fetcher) = fixture(Some(Digest::of("fixture/profile", b"unknown"))).await;
    assert!(register_http_session(&rc, &lease, &fetcher).await.is_err());
}

#[tokio::test]
async fn ordinary_run_keeps_ordinary_session_identity() {
    let (_dir, rc, lease, fetcher) = fixture(None).await;
    register_http_session(&rc, &lease, &fetcher).await.unwrap();
    let profile = IdentityProfileV1::pinned_chromium();
    // Without a selection no coherent-profile check applies to either binding.
    let ordinary = Digest::of("fixture/session", b"ordinary-client");
    register_bound_http_session(&rc, &lease, &fetcher, binding(&rc, &lease, ordinary, ordinary)).unwrap();
    register_bound_http_session(
        &rc,
        &lease,
        &fetcher,
        binding(
            &rc,
            &lease,
            profile.backend_build_digest(),
            profile.digest().unwrap(),
        ),
    )
    .unwrap();
}

fn retired(rc: &RunContext, lease: &SessionLease, build: Digest, policy: Digest) -> SessionBindingV1 {
    let mut retired = binding(rc, lease, build, policy);
    let limits = crawlx_core::session_binding::SessionLimits::default();
    retired.usage = limits.max_usage.saturating_sub(1);
    retired.record_use(true, rc.clock.now(), limits).unwrap();
    retired.finish_cleanup(true).unwrap();
    retired
}

#[tokio::test]
async fn coherent_identity_generation_is_never_replaced_but_ordinary_generation_is() {
    let profile = IdentityProfileV1::pinned_chromium();
    let installed = profile.digest().unwrap();
    let (_dir, rc, lease, _fetcher) = fixture(Some(installed)).await;
    let pinned = retired(&rc, &lease, profile.backend_build_digest(), installed);
    assert!(
        replace_retired_generation(&rc, &lease, &pinned).await.is_err(),
        "a selection bound to one generation fails closed instead of re-binding"
    );

    let (_dir, rc, lease, _fetcher) = fixture(None).await;
    let ordinary = Digest::of("fixture/session", b"ordinary-client");
    let next = replace_retired_generation(&rc, &lease, &retired(&rc, &lease, ordinary, ordinary))
        .await
        .unwrap();
    assert_eq!(next.generation, 2);
}
