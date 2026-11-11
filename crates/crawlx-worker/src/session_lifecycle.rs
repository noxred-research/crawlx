//! Named HTTP session registration under the existing scheduler lease and binding fence.

use crate::http_sessions::{
    HttpSessionAuthority, HttpSessionLimits, HttpSessionOwner, NamedHttpSessions, DEFAULT_HTTP_SESSION,
};
use crate::run::RunContext;
use crate::WorkerError;
use crawlx_core::hash::Digest;
use crawlx_core::session_binding::{BindingState, RetirementReason, SessionBindingV1, SessionIdentityV1};
use crawlx_core::{StoreError, TenantId};
use crawlx_fetch::{FetchError, Fetcher};
use crawlx_storage::SessionLease;
use parking_lot::Mutex;
use std::future::Future;
use std::sync::Arc;

/// One registered default session and its independent, live existing-lease verifier.
pub(crate) struct HttpSessionRegistration {
    pub(crate) manager: Arc<NamedHttpSessions>,
    pub(crate) authority: Arc<dyn HttpSessionAuthority>,
}

struct ExistingSessionAuthority {
    rc: Arc<RunContext>,
    lease: SessionLease,
    tenant: TenantId,
    current: Mutex<SessionBindingV1>,
}

fn unavailable() -> FetchError {
    FetchError::OriginAdmission(StoreError::Conflict("session_unavailable".into()))
}

impl ExistingSessionAuthority {
    async fn verify_metadata(&self, binding: &SessionBindingV1) -> Result<(), FetchError> {
        if self.rc.cancel.is_cancelled() {
            return Err(FetchError::AcquisitionCancelled);
        }
        if let Some(guard) = &self.rc.authorization {
            guard
                .check_now()
                .await
                .map_err(|_| FetchError::AcquisitionCancelled)?;
        }
        if *self.current.lock() != *binding || binding.expires_at <= self.rc.clock.now() {
            return Err(unavailable());
        }
        if let Some(pg) = &self.rc.stores.pg {
            let current = pg
                .load_session_binding(&self.lease, self.tenant)
                .await
                .map_err(FetchError::OriginAdmission)?;
            if current != *binding {
                return Err(unavailable());
            }
        } else {
            // Same holder check used by the local actor. This renews the scheduler
            // heartbeat, never the immutable binding or credential lifetime.
            self.rc
                .stores
                .leases
                .heartbeat(&self.lease)
                .await
                .map_err(FetchError::OriginAdmission)?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl HttpSessionAuthority for ExistingSessionAuthority {
    async fn verify(&self, binding: &SessionBindingV1) -> Result<(), FetchError> {
        self.verify_metadata(binding).await?;
        // Only the active sender may finish its already-persisted last-use reservation.
        if binding.state == BindingState::Leased
            || (binding.state == BindingState::Draining
                && binding.retirement == Some(RetirementReason::UsageLimit))
        {
            Ok(())
        } else {
            Err(unavailable())
        }
    }

    async fn record_use(
        &self,
        before: &SessionBindingV1,
        after: &SessionBindingV1,
    ) -> Result<(), FetchError> {
        self.verify_metadata(before).await?;
        if before.identity != after.identity
            || before.generation != after.generation
            || before.lease_fence != after.lease_fence
            || before.state_version.checked_add(1) != Some(after.state_version)
            || after.usage < before.usage
            || after.usage > before.usage.saturating_add(1)
            || after.expires_at > before.expires_at
            || after.lifetime_expires_at != before.lifetime_expires_at
        {
            return Err(unavailable());
        }
        if let Some(pg) = &self.rc.stores.pg {
            pg.update_session_binding(&self.lease, before.state_version, after)
                .await
                .map_err(FetchError::OriginAdmission)?;
        }
        let mut current = self.current.lock();
        if *current != *before {
            return Err(unavailable());
        }
        *current = after.clone();
        Ok(())
    }
}

/// Installed coherent identity profile for this run, as its backend build and identity-policy digests.
///
/// Absent selection keeps the ordinary client identity. A selected digest that is not the installed
/// pinned profile fails closed; it never degrades to ordinary transport.
fn coherent_profile(rc: &RunContext) -> Result<Option<(Digest, Digest)>, WorkerError> {
    let Some(selected) = rc.crawl.fetch.identity_profile else {
        return Ok(None);
    };
    let profile = crawlx_core::identity_profile::IdentityProfileV1::pinned_chromium();
    let installed = profile
        .digest()
        .map_err(|error| WorkerError::Config(error.to_string()))?;
    if installed != selected {
        return Err(WorkerError::Config(
            "fetch.identityProfile not installed".to_owned(),
        ));
    }
    Ok(Some((profile.backend_build_digest(), installed)))
}

/// Register a default HTTP session from an existing real coordinator lease.
/// The client starts only when its first admitted request arrives.
pub(crate) async fn register_http_session(
    rc: &Arc<RunContext>,
    lease: &SessionLease,
    fetcher: &Fetcher,
) -> Result<HttpSessionRegistration, WorkerError> {
    let metadata = rc.stores.runs.get_metadata(rc.run).await?;
    let coherent = coherent_profile(rc)?;
    let identity = SessionIdentityV1::new(
        metadata.tenant,
        &lease.session,
        Digest::of_value("crawlx/http-session-acquisition/v1", &rc.crawl.fetch)
            .map_err(|error| WorkerError::Config(error.to_string()))?,
        coherent.map_or_else(
            || {
                Digest::of(
                    "crawlx/http-session-client/v1",
                    env!("CARGO_PKG_VERSION").as_bytes(),
                )
            },
            |(build, _)| build,
        ),
        rc.egress.route_for(&rc.crawl)?.egress_digest(),
        coherent.map_or(metadata.config_digest, |(_, policy)| policy),
        None,
    );
    let deadline = rc.budget.lock().deadline();
    let expiry = rc
        .authorization
        .as_ref()
        .map_or(deadline, |guard| deadline.min(guard.record().valid_to));
    let binding = if let Some(pg) = &rc.stores.pg {
        pg.bind_session(lease, identity, expiry).await?
    } else {
        rc.stores.leases.heartbeat(lease).await?;
        SessionBindingV1::new(identity, lease.fencing_token, expiry)
    };
    register_bound_http_session(rc, lease, fetcher, binding)
}

/// Reuse exactly the browser generation and transport pin when the caller already holds one.
pub(crate) fn register_bound_http_session(
    rc: &Arc<RunContext>,
    lease: &SessionLease,
    fetcher: &Fetcher,
    binding: SessionBindingV1,
) -> Result<HttpSessionRegistration, WorkerError> {
    if binding.identity.run != rc.run
        || binding.identity.session != lease.session.id
        || binding.identity.principal != lease.session.role
        || binding.lease_fence != lease.fencing_token
        || binding.identity.tenant != rc.stores.tenant
    {
        return Err(unavailable().into());
    }
    let mut config = fetcher.config().clone();
    if rc.crawl.fetch.identity_profile.is_some() {
        // Exact trusted binding or nothing: a mismatched build/policy/generation never falls back.
        coherent_profile(rc)?;
        config.identity_profile = Some(
            crawlx_core::identity_profile::IdentitySelectionV1::new(
                binding.identity.clone(),
                binding.generation,
            )
            .map_err(|error| WorkerError::Config(error.to_string()))?,
        );
    }
    config.pool = rc.session_pool_binding(&binding, lease)?;
    config.shared_governor = Some(Arc::clone(fetcher.governor()));
    let manager = Arc::new(
        NamedHttpSessions::new(
            HttpSessionOwner::new(
                binding.identity.tenant,
                rc.run,
                binding.identity.principal.clone(),
            ),
            HttpSessionLimits::default(),
            Arc::clone(&rc.clock),
            Arc::clone(fetcher.governor()),
        )?
        .with_secret_registry(rc.captcha_secrets.clone())?,
    );
    manager.register(
        DEFAULT_HTTP_SESSION,
        binding.clone(),
        config,
        Arc::clone(&rc.delivery_authority.policy),
        Arc::clone(&rc.delivery_authority.resolver),
    )?;
    let authority = Arc::new(ExistingSessionAuthority {
        tenant: binding.identity.tenant,
        rc: Arc::clone(rc),
        lease: lease.clone(),
        current: Mutex::new(binding),
    });
    Ok(HttpSessionRegistration { manager, authority })
}

/// Replace only a proven drained anonymous generation within its admitted rotation budget.
/// A coherent identity selection is pinned to its exact generation, so a replacement is refused
/// (never re-bound or downgraded to ordinary transport) when `fetch.identityProfile` is selected.
pub(crate) async fn replace_retired_generation(
    rc: &Arc<RunContext>,
    lease: &SessionLease,
    retired: &SessionBindingV1,
) -> Result<SessionBindingV1, WorkerError> {
    let rotations = rc
        .crawl
        .orchestration
        .as_ref()
        .map_or(0, |policy| policy.attempts.max_session_rotations);
    if rc.cancel.is_cancelled()
        || rc.crawl.fetch.identity_profile.is_some()
        || rotations == 0
        || retired.generation > u64::from(rotations)
        || retired.identity.principal != crawlx_core::PrincipalId::anonymous()
        || retired.identity.profile.is_some()
        || rc.crawl.roles.iter().any(|role| {
            role.name == retired.identity.principal.0
                && (role.credential_ref.is_some() || role.login_plan.is_some())
        })
    {
        return Err(crate::SessionError::Binding(
            crawlx_core::session_binding::SessionBindingError::GenerationConflict,
        )
        .into());
    }
    if let Some(guard) = &rc.authorization {
        guard.check_now().await?;
    }
    let replacement = if let Some(pg) = &rc.stores.pg {
        let current = pg.load_session_binding(lease, retired.identity.tenant).await?;
        if current != *retired {
            return Err(StoreError::Conflict("session generation conflict".into()).into());
        }
        pg.replace_retired_session_binding(lease, &current, current.identity.clone(), current.expires_at)
            .await
            .map_err(|error| match error {
                crawlx_storage::session_binding::SessionBindingVerificationError::Store(error) => {
                    WorkerError::Store(error)
                }
                crawlx_storage::session_binding::SessionBindingVerificationError::Binding(error) => {
                    WorkerError::Session(crate::SessionError::Binding(error))
                }
                _ => WorkerError::Config("unsupported session replacement failure".into()),
            })?
    } else {
        rc.stores.leases.heartbeat(lease).await?;
        for status in [
            crawlx_core::counters::ActionStatus::Intended,
            crawlx_core::counters::ActionStatus::Unknown,
        ] {
            if rc
                .stores
                .journal
                .list(rc.run, Some(status))
                .await?
                .iter()
                .any(|action| action.session == lease.session.id)
            {
                return Err(StoreError::Conflict("session generation has unresolved writes".into()).into());
            }
        }
        retired
            .replace(retired.identity.clone(), true, retired.expires_at)
            .map_err(crate::SessionError::from)?
    };
    rc.release_session_pool_binding(retired)?;
    rc.stores
        .events
        .append(
            rc.run,
            "session.replaced",
            serde_json::json!({
                "session_id": lease.session.id,
                "previous_generation": retired.generation,
                "generation": replacement.generation,
                "reason": retired.retirement,
            }),
        )
        .await?;
    Ok(replacement)
}

pub(crate) fn is_binding_retirement(error: &WorkerError) -> bool {
    let mut cause = match error {
        WorkerError::Session(cause) => cause,
        _ => return false,
    };
    while let crate::SessionError::ActorStopped(source) = cause {
        cause = source.as_ref();
    }
    matches!(
        cause,
        crate::SessionError::Binding(
            crawlx_core::session_binding::SessionBindingError::Draining { .. }
                | crawlx_core::session_binding::SessionBindingError::Retired { .. }
        )
    )
}

/// Give local static execution the same real coordinator fence as leased execution.
pub(crate) fn run_local_http_plane<'a>(
    rc: &'a Arc<RunContext>,
    plane: &'a mut crate::url_plane::UrlPlaneRunner,
    fetcher: &'a Fetcher,
    cancel: &'a tokio_util::sync::CancellationToken,
) -> impl Future<Output = Result<crate::url_plane::UrlPlaneOutcome, WorkerError>> + Send + 'a {
    // Construct the coordinator state outside the orchestration poll frame.
    // Boxing at the call site retains its large temporary while polling URL work.
    Box::pin(run_local_http_plane_inner(rc, plane, fetcher, cancel))
}

async fn run_local_http_plane_inner(
    rc: &Arc<RunContext>,
    plane: &mut crate::url_plane::UrlPlaneRunner,
    fetcher: &Fetcher,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<crate::url_plane::UrlPlaneOutcome, WorkerError> {
    let mut session = crawlx_scheduler::RunSlot {
        role_index: 0,
        role: crawlx_core::PrincipalId::anonymous(),
        run_index: 1,
        schedule_slot: 0,
    }
    .into_session(rc.run);
    session.kind = crawlx_core::repo::SessionKind::HttpCoordinator;
    rc.stores
        .runs
        .create_sessions(std::slice::from_ref(&session))
        .await?;
    let scheduler = crawlx_scheduler::Scheduler::new(Arc::clone(&rc.stores.leases));
    let lease = scheduler
        .lease_in_run(rc.run, rc.worker, false)
        .await?
        .ok_or_else(|| StoreError::Conflict("HTTP coordinator session_unavailable".into()))?;
    if lease.session.id != session.id {
        return Err(StoreError::Conflict("HTTP coordinator session collision".into()).into());
    }
    let stop = tokio_util::sync::CancellationToken::new();
    let _stop_on_drop = stop.clone().drop_guard();
    let heartbeat = scheduler.keep_alive(lease.clone(), crawlx_scheduler::HEARTBEAT_INTERVAL, stop.clone());
    let result = async {
        // Keep coordinator custody for facade scrapes without binding their stateless transport.
        if rc.crawl.scrape.is_none() {
            let registration = register_http_session(rc, &lease, fetcher).await?;
            plane.set_http_sessions(registration.manager, registration.authority);
        }
        let producer = rc.stores.session_producer(rc.run, &lease);
        let outcome = crawlx_core::custody::with_producer(
            producer.clone(),
            crate::custody_renewal::with_custody_renewal(
                rc.stores.pg_secret_authority.clone(),
                producer,
                Box::pin(plane.run(cancel)),
            ),
        )
        .await?;
        Ok::<_, WorkerError>(outcome)
    }
    .await;
    stop.cancel();
    let heartbeat = heartbeat
        .await
        .map_err(WorkerError::SessionHeartbeatTask)
        .and_then(|result| result.map_err(WorkerError::from));
    let status = if result.is_err() {
        crawlx_core::repo::SessionStatus::Failed
    } else if cancel.is_cancelled() {
        crawlx_core::repo::SessionStatus::Recovering
    } else {
        crawlx_core::repo::SessionStatus::Completed
    };
    let release = scheduler.release(&lease, status).await.map_err(WorkerError::from);
    crate::replay::finish_replay(result, heartbeat, release)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::repo::CrawlRun;
    use crawlx_core::time::ManualClock;
    use crawlx_core::{Clock, CreateCrawl, PrincipalId};

    async fn fixture() -> (tempfile::TempDir, Arc<RunContext>, SessionLease, SessionBindingV1) {
        let dir = tempfile::tempdir().unwrap();
        let now = chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap();
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(now));
        let memory = Arc::new(crawlx_storage::MemoryStore::with_clock(Arc::clone(&clock)));
        let stores = crate::Stores::over_memory(memory, dir.path()).await.unwrap();
        let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
        crawl.mode = crawlx_core::config::CrawlMode::Static;
        let mut policy = crawlx_core::orchestration::OrchestrationConfigV1::default();
        policy.attempts.max_session_rotations = 1;
        crawl.orchestration = Some(policy);
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
        let digest = Digest::of("fixture/session", b"same-identity");
        let identity = SessionIdentityV1::new(
            rc.stores.tenant,
            &lease.session,
            digest,
            digest,
            digest,
            digest,
            None,
        );
        let mut retired =
            SessionBindingV1::new(identity, lease.fencing_token, now + chrono::Duration::minutes(10));
        let limits = crawlx_core::session_binding::SessionLimits::default();
        retired.usage = limits.max_usage.saturating_sub(1);
        retired.record_use(true, now, limits).unwrap();
        retired.finish_cleanup(true).unwrap();
        (dir, rc, lease, retired)
    }

    #[tokio::test]
    async fn explicit_replacement_preserves_identity_expiry_and_finite_rotation_budget() {
        let (_dir, rc, lease, retired) = fixture().await;
        let next = replace_retired_generation(&rc, &lease, &retired).await.unwrap();
        assert_eq!(next.generation, 2);
        assert_eq!(next.identity, retired.identity);
        assert_eq!(next.expires_at, retired.expires_at);
        let events = rc.stores.events.list_after(rc.run, 0, 64).await.unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "session.replaced")
                .count(),
            1
        );
        let mut exhausted = next;
        exhausted.begin_drain(RetirementReason::UsageLimit).unwrap();
        exhausted.finish_cleanup(true).unwrap();
        assert!(replace_retired_generation(&rc, &lease, &exhausted).await.is_err());
        let mut foreign = retired;
        foreign.identity.principal = PrincipalId("reader".into());
        assert!(replace_retired_generation(&rc, &lease, &foreign).await.is_err());
    }

    #[test]
    fn typed_retirement_survives_actor_error_wrapping_without_matching_unrelated_failures() {
        let error = WorkerError::Session(crate::SessionError::ActorStopped(Arc::new(
            crate::SessionError::Binding(crawlx_core::session_binding::SessionBindingError::Draining {
                reason: RetirementReason::UsageLimit,
            }),
        )));
        assert!(is_binding_retirement(&error));
        assert!(!is_binding_retirement(&WorkerError::Session(
            crate::SessionError::ActorGone
        )));
    }
}

#[cfg(test)]
#[path = "session_identity_tests.rs"]
mod identity_tests;
