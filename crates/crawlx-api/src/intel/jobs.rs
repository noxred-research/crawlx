//! Background jobs of the LLM products: [`JobRegistry`] runs a job's future on a tracked task
//! with a per-job cancellation token (`DELETE /agent/{id}` cancels it, server shutdown drains
//! it), and the helpers here admit job rows and write their terminal state.

use crate::errors::ApiResult;
use crate::intel::common::JOB_TTL_HOURS;
use crate::state::AppState;
use chrono::Duration as ChronoDuration;
use crawlx_core::TenantId;
use crawlx_storage::{JobKind, JobPatch, JobRecord, JobStatus};
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use uuid::Uuid;

/// Tracked background tasks keyed by job id.
#[derive(Debug)]
pub struct JobRegistry {
    tracker: TaskTracker,
    tokens: Mutex<BTreeMap<Uuid, CancellationToken>>,
    shutdown: CancellationToken,
}

impl JobRegistry {
    /// A registry whose jobs are cancelled when `shutdown` is.
    #[must_use]
    pub fn new(shutdown: CancellationToken) -> Self {
        Self {
            tracker: TaskTracker::new(),
            tokens: Mutex::new(BTreeMap::new()),
            shutdown,
        }
    }

    /// Run `work` for job `id` on a tracked task. `work` receives the job's cancellation token
    /// (cancelled by [`Self::cancel`] and by server shutdown) and must finish promptly once it
    /// fires. The id is deregistered when `work` returns.
    pub fn spawn<F, Fut>(self: &Arc<Self>, id: Uuid, work: F)
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let token = self.shutdown.child_token();
        self.tokens.lock().insert(id, token.clone());
        let registry = Arc::clone(self);
        let tenant = crawlx_storage::tenant::current();
        self.tracker.spawn(async move {
            match tenant {
                Some(tenant) => crawlx_storage::tenant::scope(tenant, work(token)).await,
                None => work(token).await,
            }
            registry.tokens.lock().remove(&id);
        });
    }

    /// Cancel job `id`; `false` when it is not running here.
    #[must_use]
    pub fn cancel(&self, id: Uuid) -> bool {
        match self.tokens.lock().get(&id) {
            Some(t) => {
                t.cancel();
                true
            }
            None => false,
        }
    }

    /// Whether job `id` is running on this process.
    #[must_use]
    pub fn is_running(&self, id: Uuid) -> bool {
        self.tokens.lock().contains_key(&id)
    }

    /// Stop accepting jobs and wait for the running ones (call after cancelling `shutdown`).
    pub async fn drain(&self) {
        self.tracker.close();
        self.tracker.wait().await;
    }
}

/// Insert a `processing` job row for `tenant`.
///
/// # Errors
/// Storage failures as [`crate::errors::HttpError`].
pub async fn admit(
    state: &AppState,
    tenant: TenantId,
    kind: JobKind,
    request: Value,
    thread_id: Option<Uuid>,
) -> ApiResult<JobRecord> {
    let now = state.clock.now();
    let job = JobRecord {
        id: Uuid::now_v7(),
        tenant,
        kind,
        status: JobStatus::Processing,
        request,
        result: None,
        error: None,
        stop_reason: None,
        tokens_used: 0,
        credits_used: 0,
        thread_id,
        created_at: now,
        updated_at: now,
        finished_at: None,
        expires_at: now + ChronoDuration::hours(JOB_TTL_HOURS),
    };
    state.repos.intel.job_insert(&job).await?;
    Ok(job)
}

/// How a job ended.
#[derive(Clone, PartialEq, Debug)]
pub struct Outcome {
    /// Terminal status.
    pub status: JobStatus,
    /// Result data of a completed job.
    pub result: Option<Value>,
    /// Failure text of a failed job.
    pub error: Option<String>,
    /// Stop reason when the job did not simply finish.
    pub stop_reason: Option<String>,
    /// Absolute LLM tokens.
    pub tokens_used: u64,
    /// Absolute credits.
    pub credits_used: u64,
}

/// Write `outcome` as the job's terminal state (a job already cancelled stays cancelled).
/// Returns the stored row, `None` when the job no longer exists.
pub async fn finish(state: &AppState, tenant: TenantId, id: Uuid, outcome: Outcome) -> Option<JobRecord> {
    let now = state.clock.now();
    let patch = JobPatch {
        at: now,
        status: Some(outcome.status),
        result: outcome.result,
        error: outcome.error,
        stop_reason: outcome.stop_reason,
        tokens_used: Some(outcome.tokens_used),
        credits_used: Some(outcome.credits_used),
        finished_at: Some(now),
    };
    match state.repos.intel.job_update(tenant, id, &patch).await {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(error = %e, job = %id, "job terminal write failed");
            None
        }
    }
}

/// Record progress counters of a running job.
pub async fn progress(state: &AppState, tenant: TenantId, id: Uuid, tokens_used: u64, credits_used: u64) {
    let mut patch = JobPatch::at(state.clock.now());
    patch.tokens_used = Some(tokens_used);
    patch.credits_used = Some(credits_used);
    if let Err(e) = state.repos.intel.job_update(tenant, id, &patch).await {
        tracing::warn!(error = %e, job = %id, "job progress write failed");
    }
}
