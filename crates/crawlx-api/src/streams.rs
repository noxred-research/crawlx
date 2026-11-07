//! SSE connection caps: at most N open event streams per tenant and M per run.
//!
//! A [`StreamPermit`] is taken before the response is built and travels inside the stream
//! state, so the slot is released exactly when the client disconnects or the stream ends.
//! The counters sit behind a synchronous mutex that is never held across an `.await`.

use crate::errors::HttpError;
use crawlx_core::{CrawlRunId, TenantId};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Open-stream counters keyed by tenant and by run.
#[derive(Default)]
struct Counts {
    tenants: BTreeMap<TenantId, usize>,
    runs: BTreeMap<CrawlRunId, usize>,
}

/// Admission control for SSE connections.
pub(crate) struct StreamLimiter {
    per_tenant: usize,
    per_run: usize,
    counts: Arc<Mutex<Counts>>,
}

impl StreamLimiter {
    /// Limiter allowing `per_tenant` concurrent streams per tenant and `per_run` per run.
    pub(crate) fn new(per_tenant: usize, per_run: usize) -> Self {
        Self {
            per_tenant,
            per_run,
            counts: Arc::new(Mutex::new(Counts::default())),
        }
    }

    /// Reserve a slot for `tenant` watching `run`.
    ///
    /// # Errors
    /// `429 too_many_streams` when either cap is already reached.
    pub(crate) fn acquire(&self, tenant: TenantId, run: CrawlRunId) -> Result<StreamPermit, HttpError> {
        let mut counts = self.counts.lock();
        if counts.tenants.get(&tenant).copied().unwrap_or(0) >= self.per_tenant {
            return Err(HttpError::too_many_streams(self.per_tenant, "the tenant"));
        }
        if counts.runs.get(&run).copied().unwrap_or(0) >= self.per_run {
            return Err(HttpError::too_many_streams(self.per_run, "the run"));
        }
        *counts.tenants.entry(tenant).or_insert(0) += 1;
        *counts.runs.entry(run).or_insert(0) += 1;
        Ok(StreamPermit {
            tenant,
            run,
            counts: Arc::clone(&self.counts),
        })
    }
}

/// A reserved SSE slot; dropping it frees the slot.
pub(crate) struct StreamPermit {
    tenant: TenantId,
    run: CrawlRunId,
    counts: Arc<Mutex<Counts>>,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        let mut counts = self.counts.lock();
        if let Some(n) = counts.tenants.get_mut(&self.tenant) {
            *n -= 1;
            if *n == 0 {
                counts.tenants.remove(&self.tenant);
            }
        }
        if let Some(n) = counts.runs.get_mut(&self.run) {
            *n -= 1;
            if *n == 0 {
                counts.runs.remove(&self.run);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn caps_per_tenant_and_per_run_and_releases_on_drop() {
        let limiter = StreamLimiter::new(3, 2);
        let t = TenantId::default();
        let (r1, r2) = (CrawlRunId::default(), CrawlRunId::default());
        let a = limiter.acquire(t, r1).unwrap();
        let _b = limiter.acquire(t, r1).unwrap();
        let err = limiter.acquire(t, r1).err().unwrap();
        assert_eq!(err.code, "too_many_streams");
        assert_eq!(err.status, axum::http::StatusCode::TOO_MANY_REQUESTS);
        let _c = limiter.acquire(t, r2).unwrap();
        assert!(limiter.acquire(t, r2).is_err(), "tenant cap of 3 reached");
        drop(a);
        assert!(limiter.acquire(t, r1).is_ok(), "slot freed by drop");
    }
}
