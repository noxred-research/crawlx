//! Advisory host/domain/IP fairness in front of every leased attempt.
//!
//! The shared [`AdvisoryFrontierV1`] only narrows: a reservation is never permission to dispatch,
//! and robots, scope, live authorization, resolver pinning and the shared origin governor all
//! still run after it. Time is the run's injected clock, expressed as milliseconds since the plane
//! was built, so a replayed clock replays the same decisions.
//!
//! Scheduling here may reorder and delay work; it never changes who holds a row. A row of the
//! held batch whose queue the controller refuses stays leased to this worker, which waits for the
//! queue to become eligible ([`UrlPlaneRunner::pause_for_dispatch`]). The wait ends early on a
//! cancel or drain, is cut at every lease heartbeat period and at the run deadline so the lease,
//! the budget and the authorization are re-read, and never returns the row to `pending`. Only a
//! lease expiry, a drain hand-back or the failure paths release it.

use super::*;
use crawlx_scheduler::frontier::{
    AdvisoryFrontierV1, AdvisoryPartitionV1, DispatchCandidateV1, DispatchTicketV1, NarrowingV1, WaitHintV1,
};

/// How long to wait when the controller names no instant: a concurrency slot, the drain or a
/// closed origin refuses the attempt and only another event clears it.
const SLOT_POLL: Duration = Duration::from_millis(100);

/// Outcome of asking the controller for one attempt.
pub(super) enum Dispatch {
    /// No controller is attached: run as before.
    Unmetered,
    /// Reserved; hold until the attempt ends.
    Reserved(DispatchTicketV1),
    /// Refused for now. The row stays leased to this worker; ask again after this long.
    Wait(Duration),
}

impl UrlPlaneRunner {
    /// Share one advisory fairness controller between this run's workers.
    #[must_use]
    pub fn with_advisory_frontier(mut self, frontier: Arc<AdvisoryFrontierV1>) -> Self {
        self.advisory = Some(frontier);
        self
    }

    /// Injected-clock milliseconds since this plane started; never a wall-clock read.
    fn advisory_now_ms(&self) -> Result<u64, WorkerError> {
        let elapsed = self.deps.clock.now().signed_duration_since(self.started_at);
        u64::try_from(elapsed.num_milliseconds().max(0))
            .map_err(|_| WorkerError::Config("advisory clock overflow".into()))
    }

    /// Reserve this attempt, or say how long the held row must wait for a slot.
    ///
    /// # Errors
    /// Returns a rejected partition or clock.
    pub(super) async fn reserve_dispatch(&self, entry: &FrontierEntry) -> Result<Dispatch, WorkerError> {
        let Some(frontier) = &self.advisory else {
            return Ok(Dispatch::Unmetered);
        };
        // Pre-resolution: only the host and operator domain partitions exist; the checked IPs are
        // enforced by the shared governor at connection time.
        let partition = AdvisoryPartitionV1::checked(&entry.url, None, &[])
            .map_err(|error| WorkerError::Config(error.to_string()))?;
        let now = self.advisory_now_ms()?;
        let rank = (i64::from(entry.depth), entry.id);
        let candidate = DispatchCandidateV1::new(&partition, 0, rank, NarrowingV1::default());
        if let Some((_, ticket)) = frontier
            .reserve(now, std::slice::from_ref(&candidate))
            .map_err(|error| WorkerError::Config(error.to_string()))?
        {
            return Ok(Dispatch::Reserved(ticket));
        }
        let hint = frontier
            .wait_hint(now, &candidate)
            .map_err(|error| WorkerError::Config(error.to_string()))?;
        Ok(Dispatch::Wait(match hint {
            WaitHintV1::At(at) => Duration::from_millis(at.saturating_sub(now)).max(Duration::from_millis(1)),
            // no instant is known (a concurrency slot, the drain or a closed origin refuses it),
            // or another worker took the slot between the refusal and the hint: never spin
            _ => SLOT_POLL,
        }))
    }

    /// Wait out a refused attempt without releasing the row. One call sleeps at most one lease
    /// heartbeat period and never past the run deadline, then returns so the caller re-reads the
    /// lease, budget, authorization and stop state; a cancel or drain ends it at once.
    pub(super) async fn pause_for_dispatch(&self, wait: Duration, cancel: &CancellationToken) {
        let to_deadline = self
            .budget
            .lock()
            .deadline()
            .signed_duration_since(self.deps.clock.now())
            .to_std()
            .unwrap_or(Duration::ZERO);
        let slice = wait
            .min(lease_heartbeat_period(self.deps.leases.url_batch_ttl()))
            .min(to_deadline);
        let stopped = async {
            let drained = async {
                match &self.graceful_drain {
                    Some(drain) => drain.cancelled().await,
                    None => std::future::pending::<()>().await,
                }
            };
            let hard = async {
                match &self.hard_cancel {
                    Some(cancel) => cancel.cancelled().await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                () = cancel.cancelled() => {}
                () = drained => {}
                () = hard => {}
            }
        };
        tokio::select! {
            () = tokio::time::sleep(slice) => {}
            () = stopped => {}
        }
    }

    /// Release the reservation with the attempt's measured outcome (or as cancelled).
    pub(super) fn settle_dispatch(&self, entry: &FrontierEntry, ticket: DispatchTicketV1, ok: bool) {
        let Ok(now) = self.advisory_now_ms() else {
            return;
        };
        let settled = if ok {
            let (status, retry_after) = self
                .attempt_response(entry.id)
                .map_or((None, None), |(status, retry)| (Some(status), retry));
            ticket.complete(now, status, retry_after)
        } else {
            ticket.cancel(now)
        };
        if let Err(error) = settled {
            tracing::warn!(run = %self.run, error = %error, "advisory dispatch completion not recorded");
        }
    }
}
