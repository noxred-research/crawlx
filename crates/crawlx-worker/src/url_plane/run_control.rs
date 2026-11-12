//! Run-level stop criteria and the terminal detail of a URL-plane run.
//!
//! `limits.urls` and `limits.durationSeconds` are the run [`Budget`]'s. The criteria here sit
//! beside it: `limits.items` (pages kept), `limits.errors` (fetches that failed), `limits.idleSeconds`
//! (no newly kept page for that long) and `limits.diskPressurePermille` (the artifact spool is that
//! full). They are evaluated in that order between batches, after the frontier and the budget: the
//! first one that holds ends the run with its own [`TerminalDetail`], the plane seals its
//! producers and leases nothing else. The count criteria also cap each lease so a batch cannot
//! overshoot them.
//!
//! A run whose frontier drains with no page kept is told apart by what the failed rows say
//! ([`UrlPlaneRunner::drained_detail`]); a run that kept at least one page has no detail.
//!
//! Counts come from the run's own counters and the idle clock from the injected run clock, so a
//! manual clock replays the same stops.

use super::*;

/// Progress the idle criterion measures: the newest kept-page count and when it last grew.
pub(super) struct IdleClock {
    kept: u64,
    since: crawlx_core::Timestamp,
}

impl IdleClock {
    /// Start measuring at `now` with `kept` pages already kept.
    pub(super) const fn new(kept: u64, now: crawlx_core::Timestamp) -> Self {
        Self { kept, since: now }
    }

    fn observe(&mut self, kept: u64, now: crawlx_core::Timestamp) {
        if kept > self.kept {
            self.kept = kept;
            self.since = now;
        }
    }
}

/// Rows a failed fetch leaves behind that mean the retries ran out: a transient transport
/// failure, a throttle or server error that never cleared, or the effect budget of the row.
fn is_transient_failure(reason: &str) -> bool {
    match reason {
        "effect_budget_exhausted" | "transport" | "timeout" | "dns" => true,
        other => other
            .strip_prefix("http_")
            .and_then(|code| code.parse::<u16>().ok())
            .is_some_and(|code| code == 429 || (500..600).contains(&code)),
    }
}

impl UrlPlaneRunner {
    /// Pages this run has kept so far.
    pub(super) fn kept_pages(&self) -> u64 {
        self.counters.snapshot().urls.succeeded
    }

    /// The detail of the first run-level criterion that holds, if any. The idle clock advances
    /// only when `limits.idleSeconds` is set.
    pub(super) fn stop_criterion(&self, idle: &mut IdleClock) -> Option<TerminalDetail> {
        let limits = &self.crawl.limits;
        let urls = self.counters.snapshot().urls;
        if limits.items > 0 && urls.succeeded >= u64::from(limits.items) {
            return Some(TerminalDetail::ItemsLimit);
        }
        if limits.errors > 0 && urls.failed.saturating_add(urls.unreachable) >= u64::from(limits.errors) {
            return Some(TerminalDetail::ErrorsLimit);
        }
        if limits.disk_pressure_permille > 0
            && self
                .deps
                .artifacts
                .spool_pressure_permille()
                .is_some_and(|permille| permille >= limits.disk_pressure_permille)
        {
            return Some(TerminalDetail::DiskPressure);
        }
        if limits.idle_seconds > 0 {
            let now = self.deps.clock.now();
            idle.observe(urls.succeeded, now);
            if now.signed_duration_since(idle.since)
                >= chrono::Duration::seconds(i64::from(limits.idle_seconds))
            {
                return Some(TerminalDetail::IdleTimeout);
            }
        }
        None
    }

    /// The most rows one lease may take without overshooting `limits.items` or `limits.errors`.
    pub(super) fn criteria_lease_cap(&self) -> u32 {
        let limits = &self.crawl.limits;
        let urls = self.counters.snapshot().urls;
        let left = |limit: u32, used: u64| {
            u32::try_from(u64::from(limit).saturating_sub(used))
                .unwrap_or(u32::MAX)
                .max(1)
        };
        let mut cap = u32::MAX;
        if limits.items > 0 {
            cap = cap.min(left(limits.items, urls.succeeded));
        }
        if limits.errors > 0 {
            cap = cap.min(left(limits.errors, urls.failed.saturating_add(urls.unreachable)));
        }
        cap
    }

    /// Why a drained frontier produced no page, read from the failed rows: a seed that could
    /// not be fetched, responses that failed the content validation, responses over the body
    /// limit, or fetches that failed after their retries. `None` when a page was kept or no
    /// failed row says why.
    ///
    /// # Errors
    /// Fails when the frontier cannot be read.
    pub(super) async fn drained_detail(&self) -> Result<Option<TerminalDetail>, WorkerError> {
        if self.kept_pages() > 0 {
            return Ok(None);
        }
        let (mut seed, mut validation, mut oversize, mut retries) = (false, false, false, false);
        let mut after = 0;
        loop {
            let rows = self.deps.frontier.page(self.run, after, 1000).await?;
            let Some(last) = rows.last() else { break };
            after = last.id;
            for row in rows
                .iter()
                .filter(|row| matches!(row.status, FrontierStatus::Failed | FrontierStatus::Unreachable))
            {
                let reason = row.denial_reason.as_deref().unwrap_or_default();
                let specific = match reason {
                    "content_validation_failed" => {
                        validation = true;
                        true
                    }
                    "body_limit" => {
                        oversize = true;
                        true
                    }
                    other => {
                        retries |= is_transient_failure(other);
                        false
                    }
                };
                seed |= !specific && row.depth == 0 && row.discovered_from.is_none();
            }
        }
        Ok(if seed {
            Some(TerminalDetail::SeedError)
        } else if validation {
            Some(TerminalDetail::ContentValidationFailed)
        } else if oversize {
            Some(TerminalDetail::ByteLimit)
        } else if retries {
            Some(TerminalDetail::RetriesExhausted)
        } else {
            None
        })
    }
}
