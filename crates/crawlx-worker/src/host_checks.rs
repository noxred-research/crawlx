//! Host checks (`scope.hostChecks`): opt-in, single-request probes of the seed origin.
//!
//! Each probe is admitted like any other fetch of the run: authorization, scope, `robots.txt`,
//! the egress policy of the fetcher and the shared origin governor (so `Crawl-delay` and the
//! politeness limits apply). A refusal means nothing is sent and the check is inconclusive.
//! A probe never follows a redirect and reads at most a small bounded prefix of the body. The
//! result is stored as a `host_check` event and listed in the run report; it is a fact, not a
//! finding.

use super::discovery::DiscoveryHopAdmission;
use super::*;
use crate::acquisition::AcquisitionBudgetV1;
use crawlx_core::host_checks::{
    HostCheck, HostCheckReason, HostCheckRecord, HostCheckVerdict, HOST_CHECK_EVENT,
};

/// Bytes of a probe response body the fetcher may read.
const PROBE_BODY_CAP: usize = 1024;

/// What one probe request came to.
enum Probe {
    /// Nothing was sent.
    NotSent(HostCheckReason),
    /// The request was sent and failed with this stable code.
    Failed(&'static str),
    /// The origin's `robots.txt` could not be fetched (this stable code), so the probe itself
    /// was not sent.
    Unreachable(&'static str),
    /// The origin answered.
    Answered { status: u16 },
}

impl UrlPlaneRunner {
    /// Run every check of `scope.hostChecks` against the seed origin, in sorted order, and
    /// store one `host_check` event per check.
    ///
    /// # Errors
    /// A record that cannot be serialized.
    pub(super) async fn run_host_checks(&self) -> Result<(), WorkerError> {
        if self.crawl.scope.host_checks.is_empty() || self.crawl.cache_only() {
            return Ok(());
        }
        let cancel = self.hard_cancel.clone().unwrap_or_default();
        let origin = crawlx_policy::authorization::origin_string(&self.crawl.seed_url);
        for check in &self.crawl.scope.host_checks {
            let record = match check {
                HostCheck::Soft404 => self.soft_404_check(&origin, &cancel).await,
                // `HostCheck` is non-exhaustive; a check added to the config without a runner
                // here records nothing rather than guessing.
                _ => continue,
            };
            let payload =
                serde_json::to_value(&record).map_err(|error| WorkerError::Config(error.to_string()))?;
            self.event(HOST_CHECK_EVENT, payload).await;
        }
        Ok(())
    }

    /// One request to a random path of the seed origin that no page links to.
    async fn soft_404_check(&self, origin: &str, cancel: &CancellationToken) -> HostCheckRecord {
        let path = crawlx_url::host_checks::soft_404_probe_path(self.crawl.effective_seed(), origin);
        let mut url = self.crawl.seed_url.clone();
        url.set_path(&path);
        url.set_query(None);
        url.set_fragment(None);
        let _ = url.set_username("");
        let _ = url.set_password(None);
        let probe = self.probe_once(&url, http::Method::GET, cancel).await;
        let mut record =
            HostCheckRecord::not_sent(HostCheck::Soft404, origin, url.as_str(), HostCheckReason::Scope);
        match probe {
            Probe::NotSent(reason) => record.reason = Some(reason),
            Probe::Unreachable(code) => {
                record.reason = Some(HostCheckReason::RobotsUnavailable);
                record.error_code = Some(code.to_owned());
            }
            Probe::Failed(code) => {
                record.requested = true;
                record.reason = Some(HostCheckReason::RequestFailed);
                record.error_code = Some(code.to_owned());
            }
            Probe::Answered { status } => {
                record.requested = true;
                record.status = Some(status);
                record.verdict = crawlx_url::host_checks::classify_soft_404(Some(status));
                record.reason = (record.verdict == HostCheckVerdict::Inconclusive)
                    .then_some(HostCheckReason::UnclassifiedStatus);
            }
        }
        record
    }

    /// One non-following request to `url`, only after authorization, scope and `robots.txt`
    /// admit it. It runs through the run's fetcher (egress checks, the shared origin governor)
    /// under its own bounded budget, and is not counted as a crawled page.
    async fn probe_once(&self, url: &Url, method: http::Method, cancel: &CancellationToken) -> Probe {
        let authority = DiscoveryHopAdmission {
            runner: self,
            sitemap_document: false,
        };
        let Ok(mut budget) =
            AcquisitionBudgetV1::new(&crawlx_core::acquisition::AcquisitionPolicyV1::default())
        else {
            return Probe::NotSent(HostCheckReason::Budget);
        };
        if crate::acquisition::HopAdmission::check_authority(&authority)
            .await
            .is_err()
        {
            return Probe::NotSent(HostCheckReason::Authorization);
        }
        match self.admit_native_scope(url, 1, false, false).await {
            Ok(canonical) if canonical.url == *url => {}
            _ => return Probe::NotSent(HostCheckReason::Scope),
        }
        let mut options = crate::acquisition::fetch_options(&self.crawl.fetch);
        options.method = method.clone();
        options.follow_redirects = false;
        options.max_body_bytes = Some(PROBE_BODY_CAP);
        // exactly one request, classified by its status: no HEAD preflight, no body refusal
        options.preflight = None;
        options.oversize = crawlx_fetch::OversizePolicy::Truncate;
        match self
            .robots
            .decide_hop_with_budget(
                crawlx_policy::robots::HopKind::Page,
                url,
                &options,
                &mut budget,
                cancel,
                &authority,
            )
            .await
        {
            Ok(RobotsDecision::Allowed) => {}
            Ok(RobotsDecision::Blocked("robots_disallow")) => return Probe::NotSent(HostCheckReason::Robots),
            Ok(RobotsDecision::Blocked(_)) => return Probe::NotSent(HostCheckReason::RobotsUnavailable),
            Ok(RobotsDecision::EgressDenied) => return Probe::NotSent(HostCheckReason::Egress),
            Err(FetchError::AcquisitionCancelled) => return Probe::NotSent(HostCheckReason::Authorization),
            Err(error) => return Probe::Unreachable(error.code()),
        }
        let fetched = Box::pin(crate::acquisition::fetch_budgeted_once(
            &self.fetcher,
            url,
            &options,
            &mut budget,
            cancel,
            &authority,
        ))
        .await;
        self.record_exchange_method(method.as_str(), url, &fetched);
        match fetched {
            Ok(response) => Probe::Answered {
                status: response.status.as_u16(),
            },
            Err(FetchError::StatusDenied { status }) => Probe::Answered { status },
            Err(FetchError::EgressDenied(_)) => Probe::NotSent(HostCheckReason::Egress),
            Err(FetchError::AcquisitionCancelled) => Probe::NotSent(HostCheckReason::Authorization),
            Err(error) => Probe::Failed(error.code()),
        }
    }
}
