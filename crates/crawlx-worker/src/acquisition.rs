//! One monotonic acquisition allowance shared by native HTTP and browser dispatches.
//!
//! Legacy robots admission keeps its existing budget. Opt-in continuation robots dispatches
//! share the same parent allowance as target retrieval. Facade defaults remain unchanged.
//! Transport, peer checks and origin cooldown stay inside the existing checked Fetcher.

use crate::runtime::CpuPool;
use crawlx_core::acquisition::{
    AcquisitionPolicyV1, AcquisitionRedirectV1, AcquisitionResultV1, BackendCapabilitiesV1, RepresentationV1,
    RetryClassV1, UrlEvidenceV1, ValidationContextV1, ValidationOutcomeV1,
};
use crawlx_core::hash::Digest;
use crawlx_core::{CrawlRunId, TenantId};
use crawlx_extract::validation::{validate_acquisition, ValidationInput};
use crawlx_extract::{Document, ExtractOptions};
use crawlx_fetch::{FetchError, FetchOptions, FetchResponse, Fetcher};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Map admitted request controls onto the existing fetcher's per-request policy.
pub(crate) fn fetch_options(fetch: &crawlx_core::config::Fetch) -> FetchOptions {
    let mut options = FetchOptions {
        preflight: fetch.preflight.as_ref().map(|policy| {
            let mut preflight =
                crawlx_fetch::HeadPreflight::new().with_content_types(policy.content_types.iter().cloned());
            preflight.max_content_length = policy.max_content_length;
            preflight
        }),
        ..FetchOptions::default()
    };
    if let Some(policy) = &fetch.declaration {
        options.declaration.content_type.clone_from(&policy.content_type);
        options.declaration.charset.clone_from(&policy.charset);
        options.declaration.statuses = crawlx_fetch::HttpErrorStatuses::default()
            .allowing(policy.statuses.allow.iter().copied())
            .denying(policy.statuses.deny.iter().copied());
    }
    if let Some(policy) = fetch.oversize {
        options.oversize = match policy {
            crawlx_core::acquisition::OversizePolicy::Refuse => crawlx_fetch::OversizePolicy::Reject,
            _ => crawlx_fetch::OversizePolicy::Truncate,
        };
    }
    options
}

/// Compile extract-owned option contracts before any network request is dispatched.
pub(crate) fn configure_extract(
    options: &mut ExtractOptions,
    extract: &crawlx_core::config::Extract,
) -> Result<(), crate::error::WorkerError> {
    options.outputs = extract
        .outputs
        .as_ref()
        .map(|value| {
            serde_json::from_value::<crawlx_extract::content_outputs::ContentOutputOptions>(value.clone())
                .map_err(|error| crate::error::WorkerError::Config(format!("extract.outputs: {error}")))
        })
        .transpose()?;
    if let Some(outputs) = &options.outputs {
        outputs
            .validate()
            .map_err(|error| crate::error::WorkerError::Config(error.to_string()))?;
    }
    options.decode = extract
        .decode
        .as_ref()
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|error| crate::error::WorkerError::Config(format!("extract.decode: {error}")))
        })
        .transpose()?;
    options.markup = extract
        .markup
        .as_ref()
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|error| crate::error::WorkerError::Config(format!("extract.markup: {error}")))
        })
        .transpose()?;
    Ok(())
}

/// Live destination admission, shared by HTTP redirects and the meta transition.
#[async_trait::async_trait]
pub(crate) trait HopAdmission: Send + Sync {
    async fn admit(
        &self,
        url: &Url,
        options: &FetchOptions,
        budget: &mut AcquisitionBudgetV1,
        cancel: &CancellationToken,
    ) -> Result<(), FetchError>;
    /// Recheck live parent ownership and authorization without loading robots.
    async fn check_authority(&self) -> Result<(), FetchError>;
    /// Recheck destination scope without recursively loading its robots document.
    /// An admission owner without a protocol-resource scope fails closed.
    async fn check_scope(&self, _url: &Url) -> Result<(), FetchError> {
        Err(FetchError::AcquisitionUnavailable)
    }
    /// Execute one transport attempt beneath the existing shared budget and admission owner.
    async fn fetch_attempt(
        &self,
        fetcher: &Fetcher,
        url: &Url,
        options: &FetchOptions,
    ) -> Result<FetchResponse, FetchError> {
        fetcher
            .fetch_once_with_authority(url, options, &|| self.check_authority())
            .await
    }
    /// Whether this authority owns a stateful transport requiring caller-managed hops.
    fn requires_checked_hops(&self) -> bool {
        false
    }
}

/// Project URL evidence through existing userinfo, sensitive-name and literal secret rules.
fn public_url(
    url: &Url,
    controls: &crawlx_core::request_controls::RequestControls,
) -> Result<Url, FetchError> {
    let mut projected = url.clone();
    if !projected.username().is_empty() {
        projected
            .set_username("")
            .map_err(|()| FetchError::AcquisitionUnavailable)?;
    }
    if projected.password().is_some() {
        projected
            .set_password(None)
            .map_err(|()| FetchError::AcquisitionUnavailable)?;
    }
    let redactor = crawlx_core::secret::Redactor::new();
    if projected.query().is_some() {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in projected.query_pairs() {
            if redactor.is_sensitive_name(&name) {
                query.append_pair(&name, crawlx_core::secret::REDACTED);
            } else {
                let value = redactor.scrub_bytes(value.as_bytes(), controls.secret_values());
                let value =
                    std::str::from_utf8(value.as_ref()).map_err(|_| FetchError::AcquisitionUnavailable)?;
                query.append_pair(&name, value);
            }
        }
        projected.set_query(Some(&query.finish()));
    }
    let bytes = redactor.scrub_bytes(projected.as_str().as_bytes(), controls.secret_values());
    let value = std::str::from_utf8(bytes.as_ref()).map_err(|_| FetchError::AcquisitionUnavailable)?;
    Url::parse(value).map_err(|_| FetchError::AcquisitionUnavailable)
}

/// One checked, non-retrying dispatch charged to the shared parent allowance.
pub(crate) async fn fetch_budgeted_once(
    fetcher: &Fetcher,
    url: &Url,
    options: &FetchOptions,
    budget: &mut AcquisitionBudgetV1,
    cancel: &CancellationToken,
    admission: &dyn HopAdmission,
) -> Result<FetchResponse, FetchError> {
    let remaining = budget.preflight(cancel)?;
    tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(FetchError::AcquisitionCancelled),
        result = tokio::time::timeout(remaining, admission.check_authority()) =>
            result.map_err(|_| FetchError::AcquisitionDeadline)??,
    }
    let remaining = budget.reserve(cancel)?;
    let options = budget.options(options, fetcher.config().max_body_bytes);
    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => Err(FetchError::AcquisitionCancelled),
        result = watch_authority(admission) => result.and(Err(FetchError::AcquisitionCancelled)),
        result = tokio::time::timeout(remaining, admission.fetch_attempt(fetcher, url, &options)) =>
            result.unwrap_or(Err(FetchError::AcquisitionDeadline)),
    };
    match result {
        Ok(response) => {
            budget.charge_bytes(response.body.len());
            budget.record(
                "native_http",
                Some(response.status.as_u16()),
                crawlx_core::acquisition::ValidationCategoryV1::Indeterminate,
            );
            Ok(response)
        }
        Err(error) => {
            budget.on_fetch_failure(
                &error,
                options.max_body_bytes.unwrap_or(fetcher.config().max_body_bytes),
            );
            budget.record(
                "native_http",
                None,
                crawlx_core::acquisition::ValidationCategoryV1::TransportError,
            );
            Err(error)
        }
    }
}

/// Cancel a pending governor/transport wait when its pinned parent fence or authority changes.
async fn watch_authority(admission: &dyn HopAdmission) -> Result<(), FetchError> {
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        admission.check_authority().await?;
    }
}

/// Retrieve one checked representation, optionally following a single HTML meta refresh.
#[allow(clippy::too_many_arguments)]
async fn fetch_checked(
    fetcher: &Fetcher,
    original: &Url,
    original_options: &FetchOptions,
    policy: Option<&crawlx_core::acquisition::MetaRefreshPolicyV1>,
    budget: &mut AcquisitionBudgetV1,
    cancel: &CancellationToken,
    cpu: &CpuPool,
    observe: &(dyn Fn(&Url, &Result<FetchResponse, FetchError>) + Send + Sync),
    admission: &dyn HopAdmission,
) -> Result<
    (
        FetchResponse,
        Option<crawlx_core::acquisition::MetaRefreshEvidenceV1>,
    ),
    FetchError,
> {
    let mut current = original.clone();
    let mut options = original_options.clone();
    options.follow_redirects = false;
    let mut seen = std::collections::BTreeSet::new();
    let mut hops = Vec::new();
    let mut evidence: Option<crawlx_core::acquisition::MetaRefreshEvidenceV1> = None;
    let max_hops = original_options
        .max_redirects
        .unwrap_or(fetcher.config().max_redirects)
        .min(20);
    let mut transitions = 0usize;
    loop {
        let result = async {
            if transitions > max_hops || !seen.insert(current.as_str().to_owned()) {
                return Err(FetchError::TooManyRedirects { limit: max_hops });
            }
            if !matches!(current.scheme(), "http" | "https")
                || !current.username().is_empty()
                || current.password().is_some()
            {
                return Err(FetchError::AcquisitionUnavailable);
            }
            budget.preflight(cancel)?;
            let deadline = budget.deadline;
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(FetchError::AcquisitionCancelled),
                result = tokio::time::timeout_at(deadline, admission.admit(&current, &options, budget, cancel)) =>
                    result.map_err(|_| FetchError::AcquisitionDeadline)??,
            }
            let result = fetch_budgeted_once(fetcher, &current, &options, budget, cancel, admission).await;
            observe(&current, &result);
            result
        }
        .await;
        let mut response = match result {
            Ok(response) => response,
            Err(source) => {
                return Err(match evidence {
                    Some(evidence) => FetchError::MetaRefresh {
                        evidence: Box::new(evidence),
                        source: Box::new(source),
                    },
                    None => source,
                })
            }
        };
        let follow_http = crawlx_fetch::redirect::is_redirect(response.status.as_u16())
            && original_options.follow_redirects
            && fetcher.config().follow_redirects;
        if !follow_http {
            if let Some(evidence) = &mut evidence {
                evidence.selected_url = Some(public_url(&response.final_url, &fetcher.config().controls)?);
                evidence.selected_status = Some(response.status.as_u16());
            }
        }
        let next = if follow_http {
            if let Some(evidence) = &mut evidence {
                evidence.http_redirects.push(AcquisitionRedirectV1::observed(
                    public_url(&response.final_url, &fetcher.config().controls)?,
                    Some(response.status.as_u16()),
                ));
            }
            match crawlx_fetch::redirect::location(&response.final_url, &response.headers) {
                Ok(next) => Some(next),
                Err(source) => {
                    return Err(match evidence {
                        Some(evidence) => FetchError::MetaRefresh {
                            evidence: Box::new(evidence),
                            source: Box::new(source),
                        },
                        None => source,
                    })
                }
            }
        } else if let Some(policy) = policy.filter(|_| {
            evidence.is_none()
                && response.status.is_success()
                && !response.truncated
                && response.content_type.as_deref().is_some_and(|mime| {
                    mime.split(';').next().is_some_and(|mime| {
                        mime.trim().eq_ignore_ascii_case("text/html")
                            || mime.trim().eq_ignore_ascii_case("application/xhtml+xml")
                    })
                })
        }) {
            let body = response.body.clone();
            let observed = response.final_url.clone();
            let bound = policy.max_parser_bytes;
            let next = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(FetchError::AcquisitionCancelled),
                result = tokio::time::timeout_at(budget.deadline, cpu.run(move ||
                    crawlx_extract::metadata::try_meta_refresh_target(&body, &observed, bound))) =>
                    result
                        .map_err(|_| FetchError::AcquisitionDeadline)?
                        .map_err(|_| FetchError::AcquisitionUnavailable)?
                        // A full budget is transient pressure; a page larger than the whole budget
                        // can never be parsed and is terminal, like the other parent allowances.
                        .map_err(|refused| {
                            if refused.exceeds_budget() {
                                FetchError::AcquisitionAllowance
                            } else {
                                FetchError::OriginAdmission(crawlx_core::StoreError::ResourceExhausted {
                                    resource: "parse_memory",
                                    requested: refused.requested,
                                    available: refused.available,
                                    source: None,
                                })
                            }
                        })?,
            };
            if let Some(next) = &next {
                let mut selected = crawlx_core::acquisition::MetaRefreshEvidenceV1::new(
                    policy.clone(),
                    public_url(&response.final_url, &fetcher.config().controls)?,
                    response.status.as_u16(),
                    public_url(next, &fetcher.config().controls)?,
                );
                selected.http_redirects = hops
                    .iter()
                    .map(|hop: &crawlx_fetch::FetchHop| {
                        Ok(AcquisitionRedirectV1::observed(
                            public_url(&hop.url, &fetcher.config().controls)?,
                            Some(hop.status.as_u16()),
                        ))
                    })
                    .collect::<Result<Vec<_>, FetchError>>()?;
                evidence = Some(selected);
            }
            next
        } else {
            None
        };
        let Some(mut next) = next else {
            if evidence.is_some() && (!response.status.is_success() || response.truncated) {
                return Err(FetchError::MetaRefresh {
                    evidence: Box::new(evidence.take().ok_or(FetchError::AcquisitionUnavailable)?),
                    source: Box::new(if response.truncated {
                        FetchError::AcquisitionAllowance
                    } else {
                        FetchError::MetaRefreshTarget {
                            status: response.status.as_u16(),
                        }
                    }),
                });
            }
            response.redirects = hops
                .iter()
                .map(|hop: &crawlx_fetch::FetchHop| hop.url.to_string())
                .collect();
            response.hops = hops;
            response.attempts = u32::try_from(response.hops.len())
                .unwrap_or(u32::MAX)
                .saturating_add(1);
            return Ok((response, evidence));
        };
        next.set_fragment(None);
        options.validators = None;
        options.suppress_validators = true;
        options.headers.remove(http::header::IF_NONE_MATCH);
        options.headers.remove(http::header::IF_MODIFIED_SINCE);
        if current.origin() != next.origin() {
            options.suppress_credentials = true;
            crawlx_fetch::redirect::strip_credentials(&mut options.headers);
        }
        if crawlx_fetch::redirect::is_redirect(response.status.as_u16()) {
            hops.push(crawlx_fetch::FetchHop::observed(
                response.final_url,
                response.status,
                response.headers,
            ));
        }
        transitions = transitions.saturating_add(1);
        current = next;
    }
}

/// One request's shared state; child backends receive this same value, never fresh budgets.
pub(crate) struct AcquisitionBudgetV1 {
    started: Instant,
    deadline: Instant,
    attempts_left: u8,
    attempts: u8,
    bytes_left: u64,
    decoded_bytes: u64,
    requests: Arc<AtomicU32>,
    initial_requests: u32,
    summaries: Vec<crawlx_core::acquisition::AcquisitionAttemptV1>,
    initial_bytes: u64,
    previous_usage: crawlx_core::acquisition::AcquisitionUsageV1,
    evidence_incomplete: bool,
}
impl AcquisitionBudgetV1 {
    pub(crate) fn new(policy: &AcquisitionPolicyV1) -> Result<Self, FetchError> {
        policy
            .validate()
            .map_err(|_| FetchError::AcquisitionUnavailable)?;
        crawlx_extract::validation::compile_policy(&policy.validation)
            .map_err(|_| FetchError::AcquisitionUnavailable)?;
        let started = Instant::now();
        Ok(Self {
            started,
            deadline: started + Duration::from_millis(u64::from(policy.max_elapsed_ms)),
            attempts_left: policy.max_attempts,
            attempts: 0,
            bytes_left: policy.max_decoded_bytes,
            decoded_bytes: 0,
            requests: Arc::new(AtomicU32::new(policy.max_network_requests)),
            initial_requests: policy.max_network_requests,
            summaries: Vec::with_capacity(usize::from(policy.max_attempts)),
            initial_bytes: policy.max_decoded_bytes,
            previous_usage: crawlx_core::acquisition::AcquisitionUsageV1::default(),
            evidence_incomplete: false,
        })
    }
    pub(crate) fn from_allowance(
        policy: &AcquisitionPolicyV1,
        allowance: &crawlx_core::acquisition::AcquisitionAllowanceV1,
    ) -> Result<Self, FetchError> {
        let mut budget = Self::new(policy)?;
        if allowance.remaining_attempts == 0
            || allowance.remaining_network_requests == 0
            || allowance.remaining_decoded_bytes == 0
        {
            return Err(FetchError::AcquisitionAllowance);
        }
        if allowance.remaining_elapsed_ms == 0 {
            return Err(FetchError::AcquisitionDeadline);
        }
        // A prior lease may have selected a meta target before losing its fence. Without
        // durable complete continuation evidence, never restart that request at its source.
        if policy.meta_refresh.is_some() && allowance.previous_usage.attempts_reserved > 0 {
            return Err(FetchError::AcquisitionUnavailable);
        }
        budget.attempts_left = budget.attempts_left.min(allowance.remaining_attempts);
        budget.bytes_left = budget.bytes_left.min(allowance.remaining_decoded_bytes);
        budget.initial_bytes = budget.bytes_left;
        budget.initial_requests = budget.initial_requests.min(allowance.remaining_network_requests);
        budget.requests.store(budget.initial_requests, Ordering::Release);
        let remaining = policy.max_elapsed_ms.min(allowance.remaining_elapsed_ms);
        budget.deadline = budget.started + Duration::from_millis(u64::from(remaining));
        budget.previous_usage.clone_from(&allowance.previous_usage);
        Ok(budget)
    }
    pub(crate) fn usage(&self) -> crawlx_core::acquisition::AcquisitionUsageV1 {
        crawlx_core::acquisition::AcquisitionUsageV1::new(
            self.attempts,
            self.initial_requests
                .saturating_sub(self.requests.load(Ordering::Acquire)),
            self.initial_bytes.saturating_sub(self.bytes_left),
            self.decoded_bytes,
            self.evidence_incomplete,
        )
    }
    pub(crate) fn on_fetch_failure(&mut self, error: &FetchError, body_cap: usize) {
        self.evidence_incomplete = true;
        let before_body = match error {
            FetchError::Resolve { .. }
            | FetchError::EgressDenied(_)
            | FetchError::InvalidUrl { .. }
            | FetchError::UnsupportedMethod(_)
            | FetchError::InvalidHeader { .. }
            | FetchError::Pool(_)
            | FetchError::PoolRefused { .. }
            | FetchError::PeerNotPinned { .. } => true,
            FetchError::Transport(crawlx_fetch::error::HttpError::Rustls(source))
            | FetchError::Timeout(crawlx_fetch::error::HttpError::Rustls(source)) => source.is_connect(),
            FetchError::Transport(crawlx_fetch::error::HttpError::Randomized(source))
            | FetchError::Timeout(crawlx_fetch::error::HttpError::Randomized(source)) => source.is_connect(),
            _ => false,
        };
        if !before_body {
            self.bytes_left = self
                .bytes_left
                .saturating_sub(u64::try_from(body_cap).unwrap_or(u64::MAX));
        }
    }
    pub(crate) fn preflight(&self, cancel: &CancellationToken) -> Result<Duration, FetchError> {
        if cancel.is_cancelled() {
            return Err(FetchError::AcquisitionCancelled);
        }
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(FetchError::AcquisitionDeadline);
        }
        if self.attempts_left == 0 || self.bytes_left == 0 || self.requests.load(Ordering::Acquire) == 0 {
            return Err(FetchError::AcquisitionAllowance);
        }
        Ok(remaining)
    }
    pub(crate) fn reserve(&mut self, cancel: &CancellationToken) -> Result<Duration, FetchError> {
        let remaining = self.preflight(cancel)?;
        self.attempts_left = self.attempts_left.saturating_sub(1);
        self.attempts = self.attempts.saturating_add(1);
        Ok(remaining)
    }
    pub(crate) fn options(&self, original: &FetchOptions, configured_cap: usize) -> FetchOptions {
        let mut options = original.clone();
        options.max_body_bytes = Some(
            usize::try_from(self.bytes_left)
                .unwrap_or(usize::MAX)
                .min(configured_cap)
                .min(original.max_body_bytes.unwrap_or(usize::MAX)),
        );
        options.max_redirects = Some(original.max_redirects.unwrap_or(20).min(20));
        options.request_allowance = Some(Arc::clone(&self.requests));
        options
    }
    pub(crate) fn charge_bytes(&mut self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.bytes_left = self.bytes_left.saturating_sub(bytes);
        self.decoded_bytes = self.decoded_bytes.saturating_add(bytes);
    }
    pub(crate) fn render_allowance(
        &self,
        cancel: &CancellationToken,
    ) -> crate::scrape::render::RenderAllowance {
        crate::scrape::render::RenderAllowance {
            requests: Arc::clone(&self.requests),
            deadline: self.deadline,
            max_decoded_bytes: self.remaining_bytes(),
            cancel: cancel.clone(),
        }
    }
    pub(crate) fn remaining_bytes(&self) -> usize {
        usize::try_from(self.bytes_left).unwrap_or(usize::MAX)
    }
    pub(crate) fn can_retry(&self) -> bool {
        self.attempts_left > 0
            && self.bytes_left > 0
            && self.requests.load(Ordering::Acquire) > 0
            && Instant::now() < self.deadline
    }
    pub(crate) fn record(
        &mut self,
        backend: &str,
        status: Option<u16>,
        category: crawlx_core::acquisition::ValidationCategoryV1,
    ) {
        self.summaries
            .push(crawlx_core::acquisition::AcquisitionAttemptV1::new(
                self.previous_usage
                    .attempts_reserved
                    .saturating_add(self.attempts),
                backend,
                status,
                category,
            ));
    }
    pub(crate) fn stamp(&self, result: &mut AcquisitionResultV1) {
        result.attempts = self
            .previous_usage
            .attempts_reserved
            .saturating_add(self.attempts);
        result.attempt_summaries.clone_from(&self.summaries);
        result.decoded_bytes = self
            .previous_usage
            .decoded_bytes_observed
            .saturating_add(self.decoded_bytes);
        result.allowance_usage = self.usage();
        result.network_requests = self
            .previous_usage
            .network_requests_reserved
            .saturating_add(result.allowance_usage.network_requests_reserved);
        let complete = !self.evidence_incomplete && !self.previous_usage.evidence_incomplete;
        result.network_requests_observed = complete.then_some(result.network_requests);
        result.evidence_truncated |= !complete || self.previous_usage.attempts_reserved > 0;
        result.elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        result.elapsed_scope = Some(crawlx_core::acquisition::AcquisitionElapsedScopeV1::CurrentCoordinator);
    }
    pub(crate) fn constrain(&mut self, max_elapsed: Duration, max_bytes: u64) {
        self.deadline = self.deadline.min(Instant::now() + max_elapsed);
        self.bytes_left = self.bytes_left.min(max_bytes);
    }
}

/// The immutable page pipeline shared by all acquisitions in this process.
pub(crate) fn parser_pipeline(
) -> Result<&'static crawlx_extract::pipeline::ParserPipeline, &'static crawlx_extract::pipeline::PipelineError>
{
    static PIPELINE: std::sync::LazyLock<
        Result<crawlx_extract::pipeline::ParserPipeline, crawlx_extract::pipeline::PipelineError>,
    > = std::sync::LazyLock::new(|| {
        crawlx_extract::pipeline::ParserPipeline::new(crawlx_core::extraction::ParserPipelineV1::default())
    });
    PIPELINE.as_ref()
}

type ContentProjection<'a> = dyn Fn(&str) -> Option<String> + 'a;

/// Run page bytes through the shared versioned parser before any caller persists content.
fn pipeline_document(
    body: &[u8],
    base: &Url,
    options: &ExtractOptions,
    projection: Option<&ContentProjection<'_>>,
) -> Result<Document, crawlx_extract::ExtractError> {
    use crawlx_extract::pipeline::{PipelineContent, PipelineError, PipelineInput};
    let pipeline = parser_pipeline().map_err(|error| {
        crawlx_extract::ExtractError::InvalidContentPolicy(crawlx_core::CoreError::Invalid {
            field: "extract.pipeline",
            reason: error.to_string(),
        })
    })?;
    let execute = || {
        let mut input = PipelineInput::new(body)
            .with_page_url(base)
            .with_content_type("text/html")
            .with_page_options(options);
        if let Some(project) = projection {
            input = input.with_projection(project);
        }
        pipeline.run(input)
    };
    let output = execute().map_err(|error| match error {
        PipelineError::Extract(error) => error,
        PipelineError::Invalid(error) => crawlx_extract::ExtractError::InvalidContentPolicy(error),
        PipelineError::Limit { what, limit, actual } => crawlx_extract::ExtractError::TooLarge {
            what,
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
            actual: usize::try_from(actual).unwrap_or(usize::MAX),
        },
        error => crawlx_extract::ExtractError::InvalidContentPolicy(crawlx_core::CoreError::Invalid {
            field: "extract.pipeline",
            reason: error.to_string(),
        }),
    })?;
    match output.content {
        PipelineContent::Page(document) => Ok(*document),
        _ => Err(crawlx_extract::ExtractError::InvalidContentPolicy(
            crawlx_core::CoreError::Invalid {
                field: "extract.pipeline",
                reason: "page extraction requires an HTML route".into(),
            },
        )),
    }
}

/// Extract with final normalized secret projection before article quality, ranges and digests.
pub(crate) fn extract_document(
    body: &[u8],
    base: &Url,
    options: &ExtractOptions,
    controls: &crawlx_core::request_controls::RequestControls,
) -> Result<Document, crawlx_extract::ExtractError> {
    if options.content.is_none() {
        return pipeline_document(body, base, options, None);
    }
    let redactor = crawlx_telemetry::Redactor::new();
    let prepared = redactor.scrub_bytes(body, controls.secret_values());
    let project = |text: &str| match redactor.scrub_bytes(text.as_bytes(), controls.secret_values()) {
        std::borrow::Cow::Borrowed(_) => None,
        std::borrow::Cow::Owned(scrubbed) => Some(match String::from_utf8(scrubbed) {
            Ok(text) => text,
            Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
        }),
    };
    pipeline_document(prepared.as_ref(), base, options, Some(&project))
}

/// Project actual request and live provider secrets before canonical derived outputs.
pub(crate) fn extract_document_with_secrets(
    body: &[u8],
    base: &Url,
    options: &ExtractOptions,
    controls: &crawlx_core::request_controls::RequestControls,
    captcha: &crawlx_core::captcha::CaptchaSecrets,
) -> Result<Document, crawlx_extract::ExtractError> {
    let unavailable = || {
        crawlx_extract::ExtractError::InvalidContentPolicy(crawlx_core::CoreError::Invalid {
            field: "extract.privacy",
            reason: "dynamic-secret projection unavailable".into(),
        })
    };
    captcha.has_values().map_err(|_| unavailable())?;
    if options.content.is_none() {
        return extract_document(body, base, options, controls);
    }
    let redactor = crawlx_telemetry::Redactor::new();
    let prepared = redactor.scrub_bytes(body, controls.secret_values());
    let failed = std::cell::Cell::new(false);
    let project = |text: &str| {
        let controlled = redactor.scrub_bytes(text.as_bytes(), controls.secret_values());
        let Ok(text) = std::str::from_utf8(controlled.as_ref()) else {
            failed.set(true);
            return Some(String::new());
        };
        match captcha.redact_if_present(text) {
            Ok(std::borrow::Cow::Owned(value)) => Some(value),
            Ok(std::borrow::Cow::Borrowed(_)) => match controlled {
                std::borrow::Cow::Borrowed(_) => None,
                std::borrow::Cow::Owned(bytes) => String::from_utf8(bytes).ok(),
            },
            Err(_) => {
                failed.set(true);
                Some(String::new())
            }
        }
    };
    let document = pipeline_document(prepared.as_ref(), base, options, Some(&project));
    if failed.get() {
        return Err(unavailable());
    }
    document
}

/// HTTP result plus extracted document. Bytes stay in FetchResponse; no body appears in metadata.
pub(crate) struct HttpAcquisition {
    pub response: FetchResponse,
    pub metadata: AcquisitionResultV1,
    pub document: Option<Box<Document>>,
}

/// Redact native extraction input before source ranges/digests are computed.
/// Retained wire bytes remain separately owned by the producer.
pub(crate) fn extraction_body(
    body: &bytes::Bytes,
    controls: &crawlx_core::request_controls::RequestControls,
    extract: &ExtractOptions,
) -> bytes::Bytes {
    if extract.content.is_none() {
        return body.clone();
    }
    match crawlx_telemetry::Redactor::new().scrub_bytes(body, controls.secret_values()) {
        std::borrow::Cow::Borrowed(_) => body.clone(),
        std::borrow::Cow::Owned(scrubbed) => bytes::Bytes::from(scrubbed),
    }
}

#[allow(clippy::too_many_arguments)]
/// Validate a producer's response using the extractor's existing parsed DOM exactly once.
/// Keep the owned document heap-placed from the CPU task through acquisition and composition;
/// returning it inline multiplies large async result temporaries on the executor's poll stack.
pub(crate) async fn validate_body(
    body: bytes::Bytes,
    base: Url,
    content_type: Option<String>,
    headers: Vec<(String, String)>,
    context: ValidationContextV1,
    mut extract: ExtractOptions,
    cpu: &CpuPool,
    controls: &crawlx_core::request_controls::RequestControls,
    captcha: Option<&crawlx_core::captcha::CaptchaSecrets>,
) -> Result<(ValidationOutcomeV1, Option<Box<Document>>), FetchError> {
    let is_html = content_type.as_deref().is_none_or(|mime| mime.contains("html"))
        || body.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'<');
    extract.status = context.target_status.unwrap_or(0);
    extract.headers.clone_from(&headers);
    extract.content_type.clone_from(&content_type);
    extract.acquisition_validation = Some(context.clone());
    if context.transport_succeeded {
        crawlx_telemetry::Metrics::global()
            .counter("crawlx_acquisition_transport_success_total")
            .inc_by(1, &[]);
    }
    let method_head = context.method_head;
    let controls = controls.clone();
    let captcha = captcha.cloned();
    let result = cpu
        .run(move || {
            if is_html && !method_head {
                let parsed = match &captcha {
                    Some(captcha) => {
                        extract_document_with_secrets(&body, &base, &extract, &controls, captcha)
                    }
                    None if extract.content.is_none() => extract_document(&body, &base, &extract, &controls),
                    None => Err(crawlx_extract::ExtractError::InvalidContentPolicy(
                        crawlx_core::CoreError::Invalid {
                            field: "extract.privacy",
                            reason: "dynamic-secret registry unavailable".into(),
                        },
                    )),
                };
                match parsed {
                    Ok(doc) => (
                        doc.validation
                            .clone()
                            .unwrap_or_else(ValidationOutcomeV1::indeterminate),
                        Some(Box::new(doc)),
                    ),
                    Err(_) => {
                        let mut outcome = ValidationOutcomeV1::indeterminate();
                        outcome.signals.push("extraction_parse_limit".to_owned());
                        (outcome, None)
                    }
                }
            } else {
                (
                    validate_acquisition(&ValidationInput {
                        context: &context,
                        content_type: content_type.as_deref(),
                        headers: &headers,
                        body: &body,
                        document: None,
                    }),
                    None,
                )
            }
        })
        .await
        .map_err(|_| FetchError::AcquisitionUnavailable)?;
    if !method_head && result.0.content_accepted {
        crawlx_telemetry::Metrics::global()
            .counter("crawlx_acquisition_accepted_document_total")
            .inc_by(1, &[]);
    }
    Ok(result)
}

pub(crate) fn context(
    policy: &AcquisitionPolicyV1,
    status: Option<u16>,
    truncated: bool,
) -> ValidationContextV1 {
    let mut context = ValidationContextV1::default();
    context.policy = policy.validation.clone();
    context.target_status = status;
    context.transport_succeeded = true;
    context.truncated = truncated;
    context
}

pub(crate) fn http_metadata(
    run: CrawlRunId,
    tenant: TenantId,
    requested: &Url,
    response: &FetchResponse,
    fetcher: &Fetcher,
) -> AcquisitionResultV1 {
    let implementation = match fetcher.config().tls_impersonation {
        crawlx_core::tls::TlsImpersonation::Off => "crawlx-fetch/reqwest-rustls",
        _ => "crawlx-fetch/wreq-boringssl-synthetic",
    };
    let mut metadata = AcquisitionResultV1::new(
        run,
        tenant,
        requested.clone(),
        Digest::of("crawlx/canonical-url/v1", requested.as_str().as_bytes()),
        BackendCapabilitiesV1::native_http(implementation, env!("CARGO_PKG_VERSION")),
    );
    metadata.final_url = Some(response.final_url.clone());
    metadata.final_url_evidence = UrlEvidenceV1::Observed;
    metadata.target_status = Some(response.status.as_u16());
    metadata.truncated = response.truncated;
    metadata.transport_succeeded = true;
    metadata.content_type.clone_from(&response.content_type);
    metadata.content_encoding = response
        .headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    metadata.connection.checked_origin = Some(response.final_url.origin().ascii_serialization());
    metadata.connection.peer = response.peer_observed.then_some(response.resolved_ip);
    metadata.connection.peer_checked = response.peer_observed.then_some(true);
    metadata.connection.proxy_route = Some(
        if fetcher.config().pool.is_some() {
            "proxyx_pool"
        } else if fetcher.config().proxy.is_some() {
            "configured_proxy"
        } else {
            "direct"
        }
        .to_owned(),
    );
    if let Some(tunnel) = fetcher.pool_tunnel(&response.final_url) {
        metadata.connection.pool_session = Some(tunnel.session);
        metadata.connection.pool_exit_ip = Some(tunnel.exit_ip);
    }
    metadata.connection.tls_verification = (response.final_url.scheme() == "https").then(|| {
        if fetcher.config().controls.skip_tls_verification() {
            "explicit_insecure"
        } else {
            "verify_peer_and_hostname"
        }
        .to_owned()
    });
    metadata.redirects = response
        .hops
        .iter()
        .take(20)
        .map(|hop| AcquisitionRedirectV1::observed(hop.url.clone(), Some(hop.status.as_u16())))
        .collect();
    metadata.evidence_truncated = response.hops.len() > 20;
    metadata.wire_body = response.retained_response_body();
    metadata.representation = RepresentationV1::WireResponse;
    metadata.decoded_bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
    metadata.network_requests = response.attempts;
    metadata.network_requests_observed = Some(response.attempts);
    metadata.attempts = u8::try_from(
        response
            .attempts
            .saturating_sub(u32::try_from(response.hops.len()).unwrap_or(u32::MAX)),
    )
    .unwrap_or(u8::MAX);
    metadata.evidence_truncated |= metadata.attempts > 1;
    metadata.elapsed_ms = u64::try_from(response.duration.as_millis()).unwrap_or(u64::MAX);
    metadata
}

/// Execute safe HTTP attempts under a caller-owned allowance. No status retry can reset it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_native(
    fetcher: &Fetcher,
    url: &Url,
    options: &FetchOptions,
    policy: &AcquisitionPolicyV1,
    budget: &mut AcquisitionBudgetV1,
    cancel: &CancellationToken,
    extract: &ExtractOptions,
    cpu: &CpuPool,
    run: CrawlRunId,
    tenant: TenantId,
    observe: &(dyn Fn(&Url, &Result<FetchResponse, FetchError>) + Send + Sync),
    one_attempt: bool,
    captcha: Option<&crawlx_core::captcha::CaptchaSecrets>,
    admission: Option<&dyn HopAdmission>,
) -> Result<HttpAcquisition, FetchError> {
    if !policy.backend_ids.iter().any(|id| id == "native_http") {
        return Err(FetchError::AcquisitionUnavailable);
    }
    if policy.meta_refresh.is_some() && (admission.is_none() || options.method != http::Method::GET) {
        return Err(FetchError::AcquisitionUnavailable);
    }
    let checked_hops = policy.meta_refresh.is_some()
        || options.method == http::Method::HEAD
        || admission.is_some_and(|authority| authority.requires_checked_hops());
    loop {
        let mut refresh_evidence = None;
        let fetched = if checked_hops {
            let selected = fetch_checked(
                fetcher,
                url,
                options,
                policy.meta_refresh.as_ref(),
                budget,
                cancel,
                cpu,
                observe,
                admission.ok_or(FetchError::AcquisitionUnavailable)?,
            )
            .await;
            match selected {
                Ok((response, evidence)) => {
                    refresh_evidence = evidence;
                    Ok(response)
                }
                Err(error) if policy.meta_refresh.is_some() => return Err(error),
                Err(error) => Err(error),
            }
        } else {
            let remaining = budget.reserve(cancel)?;
            let options = budget.options(options, fetcher.config().max_body_bytes);
            tokio::select! {
                biased;
                () = cancel.cancelled() => Err(FetchError::AcquisitionCancelled),
                result = tokio::time::timeout(remaining, fetcher.fetch_once(url, &options)) => result.unwrap_or(Err(FetchError::AcquisitionDeadline)),
            }
        };
        if !checked_hops {
            observe(url, &fetched);
        }
        let response = match fetched {
            Ok(response) => response,
            Err(error) => {
                if !checked_hops {
                    budget.on_fetch_failure(
                        &error,
                        options.max_body_bytes.unwrap_or(fetcher.config().max_body_bytes),
                    );
                    budget.record(
                        "native_http",
                        None,
                        crawlx_core::acquisition::ValidationCategoryV1::TransportError,
                    );
                }
                let safe_transport = matches!(
                    error,
                    FetchError::Transport(_) | FetchError::Timeout(_) | FetchError::Resolve { .. }
                );
                if !one_attempt
                    && safe_transport
                    && policy.retry_on.contains(&RetryClassV1::Transport)
                    && budget.can_retry()
                {
                    continue;
                }
                return Err(error);
            }
        };
        if !checked_hops {
            budget.charge_bytes(response.body.len());
        }
        let mut metadata = http_metadata(run, tenant, url, &response, fetcher);
        metadata.meta_refresh = refresh_evidence;
        metadata.meta_refresh_policy.clone_from(&policy.meta_refresh);
        if policy.meta_refresh.is_some() {
            metadata.meta_refresh_revision = Some(crawlx_core::acquisition::META_REFRESH_RUNTIME_REVISION);
        }
        if policy.meta_refresh.is_some() || options.method == http::Method::HEAD {
            let requested = public_url(&metadata.requested_url, &fetcher.config().controls)?;
            metadata.evidence_truncated |= requested != metadata.requested_url;
            metadata.requested_url = requested;
            if let Some(final_url) = &mut metadata.final_url {
                let projected = public_url(final_url, &fetcher.config().controls)?;
                metadata.evidence_truncated |= projected != *final_url;
                *final_url = projected;
            }
            for hop in &mut metadata.redirects {
                let projected = public_url(&hop.url, &fetcher.config().controls)?;
                metadata.evidence_truncated |= projected != hop.url;
                hop.url = projected;
            }
        }
        let mut facts = context(policy, metadata.target_status, response.truncated);
        facts.method_head = options.method == http::Method::HEAD;
        let validation = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(FetchError::AcquisitionCancelled),
            result = tokio::time::timeout_at(budget.deadline, validate_body(extraction_body(&response.body, &fetcher.config().controls, extract), response.final_url.clone(), response.content_type.clone(), crate::url_plane::header_pairs(&response.headers), facts, extract.clone(), cpu, &fetcher.config().controls, captcha)) => result.map_err(|_| FetchError::AcquisitionDeadline).and_then(|result| result),
        };
        let mut validation = validation.map_err(|source| match &metadata.meta_refresh {
            Some(evidence) => FetchError::MetaRefresh {
                evidence: Box::new(evidence.clone()),
                source: Box::new(source),
            },
            None => source,
        })?;
        metadata.validation = validation.0;
        metadata.extraction_succeeded = validation.1.as_ref().map(|_| true);
        if let Some(article) = validation
            .1
            .as_mut()
            .and_then(|document| document.article.as_mut())
        {
            article.acquisition_request_digest = Some(metadata.request_digest);
            article.source_artifact.clone_from(&metadata.wire_body);
        }
        if !checked_hops {
            budget.record(
                "native_http",
                metadata.target_status,
                metadata.validation.category,
            );
        } else if let Some(summary) = budget.summaries.last_mut() {
            summary.category = metadata.validation.category;
        }
        budget.stamp(&mut metadata);
        metadata.bound().map_err(|_| FetchError::AcquisitionUnavailable)?;
        // 429 already updates the shared OriginGovernor inside Fetcher. Retry on the same
        // identity only: never treat cooldown as permission for proxy/browser rotation.
        let retry = metadata
            .validation
            .retry_disposition
            .is_some_and(|class| policy.retry_on.contains(&class));
        if policy.meta_refresh.is_none()
            && !one_attempt
            && retry
            && budget.can_retry()
            && !(metadata.target_status == Some(429) && fetcher.governor().defers_source_throttle())
        {
            continue;
        }
        return Ok(HttpAcquisition {
            response,
            metadata,
            document: validation.1,
        });
    }
}

/// Validate parsers and actual selected native backends before robots or target traffic.
pub(crate) async fn admit_runtime(
    rc: &crate::run::RunContext,
    cfg: &crate::WorkerConfig,
    operator_backend: bool,
    local: bool,
) -> Result<(), crate::error::WorkerError> {
    use crate::error::WorkerError;
    use crawlx_storage::admin::WorkerRegistry;
    // RunContext construction already admits deployment gates or a run-bound fixture permit.
    // Reapplying deployment G3 here would reject controlled pre-promotion advisory experiments.
    cfg.check_data_capabilities(&rc.crawl)?;
    for content in [
        rc.crawl
            .scrape
            .as_ref()
            .and_then(|job| job.options.content_policy.as_ref()),
        rc.crawl.extract.content.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        crawlx_extract::validate_content_policy(content)?;
    }
    if let Some(policy) = &rc.crawl.acquisition {
        policy.validate()?;
        rc.crawl.validate_meta_refresh()?;
        crawlx_extract::validation::compile_policy(&policy.validation)?;
    }
    let required_browser = rc
        .crawl
        .acquisition
        .as_ref()
        .is_some_and(|policy| policy.backend_ids.iter().any(|id| id == "native_browser"));
    let http = BackendCapabilitiesV1::native_http("crawlx-fetch/native", env!("CARGO_PKG_VERSION"));
    let mut capabilities = vec![http];
    let mut unavailable = false;
    if required_browser {
        let browser = if cfg.renderer.is_some() || operator_backend || cfg.launch.cdp_ws_url.is_some() {
            BackendCapabilitiesV1::native_browser_unavailable("operator_backend_capability_unattested")
        } else {
            // A real targetless context exercises this run's admitted pool/proxy settings.
            // Named profile material is never opened by an unauthenticated capability probe.
            let mut context = rc.context_config(crawlx_core::SessionId::new());
            context.browser_profile = None;
            context.incognito = true;
            let acquired = tokio::select! {
                biased;
                () = rc.cancel.cancelled() => return Err(WorkerError::AcquisitionUnavailable("capability probe cancelled")),
                result = tokio::time::timeout(Duration::from_secs(30), rc.pool.acquire(context, false)) => result,
            };
            match acquired {
                Ok(Ok(pooled)) => {
                    let build = pooled.build.clone();
                    let (context, _, capacity) = pooled.into_parts();
                    let closed = tokio::time::timeout(Duration::from_secs(5), context.close()).await;
                    let confirmed = matches!(closed, Ok(Ok(())));
                    capacity.release(confirmed).await?;
                    if confirmed {
                        BackendCapabilitiesV1::native_browser(build)
                    } else {
                        BackendCapabilitiesV1::native_browser_unavailable("probe_context_close_unconfirmed")
                    }
                }
                _ => BackendCapabilitiesV1::native_browser_unavailable("run_context_probe_failed"),
            }
        };
        unavailable = !browser.available;
        capabilities.push(browser);
    }
    let registry: Arc<dyn WorkerRegistry> = if let Some(pg) = &rc.stores.pg {
        Arc::new(pg.clone())
    } else if let Some(memory) = &rc.stores.memory {
        memory.clone()
    } else {
        return Err(WorkerError::AcquisitionUnavailable("worker registry unavailable"));
    };
    if local {
        registry
            .register_worker(rc.worker, "local-executor", env!("CARGO_PKG_VERSION"))
            .await?;
        registry
            .publish_local_acquisition_capabilities(rc.worker, rc.run, &capabilities)
            .await?;
    } else if required_browser {
        // Preserve the startup browser observation for unrelated HTTP-only jobs.
        registry
            .publish_acquisition_capabilities(rc.worker, &capabilities)
            .await?;
    }
    registry
        .publish_data_capabilities(rc.worker, &cfg.data_capabilities()?)
        .await?;
    if unavailable {
        return Err(WorkerError::AcquisitionUnavailable(
            "required native browser unavailable",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[tokio::test]
    async fn parent_attempt_byte_deadline_and_cancel_allowances_never_reset() {
        let mut policy = AcquisitionPolicyV1::default();
        policy.max_attempts = 2;
        policy.max_decoded_bytes = 100;
        let cancel = CancellationToken::new();
        let mut budget = AcquisitionBudgetV1::new(&policy).unwrap();
        budget.reserve(&cancel).unwrap();
        budget.charge_bytes(60);
        let options = budget.options(&FetchOptions::default(), 1000);
        assert_eq!(options.max_body_bytes, Some(40));
        budget.reserve(&cancel).unwrap();
        assert!(matches!(
            budget.reserve(&cancel),
            Err(FetchError::AcquisitionAllowance)
        ));
        let mut expired = AcquisitionBudgetV1::new(&policy).unwrap();
        expired.deadline = Instant::now();
        assert!(matches!(
            expired.reserve(&cancel),
            Err(FetchError::AcquisitionDeadline)
        ));
        let mut cancelled = AcquisitionBudgetV1::new(&policy).unwrap();
        cancel.cancel();
        assert!(matches!(
            cancelled.reserve(&cancel),
            Err(FetchError::AcquisitionCancelled)
        ));
        assert_eq!(cancelled.attempts, 0);
    }
    #[tokio::test]
    async fn combined_http_meta_hop_limit_rejects_before_target_connection() {
        use axum::{http::StatusCode, routing::get, Router};
        use std::sync::atomic::AtomicUsize;
        struct Allow;
        #[async_trait::async_trait]
        impl HopAdmission for Allow {
            async fn admit(
                &self,
                _: &Url,
                _: &FetchOptions,
                _: &mut AcquisitionBudgetV1,
                _: &CancellationToken,
            ) -> Result<(), FetchError> {
                Ok(())
            }
            async fn check_authority(&self) -> Result<(), FetchError> {
                Ok(())
            }
        }
        let target_hits = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&target_hits);
        let app = Router::new()
            .route(
                "/source",
                get(|| async { (StatusCode::FOUND, [("location", "/middle")]) }),
            )
            .route(
                "/middle",
                get(|| async {
                    (
                        [("content-type", "text/html")],
                        "<meta http-equiv=refresh content='0; url=/final'>",
                    )
                }),
            )
            .route(
                "/final",
                get(move || {
                    let observed = Arc::clone(&observed);
                    async move {
                        observed.fetch_add(1, Ordering::AcqRel);
                        "must not connect"
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/source", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut config = crawlx_fetch::FetchConfig::default();
        config.governor.base_delay = Duration::ZERO;
        let fetcher = Fetcher::new(
            config,
            Arc::new(crawlx_policy::egress::EgressPolicy::new(true).with_seed_port(&url)),
            Arc::new(crawlx_fetch::StaticResolver::new()),
        )
        .unwrap();
        let mut policy = AcquisitionPolicyV1::default();
        policy.max_attempts = 8;
        policy.meta_refresh = Some(Default::default());
        let mut budget = AcquisitionBudgetV1::new(&policy).unwrap();
        let cpu = CpuPool::new(&crate::runtime::RuntimeConfig::default());
        let options = FetchOptions {
            max_redirects: Some(1),
            ..FetchOptions::default()
        };
        let result = fetch_native(
            &fetcher,
            &url,
            &options,
            &policy,
            &mut budget,
            &CancellationToken::new(),
            &ExtractOptions::default(),
            &cpu,
            CrawlRunId::new(),
            TenantId::new(),
            &|_, _| {},
            false,
            None,
            Some(&Allow),
        )
        .await;
        let Err(FetchError::MetaRefresh { evidence, source }) = result else {
            panic!("combined HTTP/meta limit did not return typed continuation failure")
        };
        assert!(matches!(*source, FetchError::TooManyRedirects { limit: 1 }));
        assert_eq!(evidence.initial_url.path(), "/middle");
        assert_eq!(evidence.http_redirects[0].status, Some(302));
        assert_eq!(evidence.selected_status, None);
        assert_eq!(target_hits.load(Ordering::Acquire), 0);
        assert_eq!(budget.usage().attempts_reserved, 2);
        assert_eq!(budget.usage().network_requests_reserved, 2);
        server.abort();
    }
    #[tokio::test(start_paused = true)]
    async fn authority_narrowed_deadline_is_not_fabricated_elapsed_time() {
        let policy = AcquisitionPolicyV1::default();
        let allowance = crawlx_core::acquisition::AcquisitionAllowanceV1::new(
            policy.max_attempts,
            policy.max_network_requests,
            policy.max_decoded_bytes,
            30_000,
            Default::default(),
        );
        let mut budget = AcquisitionBudgetV1::from_allowance(&policy, &allowance).unwrap();
        tokio::time::advance(Duration::from_millis(250)).await;
        let url = Url::parse("https://elapsed.example.test/").unwrap();
        let mut receipt = AcquisitionResultV1::new(
            CrawlRunId::new(),
            TenantId::new(),
            url,
            Digest::of("elapsed-fixture", b"request"),
            BackendCapabilitiesV1::native_http("fixture", "1"),
        );
        budget.stamp(&mut receipt);
        assert_eq!(receipt.elapsed_ms, 250);
        assert_eq!(
            receipt.elapsed_scope,
            Some(crawlx_core::acquisition::AcquisitionElapsedScopeV1::CurrentCoordinator)
        );
        assert_eq!(
            budget.reserve(&CancellationToken::new()).unwrap(),
            Duration::from_millis(29_750)
        );
    }
}
