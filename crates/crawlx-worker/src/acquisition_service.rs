//! Registered HTML service execution under the existing admission and acquisition allowance.
//!
//! This boundary owns no independent retry, session, cookie jar, governor or frontier.

use crate::acquisition::{self, AcquisitionBudgetV1, HopAdmission};
use crate::runtime::CpuPool;
use crawlx_core::{acquisition::AcquisitionPolicyV1, request_controls::RequestControls};
use crawlx_extract::{Document, ExtractOptions};
use crawlx_fetch::{
    acquisition_service::{AcquisitionServiceAdapter, AcquisitionServiceResultV1, AcquisitionServiceScopeV1},
    FetchError, FetchOptions, OriginGovernor, Resolver,
};
use crawlx_policy::egress::EgressPolicy;
use tokio_util::sync::CancellationToken;
use url::Url;

/// A service result and the same native validation/extraction used by direct acquisition.
pub(crate) struct ServiceAcquisition {
    pub acquired: AcquisitionServiceResultV1,
    pub document: Option<crawlx_core::parser_memory::Budgeted<Box<Document>>>,
}

/// Execute one target request; caller owns explicit backend selection and any retry.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_service(
    service: &AcquisitionServiceAdapter,
    scope: &AcquisitionServiceScopeV1,
    target: &Url,
    options: &FetchOptions,
    policy: &AcquisitionPolicyV1,
    budget: &mut AcquisitionBudgetV1,
    egress: &EgressPolicy,
    resolver: &dyn Resolver,
    governor: &OriginGovernor,
    controls: &RequestControls,
    extract: &ExtractOptions,
    cpu: &CpuPool,
    cancel: &CancellationToken,
    admission: &dyn HopAdmission,
    captcha: Option<&crawlx_core::captcha::CaptchaSecrets>,
) -> Result<ServiceAcquisition, FetchError> {
    policy
        .validate()
        .map_err(|_| FetchError::AcquisitionUnavailable)?;
    // This version does not forward caller headers, cookies, unsafe methods, validators,
    // meta-refresh, or prebody callbacks. Never silently omit a requested control.
    if !policy.backend_ids.iter().any(|id| id == "acquisition_service")
        || options.method != http::Method::GET
        || !options.headers.is_empty()
        || options.validators.is_some()
        || options.preflight.is_some()
        || options.header_gate.is_some()
        || policy.meta_refresh.is_some()
        || !controls.headers().is_empty()
        || !controls.cookies().is_empty()
        || controls.user_agent().is_some()
        || controls.skip_tls_verification()
    {
        return Err(FetchError::AcquisitionUnavailable);
    }
    let remaining = budget.preflight(cancel)?;
    tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(FetchError::AcquisitionCancelled),
        result = tokio::time::timeout(remaining, async {
            admission.admit(target, options, budget, cancel).await?;
            admission.check_authority().await
        }) => result.map_err(|_| FetchError::AcquisitionDeadline)??,
    }
    let remaining = budget.reserve(cancel)?;
    budget.reserve_service_request()?;
    let max_body = options
        .max_body_bytes
        .unwrap_or(usize::MAX)
        .min(budget.remaining_bytes());
    let cap = u32::try_from(max_body).map_err(|_| FetchError::AcquisitionAllowance)?;
    let fetched = tokio::select! {
        biased;
        () = cancel.cancelled() => Err(FetchError::AcquisitionCancelled),
        result = acquisition::watch_authority(admission) => result.and(Err(FetchError::AcquisitionCancelled)),
        result = tokio::time::timeout(remaining,
            service.acquire(scope, target, cap, remaining, egress, resolver, governor, cancel)) =>
                result.map_err(|_| FetchError::AcquisitionDeadline).and_then(|response| response.map_err(FetchError::from)),
    };
    let mut acquired = match fetched {
        Ok(result) => result,
        Err(error) => {
            budget.on_fetch_failure(&error, max_body);
            budget.record(
                "acquisition_service",
                None,
                crawlx_core::acquisition::ValidationCategoryV1::TransportError,
            );
            return Err(error);
        }
    };
    budget.charge_bytes(acquired.body.len());
    // Public URLs are evidence, not future dispatch authority. Redact before publishing.
    let requested = acquisition::public_url(&acquired.metadata.requested_url, controls)?;
    acquired.metadata.evidence_truncated |= requested != acquired.metadata.requested_url;
    acquired.metadata.requested_url = requested;
    if let Some(final_url) = &mut acquired.metadata.final_url {
        let projected = acquisition::public_url(final_url, controls)?;
        acquired.metadata.evidence_truncated |= projected != *final_url;
        *final_url = projected;
    }
    let facts = acquisition::context(policy, acquired.metadata.target_status, false);
    let base = acquired
        .metadata
        .final_url
        .clone()
        .unwrap_or_else(|| target.clone());
    let validation = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(FetchError::AcquisitionCancelled),
        result = acquisition::watch_authority(admission) => return result.and(Err(FetchError::AcquisitionCancelled)),
        result = tokio::time::timeout_at(budget.deadline(), acquisition::validate_body(
            acquisition::acquired_body(&acquired.body)?,
            base, acquired.metadata.content_type.clone(), Vec::new(), facts, extract.clone(),
            cpu, controls, captcha, cancel)) => result.map_err(|_| FetchError::AcquisitionDeadline)??,
    };
    acquired.metadata.validation = validation.0;
    acquired.metadata.extraction_succeeded = validation.1.as_ref().map(|_| true);
    budget.record(
        "acquisition_service",
        acquired.metadata.target_status,
        acquired.metadata.validation.category,
    );
    budget.stamp(&mut acquired.metadata);
    acquired
        .metadata
        .bound()
        .map_err(|_| FetchError::AcquisitionUnavailable)?;
    Ok(ServiceAcquisition {
        acquired,
        document: validation.1,
    })
}
