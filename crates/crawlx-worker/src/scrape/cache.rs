//! Principal-scoped stored responses and strictly offline development replay.
//!
//! Both API fast paths and workers use this implementation. Reads verify source-run
//! ownership, retention, validator/backend identity and every referenced artifact.
use crawlx_core::acquisition::{AcquisitionPolicyV1, AcquisitionResultV1};
use crawlx_core::cache::CacheKeyV1;
use crawlx_core::config::RetentionMode;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ArtifactStore, PageRecord, PageRepo, RunRepo};
use crawlx_core::scrape::{ScrapeDocument, ScrapeOptions};
use crawlx_core::{CanonicalUrl, CrawlRunId, StoreError, TenantId, Timestamp};

const CANDIDATES: u32 = 64;

/// A matching stored response cannot be consumed safely.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    /// Retained metadata exists, but referenced content has expired or disappeared.
    #[error("stored response body unavailable")]
    BodyUnavailable,
    /// Repository or artifact service failure.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl crawlx_core::Classify for CacheError {
    fn class(&self) -> crawlx_core::ErrorClass {
        match self {
            Self::BodyUnavailable => crawlx_core::ErrorClass::Terminal,
            Self::Store(error) => crawlx_core::Classify::class(error),
        }
    }
}

/// Whether a miss must stop without a request, preserving facade compatibility.
#[must_use]
pub fn cache_only(options: &ScrapeOptions) -> bool {
    options
        .cache
        .as_ref()
        .map_or(options.lockdown || options.min_age_ms.is_some(), |p| {
            p.cache_only()
        })
}
/// Whether successful responses may become reusable cache entries.
#[must_use]
pub fn writes(options: &ScrapeOptions) -> bool {
    if (!options.headers.is_empty() && options.cache_header_identity.is_none()) || options.profile.is_some() {
        return false;
    }
    options
        .cache
        .as_ref()
        .map_or(options.store_in_cache, |p| p.writes())
}
/// Whether the request permits retained-response reads.
#[must_use]
pub fn reads(options: &ScrapeOptions) -> bool {
    if (!options.headers.is_empty() && options.cache_header_identity.is_none()) || options.profile.is_some() {
        return false;
    }
    options.cache.as_ref().map_or(
        options.lockdown || options.min_age_ms.is_some() || options.max_age_ms > 0,
        |p| p.reads(),
    )
}

fn acquisition_profile(policy: Option<&AcquisitionPolicyV1>) -> Vec<u8> {
    if policy.is_some_and(|policy| policy.meta_refresh.is_some()) {
        serde_json::to_vec(&(policy, crawlx_core::acquisition::META_REFRESH_RUNTIME_REVISION))
            .unwrap_or_default()
    } else {
        serde_json::to_vec(&policy).unwrap_or_default()
    }
}

/// Execution-derived identity, including the native policy, request identity and revision.
#[must_use]
pub fn key(
    options: &ScrapeOptions,
    policy: Option<&AcquisitionPolicyV1>,
    local_run: CrawlRunId,
) -> CacheKeyV1 {
    let principal = options
        .cache_principal
        .map_or_else(|| format!("local-run:{local_run}"), |id| format!("api-key:{id}"));
    let profile = acquisition_profile(policy);
    let backend = if options.needs_browser()
        || policy.is_some_and(|p| p.backend_ids.iter().any(|id| id == "native_browser"))
    {
        "browser-build-unavailable".to_owned()
    } else {
        format!(
            "crawlx-fetch/{};native-http-capability/1",
            env!("CARGO_PKG_VERSION")
        )
    };
    CacheKeyV1::new(
        principal,
        Digest::of("crawlx/acquisition-profile/v1", &profile),
        backend,
        policy.map_or(0, |p| p.validation.rule_set_version),
        if options.needs_browser() {
            "rendered_dom"
        } else {
            "wire_response"
        }
        .to_owned(),
        options.cache_digest(),
    )
}

/// Return a matching retained scrape. This function never has a network capability.
///
/// # Errors
/// Returns typed missing-body failures and repository failures.
#[allow(clippy::too_many_arguments)]
pub async fn lookup(
    pages: &dyn PageRepo,
    runs: &dyn RunRepo,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    url: &CanonicalUrl,
    options: &ScrapeOptions,
    policy: Option<&AcquisitionPolicyV1>,
    local_run: CrawlRunId,
    now: Timestamp,
) -> Result<Option<PageRecord>, CacheError> {
    if !reads(options) {
        return Ok(None);
    }
    let identity = key(options, policy, local_run);
    // A browser version requested in configuration is not evidence of the executing binary.
    if identity.backend_capability == "browser-build-unavailable" {
        return Ok(None);
    }
    let digest = identity.digest();
    for page in pages.recent_for_url(tenant, url, CANDIDATES).await? {
        let Some(doc) = ScrapeDocument::from_page_metadata(&page.metadata) else {
            continue;
        };
        if doc.not_cacheable || doc.options_digest != digest {
            continue;
        }
        let source = match runs.get_metadata(page.run).await {
            Ok(run) => run,
            Err(StoreError::NotFound { .. }) => continue,
            Err(error) => return Err(error.into()),
        };
        if source.tenant != tenant
            || source.retention.mode == RetentionMode::Zdr
            || source.retention.days == 0
            || source.created_at + chrono::Duration::days(i64::from(source.retention.days)) <= now
        {
            continue;
        }
        if let Some(policy) = policy {
            let Some(value) = page.metadata.get("acquisition") else {
                continue;
            };
            let Ok(acquisition) = serde_json::from_value::<AcquisitionResultV1>(value.clone()) else {
                continue;
            };
            if acquisition.truncated
                || !acquisition.validation.content_accepted
                || acquisition.backend.version != env!("CARGO_PKG_VERSION")
                || acquisition.backend.backend_id != "native_http"
                || !acquisition.backend.available
                || acquisition.representation != crawlx_core::acquisition::RepresentationV1::WireResponse
                || acquisition.validation.rule_set_version != policy.validation.rule_set_version
                || !refresh_compatible(&acquisition, Some(policy))
            {
                continue;
            }
        }
        let age = age_ms(now, page.fetched_at);
        let fresh = options.cache.as_ref().map_or_else(
            || {
                options
                    .min_age_ms
                    .map_or(cache_only(options) || age <= options.max_age_ms, |minimum| {
                        age >= minimum
                    })
            },
            |p| age <= p.max_age_ms,
        );
        if !fresh {
            continue;
        }
        ensure_body(artifacts, &page, &doc).await?;
        return Ok(Some(page));
    }
    Ok(None)
}

/// Resolve every rendition before serving a retained response, including binary formats.
/// # Errors
/// Returns `BodyUnavailable` when content has expired; other backend errors retain their source.
pub async fn ensure_body(
    artifacts: &dyn ArtifactStore,
    page: &PageRecord,
    doc: &ScrapeDocument,
) -> Result<(), CacheError> {
    let mut references = Vec::new();
    references.extend(page.markdown.iter());
    references.extend(page.html.iter());
    for blob in [
        &doc.raw_html,
        &doc.raw_base64,
        &doc.screenshot,
        &doc.audio,
        &doc.video,
    ]
    .into_iter()
    .flatten()
    {
        references.push(&blob.artifact);
    }
    if let Some(actions) = &doc.actions {
        references.extend(
            actions
                .screenshots
                .iter()
                .chain(&actions.pdfs)
                .chain(&actions.virtual_rows)
                .map(|blob| &blob.artifact),
        );
    }
    for reference in references {
        match artifacts.get(reference).await {
            Ok(_) => {}
            Err(
                StoreError::NotFound { .. } | StoreError::RetentionDenied(_) | StoreError::AccessDenied(_),
            ) => return Err(CacheError::BodyUnavailable),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Replay retained response artifacts with explicit provenance and zero network calls.
///
/// # Errors
/// Returns `BodyUnavailable` or a repository error. A miss is `Ok(None)` and never fetches.
#[allow(clippy::too_many_arguments)]
pub async fn replay(
    pages: &dyn PageRepo,
    runs: &dyn RunRepo,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    url: &CanonicalUrl,
    options: &ScrapeOptions,
    policy: Option<&AcquisitionPolicyV1>,
    local_run: CrawlRunId,
    now: Timestamp,
) -> Result<Option<PageRecord>, CacheError> {
    let mut offline = options.clone();
    let mut cache_policy = options.cache.clone().unwrap_or_default();
    cache_policy.development_replay = true;
    offline.cache = Some(cache_policy);
    let Some(mut page) = lookup(
        pages, runs, artifacts, tenant, url, &offline, policy, local_run, now,
    )
    .await?
    else {
        return Ok(None);
    };
    page.metadata["developmentReplay"] = serde_json::json!({
        "version": 1, "provenance": "retained_artifacts", "sourceRun": page.run,
        "sourceFetchedAt": page.fetched_at, "networkRequests": 0,
        "requestIdentity": key(options, policy, local_run).digest(),
    });
    Ok(Some(page))
}

/// Validate an owned retained response through the checked fetcher and the same parent budget.
pub(crate) async fn validate_freshness(
    fetcher: &crawlx_fetch::Fetcher,
    page: &PageRecord,
    options: &ScrapeOptions,
    budget: &mut crate::acquisition::AcquisitionBudgetV1,
    cancel: &tokio_util::sync::CancellationToken,
    observe: &super::FetchObserver<'_>,
) -> Result<bool, crawlx_fetch::FetchError> {
    use crawlx_core::cache::CacheFreshnessV1;
    let freshness = options
        .cache
        .as_ref()
        .map_or(CacheFreshnessV1::Retained, |p| p.freshness);
    if freshness != CacheFreshnessV1::Retained
        && page.metadata.pointer("/acquisition/metaRefreshPolicy").is_some()
    {
        return Err(crawlx_fetch::FetchError::AcquisitionUnavailable);
    }
    if cache_only(options) || freshness == CacheFreshnessV1::Retained {
        return Ok(true);
    }
    let headers = page.metadata.get("response_headers");
    let header = |name: &str| {
        headers
            .and_then(|h| h.get(name))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let validators = crawlx_fetch::Validators {
        etag: header("etag"),
        last_modified: header("last-modified"),
    };
    if validators.is_empty() {
        return Ok(false);
    }
    let expected_final = page
        .metadata
        .get("final_url")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| url::Url::parse(value).ok());
    let Some(expected_final) = expected_final else {
        return Ok(false);
    };
    let mut request = crawlx_fetch::FetchOptions {
        method: if freshness == CacheFreshnessV1::Head {
            http::Method::HEAD
        } else {
            http::Method::GET
        },
        ..crawlx_fetch::FetchOptions::default()
    };
    if freshness == CacheFreshnessV1::ConditionalGet {
        request.validators = Some(validators.clone());
    }
    let timeout = budget.reserve(cancel)?;
    let request = budget.options(&request, fetcher.config().max_body_bytes);
    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(crawlx_fetch::FetchError::AcquisitionCancelled),
        response = tokio::time::timeout(timeout, fetcher.fetch_once(&page.url.url, &request)) =>
            response.map_err(|_| crawlx_fetch::FetchError::AcquisitionDeadline)?,
    };
    observe(&page.url.url, &result);
    let response = result?;
    budget.charge_bytes(response.body.len());
    let current = crawlx_fetch::Validators::from_headers(&response.headers);
    let valid = response.final_url == expected_final
        && if freshness == CacheFreshnessV1::ConditionalGet {
            response.status == http::StatusCode::NOT_MODIFIED
                && current
                    .etag
                    .as_ref()
                    .is_none_or(|value| validators.etag.as_ref() == Some(value))
        } else {
            response.status.is_success()
                && !response.truncated
                && response.content_type == page.content_type
                && if let Some(etag) = &validators.etag {
                    current.etag.as_ref() == Some(etag)
                } else {
                    current.last_modified == validators.last_modified
                }
        };
    budget.record(
        "native_http",
        Some(response.status.as_u16()),
        if valid {
            crawlx_core::acquisition::ValidationCategoryV1::Valid
        } else {
            crawlx_core::acquisition::ValidationCategoryV1::Indeterminate
        },
    );
    Ok(valid)
}

/// Secret-free static acquisition identity, including request route and extraction pipeline.
#[must_use]
pub fn native_key(
    crawl: &crawlx_core::CreateCrawl,
    request: &crawlx_core::request::RequestEnvelopeV1,
    local_run: CrawlRunId,
    credential_identity: Option<Digest>,
) -> CacheKeyV1 {
    let principal = crawl
        .cache_principal
        .map_or_else(|| format!("local-run:{local_run}"), |id| format!("api-key:{id}"));
    let profile = acquisition_profile(crawl.acquisition.as_ref());
    let shape = serde_json::to_vec(&(
        &crawl.extract,
        &crawl.extensions,
        &crawl.protocol,
        &crawl.output.formats,
        &crawl.fetch.user_agent,
        crawl.fetch.skip_tls_verification,
        &crawl.fetch.tls_impersonation,
        &crawl.fetch.identity_profile,
        &crawl.fetch.acquisition_service,
        &request.url,
        &request.method,
        &request.route,
        request.source_key,
        request.session_generation,
        credential_identity,
    ))
    .unwrap_or_default();
    CacheKeyV1::new(
        principal,
        Digest::of("crawlx/acquisition-profile/v1", &profile),
        match crawl.fetch.identity_profile {
            Some(profile) => format!(
                "crawlx-fetch/{};native-http-capability/1;identity/{}",
                env!("CARGO_PKG_VERSION"),
                profile.to_hex()
            ),
            None => format!(
                "crawlx-fetch/{};native-http-capability/1",
                env!("CARGO_PKG_VERSION")
            ),
        },
        crawl
            .acquisition
            .as_ref()
            .map_or(1, |p| p.validation.rule_set_version),
        "wire_response".into(),
        Digest::of("crawlx/native-response-request/v1", &shape),
    )
}

/// Whether native response identity can be correlated without exposing credential hashes.
#[must_use]
pub fn native_eligible(crawl: &crawlx_core::CreateCrawl, credential_identity: Option<Digest>) -> bool {
    // External-service bytes and coherent-identity session bytes are bound to a live actor
    // generation or a third party; neither may be served to or from the shared native cache.
    ((crawl.fetch.extra_headers.is_empty() && crawl.fetch.cookies.is_empty())
        || credential_identity.is_some())
        && crawl.protocol.routes.is_empty()
        && crawl.fetch.acquisition_service.is_none()
        && crawl.fetch.identity_profile.is_none()
}

fn refresh_compatible(metadata: &AcquisitionResultV1, policy: Option<&AcquisitionPolicyV1>) -> bool {
    let effective = policy.and_then(|policy| policy.meta_refresh.as_ref());
    if metadata.meta_refresh_policy.as_ref() != effective
        || (effective.is_some() && metadata.evidence_truncated)
        || metadata.meta_refresh_revision
            != effective.map(|_| crawlx_core::acquisition::META_REFRESH_RUNTIME_REVISION)
    {
        return false;
    }
    match &metadata.meta_refresh {
        None => true,
        Some(evidence) => {
            effective == Some(&evidence.policy)
                && evidence.initial_status >= 200
                && evidence.initial_status < 300
                && evidence.selected_url == metadata.final_url
                && evidence.selected_status == metadata.target_status
                && evidence.http_redirects == metadata.redirects
                && !metadata.evidence_truncated
        }
    }
}
/// Offline native response plus retained producer facts. No new connection evidence is invented.
pub(crate) struct NativeHit {
    pub(crate) page: PageRecord,
    pub(crate) response: crawlx_fetch::FetchResponse,
    pub(crate) metadata: AcquisitionResultV1,
}

/// Read a retained wire response for re-extraction under the current static pipeline.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn lookup_native(
    pages: &dyn PageRepo,
    runs: &dyn RunRepo,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    crawl: &crawlx_core::CreateCrawl,
    request: &crawlx_core::request::RequestEnvelopeV1,
    local_run: CrawlRunId,
    credential_identity: Option<Digest>,
    now: Timestamp,
) -> Result<Option<NativeHit>, CacheError> {
    let Some(policy) = &crawl.cache else {
        return Ok(None);
    };
    if !policy.reads() || !native_eligible(crawl, credential_identity) {
        return Ok(None);
    }
    let identity = native_key(crawl, request, local_run, credential_identity).digest();
    for page in pages.recent_for_url(tenant, &request.url, CANDIDATES).await? {
        let Some(entry) = page.metadata.get("nativeCache") else {
            continue;
        };
        if entry.get("key").and_then(serde_json::Value::as_str) != Some(identity.to_hex().as_str())
            || age_ms(now, page.fetched_at) > policy.max_age_ms
        {
            continue;
        }
        let owner = runs.get_metadata(page.run).await?;
        if owner.tenant != tenant
            || owner.retention.mode == RetentionMode::Zdr
            || owner.retention.days == 0
            || owner.created_at + chrono::Duration::days(i64::from(owner.retention.days)) <= now
        {
            continue;
        }
        let Some(value) = page.metadata.get("acquisition") else {
            continue;
        };
        let Ok(metadata) = serde_json::from_value::<AcquisitionResultV1>(value.clone()) else {
            continue;
        };
        if metadata.truncated
            || !metadata.validation.content_accepted
            || metadata.backend.version != env!("CARGO_PKG_VERSION")
            || metadata.backend.backend_id != "native_http"
            || !metadata.backend.available
            || metadata.representation != crawlx_core::acquisition::RepresentationV1::WireResponse
            || metadata.validation.rule_set_version
                != crawl
                    .acquisition
                    .as_ref()
                    .map_or(1, |p| p.validation.rule_set_version)
            || !refresh_compatible(&metadata, crawl.acquisition.as_ref())
        {
            continue;
        }
        let Some(peer) = metadata.connection.peer else {
            continue;
        };
        let Some(value) = entry.get("wire") else {
            return Err(CacheError::BodyUnavailable);
        };
        let wire: crawlx_core::ArtifactRef =
            serde_json::from_value(value.clone()).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let body = match artifacts
            .read_archive_content(tenant, page.run, &wire, crawl.fetch.max_response_bytes)
            .await
        {
            Ok(body) => body,
            Err(
                StoreError::NotFound { .. } | StoreError::RetentionDenied(_) | StoreError::AccessDenied(_),
            ) => return Err(CacheError::BodyUnavailable),
            Err(error) => return Err(error.into()),
        };
        let final_url = metadata
            .final_url
            .clone()
            .ok_or_else(|| StoreError::Serialization("cached final URL unavailable".into()))?;
        let mut headers = http::HeaderMap::new();
        if let Some(values) = page
            .metadata
            .get("response_headers")
            .and_then(serde_json::Value::as_object)
        {
            for (name, value) in values {
                if let (Ok(name), Some(value)) = (http::HeaderName::try_from(name.as_str()), value.as_str()) {
                    if let Ok(value) = http::HeaderValue::try_from(value) {
                        headers.insert(name, value);
                    }
                }
            }
        }
        let response = crawlx_fetch::FetchResponse {
            final_url,
            status: http::StatusCode::from_u16(page.status)
                .map_err(|e| StoreError::Serialization(e.to_string()))?,
            headers,
            body: bytes::Bytes::from(body),
            body_permit: None,
            wire_bytes: None,
            dns_report: None,
            negotiated_protocol: None,
            truncated: false,
            redirects: Vec::new(),
            hops: Vec::new(),
            resolved_ip: peer,
            peer_observed: false,
            content_type: page.content_type.clone(),
            attempts: 0,
            duration: std::time::Duration::ZERO,
        };
        return Ok(Some(NativeHit {
            page,
            response,
            metadata,
        }));
    }
    Ok(None)
}

/// One exact retained response, not browser action replay or a new acquisition.
#[derive(Debug)]
#[non_exhaustive]
pub struct SavedResponseReplay {
    /// Approved source page and immutable request identity.
    pub page: PageRecord,
    /// Exact identity required by the caller.
    pub identity: Digest,
    /// Retained rendition, explicitly not conflated with wire bytes.
    pub representation: &'static str,
    /// Retention-approved content bytes; never a newly fetched body.
    pub body: Vec<u8>,
}

/// Pure development replay of one committed response with an exact saved request identity.
/// No fetcher, browser, provider or secret resolver is accepted by this function.
///
/// # Errors
/// Returns ownership/identity/retention denial, missing-body or storage errors.
#[allow(clippy::too_many_arguments)]
pub async fn replay_saved_response(
    pages: &dyn PageRepo,
    runs: &dyn RunRepo,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    run: CrawlRunId,
    frontier: i64,
    identity: Digest,
    principal: Option<uuid::Uuid>,
    now: Timestamp,
    max_bytes: u64,
) -> Result<SavedResponseReplay, CacheError> {
    let owner = runs.get(run).await?;
    let source_principal = owner.config.cache_principal.or_else(|| {
        owner
            .config
            .scrape
            .as_ref()
            .and_then(|j| j.options.cache_principal)
    });
    if owner.tenant != tenant || source_principal != principal {
        return Err(StoreError::AccessDenied("saved response principal or tenant mismatch".into()).into());
    }
    if owner.config.retention.mode == RetentionMode::Zdr
        || owner.config.retention.days == 0
        || owner.created_at + chrono::Duration::days(i64::from(owner.config.retention.days)) <= now
    {
        return Err(StoreError::RetentionDenied("saved response source retention expired".into()).into());
    }
    let page = pages
        .get_committed(run, frontier)
        .await?
        .ok_or(CacheError::BodyUnavailable)?;
    let (reference, representation) = if let Some(cache) = page.metadata.get("nativeCache") {
        let key: Digest =
            serde_json::from_value(cache.get("key").cloned().unwrap_or(serde_json::Value::Null))
                .map_err(|_| StoreError::Serialization("saved response identity unavailable".into()))?;
        if key != identity {
            return Err(StoreError::AccessDenied("saved response request identity mismatch".into()).into());
        }
        let wire = serde_json::from_value(cache.get("wire").cloned().unwrap_or(serde_json::Value::Null))
            .map_err(|_| StoreError::Serialization("saved response body reference unavailable".into()))?;
        (wire, "retained_redacted_wire")
    } else {
        let doc = ScrapeDocument::from_page_metadata(&page.metadata).ok_or(CacheError::BodyUnavailable)?;
        if doc.options_digest != identity {
            return Err(StoreError::AccessDenied("saved response request identity mismatch".into()).into());
        }
        if let Some(blob) = doc.raw_base64 {
            (blob.artifact, "retained_response_bytes")
        } else if let Some(blob) = doc.raw_html {
            (
                blob.artifact,
                if owner
                    .config
                    .scrape
                    .as_ref()
                    .is_some_and(|j| j.options.needs_browser())
                {
                    "retained_rendered_dom"
                } else {
                    "retained_redacted_wire"
                },
            )
        } else {
            (
                page.html.clone().ok_or(CacheError::BodyUnavailable)?,
                "retained_cleaned_html",
            )
        }
    };
    let body = artifacts
        .read_archive_content(tenant, run, &reference, max_bytes)
        .await
        .map_err(|error| match error {
            StoreError::NotFound { .. } | StoreError::RetentionDenied(_) => CacheError::BodyUnavailable,
            error => CacheError::Store(error),
        })?;
    Ok(SavedResponseReplay {
        page,
        identity,
        representation,
        body,
    })
}

fn age_ms(now: Timestamp, then: Timestamp) -> u64 {
    u64::try_from((now - then).num_milliseconds()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn facade_and_native_modes_do_not_leak_controls() {
        let mut options = ScrapeOptions {
            lockdown: true,
            store_in_cache: false,
            ..ScrapeOptions::default()
        };
        assert!(cache_only(&options));
        assert!(!writes(&options));
        options.cache = Some(crawlx_core::cache::CachePolicyV1::default());
        assert!(!cache_only(&options));
        assert!(writes(&options));
        options.cache.as_mut().unwrap().mode = crawlx_core::cache::CacheModeV1::ReadOnly;
        assert!(cache_only(&options));
        assert!(!writes(&options));
    }
    #[test]
    fn unbound_local_runs_and_changed_native_policy_never_share_keys() {
        let options = ScrapeOptions::default();
        let first = CrawlRunId::new();
        let second = CrawlRunId::new();
        assert_ne!(
            key(&options, None, first).digest(),
            key(&options, None, second).digest()
        );
        let mut p = AcquisitionPolicyV1::default();
        let original = key(&options, Some(&p), first).digest();
        p.validation.minimum_text_bytes = 80;
        assert_ne!(original, key(&options, Some(&p), first).digest());
    }

    fn native_crawl() -> (crawlx_core::CreateCrawl, crawlx_core::request::RequestEnvelopeV1) {
        let crawl = crawlx_core::CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
        let url = crawlx_url::Canonicalizer::canonicalize_url(
            &url::Url::parse("https://example.test/page").unwrap(),
            &crawlx_url::CanonicalizeOptions::default(),
        )
        .unwrap();
        (crawl, crawlx_core::request::RequestEnvelopeV1::get(url, 0, None))
    }

    #[test]
    fn identity_and_service_selectors_never_share_native_keys_or_eligibility() {
        let run = CrawlRunId::new();
        let (mut crawl, request) = native_crawl();
        let ordinary = native_key(&crawl, &request, run, None);
        assert!(native_eligible(&crawl, None));

        crawl.fetch.identity_profile = Some(
            crawlx_core::identity_profile::IdentityProfileV1::pinned_chromium()
                .digest()
                .unwrap(),
        );
        let coherent = native_key(&crawl, &request, run, None);
        assert_ne!(ordinary.digest(), coherent.digest());
        assert!(
            !native_eligible(&crawl, None),
            "coherent session bytes are never shared"
        );

        crawl.fetch.identity_profile = None;
        crawl.fetch.acquisition_service = Some("render-a".to_owned());
        let service_a = native_key(&crawl, &request, run, None);
        crawl.fetch.acquisition_service = Some("render-b".to_owned());
        let service_b = native_key(&crawl, &request, run, None);
        assert_ne!(ordinary.digest(), service_a.digest());
        assert_ne!(service_a.digest(), service_b.digest());
        assert!(
            !native_eligible(&crawl, None),
            "external-service bytes never enter the native cache"
        );

        crawl.fetch.acquisition_service = None;
        assert_eq!(
            ordinary.digest(),
            native_key(&crawl, &request, run, None).digest()
        );
        assert!(native_eligible(&crawl, None));
    }
}
