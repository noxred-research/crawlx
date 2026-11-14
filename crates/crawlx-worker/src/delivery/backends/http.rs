//! Bounded HTTP client of the infrastructure sinks (search and analytics engines).
//!
//! The endpoint comes from the operator registry file, never from a crawl or a page, and is
//! trusted infrastructure like the database and the object store, not a crawl target. Redirects
//! and ambient proxies are off, every request has a deadline and a response is read up to a fixed
//! ceiling.

use crate::delivery::DeliveryError;
use bytes::Bytes;
use reqwest::header::{HeaderMap, CONTENT_TYPE};
use reqwest::Method;
use std::time::Duration;
use url::Url;

/// Largest response body read.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Deadline of one request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Cooldown asked of the delivery retry machinery after a server-side failure.
pub(super) const RETRY_AFTER: Duration = Duration::from_secs(30);

/// One reply: status and bounded body.
pub(super) struct Reply {
    pub(super) status: u16,
    pub(super) body: Bytes,
}

impl Reply {
    /// The body as JSON.
    pub(super) fn json(&self) -> Result<serde_json::Value, DeliveryError> {
        serde_json::from_slice(&self.body).map_err(|_| DeliveryError::Rejected("provider_ack_invalid_json"))
    }

    /// Turn a failure status into the error class the retry machinery understands: throttling and
    /// server-side failures retry later, anything else is a rejection.
    pub(super) fn require_success(self) -> Result<Self, DeliveryError> {
        match self.status {
            200..=299 => Ok(self),
            429 | 500..=599 => Err(DeliveryError::ProviderBackoff(RETRY_AFTER)),
            _ => Err(DeliveryError::Rejected("provider_http_status")),
        }
    }
}

#[allow(
    clippy::disallowed_types,
    reason = "infrastructure sinks own the raw reqwest client behind this bounded adapter"
)]
pub(super) struct InfraHttp {
    client: reqwest::Client,
    base: Url,
    headers: HeaderMap,
}

impl std::fmt::Debug for InfraHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfraHttp")
            .field("host", &self.base.host_str())
            .finish_non_exhaustive()
    }
}

impl InfraHttp {
    /// A client for `base` (`http` or `https`, no credentials, query or fragment) sending
    /// `headers` (already resolved from credential references) with every request.
    pub(super) fn new(base: Url, headers: HeaderMap) -> Result<Self, DeliveryError> {
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(DeliveryError::Unavailable("invalid_backend_endpoint"));
        }
        #[allow(
            clippy::disallowed_types,
            reason = "infrastructure sinks own the raw reqwest client behind this bounded adapter"
        )]
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            base,
            headers,
        })
    }

    /// Send one request. `path` starts with `/` and is appended to the endpoint's own path.
    pub(super) async fn send(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        content_type: Option<&str>,
        body: Bytes,
    ) -> Result<Reply, DeliveryError> {
        let mut url = self.base.clone();
        let joined = format!("{}{path}", self.base.path().trim_end_matches('/'));
        url.set_path(&joined);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query.iter().copied());
        }
        let mut request = self.client.request(method, url).headers(self.headers.clone());
        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        let mut response = request.body(body).send().await.map_err(|e| e.without_url())?;
        let status = response.status().as_u16();
        let mut collected = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.without_url())? {
            if collected.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(DeliveryError::Rejected("provider_ack_too_large"));
            }
            collected.extend_from_slice(&chunk);
        }
        Ok(Reply {
            status,
            body: Bytes::from(collected),
        })
    }
}
