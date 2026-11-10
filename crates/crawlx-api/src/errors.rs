//! Error envelope: `{error:{code,message,requestId,retryable,details[]}}`.

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use crawlx_core::StoreError;
use serde::Serialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

/// Startup / serving failures (`run`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApiError {
    /// The listen socket could not be bound.
    #[error("cannot bind {0}")]
    Bind(SocketAddr, #[source] std::io::Error),
    /// The HTTP server stopped with an I/O failure while serving.
    #[error("server failed")]
    Serve(#[source] std::io::Error),
    /// A repository or artifact store failed during startup or bootstrap.
    #[error("storage failure")]
    Store(#[from] StoreError),
    /// The configuration is unusable (for example a malformed bootstrap API key).
    #[error("configuration: {0}")]
    Config(String),
    /// Operator request-identity key configuration is invalid or unreadable.
    #[error("configuration: {0}")]
    RequestIdentityKey(#[from] crawlx_core::secret::RequestIdentityKeyError),
    /// A file containing the restricted API database DSN could not be read.
    #[error("cannot read API database secret file {path:?}")]
    SecretFile {
        /// Secret file path; its contents are never included in diagnostics.
        path: std::path::PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
}

/// One `details[]` entry.
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct Detail {
    /// JSON Pointer to the offending request field (`/safety/profile`); empty for the whole body.
    pub path: String,
    /// Stable machine-readable violation code (`required`, `out_of_range`, ...).
    pub code: String,
    /// Human-readable explanation; never contains secrets or page content.
    pub message: String,
}

impl Detail {
    /// A violation at JSON Pointer `path` with machine code `code`.
    #[must_use]
    pub fn new(path: impl Into<String>, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            code: code.into(),
            message: message.into(),
        }
    }
}

/// A request failure rendered as the error envelope.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HttpError {
    /// HTTP status of the response.
    pub status: StatusCode,
    /// Stable machine-readable error code.
    pub code: &'static str,
    /// Human-readable summary; never contains secrets or page content.
    pub message: String,
    /// Whether the client may retry the identical request later.
    pub retryable: bool,
    /// Per-field violations (validation failures only).
    pub details: Vec<Detail>,
    /// Seconds for the `Retry-After` header on `429`/`503` responses.
    pub retry_after: Option<u64>,
    /// The job a conflict is about: the `id` of the compat error body of a reused
    /// `x-request-id` (`request_in_flight`, `duplicate_request`).
    pub job_id: Option<String>,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.status.as_u16(), self.code, self.message)
    }
}

impl std::error::Error for HttpError {}

/// Rendered by the envelope middleware once the request id is known.
#[derive(Clone)]
pub(crate) struct ErrorParts(pub Arc<HttpError>);

impl HttpError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retryable,
            details: Vec::new(),
            retry_after: None,
            job_id: None,
        }
    }

    /// Name `job` as the job this conflict is about (rendered as `id` on the facade).
    #[must_use]
    pub fn with_job_id(mut self, job: impl ToString) -> Self {
        self.job_id = Some(job.to_string());
        self
    }

    /// `409 request_in_flight` (the compat API): a request with this `x-request-id` or
    /// `Idempotency-Key` is still being processed.
    #[must_use]
    pub fn request_in_flight() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "request_in_flight",
            "a request with this x-request-id is still being processed",
            true,
        )
    }

    /// `409 duplicate_request` (the compat API): this `x-request-id` was already used with different
    /// parameters.
    #[must_use]
    pub fn duplicate_request() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "duplicate_request",
            "this x-request-id was already used with different parameters",
            false,
        )
    }

    /// `400 malformed_request`: not JSON, bad encoding or a tampered cursor.
    #[must_use]
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "malformed_request", message, false)
    }

    /// `401 unauthenticated`: missing, invalid or revoked API key.
    #[must_use]
    pub fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "missing, invalid or revoked API key",
            false,
        )
    }

    /// `403 scope_missing`: the key lacks `scope`.
    #[must_use]
    pub fn scope_missing(scope: &str) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "scope_missing",
            format!("the API key lacks the {scope} scope"),
            false,
        )
    }

    /// `404 not_found` for `what` (absent, expired, or owned by another tenant).
    #[must_use]
    pub fn not_found(what: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("{what} not found"),
            false,
        )
    }

    /// `405 method_not_allowed`.
    #[must_use]
    pub fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "method not allowed for this resource",
            false,
        )
    }

    /// `409 invalid_state`: the verb is not valid in the resource's current status.
    #[must_use]
    pub fn invalid_state(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "invalid_state", message, false)
    }

    /// `409 engine_mismatch`: the tenant's `engine` flag routes this request elsewhere
    /// (the strangler gateway); the gateway must send it to the compat API or mirror it as a shadow.
    #[must_use]
    pub fn engine_mismatch(engine: &str, shadow: bool) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "engine_mismatch",
            format!(
                "tenant engine is `{engine}`; this {} request is not served by crawlx",
                if shadow { "shadow" } else { "non-shadow" }
            ),
            false,
        )
    }

    /// `409 approval_not_pending`: the approval was already decided or expired.
    #[must_use]
    pub fn approval_not_pending(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "approval_not_pending", message, false)
    }

    /// `409 idempotency_in_progress`: a request with the same key is still executing.
    #[must_use]
    pub fn idempotency_in_progress() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "idempotency_in_progress",
            "a request with this Idempotency-Key is still executing",
            true,
        )
    }

    /// `422 idempotency_key_reuse`: the `Idempotency-Key` was already used with a different
    /// request body.
    #[must_use]
    pub fn idempotency_key_reuse() -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "idempotency_key_reuse",
            "this Idempotency-Key was used with a different request",
            false,
        )
    }

    /// `410 expired`: the resource was purged by retention.
    #[must_use]
    pub fn expired(message: impl Into<String>) -> Self {
        Self::new(StatusCode::GONE, "expired", message, false)
    }

    /// `410 artifact_unavailable`: the artifact is purged, ZDR, or credential-bearing.
    #[must_use]
    pub fn artifact_unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::GONE, "artifact_unavailable", message, false)
    }

    /// `413 payload_too_large`: the request body exceeds `limit` bytes.
    #[must_use]
    pub fn payload_too_large(limit: usize) -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("request body exceeds {limit} bytes"),
            false,
        )
    }

    /// `422 validation_failed` carrying every violation.
    #[must_use]
    pub fn validation(details: Vec<Detail>) -> Self {
        let code = if !details.is_empty() && details.iter().all(|d| d.code == "url_denied") {
            "url_denied"
        } else if !details.is_empty() && details.iter().all(|d| d.code == "authorization_required") {
            "authorization_required"
        } else {
            "validation_failed"
        };
        let message = match code {
            "url_denied" => "a URL was rejected by the egress policy",
            "authorization_required" => "the request needs a valid authorization record",
            _ => "request body failed validation",
        };
        let mut e = Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, message, false);
        e.details = details;
        e
    }

    /// `422 invalid_request` carrying every violation: a body that is not a valid authorization
    /// record (unknown field, missing key, failed structural validation, tenant mismatch).
    #[must_use]
    pub fn invalid_request(details: Vec<Detail>) -> Self {
        let mut e = Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "the request body is not a valid authorization record",
            false,
        );
        e.details = details;
        e
    }

    /// `422 ownership_unverified`: the record's ownership proof did not hold; `details` names each
    /// host or origin and why.
    #[must_use]
    pub fn ownership_unverified(details: Vec<Detail>) -> Self {
        let mut e = Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ownership_unverified",
            "the ownership proof of the authorization record did not verify",
            true,
        );
        e.details = details;
        e
    }

    /// `409 authorization_exists`: the record id is taken by another body; records are immutable
    /// and an amendment is a new record id.
    #[must_use]
    pub fn authorization_exists() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "authorization_exists",
            "an authorization record with this id already exists with a different body; records are \
             immutable, an amendment is a new record id with version + 1",
            false,
        )
    }

    /// `429 rate_limited`: the token bucket is empty; retry after `retry_after_secs` (at least 1).
    #[must_use]
    pub fn rate_limited(retry_after_secs: u64) -> Self {
        let mut e = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "rate limit exceeded",
            true,
        );
        e.retry_after = Some(retry_after_secs.max(1));
        e
    }

    /// `429 quota_exceeded`: the tenant already has `limit` active runs.
    #[must_use]
    pub fn quota_exceeded(limit: u64) -> Self {
        let mut e = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "quota_exceeded",
            format!("the tenant already has {limit} active runs"),
            true,
        );
        e.retry_after = Some(30);
        e
    }

    /// `500 internal`: details stay in the server log, the client gets the request id only.
    #[must_use]
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
            true,
        )
    }

    /// `429 too_many_streams`: the tenant or run already holds its maximum number of SSE
    /// connections.
    #[must_use]
    pub fn too_many_streams(limit: usize, per: &str) -> Self {
        let mut e = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_streams",
            format!("{per} already has {limit} open event streams"),
            true,
        );
        e.retry_after = Some(5);
        e
    }

    /// `503 unavailable` with `Retry-After: 5`: storage or the scheduler cannot answer now.
    #[must_use]
    pub fn unavailable() -> Self {
        let mut e = Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "storage is temporarily unavailable",
            true,
        );
        e.retry_after = Some(5);
        e
    }

    /// `503 <code>` with `Retry-After: 5`: an optional backend (LLM endpoint, search provider)
    /// is not configured or not reachable; `message` names what to configure.
    #[must_use]
    pub fn backend_unavailable(code: &'static str, message: impl Into<String>) -> Self {
        let mut e = Self::new(StatusCode::SERVICE_UNAVAILABLE, code, message, true);
        e.retry_after = Some(5);
        e
    }

    /// `<status> <code>` for a compat condition without a dedicated constructor
    /// (`unsupported_content_type`, `zdr_unsupported`, ...).
    #[must_use]
    pub fn compat(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self::new(status, code, message, false)
    }

    /// `400 BAD_REQUEST` carrying every violation: the compat API's validation failure
    /// (`{success:false, error:"Bad Request", code:"BAD_REQUEST", details[]}` on the facade).
    #[must_use]
    pub fn bad_request(details: Vec<Detail>) -> Self {
        let mut e = Self::new(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Bad Request", false);
        e.details = details;
        e
    }

    /// The JSON envelope body.
    #[must_use]
    pub fn envelope(&self, request_id: &str) -> Value {
        json!({ "error": {
            "code": self.code,
            "message": self.message,
            "requestId": request_id,
            "retryable": self.retryable,
            "details": self.details,
        }})
    }

    /// compat-facade shape: `{success:false, error:"<message>", code, details, requestId}`,
    /// plus `id` (the job the conflict is about) for a reused request id.
    #[must_use]
    pub fn compat_envelope(&self, request_id: &str) -> Value {
        let mut body = json!({
            "success": false,
            "error": self.message,
            "code": self.code,
            "details": self.details,
            "requestId": request_id,
        });
        if let Some(id) = &self.job_id {
            body["id"] = json!(id);
        }
        body
    }
}

impl From<StoreError> for HttpError {
    fn from(e: StoreError) -> Self {
        match &e {
            StoreError::NotFound { entity, .. } => Self::not_found(entity),
            StoreError::Conflict(m) => Self::invalid_state(m.clone()),
            StoreError::IllegalTransition { from, to } => {
                Self::invalid_state(format!("cannot move a run from {from} to {to}"))
            }
            StoreError::AccessDenied(m) => {
                Self::new(StatusCode::FORBIDDEN, "access_denied", m.clone(), false)
            }
            StoreError::Unavailable(_) => {
                tracing::warn!(error = %e, "storage unavailable");
                Self::unavailable()
            }
            StoreError::ResourceExhausted { .. } => {
                tracing::warn!(error = %e, "worker resource capacity exhausted");
                Self::backend_unavailable("resource_exhausted", "worker resource capacity exhausted")
            }
            StoreError::Database { retryable: true, .. } => {
                tracing::warn!(error = %e, "storage unavailable");
                Self::unavailable()
            }
            StoreError::Database { retryable: false, .. } => {
                tracing::error!(error = %e, "storage error");
                Self::internal()
            }
            StoreError::LeaseLost
            | StoreError::RetentionDenied(_)
            | StoreError::Serialization(_)
            | StoreError::Backend(_) => {
                tracing::error!(error = %e, "storage error");
                Self::internal()
            }
            _ => {
                tracing::error!(error = %e, "unclassified storage error");
                Self::internal()
            }
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = self.status;
        let retry_after = self.retry_after;
        let www = status == StatusCode::UNAUTHORIZED;
        let body = self.envelope("");
        let mut resp = Response::new(Body::from(body.to_string()));
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        if let Some(s) = retry_after {
            if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        if www {
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp.extensions_mut().insert(ErrorParts(Arc::new(self)));
        resp
    }
}

/// Handler result.
pub type ApiResult<T> = Result<T, HttpError>;
