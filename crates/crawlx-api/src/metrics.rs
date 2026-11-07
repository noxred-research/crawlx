//! Request metrics and the Prometheus exposition.
//!
//! * [`request_metrics`] is the per-route middleware: it counts
//!   `crawlx.api.requests{route,outcome}` and observes `crawlx.api.request.duration{route}`.
//!   The `route` label is the templated [`MatchedPath`] (`/v1/crawls/{id}`), never the raw
//!   URI, so label cardinality stays bounded; requests no route matched carry
//!   `route="unmatched"`.
//! * [`prometheus`] renders [`Metrics::global`] for `GET /metrics` on the authenticated
//!   router (scope `metrics:read`).
//! * [`serve_metrics`] runs a second, unauthenticated listener exposing only `GET /metrics`.
//!   Because nothing guards it, it refuses any address that is not loopback: the intended
//!   deployment is a scraper sidecar on the same host.

use crate::auth::Principal;
use crate::errors::{ApiError, ApiResult};
use crate::store::Scope;
use axum::body::Body;
use axum::extract::{MatchedPath, Request};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// `route` label of requests that matched no route.
pub const UNMATCHED_ROUTE: &str = "unmatched";

/// Prometheus text exposition format 0.0.4.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// `outcome` label for a response status: 1xx-3xx `ok`, 4xx `client_error`, 5xx `error`.
#[must_use]
pub fn outcome(status: StatusCode) -> &'static str {
    if status.is_client_error() {
        "client_error"
    } else if status.is_server_error() {
        "error"
    } else {
        "ok"
    }
}

/// Middleware counting every request by templated route and outcome and observing its
/// duration. Apply with `Router::layer` on the router that owns the routes so
/// [`MatchedPath`] is present; the fallback has none and is labelled
/// [`UNMATCHED_ROUTE`].
pub async fn request_metrics(req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| UNMATCHED_ROUTE.to_owned(), |m| m.as_str().to_owned());
    let started = Instant::now();
    let resp = next.run(req).await;
    let metrics = Metrics::global();
    metrics
        .counter(names::API_REQUESTS)
        .inc_by(1, &[("route", &route), ("outcome", outcome(resp.status()))]);
    metrics
        .histogram(names::API_REQUEST_DURATION)
        .observe_duration(started.elapsed(), &[("route", &route)]);
    resp
}

/// The exposition as an HTTP response.
#[must_use]
pub fn exposition() -> Response {
    let mut resp = Response::new(Body::from(Metrics::global().render_prometheus()));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(PROMETHEUS_CONTENT_TYPE),
    );
    resp
}

/// `GET /metrics` on the authenticated router.
///
/// # Errors
/// `403 scope_missing` without `metrics:read`.
pub async fn prometheus(Extension(principal): Extension<Principal>) -> ApiResult<Response> {
    principal.require(Scope::MetricsRead)?;
    Ok(exposition())
}

async fn unauthenticated_exposition() -> Response {
    exposition()
}

/// Bind the unauthenticated metrics listener on `bind`.
///
/// The listener carries no authentication, so it is only allowed on a loopback address: a
/// scraper sidecar on the same host reaches it, nothing else does.
///
/// # Errors
/// [`ApiError::Config`] when `bind` is not a loopback address (nothing is bound);
/// [`ApiError::Bind`] when the socket cannot be bound.
pub async fn bind_metrics(bind: SocketAddr) -> Result<TcpListener, ApiError> {
    if !bind.ip().is_loopback() {
        return Err(ApiError::Config(format!(
            "metrics listener {bind} is not a loopback address; the unauthenticated metrics \
             endpoint is only served on loopback for a sidecar scraper"
        )));
    }
    TcpListener::bind(bind).await.map_err(|e| ApiError::Bind(bind, e))
}

/// Serve an unauthenticated `GET /metrics` on `bind` until `shutdown` is cancelled
/// ([`bind_metrics`] followed by [`serve_metrics_on`]).
///
/// # Errors
/// [`ApiError::Config`] when `bind` is not a loopback address (nothing is bound);
/// [`ApiError::Bind`] and [`ApiError::Serve`] for socket failures.
pub async fn serve_metrics(bind: SocketAddr, shutdown: CancellationToken) -> Result<(), ApiError> {
    let listener = bind_metrics(bind).await?;
    serve_metrics_on(listener, shutdown).await
}

/// Serve an unauthenticated `GET /metrics` on an already bound `listener` until `shutdown`
/// is cancelled. [`bind_metrics`] performs the loopback check; callers of this function
/// are responsible for where `listener` is bound.
///
/// # Errors
/// [`ApiError::Serve`] when the listener's address cannot be read or the server stops with an
/// I/O failure.
pub async fn serve_metrics_on(listener: TcpListener, shutdown: CancellationToken) -> Result<(), ApiError> {
    let addr = listener.local_addr().map_err(ApiError::Serve)?;
    tracing::info!(bind = %addr, "crawlx metrics listening");
    let app = Router::new().route("/metrics", get(unauthenticated_exposition));
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .map_err(ApiError::Serve)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn outcome_buckets_by_status_class() {
        assert_eq!(outcome(StatusCode::OK), "ok");
        assert_eq!(outcome(StatusCode::ACCEPTED), "ok");
        assert_eq!(outcome(StatusCode::NOT_MODIFIED), "ok");
        assert_eq!(outcome(StatusCode::UNAUTHORIZED), "client_error");
        assert_eq!(outcome(StatusCode::NOT_FOUND), "client_error");
        assert_eq!(outcome(StatusCode::INTERNAL_SERVER_ERROR), "error");
    }
}
