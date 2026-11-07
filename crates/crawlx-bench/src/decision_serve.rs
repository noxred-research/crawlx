//! A typed-decision endpoint over a model bundle.
//!
//! The wire format is the one `crawlx_model::decision_http::DecisionHttpEngine` speaks, so the worker reaches a
//! served bundle through its ordinary model endpoint (`crawl --model-endpoint URL`): one `POST
//! /v1/decide` with the goal, the provenance-tagged state and the typed questions; the answer
//! carries calibrated probabilities per option plus the `none of these` mass. The server runs
//! the same [`OnnxRankerEngine`] (tokenizer, ONNX session, temperature) as an in-process engine
//! would, on whatever execution provider the session was built with.
//!
//! `GET /health` reports the identity of the served model and the execution provider.

use crate::error::BenchError;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use crawlx_model::decision_http::{served_response, ServedRequest};
use crawlx_model::onnx_ranker::OnnxRankerEngine;
use crawlx_model::{DecisionEngine, ModelError};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// A running endpoint.
pub struct ServeHandle {
    /// `http://host:port/v1/decide`, what `--model-endpoint` takes.
    pub endpoint: String,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl ServeHandle {
    /// Stop accepting requests and wait for the server task.
    pub async fn shutdown(mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for ServeHandle {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

const fn status_of(e: &ModelError) -> StatusCode {
    match e {
        ModelError::InvalidRequest(_) => StatusCode::UNPROCESSABLE_ENTITY,
        ModelError::BreakerOpen | ModelError::Timeout { .. } => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn decide(
    State(engine): State<Arc<OnnxRankerEngine>>,
    Json(req): Json<ServedRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    req.validate().map_err(|e| (status_of(&e), e.to_string()))?;
    let decision = engine
        .decide_parts(&req.goal, req.state.value(), &req.questions)
        .await
        .map_err(|e| (status_of(&e), e.to_string()))?;
    Ok(Json(served_response(&decision)))
}

async fn health(State(engine): State<Arc<OnnxRankerEngine>>) -> Json<serde_json::Value> {
    let id = engine.id();
    Json(serde_json::json!({
        "provider": id.provider,
        "model": id.model,
        "checkpoint_digest": id.checkpoint_digest,
        "calibration_version": id.calibration_version,
    }))
}

/// Serve `engine` on `bind` (port 0 picks a free one) until [`ServeHandle::shutdown`].
///
/// # Errors
/// [`BenchError::Bind`] when binding fails, [`BenchError::LocalAddr`] when the bound address
/// cannot be read.
pub async fn start(engine: Arc<OnnxRankerEngine>, bind: SocketAddr) -> Result<ServeHandle, BenchError> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|source| BenchError::Bind { addr: bind, source })?;
    let addr = listener.local_addr().map_err(BenchError::LocalAddr)?;
    let app = Router::new()
        .route("/v1/decide", post(decide))
        .route("/health", get(health))
        .with_state(engine);
    let stop = CancellationToken::new();
    let task = tokio::spawn({
        let stop = stop.clone();
        async move {
            let served = axum::serve(listener, app)
                .with_graceful_shutdown(stop.cancelled_owned())
                .await;
            if let Err(error) = served {
                tracing::error!(%error, %addr, "model endpoint stopped with an error");
            }
        }
    });
    Ok(ServeHandle {
        endpoint: format!("http://{}:{}/v1/decide", addr.ip(), addr.port()),
        stop,
        task: Some(task),
    })
}
