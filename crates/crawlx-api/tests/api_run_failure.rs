#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `GET /v1/crawls/{id}` shows why a run the worker refused ended `failed`.
mod common;

use common::{env, simple_body};
use crawlx_core::counters::{RunFailure, RunFailureCode, RunStatus, TerminalReason};
use crawlx_core::repo::{EventRepo, RunRepo};
use crawlx_core::CrawlRunId;
use serde_json::json;

async fn run_in(e: &common::Env, status: RunStatus, reason: Option<TerminalReason>) -> (String, CrawlRunId) {
    let id = e.create_run(&simple_body()).await;
    let run_id: CrawlRunId = id.parse().unwrap();
    e.store.set_status(run_id, status, reason).await.unwrap();
    (id, run_id)
}

#[tokio::test]
async fn a_refused_run_shows_its_typed_failure() {
    let e = env();
    let (id, run_id) = run_in(&e, RunStatus::Failed, Some(TerminalReason::FatalError)).await;
    let failure = RunFailure::new(
        RunFailureCode::CheckpointKeysRequired,
        "browser checkpoints require a checkpoint key provider",
    );
    e.store
        .append(run_id, RunFailure::EVENT_KIND, failure.event_payload())
        .await
        .unwrap();
    let (status, _, v) = e.get(&format!("/v1/crawls/{id}")).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{v}");
    assert_eq!(v["status"], "failed");
    assert_eq!(v["terminalReason"], "fatal_error");
    assert_eq!(
        v["failure"],
        json!({
            "code": "checkpoint_keys_required",
            "message": "browser checkpoints require a checkpoint key provider"
        })
    );
}

#[tokio::test]
async fn only_failed_fatal_runs_with_a_closed_code_carry_a_failure() {
    let e = env();
    // a failed run that was never refused has nothing to explain
    let (id, _) = run_in(&e, RunStatus::Failed, Some(TerminalReason::FatalError)).await;
    let (_, _, v) = e.get(&format!("/v1/crawls/{id}")).await;
    assert!(v.get("failure").is_none(), "{v}");

    // a code outside the closed vocabulary is never surfaced
    let (id, run_id) = run_in(&e, RunStatus::Failed, Some(TerminalReason::FatalError)).await;
    e.store
        .append(
            run_id,
            RunFailure::EVENT_KIND,
            json!({"failure": {"code": "made_up_code", "message": "x"}}),
        )
        .await
        .unwrap();
    let (_, _, v) = e.get(&format!("/v1/crawls/{id}")).await;
    assert!(v.get("failure").is_none(), "{v}");

    // a run that is not failed does not report one
    let (id, run_id) = run_in(&e, RunStatus::Completed, Some(TerminalReason::FrontierExhausted)).await;
    e.store
        .append(
            run_id,
            RunFailure::EVENT_KIND,
            RunFailure::new(RunFailureCode::ConfigRefused, "stale").event_payload(),
        )
        .await
        .unwrap();
    let (_, _, v) = e.get(&format!("/v1/crawls/{id}")).await;
    assert!(v.get("failure").is_none(), "{v}");

    // the message is bounded
    let (id, run_id) = run_in(&e, RunStatus::Failed, Some(TerminalReason::FatalError)).await;
    e.store
        .append(
            run_id,
            RunFailure::EVENT_KIND,
            json!({"failure": {"code": "config_refused", "message": "m".repeat(5_000)}}),
        )
        .await
        .unwrap();
    let (_, _, v) = e.get(&format!("/v1/crawls/{id}")).await;
    let message = v["failure"]["message"].as_str().unwrap();
    assert_eq!(message.chars().count(), RunFailure::MAX_MESSAGE_CHARS);
}
