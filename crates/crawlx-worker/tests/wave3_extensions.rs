//! Deterministic compiled lifecycle, replay and bounded stream acceptance tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::{
    extensions::{
        validate_extension_receipts, ExtensionConfigV1, ExtensionError, ExtensionEventLimitsV1,
        ExtensionEventV1, ExtensionPipelineV1, ExtensionReasonV1, ExtensionResultV1, ExtensionSpecV1,
        ExtensionStageV1, ExtensionTerminalV1, HeaderFactsV1, HeaderPolicyV1,
    },
    hash::Digest,
};
use crawlx_worker::extensions::{extension_result_channel, ExtensionStreamResultV1, RequestLifecycle};
use tokio_util::sync::CancellationToken;

fn annotated(stage: ExtensionStageV1, code: &str, order: i32) -> ExtensionSpecV1 {
    ExtensionSpecV1::new(
        ExtensionConfigV1::Annotate {
            stage,
            code: code.into(),
        },
        order,
    )
}
fn pipeline(entries: Vec<ExtensionSpecV1>) -> ExtensionPipelineV1 {
    let mut pipeline = ExtensionPipelineV1::default();
    pipeline.extensions = entries;
    pipeline
}
fn completed(lifecycle: &mut RequestLifecycle) {
    assert!(lifecycle.finish(ExtensionTerminalV1::Completed).unwrap());
    validate_extension_receipts(&lifecycle.events()).unwrap();
}

#[test]
fn cancellation_executes_real_cleanup_callbacks_in_fixed_order() {
    let pipeline = pipeline(vec![
        annotated(ExtensionStageV1::Error, "on_error", 0),
        annotated(ExtensionStageV1::Skipped, "on_skip", 0),
        annotated(ExtensionStageV1::Terminal, "on_terminal", 0),
        annotated(ExtensionStageV1::Checkpoint, "on_checkpoint", 0),
        annotated(ExtensionStageV1::Close, "on_close", 0),
    ]);
    let mut lifecycle = RequestLifecycle::new(&pipeline).unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        lifecycle.dispatch(ExtensionEventV1::Response, &cancel),
        Err(ExtensionError::Cancelled)
    ));
    completed(&mut lifecycle);
    let events = lifecycle.events();
    assert_eq!(
        events
            .iter()
            .skip(1)
            .map(|receipt| receipt.event.stage())
            .collect::<Vec<_>>(),
        [
            ExtensionStageV1::Error,
            ExtensionStageV1::Skipped,
            ExtensionStageV1::Terminal,
            ExtensionStageV1::Checkpoint,
            ExtensionStageV1::Close,
        ]
    );
    let codes = events
        .iter()
        .flat_map(|receipt| &receipt.callbacks)
        .map(|callback| match &callback.result {
            ExtensionResultV1::Annotation(code) => code.as_str(),
            other => panic!("unexpected callback result: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        codes,
        ["on_error", "on_skip", "on_terminal", "on_checkpoint", "on_close"]
    );
    assert_eq!(
        lifecycle.terminal(),
        Some(ExtensionTerminalV1::Skipped(ExtensionReasonV1::Cancelled))
    );
    RequestLifecycle::validate_replay(&pipeline, ExtensionEventLimitsV1::default(), &events).unwrap();
}

#[test]
fn native_denial_survives_failure_callbacks_cancellation_and_duplicate_finish() {
    let pipeline = pipeline(vec![
        ExtensionSpecV1::new(ExtensionConfigV1::ReadOnly {}, 0),
        ExtensionSpecV1::new(
            ExtensionConfigV1::FailStage {
                stage: ExtensionStageV1::Error,
            },
            0,
        ),
        annotated(ExtensionStageV1::Terminal, "observed", 0),
    ]);
    let mut lifecycle = RequestLifecycle::new(&pipeline).unwrap();
    let cancel = CancellationToken::new();
    assert_eq!(
        lifecycle
            .dispatch(ExtensionEventV1::RequestProposed { read_only: false }, &cancel)
            .unwrap(),
        ExtensionResultV1::Skip(ExtensionReasonV1::PolicyDenied)
    );
    cancel.cancel();
    assert!(matches!(
        lifecycle.dispatch(ExtensionEventV1::BeforeAcquisition, &cancel),
        Err(ExtensionError::PolicyDenied)
    ));
    completed(&mut lifecycle);
    let before = lifecycle.events();
    assert!(!lifecycle
        .finish(ExtensionTerminalV1::Failed(ExtensionReasonV1::Processing))
        .unwrap());
    assert_eq!(lifecycle.events(), before);
    assert!(lifecycle.policy_denied());
    assert_eq!(
        lifecycle.terminal(),
        Some(ExtensionTerminalV1::Skipped(ExtensionReasonV1::PolicyDenied))
    );
    RequestLifecycle::validate_replay(&pipeline, ExtensionEventLimitsV1::default(), &before).unwrap();
}

#[test]
fn callback_failure_and_retry_exhaustion_have_one_typed_terminal() {
    let pipeline = pipeline(vec![ExtensionSpecV1::new(
        ExtensionConfigV1::FailStage {
            stage: ExtensionStageV1::Response,
        },
        0,
    )]);
    let mut lifecycle = RequestLifecycle::new(&pipeline).unwrap();
    assert_eq!(
        lifecycle
            .dispatch(ExtensionEventV1::Response, &CancellationToken::new())
            .unwrap(),
        ExtensionResultV1::Fail(ExtensionReasonV1::HandlerFailed)
    );
    completed(&mut lifecycle);
    assert_eq!(
        lifecycle.terminal(),
        Some(ExtensionTerminalV1::Failed(ExtensionReasonV1::HandlerFailed))
    );
    RequestLifecycle::validate_replay(&pipeline, ExtensionEventLimitsV1::default(), &lifecycle.events())
        .unwrap();

    let mut retry = RequestLifecycle::new(&ExtensionPipelineV1::default()).unwrap();
    retry
        .finish(ExtensionTerminalV1::Failed(ExtensionReasonV1::RetryExhausted))
        .unwrap();
    assert_eq!(
        retry
            .events()
            .iter()
            .filter(|receipt| matches!(receipt.event, ExtensionEventV1::Failed(_)))
            .count(),
        1
    );
    assert_eq!(
        retry
            .events()
            .iter()
            .filter(|receipt| matches!(receipt.event, ExtensionEventV1::Terminal(_)))
            .count(),
        1
    );
    assert_eq!(
        retry.terminal(),
        Some(ExtensionTerminalV1::Failed(ExtensionReasonV1::RetryExhausted))
    );
    validate_extension_receipts(&retry.events()).unwrap();
}

#[test]
fn duplicates_keep_immutable_configuration_and_registration_order_in_both_directions() {
    let entry = annotated(ExtensionStageV1::Response, "stable", 4);
    let mut pipeline = pipeline(vec![entry.clone(), entry]);
    for reverse in [false, true] {
        pipeline.reverse_response = reverse;
        let mut lifecycle = RequestLifecycle::new(&pipeline).unwrap();
        lifecycle
            .dispatch(ExtensionEventV1::Response, &CancellationToken::new())
            .unwrap();
        completed(&mut lifecycle);
        let events = lifecycle.events();
        let registrations = events[1]
            .callbacks
            .iter()
            .map(|callback| callback.registration)
            .collect::<Vec<_>>();
        assert_eq!(registrations, if reverse { vec![1, 0] } else { vec![0, 1] });
        RequestLifecycle::validate_replay(&pipeline, ExtensionEventLimitsV1::default(), &events).unwrap();
    }
    pipeline.extensions[1].config = ExtensionConfigV1::Annotate {
        stage: ExtensionStageV1::Response,
        code: "changed".into(),
    };
    assert!(matches!(pipeline.validate(), Err(ExtensionError::InvalidSpec)));
    pipeline.extensions[1].implementation_version = "2.0.0".into();
    assert!(matches!(pipeline.validate(), Err(ExtensionError::InvalidSpec)));
}

#[test]
fn replay_rejects_gaps_tampering_truncation_and_duplicate_terminal() {
    let pipeline = pipeline(vec![annotated(ExtensionStageV1::Response, "response", 0)]);
    let mut lifecycle = RequestLifecycle::new(&pipeline).unwrap();
    lifecycle
        .dispatch(ExtensionEventV1::Response, &CancellationToken::new())
        .unwrap();
    completed(&mut lifecycle);
    let original = lifecycle.events();
    let check = |events: &[crawlx_core::extensions::ExtensionReceiptV1]| {
        RequestLifecycle::validate_replay(&pipeline, ExtensionEventLimitsV1::default(), events)
    };
    check(&original).unwrap();
    let mut changed = original.clone();
    changed[1].sequence += 1;
    assert!(check(&changed).is_err());
    let mut changed = original.clone();
    changed[1].callbacks[0].result = ExtensionResultV1::Continue;
    assert!(check(&changed).is_err());
    assert!(check(&original[..original.len() - 1]).is_err());
    let mut changed = original.clone();
    changed.push(
        original
            .iter()
            .find(|receipt| matches!(receipt.event, ExtensionEventV1::Terminal(_)))
            .unwrap()
            .clone(),
    );
    assert!(check(&changed).is_err());
    assert!(validate_extension_receipts(&changed).is_err());
}

#[test]
fn count_and_serialized_capacity_reserve_cleanup_and_survive_draining() {
    let pipeline = ExtensionPipelineV1::default();
    let limits = ExtensionEventLimitsV1::new(8, 65_536).unwrap();
    let mut lifecycle = RequestLifecycle::with_limits(&pipeline, limits).unwrap();
    let cancel = CancellationToken::new();
    lifecycle.dispatch(ExtensionEventV1::Response, &cancel).unwrap();
    let first = lifecycle.drain_events();
    assert!(matches!(
        lifecycle.dispatch(ExtensionEventV1::Parse, &cancel),
        Err(ExtensionError::Limit)
    ));
    assert_eq!(lifecycle.event_usage().2, 1);
    lifecycle.finish(ExtensionTerminalV1::Completed).unwrap();
    let mut all = first;
    all.extend(lifecycle.drain_events());
    assert!(all.len() <= limits.events);
    assert_eq!(
        lifecycle.terminal(),
        Some(ExtensionTerminalV1::Failed(ExtensionReasonV1::Capacity))
    );
    validate_extension_receipts(&all).unwrap();
    RequestLifecycle::validate_replay(&pipeline, limits, &all).unwrap();

    let entry = annotated(ExtensionStageV1::Response, &"a".repeat(64), 0);
    let dense = {
        let mut dense = ExtensionPipelineV1::default();
        dense.extensions = vec![entry; 32];
        dense
    };
    let limits = ExtensionEventLimitsV1::new(4096, 65_536).unwrap();
    let mut lifecycle = RequestLifecycle::with_limits(&dense, limits).unwrap();
    while lifecycle.dispatch(ExtensionEventV1::Response, &cancel).is_ok() {}
    lifecycle.finish(ExtensionTerminalV1::Completed).unwrap();
    let (count, bytes, refused) = lifecycle.event_usage();
    assert!(count < 4096);
    assert!(bytes <= limits.bytes);
    assert_eq!(refused, 1);
    validate_extension_receipts(&lifecycle.events()).unwrap();
}

#[test]
fn shared_handles_seal_once_and_last_drop_stops_header_admission() {
    let mut owner = RequestLifecycle::new(&ExtensionPipelineV1::default()).unwrap();
    let mut other = owner.clone();
    let gate = owner.header_gate();
    drop(owner.clone());
    gate.check(200, Some("text/html"), Some(1)).unwrap();
    assert_eq!(other.events(), owner.events());
    completed(&mut owner);
    assert!(!other.finish(ExtensionTerminalV1::Completed).unwrap());
    assert!(gate.check(200, Some("text/html"), Some(1)).is_err());
    assert!(matches!(
        other.dispatch(ExtensionEventV1::BeforeAcquisition, &CancellationToken::new()),
        Err(ExtensionError::Closed)
    ));
    let gate = {
        let lifecycle = RequestLifecycle::new(&ExtensionPipelineV1::default()).unwrap();
        lifecycle.header_gate()
    };
    assert!(gate.check(200, Some("text/html"), None).is_err());
}

#[test]
fn admitted_header_gate_projects_only_facts_and_stops_disallowed_response() {
    let mut policy = HeaderPolicyV1::default();
    policy.min_status = 200;
    policy.max_status = 299;
    policy.content_types.insert("text/html".into());
    policy.max_content_length = Some(64);
    let pipeline = pipeline(vec![ExtensionSpecV1::new(
        ExtensionConfigV1::HeaderPolicy { policy },
        0,
    )]);
    assert_eq!(pipeline.header_policies().count(), 1);
    let mut lifecycle = RequestLifecycle::new(&pipeline).unwrap();
    let gate = lifecycle.header_gate();
    gate.check(200, Some("Text/HTML; charset=utf-8"), Some(12))
        .unwrap();
    assert!(gate.check(403, Some("text/html"), Some(12)).is_err());
    assert!(gate.check(200, Some("text/html"), Some(12)).is_err());
    completed(&mut lifecycle);
    assert_eq!(
        lifecycle.terminal(),
        Some(ExtensionTerminalV1::Skipped(ExtensionReasonV1::Rejected))
    );
    let events = lifecycle.events();
    assert_eq!(
        events
            .iter()
            .filter(|receipt| matches!(receipt.event, ExtensionEventV1::HeadersReceived(_)))
            .count(),
        2
    );
    let encoded = serde_json::to_string(&events).unwrap();
    assert!(!encoded.contains("charset"));
    assert!(!encoded.contains("cookie"));
    RequestLifecycle::validate_replay(&pipeline, ExtensionEventLimitsV1::default(), &events).unwrap();
    assert!(HeaderFactsV1::new(200, Some("text/html\r\nx-secret: value"), None).is_err());
    assert!(HeaderFactsV1::new(99, None, None).is_err());
}

#[test]
fn browser_and_document_boundaries_execute_real_selected_callbacks() {
    let stages = [
        ExtensionStageV1::BrowserPreLaunch,
        ExtensionStageV1::BrowserPostLaunch,
        ExtensionStageV1::BrowserPageCreate,
        ExtensionStageV1::BrowserPreNavigation,
        ExtensionStageV1::BrowserPostNavigation,
        ExtensionStageV1::Response,
        ExtensionStageV1::Html,
        ExtensionStageV1::Xml,
        ExtensionStageV1::Parse,
        ExtensionStageV1::Item,
        ExtensionStageV1::Feed,
        ExtensionStageV1::BrowserPageClose,
        ExtensionStageV1::BrowserClose,
    ];
    let events = [
        ExtensionEventV1::BrowserPreLaunch,
        ExtensionEventV1::BrowserPostLaunch,
        ExtensionEventV1::BrowserPageCreate,
        ExtensionEventV1::BrowserPreNavigation,
        ExtensionEventV1::BrowserPostNavigation,
        ExtensionEventV1::Response,
        ExtensionEventV1::Html,
        ExtensionEventV1::Xml,
        ExtensionEventV1::Parse,
        ExtensionEventV1::Item,
        ExtensionEventV1::Feed,
        ExtensionEventV1::BrowserPageClose,
        ExtensionEventV1::BrowserClose,
    ];
    let pipeline = pipeline(
        stages
            .into_iter()
            .map(|stage| annotated(stage, "called", 0))
            .collect(),
    );
    let mut lifecycle = RequestLifecycle::new(&pipeline).unwrap();
    for event in events {
        lifecycle.dispatch(event, &CancellationToken::new()).unwrap();
    }
    completed(&mut lifecycle);
    assert_eq!(
        lifecycle
            .events()
            .iter()
            .flat_map(|receipt| &receipt.callbacks)
            .count(),
        stages.len()
    );
}

#[tokio::test]
async fn slow_consumer_applies_backpressure_without_losing_committed_items() {
    let cancel = CancellationToken::new();
    let (mut sender, mut receiver) = extension_result_channel(1, cancel).unwrap();
    let first = ExtensionStreamResultV1::Committed {
        item: Digest([1; 32]),
    };
    let second = ExtensionStreamResultV1::Committed {
        item: Digest([2; 32]),
    };
    sender.send(first.clone()).await.unwrap();
    {
        let send = sender.send(second.clone());
        tokio::pin!(send);
        tokio::select! {
            biased;
            _ = &mut send => panic!("full bounded channel did not apply backpressure"),
            () = std::future::ready(()) => {}
        }
        assert_eq!(receiver.recv().await, Some(first));
        send.await.unwrap();
    }
    assert_eq!(receiver.recv().await, Some(second));
}

#[tokio::test]
async fn cancellation_returns_unsent_items_and_drains_already_committed_references() {
    let cancel = CancellationToken::new();
    let (mut sender, mut receiver) = extension_result_channel(1, cancel.clone()).unwrap();
    let committed = ExtensionStreamResultV1::Committed {
        item: Digest([3; 32]),
    };
    sender.send(committed.clone()).await.unwrap();
    let unsent = ExtensionStreamResultV1::Committed {
        item: Digest([4; 32]),
    };
    cancel.cancel();
    let error = sender.send(unsent.clone()).await.unwrap_err();
    assert_eq!(error.item, unsent);
    assert!(matches!(error.source, ExtensionError::Cancelled));
    assert_eq!(receiver.recv().await, Some(committed));
    assert_eq!(receiver.recv().await, None);
}

#[tokio::test]
async fn dropped_pending_send_releases_capacity_and_skip_decisions_are_unique() {
    let (mut sender, mut receiver) = extension_result_channel(1, CancellationToken::new()).unwrap();
    let skip = ExtensionStreamResultV1::Skipped {
        decision: 1,
        reason: ExtensionReasonV1::Rejected,
    };
    sender.send(skip.clone()).await.unwrap();
    let next = ExtensionStreamResultV1::Skipped {
        decision: 2,
        reason: ExtensionReasonV1::Rejected,
    };
    {
        let pending = sender.send(next.clone());
        tokio::pin!(pending);
        tokio::select! {
            biased;
            _ = &mut pending => panic!("full stream accepted a second item"),
            () = std::future::ready(()) => {}
        }
    }
    assert_eq!(receiver.recv().await, Some(skip.clone()));
    assert!(matches!(
        sender.send(skip).await.unwrap_err().source,
        ExtensionError::Rejected
    ));
    tokio::time::timeout(std::time::Duration::from_secs(1), sender.send(next.clone()))
        .await
        .unwrap()
        .unwrap();
    receiver.close();
    assert_eq!(receiver.recv().await, Some(next));
    assert_eq!(receiver.recv().await, None);
}

#[test]
fn replay_binds_configuration_even_when_changed_policy_returns_same_result() {
    let original = pipeline(vec![ExtensionSpecV1::new(
        ExtensionConfigV1::HeaderPolicy {
            policy: HeaderPolicyV1::default(),
        },
        0,
    )]);
    let mut lifecycle = RequestLifecycle::new(&original).unwrap();
    lifecycle
        .header_gate()
        .check(200, Some("text/html"), Some(1))
        .unwrap();
    completed(&mut lifecycle);
    let mut changed = original.clone();
    if let ExtensionConfigV1::HeaderPolicy { policy } = &mut changed.extensions[0].config {
        policy.max_status = 399;
    }
    changed.validate().unwrap();
    assert!(RequestLifecycle::validate_replay(
        &changed,
        ExtensionEventLimitsV1::default(),
        &lifecycle.events(),
    )
    .is_err());
}

#[test]
fn concurrent_last_handle_drop_seals_gate_without_reference_count_races() {
    let first = RequestLifecycle::new(&ExtensionPipelineV1::default()).unwrap();
    let second = first.clone();
    let gate = first.header_gate();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            drop(first);
        });
        scope.spawn(|| {
            barrier.wait();
            drop(second);
        });
    });
    assert!(gate.check(200, Some("text/html"), None).is_err());
}

#[test]
fn closed_inputs_and_results_reject_unknown_fields_and_raw_handles() {
    assert!(
        serde_json::from_str::<ExtensionEventV1>(r#"{"kind":"response","rawPage":"forbidden"}"#,).is_err()
    );
    assert!(
        serde_json::from_str::<ExtensionResultV1>(r#"{"kind":"continue","authority":"forbidden"}"#,).is_err()
    );
    assert!(
        serde_json::from_str::<ExtensionEventV1>(r#"{"kind":"arbitrary_callback","facts":{}}"#,).is_err()
    );
}

#[test]
fn fenced_handoff_seals_and_transfers_shared_receipts_once() {
    let mut lifecycle = RequestLifecycle::new(&ExtensionPipelineV1::default()).unwrap();
    let mut peer = lifecycle.clone();
    let (first, receipts) = lifecycle
        .finish_and_drain(ExtensionTerminalV1::Completed)
        .unwrap();
    assert!(first);
    validate_extension_receipts(&receipts).unwrap();
    assert!(peer.events().is_empty());
    let (first, receipts) = peer
        .finish_and_drain(ExtensionTerminalV1::Failed(ExtensionReasonV1::Processing))
        .unwrap();
    assert!(!first);
    assert!(receipts.is_empty());
    assert_eq!(peer.terminal(), Some(ExtensionTerminalV1::Completed));
}
