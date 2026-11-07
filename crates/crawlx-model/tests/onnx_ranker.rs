#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! ONNX ranker pipeline (tokenize → logits → calibration → gate) over `MockOnnx`.

mod common;

use common::request;
use crawlx_model::breaker::BreakerConfig;
use crawlx_model::calibration::{Gate, TemperatureScaler};
use crawlx_model::onnx_ranker::{
    MockOnnx, OnnxRankerConfig, OnnxRankerEngine, TensorInput, CLS_ID, OPTION_ID,
};
use crawlx_model::{CandidateRef, DecisionEngine, GuardConfig, ModelError, ModelId, TypedAnswer};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn ranker_model() -> ModelId {
    ModelId::new("onnx-ranker", "browser-ranker", "b3:feedbeef", "cal-v3")
}

/// Choice rows: none + 3 candidates; score rows: 3 levels; noul rows: 2.
fn scripted() -> MockOnnx {
    MockOnnx::new(|input| match input.rows {
        4 => Ok(vec![0.0, -1.0, 6.0, -1.0]),
        3 => Ok(vec![0.0, 0.0, 4.0]),
        2 => Ok(vec![-3.0, 3.0]),
        n => Err(ModelError::Malformed(format!("unexpected row count {n}"))),
    })
}

fn engine(session: MockOnnx, scaler: TemperatureScaler) -> OnnxRankerEngine {
    let mut cfg = OnnxRankerConfig::new(ranker_model());
    cfg.scaler = scaler;
    OnnxRankerEngine::new(Arc::new(session), cfg)
}

#[tokio::test]
async fn pipeline_calibrates_gates_and_answers_every_question() {
    let d = engine(scripted(), TemperatureScaler::default())
        .decide(request(3))
        .await
        .unwrap();
    assert_eq!(d.model, ranker_model());
    assert_eq!(d.selected("next_action"), Some(CandidateRef(1)));
    assert!(d.abstained.is_empty());
    let Some(TypedAnswer::Choice { probs, none_p, .. }) = d.answer("next_action") else {
        panic!()
    };
    let sum: f32 = probs.iter().map(|(_, p)| p).sum::<f32>() + none_p;
    assert!((sum - 1.0).abs() < 1e-5);
    assert!(probs[1].1 > 0.97);
    let Some(TypedAnswer::Score {
        level, distribution, ..
    }) = d.answer("risk")
    else {
        panic!()
    };
    assert_eq!(*level, 2);
    assert!((distribution.iter().sum::<f32>() - 1.0).abs() < 1e-5);
    let Some(TypedAnswer::Noul { p_yes, .. }) = d.answer("modal_blocking") else {
        panic!()
    };
    assert!(*p_yes > 0.99);
}

#[tokio::test]
async fn higher_temperature_lowers_confidence_until_the_gate_abstains() {
    let hot = TemperatureScaler::new(6.0).unwrap();
    let d = engine(scripted(), hot).decide(request(3)).await.unwrap();
    assert_eq!(d.abstained, ["next_action"]);
    assert_eq!(d.selected("next_action"), None);
}

#[tokio::test]
async fn stricter_gate_abstains_on_the_same_logits() {
    let mut cfg = OnnxRankerConfig::new(ranker_model());
    cfg.gate = Gate {
        p_top_min: 0.999,
        ..Gate::default()
    };
    let eng = OnnxRankerEngine::new(Arc::new(scripted()), cfg);
    let d = eng.decide(request(3)).await.unwrap();
    assert_eq!(d.selected("next_action"), None);
}

#[tokio::test]
async fn session_sees_one_row_per_alternative_with_the_none_row_first() {
    let seen: Arc<Mutex<Vec<TensorInput>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let session = MockOnnx::new(move |input| {
        sink.lock().unwrap().push(input.clone());
        Ok(vec![0.0; input.rows])
    });
    engine(session, TemperatureScaler::default())
        .decide(request(3))
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.iter().map(|t| t.rows).collect::<Vec<_>>(), [4, 3, 2]);
    for t in seen.iter() {
        for r in 0..t.rows {
            let row = t.row(r);
            assert_eq!(row[0], CLS_ID);
            assert_eq!(row.iter().filter(|&&i| i == OPTION_ID).count(), 1);
        }
    }
    // Rows 1.. of the choice batch differ (different candidates); row 0 is the fixed `none` row.
    assert_ne!(seen[0].row(1), seen[0].row(2));
    assert_ne!(seen[0].row(0), seen[0].row(1));
}

#[tokio::test]
async fn session_failures_are_typed_and_count_against_the_breaker() {
    let session = MockOnnx::failing(ModelError::RuntimeUnavailable("no runtime".into()));
    let probe = session.clone();
    let mut cfg = OnnxRankerConfig::new(ranker_model());
    cfg.guard = GuardConfig {
        timeout: Duration::from_millis(300),
        max_concurrent: 1,
        breaker: BreakerConfig::default(),
    };
    let eng = OnnxRankerEngine::new(Arc::new(session), cfg);
    for _ in 0..5 {
        assert!(matches!(
            eng.decide(request(3)).await,
            Err(ModelError::RuntimeUnavailable(_))
        ));
    }
    assert_eq!(eng.decide(request(3)).await.unwrap_err(), ModelError::BreakerOpen);
    assert_eq!(probe.calls(), 5, "no inference after the breaker opened");
}

#[tokio::test]
async fn slow_inference_times_out() {
    let session = scripted().with_delay(Duration::from_millis(250));
    let mut cfg = OnnxRankerConfig::new(ranker_model());
    cfg.guard = GuardConfig {
        timeout: Duration::from_millis(30),
        max_concurrent: 1,
        breaker: BreakerConfig::default(),
    };
    let eng = OnnxRankerEngine::new(Arc::new(session), cfg);
    assert_eq!(
        eng.decide(request(3)).await.unwrap_err(),
        ModelError::Timeout { after_ms: 30 }
    );
}

#[tokio::test]
async fn bad_logits_are_rejected() {
    for (name, logits) in [
        ("wrong count", vec![0.0, 1.0]),
        ("nan", vec![0.0, f32::NAN, 1.0, 2.0]),
        ("inf", vec![f32::INFINITY, 0.0, 0.0, 0.0]),
    ] {
        let err = engine(MockOnnx::fixed(logits), TemperatureScaler::default())
            .decide(request(3))
            .await
            .unwrap_err();
        assert!(matches!(err, ModelError::Malformed(_)), "{name}: {err:?}");
    }
}

#[tokio::test]
async fn oversized_requests_and_invalid_requests_do_not_reach_the_session() {
    let session = MockOnnx::fixed(vec![0.0; 4]);
    let probe = session.clone();
    let eng = engine(session, TemperatureScaler::default());
    let mut req = request(3);
    req.questions = vec![crawlx_model::TypedQuestion::Choice {
        id: "q".into(),
        options: vec![CandidateRef(5)],
    }];
    assert!(matches!(
        eng.decide(req).await,
        Err(ModelError::InvalidRequest(_))
    ));
    // 20 candidates need 21 rows; a session limited to 5 rows refuses before running.
    struct Small;
    impl crawlx_model::onnx_ranker::OnnxSession for Small {
        fn max_rows(&self) -> usize {
            5
        }
        fn run(&self, _: &TensorInput) -> Result<Vec<f32>, ModelError> {
            Err(ModelError::Malformed("must not run".into()))
        }
    }
    let eng = OnnxRankerEngine::new(Arc::new(Small), OnnxRankerConfig::new(ranker_model()));
    assert!(
        matches!(eng.decide(request(20)).await, Err(ModelError::InvalidRequest(m)) if m.contains("rows"))
    );
    assert_eq!(probe.calls(), 0);
}
