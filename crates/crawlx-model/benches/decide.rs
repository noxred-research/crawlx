//! `calibration_apply`, `tokenize_shortlist`, `mock_engine_decide` and `ort_infer_shortlist16`.
//!
//! Gate: warm local System-1 inference < 100 ms p95 on the reference GPU,
//! measured by `ort_infer_shortlist16`. That group exists only with the `onnx` feature and
//! skips unless `ORT_DYLIB_PATH` names the ONNX Runtime library; the bundle comes from
//! `CRAWLX_MODEL_BUNDLE`, else the committed smoke bundle (whose `max_options` bounds the
//! shortlist). The other groups isolate the Rust-side cost of the pipeline — tokenization,
//! temperature scaling, the confidence gate and the call guard — with no runtime involved.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use crawlx_model::calibration::{Gate, GateDecision, TemperatureScaler};
use crawlx_model::onnx_ranker::{
    tensor_of, HashTokenizer, MockOnnx, OnnxRankerConfig, OnnxRankerEngine, TensorInput, NONE_ROW_TEXT,
};
use crawlx_model::provenance::{Instruction, Provenance, ProvenanceTagged};
use crawlx_model::typed::{CandidateView, RegionSummary};
use crawlx_model::{CandidateRef, DecisionEngine, ModelId, StateView, TypedDecisionRequest, TypedQuestion};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::hint::black_box;
use std::sync::Arc;

/// Shortlist size of the gate row (K ≤ 20).
const SHORTLIST: usize = 16;
/// Rows of logits for `calibration_apply`.
const LOGIT_ROWS: usize = 10_000;

/// SplitMix64 step: a deterministic generator with no `rand` dependency.
fn next_u64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Uniform in `[0, 1)` from 24 random bits.
fn unit(state: &mut u64) -> f32 {
    #[allow(clippy::cast_precision_loss)]
    let bits = (next_u64(state) >> 40) as f32;
    bits / 16_777_216.0
}

/// `rows` rows of `width` logits in `[-4, 4)`: one `none of these` row plus the shortlist.
fn logits(rows: usize, width: usize) -> Vec<Vec<f32>> {
    let mut state = 0x5EED_u64;
    (0..rows)
        .map(|_| (0..width).map(|_| unit(&mut state) * 8.0 - 4.0).collect())
        .collect()
}

fn candidate_texts(n: usize) -> Vec<String> {
    let roles = ["button", "link", "textbox", "checkbox", "menuitem"];
    (0..n)
        .map(|i| {
            format!(
                "{} {} {} | tried {}",
                roles[i % roles.len()],
                [
                    "Save changes",
                    "Open project",
                    "Search orders",
                    "Accept terms",
                    "Next page"
                ][i % 5],
                ["main", "navigation", "banner"][i % 3],
                i % 4
            )
        })
        .collect()
}

/// The context string `OnnxRankerEngine` builds: goal, route, regions and the question id.
fn context() -> String {
    "Pick the next control to exercise. | route /projects/:id | main project list | navigation \
     primary links | question next_action"
        .to_owned()
}

/// Rows as the engine lowers a `Choice` question: `none of these` plus one row per candidate.
fn rows(n: usize) -> Vec<String> {
    let mut rows = vec![NONE_ROW_TEXT.to_owned()];
    rows.extend(candidate_texts(n));
    rows
}

fn request(n: usize) -> TypedDecisionRequest {
    let n_u32 = u32::try_from(n).unwrap();
    TypedDecisionRequest {
        goal: Instruction::from_static("Pick the next control to exercise."),
        state: ProvenanceTagged::new(
            Provenance::PageText,
            StateView {
                route_template: "/projects/:id".to_owned(),
                regions: vec![
                    RegionSummary {
                        name: "main".into(),
                        summary: "project list".into(),
                    },
                    RegionSummary {
                        name: "navigation".into(),
                        summary: "primary links".into(),
                    },
                ],
                candidates: candidate_texts(n)
                    .iter()
                    .map(|t| {
                        let mut parts = t.splitn(2, ' ');
                        let role = parts.next().unwrap_or("button");
                        let text = parts.next().unwrap_or("");
                        CandidateView::new(role, text, Some("main"))
                    })
                    .collect(),
            },
        ),
        questions: vec![TypedQuestion::Choice {
            id: "next_action".into(),
            options: (0..n_u32).map(CandidateRef).collect(),
        }],
    }
}

/// Temperature scaling and the confidence gate over 10k rows of `SHORTLIST + 1` logits.
fn calibration_apply(c: &mut Criterion) {
    let logits = logits(LOGIT_ROWS, SHORTLIST + 1);
    let scaler = TemperatureScaler::new(1.37).unwrap();
    let gate = Gate::default();
    let mut g = c.benchmark_group("calibration_apply");
    g.bench_with_input(BenchmarkId::new("rows", LOGIT_ROWS), &logits, |b, logits| {
        b.iter(|| {
            let mut accepted = 0_u32;
            for row in logits {
                let probs = scaler.apply(black_box(row));
                let (none_p, options) = probs.split_first().unwrap();
                if let GateDecision::Accept(_) = gate.decide_with_abstain(options, *none_p) {
                    accepted += 1;
                }
            }
            accepted
        });
    });
    g.finish();
}

/// `tensor_of` over the hashing tokenizer: 17 rows (`none of these` + 16 candidates), 128 tokens each.
fn tokenize_shortlist(c: &mut Criterion) {
    let tok = HashTokenizer::default();
    let ctx = context();
    let rows = rows(SHORTLIST);
    let mut g = c.benchmark_group("tokenize_shortlist");
    g.bench_with_input(BenchmarkId::new("candidates", SHORTLIST), &rows, |b, rows| {
        b.iter(|| {
            let input: TensorInput = tensor_of(&tok, black_box(&ctx), black_box(rows));
            (
                input.rows,
                input.seq_len,
                input.attention_mask.iter().sum::<i64>(),
            )
        });
    });
    g.finish();
}

/// Scripted session: logit `k/10` for row `k`, so the gate accepts the last option.
fn mock_session() -> MockOnnx {
    MockOnnx::new(|input| {
        Ok((0..input.rows)
            .map(|k| {
                #[allow(clippy::cast_precision_loss)]
                let z = k as f32 / 10.0;
                z
            })
            .collect())
    })
}

/// The whole `decide` path (validation, sanitization, tokenization, guard + blocking pool,
/// calibration, gate) over a scripted session returning fixed logits.
fn mock_engine_decide(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let engine = OnnxRankerEngine::new(
        Arc::new(mock_session()),
        OnnxRankerConfig::new(ModelId::new("onnx-ranker", "bench", "b3:bench", "cal-bench")),
    );
    let req = request(SHORTLIST);
    let mut g = c.benchmark_group("mock_engine_decide");
    g.bench_with_input(BenchmarkId::new("shortlist", SHORTLIST), &req, |b, req| {
        b.iter_batched(
            || req.clone(),
            |req| {
                let d = rt.block_on(engine.decide(req)).unwrap();
                (d.answers.len(), d.abstained.len())
            },
            BatchSize::SmallInput,
        );
    });
    g.finish();
}

#[cfg(feature = "onnx")]
mod ort {
    use super::{context, request, rows, SHORTLIST};
    use crawlx_model::onnx_ranker::{
        BundleTokenizer, OnnxRankerEngine, OnnxSession, OrtSession, ORT_DYLIB_ENV,
    };
    use crawlx_model::{DecisionEngine, GuardConfig, ModelBundle, TypedDecisionRequest};
    use criterion::{BatchSize, BenchmarkId, Criterion};
    use std::hint::black_box;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    const SMOKE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/smoke-bundle");
    const BUNDLE_ENV: &str = "CRAWLX_MODEL_BUNDLE";

    fn env_path(name: &str) -> Option<PathBuf> {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }

    /// Real ONNX Runtime session: `session.run` over the tokenized shortlist and the engine's
    /// end-to-end `decide`. The shortlist is clamped to the bundle's `max_options`.
    pub(super) fn ort_infer_shortlist16(c: &mut Criterion) {
        if env_path(ORT_DYLIB_ENV).is_none() {
            eprintln!("skipping ort_infer_shortlist16: {ORT_DYLIB_ENV} unset");
            return;
        }
        let dir = env_path(BUNDLE_ENV).unwrap_or_else(|| {
            eprintln!("ort_infer_shortlist16: {BUNDLE_ENV} unset; using the smoke bundle {SMOKE}");
            PathBuf::from(SMOKE)
        });
        let bundle = ModelBundle::open(Path::new(&dir)).unwrap();
        let tok = BundleTokenizer::load(&bundle).unwrap();
        let session = OrtSession::load(&bundle).unwrap();
        // One row per candidate plus the `none of these` row.
        let candidates = SHORTLIST.min(session.max_rows().saturating_sub(1));
        let rows = rows(candidates);
        let ctx = context();
        let input = crawlx_model::onnx_ranker::tensor_of(&tok, &ctx, &rows);

        let mut g = c.benchmark_group("ort_infer_shortlist16");
        g.bench_with_input(
            BenchmarkId::new("session_run/rows", input.rows),
            &input,
            |b, input| {
                b.iter(|| session.run(black_box(input)).unwrap().len());
            },
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let engine = OnnxRankerEngine::from_bundle(Path::new(&dir), GuardConfig::local()).unwrap();
        let req = request(candidates);
        g.bench_with_input(
            BenchmarkId::new("engine_decide/candidates", candidates),
            &req,
            |b, req| {
                b.iter_batched(
                    || req.clone(),
                    |req| rt.block_on(engine.decide(req)).unwrap().answers.len(),
                    BatchSize::SmallInput,
                );
            },
        );
        g.finish();
        per_call_latency(&session, &input, &engine, &req, &rt);
    }

    /// Individually timed calls after a warm-up: Criterion's samples are means over batches of
    /// iterations, which smooths out the tail, so the p95 the gate reads comes from
    /// per-call timings. Printed, and written as JSON to `CRAWLX_LATENCY_REPORT` when set.
    fn per_call_latency(
        session: &OrtSession,
        input: &crawlx_model::onnx_ranker::TensorInput,
        engine: &OnnxRankerEngine,
        req: &TypedDecisionRequest,
        rt: &tokio::runtime::Runtime,
    ) {
        let session_ms = time_calls(|| {
            black_box(session.run(black_box(input)).unwrap().len());
        });
        let engine_ms = time_calls(|| {
            black_box(rt.block_on(engine.decide(req.clone())).unwrap().answers.len());
        });
        let summary = |ms: &[f64]| {
            serde_json::json!({
                "calls": ms.len(),
                "p50_ms": nearest_rank(ms, 0.50),
                "p95_ms": nearest_rank(ms, 0.95),
                "p99_ms": nearest_rank(ms, 0.99),
                "max_ms": ms.last().copied().unwrap_or(0.0),
            })
        };
        let report = serde_json::json!({
            "warm_up_calls": WARM_UP,
            "session_run": summary(&session_ms),
            "engine_decide": summary(&engine_ms),
        });
        eprintln!("ort_infer_shortlist16 per-call latency: {report}");
        if let Some(path) = env_path("CRAWLX_LATENCY_REPORT") {
            std::fs::write(&path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        }
    }

    const WARM_UP: usize = 200;
    const CALLS: usize = 2_000;

    /// Wall time in milliseconds of each of [`CALLS`] calls after [`WARM_UP`] untimed ones, ascending.
    fn time_calls(mut call: impl FnMut()) -> Vec<f64> {
        for _ in 0..WARM_UP {
            call();
        }
        let mut ms: Vec<f64> = (0..CALLS)
            .map(|_| {
                let started = Instant::now();
                call();
                started.elapsed().as_secs_f64() * 1e3
            })
            .collect();
        ms.sort_by(f64::total_cmp);
        ms
    }

    /// Nearest-rank percentile `q` of ascending `sorted`.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn nearest_rank(sorted: &[f64], q: f64) -> f64 {
        let rank = (q * sorted.len() as f64).ceil() as usize;
        sorted[rank.clamp(1, sorted.len()) - 1]
    }
}

#[cfg(feature = "onnx")]
criterion_group!(
    benches,
    calibration_apply,
    tokenize_shortlist,
    mock_engine_decide,
    ort::ort_infer_shortlist16
);
#[cfg(not(feature = "onnx"))]
criterion_group!(benches, calibration_apply, tokenize_shortlist, mock_engine_decide);
criterion_main!(benches);
