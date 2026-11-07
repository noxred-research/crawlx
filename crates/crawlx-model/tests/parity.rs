//! ONNX Runtime parity and smoke tests.
//!
//! * `onnx_parity_matches_reference` replays `parity/vectors.json` produced by
//!   the reference exporter against a bundle: token ids must be
//!   identical, logits within 1e-4, calibrated probabilities within 1e-5.
//!   Needs `CRAWLX_MODEL_BUNDLE`, `CRAWLX_PARITY_VECTORS` and `ORT_DYLIB_PATH`.
//! * `ort_smoke_model_runs` exercises the real session on the committed smoke
//!   bundle (`tests/fixtures/smoke-bundle`).
//!   Needs only `ORT_DYLIB_PATH`.
//!
//! Every test skips (prints and returns) when its prerequisite is absent.
#![cfg(feature = "onnx")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::request;
use crawlx_model::bundle::ModelBundle;
use crawlx_model::onnx_ranker::{
    tensor_of, BundleTokenizer, OnnxRankerConfig, OnnxRankerEngine, OnnxSession, OptionTokenizer, OrtSession,
    ORT_DYLIB_ENV,
};
use crawlx_model::{DecisionEngine, GuardConfig, ModelError, TypedAnswer};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const SMOKE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/smoke-bundle");

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn runtime_present() -> bool {
    env_path(ORT_DYLIB_ENV).is_some()
}

#[derive(Deserialize)]
struct Vectors {
    model_digest: String,
    temperature: f32,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    context: String,
    rows: Vec<String>,
    input_ids: Vec<Vec<i64>>,
    attention_mask: Vec<Vec<i64>>,
    logits: Vec<f32>,
    probabilities: Vec<f32>,
}

#[test]
fn onnx_parity_matches_reference() {
    let (Some(bundle_dir), Some(vectors_path)) =
        (env_path("CRAWLX_MODEL_BUNDLE"), env_path("CRAWLX_PARITY_VECTORS"))
    else {
        eprintln!(
            "skipping onnx_parity_matches_reference: CRAWLX_MODEL_BUNDLE / CRAWLX_PARITY_VECTORS unset"
        );
        return;
    };
    let bundle = ModelBundle::open(&bundle_dir).unwrap();
    let vectors: Vectors = serde_json::from_slice(&std::fs::read(&vectors_path).unwrap()).unwrap();
    assert_eq!(
        vectors.model_digest,
        bundle.manifest().files["model.onnx"].to_hex(),
        "parity vectors were produced for a different model.onnx"
    );
    let scaler = bundle.scaler().unwrap();
    assert!((bundle.calibration().temperature - vectors.temperature).abs() < 1e-9);
    let tokenizer = BundleTokenizer::load(&bundle).unwrap();
    let session = OrtSession::load(&bundle).unwrap();
    assert!(
        vectors.cases.len() >= 512,
        "parity corpus has {} cases, planning default is 512",
        vectors.cases.len()
    );

    let mut worst_logit = 0.0_f32;
    let mut worst_prob = 0.0_f32;
    let (mut top1_agree, mut top3_cases, mut top3_agree, mut top3_ties) =
        (0_usize, 0_usize, 0_usize, 0_usize);
    for case in &vectors.cases {
        // Tokenization parity: byte-identical ids and mask.
        let input = tensor_of(&tokenizer, &case.context, &case.rows);
        for (r, (ids, mask)) in case.input_ids.iter().zip(&case.attention_mask).enumerate() {
            assert_eq!(
                input.row(r),
                ids.as_slice(),
                "{}: token ids of row {r}",
                case.name
            );
            assert_eq!(
                input.mask_row(r),
                mask.as_slice(),
                "{}: mask of row {r}",
                case.name
            );
        }
        // Numeric parity.
        let logits = session.run(&input).unwrap();
        assert_eq!(logits.len(), case.logits.len(), "{}: logit count", case.name);
        for (z, want) in logits.iter().zip(&case.logits) {
            let d = (z - want).abs();
            worst_logit = worst_logit.max(d);
            assert!(
                d <= 1e-4,
                "{}: logit {z} vs reference {want} (diff {d})",
                case.name
            );
        }
        let probs = scaler.apply(&logits);
        for (p, want) in probs.iter().zip(&case.probabilities) {
            let d = (p - want).abs();
            worst_prob = worst_prob.max(d);
            assert!(
                d <= 1e-5,
                "{}: probability {p} vs reference {want} (diff {d})",
                case.name
            );
        }
        let top1 = |v: &[f32]| {
            v.iter()
                .enumerate()
                .fold(0, |b, (i, x)| if *x > v[b] { i } else { b })
        };
        assert_eq!(
            top1(&logits),
            top1(&case.logits),
            "{}: top-1 agreement",
            case.name
        );
        top1_agree += 1;
        // identical top-3 set on at least 99.9 % of the inputs, ties excluded
        // (a case whose reference logits tie between the 3rd and 4th place has no defined set)
        let order = |v: &[f32]| {
            let mut idx: Vec<usize> = (0..v.len()).collect();
            idx.sort_by(|a, b| v[*b].total_cmp(&v[*a]).then(a.cmp(b)));
            idx
        };
        if case.logits.len() > 3 {
            let reference = order(&case.logits);
            if (case.logits[reference[2]] - case.logits[reference[3]]).abs() <= 1e-6 {
                top3_ties += 1;
            } else {
                top3_cases += 1;
                let mut ours: Vec<usize> = order(&logits)[..3].to_vec();
                let mut want: Vec<usize> = reference[..3].to_vec();
                ours.sort_unstable();
                want.sort_unstable();
                top3_agree += usize::from(ours == want);
            }
        }
    }
    eprintln!(
        "parity over {} cases: max |logit diff| {worst_logit:.2e}, max |prob diff| {worst_prob:.2e}, top-1 agreement {top1_agree}/{}, top-3 set agreement {top3_agree}/{top3_cases} ({top3_ties} ties excluded)",
        vectors.cases.len(),
        vectors.cases.len()
    );
    assert!(
        top3_cases == 0 || top3_agree as f64 / top3_cases as f64 >= 0.999,
        "top-3 set agreement {top3_agree}/{top3_cases}"
    );
    if let Some(path) = env_path("CRAWLX_PARITY_REPORT") {
        let report = serde_json::json!({
            "schema": "onnx-parity/v1",
            "model_digest": vectors.model_digest,
            "temperature": vectors.temperature,
            "cases": vectors.cases.len(),
            "max_abs_logit_diff": worst_logit,
            "max_abs_prob_diff": worst_prob,
            "top1_agree": top1_agree,
            "top1_cases": vectors.cases.len(),
            "top3_agree": top3_agree,
            "top3_cases": top3_cases,
            "top3_ties_excluded": top3_ties,
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
}

#[test]
fn bundle_tokenizer_numbers_options_and_blocks_marker_injection() {
    let bundle = ModelBundle::open(Path::new(SMOKE)).unwrap();
    let t = BundleTokenizer::load(&bundle).unwrap();
    assert_eq!((t.max_len(), t.max_rows()), (16, 5));
    let r0 = t.encode_row("Pick the next control", 0, "none of these");
    let r1 = t.encode_row("Pick the next control", 1, "button Save changes");
    let r2 = t.encode_row("Pick the next control", 2, "button Save changes");
    // Same framing: CLS ... SEP marker ... SEP; markers differ by row index.
    assert_eq!(r0[0], r1[0]);
    assert_eq!(r1.last(), r2.last());
    assert_ne!(r1, r2);
    let diff: Vec<usize> = (0..r1.len()).filter(|&i| r1[i] != r2[i]).collect();
    assert_eq!(diff.len(), 1, "exactly the marker differs between rows 1 and 2");
    let marker1 = r1[diff[0]];
    // A text that spells a marker cannot smuggle that marker in.
    let injected = t.encode_row("ctx", 2, "[OPT_1] evil");
    assert!(!injected.contains(&marker1));
    assert_eq!(injected.iter().filter(|&&i| i == r2[diff[0]]).count(), 1);
    // Padding and truncation.
    let long = t.encode_row(&"word ".repeat(50), 1, "a b c d e f g h");
    assert_eq!(long.len(), 16);
    assert_eq!(long.last(), r1.last());
    let input = tensor_of(&t, "ctx", &["none of these".to_owned(), "x".to_owned()]);
    assert_eq!(input.seq_len, 16);
    assert_eq!(
        input.mask_row(0).iter().sum::<i64>(),
        8,
        "CLS ctx SEP marker none of these SEP"
    );
    assert_eq!(input.row(0)[8..], [t.pad_id(); 8]);
}

#[test]
fn ort_session_reports_runtime_unavailable_without_dylib() {
    if runtime_present() {
        eprintln!("skipping ort_session_reports_runtime_unavailable_without_dylib: {ORT_DYLIB_ENV} is set");
        return;
    }
    let bundle = ModelBundle::open(Path::new(SMOKE)).unwrap();
    assert!(matches!(
        OrtSession::load(&bundle),
        Err(ModelError::RuntimeUnavailable(m)) if m.contains(ORT_DYLIB_ENV)
    ));
    assert!(matches!(
        OnnxRankerEngine::from_bundle(Path::new(SMOKE), GuardConfig::local()),
        Err(ModelError::RuntimeUnavailable(_))
    ));
}

#[test]
fn ort_smoke_model_runs() {
    if !runtime_present() {
        eprintln!("skipping ort_smoke_model_runs: {ORT_DYLIB_ENV} unset");
        return;
    }
    let bundle = ModelBundle::open(Path::new(SMOKE)).unwrap();
    let t = BundleTokenizer::load(&bundle).unwrap();
    let session = OrtSession::load(&bundle).unwrap();
    assert_eq!(session.max_rows(), 5);
    for rows in [1, 3, 5] {
        let texts: Vec<String> = (0..rows).map(|i| format!("option {i} button")).collect();
        let input = tensor_of(&t, "Pick the next control | route /shop", &texts);
        let logits = session.run(&input).unwrap();
        assert_eq!(logits.len(), rows);
        for (r, z) in logits.iter().enumerate() {
            // The smoke graph computes sum(input_ids * attention_mask) / 1000 per row.
            let want: i64 = input
                .row(r)
                .iter()
                .zip(input.mask_row(r))
                .map(|(i, m)| i * m)
                .sum();
            #[allow(clippy::cast_precision_loss)]
            let want = want as f32 / 1000.0;
            assert!((z - want).abs() <= 1e-5, "row {r}: {z} vs {want}");
        }
    }
    // A graph input/output name mismatch is a typed error, not a panic.
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(Path::new(SMOKE).join("manifest.json")).unwrap()).unwrap();
    manifest["output"] = "scores".into();
    let dir = tempfile::tempdir().unwrap();
    for name in ["model.onnx", "tokenizer.json", "calibration.json"] {
        std::fs::copy(Path::new(SMOKE).join(name), dir.path().join(name)).unwrap();
    }
    std::fs::write(
        dir.path().join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        OrtSession::load(&ModelBundle::open(dir.path()).unwrap()),
        Err(ModelError::Malformed(m)) if m.contains("scores")
    ));
}

#[tokio::test]
async fn ort_engine_decides_end_to_end_on_the_smoke_bundle() {
    if !runtime_present() {
        eprintln!("skipping ort_engine_decides_end_to_end_on_the_smoke_bundle: {ORT_DYLIB_ENV} unset");
        return;
    }
    let engine = OnnxRankerEngine::from_bundle(Path::new(SMOKE), GuardConfig::local()).unwrap();
    assert_eq!(engine.id().model, "crawlx-smoke");
    let bundle = ModelBundle::open(Path::new(SMOKE)).unwrap();
    let cfg = OnnxRankerConfig::from_bundle(&bundle).unwrap();
    assert_eq!(cfg.model, bundle.model_id());

    // Choice with 2 candidates (3 rows), score (3 rows), noul (2 rows): all within max_rows = 5.
    let decision = engine.decide(request(2)).await.unwrap();
    assert_eq!(decision.answers.len(), 3);
    assert!(matches!(&decision.answers[2], TypedAnswer::Noul { p_yes, .. } if (0.0..=1.0).contains(p_yes)));
    assert_eq!(decision.model, bundle.model_id());

    // More rows than the bundle numbers is an invalid request, never a session call.
    assert!(matches!(
        engine.decide(request(5)).await,
        Err(ModelError::InvalidRequest(_))
    ));
}
