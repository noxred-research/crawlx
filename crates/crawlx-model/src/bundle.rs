//! Versioned model artifact bundle.
//!
//! A bundle is a directory holding `model.onnx`, `tokenizer.json`,
//! `calibration.json` and `manifest.json`. [`ModelBundle::open`] parses the
//! manifest, reads every listed file and refuses the bundle when a digest does
//! not match (`crawlx/model-file/v1`-tagged BLAKE3, the same tag the Python
//! exporter that produces bundles uses). Nothing here needs the ONNX
//! Runtime: the session ([`crate::onnx_ranker::OrtSession`]) and the tokenizer
//! ([`crate::onnx_ranker::BundleTokenizer`]) are built from an opened bundle
//! behind the `onnx` feature.

use crate::calibration::TemperatureScaler;
use crate::error::ModelError;
use crate::onnx_ranker::ROW_SIGNALS;
use crate::typed::ModelId;
use crawlx_core::hash::Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Domain tag for model artifact digests.
pub const MODEL_FILE_DOMAIN: &str = "crawlx/model-file/v1";
/// Manifest file name inside a bundle.
pub const MANIFEST_FILE: &str = "manifest.json";
/// ONNX graph file name inside a bundle.
pub const MODEL_FILE: &str = "model.onnx";
/// Tokenizer file name inside a bundle.
pub const TOKENIZER_FILE: &str = "tokenizer.json";
/// Calibration file name inside a bundle.
pub const CALIBRATION_FILE: &str = "calibration.json";
/// Provider recorded in [`ModelId`] for bundles served by the local `ort` session.
pub const BUNDLE_PROVIDER: &str = "onnx-ranker";

/// Files every bundle must list in `manifest.files`.
const REQUIRED_FILES: [&str; 3] = [MODEL_FILE, TOKENIZER_FILE, CALIBRATION_FILE];

/// How option rows are framed for the model (`manifest.option_markers.scheme`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MarkerScheme {
    /// `[CLS] context [SEP] [OPT_k] alternative [SEP]`, `k` = row index.
    #[serde(rename = "numbered-v1")]
    NumberedV1,
}

/// Marker tokens of the `numbered-v1` scheme, by name as they appear in `tokenizer.json`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OptionMarkers {
    /// Framing scheme the tokenizer implements.
    pub scheme: MarkerScheme,
    /// Start-of-row token.
    pub cls: String,
    /// Separator token.
    pub sep: String,
    /// Padding token.
    pub pad: String,
    /// Unknown token; marker ids found inside text spans are rewritten to it.
    pub unk: String,
    /// Prefix of the numbered option marker, e.g. `[OPT_`.
    pub option_prefix: String,
    /// Suffix of the numbered option marker, e.g. `]`.
    pub option_suffix: String,
}

impl OptionMarkers {
    /// Name of the marker token for option row `index`.
    #[must_use]
    pub fn option_token(&self, index: usize) -> String {
        format!("{}{index}{}", self.option_prefix, self.option_suffix)
    }
}

/// Graph input names.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ModelInputs {
    /// `int64 [rows, seq]` token ids.
    pub input_ids: String,
    /// `int64 [rows, seq]` attention mask; `None` for graphs without one.
    #[serde(default)]
    pub attention_mask: Option<String>,
}

/// `manifest.json`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BundleManifest {
    /// Model name, recorded as [`ModelId::model`].
    pub model_id: String,
    /// Bundle version string.
    pub version: String,
    /// ONNX opset the graph was exported with.
    pub opset: u32,
    /// Digest of the training checkpoint (opaque; empty when untrained), recorded as [`ModelId::checkpoint_digest`].
    pub checkpoint_digest: String,
    /// Padded row length the graph was exported for.
    pub max_seq_len: usize,
    /// Most options a choice question may carry; rows per call are `max_options + 1`.
    pub max_options: usize,
    /// Longest share of a row reserved for the alternative text.
    pub max_alternative_tokens: usize,
    /// Graph input names.
    pub inputs: ModelInputs,
    /// Graph output name: `float32 [rows]` or `[rows, 1]`.
    pub output: String,
    /// Marker scheme and token names.
    pub option_markers: OptionMarkers,
    /// Names of the per-candidate row signals the model was trained on, in render order (see
    /// [`ROW_SIGNALS`]). Absent means none. [`ModelBundle::open`] refuses a bundle whose list
    /// differs from what this runtime renders.
    #[serde(default)]
    pub row_signals: Vec<String>,
    /// Digest of every artifact file, keyed by file name.
    pub files: BTreeMap<String, Digest>,
}

impl BundleManifest {
    /// Rows a single session call accepts.
    #[must_use]
    pub const fn max_rows(&self) -> usize {
        self.max_options + 1
    }

    fn validate(&self) -> Result<(), ModelError> {
        for name in REQUIRED_FILES {
            if !self.files.contains_key(name) {
                return Err(ModelError::Malformed(format!(
                    "manifest lists no digest for {name}"
                )));
            }
        }
        if self.max_seq_len < 8 {
            return Err(ModelError::Malformed(format!(
                "max_seq_len {} is below the five-marker minimum of 8",
                self.max_seq_len
            )));
        }
        if self.max_options == 0 {
            return Err(ModelError::Malformed("max_options must be at least 1".to_owned()));
        }
        if self.inputs.input_ids.is_empty() || self.output.is_empty() {
            return Err(ModelError::Malformed(
                "manifest input/output names must not be empty".to_owned(),
            ));
        }
        if self.row_signals != ROW_SIGNALS {
            return Err(ModelError::Malformed(format!(
                "manifest row_signals {:?} differ from the row signals {:?} this runtime renders",
                self.row_signals, ROW_SIGNALS
            )));
        }
        Ok(())
    }
}

/// `calibration.json`: temperature scaling fitted for this bundle version.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CalibrationFile {
    /// Calibration method; only `temperature` is supported.
    pub method: String,
    /// Fitted temperature.
    pub temperature: f32,
    /// Calibration version, recorded as [`ModelId::calibration_version`].
    pub version: String,
}

impl CalibrationFile {
    /// The scaler described by this file.
    ///
    /// # Errors
    /// [`ModelError::Calibration`] for an unsupported method or an unusable temperature.
    pub fn scaler(&self) -> Result<TemperatureScaler, ModelError> {
        if self.method != "temperature" {
            return Err(ModelError::Calibration(format!(
                "unsupported calibration method {:?}",
                self.method
            )));
        }
        TemperatureScaler::new(self.temperature)
    }
}

/// An opened, digest-verified bundle.
#[derive(Clone, Debug)]
pub struct ModelBundle {
    dir: PathBuf,
    manifest: BundleManifest,
    calibration: CalibrationFile,
    model: Vec<u8>,
}

impl ModelBundle {
    /// Open the bundle at `dir`, verifying the digest of every listed file.
    ///
    /// # Errors
    /// [`ModelError::Malformed`] when a file is missing, unreadable, fails its
    /// digest, the manifest/calibration is not usable, or `manifest.row_signals`
    /// differs from [`ROW_SIGNALS`] (a model trained on other row text must not be served).
    pub fn open(dir: &Path) -> Result<Self, ModelError> {
        let manifest: BundleManifest = serde_json::from_slice(&read(dir, MANIFEST_FILE)?)
            .map_err(|e| ModelError::Malformed(format!("{MANIFEST_FILE}: {e}")))?;
        manifest.validate()?;
        let mut model = Vec::new();
        let mut calibration = None;
        for (name, expected) in &manifest.files {
            let bytes = read(dir, name)?;
            verify_artifact(&bytes, expected).map_err(|e| match e {
                ModelError::Malformed(m) => ModelError::Malformed(format!("{name}: {m}")),
                other => other,
            })?;
            match name.as_str() {
                MODEL_FILE => model = bytes,
                CALIBRATION_FILE => {
                    let parsed: CalibrationFile = serde_json::from_slice(&bytes)
                        .map_err(|e| ModelError::Malformed(format!("{CALIBRATION_FILE}: {e}")))?;
                    parsed.scaler()?;
                    calibration = Some(parsed);
                }
                _ => {}
            }
        }
        let calibration = calibration
            .ok_or_else(|| ModelError::Malformed(format!("{CALIBRATION_FILE} missing from bundle")))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            manifest,
            calibration,
            model,
        })
    }

    /// Directory the bundle was opened from.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Parsed manifest.
    #[must_use]
    pub const fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    /// Parsed calibration.
    #[must_use]
    pub const fn calibration(&self) -> &CalibrationFile {
        &self.calibration
    }

    /// Verified `model.onnx` bytes.
    #[must_use]
    pub fn model_bytes(&self) -> &[u8] {
        &self.model
    }

    /// Path of the verified `tokenizer.json`.
    #[must_use]
    pub fn tokenizer_path(&self) -> PathBuf {
        self.dir.join(TOKENIZER_FILE)
    }

    /// Identity recorded on every decision made with this bundle.
    #[must_use]
    pub fn model_id(&self) -> ModelId {
        ModelId::new(
            BUNDLE_PROVIDER,
            &self.manifest.model_id,
            &self.manifest.checkpoint_digest,
            &self.calibration.version,
        )
    }

    /// Temperature scaler shipped with the bundle.
    ///
    /// # Errors
    /// [`ModelError::Calibration`] when the file is unusable (already checked by [`Self::open`]).
    pub fn scaler(&self) -> Result<TemperatureScaler, ModelError> {
        self.calibration.scaler()
    }
}

fn read(dir: &Path, name: &str) -> Result<Vec<u8>, ModelError> {
    std::fs::read(dir.join(name))
        .map_err(|e| ModelError::Malformed(format!("cannot read bundle file {name}: {e}")))
}

/// Check a model file against the digest recorded in the bundle manifest
/// (refuse to load on mismatch).
///
/// # Errors
/// [`ModelError::Malformed`] when the digests differ.
pub fn verify_artifact(bytes: &[u8], expected: &Digest) -> Result<(), ModelError> {
    let actual = Digest::of(MODEL_FILE_DOMAIN, bytes);
    if &actual == expected {
        Ok(())
    } else {
        Err(ModelError::Malformed(format!(
            "model artifact digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const SMOKE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/smoke-bundle");

    fn copy_smoke(to: &Path) {
        for name in [MANIFEST_FILE, MODEL_FILE, TOKENIZER_FILE, CALIBRATION_FILE] {
            std::fs::copy(Path::new(SMOKE).join(name), to.join(name)).unwrap();
        }
    }

    #[test]
    fn artifact_digest_is_verified() {
        let bytes = b"onnx-model-bytes";
        let digest = Digest::of(MODEL_FILE_DOMAIN, bytes);
        assert!(verify_artifact(bytes, &digest).is_ok());
        assert!(
            matches!(verify_artifact(b"tampered", &digest), Err(ModelError::Malformed(m)) if m.contains("mismatch"))
        );
    }

    #[test]
    fn smoke_bundle_opens_and_exposes_its_identity() {
        let b = ModelBundle::open(Path::new(SMOKE)).unwrap();
        let m = b.manifest();
        assert_eq!(
            (m.model_id.as_str(), m.max_options, m.max_seq_len),
            ("crawlx-smoke", 4, 16)
        );
        assert_eq!(m.option_markers.scheme, MarkerScheme::NumberedV1);
        assert_eq!(m.option_markers.option_token(3), "[OPT_3]");
        assert_eq!(m.max_rows(), 5);
        assert_eq!(b.scaler().unwrap(), TemperatureScaler::new(2.0).unwrap());
        let id = b.model_id();
        assert_eq!(
            (id.provider.as_str(), id.model.as_str()),
            ("onnx-ranker", "crawlx-smoke")
        );
        assert_eq!(id.calibration_version, "smoke-1");
        assert!(!b.model_bytes().is_empty());
        assert!(b.tokenizer_path().is_file());
    }

    #[test]
    fn tampered_or_missing_files_refuse_to_load() {
        let dir = tempfile::tempdir().unwrap();
        copy_smoke(dir.path());
        let mut model = std::fs::read(dir.path().join(MODEL_FILE)).unwrap();
        model.push(0);
        std::fs::write(dir.path().join(MODEL_FILE), model).unwrap();
        assert!(matches!(
            ModelBundle::open(dir.path()),
            Err(ModelError::Malformed(m)) if m.starts_with("model.onnx: model artifact digest mismatch")
        ));
        std::fs::remove_file(dir.path().join(MODEL_FILE)).unwrap();
        assert!(matches!(
            ModelBundle::open(dir.path()),
            Err(ModelError::Malformed(m)) if m.contains("cannot read bundle file model.onnx")
        ));
        assert!(matches!(
            ModelBundle::open(Path::new("/nonexistent/bundle")),
            Err(ModelError::Malformed(_))
        ));
    }

    #[test]
    fn manifest_shape_and_calibration_errors_are_typed() {
        let dir = tempfile::tempdir().unwrap();
        copy_smoke(dir.path());
        let path = dir.path().join(MANIFEST_FILE);
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        v["max_options"] = 0.into();
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(matches!(
            ModelBundle::open(dir.path()),
            Err(ModelError::Malformed(m)) if m.contains("max_options")
        ));
        v["max_options"] = 4.into();
        v["option_markers"]["scheme"] = "pairs-v0".into();
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(matches!(
            ModelBundle::open(dir.path()),
            Err(ModelError::Malformed(m)) if m.starts_with("manifest.json:")
        ));

        // A bad calibration file with a correct digest is still refused.
        copy_smoke(dir.path());
        let cal = br#"{"method":"isotonic","temperature":1.0,"version":"x"}"#;
        std::fs::write(dir.path().join(CALIBRATION_FILE), cal).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        v["files"][CALIBRATION_FILE] = Digest::of(MODEL_FILE_DOMAIN, cal).to_hex().into();
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(matches!(
            ModelBundle::open(dir.path()),
            Err(ModelError::Calibration(m)) if m.contains("isotonic")
        ));
    }

    #[test]
    fn bundle_must_declare_the_row_signals_this_runtime_renders() {
        let dir = tempfile::tempdir().unwrap();
        copy_smoke(dir.path());
        let path = dir.path().join(MANIFEST_FILE);
        let original: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let opened = ModelBundle::open(dir.path()).unwrap();
        assert_eq!(opened.manifest().row_signals, ["tried"]);

        let refused = |signals: Option<serde_json::Value>| {
            let mut v = original.clone();
            match signals {
                Some(s) => v["row_signals"] = s,
                None => {
                    v.as_object_mut().unwrap().remove("row_signals");
                }
            }
            std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
            ModelBundle::open(dir.path())
        };
        // Absent (a model trained before the signal existed), empty, other and extra lists all fail closed.
        for signals in [
            None,
            Some(serde_json::json!([])),
            Some(serde_json::json!(["visits"])),
            Some(serde_json::json!(["tried", "age"])),
            Some(serde_json::json!(["age", "tried"])),
        ] {
            let err = refused(signals.clone()).unwrap_err();
            let ModelError::Malformed(m) = err else {
                panic!("expected Malformed for {signals:?}");
            };
            let shown: Vec<String> = signals.map_or_else(Vec::new, |s| serde_json::from_value(s).unwrap());
            let shown = format!("{shown:?}");
            assert!(m.starts_with("manifest row_signals "), "{m}");
            assert!(m.contains(&shown) && m.contains(r#"["tried"]"#), "{m}");
        }
        assert!(refused(Some(serde_json::json!(["tried"]))).is_ok());
    }
}
