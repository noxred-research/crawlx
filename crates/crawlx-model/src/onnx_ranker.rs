//! ONNX ranker adapter.
//!
//! Pipeline per request: build one *row* per answer alternative (a leading
//! `none of these` row plus one per candidate for `Choice`; one row per level
//! for `Score`; `no`/`yes` for `Noul`) → tokenize `(context, row index, row)`
//! triples into a padded id matrix ([`TensorInput`]) → run an [`OnnxSession`]
//! (one logit per row) → temperature-scale → softmax → confidence [`Gate`].
//!
//! The session is a seam: [`MockOnnx`] makes the whole pipeline testable
//! without a runtime. The real ONNX Runtime session, [`OrtSession`], and the
//! bundle tokenizer, [`BundleTokenizer`], exist only with the `onnx` cargo
//! feature and are built from a digest-verified [`ModelBundle`]. `ort` is
//! linked with `load-dynamic`: the shared library named by `ORT_DYLIB_PATH` is
//! bound at run time, and a missing or incompatible library surfaces as
//! [`ModelError::RuntimeUnavailable`] instead of a panic. [`HashTokenizer`] is
//! a deterministic tokenizer for tests and development without a bundle.
//!
//! Inference runs on tokio's blocking pool behind the guard's semaphore with a
//! 300 ms budget ([`CallGuard::run_blocking`]); a timed-out call keeps its slot
//! until the thread really finishes.

#[cfg(feature = "onnx")]
use crate::bundle::ModelBundle;
use crate::calibration::{Gate, TemperatureScaler};
use crate::error::ModelError;
use crate::guard::{CallGuard, GuardConfig};
use crate::typed::{
    choice_answer, CandidateView, DecisionEngine, ModelId, StateView, TypedAnswer, TypedDecision,
    TypedDecisionRequest, TypedQuestion,
};
use crawlx_core::hash::Digest;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Padding token id of [`HashTokenizer`].
pub const PAD_ID: i64 = 0;
/// Start-of-sequence token id of [`HashTokenizer`].
pub const CLS_ID: i64 = 1;
/// Separator token id of [`HashTokenizer`].
pub const SEP_ID: i64 = 2;
/// Marks the start of the answer alternative inside a [`HashTokenizer`] row.
pub const OPTION_ID: i64 = 3;
/// First id used for hashed word pieces.
pub const FIRST_WORD_ID: i64 = 4;
/// Text of the always-present `none of these` alternative.
pub const NONE_ROW_TEXT: &str = "none of these";
/// Largest `tried` count a candidate row shows the ranker: `min(tried, ROW_TRIED_CAP)` is
/// rendered, so every count at or above the cap reads the same.
pub const ROW_TRIED_CAP: u32 = 3;
/// Names of the per-candidate row signals this runtime renders after `role text region`, in
/// render order. A bundle is served only when its `manifest.row_signals` equals this list: a
/// model trained on other rows would score these ones as noise.
pub const ROW_SIGNALS: [&str; 1] = ["tried"];

/// Padded token matrix handed to a session: `rows × seq_len`, row-major.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TensorInput {
    /// Token ids, `rows * seq_len` entries, row-major.
    pub input_ids: Vec<i64>,
    /// `1` for real tokens, `0` for padding; same layout as `input_ids`.
    pub attention_mask: Vec<i64>,
    /// Number of sequences (one per option, plus the `none of these` row).
    pub rows: usize,
    /// Padded length of every sequence.
    pub seq_len: usize,
}

impl TensorInput {
    /// Token ids of row `i`.
    #[must_use]
    pub fn row(&self, i: usize) -> &[i64] {
        let start = i * self.seq_len;
        self.input_ids.get(start..start + self.seq_len).unwrap_or(&[])
    }

    /// Attention mask of row `i`.
    #[must_use]
    pub fn mask_row(&self, i: usize) -> &[i64] {
        let start = i * self.seq_len;
        self.attention_mask
            .get(start..start + self.seq_len)
            .unwrap_or(&[])
    }
}

/// Turns a `(context, row index, alternative)` triple into token ids.
pub trait OptionTokenizer: Send + Sync {
    /// Longest sequence the tokenizer emits.
    fn max_len(&self) -> usize;
    /// Id used to pad rows to [`Self::max_len`].
    fn pad_id(&self) -> i64;
    /// `[CLS] context [SEP] <option marker for index> alternative [SEP]`, truncated to `max_len`.
    fn encode_row(&self, context: &str, index: usize, alternative: &str) -> Vec<i64>;
}

/// Deterministic word-piece-free tokenizer: lowercase alphanumeric words hashed
/// into a fixed vocabulary. Stable across platforms and releases. Every row
/// carries the same [`OPTION_ID`] marker; the row index is not encoded.
#[derive(Clone, Copy, Debug)]
pub struct HashTokenizer {
    vocab_size: u32,
    max_len: usize,
}

/// Longest share of a row reserved for the answer alternative.
const MAX_ALTERNATIVE_TOKENS: usize = 32;

impl HashTokenizer {
    /// `vocab_size` must exceed the special ids; `max_len` must fit at least the five markers.
    ///
    /// # Errors
    /// [`ModelError::InvalidRequest`] for unusable sizes.
    pub fn new(vocab_size: u32, max_len: usize) -> Result<Self, ModelError> {
        if i64::from(vocab_size) <= FIRST_WORD_ID || max_len < 8 {
            return Err(ModelError::InvalidRequest(
                "tokenizer needs vocab_size > 4 and max_len >= 8".to_owned(),
            ));
        }
        Ok(Self { vocab_size, max_len })
    }

    fn word_id(&self, word: &str) -> i64 {
        let d = Digest::of("crawlx/tokenizer/v1", word.as_bytes());
        let mut first = [0_u8; 4];
        first.copy_from_slice(&d.0[..4]);
        let span = u32::try_from(i64::from(self.vocab_size) - FIRST_WORD_ID)
            .unwrap_or(1)
            .max(1);
        FIRST_WORD_ID + i64::from(u32::from_le_bytes(first) % span)
    }

    fn words(&self, text: &str) -> Vec<i64> {
        text.split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(|w| self.word_id(&w.to_lowercase()))
            .collect()
    }
}

impl Default for HashTokenizer {
    fn default() -> Self {
        Self {
            vocab_size: 30_000,
            max_len: 128,
        }
    }
}

/// `[CLS] ctx [SEP] marker alt [SEP]` with the alternative capped at
/// `max_alternative` tokens and the context truncated to what is left of `max_len`.
fn frame_row(
    cls: i64,
    sep: i64,
    marker: i64,
    mut ctx: Vec<i64>,
    mut alt: Vec<i64>,
    max_len: usize,
    max_alternative: usize,
) -> Vec<i64> {
    alt.truncate(max_alternative.min(max_len.saturating_sub(5)));
    // CLS ctx SEP marker alt SEP => 4 markers + 1 trailing SEP.
    let room = max_len.saturating_sub(alt.len() + 4);
    ctx.truncate(room);
    let mut ids = Vec::with_capacity(ctx.len() + alt.len() + 4);
    ids.push(cls);
    ids.extend(ctx);
    ids.push(sep);
    ids.push(marker);
    ids.extend(alt);
    ids.push(sep);
    ids
}

impl OptionTokenizer for HashTokenizer {
    fn max_len(&self) -> usize {
        self.max_len
    }

    fn pad_id(&self) -> i64 {
        PAD_ID
    }

    fn encode_row(&self, context: &str, _index: usize, alternative: &str) -> Vec<i64> {
        frame_row(
            CLS_ID,
            SEP_ID,
            OPTION_ID,
            self.words(context),
            self.words(alternative),
            self.max_len,
            MAX_ALTERNATIVE_TOKENS,
        )
    }
}

/// Tokenizer of a model bundle (`tokenizer.json` through the `tokenizers`
/// crate) implementing the `numbered-v1` option-marker scheme: row `k` is
/// `[CLS] context [SEP] [OPT_k] alternative [SEP]`. Marker ids that a text
/// smuggles in (an option literally named `[OPT_1]`) are replaced by the
/// unknown token so a row can only ever carry its own marker.
#[cfg(feature = "onnx")]
pub struct BundleTokenizer {
    inner: tokenizers::Tokenizer,
    cls: i64,
    sep: i64,
    pad: i64,
    unk: i64,
    options: Vec<i64>,
    max_len: usize,
    max_alternative: usize,
}

#[cfg(feature = "onnx")]
impl std::fmt::Debug for BundleTokenizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleTokenizer")
            .field("max_len", &self.max_len)
            .field("options", &self.options.len())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "onnx")]
impl BundleTokenizer {
    /// Load `tokenizer.json` of `bundle` and resolve the marker tokens named in its manifest.
    ///
    /// # Errors
    /// [`ModelError::Malformed`] when the file does not parse or a marker token is missing.
    pub fn load(bundle: &ModelBundle) -> Result<Self, ModelError> {
        let manifest = bundle.manifest();
        let markers = &manifest.option_markers;
        let inner = tokenizers::Tokenizer::from_file(bundle.tokenizer_path())
            .map_err(|e| ModelError::Malformed(format!("tokenizer.json: {e}")))?;
        let id_of = |name: &str| -> Result<i64, ModelError> {
            inner
                .token_to_id(name)
                .map(i64::from)
                .ok_or_else(|| ModelError::Malformed(format!("tokenizer.json lacks marker token {name:?}")))
        };
        let options = (0..=manifest.max_options)
            .map(|k| id_of(&markers.option_token(k)))
            .collect::<Result<Vec<_>, _>>()?;
        let unk = id_of(&markers.unk)?;
        Ok(Self {
            cls: id_of(&markers.cls)?,
            sep: id_of(&markers.sep)?,
            pad: id_of(&markers.pad)?,
            unk,
            options,
            inner,
            max_len: manifest.max_seq_len,
            max_alternative: manifest.max_alternative_tokens,
        })
    }

    /// Most option rows (including the `none` row) this tokenizer can number.
    #[must_use]
    pub fn max_rows(&self) -> usize {
        self.options.len()
    }

    fn text_ids(&self, text: &str) -> Vec<i64> {
        let ids = match self.inner.encode(text, false) {
            Ok(enc) => enc.get_ids().iter().map(|&i| i64::from(i)).collect(),
            Err(e) => {
                tracing::warn!(error = %e, "tokenizer failed on a text span; encoding it as unknown");
                vec![self.unk]
            }
        };
        ids.into_iter()
            .map(|i| {
                if i == self.cls || i == self.sep || i == self.pad || self.options.contains(&i) {
                    self.unk
                } else {
                    i
                }
            })
            .collect()
    }
}

#[cfg(feature = "onnx")]
impl OptionTokenizer for BundleTokenizer {
    fn max_len(&self) -> usize {
        self.max_len
    }

    fn pad_id(&self) -> i64 {
        self.pad
    }

    fn encode_row(&self, context: &str, index: usize, alternative: &str) -> Vec<i64> {
        // Rows beyond the numbered range cannot occur: the engine checks `max_rows` first.
        let marker = self.options.get(index).copied().unwrap_or(self.unk);
        frame_row(
            self.cls,
            self.sep,
            marker,
            self.text_ids(context),
            self.text_ids(alternative),
            self.max_len,
            self.max_alternative,
        )
    }
}

/// An inference session: one logit per input row.
pub trait OnnxSession: Send + Sync {
    /// Most rows a single call accepts (`manifest.max_options + 1`).
    fn max_rows(&self) -> usize;

    /// Score every row of `input`; the result has exactly `input.rows` logits.
    ///
    /// # Errors
    /// [`ModelError::RuntimeUnavailable`] or [`ModelError::Malformed`] and friends.
    fn run(&self, input: &TensorInput) -> Result<Vec<f32>, ModelError>;
}

type MockFn = dyn Fn(&TensorInput) -> Result<Vec<f32>, ModelError> + Send + Sync;

/// Scripted session for tests: no runtime, deterministic.
#[derive(Clone)]
pub struct MockOnnx {
    script: Arc<MockFn>,
    calls: Arc<AtomicUsize>,
    delay: Duration,
    max_rows: usize,
}

impl MockOnnx {
    /// A session whose logits come from `script`.
    #[must_use]
    pub fn new(
        script: impl Fn(&TensorInput) -> Result<Vec<f32>, ModelError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            script: Arc::new(script),
            calls: Arc::new(AtomicUsize::new(0)),
            delay: Duration::ZERO,
            max_rows: 21,
        }
    }

    /// Always return `logits`, whatever the input.
    #[must_use]
    pub fn fixed(logits: Vec<f32>) -> Self {
        Self::new(move |_| Ok(logits.clone()))
    }

    /// Always fail with `error`.
    #[must_use]
    pub fn failing(error: ModelError) -> Self {
        Self::new(move |_| Err(error.clone()))
    }

    /// Block for `delay` inside every call (exercises the timeout).
    #[must_use]
    pub const fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Calls made so far.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl OnnxSession for MockOnnx {
    fn max_rows(&self) -> usize {
        self.max_rows
    }

    fn run(&self, input: &TensorInput) -> Result<Vec<f32>, ModelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        (self.script)(input)
    }
}

/// Environment variable naming the ONNX Runtime shared library (`ort` `load-dynamic`).
#[cfg(feature = "onnx")]
pub const ORT_DYLIB_ENV: &str = "ORT_DYLIB_PATH";

/// ONNX Runtime session over a verified [`ModelBundle`] (feature `onnx`).
///
/// The session is single-threaded inside the runtime (`intra_threads = 1`) and
/// serialised by a mutex; concurrency comes from the engine's [`CallGuard`]
/// semaphore, not from the runtime.
#[cfg(feature = "onnx")]
pub struct OrtSession {
    session: parking_lot::Mutex<ort::session::Session>,
    input_ids: String,
    attention_mask: Option<String>,
    output: String,
    max_rows: usize,
}

#[cfg(feature = "onnx")]
impl std::fmt::Debug for OrtSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrtSession")
            .field("input_ids", &self.input_ids)
            .field("attention_mask", &self.attention_mask)
            .field("output", &self.output)
            .field("max_rows", &self.max_rows)
            .finish_non_exhaustive()
    }
}

/// Environment variable choosing the execution provider of [`OrtSession::load`]: `cpu`
/// (default), `cuda` or `cuda:<device>`.
#[cfg(feature = "onnx")]
pub const ORT_EP_ENV: &str = "CRAWLX_ORT_EP";

/// Where an [`OrtSession`] runs the graph.
#[cfg(feature = "onnx")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum ExecutionProvider {
    /// The CPU provider of the runtime (always available).
    #[default]
    Cpu,
    /// The CUDA provider on `device`; loading fails when the runtime lacks it.
    Cuda {
        /// CUDA device ordinal.
        device: i32,
    },
}

#[cfg(feature = "onnx")]
impl ExecutionProvider {
    /// Parse `cpu`, `cuda` or `cuda:<device>` (case-insensitive).
    ///
    /// # Errors
    /// [`ModelError::InvalidRequest`] for any other spelling.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let lower = text.trim().to_ascii_lowercase();
        match lower.as_str() {
            "" | "cpu" => Ok(Self::Cpu),
            "cuda" => Ok(Self::Cuda { device: 0 }),
            other => other
                .strip_prefix("cuda:")
                .and_then(|d| d.parse::<i32>().ok())
                .filter(|d| *d >= 0)
                .map(|device| Self::Cuda { device })
                .ok_or_else(|| {
                    ModelError::InvalidRequest(format!(
                        "{ORT_EP_ENV} must be `cpu`, `cuda` or `cuda:<device>`, got {text:?}"
                    ))
                }),
        }
    }

    /// The provider named by [`ORT_EP_ENV`]; [`Self::Cpu`] when it is unset.
    ///
    /// # Errors
    /// [`ModelError::InvalidRequest`] when the variable holds an unknown provider.
    pub fn from_env() -> Result<Self, ModelError> {
        match std::env::var(ORT_EP_ENV) {
            Ok(v) => Self::parse(&v),
            Err(_) => Ok(Self::Cpu),
        }
    }
}

#[cfg(feature = "onnx")]
impl OrtSession {
    /// Bind the runtime named by `ORT_DYLIB_PATH` and build a session from the bundle's
    /// `model.onnx` on the provider named by `CRAWLX_ORT_EP` (CPU when unset).
    ///
    /// # Errors
    /// [`ModelError::RuntimeUnavailable`] when `ORT_DYLIB_PATH` is unset or the
    /// library cannot be loaded or lacks the requested provider; [`ModelError::Malformed`]
    /// when the graph does not build or its inputs/outputs disagree with the manifest.
    pub fn load(bundle: &ModelBundle) -> Result<Self, ModelError> {
        Self::load_with(bundle, ExecutionProvider::from_env()?)
    }

    /// [`Self::load`] on an explicit execution provider.
    ///
    /// # Errors
    /// As [`Self::load`].
    pub fn load_with(bundle: &ModelBundle, provider: ExecutionProvider) -> Result<Self, ModelError> {
        let dylib = std::env::var_os(ORT_DYLIB_ENV)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| {
                ModelError::RuntimeUnavailable(format!(
                    "{ORT_DYLIB_ENV} is not set; point it at the ONNX Runtime shared library"
                ))
            })?;
        ort::init_from(&dylib)
            .map_err(|e| ModelError::RuntimeUnavailable(format!("cannot bind onnx runtime: {e}")))?
            .with_name("crawlx")
            .commit();
        let manifest = bundle.manifest();
        let build_err = |what: &str, message: &str| {
            ModelError::Malformed(format!("cannot build onnx session ({what}): {message}"))
        };
        let builder = ort::session::Session::builder().map_err(|e| build_err("builder", e.message()))?;
        let builder = builder
            .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)
            .map_err(|e| build_err("optimization level", e.message()))?;
        let builder = match provider {
            ExecutionProvider::Cpu => builder,
            ExecutionProvider::Cuda { device } => builder
                .with_execution_providers([ort::ep::CUDA::default()
                    .with_device_id(device)
                    // strict fp32: TF32 matmuls (the provider's default on Ampere and later)
                    // move logits by ~1e-3 and miss the 1e-4 parity gate
                    .with_tf32(false)
                    .build()
                    .error_on_failure()])
                .map_err(|e| {
                    ModelError::RuntimeUnavailable(format!(
                        "cuda execution provider on device {device}: {}",
                        e.message()
                    ))
                })?,
        };
        let mut builder = builder
            .with_intra_threads(1)
            .map_err(|e| build_err("threads", e.message()))?;
        let session = builder
            .commit_from_memory(bundle.model_bytes())
            .map_err(|e| build_err("graph", e.message()))?;
        let has_input = |name: &str| session.inputs().iter().any(|i| i.name() == name);
        if !has_input(&manifest.inputs.input_ids) {
            return Err(ModelError::Malformed(format!(
                "graph has no input named {:?}",
                manifest.inputs.input_ids
            )));
        }
        if let Some(mask) = &manifest.inputs.attention_mask {
            if !has_input(mask) {
                return Err(ModelError::Malformed(format!(
                    "graph has no input named {mask:?}"
                )));
            }
        }
        if !session.outputs().iter().any(|o| o.name() == manifest.output) {
            return Err(ModelError::Malformed(format!(
                "graph has no output named {:?}",
                manifest.output
            )));
        }
        tracing::info!(
            model = %manifest.model_id,
            version = %manifest.version,
            provider = ?provider,
            runtime = ort::info(),
            "onnx session ready"
        );
        Ok(Self {
            session: parking_lot::Mutex::new(session),
            input_ids: manifest.inputs.input_ids.clone(),
            attention_mask: manifest.inputs.attention_mask.clone(),
            output: manifest.output.clone(),
            max_rows: manifest.max_rows(),
        })
    }
}

#[cfg(feature = "onnx")]
impl OnnxSession for OrtSession {
    fn max_rows(&self) -> usize {
        self.max_rows
    }

    fn run(&self, input: &TensorInput) -> Result<Vec<f32>, ModelError> {
        use ort::value::TensorRef;
        use std::borrow::Cow;

        fn ort_err(what: &'static str) -> impl Fn(ort::Error) -> ModelError {
            move |e| ModelError::Malformed(format!("{what}: {}", e.message()))
        }
        let shape = [input.rows, input.seq_len];
        let mut feeds: Vec<(Cow<'_, str>, ort::session::SessionInputValue<'_>)> = Vec::with_capacity(2);
        feeds.push((
            Cow::Borrowed(self.input_ids.as_str()),
            TensorRef::from_array_view((shape, input.input_ids.as_slice()))
                .map_err(ort_err("input_ids tensor"))?
                .into(),
        ));
        if let Some(mask) = &self.attention_mask {
            feeds.push((
                Cow::Borrowed(mask.as_str()),
                TensorRef::from_array_view((shape, input.attention_mask.as_slice()))
                    .map_err(ort_err("attention_mask tensor"))?
                    .into(),
            ));
        }
        let mut session = self.session.lock();
        let outputs = session.run(feeds).map_err(ort_err("onnx run"))?;
        let value = outputs
            .get(&self.output)
            .ok_or_else(|| ModelError::Malformed(format!("graph returned no output {:?}", self.output)))?;
        let (_, logits) = value
            .try_extract_tensor::<f32>()
            .map_err(ort_err("logits tensor"))?;
        Ok(logits.to_vec())
    }
}

/// Configuration of a [`OnnxRankerEngine`].
#[derive(Clone)]
pub struct OnnxRankerConfig {
    /// Identity of the loaded model, recorded in decision provenance.
    pub model: ModelId,
    /// Temperature fitted for this model version.
    pub scaler: TemperatureScaler,
    /// Confidence gate that decides between accepting and abstaining.
    pub gate: Gate,
    /// Timeout, concurrency and breaker settings of local inference.
    pub guard: GuardConfig,
    /// Turns option texts into token ids for the model.
    pub tokenizer: Arc<dyn OptionTokenizer>,
}

impl OnnxRankerConfig {
    /// Identity calibration, default gate, local guard and hashing tokenizer.
    #[must_use]
    pub fn new(model: ModelId) -> Self {
        Self {
            model,
            scaler: TemperatureScaler::default(),
            gate: Gate::default(),
            guard: GuardConfig::local(),
            tokenizer: Arc::new(HashTokenizer::default()),
        }
    }

    /// Identity, calibration and tokenizer of a bundle; default gate and local guard.
    ///
    /// # Errors
    /// [`ModelError::Malformed`] when the bundle tokenizer cannot be loaded.
    #[cfg(feature = "onnx")]
    pub fn from_bundle(bundle: &ModelBundle) -> Result<Self, ModelError> {
        Ok(Self {
            model: bundle.model_id(),
            scaler: bundle.scaler()?,
            gate: Gate::default(),
            guard: GuardConfig::local(),
            tokenizer: Arc::new(BundleTokenizer::load(bundle)?),
        })
    }
}

/// Typed-decision engine over an [`OnnxSession`].
pub struct OnnxRankerEngine {
    session: Arc<dyn OnnxSession>,
    config: OnnxRankerConfig,
    guard: CallGuard,
}

/// Row text of one candidate: `{role} {text} {region} | tried {n}` with `n = min(tried,
/// ROW_TRIED_CAP)`. A missing region leaves the trailing space before the bar, so the string is
/// byte-identical to what the Python trainer renders (`tests/fixtures/row-render.json`).
fn candidate_row(c: &CandidateView) -> String {
    format!(
        "{} {} {} | tried {}",
        c.role,
        c.text,
        c.region.as_deref().unwrap_or(""),
        c.tried.min(ROW_TRIED_CAP)
    )
}

/// One question lowered to scoring rows.
struct Rows {
    texts: Vec<String>,
}

impl OnnxRankerEngine {
    /// Engine that runs `session` under the guard and gate of `config`.
    #[must_use]
    pub fn new(session: Arc<dyn OnnxSession>, config: OnnxRankerConfig) -> Self {
        let guard = CallGuard::new(config.guard);
        Self {
            session,
            config,
            guard,
        }
    }

    /// Open the bundle at `dir` and serve it through a real [`OrtSession`] on the provider
    /// named by `CRAWLX_ORT_EP` (CPU when unset).
    ///
    /// # Errors
    /// Bundle errors from [`ModelBundle::open`], tokenizer errors from
    /// [`BundleTokenizer::load`], runtime errors from [`OrtSession::load`].
    #[cfg(feature = "onnx")]
    pub fn from_bundle(dir: &std::path::Path, guard: GuardConfig) -> Result<Self, ModelError> {
        Self::from_bundle_with(dir, guard, ExecutionProvider::from_env()?)
    }

    /// [`Self::from_bundle`] on an explicit execution provider.
    ///
    /// # Errors
    /// As [`Self::from_bundle`].
    #[cfg(feature = "onnx")]
    pub fn from_bundle_with(
        dir: &std::path::Path,
        guard: GuardConfig,
        provider: ExecutionProvider,
    ) -> Result<Self, ModelError> {
        let bundle = ModelBundle::open(dir)?;
        let mut config = OnnxRankerConfig::from_bundle(&bundle)?;
        config.guard = guard;
        let session = OrtSession::load_with(&bundle, provider)?;
        Ok(Self::new(Arc::new(session), config))
    }

    /// The engine's call guard.
    #[must_use]
    pub const fn guard(&self) -> &CallGuard {
        &self.guard
    }

    fn context(goal: &str, state: &StateView, question: &TypedQuestion) -> String {
        let mut ctx = format!("{goal} | route {}", state.route_template);
        for r in &state.regions {
            ctx.push_str(&format!(" | {} {}", r.name, r.summary));
        }
        match question {
            TypedQuestion::Choice { id, .. } | TypedQuestion::Score { id, .. } => {
                ctx.push_str(&format!(" | question {id}"));
            }
            TypedQuestion::Noul { id, question } => ctx.push_str(&format!(" | question {id} {question}")),
        }
        ctx
    }

    fn rows(question: &TypedQuestion, state: &StateView) -> Rows {
        let texts = match question {
            TypedQuestion::Choice { options, .. } => {
                let mut rows = vec![NONE_ROW_TEXT.to_owned()];
                for o in options {
                    let text = o
                        .resolve(state.candidates.len())
                        .and_then(|i| state.candidates.get(i))
                        .map_or_else(String::new, candidate_row);
                    rows.push(text);
                }
                rows
            }
            TypedQuestion::Score { criteria, .. } => criteria.clone(),
            TypedQuestion::Noul { .. } => vec!["no".to_owned(), "yes".to_owned()],
        };
        Rows { texts }
    }

    fn tensor(&self, context: &str, rows: &Rows) -> TensorInput {
        tensor_of(self.config.tokenizer.as_ref(), context, &rows.texts)
    }
}

/// A typed question lowered to what the ranker scores: one shared `context` string and one text
/// per scoring row (row `k` carries option marker `k`). This is the single rendering shared by
/// [`OnnxRankerEngine`] and the dataset recorder, so the training rows are byte-identical to the
/// rows the engine tokenizes at inference.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct RenderedQuestion {
    /// Goal, route, region summaries and question id, joined the way the ranker was trained on.
    pub context: String,
    /// Row texts: the `none of these` row first for a `Choice`, then one row per option.
    pub rows: Vec<String>,
}

/// Lower `question` of `req` to the rows the ranker scores. The state is sanitized first,
/// exactly as [`OnnxRankerEngine::decide`] does.
#[must_use]
pub fn render_question(req: &TypedDecisionRequest, question: &TypedQuestion) -> RenderedQuestion {
    let state = req.state.value().sanitized();
    RenderedQuestion {
        context: OnnxRankerEngine::context(req.goal.as_str(), &state, question),
        rows: OnnxRankerEngine::rows(question, &state).texts,
    }
}

/// Encode `rows` (row `k` gets marker `k`) into a padded rectangle.
pub fn tensor_of(tok: &dyn OptionTokenizer, context: &str, rows: &[String]) -> TensorInput {
    let seq_len = tok.max_len();
    let mut ids = Vec::with_capacity(rows.len() * seq_len);
    let mut mask = Vec::with_capacity(rows.len() * seq_len);
    for (k, text) in rows.iter().enumerate() {
        let mut row = tok.encode_row(context, k, text);
        row.truncate(seq_len);
        mask.extend(std::iter::repeat_n(1, row.len()));
        mask.extend(std::iter::repeat_n(0, seq_len - row.len()));
        row.resize(seq_len, tok.pad_id());
        ids.extend(row);
    }
    TensorInput {
        input_ids: ids,
        attention_mask: mask,
        rows: rows.len(),
        seq_len,
    }
}

impl OnnxRankerEngine {
    /// Answer `questions` about `state` for a goal given as text. A typed-decision *server*
    /// answers requests that arrived over the wire with this: it cannot rebuild a
    /// [`TypedDecisionRequest`], whose goal is an `Instruction` constructible only from static
    /// templates. The caller has validated the request ([`crate::typed::validate_parts`]).
    ///
    /// # Errors
    /// [`ModelError::InvalidRequest`] when a question needs more rows than the session accepts,
    /// and the guard and session errors of [`DecisionEngine::decide`].
    pub async fn decide_parts(
        &self,
        goal: &str,
        state: &StateView,
        questions: &[TypedQuestion],
    ) -> Result<TypedDecision, ModelError> {
        let started = Instant::now();
        let state = state.sanitized();
        let mut batches = Vec::with_capacity(questions.len());
        for q in questions {
            let rows = Self::rows(q, &state);
            if rows.texts.len() > self.session.max_rows() {
                return Err(ModelError::InvalidRequest(format!(
                    "question {:?} needs {} rows but the session accepts {}",
                    q.id(),
                    rows.texts.len(),
                    self.session.max_rows()
                )));
            }
            batches.push(self.tensor(&Self::context(goal, &state, q), &rows));
        }
        let session = Arc::clone(&self.session);
        let logits: Vec<Vec<f32>> = self
            .guard
            .run_blocking(move || {
                let mut out = Vec::with_capacity(batches.len());
                for batch in &batches {
                    let logits = session.run(batch)?;
                    if logits.len() != batch.rows {
                        return Err(ModelError::Malformed(format!(
                            "session returned {} logits for {} rows",
                            logits.len(),
                            batch.rows
                        )));
                    }
                    if logits.iter().any(|z| !z.is_finite()) {
                        return Err(ModelError::Malformed(
                            "session returned a non-finite logit".to_owned(),
                        ));
                    }
                    out.push(logits);
                }
                Ok(out)
            })
            .await?;

        let mut answers = Vec::with_capacity(questions.len());
        let mut abstained = Vec::new();
        for (q, row_logits) in questions.iter().zip(&logits) {
            let probs = self.config.scaler.apply(row_logits);
            match q {
                TypedQuestion::Choice { id, options } => {
                    let (none_p, option_probs) =
                        probs.split_first().map_or((0.0, &[][..]), |(n, rest)| (*n, rest));
                    let (answer, did_abstain) =
                        choice_answer(id, options, option_probs, none_p, &self.config.gate);
                    if did_abstain {
                        abstained.push(id.clone());
                    }
                    answers.push(answer);
                }
                TypedQuestion::Score { id, .. } => {
                    let level = probs
                        .iter()
                        .enumerate()
                        .fold(
                            (0, f32::NEG_INFINITY),
                            |best, (i, p)| if *p > best.1 { (i, *p) } else { best },
                        )
                        .0;
                    answers.push(TypedAnswer::Score {
                        id: id.clone(),
                        distribution: probs,
                        level,
                    });
                }
                TypedQuestion::Noul { id, .. } => {
                    answers.push(TypedAnswer::Noul {
                        id: id.clone(),
                        p_yes: probs.get(1).copied().unwrap_or(0.0),
                    });
                }
            }
        }
        Ok(TypedDecision {
            answers,
            abstained,
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            model: self.config.model.clone(),
        })
    }
}

#[async_trait::async_trait]
impl DecisionEngine for OnnxRankerEngine {
    async fn decide(&self, req: TypedDecisionRequest) -> Result<TypedDecision, ModelError> {
        req.validate()?;
        self.decide_parts(req.goal.as_str(), req.state.value(), &req.questions)
            .await
    }

    fn id(&self) -> &ModelId {
        &self.config.model
    }

    fn breaker_state(&self) -> Option<crate::breaker::BreakerState> {
        Some(self.guard.breaker_state())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::typed::CandidateRef;

    #[test]
    fn tokenizer_is_deterministic_and_well_framed() {
        let t = HashTokenizer::default();
        let a = t.encode_row("Pick the next control", 1, "button Save changes");
        assert_eq!(a, t.encode_row("Pick the next control", 2, "button Save changes"));
        assert_eq!(a.first(), Some(&CLS_ID));
        assert_eq!(a.last(), Some(&SEP_ID));
        assert_eq!(a.iter().filter(|&&i| i == OPTION_ID).count(), 1);
        assert!(a.iter().all(|&i| (0..30_000).contains(&i)));
        // Case and punctuation do not change ids.
        assert_eq!(
            t.encode_row("PICK, the next control!", 1, "Button save CHANGES"),
            a
        );
        // Different alternatives give different rows.
        assert_ne!(t.encode_row("ctx", 0, "alpha"), t.encode_row("ctx", 0, "beta"));
    }

    #[test]
    fn tokenizer_word_ids_are_pinned() {
        // Golden ids: a change here means the tokenizer (and every model trained on it) changed.
        let t = HashTokenizer::default();
        let ids = t.encode_row("open menu", 0, "none of these");
        assert_eq!(ids, [1, 13_775, 13_772, 2, 3, 8_583, 3_004, 10_684, 2]);
    }

    #[test]
    fn tokenizer_truncates_context_but_keeps_the_alternative() {
        let t = HashTokenizer::new(1000, 16).unwrap();
        let ctx = "word ".repeat(100);
        let ids = t.encode_row(&ctx, 0, "keep these three");
        assert_eq!(ids.len(), 16);
        assert_eq!(ids.last(), Some(&SEP_ID));
        let opt = ids.iter().position(|&i| i == OPTION_ID).unwrap();
        assert_eq!(ids.len() - opt - 2, 3, "alternative tokens survive");
        assert!(HashTokenizer::new(3, 16).is_err());
        assert!(HashTokenizer::new(1000, 4).is_err());
    }

    #[test]
    fn tensor_rows_are_padded_to_a_rectangle() {
        let t = HashTokenizer::default();
        let rows = Rows {
            texts: vec!["a".into(), "a much longer alternative text".into()],
        };
        let engine = OnnxRankerEngine::new(
            Arc::new(MockOnnx::fixed(vec![0.0, 0.0])),
            OnnxRankerConfig::new(ModelId::new("onnx-ranker", "m", "d", "c")),
        );
        let input = engine.tensor("context words", &rows);
        assert_eq!((input.rows, input.seq_len), (2, t.max_len()));
        assert_eq!(input.input_ids.len(), 2 * t.max_len());
        assert_eq!(input.attention_mask.len(), 2 * t.max_len());
        assert_eq!(input.row(0).first(), Some(&CLS_ID));
        assert_eq!(input.row(0).last(), Some(&PAD_ID));
        assert_eq!(input.mask_row(0).last(), Some(&0));
        let real = input.row(0).iter().filter(|&&i| i != PAD_ID).count();
        assert_eq!(
            input.mask_row(0).iter().sum::<i64>(),
            i64::try_from(real).unwrap()
        );
        assert_eq!(input.row(2), &[] as &[i64]);
    }

    #[test]
    fn candidate_row_golden_strings_cap_tried_and_keep_the_empty_region_space() {
        let row = |role, text, region, tried| {
            candidate_row(&CandidateView::new(role, text, region).with_tried(tried))
        };
        // No region: the empty field leaves two spaces before the bar.
        assert_eq!(row("button", "menu", None, 0), "button menu  | tried 0");
        assert_eq!(row("button", "menu", None, 2), "button menu  | tried 2");
        assert_eq!(row("button", "menu", None, 3), "button menu  | tried 3");
        assert_eq!(row("button", "menu", None, 7), "button menu  | tried 3");
        assert_eq!(
            row("link", "settings", Some("navigation:main"), 0),
            "link settings navigation:main | tried 0"
        );
        assert_eq!(
            row("link", "settings", Some("navigation:main"), 2),
            "link settings navigation:main | tried 2"
        );
        assert_eq!(
            row("link", "settings", Some("navigation:main"), 3),
            "link settings navigation:main | tried 3"
        );
        assert_eq!(
            row("link", "settings", Some("navigation:main"), 7),
            "link settings navigation:main | tried 3"
        );
        assert_eq!(
            row("link", "settings", Some("navigation:main"), u32::MAX),
            "link settings navigation:main | tried 3"
        );
        assert_eq!((ROW_TRIED_CAP, ROW_SIGNALS), (3, ["tried"]));
    }

    fn state_with_tried() -> StateView {
        StateView {
            route_template: "/app".to_owned(),
            regions: Vec::new(),
            candidates: vec![
                CandidateView::new("button", "menu", None),
                CandidateView::new("link", "settings", Some("navigation:main")).with_tried(2),
                CandidateView::new("button", "delete", Some("main")).with_tried(9),
            ],
        }
    }

    #[test]
    fn render_question_rows_are_the_engine_rows_with_the_tried_suffix() {
        let state = state_with_tried();
        let req = TypedDecisionRequest {
            goal: crate::provenance::Instruction::from_static("Pick the next control."),
            state: crate::provenance::ProvenanceTagged::new(
                crate::provenance::Provenance::PageText,
                state.clone(),
            ),
            questions: Vec::new(),
        };
        let choice = TypedQuestion::Choice {
            id: "next".into(),
            options: vec![CandidateRef(1), CandidateRef(0), CandidateRef(2)],
        };
        let rendered = render_question(&req, &choice);
        assert_eq!(
            rendered.rows,
            [
                "none of these",
                "link settings navigation:main | tried 2",
                "button menu  | tried 0",
                "button delete main | tried 3",
            ]
        );
        assert_eq!(
            rendered.rows,
            OnnxRankerEngine::rows(&choice, &state.sanitized()).texts
        );
        // The context string carries no row signal.
        assert_eq!(
            rendered.context,
            "Pick the next control. | route /app | question next"
        );

        let score = TypedQuestion::Score {
            id: "risk".into(),
            criteria: vec!["safe".into(), "risky".into(), "destructive".into()],
        };
        assert_eq!(
            render_question(&req, &score).rows,
            ["safe", "risky", "destructive"]
        );
        let noul = TypedQuestion::Noul {
            id: "ok".into(),
            question: "Is it safe?".into(),
        };
        assert_eq!(render_question(&req, &noul).rows, ["no", "yes"]);
    }
}
