//! OCR for scanned PDF pages and image uploads (compatibility API `parsers[].mode: ocr`, the
//! `image` parser and `IMAGE_OCR_ENABLED`).
//!
//! An [`Ocr`] is built once from an [`OcrConfig`] ([`Ocr::from_config`]) and shared (`Arc`) by
//! the API (`/parse`) and the worker (the scrape `parsers`). The backend is chosen by
//! [`OcrConfig::backend`]:
//!
//! | backend | engine | needs |
//! |---|---|---|
//! | `off` (default) | none: PDFs yield their text layer, images yield nothing | nothing |
//! | `tesseract` | the Tesseract command line (`tesseract stdin stdout tsv`) | the `tesseract` binary and trained data for [`OcrConfig::languages`]; `TESSDATA_PREFIX` is honoured |
//! | `ocrs` | the pure-Rust [`ocrs`](https://crates.io/crates/ocrs) engine | the two model files in `CRAWLX_OCR_MODELS` (the `ocrs` cargo feature, on by default) |
//!
//! Environment (read by [`OcrConfig::from_env`]): `CRAWLX_OCR_BACKEND`, `CRAWLX_OCR_LANGUAGES`,
//! `CRAWLX_OCR_TESSERACT`, `CRAWLX_OCR_TESSDATA` (falls back to `TESSDATA_PREFIX`),
//! `CRAWLX_OCR_MODELS`, `CRAWLX_OCR_RASTERIZER`, `CRAWLX_OCR_PDFTOPPM`, `CRAWLX_OCR_DPI`,
//! `CRAWLX_OCR_TIMEOUT_MS`, `CRAWLX_OCR_MAX_PDF_PAGES`, `CRAWLX_OCR_MAX_IMAGE_PIXELS`,
//! `CRAWLX_OCR_MIN_CONFIDENCE`, and the drop-in `IMAGE_OCR_ENABLED=true` (selects `tesseract`
//! when no backend is named).
//!
//! # PDF pages
//!
//! A page needs OCR when the caller asks for every page (`mode: ocr`) or when it has no text
//! layer (`mode: auto`). Its pixels come from the images the page draws (the usual scan: one
//! page-sized image; JPEG, Flate/LZW raw samples, CCITT G3/G4 are decoded, then rotated to the
//! orientation the page displays) or, for a page that draws no usable image (vector-only
//! pages; JBIG2 or JPEG 2000 scans), from `pdftoppm` when [`Rasterizer`] allows it. Without a
//! rasteriser, a page with neither is reported in the document warnings.

mod image_io;
#[cfg(feature = "ocrs")]
mod ocrs_backend;
pub(crate) mod pdf_pages;
mod process;
mod raster;
mod tesseract;

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use image::DynamicImage;
use serde::{Deserialize, Serialize};

pub use pdf_pages::PdfOcr;
pub(crate) use raster::PdfRaster;

/// Why OCR could not run.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OcrError {
    /// A setting is invalid.
    #[error("invalid OCR setting: {0}")]
    Config(String),
    /// The configured backend cannot be used on this host.
    #[error("OCR backend {backend} is unavailable: {reason}")]
    Unavailable {
        /// The backend name.
        backend: &'static str,
        /// What is missing.
        reason: String,
    },
    /// The bytes are not an image the decoder reads, or the image is over the pixel limit.
    #[error("unreadable image: {0}")]
    Image(String),
    /// A program could not be started.
    #[error("cannot run {program}")]
    Spawn {
        /// Program name.
        program: String,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
    /// A program ran past the deadline and was killed.
    #[error("{program} did not finish within {millis} ms")]
    Timeout {
        /// Program name.
        program: String,
        /// The deadline.
        millis: u64,
    },
    /// A program exited with an error.
    #[error("{program} failed ({status}): {stderr}")]
    Failed {
        /// Program name.
        program: String,
        /// Exit status.
        status: String,
        /// The head of its standard error.
        stderr: String,
    },
    /// The engine failed on the image.
    #[error("{0}")]
    Backend(String),
}

/// Which OCR engine runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum OcrBackend {
    /// No OCR.
    #[default]
    Off,
    /// The Tesseract command line.
    Tesseract,
    /// The pure-Rust `ocrs` engine.
    Ocrs,
}

impl OcrBackend {
    /// The setting value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Tesseract => "tesseract",
            Self::Ocrs => "ocrs",
        }
    }
}

impl FromStr for OcrBackend {
    type Err = OcrError;

    fn from_str(s: &str) -> Result<Self, OcrError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "" => Ok(Self::Off),
            "tesseract" => Ok(Self::Tesseract),
            "ocrs" => Ok(Self::Ocrs),
            other => Err(OcrError::Config(format!(
                "backend `{other}`; expected off, tesseract or ocrs"
            ))),
        }
    }
}

/// Where the pixels of a PDF page without a usable embedded image come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Rasterizer {
    /// `pdftoppm` when it is installed; embedded images otherwise.
    #[default]
    Auto,
    /// Embedded images only.
    Embedded,
    /// `pdftoppm` is required: a missing binary is a start-up error.
    Pdftoppm,
}

impl FromStr for Rasterizer {
    type Err = OcrError;

    fn from_str(s: &str) -> Result<Self, OcrError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => Ok(Self::Auto),
            "embedded" => Ok(Self::Embedded),
            "pdftoppm" => Ok(Self::Pdftoppm),
            other => Err(OcrError::Config(format!(
                "rasterizer `{other}`; expected auto, embedded or pdftoppm"
            ))),
        }
    }
}

/// The `ocr` configuration (`crawlx.toml` `[ocr]` with snake_case keys, `CRAWLX_OCR_*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OcrConfig {
    /// The engine. Default `off`.
    pub backend: OcrBackend,
    /// Tesseract language codes joined by `+` (`eng`, `eng+tur`).
    pub languages: String,
    /// The Tesseract binary; `tesseract` is looked up in `PATH` when unset.
    pub tesseract_path: Option<PathBuf>,
    /// Directory with the `.traineddata` files (`TESSDATA_PREFIX` of Tesseract).
    pub tessdata_dir: Option<PathBuf>,
    /// Directory with the `ocrs` model files.
    pub models_dir: Option<PathBuf>,
    /// Page source for PDF pages without a usable embedded image.
    pub rasterizer: Rasterizer,
    /// The `pdftoppm` binary; looked up in `PATH` when unset.
    pub pdftoppm_path: Option<PathBuf>,
    /// Resolution of rasterised pages, 72 to 600 dpi.
    pub dpi: u32,
    /// Deadline of one engine or rasteriser run, milliseconds.
    pub timeout_ms: u64,
    /// Pages of one PDF that are OCR'd; later pages keep their (empty) text layer and the
    /// document warns.
    pub max_pdf_pages: u32,
    /// Largest image the engines read, in pixels.
    pub max_image_pixels: u64,
    /// Tesseract words under this confidence (0 to 100) are dropped.
    pub min_confidence: u8,
}

impl Default for OcrConfig {
    fn default() -> Self {
        Self {
            backend: OcrBackend::Off,
            languages: "eng".to_owned(),
            tesseract_path: None,
            tessdata_dir: None,
            models_dir: None,
            rasterizer: Rasterizer::Auto,
            pdftoppm_path: None,
            dpi: 300,
            timeout_ms: 60_000,
            max_pdf_pages: 100,
            max_image_pixels: 50_000_000,
            min_confidence: 0,
        }
    }
}

fn parse_num<T: FromStr>(name: &str, value: &str) -> Result<T, OcrError> {
    value
        .trim()
        .parse()
        .map_err(|_| OcrError::Config(format!("{name} `{value}` is not a number in range")))
}

impl OcrConfig {
    /// The defaults with the `CRAWLX_OCR_*` environment applied.
    ///
    /// # Errors
    /// [`OcrError::Config`] for a malformed value.
    pub fn from_env(getenv: &dyn Fn(&str) -> Option<String>) -> Result<Self, OcrError> {
        Self::default().apply_env(getenv)
    }

    /// Apply the `CRAWLX_OCR_*` environment over `self`; a variable that is unset or empty
    /// leaves the field alone, so flags applied before keep their value.
    ///
    /// # Errors
    /// [`OcrError::Config`] for a malformed value.
    pub fn apply_env(mut self, getenv: &dyn Fn(&str) -> Option<String>) -> Result<Self, OcrError> {
        let get = |name: &str| {
            getenv(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        match get("CRAWLX_OCR_BACKEND") {
            Some(v) => self.backend = v.parse()?,
            None => {
                // Drop-in switch (wire-compat: env name set by existing deployments): on means the engine every self-host image carries
                let image_ocr = get("IMAGE_OCR_ENABLED")
                    .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"));
                if image_ocr && self.backend == OcrBackend::Off {
                    self.backend = OcrBackend::Tesseract;
                }
            }
        }
        if let Some(v) = get("CRAWLX_OCR_LANGUAGES") {
            self.languages = v;
        }
        if let Some(v) = get("CRAWLX_OCR_TESSERACT") {
            self.tesseract_path = Some(v.into());
        }
        if let Some(v) = get("CRAWLX_OCR_TESSDATA").or_else(|| get("TESSDATA_PREFIX")) {
            self.tessdata_dir = Some(v.into());
        }
        if let Some(v) = get("CRAWLX_OCR_MODELS") {
            self.models_dir = Some(v.into());
        }
        if let Some(v) = get("CRAWLX_OCR_RASTERIZER") {
            self.rasterizer = v.parse()?;
        }
        if let Some(v) = get("CRAWLX_OCR_PDFTOPPM") {
            self.pdftoppm_path = Some(v.into());
        }
        if let Some(v) = get("CRAWLX_OCR_DPI") {
            self.dpi = parse_num("CRAWLX_OCR_DPI", &v)?;
        }
        if let Some(v) = get("CRAWLX_OCR_TIMEOUT_MS") {
            self.timeout_ms = parse_num("CRAWLX_OCR_TIMEOUT_MS", &v)?;
        }
        if let Some(v) = get("CRAWLX_OCR_MAX_PDF_PAGES") {
            self.max_pdf_pages = parse_num("CRAWLX_OCR_MAX_PDF_PAGES", &v)?;
        }
        if let Some(v) = get("CRAWLX_OCR_MAX_IMAGE_PIXELS") {
            self.max_image_pixels = parse_num("CRAWLX_OCR_MAX_IMAGE_PIXELS", &v)?;
        }
        if let Some(v) = get("CRAWLX_OCR_MIN_CONFIDENCE") {
            self.min_confidence = parse_num("CRAWLX_OCR_MIN_CONFIDENCE", &v)?;
        }
        self.validate()?;
        Ok(self)
    }

    /// Check the ranges.
    ///
    /// # Errors
    /// [`OcrError::Config`] naming the setting.
    pub fn validate(&self) -> Result<(), OcrError> {
        let bad = |what: &str| Err(OcrError::Config(what.to_owned()));
        if self.languages.is_empty()
            || !self
                .languages
                .split('+')
                .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        {
            return bad("languages must be Tesseract codes joined by `+` (for example eng+tur)");
        }
        if !(72..=600).contains(&self.dpi) {
            return bad("dpi must be between 72 and 600");
        }
        if self.timeout_ms == 0 || self.max_pdf_pages == 0 || self.max_image_pixels == 0 {
            return bad("timeoutMs, maxPdfPages and maxImagePixels must be positive");
        }
        if self.min_confidence > 100 {
            return bad("minConfidence must be between 0 and 100");
        }
        Ok(())
    }
}

/// One recognised paragraph.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct OcrParagraph {
    /// The text, lines joined by a space.
    pub text: String,
    /// `[left, top, right, bottom]` in pixels of the recognised image.
    pub bbox: [u32; 4],
    /// Mean word confidence, 0 to 1; `None` when the engine reports none.
    pub confidence: Option<f64>,
}

/// The text of one image.
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub struct OcrPage {
    /// Width of the recognised image in pixels.
    pub width: u32,
    /// Height of the recognised image in pixels.
    pub height: u32,
    /// Paragraphs in reading order.
    pub paragraphs: Vec<OcrParagraph>,
}

impl OcrPage {
    /// The paragraphs separated by a blank line.
    #[must_use]
    pub fn text(&self) -> String {
        self.paragraphs
            .iter()
            .map(|p| p.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    /// Mean of the paragraph confidences, when the engine reports them.
    #[must_use]
    pub fn confidence(&self) -> Option<f64> {
        let values: Vec<f64> = self.paragraphs.iter().filter_map(|p| p.confidence).collect();
        if values.is_empty() {
            return None;
        }
        // a page has far fewer than 2^32 paragraphs
        Some(values.iter().sum::<f64>() / f64::from(u32::try_from(values.len()).unwrap_or(u32::MAX)))
    }
}

#[derive(Debug)]
enum Engine {
    Tesseract(tesseract::Tesseract),
    #[cfg(feature = "ocrs")]
    Ocrs(ocrs_backend::Ocrs),
}

/// A checked OCR engine. Build it once with [`Ocr::from_config`] and share it behind an `Arc`.
pub struct Ocr {
    config: OcrConfig,
    engine: Engine,
    pdftoppm: Option<PathBuf>,
}

impl fmt::Debug for Ocr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ocr")
            .field("backend", &self.config.backend)
            .field("languages", &self.config.languages)
            .field("rasterizer", &self.pdftoppm.is_some())
            .finish_non_exhaustive()
    }
}

impl PartialEq for Ocr {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config && self.pdftoppm == other.pdftoppm
    }
}

impl Eq for Ocr {}

impl Ocr {
    /// Check the backend of `config` and load it. `None` for `backend: off`.
    ///
    /// Runs the binaries (`tesseract --version`, `--list-langs`, `pdftoppm -v`) or loads the
    /// models, so a missing dependency fails at start-up and not on the first upload.
    ///
    /// # Errors
    /// [`OcrError::Config`] for out-of-range settings, [`OcrError::Unavailable`] when the engine
    /// (or a required `pdftoppm`) is missing.
    pub fn from_config(config: &OcrConfig) -> Result<Option<Self>, OcrError> {
        config.validate()?;
        let engine = match config.backend {
            OcrBackend::Off => return Ok(None),
            OcrBackend::Tesseract => Engine::Tesseract(tesseract::Tesseract::probe(config)?),
            #[cfg(feature = "ocrs")]
            OcrBackend::Ocrs => Engine::Ocrs(ocrs_backend::Ocrs::load(config.models_dir.as_deref())?),
            #[cfg(not(feature = "ocrs"))]
            OcrBackend::Ocrs => {
                return Err(OcrError::Unavailable {
                    backend: "ocrs",
                    reason: "this build has no `ocrs` feature".to_owned(),
                })
            }
        };
        let pdftoppm = raster::locate(config)?;
        Ok(Some(Self {
            config: config.clone(),
            engine,
            pdftoppm,
        }))
    }

    /// [`Ocr::from_config`] in an `Arc`, the form the API and the worker hold.
    ///
    /// # Errors
    /// As [`Ocr::from_config`].
    pub fn shared(config: &OcrConfig) -> Result<Option<Arc<Self>>, OcrError> {
        Ok(Self::from_config(config)?.map(Arc::new))
    }

    /// The configuration this engine was built from.
    #[must_use]
    pub const fn config(&self) -> &OcrConfig {
        &self.config
    }

    /// The backend.
    #[must_use]
    pub const fn backend(&self) -> OcrBackend {
        self.config.backend
    }

    /// Whether `pdftoppm` is available for PDF pages without an embedded image.
    #[must_use]
    pub const fn can_rasterize(&self) -> bool {
        self.pdftoppm.is_some()
    }

    pub(crate) fn timeout(&self) -> Duration {
        Duration::from_millis(self.config.timeout_ms)
    }

    /// Recognise the text of an image file (PNG, JPEG, GIF, BMP, TIFF, WebP; the first frame).
    ///
    /// Synchronous and CPU-bound: call it from a blocking thread.
    ///
    /// # Errors
    /// [`OcrError::Image`] for undecodable or oversized images; engine errors otherwise.
    pub fn recognize_bytes(&self, bytes: &[u8]) -> Result<OcrPage, OcrError> {
        let img = image_io::decode(bytes, self.config.max_image_pixels)?;
        self.recognize(&img, None)
    }

    /// Recognise the text of a decoded image. `dpi` is its scan resolution when known.
    ///
    /// # Errors
    /// [`OcrError::Image`] for an image over the pixel limit; engine errors otherwise.
    pub fn recognize(&self, img: &DynamicImage, dpi: Option<u32>) -> Result<OcrPage, OcrError> {
        image_io::check_size(img.width(), img.height(), self.config.max_image_pixels)?;
        match &self.engine {
            Engine::Tesseract(t) => {
                let png = image_io::to_png(img)?;
                t.recognize(&png, dpi)
            }
            #[cfg(feature = "ocrs")]
            Engine::Ocrs(o) => {
                // a model that panics on odd input must not unwind into the caller
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| o.recognize(img))).unwrap_or_else(
                    |_| {
                        Err(OcrError::Backend(
                            "ocrs: the engine panicked on this image".to_owned(),
                        ))
                    },
                )
            }
        }
    }
}
