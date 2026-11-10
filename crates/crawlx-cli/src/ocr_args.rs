//! OCR flags of `crawlx serve` and `crawlx worker` (`--ocr-*`).
//!
//! Precedence, highest first: the flags, the `CRAWLX_OCR_*` variables (and the compatibility API's
//! `IMAGE_OCR_ENABLED`), the `[ocr]` table of `crawlx.toml` (`$CRAWLX_CONFIG`, else
//! `./crawlx.toml` when present), the defaults (`backend = off`).

use anyhow::{anyhow, Context as _};
use clap::Args;
use crawlx_extract::parse::ocr::{Ocr, OcrBackend, OcrConfig, Rasterizer};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// OCR for scanned PDF pages and image files (compatibility API `parsers`: `mode: ocr`, `image`).
#[derive(Args, Debug, Clone, Default)]
pub struct OcrArgs {
    /// OCR engine: `off` (default), `tesseract` (the `tesseract` binary) or `ocrs` (pure Rust,
    /// models from `--ocr-models`). `CRAWLX_OCR_BACKEND`; `IMAGE_OCR_ENABLED=true` means tesseract.
    #[arg(long, value_name = "BACKEND", value_parser = |s: &str| s.parse::<OcrBackend>())]
    pub ocr_backend: Option<OcrBackend>,
    /// Tesseract language codes joined by `+` (default `eng`). `CRAWLX_OCR_LANGUAGES`.
    #[arg(long, value_name = "LANGS")]
    pub ocr_languages: Option<String>,
    /// The Tesseract binary (default: `tesseract` from `PATH`). `CRAWLX_OCR_TESSERACT`.
    #[arg(long, value_name = "FILE")]
    pub ocr_tesseract: Option<PathBuf>,
    /// Directory with the `.traineddata` files. `CRAWLX_OCR_TESSDATA`, else `TESSDATA_PREFIX`.
    #[arg(long, value_name = "DIR")]
    pub ocr_tessdata: Option<PathBuf>,
    /// Directory with `text-detection.onnx` and `text-recognition.onnx` for the `ocrs` engine
    /// (https://ocrs-models.s3-accelerate.amazonaws.com/). `CRAWLX_OCR_MODELS`.
    #[arg(long, value_name = "DIR")]
    pub ocr_models: Option<PathBuf>,
    /// Page source for PDF pages that draw no image: `auto` (`pdftoppm` when installed),
    /// `embedded` or `pdftoppm`. `CRAWLX_OCR_RASTERIZER`.
    #[arg(long, value_name = "MODE", value_parser = |s: &str| s.parse::<Rasterizer>())]
    pub ocr_rasterizer: Option<Rasterizer>,
    /// Pages of one PDF that are OCR'd (default 100). `CRAWLX_OCR_MAX_PDF_PAGES`.
    #[arg(long, value_name = "N")]
    pub ocr_max_pdf_pages: Option<u32>,
}

/// The `[ocr]` table of `crawlx.toml`, when a file is discoverable and has one.
fn from_file(getenv: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<OcrConfig> {
    let path = getenv("CRAWLX_CONFIG")
        .filter(|p| !p.trim().is_empty())
        .map_or_else(|| PathBuf::from("crawlx.toml"), PathBuf::from);
    if !Path::new(&path).is_file() {
        return Ok(OcrConfig::default());
    }
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let doc: toml::Table = text
        .parse()
        .with_context(|| format!("parsing {}", path.display()))?;
    match doc.get("ocr") {
        Some(table) => table
            .clone()
            .try_into()
            .map_err(|e| anyhow!("{}: [ocr] is invalid: {e}", path.display())),
        None => Ok(OcrConfig::default()),
    }
}

impl OcrArgs {
    /// The effective configuration: file, then environment, then these flags.
    ///
    /// # Errors
    /// An unreadable `crawlx.toml`, a malformed `[ocr]` table or `CRAWLX_OCR_*` value, or
    /// out-of-range settings.
    pub fn config(&self, getenv: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<OcrConfig> {
        let mut c = from_file(getenv)?.apply_env(getenv).map_err(|e| anyhow!("{e}"))?;
        if let Some(v) = self.ocr_backend {
            c.backend = v;
        }
        if let Some(v) = &self.ocr_languages {
            c.languages.clone_from(v);
        }
        if let Some(v) = &self.ocr_tesseract {
            c.tesseract_path = Some(v.clone());
        }
        if let Some(v) = &self.ocr_tessdata {
            c.tessdata_dir = Some(v.clone());
        }
        if let Some(v) = &self.ocr_models {
            c.models_dir = Some(v.clone());
        }
        if let Some(v) = self.ocr_rasterizer {
            c.rasterizer = v;
        }
        if let Some(v) = self.ocr_max_pdf_pages {
            c.max_pdf_pages = v;
        }
        c.validate().map_err(|e| anyhow!("{e}"))?;
        Ok(c)
    }

    /// Build the engine of [`Self::config`]: `None` for `off`. Runs the probe (`tesseract
    /// --version`, model loading) on the blocking pool, so a missing dependency stops the
    /// command at start-up.
    ///
    /// # Errors
    /// As [`Self::config`], and [`crawlx_extract::parse::ocr::OcrError::Unavailable`] when the
    /// engine cannot run here.
    pub async fn engine(&self, getenv: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Option<Arc<Ocr>>> {
        let config = self.config(getenv)?;
        tokio::task::spawn_blocking(move || Ocr::shared(&config))
            .await
            .context("the OCR probe did not finish")?
            .map_err(|e| anyhow!("ocr: {e}"))
    }
}
