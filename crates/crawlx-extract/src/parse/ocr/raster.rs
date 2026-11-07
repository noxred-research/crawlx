//! Rendering a PDF page to pixels with `pdftoppm` (poppler), for pages that draw no image the
//! decoders read: vector-only pages, JBIG2 and JPEG 2000 scans.

use std::path::{Path, PathBuf};
use std::process::Command;

use image::DynamicImage;

use super::{image_io, process, Ocr, OcrConfig, OcrError, Rasterizer};

/// The `pdftoppm` binary the config allows, checked with `-v`.
pub(super) fn locate(config: &OcrConfig) -> Result<Option<PathBuf>, OcrError> {
    if config.rasterizer == Rasterizer::Embedded {
        return Ok(None);
    }
    let wanted = config
        .pdftoppm_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("pdftoppm"));
    let found = process::resolve(&wanted).filter(|p| {
        // poppler prints its version on stderr and exits 0
        process::run(
            {
                let mut c = Command::new(p);
                c.arg("-v");
                c
            },
            p,
            &[],
            std::time::Duration::from_millis(config.timeout_ms),
        )
        .is_ok_and(|o| o.status.success())
    });
    match (found, config.rasterizer) {
        (Some(p), _) => Ok(Some(p)),
        (None, Rasterizer::Pdftoppm) => Err(OcrError::Unavailable {
            backend: "pdftoppm",
            reason: format!(
                "the `{}` binary was not found; install poppler-utils or set CRAWLX_OCR_PDFTOPPM",
                process::program_name(&wanted)
            ),
        }),
        (None, _) => Ok(None),
    }
}

/// One PDF written to a temporary directory, rendered page by page.
#[derive(Debug)]
pub(crate) struct PdfRaster {
    program: PathBuf,
    dir: tempfile::TempDir,
    pdf: PathBuf,
    dpi: u32,
    max_pixels: u64,
    timeout: std::time::Duration,
}

impl PdfRaster {
    /// The renderer of `bytes`, or `None` when `ocr` has no `pdftoppm`.
    pub(crate) fn new(ocr: &Ocr, bytes: &[u8]) -> Result<Option<Self>, OcrError> {
        let Some(program) = ocr.pdftoppm.clone() else {
            return Ok(None);
        };
        let io = |e: std::io::Error| OcrError::Backend(format!("pdftoppm: temporary file: {e}"));
        let dir = tempfile::Builder::new()
            .prefix("crawlx-ocr-")
            .tempdir()
            .map_err(io)?;
        let pdf = dir.path().join("input.pdf");
        std::fs::write(&pdf, bytes).map_err(io)?;
        Ok(Some(Self {
            program,
            dir,
            pdf,
            dpi: ocr.config.dpi,
            max_pixels: ocr.config.max_image_pixels,
            timeout: ocr.timeout(),
        }))
    }

    /// Render page `number` (1-based). `size_pt` is the page's size in PDF points when known:
    /// the resolution is lowered so the bitmap stays under the pixel limit.
    pub(crate) fn render(&self, number: u32, size_pt: Option<(f32, f32)>) -> Result<DynamicImage, OcrError> {
        let mut dpi = self.dpi;
        if let Some((w, h)) = size_pt {
            let area_in2 = f64::from(w.max(1.0)) * f64::from(h.max(1.0)) / (72.0 * 72.0);
            // pixels = area * dpi^2: lower the resolution (never under 72) until the page fits
            let pixels = |d: u32| area_in2 * f64::from(d) * f64::from(d);
            while dpi > 72 && pixels(dpi) > self.max_pixels as f64 {
                dpi -= 1;
            }
        }
        let out_root = self.dir.path().join(format!("page-{number}"));
        let mut cmd = Command::new(&self.program);
        cmd.args(["-f", &number.to_string(), "-l", &number.to_string()])
            .args(["-r", &dpi.to_string(), "-gray", "-png", "-singlefile"])
            .arg(&self.pdf)
            .arg(&out_root);
        let out = process::run(cmd, &self.program, &[], self.timeout)?;
        if !out.status.success() {
            return Err(OcrError::Failed {
                program: process::program_name(&self.program),
                status: out.status.to_string(),
                stderr: out.stderr,
            });
        }
        let png = read_png(&out_root.with_extension("png"))?;
        image_io::decode(&png, self.max_pixels)
    }
}

fn read_png(path: &Path) -> Result<Vec<u8>, OcrError> {
    std::fs::read(path).map_err(|e| OcrError::Backend(format!("pdftoppm wrote no page image: {e}")))
}
