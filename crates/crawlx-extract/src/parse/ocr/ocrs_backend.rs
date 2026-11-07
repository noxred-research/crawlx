//! The `ocrs` backend: the pure-Rust `ocrs` engine over `rten` models.
//!
//! The two models are not part of the build and are never downloaded by crawlx. Put them in
//! the directory `CRAWLX_OCR_MODELS` names:
//!
//! ```text
//! curl -LO https://ocrs-models.s3-accelerate.amazonaws.com/text-detection.onnx
//! curl -LO https://ocrs-models.s3-accelerate.amazonaws.com/text-recognition.onnx
//! ```
//!
//! (`.rten` files of the same names are accepted too.) The models read Latin text.

use std::path::{Path, PathBuf};

use image::DynamicImage;
use ocrs::{ImageSource, OcrEngine, OcrEngineParams, TextItem};

use super::{image_io, OcrError, OcrPage, OcrParagraph};

const DETECTION: &str = "text-detection";
const RECOGNITION: &str = "text-recognition";

/// A loaded `ocrs` engine.
pub(super) struct Ocrs {
    engine: OcrEngine,
    models: PathBuf,
}

impl std::fmt::Debug for Ocrs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ocrs")
            .field("models", &self.models)
            .finish_non_exhaustive()
    }
}

fn model_file(dir: &Path, stem: &str) -> Option<PathBuf> {
    ["onnx", "rten"]
        .iter()
        .map(|ext| dir.join(format!("{stem}.{ext}")))
        .find(|p| p.is_file())
}

impl Ocrs {
    /// Load both models from `dir`.
    pub(super) fn load(dir: Option<&Path>) -> Result<Self, OcrError> {
        let unavailable = |reason: String| OcrError::Unavailable {
            backend: "ocrs",
            reason,
        };
        let dir = dir.ok_or_else(|| {
            unavailable(
                "no model directory; set CRAWLX_OCR_MODELS to a directory holding text-detection.onnx and text-recognition.onnx (https://ocrs-models.s3-accelerate.amazonaws.com/)".to_owned(),
            )
        })?;
        let load = |stem: &str| -> Result<rten::Model, OcrError> {
            let file = model_file(dir, stem).ok_or_else(|| {
                unavailable(format!(
                    "{stem}.onnx (or .rten) is missing in the model directory; download it from https://ocrs-models.s3-accelerate.amazonaws.com/{stem}.onnx"
                ))
            })?;
            rten::Model::load_file(&file)
                .map_err(|e| unavailable(format!("{} cannot be loaded: {e}", file.display())))
        };
        let engine = OcrEngine::new(OcrEngineParams {
            detection_model: Some(load(DETECTION)?),
            recognition_model: Some(load(RECOGNITION)?),
            ..OcrEngineParams::default()
        })
        .map_err(|e| unavailable(format!("the engine cannot be built from the models: {e}")))?;
        Ok(Self {
            engine,
            models: dir.to_path_buf(),
        })
    }

    /// Recognise `img`: lines in reading order, grouped into paragraphs by their spacing.
    pub(super) fn recognize(&self, img: &DynamicImage) -> Result<OcrPage, OcrError> {
        let backend = |e: &dyn std::fmt::Display| OcrError::Backend(format!("ocrs: {e}"));
        let rgb = image_io::to_rgb(img);
        let (width, height) = rgb.dimensions();
        let source = ImageSource::from_bytes(rgb.as_raw(), (width, height)).map_err(|e| backend(&e))?;
        let input = self.engine.prepare_input(source).map_err(|e| backend(&e))?;
        let words = self.engine.detect_words(&input).map_err(|e| backend(&e))?;
        let lines = self.engine.find_text_lines(&input, &words);
        let recognized = self
            .engine
            .recognize_text(&input, &lines)
            .map_err(|e| backend(&e))?;
        let mut paragraphs: Vec<OcrParagraph> = Vec::new();
        // bottom edge and height of the previous line, to tell a wrapped line from a new paragraph
        let mut previous: Option<(i64, i64)> = None;
        for line in recognized.into_iter().flatten() {
            let text = line.to_string();
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            let r = line.bounding_rect();
            let (left, top, right, bottom) = (r.left(), r.top(), r.right(), r.bottom());
            let clamp = |v: i32| u32::try_from(v.max(0)).unwrap_or(0);
            let bbox = [clamp(left), clamp(top), clamp(right), clamp(bottom)];
            let line_height = i64::from(bottom - top).max(1);
            let continues = previous.is_some_and(|(prev_bottom, prev_height)| {
                i64::from(top) - prev_bottom <= prev_height.max(line_height) * 3 / 4
            });
            match paragraphs.last_mut() {
                Some(p) if continues => {
                    join(&mut p.text, text);
                    p.bbox = [
                        p.bbox[0].min(bbox[0]),
                        p.bbox[1].min(bbox[1]),
                        p.bbox[2].max(bbox[2]),
                        p.bbox[3].max(bbox[3]),
                    ];
                }
                _ => paragraphs.push(OcrParagraph {
                    text: text.to_owned(),
                    bbox,
                    confidence: None,
                }),
            }
            previous = Some((i64::from(bottom), line_height));
        }
        Ok(OcrPage {
            width,
            height,
            paragraphs,
        })
    }
}

fn join(into: &mut String, line: &str) {
    if into.ends_with('-') && into.chars().rev().nth(1).is_some_and(char::is_alphabetic) {
        into.pop();
    } else {
        into.push(' ');
    }
    into.push_str(line);
}
