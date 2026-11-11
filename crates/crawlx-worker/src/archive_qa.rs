//! Bounded offline archive QA. Missing baselines are never counted as equal.

use crate::archive_replay::{ReplayCapture, ReplayError, ReplayReport};
use crawlx_core::parser_memory::{global, AdmittedBytes, ByteAdmissionError, BytePermit};
use image::{DynamicImage, ImageDecoder as _, ImageReader};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::Cursor;

/// One evaluated or explicitly absent comparison.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct QaComparison {
    /// Stable page/capture or provenance/resource identifier.
    pub subject: String,
    /// None means not evaluated because the baseline is absent.
    pub passed: Option<bool>,
    /// Normalized pixel/text distance when measured.
    pub distance: Option<f64>,
    /// Explicit result, including missing-baseline reasons.
    pub reason: String,
}

/// Honest aggregate QA result.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct QaReport {
    /// Result schema.
    pub schema_version: u8,
    /// Number of real comparisons that passed.
    pub passed: usize,
    /// Number of real comparisons that failed.
    pub failed: usize,
    /// Number of requested comparisons with no baseline.
    pub not_evaluated: usize,
    /// Individual comparison facts.
    pub comparisons: Vec<QaComparison>,
}

impl QaReport {
    /// Whether every requested comparison was actually evaluated and passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failed == 0 && self.not_evaluated == 0 && self.passed > 0
    }
}

/// Optional decoded-channel difference image. Retain through the sensitive artifact sink.
#[non_exhaustive]
pub struct QaDiff {
    /// Page ordinal within the selected replay.
    pub page: usize,
    /// Screenshot phase, independent of archive-controlled paths.
    pub phase: String,
    /// PNG evidence; never embed these bytes in a JSON report.
    pub capture: ReplayCapture,
}

/// Fixed allowance for the deflate compressor state. `flate2` 1.1 over `miniz_oxide` keeps a
/// 32 KiB dictionary with its hash chains and a small Huffman table, a few hundred KiB; 1 MiB
/// is a deliberate rounding-up, not a measurement.
const PNG_COMPRESSOR_STATE_BYTES: usize = 1024 * 1024;

/// Upper bound on what `image` 0.25 / `png` 0.18 allocate while encoding an `Rgba8` image with
/// its default (balanced, adaptive-filter) settings, derived from their source and **not
/// measured**: the previous-row buffer and the filtered-row buffer (two rows), the whole zlib
/// stream held in a `Vec` before it is written out, and the compressor state.
///
/// The zlib stream cannot exceed the stored-block form of the filtered input (one filter byte
/// per row plus `5` bytes per `65535`-byte block plus the `6`-byte zlib frame). A `Vec` that
/// grows by doubling holds its old and its new buffer while it moves, so up to `3x` that size
/// can be live at once. This is an admission bound; the allocator is still infallible, so the
/// guarantee is only that the shared budget refuses the encode before it starts.
fn png_encoder_bytes(width: u32, height: u32) -> Result<usize, ReplayError> {
    let bound = || ReplayError::Refused("QA difference pixel bound");
    let row = usize::try_from(width)
        .ok()
        .and_then(|w| w.checked_mul(4))
        .ok_or_else(bound)?;
    let rows = usize::try_from(height).map_err(|_| bound())?;
    let filtered = row
        .checked_add(1)
        .and_then(|r| r.checked_mul(rows))
        .ok_or_else(bound)?;
    let stream = filtered
        .checked_add(filtered.div_ceil(65_535).checked_mul(5).ok_or_else(bound)?)
        .and_then(|n| n.checked_add(6))
        .ok_or_else(bound)?;
    stream
        .checked_mul(3)
        .and_then(|n| n.checked_add(row.checked_mul(2)?))
        .and_then(|n| n.checked_add(PNG_COMPRESSOR_STATE_BYTES))
        .ok_or_else(bound)
}

/// Reserve the encoder's bound before the encoder runs and hold it until it is dropped.
fn png_encoder_guard(width: u32, height: u32) -> Result<BytePermit, ReplayError> {
    global()
        .try_reserve(png_encoder_bytes(width, height)?)
        .map_err(|_| ReplayError::Refused("QA difference encoder byte admission"))
}

/// Bounded PNG sink that reserves every growth step before the buffer allocates it.
struct BoundedPng {
    bytes: Vec<u8>,
    permit: BytePermit,
    maximum: usize,
}

impl BoundedPng {
    fn new(maximum: usize) -> Result<Self, ReplayError> {
        let permit = global()
            .try_reserve(0)
            .map_err(|_| ReplayError::Refused("QA difference byte admission"))?;
        Ok(Self {
            bytes: Vec::new(),
            permit,
            maximum,
        })
    }

    /// Hand the encoded bytes and the reservation covering their capacity to the caller.
    fn finish(mut self) -> Result<AdmittedBytes, ReplayError> {
        self.permit
            .grow_to(self.bytes.capacity())
            .map_err(|_| ReplayError::Refused("QA difference byte admission"))?;
        Ok(AdmittedBytes::new(self.bytes, self.permit))
    }
}

impl std::io::Write for BoundedPng {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("QA difference PNG byte bound"));
        }
        let needed = self.bytes.len() + bytes.len();
        if needed > self.bytes.capacity() {
            let target = needed
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.maximum);
            self.permit
                .grow_to(target)
                .map_err(|_| std::io::Error::other("QA difference byte admission"))?;
            self.bytes.reserve_exact(target - self.bytes.len());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Produce optional bounded screenshot differences for matching retained page phases.
/// Equal samples are black; channel differences are visible, including alpha changes.
/// Different-sized captures use a shared canvas and mark unmatched pixels magenta.
/// Missing or truncated captures remain unevaluated in [`compare`] and yield no image.
///
/// # Errors
/// Rejects corrupt capture fixity, invalid PNGs, excessive pixels, or more than
/// 64 MiB of encoded difference images. Call from a blocking computation pool.
pub fn diff_images(actual: &ReplayReport, baseline: &ReplayReport) -> Result<Vec<QaDiff>, ReplayError> {
    use image::ImageEncoder as _;

    if actual.pages.len() > 32 || baseline.pages.len() > 32 {
        return Err(ReplayError::Refused("QA page count bound"));
    }
    let mut remaining = 64 * 1024 * 1024;
    let mut differences = Vec::new();
    for page in &actual.pages {
        let Some(prior) = baseline
            .pages
            .iter()
            .find(|prior| prior.ordinal == page.ordinal && prior.target == page.target)
        else {
            continue;
        };
        for phase in ["viewport", "full_page", "final"] {
            let Some(capture) = page.captures.iter().find(|capture| capture.kind == phase) else {
                continue;
            };
            let Some(expected) = prior.captures.iter().find(|capture| capture.kind == phase) else {
                continue;
            };
            if capture.truncated
                || expected.truncated
                || capture.media_type != "image/png"
                || expected.media_type != "image/png"
            {
                continue;
            }
            checked_bytes(capture)?;
            let identical = capture.bytes == expected.bytes;
            if identical {
                if capture.length != expected.length || capture.digest != expected.digest {
                    return Err(ReplayError::Refused("QA capture fixity or byte bound"));
                }
            } else {
                checked_bytes(expected)?;
            }
            let left = pixels(&capture.bytes)?;
            let decoded = if identical {
                None
            } else {
                Some(pixels(&expected.bytes)?)
            };
            let right = decoded.as_ref().unwrap_or(&left);
            let width = left.width().max(right.width());
            let height = left.height().max(right.height());
            if u64::from(width) * u64::from(height) > 16_777_216 {
                return Err(ReplayError::Refused("QA difference pixel bound"));
            }
            let _canvas = global()
                .try_reserve(rgba_bytes(width, height)?)
                .map_err(admission)?;
            let image = image::RgbaImage::from_fn(width, height, |x, y| {
                match (left.get_pixel_checked(x, y), right.get_pixel_checked(x, y)) {
                    (Some(a), Some(b)) => {
                        let alpha = a[3].abs_diff(b[3]);
                        image::Rgba([
                            a[0].abs_diff(b[0]).max(alpha),
                            a[1].abs_diff(b[1]).max(alpha),
                            a[2].abs_diff(b[2]).max(alpha),
                            255,
                        ])
                    }
                    _ => image::Rgba([255, 0, 255, 255]),
                }
            });
            let _encoder_memory = png_encoder_guard(width, height)?;
            let mut output = BoundedPng::new(remaining.min(16 * 1024 * 1024))?;
            image::codecs::png::PngEncoder::new(&mut output)
                .write_image(image.as_raw(), width, height, image::ExtendedColorType::Rgba8)
                .map_err(ReplayError::Image)?;
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&output.bytes)));
            let length = output.bytes.len();
            remaining = remaining.saturating_sub(length);
            differences.push(QaDiff {
                page: page.ordinal,
                phase: phase.into(),
                capture: ReplayCapture {
                    kind: format!("diff_{phase}"),
                    digest,
                    media_type: "image/png".into(),
                    length,
                    truncated: false,
                    bytes: output.finish()?,
                },
            });
        }
    }
    Ok(differences)
}

fn checked_bytes(capture: &ReplayCapture) -> Result<(), ReplayError> {
    if capture.bytes.len() > 16 * 1024 * 1024
        || capture.length != capture.bytes.len()
        || capture.digest != format!("sha256:{}", hex::encode(Sha256::digest(&capture.bytes)))
    {
        return Err(ReplayError::Refused("QA capture fixity or byte bound"));
    }
    Ok(())
}

/// A decoded RGBA image that keeps the reservation covering its pixel buffer.
struct ChargedImage {
    image: image::RgbaImage,
    _permit: BytePermit,
}

impl std::ops::Deref for ChargedImage {
    type Target = image::RgbaImage;
    fn deref(&self) -> &image::RgbaImage {
        &self.image
    }
}

fn rgba_bytes(width: u32, height: u32) -> Result<usize, ReplayError> {
    usize::try_from(u64::from(width) * u64::from(height))
        .ok()
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(ReplayError::Refused("QA image pixel bound"))
}

fn admission(_: ByteAdmissionError) -> ReplayError {
    ReplayError::Refused("QA image byte admission")
}

/// Decode a PNG to RGBA. The decoder's native buffer (up to 16-bit samples) and the converted
/// RGBA8 buffer are both reserved from the declared dimensions before any pixel is allocated;
/// once converted, only the RGBA8 share stays reserved.
fn pixels(bytes: &[u8]) -> Result<ChargedImage, ReplayError> {
    let decoder = ImageReader::with_format(Cursor::new(bytes), image::ImageFormat::Png)
        .into_decoder()
        .map_err(|_| ReplayError::Refused("invalid QA PNG"))?;
    let (width, height) = decoder.dimensions();
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > 16_777_216 {
        return Err(ReplayError::Refused("QA image pixel bound"));
    }
    let rgba = rgba_bytes(width, height)?;
    let native =
        usize::try_from(decoder.total_bytes()).map_err(|_| ReplayError::Refused("QA image pixel bound"))?;
    let total = native
        .checked_add(rgba)
        .ok_or(ReplayError::Refused("QA image pixel bound"))?;
    let mut permit = global().try_reserve(total).map_err(admission)?;
    let image = DynamicImage::from_decoder(decoder)
        .map(DynamicImage::into_rgba8)
        .map_err(|_| ReplayError::Refused("QA image decoding failed"))?;
    // The conversion may reuse or replace the native buffer; keep exactly the RGBA8 share.
    let kept = permit.split(rgba).map_err(admission)?;
    drop(permit);
    Ok(ChargedImage { image, _permit: kept })
}

fn pixel_distance(left: &[u8], right: &[u8]) -> Result<f64, ReplayError> {
    let a = pixels(left)?;
    if left == right {
        return Ok(0.0);
    }
    let b = pixels(right)?;
    if a.dimensions() != b.dimensions() {
        return Ok(1.0);
    }
    let sum: u64 = a
        .as_raw()
        .iter()
        .zip(b.as_raw())
        .map(|(a, b)| u64::from(a.abs_diff(*b)))
        .sum();
    Ok(sum as f64 / (a.as_raw().len() as f64 * 255.0))
}

/// Largest QA text accepted for distance work, in bytes.
const QA_TEXT_BYTES: usize = 262_144;

fn grow(permit: &mut BytePermit, bytes: usize) -> Result<(), ReplayError> {
    permit
        .grow_by(bytes)
        .map_err(|_| ReplayError::Refused("QA text byte admission"))
}

/// Whitespace-normalize `bytes` into a string whose exact capacity was added to `permit`
/// first. Normalization only removes or shrinks whitespace runs to one space, so the result
/// never exceeds the input length; that bound is the reservation.
fn normalized(bytes: &[u8], permit: &mut BytePermit) -> Result<String, ReplayError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ReplayError::Refused("QA text is not UTF-8"))?;
    if text.len() > QA_TEXT_BYTES {
        return Err(ReplayError::Refused("QA text byte bound"));
    }
    grow(permit, text.len())?;
    let mut out = String::with_capacity(text.len());
    for word in text.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    Ok(out)
}

/// Characters of `text` in a vector whose exact size was added to `permit` first.
fn chars_of(text: &str, permit: &mut BytePermit) -> Result<Vec<char>, ReplayError> {
    let count = text.chars().count();
    grow(
        permit,
        count
            .checked_mul(std::mem::size_of::<char>())
            .ok_or(ReplayError::Refused("QA text byte bound"))?,
    )?;
    let mut chars = Vec::with_capacity(count);
    chars.extend(text.chars());
    Ok(chars)
}

fn text_distance(left: &[u8], right: &[u8]) -> Result<f64, ReplayError> {
    // Every buffer below is reserved, with checked exact sizes, before it is allocated and
    // stays reserved until the distance is computed.
    let mut permit = global()
        .try_reserve(0)
        .map_err(|_| ReplayError::Refused("QA text byte admission"))?;
    let left = normalized(left, &mut permit)?;
    let right = normalized(right, &mut permit)?;
    if left == right {
        return Ok(0.0);
    }
    let a = chars_of(&left, &mut permit)?;
    let b = chars_of(&right, &mut permit)?;
    let length = a.len().max(b.len());
    if length == 0 {
        return Ok(0.0);
    }
    let prefix = a.iter().zip(&b).take_while(|(a, b)| a == b).count();
    let a = &a[prefix..];
    let b = &b[prefix..];
    let suffix = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let a = &a[..a.len() - suffix];
    let b = &b[..b.len() - suffix];
    if a.len().saturating_mul(b.len()) > 4_194_304 {
        return Err(ReplayError::Refused("QA text distance operation bound"));
    }
    let row = b
        .len()
        .checked_add(1)
        .ok_or(ReplayError::Refused("QA text byte bound"))?;
    grow(
        &mut permit,
        row.checked_mul(std::mem::size_of::<usize>() * 2)
            .ok_or(ReplayError::Refused("QA text byte bound"))?,
    )?;
    let mut previous: Vec<usize> = Vec::with_capacity(row);
    previous.extend(0..=b.len());
    let mut current = vec![0usize; row];
    for (i, ca) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            current[j + 1] = (previous[j + 1] + 1)
                .min(current[j] + 1)
                .min(previous[j] + usize::from(ca != cb));
        }
        std::mem::swap(&mut previous, &mut current);
    }
    Ok(previous[b.len()] as f64 / length as f64)
}

fn refusal_evidence(report: &ReplayReport) -> Vec<&str> {
    report
        .denial_evidence
        .iter()
        .take(32)
        .map(|detail| {
            if detail.len() <= 2048
                && crate::archive_replay::approve_body("text/plain", detail.as_bytes()).is_ok()
            {
                detail.as_str()
            } else {
                "refusal_details_redacted"
            }
        })
        .collect()
}

/// Compare actual replay captures with a pinned baseline. Thresholds are normalized
/// distances in 0..=1; the default caller passes zero for exact fixture equality.
/// Resource comparison includes actual request count, status and served-byte digest.
///
/// # Errors
/// Rejects invalid thresholds, corrupt PNGs/capture fixity and bounded-work overflow.
/// This CPU-bound operation should run in the worker's blocking/CPU pool.
pub fn compare(
    actual: &ReplayReport,
    baseline: Option<&ReplayReport>,
    max_pixel_distance: f64,
    max_text_distance: f64,
) -> Result<QaReport, ReplayError> {
    if !max_pixel_distance.is_finite()
        || !max_text_distance.is_finite()
        || !(0.0..=1.0).contains(&max_pixel_distance)
        || !(0.0..=1.0).contains(&max_text_distance)
    {
        return Err(ReplayError::Refused("QA distance thresholds must be 0..1"));
    }
    if actual.pages.len() > 32 || baseline.is_some_and(|b| b.pages.len() > 32) {
        return Err(ReplayError::Refused("QA page count bound"));
    }
    let mut comparisons = Vec::new();
    let pins_equal = baseline.map(|b| {
        b.schema_version == actual.schema_version
            && b.archive_digest == actual.archive_digest
            && b.policy == actual.policy
            && b.dependency_digests == actual.dependency_digests
            && b.build == actual.build
            && b.browser == actual.browser
            && b.seed == actual.seed
            && b.page_filter == actual.page_filter
            && b.viewport == actual.viewport
    });
    comparisons.push(QaComparison {
        subject: "pins".into(),
        passed: pins_equal,
        distance: None,
        reason: if baseline.is_none() {
            "baseline_absent"
        } else if pins_equal == Some(true) {
            "pins_match"
        } else {
            "pin_mismatch"
        }
        .into(),
    });
    comparisons.push(QaComparison {
        subject: "resources".into(),
        passed: baseline.map(|b| actual.resources == b.resources),
        distance: None,
        reason: if baseline.is_none() {
            "baseline_absent"
        } else {
            "resource_count_status_digest_comparison"
        }
        .into(),
    });
    comparisons.push(QaComparison {
        subject: "denied_requests".into(),
        passed: baseline.map(|b| actual.denied_requests == b.denied_requests),
        distance: None,
        reason: baseline.map_or_else(
            || "baseline_absent".into(),
            |b| {
                format!(
            "actual_proxy_refusals actual={} baseline={}; actual_evidence={:?}; baseline_evidence={:?}",
            actual.denied_requests, b.denied_requests, refusal_evidence(actual), refusal_evidence(b))
            },
        ),
    });
    for page in &actual.pages {
        for kind in ["initial_text", "viewport", "full_page", "final_text", "final"] {
            let subject = format!("page:{}/{kind}", page.ordinal);
            let capture = page.captures.iter().find(|c| c.kind == kind);
            let expected = baseline
                .and_then(|b| {
                    b.pages
                        .iter()
                        .find(|p| p.ordinal == page.ordinal && p.target == page.target)
                })
                .and_then(|p| p.captures.iter().find(|c| c.kind == kind));
            let (Some(capture), Some(expected)) = (capture, expected) else {
                comparisons.push(QaComparison {
                    subject,
                    passed: if capture.is_none() { Some(false) } else { None },
                    distance: None,
                    reason: if capture.is_none() {
                        "actual_capture_absent"
                    } else {
                        "baseline_capture_absent"
                    }
                    .into(),
                });
                continue;
            };
            checked_bytes(capture)?;
            checked_bytes(expected)?;
            if capture.truncated || expected.truncated {
                comparisons.push(QaComparison {
                    subject,
                    passed: None,
                    distance: None,
                    reason: "truncated_capture_not_fully_evaluated".into(),
                });
                continue;
            }
            if capture.media_type != expected.media_type {
                comparisons.push(QaComparison {
                    subject,
                    passed: Some(false),
                    distance: None,
                    reason: "capture_media_mismatch".into(),
                });
                continue;
            }
            let (distance, max) = if capture.media_type == "image/png" {
                (
                    pixel_distance(&capture.bytes, &expected.bytes)?,
                    max_pixel_distance,
                )
            } else if capture.media_type == "text/plain" {
                (text_distance(&capture.bytes, &expected.bytes)?, max_text_distance)
            } else {
                return Err(ReplayError::Refused("unsupported QA capture type"));
            };
            comparisons.push(QaComparison {
                subject,
                passed: Some(distance <= max),
                distance: Some(distance),
                reason: "measured_distance".into(),
            });
        }
    }
    if let Some(baseline) = baseline {
        for page in &baseline.pages {
            if !actual
                .pages
                .iter()
                .any(|p| p.ordinal == page.ordinal && p.target == page.target)
            {
                comparisons.push(QaComparison {
                    subject: format!("page:{}", page.ordinal),
                    passed: Some(false),
                    distance: None,
                    reason: "expected_page_absent".into(),
                });
            }
        }
    }
    Ok(QaReport {
        schema_version: 1,
        passed: comparisons.iter().filter(|c| c.passed == Some(true)).count(),
        failed: comparisons.iter().filter(|c| c.passed == Some(false)).count(),
        not_evaluated: comparisons.iter().filter(|c| c.passed.is_none()).count(),
        comparisons,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn image_report(width: u32, pixel: [u8; 4]) -> ReplayReport {
        use image::ImageEncoder as _;
        let image = image::RgbaImage::from_pixel(width, 1, image::Rgba(pixel));
        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(image.as_raw(), width, 1, image::ExtendedColorType::Rgba8)
            .unwrap();
        ReplayReport {
            schema_version: 1,
            archive_digest: "fixture".into(),
            dependency_digests: Vec::new(),
            policy: "fixture".into(),
            build: "fixture".into(),
            browser: crawlx_core::observation::BrowserBuildInfo {
                chromium_version: "fixture".into(),
                cdp_revision: "fixture".into(),
                user_agent: "fixture".into(),
                pinned: true,
                launch_profile: Default::default(),
                console_capture: false,
                attached: false,
            },
            seed: crawlx_core::seed::CrawlSeed(0),
            page_filter: None,
            viewport: (1, 1),
            pages: vec![crate::archive_replay::ReplayPage {
                ordinal: 0,
                target: "https://fixture.example.test/".into(),
                captures: vec![ReplayCapture {
                    kind: "viewport".into(),
                    digest: format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
                    media_type: "image/png".into(),
                    length: bytes.len(),
                    truncated: false,
                    bytes: AdmittedBytes::new(bytes.clone(), global().try_reserve(bytes.len()).unwrap()),
                }],
            }],
            resources: Vec::new(),
            denied_requests: 0,
            denial_evidence: Vec::new(),
            limitations: Vec::new(),
        }
    }

    #[test]
    fn difference_images_measure_channels_alpha_and_missing_pixels() {
        let baseline = image_report(1, [10, 20, 30, 255]);
        let equal = diff_images(&baseline, &baseline).unwrap();
        assert_eq!(equal.len(), 1);
        assert_eq!(equal[0].phase, "viewport");
        checked_bytes(&equal[0].capture).unwrap();
        assert_eq!(
            pixels(&equal[0].capture.bytes).unwrap().get_pixel(0, 0).0,
            [0, 0, 0, 255]
        );

        let actual = image_report(2, [20, 20, 30, 250]);
        let differences = diff_images(&actual, &baseline).unwrap();
        let decoded = pixels(&differences[0].capture.bytes).unwrap();
        assert_eq!(decoded.dimensions(), (2, 1));
        assert_eq!(decoded.get_pixel(0, 0).0, [10, 5, 5, 255]);
        assert_eq!(decoded.get_pixel(1, 0).0, [255, 0, 255, 255]);
    }

    #[test]
    fn difference_images_refuse_bad_fixity_and_skip_unmeasured_pairs() {
        let baseline = image_report(1, [0, 0, 0, 255]);
        let mut bad_baseline = baseline.clone();
        bad_baseline.pages[0].captures[0].length = 0;
        assert!(diff_images(&baseline, &bad_baseline).is_err());
        bad_baseline.pages[0].captures[0].length = baseline.pages[0].captures[0].length;
        bad_baseline.pages[0].captures[0].digest.clear();
        assert!(diff_images(&baseline, &bad_baseline).is_err());
        let mut actual = baseline.clone();
        actual.pages[0].captures[0].digest.clear();
        assert!(diff_images(&actual, &baseline).is_err());
        actual.pages[0].captures[0].truncated = true;
        assert!(diff_images(&actual, &baseline).unwrap().is_empty());
        actual.pages[0].captures.clear();
        assert!(diff_images(&actual, &baseline).unwrap().is_empty());
        actual.pages.clear();
        assert!(diff_images(&actual, &baseline).unwrap().is_empty());
    }

    #[test]
    fn difference_encoder_rejects_growth_before_appending() {
        use std::io::Write as _;
        let mut output = BoundedPng::new(2).unwrap();
        output.write_all(b"ab").unwrap();
        assert!(output.write_all(b"c").is_err());
        assert_eq!(output.bytes, b"ab");
    }

    #[test]
    fn normalized_levenshtein_is_measured_not_encoded_byte_difference() {
        assert_eq!(text_distance(b"alpha  beta", b"alpha beta").unwrap(), 0.0);
        assert!(text_distance(b"alpha", b"omega").unwrap() > 0.0);
        assert_eq!(text_distance(b"", b"hello").unwrap(), 1.0);
    }

    #[test]
    fn png_encoder_bound_covers_stream_rows_and_state_and_never_wraps() {
        // 1x1: two rows (8) + 3 x (filtered 5 + 5 + 6) + 1 MiB state.
        assert_eq!(
            png_encoder_bytes(1, 1).unwrap(),
            8 + 3 * 16 + PNG_COMPRESSOR_STATE_BYTES
        );
        let large = png_encoder_bytes(4096, 4096).unwrap();
        assert!(
            large > 3 * 4096 * 4096 * 4,
            "stored-block form is the floor of the bound"
        );
        assert!(png_encoder_bytes(u32::MAX, u32::MAX).is_err());
    }

    #[test]
    fn png_encoder_guard_refuses_before_encoding_and_holds_until_dropped() {
        let budget = std::sync::Arc::new(crawlx_core::parser_memory::ByteBudget::new(10));
        assert!(budget.try_reserve(png_encoder_bytes(2, 2).unwrap()).is_err());
        assert_eq!(budget.used(), 0, "refusal reserves nothing");
    }

    #[test]
    fn text_distance_normalizes_without_growing_and_matches_levenshtein() {
        let mut permit = global().try_reserve(0).unwrap();
        let input = b" a \t b\n\nc ";
        assert_eq!(normalized(input, &mut permit).unwrap(), "a b c");
        assert_eq!(permit.bytes(), input.len(), "reserved exactly the input length");
        assert!(normalized(&vec![b'a'; QA_TEXT_BYTES + 1], &mut permit).is_err());
        assert_eq!(text_distance(b"kitten", b"sitting").unwrap(), 3.0 / 7.0);
    }

    #[test]
    fn pixels_compare_decoded_samples_and_reject_oversized_dimensions() {
        use image::ImageEncoder as _;
        let encode = |value| {
            let mut bytes = Vec::new();
            image::codecs::png::PngEncoder::new(&mut bytes)
                .write_image(&[value, 0, 0, 255], 1, 1, image::ExtendedColorType::Rgba8)
                .unwrap();
            bytes
        };
        assert_eq!(pixel_distance(&encode(20), &encode(20)).unwrap(), 0.0);
        assert!(pixel_distance(&encode(20), &encode(255)).unwrap() > 0.0);
        assert!(pixels(b"not a PNG").is_err());
    }
}
