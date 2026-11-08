//! Bounded offline archive QA. Missing baselines are never counted as equal.

use crate::archive_replay::{ReplayCapture, ReplayError, ReplayReport};
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

fn checked_bytes(capture: &ReplayCapture) -> Result<(), ReplayError> {
    if capture.bytes.len() > 16 * 1024 * 1024
        || capture.length != capture.bytes.len()
        || capture.digest != format!("sha256:{}", hex::encode(Sha256::digest(&capture.bytes)))
    {
        return Err(ReplayError::Refused("QA capture fixity or byte bound"));
    }
    Ok(())
}

fn pixels(bytes: &[u8]) -> Result<image::RgbaImage, ReplayError> {
    let decoder = ImageReader::with_format(Cursor::new(bytes), image::ImageFormat::Png)
        .into_decoder()
        .map_err(|_| ReplayError::Refused("invalid QA PNG"))?;
    let (width, height) = decoder.dimensions();
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > 16_777_216 {
        return Err(ReplayError::Refused("QA image pixel bound"));
    }
    DynamicImage::from_decoder(decoder)
        .map(|image| image.into_rgba8())
        .map_err(|_| ReplayError::Refused("QA image decoding failed"))
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

fn normalized(bytes: &[u8]) -> Result<String, ReplayError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ReplayError::Refused("QA text is not UTF-8"))?;
    if text.len() > 262_144 {
        return Err(ReplayError::Refused("QA text byte bound"));
    }
    Ok(text.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn text_distance(left: &[u8], right: &[u8]) -> Result<f64, ReplayError> {
    let left = normalized(left)?;
    let right = normalized(right)?;
    if left == right {
        return Ok(0.0);
    }
    let a: Vec<char> = left.chars().collect();
    let b: Vec<char> = right.chars().collect();
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
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];
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

    #[test]
    fn normalized_levenshtein_is_measured_not_encoded_byte_difference() {
        assert_eq!(text_distance(b"alpha  beta", b"alpha beta").unwrap(), 0.0);
        assert!(text_distance(b"alpha", b"omega").unwrap() > 0.0);
        assert_eq!(text_distance(b"", b"hello").unwrap(), 1.0);
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
