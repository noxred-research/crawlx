//! Only explicitly retained producer-approved PNG screenshots enter sensitive archives.

use super::resource::ResourceInput;
use crawlx_core::archive::ArchiveRepresentation;
use crawlx_core::browser_capture::{CaptureCompleteness, CaptureKind};
use crawlx_core::repo::CrawlRun;
use crawlx_storage::archive::ArchiveError;
use image::ImageDecoder as _;
use std::io::Cursor;

pub(super) fn approved(run: &CrawlRun, input: &ResourceInput<'_>) -> bool {
    let Some(capture) = input.capture else {
        return false;
    };
    run.config.capture.browser.phase_resources
        && capture.descriptor.kind == CaptureKind::Screenshot
        && capture.completeness == CaptureCompleteness::Complete
        && !capture.descriptor.truncated
        && input.source == Some(&capture.artifact)
        && capture.descriptor.content_type == "image/png"
        && input.mime == "image/png"
        && input.facts.representation == ArchiveRepresentation::Screenshot
        && input.facts.redaction_revision == "browser-evidence-v1"
        && matches!(
            input.facts.capture_source.as_str(),
            "browser_evidence_initial" | "browser_evidence_final"
        )
        && input.facts.body_state == "complete"
        && super::approved_target(&capture.descriptor.source_url).is_ok_and(|target| target == input.target)
}
pub(super) fn validate_png(
    bytes: &[u8],
    expected_bytes: u64,
    expected_width: Option<u32>,
    expected_height: Option<u32>,
) -> Result<(), ArchiveError> {
    if u64::try_from(bytes.len()).ok() != Some(expected_bytes) {
        return Err(ArchiveError::Invalid("screenshot descriptor byte mismatch"));
    }
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(ArchiveError::Invalid("invalid approved screenshot PNG"));
    }
    let mut reader = image::ImageReader::with_format(Cursor::new(bytes), image::ImageFormat::Png);
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(67_108_864);
    limits.max_image_width = Some(16_777_216);
    limits.max_image_height = Some(16_777_216);
    reader.limits(limits);
    let decoder = reader
        .into_decoder()
        .map_err(|_| ArchiveError::Invalid("invalid approved screenshot PNG"))?;
    let (width, height) = decoder.dimensions();
    if width == 0
        || height == 0
        || u64::from(width) * u64::from(height) > 16_777_216
        || decoder.total_bytes() > 67_108_864
    {
        return Err(ArchiveError::Limit("archive screenshot decoded pixels"));
    }
    if expected_width != Some(width) || expected_height != Some(height) {
        return Err(ArchiveError::Invalid("screenshot descriptor dimension mismatch"));
    }
    let length = usize::try_from(decoder.total_bytes())
        .map_err(|_| ArchiveError::Limit("archive screenshot decoded bytes"))?;
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(length)
        .map_err(|_| ArchiveError::Limit("archive screenshot decoded bytes"))?;
    decoded.resize(length, 0);
    decoder
        .read_image(&mut decoded)
        .map_err(|_| ArchiveError::Invalid("invalid approved screenshot PNG"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use image::ImageEncoder as _;

    #[test]
    fn png_archive_validation_checks_decoding_and_exact_descriptor() {
        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(
                &[0, 10, 20, 255, 30, 40, 50, 255],
                2,
                1,
                image::ExtendedColorType::Rgba8,
            )
            .unwrap();
        let length = u64::try_from(bytes.len()).unwrap();
        validate_png(&bytes, length, Some(2), Some(1)).unwrap();
        assert!(validate_png(&bytes, length + 1, Some(2), Some(1)).is_err());
        assert!(validate_png(&bytes, length, Some(1), Some(1)).is_err());
        assert!(validate_png(&bytes, length, None, Some(1)).is_err());
        assert!(validate_png(&bytes[..bytes.len() / 2], length / 2, Some(2), Some(1)).is_err());
        bytes[0] = 0;
        assert!(validate_png(&bytes, length, Some(2), Some(1)).is_err());
    }
}
