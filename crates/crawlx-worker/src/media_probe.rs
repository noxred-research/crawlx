//! Bounded image header inspection. No full image decoding and no parser-owned network.
//!
//! The URL plane acquires at most 64 KiB through the run's checked fetcher and shared
//! acquisition allowance. Header dimensions do not claim successful image decoding.

use serde::Serialize;

/// Intrinsic dimensions read from a known image header, not HTML attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct MediaDimensionsV1 {
    /// Pixel width from the header.
    pub width: u32,
    /// Pixel height from the header.
    pub height: u32,
    /// Header format, not a content-type claim.
    pub format: &'static str,
}
/// Header or pixel limit failure; no image decoder is invoked.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum MediaProbeError {
    /// Header unsupported, malformed or incomplete within the fixed byte allowance.
    #[error("media header unsupported or incomplete")]
    Header,
    /// Caller supplied more bytes than the header ceiling.
    #[error("media header byte limit exceeded")]
    Bytes,
    /// Dimensions are zero or exceed the configured pixel allowance.
    #[error("media pixel limit exceeded")]
    Pixels,
}
fn be_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn le_u24(bytes: &[u8], at: usize) -> Option<u32> {
    let bytes = bytes.get(at..at.checked_add(3)?)?;
    Some(u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16))
}
fn dimensions(bytes: &[u8]) -> Option<(u32, u32, &'static str)> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        && bytes.get(12..16) == Some(b"IHDR")
        && be_u32(bytes, 8) == Some(13)
    {
        return Some((be_u32(bytes, 16)?, be_u32(bytes, 20)?, "png"));
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some((u32::from(le_u16(bytes, 6)?), u32::from(le_u16(bytes, 8)?), "gif"));
    }
    if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        if bytes.get(12..16) == Some(b"VP8X") && bytes.get(20).is_some() {
            return Some((
                le_u24(bytes, 24)?.checked_add(1)?,
                le_u24(bytes, 27)?.checked_add(1)?,
                "webp",
            ));
        }
        if bytes.get(12..16) == Some(b"VP8 ") && bytes.get(23..26) == Some(b"\x9d\x01\x2a") {
            return Some((
                u32::from(le_u16(bytes, 26)? & 0x3fff),
                u32::from(le_u16(bytes, 28)? & 0x3fff),
                "webp",
            ));
        }
        if bytes.get(12..16) == Some(b"VP8L") && bytes.get(20) == Some(&0x2f) {
            let b = bytes.get(21..25)?;
            let width = 1 + (u32::from(b[0]) | ((u32::from(b[1]) & 0x3f) << 8));
            let height =
                1 + ((u32::from(b[1]) >> 6) | (u32::from(b[2]) << 2) | ((u32::from(b[3]) & 0xf) << 10));
            return Some((width, height, "webp"));
        }
    }
    if !bytes.starts_with(&[0xff, 0xd8]) {
        return None;
    }
    let mut position = 2usize;
    while position < bytes.len() {
        if *bytes.get(position)? != 0xff {
            return None;
        }
        while *bytes.get(position)? == 0xff {
            position = position.checked_add(1)?;
        }
        let marker = *bytes.get(position)?;
        position = position.checked_add(1)?;
        if matches!(marker, 0xd9 | 0xda | 0x00) {
            return None;
        }
        if matches!(marker, 0xd8 | 0x01 | 0xd0..=0xd7) {
            continue;
        }
        let length = usize::from(be_u16(bytes, position)?);
        if length < 2 {
            return None;
        }
        let end = position.checked_add(length)?;
        if end > bytes.len() {
            return None;
        }
        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
            if length < 8 {
                return None;
            }
            return Some((
                u32::from(be_u16(bytes, position.checked_add(5)?)?),
                u32::from(be_u16(bytes, position.checked_add(3)?)?),
                "jpeg",
            ));
        }
        position = end;
    }
    None
}
/// Read dimensions from an already bounded response prefix.
///
/// # Errors
/// Rejects more than 64 KiB, unsupported/incomplete headers, zero dimensions and pixel bombs.
pub fn inspect_header(bytes: &[u8], max_pixels: u64) -> Result<MediaDimensionsV1, MediaProbeError> {
    if bytes.len() > 65_536 {
        return Err(MediaProbeError::Bytes);
    }
    let (width, height, format) = dimensions(bytes).ok_or(MediaProbeError::Header)?;
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(MediaProbeError::Pixels)?;
    if width == 0 || height == 0 || pixels > max_pixels || max_pixels > 100_000_000 {
        return Err(MediaProbeError::Pixels);
    }
    Ok(MediaDimensionsV1 {
        width,
        height,
        format,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn header_only_png_and_pixel_bomb_refusal() {
        let mut header = Vec::from(&b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"[..]);
        header.extend_from_slice(&640u32.to_be_bytes());
        header.extend_from_slice(&480u32.to_be_bytes());
        assert_eq!(inspect_header(&header, 1_000_000).unwrap().width, 640);
        assert_eq!(inspect_header(&header, 100), Err(MediaProbeError::Pixels));
        assert_eq!(
            inspect_header(&vec![0; 65_537], 1_000_000),
            Err(MediaProbeError::Bytes)
        );
    }
    #[test]
    fn jpeg_segment_bombs_and_truncated_headers_never_decode() {
        assert_eq!(
            inspect_header(&[0xff, 0xd8, 0xff, 0xe0, 0xff, 0xff], 1_000_000),
            Err(MediaProbeError::Header)
        );
        let jpeg = [0xff, 0xd8, 0xff, 0xc0, 0, 8, 8, 0, 200, 1, 44, 1];
        let dimensions = inspect_header(&jpeg, 100_000).unwrap();
        assert_eq!((dimensions.width, dimensions.height), (300, 200));
        assert_eq!(
            inspect_header(b"GIF89a\x00\x00\x01\x00", 10),
            Err(MediaProbeError::Pixels)
        );
    }
}
