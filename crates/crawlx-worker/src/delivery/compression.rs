//! Fixed streaming codecs for already-approved feed plaintext.
//!
//! Encoders never consume page-selected code or options. Input and encoded output each obey
//! the feed cap. Reservations include both simultaneously live buffers (including the binary
//! approval copy) and conservative fixed codec-state ceilings before entering the CPU pool.

use super::LimitedOutput;
use crawlx_core::dataset::FeedCompressionV1;
use crawlx_core::secret::{Redacted, Redactor};
use crawlx_core::StoreError;
use std::io::Write;

pub(super) fn reservation_bytes(codec: FeedCompressionV1, maximum: usize) -> Result<usize, StoreError> {
    // Fixed fast settings bound dictionary/block/search state independently of target content.
    // Gzip uses a 32 KiB window; bzip2 level 1 uses 100 KiB blocks; XZ preset 0 uses a
    // 256 KiB dictionary and depth 4. Ceilings also cover codec work tables and staging.
    let state = match codec {
        FeedCompressionV1::None => return Ok(maximum),
        FeedCompressionV1::Gzip => 1024 * 1024,
        FeedCompressionV1::Bzip2 => 2 * 1024 * 1024,
        FeedCompressionV1::Xz => 16 * 1024 * 1024,
        _ => return Err(StoreError::Conflict("unsupported feed compression".into())),
    };
    maximum
        .checked_mul(2)
        .and_then(|buffers| buffers.checked_add(state))
        .ok_or_else(|| StoreError::Conflict("feed compression reservation overflow".into()))
}

pub(super) fn media_type(codec: FeedCompressionV1, plaintext: &str) -> Result<&str, StoreError> {
    match codec {
        FeedCompressionV1::None => Ok(plaintext),
        FeedCompressionV1::Gzip => Ok("application/gzip"),
        FeedCompressionV1::Bzip2 => Ok("application/x-bzip2"),
        FeedCompressionV1::Xz => Ok("application/x-xz"),
        _ => Err(StoreError::Conflict("unsupported feed compression".into())),
    }
}

/// Caller must first approve the exact serialized plaintext with canonical verification.
/// Binary approval alone cannot inspect the content hidden inside compression.
pub(super) fn encode_approved(
    plaintext: Redacted<Vec<u8>>,
    codec: FeedCompressionV1,
    maximum: usize,
) -> Result<Redacted<Vec<u8>>, StoreError> {
    if plaintext.as_ref().len() > maximum {
        return Err(StoreError::RetentionDenied("feed plaintext byte limit".into()));
    }
    if codec == FeedCompressionV1::None {
        return Ok(plaintext);
    }
    let mut output = LimitedOutput::new(maximum);
    let encoded = (|| -> std::io::Result<()> {
        match codec {
            FeedCompressionV1::Gzip => {
                let mut encoder = flate2::GzBuilder::new()
                    .mtime(0)
                    .operating_system(255)
                    .write(&mut output, flate2::Compression::fast());
                write_chunks(&mut encoder, plaintext.as_ref())?;
                encoder.finish()?;
            }
            FeedCompressionV1::Bzip2 => {
                let mut encoder = bzip2::write::BzEncoder::new(&mut output, bzip2::Compression::fast());
                write_chunks(&mut encoder, plaintext.as_ref())?;
                encoder.finish()?;
            }
            FeedCompressionV1::Xz => {
                // One XZ block keeps the index constant-sized; do not enable multi-threading.
                let mut encoder =
                    lzma_rust2::XzWriter::new(&mut output, lzma_rust2::XzOptions::with_preset(0))?;
                write_chunks(&mut encoder, plaintext.as_ref())?;
                encoder.finish()?;
            }
            _ => return Err(std::io::ErrorKind::Unsupported.into()),
        }
        Ok(())
    })();
    encoded.map_err(|_| output.serialization_error("feed compression failed or exceeded byte limit"))?;
    // Release plaintext before verify_binary's required owned copy. The reserved two-buffer
    // ceiling covers both this copy and the earlier plaintext/encoded overlap.
    drop(plaintext);
    Redactor::new().verify_binary(&output.bytes)
}

fn write_chunks(writer: &mut dyn Write, plaintext: &[u8]) -> std::io::Result<()> {
    for chunk in plaintext.chunks(32 * 1024) {
        writer.write_all(chunk)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "compression_tests.rs"]
mod tests;
