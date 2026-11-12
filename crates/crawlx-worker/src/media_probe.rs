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

/// Per-scope image ingest: validate, checksum, de-duplicate and store downloaded images.
///
/// An image URL found on a page re-enters the frontier like any other discovered URL
/// ([`crawlx_extract::images::frontier_candidates`] proposes it, the run's scope, robots and
/// governor decide), and the bytes the checked fetcher returns arrive here. [`ImagePipeline`]
/// never fetches anything itself.
///
/// * A full decode runs on the [`CpuPool`] under an [`ImagePolicy`] (byte, pixel and minimum-size
///   limits, decoder memory capped from the pixel limit), so a corrupt, truncated or hostile image
///   is refused before anything is written and costs one bounded pool slot.
/// * Identical bytes under one [`ImageScope`] are stored once: later ingests return the first
///   artifact with `deduplicated` set. Another scope stores its own copy, so one tenant's
///   dedupe never exposes or removes another's content.
/// * Stored bytes and image counts are limited per scope by [`ImageQuota`]; one over is refused
///   and nothing is stored. A refused image charges nothing.
/// * An optional deadline only shortens the artifact's normal retention.
pub mod ingest {
    use super::{ImagePolicy, ImageQuota};
    use crate::runtime::CpuPool;
    use bytes::Bytes;
    use crawlx_core::repo::{ArtifactStore, Sensitivity};
    use crawlx_core::{ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};
    use crawlx_extract::images::{inspect_image, ImageError, ImageFacts};
    use parking_lot::Mutex;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tokio::sync::OnceCell;
    use url::Url;

    /// The identity images are de-duplicated and counted under: one tenant's one run.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct ImageScope {
        /// Owning tenant.
        pub tenant: TenantId,
        /// Run the images belong to.
        pub run: CrawlRunId,
    }

    /// Map key of a scope: tenant and run identifiers.
    type ScopeKey = ([u8; 16], [u8; 16]);

    impl ImageScope {
        /// The scope of `run` owned by `tenant`.
        #[must_use]
        pub const fn new(tenant: TenantId, run: CrawlRunId) -> Self {
            Self { tenant, run }
        }

        fn key(&self) -> ScopeKey {
            (
                self.tenant.as_uuid().into_bytes(),
                self.run.as_uuid().into_bytes(),
            )
        }
    }

    /// One downloaded image to ingest.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct ImageIngest {
        /// Scope the image is stored and de-duplicated under.
        pub scope: ImageScope,
        /// Where the bytes came from (after redirects); recorded, never fetched here.
        pub source: Url,
        /// The downloaded bytes.
        pub bytes: Bytes,
        /// Retention can only be shortened to this instant.
        pub deadline: Option<Timestamp>,
    }

    impl ImageIngest {
        /// An ingest of `bytes` fetched from `source` for `scope`.
        #[must_use]
        pub const fn new(scope: ImageScope, source: Url, bytes: Bytes) -> Self {
            Self {
                scope,
                source,
                bytes,
                deadline: None,
            }
        }
    }

    /// A stored (or already stored) image.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct StoredImage {
        /// Facts of the decoded image, including its checksum.
        pub facts: ImageFacts,
        /// The stored original.
        pub artifact: ArtifactRef,
        /// The stored PNG thumbnail when the policy asked for one.
        pub thumbnail: Option<ArtifactRef>,
    }

    /// The outcome of one ingest.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct IngestedImage {
        /// What is stored for these bytes in this scope.
        pub stored: StoredImage,
        /// These exact bytes were already stored in this scope; nothing was written.
        pub deduplicated: bool,
        /// Where this copy came from.
        pub source: Url,
    }

    /// Why an image was not stored. Never carries image bytes.
    #[derive(Debug, thiserror::Error)]
    #[non_exhaustive]
    pub enum ImageRefusal {
        /// The image failed validation (corrupt, truncated, too big, too small, unsupported).
        #[error(transparent)]
        Image(#[from] ImageError),
        /// The scope already holds the maximum number of images.
        #[error("image count quota of {max} reached")]
        TooManyImages {
            /// Quota.
            max: usize,
        },
        /// Storing the image would exceed the scope's byte quota.
        #[error("image byte quota of {max} bytes would be exceeded")]
        ByteQuota {
            /// Quota.
            max: u64,
        },
        /// The artifact store refused or failed the write.
        #[error("image store failed: {0}")]
        Store(#[from] StoreError),
        /// The decode task did not complete (panic or shutdown).
        #[error("image decode task failed")]
        Task,
    }

    /// What a scope currently holds.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    #[non_exhaustive]
    pub struct ScopeUsage {
        /// Distinct images stored.
        pub images: usize,
        /// Bytes of originals and thumbnails stored.
        pub bytes: u64,
    }

    #[derive(Default)]
    struct Scope {
        slots: BTreeMap<[u8; 32], Arc<OnceCell<StoredImage>>>,
        usage: ScopeUsage,
    }

    /// See the module documentation.
    pub struct ImagePipeline {
        policy: ImagePolicy,
        quota: ImageQuota,
        scopes: Mutex<BTreeMap<ScopeKey, Scope>>,
    }

    impl std::fmt::Debug for ImagePipeline {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ImagePipeline")
                .field("policy", &self.policy)
                .field("quota", &self.quota)
                .finish_non_exhaustive()
        }
    }

    fn content_type(format: &str) -> &'static str {
        match format {
            "png" => "image/png",
            "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "webp" => "image/webp",
            "bmp" => "image/bmp",
            "tiff" => "image/tiff",
            _ => "application/octet-stream",
        }
    }

    impl ImagePipeline {
        /// A pipeline with `policy` limits per image and `quota` limits per scope.
        ///
        /// # Errors
        /// [`ImageError::InvalidPolicy`] when the policy or quota is outside its hard ceilings.
        pub fn new(policy: ImagePolicy, quota: ImageQuota) -> Result<Self, ImageError> {
            policy.validate()?;
            if quota.max_images == 0 || quota.max_scope_bytes == 0 {
                return Err(ImageError::InvalidPolicy);
            }
            Ok(Self {
                policy,
                quota,
                scopes: Mutex::new(BTreeMap::new()),
            })
        }

        /// The distinct images and bytes `scope` holds.
        #[must_use]
        pub fn usage(&self, scope: &ImageScope) -> ScopeUsage {
            self.scopes
                .lock()
                .get(&scope.key())
                .map_or_else(ScopeUsage::default, |s| s.usage)
        }

        /// Validate, de-duplicate and store `request.bytes`.
        ///
        /// The byte ceiling is checked before any CPU is spent; the decode runs on `cpu`; a
        /// refused image changes no counter. Concurrent ingests of identical bytes in one scope
        /// store once.
        ///
        /// # Errors
        /// [`ImageRefusal`] for a refused image, an exhausted quota or a store failure.
        pub async fn ingest(
            &self,
            cpu: &CpuPool,
            store: &dyn ArtifactStore,
            request: &ImageIngest,
        ) -> Result<IngestedImage, ImageRefusal> {
            if request.bytes.len() > self.policy.max_bytes {
                return Err(ImageError::TooLarge {
                    len: request.bytes.len(),
                    max: self.policy.max_bytes,
                }
                .into());
            }
            let (bytes, policy) = (request.bytes.clone(), self.policy);
            let inspected = cpu
                .run(move || inspect_image(&bytes, &policy))
                .await
                .map_err(|_| ImageRefusal::Task)??;
            let key = request.scope.key();
            let digest = inspected.facts.checksum.0;
            let slot = {
                let mut scopes = self.scopes.lock();
                let scope = scopes.entry(key).or_default();
                Arc::clone(scope.slots.entry(digest).or_default())
            };
            let mut wrote = false;
            let stored = slot
                .get_or_try_init(|| async {
                    wrote = true;
                    let reserved = self.reserve(
                        key,
                        inspected.facts.bytes,
                        inspected.thumbnail.as_ref().map_or(0, Vec::len),
                    )?;
                    let written = self.write(store, request, &inspected).await;
                    if written.is_err() {
                        self.release(key, reserved);
                    }
                    written
                })
                .await;
            let stored = match stored {
                Ok(stored) => stored.clone(),
                Err(error) => {
                    // A failed first write leaves no empty slot behind to be mistaken for a hit.
                    self.forget_if_empty(key, &digest);
                    return Err(error);
                }
            };
            Ok(IngestedImage {
                stored,
                deduplicated: !wrote,
                source: request.source.clone(),
            })
        }

        /// Reserve count and bytes for a new image, refusing one over either quota.
        fn reserve(
            &self,
            key: ScopeKey,
            original: usize,
            thumbnail: usize,
        ) -> Result<ScopeUsage, ImageRefusal> {
            let added = u64::try_from(original.saturating_add(thumbnail)).unwrap_or(u64::MAX);
            let mut scopes = self.scopes.lock();
            let scope = scopes.entry(key).or_default();
            if scope.usage.images >= self.quota.max_images {
                return Err(ImageRefusal::TooManyImages {
                    max: self.quota.max_images,
                });
            }
            let total = scope.usage.bytes.checked_add(added);
            if total.is_none_or(|t| t > self.quota.max_scope_bytes) {
                return Err(ImageRefusal::ByteQuota {
                    max: self.quota.max_scope_bytes,
                });
            }
            let reserved = ScopeUsage {
                images: 1,
                bytes: added,
            };
            scope.usage.images = scope.usage.images.saturating_add(1);
            scope.usage.bytes = scope.usage.bytes.saturating_add(added);
            Ok(reserved)
        }

        fn release(&self, key: ScopeKey, reserved: ScopeUsage) {
            if let Some(scope) = self.scopes.lock().get_mut(&key) {
                scope.usage.images = scope.usage.images.saturating_sub(reserved.images);
                scope.usage.bytes = scope.usage.bytes.saturating_sub(reserved.bytes);
            }
        }

        fn forget_if_empty(&self, key: ScopeKey, digest: &[u8; 32]) {
            if let Some(scope) = self.scopes.lock().get_mut(&key) {
                if scope.slots.get(digest).is_some_and(|slot| slot.get().is_none()) {
                    scope.slots.remove(digest);
                }
            }
        }

        async fn write(
            &self,
            store: &dyn ArtifactStore,
            request: &ImageIngest,
            inspected: &crawlx_extract::images::InspectedImage,
        ) -> Result<StoredImage, ImageRefusal> {
            let run = request.scope.run;
            let kind = content_type(inspected.facts.format);
            let artifact = match request.deadline {
                Some(deadline) => {
                    store
                        .put_until(run, Sensitivity::Content, kind, &request.bytes, deadline)
                        .await?
                }
                None => store.put(run, Sensitivity::Content, kind, &request.bytes).await?,
            };
            let thumbnail = match &inspected.thumbnail {
                Some(png) => Some(match request.deadline {
                    Some(deadline) => {
                        store
                            .put_until(run, Sensitivity::Content, "image/png", png, deadline)
                            .await?
                    }
                    None => store.put(run, Sensitivity::Content, "image/png", png).await?,
                }),
                None => None,
            };
            Ok(StoredImage {
                facts: inspected.facts.clone(),
                artifact,
                thumbnail,
            })
        }
    }
}

pub use crawlx_extract::images::ImagePolicy;

/// Per-scope limits of an [`ingest::ImagePipeline`]. One over either limit is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageQuota {
    /// Most distinct images one scope may store.
    pub max_images: usize,
    /// Most bytes (originals and thumbnails) one scope may store.
    pub max_scope_bytes: u64,
}

impl Default for ImageQuota {
    fn default() -> Self {
        Self {
            max_images: 10_000,
            max_scope_bytes: 1024 * 1024 * 1024,
        }
    }
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
