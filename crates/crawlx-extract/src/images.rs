//! The compatibility API `images` format: every image URL a page references.
//!
//! [`images`] reads `<img>` (`src`, the lazy-loading attributes `data-src`/`data-original`/
//! `data-lazy-src` and every candidate of `srcset`/`data-srcset`), the `srcset` of `<source>`
//! elements inside `<picture>`, and the Open Graph image meta tags. URLs resolve against the
//! document's effective base (`<base href>` aware), are limited to `http`/`https` (inline
//! `data:` images are not URLs worth listing), lose their fragment, and are de-duplicated in
//! document order.
//!
//! [`frontier_candidates`] turns those references into scope-filtered frontier proposals, and
//! [`inspect_image`] validates a downloaded image: bounded bytes and pixels, a full decode that
//! refuses corrupt or truncated files, a checksum of the exact bytes and an optional thumbnail.

use std::collections::HashSet;

use scraper::Html;
use url::Url;

use crate::dom::{resolve, srcset_urls, walk};
use crate::metadata::effective_base;
use crate::parse_budget::{ParseBudgetExhausted, ParseCharge};
use crate::ExtractOptions;

/// Most image URLs returned for one page.
pub const MAX_IMAGES: usize = 5_000;

/// Lazy-loading and plain source attributes of `<img>`, in precedence order.
const IMG_SRC_ATTRS: [&str; 4] = ["src", "data-src", "data-original", "data-lazy-src"];
/// `srcset` attributes of `<img>` and `<source>`.
const SRCSET_ATTRS: [&str; 2] = ["srcset", "data-srcset"];
/// Open Graph meta properties that name an image.
const OG_IMAGE_KEYS: [&str; 3] = ["og:image", "og:image:url", "og:image:secure_url"];

/// Absolute, de-duplicated image URLs of `html` in document order, at most [`MAX_IMAGES`].
/// `base` is the page URL; `<base href>` in the document refines it. Input beyond the default
/// extraction limits yields an empty list. The DOM is built under `charge`, a
/// [`crate::parse_budget::charge`] the caller holds until the result is no longer needed.
///
/// # Errors
/// [`ParseBudgetExhausted`] when the process-wide parse-memory budget cannot hold the tree.
pub fn images(charge: &mut ParseCharge, html: &str, base: &Url) -> Result<Vec<String>, ParseBudgetExhausted> {
    if crate::precheck(html, &ExtractOptions::default()).is_err() {
        return Ok(Vec::new());
    }
    let doc = crate::dom::parse_document(charge, html)?;
    let base = effective_base(&doc, base);
    Ok(from_document(&doc, &base))
}

/// Collect image references from an existing, resource-checked HTML parse.
/// `base` must already reflect the document's effective base.
#[must_use]
pub fn from_document(doc: &Html, base: &Url) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut add = |raw: &str| {
        if out.len() >= MAX_IMAGES {
            return;
        }
        if let Some(mut u) = resolve(base, raw) {
            if matches!(u.scheme(), "http" | "https") {
                u.set_fragment(None);
                if seen.insert(u.as_str().to_owned()) {
                    out.push(u.into());
                }
            }
        }
    };
    walk(doc.tree.root(), |el| {
        let v = el.value();
        match v.name() {
            "img" => {
                for name in IMG_SRC_ATTRS {
                    if let Some(s) = v.attr(name) {
                        add(s);
                    }
                }
                for name in SRCSET_ATTRS {
                    if let Some(s) = v.attr(name) {
                        srcset_urls(s).into_iter().for_each(&mut add);
                    }
                }
            }
            "source" => {
                let in_picture = el
                    .parent()
                    .and_then(scraper::ElementRef::wrap)
                    .is_some_and(|p| p.value().name() == "picture");
                if in_picture {
                    for name in SRCSET_ATTRS {
                        if let Some(s) = v.attr(name) {
                            srcset_urls(s).into_iter().for_each(&mut add);
                        }
                    }
                }
            }
            "meta" => {
                let key = v.attr("property").or_else(|| v.attr("name")).map(str::trim);
                if key.is_some_and(|k| OG_IMAGE_KEYS.iter().any(|o| k.eq_ignore_ascii_case(o))) {
                    if let Some(c) = v.attr("content") {
                        add(c);
                    }
                }
                return false;
            }
            "script" | "style" | "template" => return false,
            _ => {}
        }
        true
    });
    out
}

/// Image URLs that may enter the crawl frontier: the page's references in document order, only
/// `http`/`https`, without fragment, de-duplicated, kept when `admit` (the run's scope decision)
/// says so, at most `limit`.
///
/// This only proposes targets. Every returned URL still passes the frontier's own scope, robots,
/// budget and egress checks when it is discovered; `admit` is the cheap scope pre-filter that keeps
/// out-of-scope assets from ever being queued.
#[must_use]
pub fn frontier_candidates(
    references: &[String],
    mut admit: impl FnMut(&Url) -> bool,
    limit: usize,
) -> Vec<Url> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for raw in references {
        if out.len() >= limit {
            break;
        }
        let Ok(mut url) = Url::parse(raw) else {
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") {
            continue;
        }
        url.set_fragment(None);
        if admit(&url) && seen.insert(url.as_str().to_owned()) {
            out.push(url);
        }
    }
    out
}

/// Domain of the image checksum.
const IMAGE_DIGEST_DOMAIN: &str = "crawlx.media.image.v1";

/// Limits of one image ingest. Every limit is inclusive; one over is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImagePolicy {
    /// Smallest accepted file, in bytes.
    pub min_bytes: usize,
    /// Largest accepted file, in bytes.
    pub max_bytes: usize,
    /// Smallest accepted pixel width.
    pub min_width: u32,
    /// Smallest accepted pixel height.
    pub min_height: u32,
    /// Most pixels (`width * height`) a decode may produce; also bounds the decoder's memory.
    pub max_pixels: u64,
    /// Longest edge of the PNG thumbnail to produce; `None` produces none.
    pub thumbnail_edge: Option<u32>,
}

impl Default for ImagePolicy {
    fn default() -> Self {
        Self {
            min_bytes: 1,
            max_bytes: 16 * 1024 * 1024,
            min_width: 1,
            min_height: 1,
            max_pixels: 16_000_000,
            thumbnail_edge: None,
        }
    }
}

/// Hard ceiling for [`ImagePolicy::max_pixels`].
pub const MAX_IMAGE_PIXELS: u64 = 100_000_000;
/// Hard ceiling for [`ImagePolicy::thumbnail_edge`].
pub const MAX_THUMBNAIL_EDGE: u32 = 2_048;

impl ImagePolicy {
    /// Check the policy itself against the hard ceilings.
    ///
    /// # Errors
    /// [`ImageError::InvalidPolicy`] when a limit is zero, inverted or above its ceiling.
    pub fn validate(&self) -> Result<(), ImageError> {
        if self.max_bytes == 0
            || self.min_bytes > self.max_bytes
            || self.max_pixels == 0
            || self.max_pixels > MAX_IMAGE_PIXELS
            || self
                .thumbnail_edge
                .is_some_and(|e| e == 0 || e > MAX_THUMBNAIL_EDGE)
        {
            return Err(ImageError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Facts of a successfully decoded image.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageFacts {
    /// Container format read from the bytes: `png`, `jpeg`, `gif`, `webp`, `bmp` or `tiff`.
    pub format: &'static str,
    /// Pixel width.
    pub width: u32,
    /// Pixel height.
    pub height: u32,
    /// File size in bytes.
    pub bytes: usize,
    /// Checksum of the exact bytes (domain-separated BLAKE3).
    pub checksum: crawlx_core::hash::Digest,
}

/// A decoded image's facts and optional PNG thumbnail.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InspectedImage {
    /// What the bytes are.
    pub facts: ImageFacts,
    /// PNG thumbnail when the policy asked for one.
    pub thumbnail: Option<Vec<u8>>,
}

/// Why an image was refused. No variant carries image bytes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageError {
    /// The policy is not within the hard ceilings.
    #[error("invalid image policy")]
    InvalidPolicy,
    /// The file is smaller than the minimum size.
    #[error("image of {len} bytes is below the {min} byte minimum")]
    TooFewBytes {
        /// Size received.
        len: usize,
        /// Minimum.
        min: usize,
    },
    /// The file is larger than the byte limit.
    #[error("image of {len} bytes exceeds the {max} byte limit")]
    TooLarge {
        /// Size received.
        len: usize,
        /// Limit.
        max: usize,
    },
    /// The bytes are not a supported raster image format.
    #[error("unsupported or unrecognized image format")]
    Unsupported,
    /// The header declares more pixels than the policy allows; nothing was decoded.
    #[error("image of {pixels} pixels exceeds the {max} pixel limit")]
    PixelLimit {
        /// Declared pixels.
        pixels: u64,
        /// Limit.
        max: u64,
    },
    /// The image is smaller than the minimum width or height.
    #[error("image of {width}x{height} is below the minimum size")]
    TooSmall {
        /// Declared width.
        width: u32,
        /// Declared height.
        height: u32,
    },
    /// The header was readable but the pixel data is corrupt or truncated.
    #[error("corrupt image: {0}")]
    Corrupt(String),
}

/// Format name of the raster formats the pipeline accepts.
const fn format_name(format: image::ImageFormat) -> Option<&'static str> {
    match format {
        image::ImageFormat::Png => Some("png"),
        image::ImageFormat::Jpeg => Some("jpeg"),
        image::ImageFormat::Gif => Some("gif"),
        image::ImageFormat::WebP => Some("webp"),
        image::ImageFormat::Bmp => Some("bmp"),
        image::ImageFormat::Tiff => Some("tiff"),
        _ => None,
    }
}

/// Decode `bytes` completely under `policy`, so a corrupt, truncated or hostile image is refused
/// before anything is stored.
///
/// Byte and header limits are checked first; the header's pixel count must fit the policy before
/// any pixel is decoded, and the decoder's allocation is capped from the same limit, so the work
/// and memory of one call are bounded by the policy. CPU-bound: callers run it on the CPU pool.
///
/// # Errors
/// [`ImageError`] naming the first limit or decoding failure.
pub fn inspect_image(bytes: &[u8], policy: &ImagePolicy) -> Result<InspectedImage, ImageError> {
    use image::ImageDecoder as _;
    policy.validate()?;
    if bytes.len() < policy.min_bytes {
        return Err(ImageError::TooFewBytes {
            len: bytes.len(),
            min: policy.min_bytes,
        });
    }
    if bytes.len() > policy.max_bytes {
        return Err(ImageError::TooLarge {
            len: bytes.len(),
            max: policy.max_bytes,
        });
    }
    let reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| ImageError::Corrupt(e.to_string()))?;
    let format = reader
        .format()
        .and_then(format_name)
        .ok_or(ImageError::Unsupported)?;
    let mut decoder = reader
        .into_decoder()
        .map_err(|e| ImageError::Corrupt(e.to_string()))?;
    let (width, height) = decoder.dimensions();
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(ImageError::PixelLimit {
            pixels: u64::MAX,
            max: policy.max_pixels,
        })?;
    if pixels > policy.max_pixels {
        return Err(ImageError::PixelLimit {
            pixels,
            max: policy.max_pixels,
        });
    }
    if width == 0 || height == 0 || width < policy.min_width || height < policy.min_height {
        return Err(ImageError::TooSmall { width, height });
    }
    let mut limits = image::Limits::no_limits();
    limits.max_image_width = Some(width);
    limits.max_image_height = Some(height);
    // Eight bytes per pixel covers the widest sample layout the decoders produce.
    limits.max_alloc = Some(policy.max_pixels.saturating_mul(8));
    decoder
        .set_limits(limits)
        .map_err(|e| ImageError::Corrupt(e.to_string()))?;
    let decoded =
        image::DynamicImage::from_decoder(decoder).map_err(|e| ImageError::Corrupt(e.to_string()))?;
    let thumbnail = match policy.thumbnail_edge {
        Some(edge) => {
            let small = image::DynamicImage::ImageRgba8(decoded.thumbnail(edge, edge).to_rgba8());
            let mut out = std::io::Cursor::new(Vec::new());
            small
                .write_to(&mut out, image::ImageFormat::Png)
                .map_err(|e| ImageError::Corrupt(e.to_string()))?;
            Some(out.into_inner())
        }
        None => None,
    };
    Ok(InspectedImage {
        facts: ImageFacts {
            format,
            width,
            height,
            bytes: bytes.len(),
            checksum: crawlx_core::hash::Digest::of(IMAGE_DIGEST_DOMAIN, bytes),
        },
        thumbnail,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn base() -> Url {
        Url::parse("https://example.com/blog/post").unwrap()
    }

    fn collect(html: &str) -> Vec<String> {
        let mut charge = crate::parse_budget::charge(html.len()).unwrap();
        images(&mut charge, html, &base()).unwrap()
    }

    const PAGE: &str = r#"<!doctype html><html><head>
        <meta property="og:image" content="/social/card.png">
        <meta property="og:image:width" content="1200">
        <script>var s = '<img src="/in-script.png">';</script>
      </head><body>
        <img src="logo.svg" alt="logo">
        <img src="/hero.jpg" srcset="/hero-1x.jpg 1x, /hero-2x.jpg 2x, https://cdn.example.org/hero-3x.jpg 3x">
        <img data-src="/lazy.png" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=">
        <picture>
          <source srcset="/art-wide.webp 1200w, /art-narrow.webp 600w" media="(min-width: 800px)">
          <img src="/art.jpg">
        </picture>
        <video><source src="/clip.mp4"></video>
        <img src="/hero.jpg#again">
        <img src="mailto:nobody@example.com">
      </body></html>"#;

    #[test]
    fn collects_img_srcset_picture_and_og_in_document_order_without_duplicates() {
        let got = collect(PAGE);
        assert_eq!(
            got,
            [
                "https://example.com/social/card.png",
                "https://example.com/blog/logo.svg",
                "https://example.com/hero.jpg",
                "https://example.com/hero-1x.jpg",
                "https://example.com/hero-2x.jpg",
                "https://cdn.example.org/hero-3x.jpg",
                "https://example.com/lazy.png",
                "https://example.com/art-wide.webp",
                "https://example.com/art-narrow.webp",
                "https://example.com/art.jpg",
            ]
        );
    }

    #[test]
    fn data_uris_scripts_video_sources_and_non_http_schemes_are_skipped() {
        let got = collect(PAGE);
        assert!(got.iter().all(|u| u.starts_with("http")));
        assert!(!got
            .iter()
            .any(|u| u.contains("in-script") || u.contains("clip.mp4")));
        assert!(!got.iter().any(|u| u.contains("data:")));
    }

    #[test]
    fn base_href_redirects_relative_urls() {
        let html = r#"<head><base href="https://static.example.net/assets/"></head>
            <body><img src="a.png"><img src="/b.png"></body>"#;
        assert_eq!(
            collect(html),
            [
                "https://static.example.net/assets/a.png",
                "https://static.example.net/b.png"
            ]
        );
    }

    #[test]
    fn result_is_capped() {
        let mut html = String::from("<body>");
        for i in 0..(MAX_IMAGES + 50) {
            html.push_str(&format!("<img src=\"/i{i}.png\">"));
        }
        assert_eq!(collect(&html).len(), MAX_IMAGES);
    }

    #[test]
    fn empty_and_imageless_documents_yield_nothing() {
        assert!(collect("").is_empty());
        assert!(collect("<p>no images</p>").is_empty());
    }

    // ---- image validation ------------------------------------------------------------------

    fn png(width: u32, height: u32, seed: u8) -> Vec<u8> {
        let mut pixels = image::RgbaImage::new(width, height);
        for (x, y, pixel) in pixels.enumerate_pixels_mut() {
            let v = u8::try_from((x * 7 + y * 13 + u32::from(seed)) % 251).unwrap();
            *pixel = image::Rgba([v, v.wrapping_mul(3), seed, 255]);
        }
        let mut out = std::io::Cursor::new(Vec::new());
        pixels.write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xffff_ffff_u32;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// A PNG whose header declares `width`x`height` with valid checksums but no pixel data.
    fn png_header_only(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = Vec::from(&b"\x89PNG\r\n\x1a\n"[..]);
        let mut ihdr = Vec::from(&b"IHDR"[..]);
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes.extend_from_slice(&13_u32.to_be_bytes());
        bytes.extend_from_slice(&ihdr);
        bytes.extend_from_slice(&crc32(&ihdr).to_be_bytes());
        // One data chunk that holds no valid pixel stream, so the header is followed by data.
        let mut idat = Vec::from(&b"IDAT"[..]);
        idat.extend_from_slice(&[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);
        bytes.extend_from_slice(&8_u32.to_be_bytes());
        bytes.extend_from_slice(&idat);
        bytes.extend_from_slice(&crc32(&idat).to_be_bytes());
        bytes
    }

    #[test]
    fn a_valid_png_is_decoded_checksummed_and_deterministic() {
        let bytes = png(40, 30, 1);
        let done = inspect_image(&bytes, &ImagePolicy::default()).unwrap();
        assert_eq!(
            (done.facts.format, done.facts.width, done.facts.height),
            ("png", 40, 30)
        );
        assert_eq!(done.facts.bytes, bytes.len());
        assert!(done.thumbnail.is_none());
        assert_eq!(done, inspect_image(&bytes, &ImagePolicy::default()).unwrap());
        let other = inspect_image(&png(40, 30, 2), &ImagePolicy::default()).unwrap();
        assert_ne!(done.facts.checksum, other.facts.checksum);
    }

    #[test]
    fn jpeg_gif_and_bmp_are_decoded_too() {
        let pixels = image::RgbImage::from_fn(16, 12, |x, y| {
            image::Rgb([u8::try_from(x * 9).unwrap(), 50, u8::try_from(y * 9).unwrap()])
        });
        for (format, name) in [
            (image::ImageFormat::Jpeg, "jpeg"),
            (image::ImageFormat::Gif, "gif"),
            (image::ImageFormat::Bmp, "bmp"),
        ] {
            let mut out = std::io::Cursor::new(Vec::new());
            image::DynamicImage::ImageRgb8(pixels.clone())
                .write_to(&mut out, format)
                .unwrap();
            let done = inspect_image(&out.into_inner(), &ImagePolicy::default()).unwrap();
            assert_eq!(
                (done.facts.format, done.facts.width, done.facts.height),
                (name, 16, 12)
            );
        }
    }

    #[test]
    fn a_thumbnail_is_a_bounded_png() {
        let policy = ImagePolicy {
            thumbnail_edge: Some(16),
            ..ImagePolicy::default()
        };
        let done = inspect_image(&png(64, 32, 3), &policy).unwrap();
        let thumb = done.thumbnail.unwrap();
        let small = inspect_image(&thumb, &ImagePolicy::default()).unwrap();
        assert_eq!(small.facts.format, "png");
        assert!(small.facts.width <= 16 && small.facts.height <= 16);
        assert_eq!((small.facts.width, small.facts.height), (16, 8));
    }

    #[test]
    fn corrupt_and_truncated_images_are_refused_after_the_header_reads() {
        let good = png(60, 60, 5);
        // Flip a byte inside the compressed pixel data: the chunk checksum no longer matches.
        let mut flipped = good.clone();
        let at = good.len() / 2;
        flipped[at] ^= 0xff;
        assert!(matches!(
            inspect_image(&flipped, &ImagePolicy::default()),
            Err(ImageError::Corrupt(_))
        ));
        // A cut-off file keeps a valid header but has no complete pixel data.
        let truncated = &good[..good.len() / 2];
        assert!(matches!(
            inspect_image(truncated, &ImagePolicy::default()),
            Err(ImageError::Corrupt(_))
        ));
        // A header-only PNG within the pixel limit has no pixel data at all.
        assert!(matches!(
            inspect_image(&png_header_only(8, 8), &ImagePolicy::default()),
            Err(ImageError::Corrupt(_))
        ));
    }

    #[test]
    fn unsupported_and_garbage_bytes_are_refused() {
        for bytes in [
            &b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"[..],
            b"GIF",
            b"not an image at all, just text",
            &[0_u8; 64],
        ] {
            assert!(inspect_image(bytes, &ImagePolicy::default()).is_err());
        }
        assert_eq!(
            inspect_image(
                b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
                &ImagePolicy::default()
            ),
            Err(ImageError::Unsupported)
        );
    }

    #[test]
    fn a_pixel_bomb_is_refused_from_the_header_without_decoding() {
        let bomb = png_header_only(60_000, 60_000);
        assert_eq!(
            inspect_image(&bomb, &ImagePolicy::default()),
            Err(ImageError::PixelLimit {
                pixels: 3_600_000_000,
                max: 16_000_000,
            })
        );
        let policy = ImagePolicy {
            max_pixels: 4 * 5,
            ..ImagePolicy::default()
        };
        assert!(inspect_image(&png(4, 5, 1), &policy).is_ok());
        assert!(matches!(
            inspect_image(&png(5, 5, 1), &policy),
            Err(ImageError::PixelLimit { .. })
        ));
    }

    #[test]
    fn byte_and_dimension_minimums_and_maximums_are_inclusive() {
        let bytes = png(10, 8, 1);
        let mut policy = ImagePolicy {
            min_bytes: bytes.len(),
            max_bytes: bytes.len(),
            ..ImagePolicy::default()
        };
        assert!(inspect_image(&bytes, &policy).is_ok());
        policy.min_bytes = 1;
        policy.max_bytes = bytes.len() - 1;
        assert!(matches!(
            inspect_image(&bytes, &policy),
            Err(ImageError::TooLarge { .. })
        ));
        policy.max_bytes = bytes.len();
        policy.min_bytes = bytes.len() + 1;
        assert!(matches!(
            inspect_image(&bytes, &policy),
            Err(ImageError::InvalidPolicy)
        ));
        let policy = ImagePolicy {
            min_bytes: bytes.len() + 1,
            ..ImagePolicy::default()
        };
        assert!(matches!(
            inspect_image(&bytes, &policy),
            Err(ImageError::TooFewBytes { .. })
        ));
        let mut policy = ImagePolicy {
            min_width: 10,
            min_height: 8,
            ..ImagePolicy::default()
        };
        assert!(inspect_image(&bytes, &policy).is_ok());
        policy.min_width = 11;
        assert_eq!(
            inspect_image(&bytes, &policy),
            Err(ImageError::TooSmall { width: 10, height: 8 })
        );
        let bad = ImagePolicy {
            max_pixels: MAX_IMAGE_PIXELS + 1,
            ..ImagePolicy::default()
        };
        assert_eq!(bad.validate(), Err(ImageError::InvalidPolicy));
        let bad = ImagePolicy {
            thumbnail_edge: Some(MAX_THUMBNAIL_EDGE + 1),
            ..ImagePolicy::default()
        };
        assert_eq!(bad.validate(), Err(ImageError::InvalidPolicy));
    }

    #[test]
    fn frontier_candidates_keep_scope_order_dedupe_and_the_limit() {
        let refs: Vec<String> = [
            "https://site.test/a.png",
            "https://cdn.other.test/b.png",
            "https://site.test/a.png#again",
            "data:image/gif;base64,AAAA",
            "ftp://site.test/c.png",
            "https://site.test/d.png",
            "not a url",
            "https://site.test/e.png",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let in_scope = |u: &Url| u.host_str() == Some("site.test");
        let got: Vec<String> = frontier_candidates(&refs, in_scope, 10)
            .iter()
            .map(Url::to_string)
            .collect();
        assert_eq!(
            got,
            [
                "https://site.test/a.png",
                "https://site.test/d.png",
                "https://site.test/e.png"
            ]
        );
        assert_eq!(frontier_candidates(&refs, in_scope, 2).len(), 2);
        assert!(frontier_candidates(&refs, in_scope, 0).is_empty());
        assert!(frontier_candidates(&refs, |_| false, 10).is_empty());
    }
}
