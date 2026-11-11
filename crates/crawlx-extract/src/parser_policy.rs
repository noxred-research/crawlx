//! Ordered input evidence and explicit decoded-text versus document-model policy.
//!
//! This policy does not make the existing DOM parser's allocator fallible. Text-only mode
//! returns decoded source text verbatim, including markup, without constructing a DOM.

use std::borrow::Cow;

use encoding_rs::{Encoding, UTF_8};

use crate::parse::{detect_format, ParseError, ParseFormat, ParseLimits};

/// Model requested by the caller, independent of MIME hints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelPolicy {
    /// Run the selected native parser.
    #[default]
    Document,
    /// Decode source only; do not tokenize markup or allocate a document tree.
    TextOnly,
}

/// Evidence which selected the format. Binary signatures always override declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatEvidence {
    /// Recognized signature or supported container layout.
    Magic,
    /// Recognized declared media type.
    Mime,
    /// Recognized file extension, used only when MIME is absent or unknown.
    Filename,
}

/// Encoding evidence in descending precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CharsetEvidence {
    /// Byte-order mark overrides declared charset.
    Bom,
    /// Explicit Content-Type charset.
    Declared,
    /// Bounded authored markup charset declaration.
    Meta,
    /// UTF-8 default; never locale-dependent.
    DefaultUtf8,
}

/// Bounded input policy. Hard input and operation limits still reject rather than truncate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct InputPolicy {
    /// Whether a document tree may be built.
    pub model: ModelPolicy,
    /// Optional decoded-text byte cap. Only text-only mode may truncate.
    pub max_text_bytes: Option<usize>,
}

impl InputPolicy {
    /// Set an explicit model and optional decoded-text soft cap.
    #[must_use]
    pub const fn new(model: ModelPolicy, max_text_bytes: Option<usize>) -> Self {
        Self {
            model,
            max_text_bytes,
        }
    }

    /// Stable policy identity; no heap allocation or content bytes enter this digest.
    #[must_use]
    pub fn digest(self) -> crawlx_core::hash::Digest {
        let mut encoded = [0_u8; 10];
        encoded[0] = match self.model {
            ModelPolicy::Document => 0,
            ModelPolicy::TextOnly => 1,
        };
        if let Some(limit) = self.max_text_bytes {
            encoded[1] = 1;
            encoded[2..].copy_from_slice(&u64::try_from(limit).unwrap_or(u64::MAX).to_be_bytes());
        }
        crawlx_core::hash::Digest::of("crawlx.parser-input-policy.v1", &encoded)
    }
}

/// Structural evidence; contains no source text, file name or raw header value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InputProvenance {
    /// Effective decoded-text/model policy identity, separate from source content.
    pub policy_digest: crawlx_core::hash::Digest,
    /// Evidence that selected the format.
    pub format_evidence: FormatEvidence,
    /// MIME disagreed with the selected signature.
    pub mime_conflict: bool,
    /// File extension disagreed with the selected format.
    pub filename_conflict: bool,
    /// Requested model.
    pub model: ModelPolicy,
    /// Actual encoding, for decoded text paths.
    pub encoding: Option<&'static str>,
    /// Encoding selection evidence.
    pub charset_evidence: Option<CharsetEvidence>,
    /// Decoder replaced invalid input sequences.
    pub lossy: bool,
    /// A recognized lower-priority charset declaration disagreed with the chosen encoding.
    pub charset_conflict: bool,
    /// Explicit text cap removed a suffix.
    pub truncated: bool,
}

/// Select signature, then MIME, then file extension; retain disagreements.
///
/// # Errors
/// Returns native detection errors for unsupported, corrupt or encrypted containers.
pub fn detect(
    bytes: &[u8],
    filename: Option<&str>,
    content_type: Option<&str>,
    limits: &ParseLimits,
    policy: InputPolicy,
) -> Result<(ParseFormat, InputProvenance), ParseError> {
    detect_declared(bytes, filename, content_type, None, limits, policy)
}

/// [`detect`] with a charset declared outside the content type (for example by explicit decode
/// options). A declared encoding that is not ASCII-compatible (UTF-16 and similar) makes NUL
/// bytes expected text, not evidence of an unsupported binary.
///
/// # Errors
/// As [`detect`].
pub fn detect_declared(
    bytes: &[u8],
    filename: Option<&str>,
    content_type: Option<&str>,
    declared_charset: Option<&str>,
    limits: &ParseLimits,
    policy: InputPolicy,
) -> Result<(ParseFormat, InputProvenance), ParseError> {
    let wide_text = declared_charset
        .map(str::to_owned)
        .or_else(|| content_type.and_then(crate::decode::charset_of_content_type))
        .and_then(|label| Encoding::for_label(label.trim().as_bytes()))
        .is_some_and(|encoding| !encoding.is_ascii_compatible());
    let mime = content_type.and_then(ParseFormat::from_mime);
    let extension = filename
        .and_then(|name| name.rsplit(['/', '\\']).next())
        .and_then(|name| name.rsplit_once('.'))
        .and_then(|(_, extension)| ParseFormat::from_extension(extension));
    let magic = detect_format(bytes, None, None, limits);
    let (format, evidence) = match magic {
        Ok(format) => (format, FormatEvidence::Magic),
        Err(error) => {
            // Never reinterpret an unsupported binary/archive signature as declared text.
            let binary = (!wide_text
                && Encoding::for_bom(bytes).is_none()
                && bytes.iter().take(1024).any(|byte| *byte == 0))
                || bytes.starts_with(b"PK")
                || bytes.starts_with(b"\x1f\x8b")
                || bytes.starts_with(b"7z\xbc\xaf\x27\x1c")
                || bytes.starts_with(b"Rar!\x1a\x07");
            if binary || !matches!(error, ParseError::UnsupportedFormat { .. }) {
                return Err(error);
            }
            if let Some(format) = mime {
                (format, FormatEvidence::Mime)
            } else if let Some(format) = extension {
                (format, FormatEvidence::Filename)
            } else {
                return Err(error);
            }
        }
    };
    Ok((
        format,
        InputProvenance {
            format_evidence: evidence,
            mime_conflict: mime.is_some_and(|hint| hint != format),
            filename_conflict: extension.is_some_and(|hint| hint != format),
            model: policy.model,
            policy_digest: policy.digest(),
            encoding: None,
            charset_evidence: None,
            lossy: false,
            charset_conflict: false,
            truncated: false,
        },
    ))
}

#[cfg(test)]
mod wide_charset_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn declared_wide_charset_keeps_the_mime_while_undeclared_nul_bytes_stay_binary() {
        let bytes: Vec<u8> = "<html>x</html>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let limits = ParseLimits::default();
        assert!(detect(&bytes, None, Some("text/html"), &limits, InputPolicy::default()).is_err());
        let (format, _) = detect_declared(
            &bytes,
            None,
            Some("text/html"),
            Some("UTF-16LE"),
            &limits,
            InputPolicy::default(),
        )
        .unwrap();
        assert_eq!(format, ParseFormat::Html);
        let (format, _) = detect(
            &bytes,
            None,
            Some("text/html; charset=utf-16le"),
            &limits,
            InputPolicy::default(),
        )
        .unwrap();
        assert_eq!(format, ParseFormat::Html);
    }
}

/// Decode BOM, declared charset, then UTF-8, preserving decoder diagnostics.
///
/// # Errors
/// Rejects unknown charset labels instead of silently replacing the declared policy.
pub fn decode<'a>(
    bytes: &'a [u8],
    content_type: Option<&str>,
    provenance: &mut InputProvenance,
) -> Result<Cow<'a, str>, ParseError> {
    let declared = content_type.and_then(crate::decode::charset_of_content_type);
    let (encoding, skip, evidence) = if let Some((encoding, skip)) = Encoding::for_bom(bytes) {
        (encoding, skip, CharsetEvidence::Bom)
    } else if let Some(label) = declared.as_deref() {
        let encoding = Encoding::for_label(label.as_bytes())
            .ok_or_else(|| ParseError::corrupt("text", "unsupported declared charset"))?;
        (encoding, 0, CharsetEvidence::Declared)
    } else {
        (UTF_8, 0, CharsetEvidence::DefaultUtf8)
    };
    let (text, lossy) = encoding.decode_without_bom_handling(&bytes[skip..]);
    provenance.encoding = Some(encoding.name());
    provenance.charset_evidence = Some(evidence);
    provenance.lossy = lossy;
    provenance.charset_conflict = declared
        .as_deref()
        .and_then(|label| Encoding::for_label(label.as_bytes()))
        .is_some_and(|declared| declared != encoding);
    Ok(text)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn mime_precedes_extension_and_signature_precedes_mime() {
        let limits = ParseLimits::default();
        let (format, evidence) = detect(
            b"plain",
            Some("source.html"),
            Some("text/plain"),
            &limits,
            InputPolicy::default(),
        )
        .unwrap();
        assert_eq!(format, ParseFormat::Txt);
        assert!(evidence.filename_conflict);
        let (format, evidence) = detect(
            b"%PDF-1.7",
            Some("source.txt"),
            Some("text/plain"),
            &limits,
            InputPolicy::default(),
        )
        .unwrap();
        assert_eq!(format, ParseFormat::Pdf);
        assert!(evidence.mime_conflict);
    }

    #[test]
    fn bom_overrides_charset_and_invalid_charset_refuses() {
        let (_, mut evidence) = detect(
            b"text",
            None,
            Some("text/plain"),
            &ParseLimits::default(),
            InputPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            decode(
                b"\xef\xbb\xbftext",
                Some("text/plain; charset=windows-1252"),
                &mut evidence
            )
            .unwrap(),
            "text"
        );
        assert_eq!(evidence.charset_evidence, Some(CharsetEvidence::Bom));
        assert!(decode(
            b"text",
            Some("text/plain; charset=not-an-encoding"),
            &mut evidence
        )
        .is_err());
    }

    #[test]
    fn unsupported_archive_never_becomes_text() {
        assert!(detect(
            b"PK\x03\x04broken",
            None,
            Some("text/plain"),
            &ParseLimits::default(),
            InputPolicy::default()
        )
        .is_err());
    }
}
