//! Fixture files for `file:*` partitions. Only fixture ids ever flow into
//! `BrowserAction::Upload`; arbitrary host paths are never uploaded.
//!
//! The PNG and PDF are produced by small encoders at construction time, so
//! checksums, chunk CRCs and the xref table are correct by construction and
//! the bytes are identical on every platform.

use crate::partition::Partition;
use crawlx_core::ids::FixtureFileId;
use std::borrow::Cow;
use std::io::{self, Write};

/// Fixture id of the 8×8 PNG.
pub const FIXTURE_SMALL_PNG: &str = "fixture_small_png";
/// Fixture id of the one-page PDF.
pub const FIXTURE_PDF: &str = "fixture_pdf";
/// Fixture id of the lazily generated oversized file.
pub const FIXTURE_OVERSIZED: &str = "oversized";

/// Size of the lazily generated `oversized` fixture (16 MiB, above the 2/5/10 MiB
/// limits common in upload handlers).
pub const OVERSIZED_LEN: u64 = 16 * 1024 * 1024;

/// Is `id` a registered fixture id?
#[must_use]
pub fn is_known_fixture(id: &str) -> bool {
    matches!(id, FIXTURE_SMALL_PNG | FIXTURE_PDF | FIXTURE_OVERSIZED)
}

/// Content of a fixture: stored bytes, or zeros generated on demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureContent<'a> {
    /// Stored bytes.
    Bytes(&'a [u8]),
    /// `len` zero bytes, never stored.
    Zeros(u64),
}

/// A registered fixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixtureFile<'a> {
    /// Registered fixture id.
    pub id: &'static str,
    /// File name presented to the upload form.
    pub file_name: &'static str,
    /// MIME type presented to the upload form.
    pub content_type: &'static str,
    /// File content.
    pub content: FixtureContent<'a>,
}

impl FixtureFile<'_> {
    /// Size in bytes (known without generating the content).
    #[must_use]
    pub fn len(&self) -> u64 {
        match self.content {
            FixtureContent::Bytes(b) => b.len() as u64,
            FixtureContent::Zeros(n) => n,
        }
    }

    /// Whether the fixture has no content.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes; zero-filled fixtures are allocated here, lazily.
    #[must_use]
    pub fn bytes(&self) -> Cow<'_, [u8]> {
        match self.content {
            FixtureContent::Bytes(b) => Cow::Borrowed(b),
            FixtureContent::Zeros(n) => Cow::Owned(vec![0u8; usize::try_from(n).unwrap_or(usize::MAX)]),
        }
    }

    /// Stream the content without materialising zero-filled fixtures.
    ///
    /// # Errors
    /// Returns any I/O error produced by `w`.
    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self.content {
            FixtureContent::Bytes(b) => w.write_all(b),
            FixtureContent::Zeros(mut left) => {
                let block = [0u8; 8192];
                while left > 0 {
                    let n = usize::try_from(left.min(block.len() as u64)).unwrap_or(block.len());
                    w.write_all(&block[..n])?;
                    left -= n as u64;
                }
                Ok(())
            }
        }
    }
}

/// Registry mapping [`FixtureFileId`] to content.
#[derive(Clone, Debug)]
pub struct FixtureFiles {
    png: Vec<u8>,
    pdf: Vec<u8>,
}

impl Default for FixtureFiles {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureFiles {
    /// Build the registry, generating the PNG and PDF bytes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            png: build_png(),
            pdf: build_pdf(),
        }
    }

    /// Look up a fixture by id.
    #[must_use]
    pub fn get(&self, id: &FixtureFileId) -> Option<FixtureFile<'_>> {
        match id.0.as_str() {
            FIXTURE_SMALL_PNG => Some(FixtureFile {
                id: FIXTURE_SMALL_PNG,
                file_name: "crawlx-fixture.png",
                content_type: "image/png",
                content: FixtureContent::Bytes(&self.png),
            }),
            FIXTURE_PDF => Some(FixtureFile {
                id: FIXTURE_PDF,
                file_name: "crawlx-fixture.pdf",
                content_type: "application/pdf",
                content: FixtureContent::Bytes(&self.pdf),
            }),
            FIXTURE_OVERSIZED => Some(FixtureFile {
                id: FIXTURE_OVERSIZED,
                file_name: "crawlx-oversized.bin",
                content_type: "application/octet-stream",
                content: FixtureContent::Zeros(OVERSIZED_LEN),
            }),
            _ => None,
        }
    }

    /// All registered ids in stable order.
    #[must_use]
    pub fn ids(&self) -> Vec<FixtureFileId> {
        [FIXTURE_SMALL_PNG, FIXTURE_PDF, FIXTURE_OVERSIZED]
            .into_iter()
            .map(|s| FixtureFileId(s.to_owned()))
            .collect()
    }

    /// The fixture id a `file:*` partition uploads.
    #[must_use]
    pub fn id_for(partition: Partition) -> Option<FixtureFileId> {
        let id = match partition {
            Partition::FileFixtureSmallPng => FIXTURE_SMALL_PNG,
            Partition::FileFixturePdf => FIXTURE_PDF,
            Partition::FileOversized => FIXTURE_OVERSIZED,
            _ => return None,
        };
        Some(FixtureFileId(id.to_owned()))
    }
}

// ----------------------------------------------------------------------- PNG

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in bytes {
        a = (a + u32::from(x)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    // Fixture chunks are tiny; the saturated value is unreachable by construction.
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    let mut body = Vec::with_capacity(4 + data.len());
    body.extend_from_slice(kind);
    body.extend_from_slice(data);
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc32(&body).to_be_bytes());
}

/// An 8×8 RGB gradient (a real, decodable PNG; stored deflate blocks).
fn build_png() -> Vec<u8> {
    const W: u8 = 8;
    const H: u8 = 8;
    let mut raw = Vec::with_capacity(usize::from(H) * (1 + usize::from(W) * 3));
    for y in 0..H {
        raw.push(0); // filter: none
        for x in 0..W {
            raw.push(x * 32);
            raw.push(y * 32);
            raw.push(0x80);
        }
    }
    let mut z = vec![0x78, 0x01];
    let len = u16::from(H) * (1 + u16::from(W) * 3);
    debug_assert_eq!(usize::from(len), raw.len());
    z.push(1); // final stored block
    z.extend_from_slice(&len.to_le_bytes());
    z.extend_from_slice(&(!len).to_le_bytes());
    z.extend_from_slice(&raw);
    z.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&u32::from(W).to_be_bytes());
    ihdr.extend_from_slice(&u32::from(H).to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB, deflate, no filter, no interlace

    let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    png_chunk(&mut out, b"IHDR", &ihdr);
    png_chunk(&mut out, b"IDAT", &z);
    png_chunk(&mut out, b"IEND", &[]);
    out
}

// ----------------------------------------------------------------------- PDF

/// A one-page PDF 1.4 with a correct xref table.
fn build_pdf() -> Vec<u8> {
    let stream = "BT /F1 18 Tf 20 100 Td (crawlx fixture) Tj ET";
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"
            .to_owned(),
        format!("<< /Length {} >>\nstream\n{stream}\nendstream", stream.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
    ];
    let mut out = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }
    let xref_at = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn id(s: &str) -> FixtureFileId {
        FixtureFileId(s.to_owned())
    }

    #[test]
    fn png_has_magic_and_valid_chunks() {
        let f = FixtureFiles::new();
        let png = f.get(&id(FIXTURE_SMALL_PNG)).unwrap();
        assert_eq!(png.content_type, "image/png");
        let b = png.bytes();
        assert_eq!(&b[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        // walk chunks and verify every CRC; the last one is IEND
        let mut pos = 8;
        let mut kinds = Vec::new();
        while pos < b.len() {
            let len = u32::from_be_bytes(b[pos..pos + 4].try_into().unwrap()) as usize;
            let body = &b[pos + 4..pos + 8 + len];
            let crc = u32::from_be_bytes(b[pos + 8 + len..pos + 12 + len].try_into().unwrap());
            assert_eq!(crc, crc32(body), "chunk {:?}", std::str::from_utf8(&body[..4]));
            kinds.push(String::from_utf8(body[..4].to_vec()).unwrap());
            pos += 12 + len;
        }
        assert_eq!(pos, b.len());
        assert_eq!(kinds, ["IHDR", "IDAT", "IEND"]);
        assert_eq!(
            &b[b.len() - 12..],
            &[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82]
        );
        assert!(b.len() < 400, "tiny: {}", b.len());
    }

    #[test]
    fn crc_and_adler_known_vectors() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn pdf_has_magic_and_consistent_xref() {
        let f = FixtureFiles::new();
        let pdf = f.get(&id(FIXTURE_PDF)).unwrap();
        assert_eq!(pdf.content_type, "application/pdf");
        let b = pdf.bytes();
        assert!(b.starts_with(b"%PDF-1.4"));
        assert!(b.ends_with(b"%%EOF\n"));
        let text = String::from_utf8_lossy(&b);
        let sx = text.rfind("startxref\n").unwrap();
        let off: usize = text[sx + 10..].lines().next().unwrap().parse().unwrap();
        assert!(b[off..].starts_with(b"xref\n"));
        // every xref entry points at "<n> 0 obj"
        let tail = String::from_utf8_lossy(&b[off..]).into_owned();
        let entries: Vec<&str> = tail.lines().skip(3).take(5).collect();
        for (i, e) in entries.iter().enumerate() {
            let o: usize = e[..10].parse().unwrap();
            assert!(
                b[o..].starts_with(format!("{} 0 obj", i + 1).as_bytes()),
                "obj {}",
                i + 1
            );
        }
    }

    #[test]
    fn oversized_is_size_only_until_asked() {
        let f = FixtureFiles::new();
        let o = f.get(&id(FIXTURE_OVERSIZED)).unwrap();
        assert_eq!(o.len(), OVERSIZED_LEN);
        assert_eq!(o.content, FixtureContent::Zeros(OVERSIZED_LEN));
        let mut sink = CountingWrite(0);
        o.write_to(&mut sink).unwrap();
        assert_eq!(sink.0, OVERSIZED_LEN);
    }

    struct CountingWrite(u64);
    impl Write for CountingWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0 += buf.len() as u64;
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn registry_and_partition_mapping() {
        let f = FixtureFiles::new();
        assert_eq!(f.ids().len(), 3);
        for fid in f.ids() {
            assert!(f.get(&fid).is_some());
            assert!(is_known_fixture(&fid.0));
        }
        assert!(f.get(&id("/etc/passwd")).is_none());
        assert_eq!(
            FixtureFiles::id_for(Partition::FileFixturePdf),
            Some(id(FIXTURE_PDF))
        );
        assert_eq!(FixtureFiles::id_for(Partition::TextEmpty), None);
    }

    #[test]
    fn fixtures_are_deterministic() {
        assert_eq!(FixtureFiles::new().png, FixtureFiles::new().png);
        assert_eq!(FixtureFiles::new().pdf, FixtureFiles::new().pdf);
    }
}
