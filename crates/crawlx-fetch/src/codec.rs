//! Bounded response-body reading and content-coding (`gzip`, `deflate`, `br`).
//!
//! One implementation serves the fetch plane and any caller that holds already-received
//! bytes ([`decode_bytes`]); no other crate needs a second decompressor.
//!
//! Three limits apply independently ([`BodyLimits`]):
//!
//! * the **wire** cap bounds bytes read from the transport (the compressed size);
//! * the **decoded** cap bounds bytes produced after decoding;
//! * the **expansion ratio** bounds decoded bytes per wire byte once a small floor is passed.
//!
//! Decoders are push decoders writing into a sink that refuses output beyond the decoded cap,
//! so decoding work is proportional to the cap and not to what a hostile stream claims to
//! contain. A body cut by the wire or decoded cap is reported as truncated (partial), never
//! as complete. An expansion-ratio violation is an error: nothing of a decompression bomb
//! is returned. A cap of `0` means "no bytes", not "unlimited", and no cap can exceed
//! [`HARD_MAX_BODY_BYTES`].

use crate::body_limits::DEFAULT_MAX_BODY_BYTES;
use crate::error::FetchError;
use crate::tls::HttpResponse;
use async_compression::tokio::write::{BrotliDecoder, DeflateDecoder, GzipDecoder, ZlibDecoder};
use bytes::Bytes;
use crawlx_core::parser_memory::{global, ByteBudget, BytePermit};
use http::{header, HeaderMap};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Deployment hard ceiling for any body cap, wire or decoded (the `fetch.maxResponseBytes`
/// range ends here). Requests for more are clamped to it.
pub const HARD_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Default decoded-bytes-per-wire-byte limit.
pub const DEFAULT_MAX_EXPANSION_RATIO: u32 = 250;

/// The ratio is only enforced once this many decoded bytes exist, so a small, highly
/// compressible document is never mistaken for a bomb.
pub const RATIO_FLOOR_BYTES: usize = 256 * 1024;

/// At most this many stacked content codings are decoded.
pub const MAX_CODINGS: usize = 2;

/// Wire chunk size [`decode_bytes`] feeds the decoder with.
const SLICE_CHUNK: usize = 16 * 1024;

// Covers owner/control blocks independently of decoded capacity. Codec working memory
// is admitted separately, before constructing the third-party push decoders.
const OWNER_OVERHEAD: usize = 256;
const DECODER_OVERHEAD: usize = 4096;
const DEFLATE_WORKING_BYTES: usize = 1024 * 1024;
const BROTLI_TABLE_BYTES: usize = 32 * 1024 * 1024;

/// The dependency enables Brotli's large-window extension. Reserve two complete
/// rings (growth can retain the old ring) plus tables and push-decoder buffers.
/// An inner coding's header is not visible, so use its largest supported window.
fn coding_working_bytes(coding: Coding, prefix: Option<&[u8]>) -> usize {
    if coding != Coding::Brotli {
        return DEFLATE_WORKING_BYTES;
    }
    let bits = prefix.and_then(|bytes| bytes.first()).map_or(30, |byte| {
        if byte & 1 == 0 {
            16
        } else {
            let next = (byte >> 1) & 7;
            if next != 0 {
                u32::from(next) + 17
            } else {
                match (byte >> 4) & 7 {
                    0 => 17,
                    1 => 30,
                    value => u32::from(value) + 8,
                }
            }
        }
    });
    (1usize << bits)
        .saturating_mul(2)
        .saturating_add(BROTLI_TABLE_BYTES)
}

/// Which limit stopped or refused a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BodyLimitKind {
    /// The declared `Content-Length` exceeded a cap (refused before the body was read).
    Declared,
    /// Decoded bytes reached the decoded cap.
    Decoded,
    /// Wire bytes reached the wire cap.
    Wire,
    /// Decoded bytes per wire byte exceeded the expansion-ratio limit.
    ExpansionRatio,
}

impl BodyLimitKind {
    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Decoded => "decoded",
            Self::Wire => "wire",
            Self::ExpansionRatio => "expansion_ratio",
        }
    }
}

/// Independent wire, decoded and expansion limits of one body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BodyLimits {
    decoded: usize,
    wire: usize,
    wire_explicit: bool,
    ratio: u32,
}

impl BodyLimits {
    /// Limits for a decoded cap. Caps above [`HARD_MAX_BODY_BYTES`] are clamped to it. The
    /// default wire cap is the decoded cap plus the framing overhead of incompressible data,
    /// so a body of exactly the decoded cap never trips it; for an identity body (wire bytes
    /// are decoded bytes) it only applies when set explicitly.
    #[must_use]
    pub fn new(decoded: usize) -> Self {
        let decoded = decoded.min(HARD_MAX_BODY_BYTES);
        Self {
            decoded,
            wire: decoded
                .saturating_add(decoded / 16 + 4096)
                .min(HARD_MAX_BODY_BYTES),
            wire_explicit: false,
            ratio: DEFAULT_MAX_EXPANSION_RATIO,
        }
    }

    /// Replace the wire cap (clamped to [`HARD_MAX_BODY_BYTES`]).
    #[must_use]
    pub fn with_wire_cap(mut self, wire: usize) -> Self {
        self.wire = wire.min(HARD_MAX_BODY_BYTES);
        self.wire_explicit = true;
        self
    }

    /// Replace the expansion-ratio limit. Zero restores [`DEFAULT_MAX_EXPANSION_RATIO`]: a
    /// ratio can be tightened or loosened but never switched off.
    #[must_use]
    pub const fn with_max_expansion_ratio(mut self, ratio: u32) -> Self {
        self.ratio = if ratio == 0 {
            DEFAULT_MAX_EXPANSION_RATIO
        } else {
            ratio
        };
        self
    }

    /// Decoded-byte cap.
    #[must_use]
    pub const fn decoded(&self) -> usize {
        self.decoded
    }

    /// Wire-byte cap.
    #[must_use]
    pub const fn wire(&self) -> usize {
        self.wire
    }

    /// Expansion-ratio limit.
    #[must_use]
    pub const fn max_expansion_ratio(&self) -> u32 {
        self.ratio
    }
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_BODY_BYTES)
    }
}

/// One supported content coding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Coding {
    /// `gzip` / `x-gzip`.
    Gzip,
    /// `deflate`: zlib-wrapped (RFC 9110), or a raw stream when the first bytes are not a
    /// zlib header.
    Deflate,
    /// `br`.
    Brotli,
}

impl Coding {
    /// The coding's token.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Brotli => "br",
        }
    }
}

/// The content coding of a response.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentEncoding {
    /// Identity, or only supported codings in the order the sender applied them.
    Supported(Vec<Coding>),
    /// A coding this plane cannot decode; the body is passed through undecoded.
    Unsupported(String),
}

impl ContentEncoding {
    /// Parse every `Content-Encoding` header value.
    ///
    /// # Errors
    /// [`FetchError::BodyDecode`] when more than [`MAX_CODINGS`] codings are stacked.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, FetchError> {
        let mut codings = Vec::new();
        for value in headers.get_all(header::CONTENT_ENCODING) {
            let Ok(value) = value.to_str() else {
                return Ok(Self::Unsupported("non-ascii".to_owned()));
            };
            for token in value.split(',') {
                let token = token.trim().to_ascii_lowercase();
                match token.as_str() {
                    "" | "identity" => {}
                    "gzip" | "x-gzip" => codings.push(Coding::Gzip),
                    "deflate" => codings.push(Coding::Deflate),
                    "br" => codings.push(Coding::Brotli),
                    _ => return Ok(Self::Unsupported(token.chars().take(32).collect())),
                }
            }
        }
        if codings.len() > MAX_CODINGS {
            return Err(FetchError::BodyDecode {
                encoding: "stacked",
                reason: format!("more than {MAX_CODINGS} content codings"),
            });
        }
        Ok(Self::Supported(codings))
    }

    /// The codings to decode (empty for identity and unsupported).
    #[must_use]
    pub fn codings(&self) -> &[Coding] {
        match self {
            Self::Supported(codings) => codings,
            Self::Unsupported(_) => &[],
        }
    }
}

/// A fully read body.
#[derive(Debug)]
pub(crate) struct BodyRead {
    pub(crate) body: Bytes,
    pub(crate) body_permit: Option<Arc<BytePermit>>,
    pub(crate) wire_bytes: u64,
    /// blake3 (hex) of the wire bytes read, kept for encoded bodies so the original
    /// representation stays identifiable after decoding.
    pub(crate) wire_digest: Option<String>,
    /// The body was cut by a cap; `limit` names it.
    pub(crate) limit: Option<BodyLimitKind>,
}

/// Accepted bytes and stop reason shared between the reader and the output sink.
#[derive(Debug)]
struct Shared {
    // Drop bytes before admission, including cancellation and decoder errors.
    buf: Vec<u8>,
    permit: Option<BytePermit>,
    budget: Arc<ByteBudget>,
    cap: usize,
    wire: u64,
    /// Expansion ratio enforced on decoded output; `None` for identity bodies.
    ratio: Option<u64>,
    stop: Option<BodyLimitKind>,
    memory_error: Option<FetchError>,
}

impl Shared {
    /// Admit geometric capacity and the temporary old allocation before reallocating.
    fn extend(&mut self, data: &[u8]) -> Result<(), FetchError> {
        let required = self.buf.len().saturating_add(data.len());
        if required > self.buf.capacity() {
            let capacity = required.max(self.buf.capacity().saturating_mul(2)).min(self.cap);
            let permit = self.permit.as_mut().ok_or(FetchError::AcquisitionUnavailable)?;
            // Reallocation may allocate the new block before freeing the old block.
            let peak = self.budget.try_reserve(self.buf.capacity())?;
            permit.grow_to(capacity.saturating_add(OWNER_OVERHEAD))?;
            self.buf
                .try_reserve_exact(capacity - self.buf.len())
                .map_err(|source| FetchError::Io(io::Error::new(io::ErrorKind::OutOfMemory, source)))?;
            drop(peak);
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }
}

/// `Bytes` owns this wrapper, so even extracting/cloning only `body` retains admission.
#[derive(Debug)]
struct OwnedBody {
    buf: Vec<u8>,
    _permit: Arc<BytePermit>,
}

impl AsRef<[u8]> for OwnedBody {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

/// Output sink: accepts up to the decoded cap and refuses the first byte beyond it.
struct Sink(Arc<Mutex<Shared>>);

impl AsyncWrite for Sink {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut shared = self.0.lock();
        let room = shared.cap - shared.buf.len();
        if room == 0 {
            shared.stop.get_or_insert(BodyLimitKind::Decoded);
            return Poll::Ready(Err(io::Error::other("decoded body cap reached")));
        }
        let accepted = room.min(data.len());
        if let Err(error) = shared.extend(&data[..accepted]) {
            shared.memory_error = Some(error);
            return Poll::Ready(Err(io::Error::other("body memory admission failed")));
        }
        if let Some(ratio) = shared.ratio {
            let decoded = u64::try_from(shared.buf.len()).unwrap_or(u64::MAX);
            let floor = u64::try_from(RATIO_FLOOR_BYTES).unwrap_or(u64::MAX);
            if decoded > floor && decoded > shared.wire.saturating_mul(ratio) {
                shared.stop = Some(BodyLimitKind::ExpansionRatio);
                return Poll::Ready(Err(io::Error::other("expansion ratio exceeded")));
            }
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

type Writer = Pin<Box<dyn AsyncWrite + Send>>;

/// A raw deflate stream has no zlib header: the first two bytes of a zlib stream form a
/// multiple of 31 with compression method 8.
fn looks_like_zlib(first: &[u8]) -> bool {
    matches!(first, [cmf, flg, ..] if cmf & 0x0f == 8 && ((u16::from(*cmf) << 8) | u16::from(*flg)) % 31 == 0)
}

/// `wire_prefix` is the start of the wire bytes for the outermost coding (the only one
/// whose input is visible); an inner `deflate` is assumed zlib-wrapped.
fn wrap(coding: Coding, inner: Writer, wire_prefix: Option<&[u8]>) -> Writer {
    match coding {
        Coding::Gzip => Box::pin(GzipDecoder::new(inner)),
        Coding::Brotli => Box::pin(BrotliDecoder::new(inner)),
        Coding::Deflate if wire_prefix.is_none_or(looks_like_zlib) => Box::pin(ZlibDecoder::new(inner)),
        Coding::Deflate => Box::pin(DeflateDecoder::new(inner)),
    }
}

/// Incremental bounded decoder.
pub(crate) struct Decoder {
    shared: Arc<Mutex<Shared>>,
    codings: Vec<Coding>,
    writer: Option<Writer>,
    wire: u64,
    received_wire: u64,
    wire_cap: u64,
    stopped: bool,
    hasher: Option<blake3::Hasher>,
    budget: Arc<ByteBudget>,
    // Must outlive writer and Shared on cancellation, errors and normal completion.
    overhead: BytePermit,
}

impl Decoder {
    pub(crate) fn new(codings: &[Coding], limits: &BodyLimits) -> Result<Self, FetchError> {
        Self::with_budget(codings, limits, global())
    }

    fn with_budget(
        codings: &[Coding],
        limits: &BodyLimits,
        budget: &Arc<ByteBudget>,
    ) -> Result<Self, FetchError> {
        if codings.len() > MAX_CODINGS {
            return Err(FetchError::BodyDecode {
                encoding: "stacked",
                reason: format!("more than {MAX_CODINGS} content codings"),
            });
        }
        let overhead = budget.try_reserve(DECODER_OVERHEAD)?;
        let permit = budget.try_reserve(OWNER_OVERHEAD)?;
        let ratio = (!codings.is_empty()).then_some(u64::from(limits.ratio));
        Ok(Self {
            shared: Arc::new(Mutex::new(Shared {
                buf: Vec::new(),
                permit: Some(permit),
                budget: Arc::clone(budget),
                cap: limits.decoded,
                wire: 0,
                ratio,
                stop: None,
                memory_error: None,
            })),
            codings: codings.to_vec(),
            writer: None,
            wire: 0,
            received_wire: 0,
            wire_cap: if codings.is_empty() && !limits.wire_explicit {
                u64::MAX
            } else {
                u64::try_from(limits.wire).unwrap_or(u64::MAX)
            },
            stopped: false,
            hasher: (!codings.is_empty()).then(blake3::Hasher::new),
            budget: Arc::clone(budget),
            overhead,
        })
    }

    fn coding_label(&self) -> &'static str {
        match self.codings.as_slice() {
            [] => "identity",
            [one] => one.name(),
            _ => "stacked",
        }
    }
    fn open(&mut self, first: &[u8]) -> Result<&mut Writer, FetchError> {
        if self.writer.is_none() {
            let last = self.codings.len().saturating_sub(1);
            let working = self
                .codings
                .iter()
                .enumerate()
                .fold(DECODER_OVERHEAD, |total, (index, coding)| {
                    total.saturating_add(coding_working_bytes(*coding, (index == last).then_some(first)))
                });
            self.overhead.grow_to(working)?;
            // Wire bytes enter the last-applied coding; each decoder feeds the one before.
            let mut writer: Writer = Box::pin(Sink(Arc::clone(&self.shared)));
            for (index, coding) in self.codings.iter().enumerate() {
                writer = wrap(*coding, writer, (index == last).then_some(first));
            }
            self.writer = Some(writer);
        }
        self.writer.as_mut().ok_or(FetchError::AcquisitionUnavailable)
    }

    /// Map a failed write: a recorded stop is a limit, anything else a decode error.
    fn failed(&mut self, error: &io::Error) -> Result<(), FetchError> {
        if let Some(error) = self.shared.lock().memory_error.take() {
            return Err(error);
        }
        let stop = self.shared.lock().stop;
        match stop {
            Some(BodyLimitKind::ExpansionRatio) => Err(FetchError::BodyLimit {
                kind: BodyLimitKind::ExpansionRatio,
                limit: self.shared.lock().ratio.unwrap_or(0),
            }),
            Some(_) => {
                self.stopped = true;
                Ok(())
            }
            None => Err(FetchError::BodyDecode {
                encoding: self.coding_label(),
                reason: error.to_string(),
            }),
        }
    }

    /// Feed one wire chunk. Returns `false` once a cap stopped the body.
    pub(crate) async fn feed(&mut self, chunk: &[u8]) -> Result<bool, FetchError> {
        if self.stopped {
            return Ok(false);
        }
        if chunk.is_empty() {
            return Ok(true);
        }
        // Native transports own their receive buffers; charge the live chunk while
        // decoding without claiming control over the transport's internal allocator.
        let _chunk_permit = self.budget.try_reserve(chunk.len())?;
        self.received_wire = self
            .received_wire
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if let Some(hasher) = &mut self.hasher {
            hasher.update(chunk);
        }
        let room = usize::try_from(self.wire_cap.saturating_sub(self.wire)).unwrap_or(usize::MAX);
        let allowed = room.min(chunk.len());
        if allowed < chunk.len() {
            self.shared.lock().stop.get_or_insert(BodyLimitKind::Wire);
        }
        self.wire = self
            .wire
            .saturating_add(u64::try_from(allowed).unwrap_or(u64::MAX));
        self.shared.lock().wire = self.wire;
        if allowed > 0 {
            let first = &chunk[..allowed];
            let writer = self.open(first)?;
            if let Err(error) = writer.write_all(first).await {
                self.failed(&error)?;
                return Ok(false);
            }
            if !self.codings.is_empty() {
                // Decoding is CPU work between awaits: let other tasks run per chunk.
                tokio::task::yield_now().await;
            }
        }
        if allowed < chunk.len() {
            self.stopped = true;
            return Ok(false);
        }
        Ok(true)
    }

    /// Finish the stream and return the body.
    pub(crate) async fn finish(mut self) -> Result<BodyRead, FetchError> {
        if !self.stopped {
            if let Some(mut writer) = self.writer.take() {
                if let Err(error) = writer.shutdown().await {
                    // A truncated stream fails here; a cap reached while flushing is a stop.
                    self.failed(&error)?;
                }
            }
        }
        let mut shared = self.shared.lock();
        let limit = shared.stop;
        let buf = std::mem::take(&mut shared.buf);
        let permit = Arc::new(shared.permit.take().ok_or(FetchError::AcquisitionUnavailable)?);
        let body = Bytes::from_owner(OwnedBody {
            buf,
            _permit: Arc::clone(&permit),
        });
        Ok(BodyRead {
            body,
            body_permit: Some(permit),
            wire_bytes: self.received_wire,
            wire_digest: self.hasher.as_ref().map(|h| h.finalize().to_hex().to_string()),
            limit,
        })
    }
}

/// Read `resp` to the end or to a cap, decoding `codings`.
pub(crate) async fn read_body(
    mut resp: HttpResponse,
    codings: &[Coding],
    limits: &BodyLimits,
) -> Result<BodyRead, FetchError> {
    let mut decoder = Decoder::new(codings, limits)?;
    // Only a clean end of stream proves completeness; empty chunks are not the end.
    while let Some(chunk) = resp.chunk().await? {
        if !decoder.feed(&chunk).await? {
            break;
        }
    }
    decoder.finish().await
}

/// A decoded body held in memory.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DecodedBody {
    /// Decoded bytes, at most the decoded cap.
    pub body: Bytes,
    /// Shared admission retained by the byte owner, including standalone `Bytes` clones.
    pub body_permit: Option<Arc<BytePermit>>,
    /// Wire bytes received, including the unprocessed tail of a chunk crossing a cap.
    pub wire_bytes: u64,
    /// blake3 (hex) of the wire bytes read; present for encoded bodies.
    pub wire_digest: Option<String>,
    /// The cap that cut the body, if any. A cut body is partial.
    pub truncated_by: Option<BodyLimitKind>,
}

impl PartialEq for DecodedBody {
    fn eq(&self, other: &Self) -> bool {
        self.body == other.body
            && self.wire_bytes == other.wire_bytes
            && self.wire_digest == other.wire_digest
            && self.truncated_by == other.truncated_by
    }
}

impl Eq for DecodedBody {}

/// Decode `wire` with the same limits the fetch plane applies to a response body.
///
/// # Errors
/// [`FetchError::BodyDecode`] for a malformed or truncated stream,
/// [`FetchError::BodyLimit`] for an expansion-ratio violation, and
/// [`FetchError::MemoryAdmission`] when shared byte admission refuses allocation.
pub async fn decode_bytes(
    codings: &[Coding],
    wire: &[u8],
    limits: &BodyLimits,
) -> Result<DecodedBody, FetchError> {
    let mut decoder = Decoder::new(codings, limits)?;
    for chunk in wire.chunks(SLICE_CHUNK) {
        if !decoder.feed(chunk).await? {
            break;
        }
    }
    let read = decoder.finish().await?;
    Ok(DecodedBody {
        body: read.body,
        body_permit: read.body_permit,
        wire_bytes: read.wire_bytes,
        wire_digest: read.wire_digest,
        truncated_by: read.limit,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use async_compression::tokio::write::{BrotliEncoder, GzipEncoder, ZlibEncoder};
    use http::HeaderValue;

    #[tokio::test]
    async fn body_admission_survives_standalone_bytes_clones() {
        let budget = Arc::new(ByteBudget::new(64 * 1024));
        let mut decoder = Decoder::with_budget(&[], &BodyLimits::new(4096), &budget).unwrap();
        decoder.feed(b"retained decoded bytes").await.unwrap();
        let read = decoder.finish().await.unwrap();
        let retained = read.body.clone();
        let weak = Arc::downgrade(read.body_permit.as_ref().unwrap());
        let reserved = read.body_permit.as_ref().unwrap().bytes();
        drop(read);
        assert_eq!(budget.used(), reserved);
        assert!(weak.upgrade().is_some());
        assert_eq!(retained.as_ref(), b"retained decoded bytes");
        drop(retained);
        assert!(weak.upgrade().is_none());
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn admission_failure_precedes_buffer_growth_and_preserves_source() {
        use std::error::Error;
        let budget = Arc::new(ByteBudget::new(DECODER_OVERHEAD + OWNER_OVERHEAD + 32));
        let mut decoder = Decoder::with_budget(&[], &BodyLimits::new(4096), &budget).unwrap();
        let error = decoder.feed(b"more than eight bytes").await.unwrap_err();
        assert!(matches!(error, FetchError::MemoryAdmission(_)));
        assert!(error.source().is_some());
        assert_eq!(decoder.shared.lock().buf.capacity(), 0);
        drop(decoder);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn reallocation_admits_new_and_old_capacity_and_keeps_existing_bytes_on_refusal() {
        let budget = Arc::new(ByteBudget::new(64 * 1024));
        let mut decoder = Decoder::with_budget(&[], &BodyLimits::new(4096), &budget).unwrap();
        decoder.feed(&[1; 64]).await.unwrap();
        let used = budget.used();
        // Enough for the borrowed wire chunk and the new output, but not both
        // old and new allocations during a copying reallocation.
        budget.set_limit(used + 128 + 128);
        assert!(matches!(
            decoder.feed(&[2; 128]).await,
            Err(FetchError::MemoryAdmission(_))
        ));
        assert_eq!(decoder.shared.lock().buf.as_slice(), &[1; 64]);
        assert_eq!(decoder.shared.lock().buf.capacity(), 64);
        drop(decoder);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn codec_working_memory_is_admitted_before_decoder_construction() {
        let budget = Arc::new(ByteBudget::new(64 * 1024));
        let mut decoder = Decoder::with_budget(&[Coding::Gzip], &BodyLimits::new(4096), &budget).unwrap();
        assert!(matches!(
            decoder.feed(b"gzip").await,
            Err(FetchError::MemoryAdmission(_))
        ));
        assert!(decoder.writer.is_none());
        assert_eq!(decoder.shared.lock().buf.capacity(), 0);
        drop(decoder);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn wire_count_includes_received_bytes_beyond_the_decoded_cap() {
        let decoded = decode_bytes(&[], b"received entire chunk", &BodyLimits::new(3))
            .await
            .unwrap();
        assert_eq!(decoded.body.as_ref(), b"rec");
        assert_eq!(decoded.wire_bytes, 21);
        assert_eq!(decoded.truncated_by, Some(BodyLimitKind::Decoded));
        let weak = Arc::downgrade(decoded.body_permit.as_ref().unwrap());
        let clone = decoded.clone();
        drop(decoded);
        assert!(weak.upgrade().is_some());
        drop(clone);
        assert!(weak.upgrade().is_none());
    }

    async fn encode(coding: Coding, plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        match coding {
            Coding::Gzip => {
                let mut e = GzipEncoder::new(&mut out);
                e.write_all(plain).await.unwrap();
                e.shutdown().await.unwrap();
            }
            Coding::Deflate => {
                let mut e = ZlibEncoder::new(&mut out);
                e.write_all(plain).await.unwrap();
                e.shutdown().await.unwrap();
            }
            Coding::Brotli => {
                let mut e = BrotliEncoder::new(&mut out);
                e.write_all(plain).await.unwrap();
                e.shutdown().await.unwrap();
            }
        }
        out
    }

    #[tokio::test]
    async fn every_coding_roundtrips_and_reports_wire_and_decoded_sizes() {
        let plain: Vec<u8> = (0..50_000u32).flat_map(|n| n.to_le_bytes()).collect();
        for coding in [Coding::Gzip, Coding::Deflate, Coding::Brotli] {
            let wire = encode(coding, &plain).await;
            let decoded = decode_bytes(&[coding], &wire, &BodyLimits::new(1 << 20))
                .await
                .unwrap();
            assert_eq!(decoded.body.as_ref(), plain.as_slice(), "{coding:?}");
            assert_eq!(decoded.wire_bytes, u64::try_from(wire.len()).unwrap());
            assert!(decoded.truncated_by.is_none());
        }
    }

    #[tokio::test]
    async fn raw_deflate_and_stacked_codings_decode() {
        use async_compression::tokio::write::DeflateEncoder;
        let plain = b"raw deflate payload ".repeat(200);
        let mut raw = Vec::new();
        let mut e = DeflateEncoder::new(&mut raw);
        e.write_all(&plain).await.unwrap();
        e.shutdown().await.unwrap();
        let decoded = decode_bytes(&[Coding::Deflate], &raw, &BodyLimits::new(1 << 20))
            .await
            .unwrap();
        assert_eq!(decoded.body.as_ref(), plain.as_slice());

        // `Content-Encoding: deflate, gzip`: gzip was applied last, so it is removed first.
        let stacked = encode(Coding::Gzip, &encode(Coding::Deflate, &plain).await).await;
        let decoded = decode_bytes(
            &[Coding::Deflate, Coding::Gzip],
            &stacked,
            &BodyLimits::new(1 << 20),
        )
        .await
        .unwrap();
        assert_eq!(decoded.body.as_ref(), plain.as_slice());
    }

    #[tokio::test]
    async fn decoded_cap_marks_the_body_partial_and_stops_decoding() {
        let plain = vec![b'a'; 4 * 1024 * 1024];
        let wire = encode(Coding::Gzip, &plain).await;
        let limits = BodyLimits::new(1000).with_max_expansion_ratio(1 << 20);
        let decoded = decode_bytes(&[Coding::Gzip], &wire, &limits).await.unwrap();
        assert_eq!(decoded.body.len(), 1000);
        assert_eq!(decoded.truncated_by, Some(BodyLimitKind::Decoded));
    }

    #[tokio::test]
    async fn a_body_of_exactly_the_cap_is_complete() {
        let plain = vec![b'z'; 5000];
        let wire = encode(Coding::Brotli, &plain).await;
        let exact = decode_bytes(&[Coding::Brotli], &wire, &BodyLimits::new(5000))
            .await
            .unwrap();
        assert_eq!(exact.body.len(), 5000);
        assert!(exact.truncated_by.is_none());
        let short = decode_bytes(&[Coding::Brotli], &wire, &BodyLimits::new(4999))
            .await
            .unwrap();
        assert_eq!(short.truncated_by, Some(BodyLimitKind::Decoded));
        // Identity bodies follow the same rule.
        let identity = decode_bytes(&[], &plain, &BodyLimits::new(5000)).await.unwrap();
        assert!(identity.truncated_by.is_none());
        let identity = decode_bytes(&[], &plain, &BodyLimits::new(10)).await.unwrap();
        assert_eq!(identity.body.len(), 10);
        assert_eq!(identity.truncated_by, Some(BodyLimitKind::Decoded));
    }

    #[tokio::test]
    async fn wire_cap_is_independent_of_the_decoded_cap() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let noise: Vec<u8> = (0..200_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect();
        let wire = encode(Coding::Gzip, &noise).await;
        let limits = BodyLimits::new(1 << 20).with_wire_cap(10_000);
        let decoded = decode_bytes(&[Coding::Gzip], &wire, &limits).await.unwrap();
        assert_eq!(decoded.truncated_by, Some(BodyLimitKind::Wire));
        assert_eq!(decoded.wire_bytes, u64::try_from(SLICE_CHUNK).unwrap());
        assert!(decoded.body.len() <= 10_000 + 64);
    }

    #[tokio::test]
    async fn expansion_bomb_is_refused_before_the_decoded_cap_fills() {
        // 64 MiB of zeroes compress by roughly 1000x.
        let wire = encode(Coding::Gzip, &vec![0u8; 64 * 1024 * 1024]).await;
        assert!(wire.len() < 200_000);
        let limits = BodyLimits::new(HARD_MAX_BODY_BYTES).with_max_expansion_ratio(100);
        let error = decode_bytes(&[Coding::Gzip], &wire, &limits).await.unwrap_err();
        assert!(
            matches!(
                error,
                FetchError::BodyLimit {
                    kind: BodyLimitKind::ExpansionRatio,
                    limit: 100
                }
            ),
            "{error:?}"
        );
        // A small, highly compressible document under the floor is fine.
        let small = encode(Coding::Gzip, &vec![0u8; 100_000]).await;
        let ok = decode_bytes(
            &[Coding::Gzip],
            &small,
            &BodyLimits::new(1 << 20).with_max_expansion_ratio(2),
        )
        .await
        .unwrap();
        assert_eq!(ok.body.len(), 100_000);
    }

    #[tokio::test]
    async fn truncated_and_corrupt_streams_are_decode_errors_not_short_successes() {
        let wire = encode(Coding::Gzip, &b"complete document ".repeat(500)).await;
        let cut = &wire[..wire.len() - 8];
        let error = decode_bytes(&[Coding::Gzip], cut, &BodyLimits::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error, FetchError::BodyDecode { encoding: "gzip", .. }),
            "{error:?}"
        );
        let error = decode_bytes(
            &[Coding::Brotli],
            b"definitely not brotli \xff\xfe",
            &BodyLimits::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, FetchError::BodyDecode { encoding: "br", .. }),
            "{error:?}"
        );
    }

    #[test]
    fn caps_clamp_to_the_hard_limit_and_zero_is_never_unlimited() {
        let big = BodyLimits::new(usize::MAX);
        assert_eq!(big.decoded(), HARD_MAX_BODY_BYTES);
        assert_eq!(big.wire(), HARD_MAX_BODY_BYTES);
        assert_eq!(BodyLimits::new(0).decoded(), 0);
        assert_eq!(
            BodyLimits::new(1)
                .with_max_expansion_ratio(0)
                .max_expansion_ratio(),
            DEFAULT_MAX_EXPANSION_RATIO
        );
        assert_eq!(
            BodyLimits::new(1).with_wire_cap(usize::MAX).wire(),
            HARD_MAX_BODY_BYTES
        );
    }

    #[test]
    fn content_encoding_parsing() {
        let parse = |values: &[&str]| {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(header::CONTENT_ENCODING, HeaderValue::from_str(value).unwrap());
            }
            ContentEncoding::from_headers(&headers)
        };
        assert_eq!(parse(&[]).unwrap(), ContentEncoding::Supported(vec![]));
        assert_eq!(parse(&["identity"]).unwrap(), ContentEncoding::Supported(vec![]));
        assert_eq!(
            parse(&["GZIP"]).unwrap(),
            ContentEncoding::Supported(vec![Coding::Gzip])
        );
        assert_eq!(
            parse(&["x-gzip"]).unwrap(),
            ContentEncoding::Supported(vec![Coding::Gzip])
        );
        assert_eq!(
            parse(&["deflate, br"]).unwrap(),
            ContentEncoding::Supported(vec![Coding::Deflate, Coding::Brotli])
        );
        assert_eq!(
            parse(&["gzip", "br"]).unwrap(),
            ContentEncoding::Supported(vec![Coding::Gzip, Coding::Brotli])
        );
        assert_eq!(
            parse(&["zstd"]).unwrap(),
            ContentEncoding::Unsupported("zstd".to_owned())
        );
        assert!(parse(&["gzip, gzip, gzip"]).is_err());
    }
}
