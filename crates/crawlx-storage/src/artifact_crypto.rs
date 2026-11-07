//! Bounded, ownership-bound artifact encryption without embedded key custody.
//!
//! Version 1 stores `CXAR`, a version byte, fixed chunk size, declared plaintext
//! length and a random nonce prefix, followed by 64 KiB AES-256-GCM chunks and an
//! authenticated empty terminal frame. Every frame authenticates the entire
//! header, tenant/run/artifact IDs, frame index, frame kind and plaintext length.
//! The terminal frame also binds the final chunk count. Neither plaintext data
//! keys nor wrapped keys are serialized here: callers must publish wrapped-key
//! custody separately, atomically with the authorized artifact catalog row.
//!
//! Encryption generates a fresh object key and nonce prefix and consumes its
//! encryptor, preventing reuse. Decryption releases only authenticated chunks;
//! it withholds the final plaintext chunk until the terminal tag and physical
//! EOF are verified. Earlier chunks remain provisional until completion. A
//! consumer must not publish a partially consumed stream as a complete object.
//! No whole-object buffering, plaintext compatibility, or implicit key exists.
//!
//! Owned plaintext buffers and raw keys are zeroized, including on cancellation
//! and errors. Caller input/output buffers and copies remain caller-owned. Ring
//! does not expose zeroization of its expanded key schedule; schedules are
//! short-lived inside bounded blocking jobs. Dropping an operation aborts it;
//! restarting an encryption requires a fresh encryptor and a fresh destination.

use crawlx_core::{ArtifactId, CrawlRunId, TenantId};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use std::{fmt, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use zeroize::{Zeroize as _, Zeroizing};

const DOMAIN: &[u8] = b"crawlx/artifact-stream/v1";
const MAGIC: &[u8; 4] = b"CXAR";
const VERSION: u8 = 1;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = 21;
const DATA_FRAME: u8 = 0;
const FINAL_FRAME: u8 = 1;
const AAD_BYTES: usize = DOMAIN.len() + 48 + HEADER_BYTES + 8 + 1 + 4;

/// Maximum plaintext held by one artifact encryption/decryption frame.
pub const ARTIFACT_CHUNK_BYTES: usize = 64 * 1024;
const CHUNK_U32: u32 = 64 * 1024;
const CHUNK_U64: u64 = 64 * 1024;

/// Immutable object identity authenticated on every frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactContext {
    tenant: TenantId,
    run: CrawlRunId,
    artifact: ArtifactId,
}

impl ArtifactContext {
    /// Bind ciphertext to a preallocated artifact ID and its owning tenant/run.
    #[must_use]
    pub fn new(tenant: TenantId, run: CrawlRunId, artifact: ArtifactId) -> Self {
        Self {
            tenant,
            run,
            artifact,
        }
    }

    /// Owning tenant authenticated by every ciphertext frame.
    #[must_use]
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Owning run authenticated by every ciphertext frame.
    #[must_use]
    pub fn run(&self) -> CrawlRunId {
        self.run
    }

    /// Preallocated artifact identity authenticated by every ciphertext frame.
    #[must_use]
    pub fn artifact(&self) -> ArtifactId {
        self.artifact
    }

    fn aad(&self, header: &[u8; HEADER_BYTES], index: u64, kind: u8, length: u32) -> [u8; AAD_BYTES] {
        let mut aad = [0; AAD_BYTES];
        aad[..DOMAIN.len()].copy_from_slice(DOMAIN);
        let mut cursor = DOMAIN.len();
        for id in [self.tenant.0, self.run.0, self.artifact.0] {
            aad[cursor..cursor + 16].copy_from_slice(id.as_bytes());
            cursor += 16;
        }
        aad[cursor..cursor + HEADER_BYTES].copy_from_slice(header);
        cursor += HEADER_BYTES;
        aad[cursor..cursor + 8].copy_from_slice(&index.to_be_bytes());
        cursor += 8;
        aad[cursor] = kind;
        aad[cursor + 1..].copy_from_slice(&length.to_be_bytes());
        aad
    }
}

/// Non-cloneable raw object key; never serialized or exposed by formatting.
#[must_use]
#[non_exhaustive]
pub struct ArtifactDataKey {
    bytes: Arc<Zeroizing<[u8; 32]>>,
}

impl ArtifactDataKey {
    /// Import an authenticated, unwrapped custody key for decryption only.
    ///
    /// This constructor cannot supply a key to [`ArtifactEncryption`].
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self {
            bytes: Arc::new(bytes),
        }
    }

    /// Borrow raw key bytes for explicit KMS wrapping; do not log or persist them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.bytes.as_ref()
    }
}

impl fmt::Debug for ArtifactDataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArtifactDataKey([REDACTED])")
    }
}

/// Fail-closed framing, authentication, size and streaming failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArtifactCryptoError {
    /// Unsupported header, malformed frame, truncated input or trailing bytes.
    #[error("artifact encryption framing invalid")]
    InvalidEnvelope,
    /// Input exceeded the caller's unchanged plaintext limit or numeric bounds.
    #[error("artifact encryption size limit exceeded")]
    LimitExceeded,
    /// Plaintext input differed from the declared final length.
    #[error("artifact encryption input length mismatch")]
    LengthMismatch,
    /// A frame's key, ownership, header, order or tag did not authenticate.
    #[error("artifact authentication failed")]
    Authentication,
    /// OS cryptographic entropy was unavailable.
    #[error("artifact encryption entropy unavailable")]
    Entropy(#[source] ring::error::Unspecified),
    /// Underlying streaming I/O failed.
    #[error("artifact encryption io failed")]
    Io(#[source] std::io::Error),
    /// A bounded blocking crypto job failed to complete.
    #[error("artifact encryption task failed")]
    Task(#[source] tokio::task::JoinError),
    /// A previous read failed or was cancelled; the reader cannot resume.
    #[error("artifact decryption reader aborted")]
    Aborted,
}

/// A successful encrypted stream, with its key kept separate from staged bytes.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub struct SealedArtifact {
    /// Fresh object key to wrap in durable custody before catalog publication.
    pub data_key: ArtifactDataKey,
    /// Authenticated final plaintext length.
    pub plaintext_len: u64,
    /// Exact ciphertext length, including header, chunk tags and terminal tag.
    pub ciphertext_len: u64,
}

/// Single-use encryption plan with fresh OS-generated object key and nonce prefix.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub struct ArtifactEncryption {
    context: ArtifactContext,
    key: ArtifactDataKey,
    header: [u8; HEADER_BYTES],
    plaintext_len: u64,
    ciphertext_len: u64,
}

impl ArtifactEncryption {
    /// Prepare encryption after checking the caller's existing plaintext limit.
    ///
    /// # Errors
    /// Rejects lengths above `max_plaintext_bytes`, overflow and unavailable entropy.
    pub fn new(
        context: ArtifactContext,
        plaintext_len: u64,
        max_plaintext_bytes: u64,
    ) -> Result<Self, ArtifactCryptoError> {
        checked_lengths(plaintext_len, max_plaintext_bytes)?;
        let mut bytes = Zeroizing::new([0; 32]);
        SystemRandom::new()
            .fill(bytes.as_mut())
            .map_err(ArtifactCryptoError::Entropy)?;
        Self::from_generated_key(
            context,
            ArtifactDataKey::from_bytes(bytes),
            plaintext_len,
            max_plaintext_bytes,
        )
    }

    // Only custody providers can supply a generated data key. Public sealing
    // cannot accept imported/reused keys.
    pub(crate) fn from_generated_key(
        context: ArtifactContext,
        key: ArtifactDataKey,
        plaintext_len: u64,
        max_plaintext_bytes: u64,
    ) -> Result<Self, ArtifactCryptoError> {
        let ciphertext_len = checked_lengths(plaintext_len, max_plaintext_bytes)?;
        let mut header = make_header(plaintext_len);
        SystemRandom::new()
            .fill(&mut header[17..])
            .map_err(ArtifactCryptoError::Entropy)?;
        Ok(Self {
            context,
            key,
            header,
            plaintext_len,
            ciphertext_len,
        })
    }

    /// Encrypt exactly the declared bytes into a caller-owned ciphertext sink.
    ///
    /// Uses at most one 64 KiB plaintext frame plus its authentication tag.
    /// Input must reach EOF exactly at the declared length. On any failure or
    /// cancellation, discard the partial destination; never publish it. This
    /// flushes the sink but leaves durable file sync/upload completion to callers.
    ///
    /// # Errors
    /// Rejects short/long input and returns entropy, authentication, I/O or task failures.
    pub async fn seal<R, W>(self, mut input: R, mut output: W) -> Result<SealedArtifact, ArtifactCryptoError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        output
            .write_all(&self.header)
            .await
            .map_err(ArtifactCryptoError::Io)?;
        let mut remaining = self.plaintext_len;
        let mut index = 0u64;
        let mut buffer = Zeroizing::new(Vec::with_capacity(ARTIFACT_CHUNK_BYTES + TAG_BYTES));
        while remaining != 0 {
            let length = next_length(remaining)?;
            buffer.resize(length, 0);
            read_exact(&mut input, &mut buffer, ArtifactCryptoError::LengthMismatch).await?;
            let size = u32::try_from(length).map_err(|_| ArtifactCryptoError::LimitExceeded)?;
            buffer = crypt_frame(
                Arc::clone(&self.key.bytes),
                self.context.aad(&self.header, index, DATA_FRAME, size),
                nonce(&self.header, index),
                buffer,
                true,
            )
            .await?;
            output.write_all(&buffer).await.map_err(ArtifactCryptoError::Io)?;
            buffer.zeroize();
            buffer.clear();
            remaining -= u64::from(size);
            index = index.checked_add(1).ok_or(ArtifactCryptoError::LimitExceeded)?;
        }
        require_eof(&mut input, ArtifactCryptoError::LengthMismatch).await?;
        let terminal = crypt_frame(
            Arc::clone(&self.key.bytes),
            self.context.aad(&self.header, index, FINAL_FRAME, 0),
            nonce(&self.header, index),
            buffer,
            true,
        )
        .await?;
        output
            .write_all(&terminal)
            .await
            .map_err(ArtifactCryptoError::Io)?;
        output.flush().await.map_err(ArtifactCryptoError::Io)?;
        Ok(SealedArtifact {
            data_key: self.key,
            plaintext_len: self.plaintext_len,
            ciphertext_len: self.ciphertext_len,
        })
    }
}

/// Bounded authenticated chunk consumer; cancellation or errors poison the reader.
///
/// `next_chunk()` returns the last plaintext only after terminal authentication
/// and physical EOF. Discard all partial consumer output if any call fails.
#[must_use]
#[non_exhaustive]
pub struct ArtifactDecryption<R> {
    input: R,
    context: ArtifactContext,
    key: ArtifactDataKey,
    header: [u8; HEADER_BYTES],
    remaining: u64,
    index: u64,
    plaintext_len: u64,
    complete: bool,
    aborted: bool,
}

impl<R: AsyncRead + Unpin> ArtifactDecryption<R> {
    /// Read a fixed header and enforce the existing consumer's plaintext limit.
    ///
    /// Header fields remain untrusted until frame authentication succeeds. No
    /// allocation scales with the header's declared length. Pass custody's key
    /// only after validating the caller's authorization and object ownership.
    ///
    /// # Errors
    /// Rejects unsupported/malformed/truncated headers, oversized lengths and I/O failures.
    pub async fn new(
        mut input: R,
        context: ArtifactContext,
        key: ArtifactDataKey,
        max_plaintext_bytes: u64,
    ) -> Result<Self, ArtifactCryptoError> {
        let mut header = [0; HEADER_BYTES];
        read_exact(&mut input, &mut header, ArtifactCryptoError::InvalidEnvelope).await?;
        if &header[..4] != MAGIC || header[4] != VERSION || header[5..9] != CHUNK_U32.to_be_bytes() {
            return Err(ArtifactCryptoError::InvalidEnvelope);
        }
        let plaintext_len = u64::from_be_bytes(
            header[9..17]
                .try_into()
                .map_err(|_| ArtifactCryptoError::InvalidEnvelope)?,
        );
        checked_lengths(plaintext_len, max_plaintext_bytes)?;
        Ok(Self {
            input,
            context,
            key,
            header,
            remaining: plaintext_len,
            index: 0,
            plaintext_len,
            complete: false,
            aborted: false,
        })
    }

    /// Return the authenticated final size only after complete terminal verification.
    #[must_use]
    pub fn authenticated_len(&self) -> Option<u64> {
        self.complete.then_some(self.plaintext_len)
    }

    /// Authenticate and consume the next bounded plaintext chunk.
    ///
    /// The final chunk is withheld until the terminal frame and physical EOF
    /// authenticate. Empty input authenticates its terminal before returning
    /// `None`. Dropping this future after polling poisons the reader: resuming
    /// would risk losing partial I/O progress or reusing frame state.
    ///
    /// # Errors
    /// Rejects tampering, truncation, reordering, trailing data, I/O failure and
    /// reuse after any prior failure/cancellation. Never returns unauthenticated bytes.
    pub async fn next_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, ArtifactCryptoError> {
        if self.aborted {
            return Err(ArtifactCryptoError::Aborted);
        }
        if self.complete {
            return Ok(None);
        }
        self.aborted = true;
        let mut chunk = None;
        if self.remaining != 0 {
            let length = next_length(self.remaining)?;
            let mut buffer = Zeroizing::new(vec![0; length + TAG_BYTES]);
            read_exact(&mut self.input, &mut buffer, ArtifactCryptoError::InvalidEnvelope).await?;
            let size = u32::try_from(length).map_err(|_| ArtifactCryptoError::LimitExceeded)?;
            let plaintext = crypt_frame(
                Arc::clone(&self.key.bytes),
                self.context.aad(&self.header, self.index, DATA_FRAME, size),
                nonce(&self.header, self.index),
                buffer,
                false,
            )
            .await?;
            self.remaining -= u64::from(size);
            self.index = self
                .index
                .checked_add(1)
                .ok_or(ArtifactCryptoError::LimitExceeded)?;
            chunk = Some(plaintext);
        }
        if self.remaining == 0 {
            let mut terminal = Zeroizing::new(vec![0; TAG_BYTES]);
            read_exact(
                &mut self.input,
                &mut terminal,
                ArtifactCryptoError::InvalidEnvelope,
            )
            .await?;
            crypt_frame(
                Arc::clone(&self.key.bytes),
                self.context.aad(&self.header, self.index, FINAL_FRAME, 0),
                nonce(&self.header, self.index),
                terminal,
                false,
            )
            .await?;
            require_eof(&mut self.input, ArtifactCryptoError::InvalidEnvelope).await?;
            self.complete = true;
        }
        self.aborted = false;
        Ok(chunk)
    }
}

fn make_header(plaintext_len: u64) -> [u8; HEADER_BYTES] {
    let mut header = [0; HEADER_BYTES];
    header[..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[5..9].copy_from_slice(&CHUNK_U32.to_be_bytes());
    header[9..17].copy_from_slice(&plaintext_len.to_be_bytes());
    header
}

pub(crate) fn checked_lengths(length: u64, max: u64) -> Result<u64, ArtifactCryptoError> {
    if length > max {
        return Err(ArtifactCryptoError::LimitExceeded);
    }
    let chunks = (length / CHUNK_U64)
        .checked_add(u64::from(!length.is_multiple_of(CHUNK_U64)))
        .ok_or(ArtifactCryptoError::LimitExceeded)?;
    chunks
        .checked_add(1)
        .and_then(|frames| frames.checked_mul(16))
        .and_then(|overhead| overhead.checked_add(21))
        .and_then(|overhead| length.checked_add(overhead))
        .ok_or(ArtifactCryptoError::LimitExceeded)
}

fn next_length(remaining: u64) -> Result<usize, ArtifactCryptoError> {
    usize::try_from(remaining.min(CHUNK_U64)).map_err(|_| ArtifactCryptoError::LimitExceeded)
}

fn nonce(header: &[u8; HEADER_BYTES], index: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(&header[17..]);
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    nonce
}

async fn crypt_frame(
    key: Arc<Zeroizing<[u8; 32]>>,
    aad: [u8; AAD_BYTES],
    nonce: [u8; 12],
    mut buffer: Zeroizing<Vec<u8>>,
    encrypt: bool,
) -> Result<Zeroizing<Vec<u8>>, ArtifactCryptoError> {
    tokio::task::spawn_blocking(move || {
        let unbound = UnboundKey::new(&aead::AES_256_GCM, key.as_ref().as_ref())
            .map_err(|_| ArtifactCryptoError::Authentication)?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce);
        if encrypt {
            let tag = key
                .seal_in_place_separate_tag(nonce, Aad::from(&aad), &mut buffer)
                .map_err(|_| ArtifactCryptoError::Authentication)?;
            buffer.extend_from_slice(tag.as_ref());
        } else {
            let length = key
                .open_in_place(nonce, Aad::from(&aad), &mut buffer)
                .map_err(|_| ArtifactCryptoError::Authentication)?
                .len();
            buffer[length..].zeroize();
            buffer.truncate(length);
        }
        Ok(buffer)
    })
    .await
    .map_err(ArtifactCryptoError::Task)?
}

async fn read_exact<R: AsyncRead + Unpin>(
    input: &mut R,
    bytes: &mut [u8],
    truncated: ArtifactCryptoError,
) -> Result<(), ArtifactCryptoError> {
    input.read_exact(bytes).await.map(|_| ()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            truncated
        } else {
            ArtifactCryptoError::Io(error)
        }
    })
}

async fn require_eof<R: AsyncRead + Unpin>(
    input: &mut R,
    trailing: ArtifactCryptoError,
) -> Result<(), ArtifactCryptoError> {
    // Encryption may discover a surplus plaintext byte; zeroize it on every exit.
    let mut extra = Zeroizing::new([0; 1]);
    if input
        .read(extra.as_mut())
        .await
        .map_err(ArtifactCryptoError::Io)?
        != 0
    {
        return Err(trailing);
    }
    Ok(())
}

#[cfg(test)]
#[path = "artifact_crypto_tests.rs"]
mod tests;
