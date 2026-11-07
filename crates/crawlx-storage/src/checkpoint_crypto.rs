//! Ownership-bound checkpoint encryption, with no plaintext compatibility path.
//!
//! The binary `CXCP` envelope contains a version, provider, wrapped-key length,
//! random nonce, wrapped data key (KMS only), and AES-256-GCM ciphertext/tag.
//! Domain, version, provider, tenant, run, session and checkpoint IDs are AEAD AAD.
//! Plaintext is bounded at 32 MiB and wrapped keys at 64 KiB before allocation.
//!
//! # Custody and operational prerequisites
//!
//! [`MemoryCheckpointKeys`] is process-local custody, not a production root or a
//! cross-process recovery mechanism. [`KmsCheckpointKeys`] requires an explicitly
//! configured symmetric KMS key, AWS region and credentials from the SDK default
//! chain, reachable KMS, and `kms:GenerateDataKey` / `kms:Decrypt` permissions.
//! Both KMS operations use the same ownership encryption context. Context IDs
//! are not secrets: AWS can record encryption context in CloudTrail. Prefer a
//! stable key ARN over a retargetable alias for durable checkpoint recovery.
//! Construction loads SDK configuration; it does not prove KMS authorization or
//! availability. Each seal generates a fresh data key; each open calls KMS. No
//! key cache, fallback key, automatic root creation, or plaintext downgrade exists.
//!
//! Owned plaintext/data-key buffers are zeroized, including on authentication
//! failure. The SDK may retain HTTP/JSON response buffers until deallocation;
//! ring's internal expanded key schedule has no public zeroization API. Such
//! schedules are short-lived inside blocking crypto jobs, never serialized.

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_kms::{primitives::Blob, types::DataKeySpec, Client};
use aws_smithy_http_client::tls;
use crawlx_core::checkpoint_crypto::{
    self as core_crypto, Ciphertext, CiphertextError, HEADER_BYTES, KMS, MAGIC, MAX_ENVELOPE, MAX_PLAINTEXT,
    MAX_WRAPPED_KEY, MEMORY, NONCE_BYTES, TAG_BYTES, VERSION,
};
use crawlx_core::{CheckpointId, CrawlRunId, SessionId, TenantId};
use ring::rand::{SecureRandom, SystemRandom};
use std::{collections::BTreeMap, error::Error, fmt, sync::Arc};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"crawlx/checkpoint/v1";

/// The complete immutable ownership tuple authenticated by checkpoint encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheckpointContext {
    tenant: TenantId,
    run: CrawlRunId,
    session: SessionId,
    checkpoint: CheckpointId,
}

impl CheckpointContext {
    /// Bind a checkpoint to its tenant, run, session and preallocated checkpoint ID.
    #[must_use]
    pub fn new(tenant: TenantId, run: CrawlRunId, session: SessionId, checkpoint: CheckpointId) -> Self {
        Self {
            tenant,
            run,
            session,
            checkpoint,
        }
    }

    fn aad(&self, provider: u8) -> [u8; DOMAIN.len() + 2 + 64] {
        let mut aad = [0; DOMAIN.len() + 2 + 64];
        aad[..DOMAIN.len()].copy_from_slice(DOMAIN);
        aad[DOMAIN.len()..DOMAIN.len() + 2].copy_from_slice(&[VERSION, provider]);
        for (slot, id) in aad[DOMAIN.len() + 2..].chunks_exact_mut(16).zip([
            self.tenant.0,
            self.run.0,
            self.session.0,
            self.checkpoint.0,
        ]) {
            slot.copy_from_slice(id.as_bytes());
        }
        aad
    }

    fn kms_context(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("domain".to_owned(), "crawlx/checkpoint/v1".to_owned()),
            ("tenant".to_owned(), self.tenant.to_string()),
            ("run".to_owned(), self.run.to_string()),
            ("session".to_owned(), self.session.to_string()),
            ("checkpoint".to_owned(), self.checkpoint.to_string()),
        ])
    }
}

/// Object-safe checkpoint encryption custody. Implementations must fail closed.
#[async_trait]
pub trait CheckpointKeys: Send + Sync {
    /// Whether custody is configured, not whether a remote service is healthy.
    fn is_available(&self) -> bool {
        true
    }

    /// Encrypt bytes for exactly this ownership tuple.
    ///
    /// # Errors
    /// Returns a typed error for missing custody, bounds, entropy, SDK or crypto failures.
    async fn seal(
        &self,
        context: &CheckpointContext,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<Ciphertext, CheckpointCryptoError>;

    /// Authenticate an envelope before exposing any plaintext.
    ///
    /// # Errors
    /// Rejects missing custody, invalid envelopes, wrong ownership/keys, tampering and SDK failures.
    async fn open(
        &self,
        context: &CheckpointContext,
        ciphertext: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, CheckpointCryptoError>;
}

/// Redacted source chain retaining the original failure privately.
///
/// Formatting and traversing `source()` never exposes SDK response bodies,
/// credentials, endpoints or service messages. The original error remains owned
/// for its lifetime; its chain shape is represented by redacted source nodes.
#[derive(thiserror::Error)]
#[error("checkpoint provider failure (details redacted)")]
#[non_exhaustive]
pub struct CheckpointCryptoSource {
    _original: Option<Box<dyn Error + Send + Sync>>,
    #[source]
    cause: Option<Box<CheckpointCryptoSource>>,
}

impl CheckpointCryptoSource {
    fn new(error: impl Error + Send + Sync + 'static) -> Self {
        // Bound traversal even if a third-party Error implementation has a cycle.
        let mut depth = 0;
        let mut source = error.source();
        while let Some(next) = source {
            depth += 1;
            if depth == 16 {
                break;
            }
            source = next.source();
        }
        let mut cause = None;
        for _ in 0..depth {
            cause = Some(Box::new(Self {
                _original: None,
                cause,
            }));
        }
        Self {
            _original: Some(Box::new(error)),
            cause,
        }
    }
}

impl fmt::Debug for CheckpointCryptoSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CheckpointCryptoSource([REDACTED])")
    }
}

/// Fail-closed checkpoint encryption errors; all formatting is secret-free.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum CheckpointCryptoError {
    /// No provider was explicitly configured for durable storage.
    #[error("checkpoint encryption provider unavailable")]
    Unavailable,
    /// Invalid or missing operator KMS configuration.
    #[error("checkpoint encryption configuration invalid")]
    InvalidConfiguration,
    /// Unknown version/provider, invalid lengths, or truncated envelope.
    #[error("checkpoint encryption envelope invalid")]
    InvalidEnvelope,
    /// Plaintext, wrapped key or envelope exceeded its fixed bound.
    #[error("checkpoint encryption size limit exceeded")]
    LimitExceeded,
    /// Ownership, key, nonce, ciphertext or authentication tag did not match.
    #[error("checkpoint authentication failed")]
    Authentication,
    /// OS cryptographic entropy was unavailable.
    #[error("checkpoint encryption entropy unavailable")]
    Entropy {
        /// Redacted entropy failure source.
        #[source]
        source: CheckpointCryptoSource,
    },
    /// An AWS KMS operation failed without a plaintext fallback.
    #[error("checkpoint kms operation failed")]
    Kms {
        /// Redacted SDK failure source chain.
        #[source]
        source: CheckpointCryptoSource,
    },
    /// The blocking crypto job could not finish.
    #[error("checkpoint encryption task failed")]
    Task {
        /// Redacted task failure source.
        #[source]
        source: CheckpointCryptoSource,
    },
}

/// Random, zeroizing custody for process-local in-memory repositories only.
#[non_exhaustive]
pub struct MemoryCheckpointKeys {
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl fmt::Debug for MemoryCheckpointKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryCheckpointKeys([REDACTED])")
    }
}

impl MemoryCheckpointKeys {
    /// Create independent ephemeral custody from OS entropy, never a default production root.
    ///
    /// # Errors
    /// Returns [`CheckpointCryptoError::Entropy`] when OS entropy is unavailable.
    pub fn new() -> Result<Self, CheckpointCryptoError> {
        let mut key = Zeroizing::new([0; 32]);
        random_fill(key.as_mut())?;
        Ok(Self { key: Arc::new(key) })
    }
}

#[async_trait]
impl CheckpointKeys for MemoryCheckpointKeys {
    async fn seal(
        &self,
        context: &CheckpointContext,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<Ciphertext, CheckpointCryptoError> {
        check_plaintext(&plaintext)?;
        let key = Arc::clone(&self.key);
        let context = *context;
        blocking(move || encrypt(&context, MEMORY, key.as_ref().as_ref(), &[], plaintext)).await
    }

    async fn open(
        &self,
        context: &CheckpointContext,
        ciphertext: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, CheckpointCryptoError> {
        let envelope = parse_envelope(&ciphertext, MEMORY)?;
        let key = Arc::clone(&self.key);
        let context = *context;
        let nonce = envelope.nonce;
        blocking(move || {
            decrypt(
                &context,
                MEMORY,
                key.as_ref().as_ref(),
                nonce,
                HEADER_BYTES,
                Zeroizing::new(ciphertext),
            )
        })
        .await
    }
}

/// Real AWS KMS envelope encryption with fresh AES-256 data keys per checkpoint.
#[non_exhaustive]
pub struct KmsCheckpointKeys {
    client: Client,
    key_id: String,
}

impl fmt::Debug for KmsCheckpointKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KmsCheckpointKeys([REDACTED])")
    }
}

impl KmsCheckpointKeys {
    /// Load the AWS default region/credential chain with the approved rustls+ring connector.
    ///
    /// Does not create a KMS key or call KMS to validate grants. Every operation
    /// supplies the configured key ID, preventing decryption under another KMS key.
    ///
    /// # Errors
    /// Rejects an empty/oversized key identifier or absent AWS region. SDK failures
    /// are returned by `seal`/`open`; no generated key or plaintext fallback exists.
    pub async fn from_environment(key_id: String) -> Result<Self, CheckpointCryptoError> {
        validate_key_id(&key_id)?;
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::Ring))
            .build_https();
        let sdk = aws_config::defaults(BehaviorVersion::latest())
            .http_client(http)
            .load()
            .await;
        if sdk.region().is_none() {
            return Err(CheckpointCryptoError::InvalidConfiguration);
        }
        Ok(Self {
            client: Client::new(&sdk),
            key_id,
        })
    }
}

#[async_trait]
impl CheckpointKeys for KmsCheckpointKeys {
    async fn seal(
        &self,
        context: &CheckpointContext,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<Ciphertext, CheckpointCryptoError> {
        check_plaintext(&plaintext)?;
        let mut request = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .key_spec(DataKeySpec::Aes256);
        for (key, value) in context.kms_context() {
            request = request.encryption_context(key, value);
        }
        let output = request.send().await.map_err(|error| CheckpointCryptoError::Kms {
            source: CheckpointCryptoSource::new(error),
        })?;
        let key = Zeroizing::new(
            output
                .plaintext
                .ok_or(CheckpointCryptoError::Authentication)?
                .into_inner(),
        );
        let wrapped = output
            .ciphertext_blob
            .ok_or(CheckpointCryptoError::InvalidEnvelope)?
            .into_inner();
        if key.len() != 32 {
            return Err(CheckpointCryptoError::Authentication);
        }
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_KEY {
            return Err(CheckpointCryptoError::LimitExceeded);
        }
        let context = *context;
        blocking(move || encrypt(&context, KMS, &key, &wrapped, plaintext)).await
    }

    async fn open(
        &self,
        context: &CheckpointContext,
        ciphertext: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, CheckpointCryptoError> {
        let envelope = parse_envelope(&ciphertext, KMS)?;
        let mut request = self
            .client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(Blob::new(envelope.wrapped.to_vec()));
        for (key, value) in context.kms_context() {
            request = request.encryption_context(key, value);
        }
        let output = request.send().await.map_err(|error| CheckpointCryptoError::Kms {
            source: CheckpointCryptoSource::new(error),
        })?;
        let key = Zeroizing::new(
            output
                .plaintext
                .ok_or(CheckpointCryptoError::Authentication)?
                .into_inner(),
        );
        if key.len() != 32 {
            return Err(CheckpointCryptoError::Authentication);
        }
        let context = *context;
        let nonce = envelope.nonce;
        let encrypted_start = HEADER_BYTES + envelope.wrapped.len();
        blocking(move || {
            decrypt(
                &context,
                KMS,
                &key,
                nonce,
                encrypted_start,
                Zeroizing::new(ciphertext),
            )
        })
        .await
    }
}

/// Explicit absent custody. Never accepts or returns plaintext.
#[derive(Debug, Default)]
pub struct UnavailableCheckpointKeys;

#[async_trait]
impl CheckpointKeys for UnavailableCheckpointKeys {
    fn is_available(&self) -> bool {
        false
    }

    async fn seal(
        &self,
        _: &CheckpointContext,
        _: Zeroizing<Vec<u8>>,
    ) -> Result<Ciphertext, CheckpointCryptoError> {
        Err(CheckpointCryptoError::Unavailable)
    }

    async fn open(
        &self,
        _: &CheckpointContext,
        _: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, CheckpointCryptoError> {
        Err(CheckpointCryptoError::Unavailable)
    }
}

fn validate_key_id(key_id: &str) -> Result<(), CheckpointCryptoError> {
    if key_id.trim().is_empty() || key_id.len() > 2048 {
        return Err(CheckpointCryptoError::InvalidConfiguration);
    }
    Ok(())
}

fn check_plaintext(plaintext: &[u8]) -> Result<(), CheckpointCryptoError> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(CheckpointCryptoError::LimitExceeded);
    }
    Ok(())
}

fn random_fill(bytes: &mut [u8]) -> Result<(), CheckpointCryptoError> {
    SystemRandom::new()
        .fill(bytes)
        .map_err(|error| CheckpointCryptoError::Entropy {
            source: CheckpointCryptoSource::new(error),
        })
}

async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, CheckpointCryptoError> + Send + 'static,
) -> Result<T, CheckpointCryptoError> {
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|error| CheckpointCryptoError::Task {
            source: CheckpointCryptoSource::new(error),
        })?
}

struct Envelope<'a> {
    nonce: [u8; NONCE_BYTES],
    wrapped: &'a [u8],
}

fn parse_envelope(bytes: &[u8], provider: u8) -> Result<Envelope<'_>, CheckpointCryptoError> {
    if bytes.len() > MAX_ENVELOPE {
        return Err(CheckpointCryptoError::LimitExceeded);
    }
    if bytes.len() < HEADER_BYTES + TAG_BYTES
        || &bytes[..4] != MAGIC
        || bytes[4] != VERSION
        || bytes[5] != provider
    {
        return Err(CheckpointCryptoError::InvalidEnvelope);
    }
    let wrapped_len = usize::try_from(u32::from_be_bytes(
        bytes[6..10]
            .try_into()
            .map_err(|_| CheckpointCryptoError::InvalidEnvelope)?,
    ))
    .map_err(|_| CheckpointCryptoError::LimitExceeded)?;
    if wrapped_len > MAX_WRAPPED_KEY {
        return Err(CheckpointCryptoError::LimitExceeded);
    }
    if (provider == MEMORY && wrapped_len != 0) || (provider == KMS && wrapped_len == 0) {
        return Err(CheckpointCryptoError::InvalidEnvelope);
    }
    let encrypted_start = HEADER_BYTES
        .checked_add(wrapped_len)
        .ok_or(CheckpointCryptoError::LimitExceeded)?;
    let encrypted = bytes
        .get(encrypted_start..)
        .ok_or(CheckpointCryptoError::InvalidEnvelope)?;
    if encrypted.len() < TAG_BYTES {
        return Err(CheckpointCryptoError::InvalidEnvelope);
    }
    if encrypted.len() - TAG_BYTES > MAX_PLAINTEXT {
        return Err(CheckpointCryptoError::LimitExceeded);
    }
    Ok(Envelope {
        nonce: bytes[10..HEADER_BYTES]
            .try_into()
            .map_err(|_| CheckpointCryptoError::InvalidEnvelope)?,
        wrapped: &bytes[HEADER_BYTES..encrypted_start],
    })
}

impl From<CiphertextError> for CheckpointCryptoError {
    fn from(error: CiphertextError) -> Self {
        match error {
            CiphertextError::InvalidEnvelope => Self::InvalidEnvelope,
            CiphertextError::LimitExceeded => Self::LimitExceeded,
            CiphertextError::Authentication => Self::Authentication,
            CiphertextError::Entropy { source } => Self::Entropy {
                source: CheckpointCryptoSource::new(source),
            },
            // Unknown future primitive failures remain fail-closed.
            _ => Self::Authentication,
        }
    }
}

fn encrypt(
    context: &CheckpointContext,
    provider: u8,
    key: &[u8],
    wrapped: &[u8],
    plaintext: Zeroizing<Vec<u8>>,
) -> Result<Ciphertext, CheckpointCryptoError> {
    core_crypto::seal(provider, key, wrapped, plaintext, &context.aad(provider)).map_err(Into::into)
}

fn decrypt(
    context: &CheckpointContext,
    provider: u8,
    key: &[u8],
    nonce: [u8; NONCE_BYTES],
    encrypted_start: usize,
    ciphertext: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, CheckpointCryptoError> {
    core_crypto::open(key, nonce, encrypted_start, ciphertext, &context.aad(provider)).map_err(Into::into)
}

#[cfg(test)]
#[path = "checkpoint_crypto_tests.rs"]
mod tests;
