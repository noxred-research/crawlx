//! Explicit artifact data-key custody, separate from encrypted staging bytes.
//!
//! Production uses AWS KMS GenerateDataKey/Decrypt with the exact ownership map
//! defined by [`ArtifactKeyEnvelope`]. No provider embeds its envelope in stage
//! bytes. Construction does not prove KMS grants or availability; each operation
//! fails closed, including unknown remote outcomes. Configure a stable symmetric
//! key ARN, AWS region/credentials and kms:GenerateDataKey/kms:Decrypt permissions.
//! AWS may record the non-secret ownership context in CloudTrail.
//!
//! [`MemoryArtifactKeys`] is explicit ephemeral local/test custody only. Its
//! version-zero envelopes cannot pass the production catalog's version-one
//! validation. [`UnavailableArtifactKeys`] refuses every operation. Neither is
//! an automatic fallback. SDK HTTP/JSON buffers may retain raw response bytes
//! until deallocation; all owned plaintext key buffers here are zeroized.

use crate::{
    artifact_crypto::{
        checked_lengths, ArtifactContext, ArtifactCryptoError, ArtifactDataKey, ArtifactEncryption,
    },
    custody::ArtifactKeyEnvelope,
};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_kms::config::endpoint::{Endpoint, EndpointFuture, Params, ResolveEndpoint};
use aws_sdk_kms::{primitives::Blob, types::DataKeySpec, Client};
use aws_smithy_http_client::tls;
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use std::{error::Error, fmt, sync::Arc};
use zeroize::{Zeroize as _, Zeroizing};

const MAX_WRAPPED_KEY: usize = 64 * 1024;
const DOMAIN: &[u8] = b"crawlx/artifact-key/v1";

/// Fresh, single-use encryption plan and separately publishable wrapped custody.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub struct PreparedArtifact {
    /// Consuming this plan writes only encrypted framing, never key metadata.
    pub encryption: ArtifactEncryption,
    /// Publish atomically with the final authorized artifact catalog row.
    pub envelope: ArtifactKeyEnvelope,
}

/// Object-safe artifact key custody. Production callers must require durable custody.
#[async_trait]
pub trait ArtifactKeys: Send + Sync {
    /// Whether this provider is explicitly configured, not remotely healthy.
    fn is_available(&self) -> bool;

    /// Whether wrapped keys survive process restart under explicit external custody.
    fn is_durable(&self) -> bool;

    /// Generate a fresh object key and a single-use streaming encryption plan.
    ///
    /// # Errors
    /// Rejects existing size limits, missing custody, entropy, KMS and task failures.
    async fn prepare(
        &self,
        context: &ArtifactContext,
        plaintext_len: u64,
        max_plaintext_bytes: u64,
    ) -> Result<PreparedArtifact, ArtifactKeyError>;

    /// Unwrap the key for exactly this tenant/run/artifact ownership context.
    ///
    /// # Errors
    /// Rejects missing custody, malformed/oversized envelopes, wrong ownership or
    /// configured keys, authentication failures and failed/unknown KMS outcomes.
    async fn open(
        &self,
        context: &ArtifactContext,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<ArtifactDataKey, ArtifactKeyError>;
}

/// Provider failure whose formatting and traversable chain redact remote details.
#[derive(thiserror::Error)]
#[error("artifact key provider failure (details redacted)")]
#[non_exhaustive]
pub struct ArtifactKeySource {
    _original: Option<Box<dyn Error + Send + Sync>>,
    #[source]
    cause: Option<Box<ArtifactKeySource>>,
}

impl ArtifactKeySource {
    fn new(error: impl Error + Send + Sync + 'static) -> Self {
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

impl fmt::Debug for ArtifactKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArtifactKeySource([REDACTED])")
    }
}

/// Fail-closed artifact key custody errors, without sensitive remote messages.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArtifactKeyError {
    /// No custody provider was explicitly configured.
    #[error("artifact key custody unavailable")]
    Unavailable,
    /// The configured KMS key or AWS region was missing/invalid.
    #[error("artifact key configuration invalid")]
    InvalidConfiguration,
    /// Wrapped metadata was malformed, oversized or did not match ownership/provider.
    #[error("artifact key envelope invalid")]
    InvalidEnvelope,
    /// Key wrapping/unwrapping did not authenticate.
    #[error("artifact key authentication failed")]
    Authentication,
    /// Stage size, entropy or bounded crypto operation failed.
    #[error("artifact encryption preparation failed")]
    Crypto(#[from] ArtifactCryptoError),
    /// AWS rejected or did not confirm an operation; no local fallback is permitted.
    #[error("artifact kms operation failed")]
    Kms(#[source] ArtifactKeySource),
    /// OS cryptographic entropy was unavailable.
    #[error("artifact key entropy unavailable")]
    Entropy(#[source] ring::error::Unspecified),
    /// A bounded key crypto job could not complete.
    #[error("artifact key task failed")]
    Task(#[source] tokio::task::JoinError),
}

/// Durable symmetric AWS KMS custody using the approved rustls+ring connector.
#[non_exhaustive]
pub struct KmsArtifactKeys {
    client: Client,
    key_id: String,
}

impl fmt::Debug for KmsArtifactKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KmsArtifactKeys([REDACTED])")
    }
}

impl KmsArtifactKeys {
    /// Load default credentials, pin a stable key ARN and its trusted HTTPS endpoint.
    ///
    /// Only AWS commercial, China and GovCloud key ARNs are supported. The ARN
    /// determines region and endpoint; ambient endpoint URLs, service profiles,
    /// region, FIPS and dual-stack settings cannot redirect this client's KMS
    /// requests. Explicit loopback endpoint injection exists only in unit tests.
    /// Does not create roots, call KMS or prove grants.
    ///
    /// # Errors
    /// Rejects aliases, bare IDs, malformed key ARNs and unsupported partitions.
    pub async fn from_environment(key_id: String) -> Result<Self, ArtifactKeyError> {
        let endpoint = trusted_endpoint(&key_id)?;
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::Ring))
            .build_https();
        let sdk = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_sdk_kms::config::Region::new(endpoint.region.clone()))
            .endpoint_url(endpoint.url.clone())
            .http_client(http)
            .load()
            .await;
        let config = endpoint
            .configure(aws_sdk_kms::config::Builder::from(&sdk))
            .build();
        Ok(Self {
            client: Client::from_conf(config),
            key_id,
        })
    }
}

#[async_trait]
impl ArtifactKeys for KmsArtifactKeys {
    fn is_available(&self) -> bool {
        true
    }
    fn is_durable(&self) -> bool {
        true
    }

    async fn prepare(
        &self,
        context: &ArtifactContext,
        plaintext_len: u64,
        max_plaintext_bytes: u64,
    ) -> Result<PreparedArtifact, ArtifactKeyError> {
        checked_lengths(plaintext_len, max_plaintext_bytes)?;
        let encryption_context = ownership(context);
        let mut request = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .key_spec(DataKeySpec::Aes256);
        for (key, value) in &encryption_context {
            request = request.encryption_context(key, value);
        }
        let output = request
            .send()
            .await
            .map_err(|error| ArtifactKeyError::Kms(ArtifactKeySource::new(error)))?;
        let plaintext = Zeroizing::new(
            output
                .plaintext
                .ok_or(ArtifactKeyError::Authentication)?
                .into_inner(),
        );
        let key = import_key(&plaintext)?;
        let wrapped_key = output
            .ciphertext_blob
            .ok_or(ArtifactKeyError::InvalidEnvelope)?
            .into_inner();
        if wrapped_key.is_empty() || wrapped_key.len() > MAX_WRAPPED_KEY {
            return Err(ArtifactKeyError::InvalidEnvelope);
        }
        let envelope = ArtifactKeyEnvelope {
            kms_key_id: self.key_id.clone(),
            wrapped_key,
            encryption_context,
            format_version: 1,
        };
        let encryption =
            ArtifactEncryption::from_generated_key(*context, key, plaintext_len, max_plaintext_bytes)?;
        Ok(PreparedArtifact { encryption, envelope })
    }

    async fn open(
        &self,
        context: &ArtifactContext,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<ArtifactDataKey, ArtifactKeyError> {
        validate_envelope(context, envelope, &self.key_id, 1)?;
        let mut request = self
            .client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(Blob::new(envelope.wrapped_key.clone()));
        for (key, value) in &envelope.encryption_context {
            request = request.encryption_context(key, value);
        }
        let output = request
            .send()
            .await
            .map_err(|error| ArtifactKeyError::Kms(ArtifactKeySource::new(error)))?;
        let plaintext = Zeroizing::new(
            output
                .plaintext
                .ok_or(ArtifactKeyError::Authentication)?
                .into_inner(),
        );
        import_key(&plaintext)
    }
}

/// Explicit process-local/test-only wrapping root, never a production fallback.
#[non_exhaustive]
pub struct MemoryArtifactKeys {
    root: Arc<Zeroizing<[u8; 32]>>,
    key_id: String,
}

impl fmt::Debug for MemoryArtifactKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryArtifactKeys([REDACTED])")
    }
}

impl MemoryArtifactKeys {
    /// Create independent ephemeral custody. Version-zero envelopes are not durable.
    ///
    /// # Errors
    /// Returns an entropy failure if the OS cannot create a wrapping root or ID.
    pub fn new() -> Result<Self, ArtifactKeyError> {
        let mut root = Zeroizing::new([0; 32]);
        let mut id = [0; 16];
        let random = SystemRandom::new();
        random.fill(root.as_mut()).map_err(ArtifactKeyError::Entropy)?;
        random.fill(&mut id).map_err(ArtifactKeyError::Entropy)?;
        Ok(Self {
            root: Arc::new(root),
            key_id: format!("memory-artifact-only:{}", hex::encode(id)),
        })
    }
}

#[async_trait]
impl ArtifactKeys for MemoryArtifactKeys {
    fn is_available(&self) -> bool {
        true
    }
    fn is_durable(&self) -> bool {
        false
    }

    async fn prepare(
        &self,
        context: &ArtifactContext,
        plaintext_len: u64,
        max_plaintext_bytes: u64,
    ) -> Result<PreparedArtifact, ArtifactKeyError> {
        // Version zero is deliberately rejected by the production PG catalog publisher.
        wrap_prepare(
            &self.root,
            &self.key_id,
            0,
            context,
            plaintext_len,
            max_plaintext_bytes,
        )
        .await
    }

    async fn open(
        &self,
        context: &ArtifactContext,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<ArtifactDataKey, ArtifactKeyError> {
        wrap_open(&self.root, &self.key_id, 0, context, envelope).await
    }
}

/// Startup failures while loading the operator-provisioned artifact key file.
///
/// Messages never include key material or the file contents.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArtifactKeyFileError {
    /// The configured file could not be opened, inspected or read.
    #[error("artifact key file is unavailable")]
    File(#[source] std::io::Error),
    /// The opened descriptor does not name a regular, non-writable-by-others file.
    #[error("artifact key file must be regular and not group- or world-writable")]
    UnsafeFile,
    /// The key is not exactly 32 bytes encoded as hexadecimal text.
    #[error("artifact key file requires exactly 64 hexadecimal characters")]
    Invalid,
}

/// Durable wrapping root loaded from a file, for deployments without AWS KMS.
///
/// Per-artifact data keys are wrapped under the root with AES-256-GCM bound to the
/// tenant/run/artifact ownership context, so wrapped keys survive restarts and are
/// version-one envelopes that the production catalog accepts. The key id is a
/// non-secret fingerprint of the root: replacing the file with a different key makes
/// existing envelopes fail closed instead of decrypting wrongly. The operator owns
/// root-key custody, backup and rotation; losing the file loses every sealed artifact.
#[non_exhaustive]
pub struct FileArtifactKeys {
    root: Arc<Zeroizing<[u8; 32]>>,
    key_id: String,
}

impl fmt::Debug for FileArtifactKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileArtifactKeys([REDACTED])")
    }
}

impl FileArtifactKeys {
    /// Load the root key named by `CRAWLX_ARTIFACT_KEY_FILE`, if set.
    ///
    /// The file holds exactly 64 hexadecimal characters with at most one final LF.
    /// Symlinks (Kubernetes projected secrets) are followed; security checks use the
    /// opened descriptor, never a separate path lookup. No key is generated.
    ///
    /// # Errors
    /// Rejects unreadable, non-regular, group/world-writable or malformed files.
    pub fn from_lookup(
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, ArtifactKeyFileError> {
        use std::io::Read as _;
        let Some(path) = getenv("CRAWLX_ARTIFACT_KEY_FILE") else {
            return Ok(None);
        };
        let descriptor = rustix::fs::open(
            path.as_str(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| ArtifactKeyFileError::File(std::io::Error::from(error)))?;
        let mut file = std::fs::File::from(descriptor);
        let metadata = file.metadata().map_err(ArtifactKeyFileError::File)?;
        if !metadata.is_file() {
            return Err(ArtifactKeyFileError::UnsafeFile);
        }
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(ArtifactKeyFileError::UnsafeFile);
            }
        }
        let mut bytes = Zeroizing::new([0_u8; 66]);
        let mut count = 0;
        while count < bytes.len() {
            let read = file
                .read(&mut bytes[count..])
                .map_err(ArtifactKeyFileError::File)?;
            if read == 0 {
                break;
            }
            count += read;
        }
        if count == 65 && bytes[64] == b'\n' {
            count = 64;
        }
        if count != 64 {
            return Err(ArtifactKeyFileError::Invalid);
        }
        let text = std::str::from_utf8(&bytes[..count]).map_err(|_| ArtifactKeyFileError::Invalid)?;
        let mut root = Zeroizing::new([0_u8; 32]);
        hex::decode_to_slice(text, root.as_mut()).map_err(|_| ArtifactKeyFileError::Invalid)?;
        let fingerprint = blake3::derive_key("crawlx/artifact-file-key-id/v1", root.as_ref());
        Ok(Some(Self {
            root: Arc::new(root),
            key_id: format!("file-artifact-key:{}", hex::encode(&fingerprint[..16])),
        }))
    }
}

#[async_trait]
impl ArtifactKeys for FileArtifactKeys {
    fn is_available(&self) -> bool {
        true
    }
    fn is_durable(&self) -> bool {
        true
    }

    async fn prepare(
        &self,
        context: &ArtifactContext,
        plaintext_len: u64,
        max_plaintext_bytes: u64,
    ) -> Result<PreparedArtifact, ArtifactKeyError> {
        wrap_prepare(
            &self.root,
            &self.key_id,
            1,
            context,
            plaintext_len,
            max_plaintext_bytes,
        )
        .await
    }

    async fn open(
        &self,
        context: &ArtifactContext,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<ArtifactDataKey, ArtifactKeyError> {
        wrap_open(&self.root, &self.key_id, 1, context, envelope).await
    }
}

async fn wrap_prepare(
    root: &Arc<Zeroizing<[u8; 32]>>,
    key_id: &str,
    version: u32,
    context: &ArtifactContext,
    plaintext_len: u64,
    max_plaintext_bytes: u64,
) -> Result<PreparedArtifact, ArtifactKeyError> {
    checked_lengths(plaintext_len, max_plaintext_bytes)?;
    let mut bytes = Zeroizing::new([0; 32]);
    let mut nonce = [0; 12];
    let random = SystemRandom::new();
    random.fill(bytes.as_mut()).map_err(ArtifactKeyError::Entropy)?;
    random.fill(&mut nonce).map_err(ArtifactKeyError::Entropy)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(48));
    buffer.extend_from_slice(bytes.as_ref());
    let wrapped = memory_crypto(Arc::clone(root), *context, nonce, buffer, true).await?;
    let mut wrapped_key = Vec::with_capacity(60);
    wrapped_key.extend_from_slice(&nonce);
    wrapped_key.extend_from_slice(&wrapped);
    let encryption = ArtifactEncryption::from_generated_key(
        *context,
        ArtifactDataKey::from_bytes(bytes),
        plaintext_len,
        max_plaintext_bytes,
    )?;
    let envelope = ArtifactKeyEnvelope {
        kms_key_id: key_id.to_owned(),
        wrapped_key,
        encryption_context: ownership(context),
        format_version: version,
    };
    Ok(PreparedArtifact { encryption, envelope })
}

async fn wrap_open(
    root: &Arc<Zeroizing<[u8; 32]>>,
    key_id: &str,
    version: u32,
    context: &ArtifactContext,
    envelope: &ArtifactKeyEnvelope,
) -> Result<ArtifactDataKey, ArtifactKeyError> {
    validate_envelope(context, envelope, key_id, version)?;
    if envelope.wrapped_key.len() != 60 {
        return Err(ArtifactKeyError::InvalidEnvelope);
    }
    let nonce = envelope.wrapped_key[..12]
        .try_into()
        .map_err(|_| ArtifactKeyError::InvalidEnvelope)?;
    let plaintext = memory_crypto(
        Arc::clone(root),
        *context,
        nonce,
        Zeroizing::new(envelope.wrapped_key[12..].to_vec()),
        false,
    )
    .await?;
    import_key(&plaintext)
}

/// Missing custody: every operation refuses, without a plaintext or local fallback.
#[derive(Debug, Default)]
pub struct UnavailableArtifactKeys;

#[async_trait]
impl ArtifactKeys for UnavailableArtifactKeys {
    fn is_available(&self) -> bool {
        false
    }
    fn is_durable(&self) -> bool {
        false
    }

    async fn prepare(
        &self,
        _: &ArtifactContext,
        _: u64,
        _: u64,
    ) -> Result<PreparedArtifact, ArtifactKeyError> {
        Err(ArtifactKeyError::Unavailable)
    }

    async fn open(
        &self,
        _: &ArtifactContext,
        _: &ArtifactKeyEnvelope,
    ) -> Result<ArtifactDataKey, ArtifactKeyError> {
        Err(ArtifactKeyError::Unavailable)
    }
}

fn ownership(context: &ArtifactContext) -> std::collections::BTreeMap<String, String> {
    ArtifactKeyEnvelope::context(context.tenant(), context.run(), context.artifact())
}

#[derive(Debug)]
struct TrustedKmsEndpoint {
    region: String,
    url: String,
}

impl TrustedKmsEndpoint {
    fn configure(self, builder: aws_sdk_kms::config::Builder) -> aws_sdk_kms::config::Builder {
        builder
            .region(aws_sdk_kms::config::Region::new(self.region.clone()))
            .endpoint_url(self.url.clone())
            // A static service resolver replaces profile/environment-derived
            // resolution entirely, including service-specific endpoint URLs.
            .endpoint_resolver(self)
    }
}

impl ResolveEndpoint for TrustedKmsEndpoint {
    fn resolve_endpoint(&self, _: &Params) -> EndpointFuture<'_> {
        EndpointFuture::ready(Ok(Endpoint::builder().url(self.url.clone()).build()))
    }
}

fn trusted_endpoint(key_id: &str) -> Result<TrustedKmsEndpoint, ArtifactKeyError> {
    let invalid = || ArtifactKeyError::InvalidConfiguration;
    if key_id.len() > 2048 {
        return Err(invalid());
    }
    let mut fields = key_id.split(':');
    let (Some("arn"), Some(partition), Some("kms"), Some(region), Some(account), Some(resource), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(invalid());
    };
    if account.len() != 12
        || !account.bytes().all(|byte| byte.is_ascii_digit())
        || region.is_empty()
        || region.len() > 63
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !region.as_bytes()[0].is_ascii_lowercase()
        || !region.as_bytes()[region.len() - 1].is_ascii_digit()
        || region.contains("--")
    {
        return Err(invalid());
    }
    let suffix = match partition {
        "aws"
            if ["af-", "ap-", "ca-", "eu-", "il-", "me-", "mx-", "sa-", "us-"]
                .iter()
                .any(|prefix| region.starts_with(prefix))
                && !region.starts_with("us-gov-")
                && !region.starts_with("us-iso") =>
        {
            "amazonaws.com"
        }
        "aws-cn" if region.starts_with("cn-") => "amazonaws.com.cn",
        "aws-us-gov" if region.starts_with("us-gov-") => "amazonaws.com",
        _ => return Err(invalid()),
    };
    let id = resource.strip_prefix("key/").ok_or_else(invalid)?;
    let uuid = id.len() == 36 && uuid::Uuid::parse_str(id).is_ok();
    let multi_region = id.strip_prefix("mrk-").is_some_and(|id| {
        id.len() == 32
            && id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if !uuid && !multi_region {
        return Err(invalid());
    }
    Ok(TrustedKmsEndpoint {
        region: region.to_owned(),
        url: format!("https://kms.{region}.{suffix}"),
    })
}

fn validate_envelope(
    context: &ArtifactContext,
    envelope: &ArtifactKeyEnvelope,
    key_id: &str,
    version: u32,
) -> Result<(), ArtifactKeyError> {
    if envelope.kms_key_id != key_id
        || envelope.format_version != version
        || envelope.wrapped_key.is_empty()
        || envelope.wrapped_key.len() > MAX_WRAPPED_KEY
        || envelope.encryption_context != ownership(context)
    {
        return Err(ArtifactKeyError::InvalidEnvelope);
    }
    Ok(())
}

fn import_key(bytes: &[u8]) -> Result<ArtifactDataKey, ArtifactKeyError> {
    if bytes.len() != 32 {
        return Err(ArtifactKeyError::Authentication);
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(bytes);
    Ok(ArtifactDataKey::from_bytes(key))
}

async fn memory_crypto(
    root: Arc<Zeroizing<[u8; 32]>>,
    context: ArtifactContext,
    nonce: [u8; 12],
    mut buffer: Zeroizing<Vec<u8>>,
    encrypt: bool,
) -> Result<Zeroizing<Vec<u8>>, ArtifactKeyError> {
    tokio::task::spawn_blocking(move || {
        let mut aad = [0; DOMAIN.len() + 48];
        aad[..DOMAIN.len()].copy_from_slice(DOMAIN);
        for (slot, id) in aad[DOMAIN.len()..].as_chunks_mut::<16>().0.iter_mut().zip([
            context.tenant().0,
            context.run().0,
            context.artifact().0,
        ]) {
            slot.copy_from_slice(id.as_bytes());
        }
        let unbound = UnboundKey::new(&aead::AES_256_GCM, root.as_ref().as_ref())
            .map_err(|_| ArtifactKeyError::Authentication)?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce);
        if encrypt {
            let tag = key
                .seal_in_place_separate_tag(nonce, Aad::from(&aad), &mut buffer)
                .map_err(|_| ArtifactKeyError::Authentication)?;
            buffer.extend_from_slice(tag.as_ref());
        } else {
            let length = key
                .open_in_place(nonce, Aad::from(&aad), &mut buffer)
                .map_err(|_| ArtifactKeyError::Authentication)?
                .len();
            buffer[length..].zeroize();
            buffer.truncate(length);
        }
        Ok(buffer)
    })
    .await
    .map_err(ArtifactKeyError::Task)?
}

#[cfg(test)]
#[path = "artifact_key_crypto_tests.rs"]
mod tests;
