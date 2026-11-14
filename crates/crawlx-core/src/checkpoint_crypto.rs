//! Checkpoint AEAD primitive and immutable, encryption-produced artifact bytes.
//!
//! Custody providers supply keys and ownership AAD; only successful AES-256-GCM
//! encryption can construct [`Ciphertext`]. Fetched envelopes remain raw bytes.

use crate::secret::{private, Redactor, SecretFree};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize as _, Zeroizing};

/// Checkpoint envelope signature.
pub const MAGIC: &[u8; 4] = b"CXCP";
/// Checkpoint envelope version.
pub const VERSION: u8 = 1;
/// Process-local key custody provider identifier.
pub const MEMORY: u8 = 1;
/// KMS-wrapped data-key custody provider identifier.
pub const KMS: u8 = 2;
/// Local key-encryption-key file wrapped data-key custody provider identifier.
pub const FILE: u8 = 3;
/// AES-GCM nonce length.
pub const NONCE_BYTES: usize = 12;
/// AES-GCM authentication tag length.
pub const TAG_BYTES: usize = 16;
/// Fixed envelope prefix length, excluding any wrapped key.
pub const HEADER_BYTES: usize = 4 + 1 + 1 + 4 + NONCE_BYTES;
/// Maximum checkpoint plaintext length.
pub const MAX_PLAINTEXT: usize = 32 * 1024 * 1024;
/// Maximum wrapped data-key length.
pub const MAX_WRAPPED_KEY: usize = 64 * 1024;
/// Maximum complete checkpoint envelope length.
pub const MAX_ENVELOPE: usize = HEADER_BYTES + MAX_WRAPPED_KEY + MAX_PLAINTEXT + TAG_BYTES;

/// Immutable checkpoint envelope constructed only by successful AEAD encryption.
///
/// No byte constructor, deserializer or mutable access can assert this boundary.
/// Reading or copying the bytes does not confer approval on the resulting bytes.
///
/// ```compile_fail
/// use crawlx_core::checkpoint_crypto::Ciphertext;
/// let forged = Ciphertext(vec![1, 2, 3]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub struct Ciphertext(Vec<u8>);

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl private::Sealed for Ciphertext {}
impl SecretFree for Ciphertext {
    fn check_class(&self, class: crate::repo::Sensitivity) -> Result<(), crate::StoreError> {
        if class != crate::repo::Sensitivity::CredentialBearing {
            return Err(crate::StoreError::RetentionDenied(
                "checkpoint ciphertext cannot change sensitivity".into(),
            ));
        }
        Ok(())
    }
}

/// Fail-closed primitive errors, translated by the key-custody provider.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CiphertextError {
    /// Unknown provider, invalid wrapped-key shape or unapproved wrapped-key bytes.
    #[error("checkpoint encryption envelope invalid")]
    InvalidEnvelope,
    /// Plaintext, wrapped key or envelope exceeded its fixed bound.
    #[error("checkpoint encryption size limit exceeded")]
    LimitExceeded,
    /// Invalid key, AEAD failure or authentication mismatch.
    #[error("checkpoint authentication failed")]
    Authentication,
    /// OS cryptographic entropy was unavailable.
    #[error("checkpoint encryption entropy unavailable")]
    Entropy {
        /// Cryptographic entropy failure, without secret data.
        #[source]
        source: ring::error::Unspecified,
    },
}

/// Encrypt and assemble the complete existing `CXCP` checkpoint envelope.
///
/// `wrapped` is the provider's wrapped-key blob (KMS ciphertext or local-KEK wrap), never a plaintext data key. Its bytes
/// must pass the shared binary secret policy unchanged before being serialized.
/// Ownership AAD is supplied by the custody provider and is not serialized in
/// the envelope. A fresh nonce is generated internally for every encryption.
///
/// # Errors
/// Rejects unknown providers, invalid or secret-bearing wrapped keys, bounds,
/// entropy and AEAD failures.
pub fn seal(
    provider: u8,
    key: &[u8],
    wrapped: &[u8],
    mut plaintext: Zeroizing<Vec<u8>>,
    aad: &[u8],
) -> Result<Ciphertext, CiphertextError> {
    if plaintext.len() > MAX_PLAINTEXT || wrapped.len() > MAX_WRAPPED_KEY {
        return Err(CiphertextError::LimitExceeded);
    }
    if !matches!(provider, MEMORY | KMS | FILE)
        || (provider == MEMORY && !wrapped.is_empty())
        || (provider != MEMORY && wrapped.is_empty())
    {
        return Err(CiphertextError::InvalidEnvelope);
    }
    // Wrapped-key bytes are caller supplied and serialized verbatim, unlike the
    // encrypted payload. They must cross the real binary policy boundary too.
    Redactor::new()
        .check_binary(wrapped)
        .map_err(|_| CiphertextError::InvalidEnvelope)?;
    let mut nonce = [0; NONCE_BYTES];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|source| CiphertextError::Entropy { source })?;
    let tag = aead_key(key)?
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut plaintext,
        )
        .map_err(|_| CiphertextError::Authentication)?;
    // Grow only after encryption, so any allocator relocation copies ciphertext, not secrets.
    let prefix = HEADER_BYTES + wrapped.len();
    let encrypted_len = plaintext.len();
    plaintext.resize(prefix + encrypted_len + TAG_BYTES, 0);
    plaintext.copy_within(..encrypted_len, prefix);
    plaintext[..4].copy_from_slice(MAGIC);
    plaintext[4..6].copy_from_slice(&[VERSION, provider]);
    plaintext[6..10].copy_from_slice(
        &u32::try_from(wrapped.len())
            .map_err(|_| CiphertextError::LimitExceeded)?
            .to_be_bytes(),
    );
    plaintext[10..HEADER_BYTES].copy_from_slice(&nonce);
    plaintext[HEADER_BYTES..prefix].copy_from_slice(wrapped);
    plaintext[prefix + encrypted_len..].copy_from_slice(tag.as_ref());
    Ok(Ciphertext(std::mem::take(&mut *plaintext)))
}

/// Authenticate and decrypt a parsed checkpoint envelope in its owned buffer.
///
/// The custody provider validates the envelope header and supplies its nonce,
/// encrypted-body offset and ownership AAD. Plaintext is zeroized on failure.
///
/// # Errors
/// Rejects out-of-bounds envelopes, invalid keys and failed AEAD authentication.
pub fn open(
    key: &[u8],
    nonce: [u8; NONCE_BYTES],
    encrypted_start: usize,
    mut plaintext: Zeroizing<Vec<u8>>,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CiphertextError> {
    if plaintext.len() > MAX_ENVELOPE {
        return Err(CiphertextError::LimitExceeded);
    }
    let encrypted = plaintext
        .get(encrypted_start..)
        .ok_or(CiphertextError::InvalidEnvelope)?;
    if encrypted.len() < TAG_BYTES {
        return Err(CiphertextError::InvalidEnvelope);
    }
    if encrypted.len() - TAG_BYTES > MAX_PLAINTEXT {
        return Err(CiphertextError::LimitExceeded);
    }
    let len = aead_key(key)?
        .open_within(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut plaintext,
            encrypted_start..,
        )
        .map_err(|_| CiphertextError::Authentication)?
        .len();
    // `open_within` may leave plaintext beyond its returned slice; erase before truncating.
    plaintext[len..].zeroize();
    plaintext.truncate(len);
    Ok(plaintext)
}

fn aead_key(key: &[u8]) -> Result<LessSafeKey, CiphertextError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| CiphertextError::Authentication)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::secret::register_secret;

    #[test]
    fn wrapped_key_cannot_smuggle_registered_or_credential_plaintext() {
        let canary = "checkpoint-wrapped-prefix-canary-5f9c";
        assert!(register_secret(canary));
        for wrapped in [
            canary.as_bytes(),
            b"\xffpassword=unknown-wrapped-secret\0".as_slice(),
            b"\xffauthorization: Bearer wrapped-key-token\0".as_slice(),
        ] {
            assert!(matches!(
                seal(KMS, &[7; 32], wrapped, Zeroizing::new(vec![0]), b"ownership"),
                Err(CiphertextError::InvalidEnvelope)
            ));
        }
    }

    #[test]
    fn opaque_wrapped_key_is_preserved_and_payload_remains_authenticated() {
        let wrapped = b"\xff\0\x93\x81\x07\x02";
        let plaintext = b"private checkpoint payload";
        let ciphertext = seal(
            KMS,
            &[7; 32],
            wrapped,
            Zeroizing::new(plaintext.to_vec()),
            b"ownership",
        )
        .unwrap();
        let _: &dyn SecretFree = &ciphertext;
        let bytes = ciphertext.as_ref();
        assert_eq!(&bytes[..4], MAGIC);
        assert_eq!(&bytes[4..6], &[VERSION, KMS]);
        assert_eq!(&bytes[6..10], &6_u32.to_be_bytes());
        assert_eq!(&bytes[HEADER_BYTES..HEADER_BYTES + wrapped.len()], wrapped);
        let nonce = bytes[10..HEADER_BYTES].try_into().unwrap();
        assert_eq!(
            open(
                &[7; 32],
                nonce,
                HEADER_BYTES + wrapped.len(),
                Zeroizing::new(bytes.to_vec()),
                b"ownership",
            )
            .unwrap()
            .as_slice(),
            plaintext
        );
    }
}
