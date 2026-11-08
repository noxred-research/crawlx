//! Operator attestation: private-network records additionally need an operator
//! attestation, a signed statement by a configured operator key
//! (see `docs/design/safety-model.md`).
//!
//! An operator holds one or more named secret keys ([`OperatorKeys`], `CRAWLX_AUTHZ_OPERATOR_KEYS_FILE`).
//! The attestation of a record is `HMAC-SHA256(key, domain || signing_digest)` over
//! [`AuthorizationRecord::signing_digest`], carried in the record as
//! [`OwnershipProof::OperatorSignature`]. Editing any field of the record after signing breaks
//! the signature. The check is offline: no DNS, no HTTP.

use crate::authorization::{AuthorizationRecord, OwnershipProof};
use crate::error::PolicyError;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;

/// Domain separation of the attestation MAC.
const DOMAIN: &[u8] = b"crawlx/authorization-attestation/v1\0";

/// Shortest operator key accepted, in bytes.
pub const MIN_KEY_BYTES: usize = 16;

/// Why an operator signature did not verify (or could not be made).
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// The record does not carry an operator signature.
    #[error("record has no operator signature")]
    NotSigned,
    /// The record names a key the deployment does not hold.
    #[error("unknown operator key {0:?}")]
    UnknownKey(String),
    /// The signature does not match the record body under the named key.
    #[error("operator signature does not match the record")]
    Mismatch,
    /// The signature field is not lowercase hex.
    #[error("operator signature is not hex")]
    NotHex,
    /// The keys file is malformed.
    #[error("operator keys: {0}")]
    Keys(String),
    /// The record body could not be digested.
    #[error("{0}")]
    Digest(String),
}

impl From<PolicyError> for AttestationError {
    fn from(e: PolicyError) -> Self {
        Self::Digest(e.to_string())
    }
}

/// The operator keys of a deployment, by key id.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OperatorKeys {
    keys: BTreeMap<String, Vec<u8>>,
}

impl std::fmt::Debug for OperatorKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // never print key material
        f.debug_struct("OperatorKeys")
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl OperatorKeys {
    /// No keys: no operator signature verifies.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key.
    ///
    /// # Errors
    /// [`AttestationError::Keys`] when the id is empty or the key is shorter than [`MIN_KEY_BYTES`].
    pub fn insert(&mut self, key_id: &str, key: Vec<u8>) -> Result<(), AttestationError> {
        if key_id.trim().is_empty() || key_id.contains(char::is_whitespace) {
            return Err(AttestationError::Keys(
                "key id must be one non-empty word".to_owned(),
            ));
        }
        if key.len() < MIN_KEY_BYTES {
            return Err(AttestationError::Keys(format!(
                "key {key_id:?} is shorter than {MIN_KEY_BYTES} bytes"
            )));
        }
        self.keys.insert(key_id.to_owned(), key);
        Ok(())
    }

    /// Parse a keys file: one `key_id hex-key` pair per line (`#` starts a comment).
    ///
    /// # Errors
    /// [`AttestationError::Keys`] naming the offending line.
    pub fn parse(text: &str) -> Result<Self, AttestationError> {
        let mut keys = Self::new();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (id, hex_key) = line.split_once(char::is_whitespace).ok_or_else(|| {
                AttestationError::Keys(format!("line {}: expected `key_id hex-key`", n + 1))
            })?;
            let bytes = hex::decode(hex_key.trim())
                .map_err(|_| AttestationError::Keys(format!("line {}: key is not hex", n + 1)))?;
            keys.insert(id, bytes)?;
        }
        Ok(keys)
    }

    /// Are there no keys?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn mac(&self, key_id: &str, record: &AuthorizationRecord) -> Result<Hmac<Sha256>, AttestationError> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| AttestationError::UnknownKey(key_id.to_owned()))?;
        let digest = record.signing_digest()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|e| AttestationError::Keys(format!("key {key_id:?}: {e}")))?;
        mac.update(DOMAIN);
        mac.update(&digest.0);
        Ok(mac)
    }

    /// Sign `record` with key `key_id`: the value for [`OwnershipProof::OperatorSignature::signature`].
    /// The record's own `ownership` must already name this key (the key id is part of the signed
    /// digest).
    ///
    /// # Errors
    /// [`AttestationError::UnknownKey`] or [`AttestationError::Digest`].
    pub fn sign(&self, key_id: &str, record: &AuthorizationRecord) -> Result<String, AttestationError> {
        Ok(hex::encode(self.mac(key_id, record)?.finalize().into_bytes()))
    }

    /// Verify the operator signature carried by `record`.
    ///
    /// # Errors
    /// [`AttestationError`] naming why the signature does not hold.
    pub fn verify(&self, record: &AuthorizationRecord) -> Result<(), AttestationError> {
        let Some(OwnershipProof::OperatorSignature { key_id, signature }) = &record.ownership else {
            return Err(AttestationError::NotSigned);
        };
        let given = hex::decode(signature).map_err(|_| AttestationError::NotHex)?;
        self.mac(key_id, record)?
            .verify_slice(&given)
            .map_err(|_| AttestationError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::authorization::tests::record;

    fn keys() -> OperatorKeys {
        OperatorKeys::parse("# operator keys\nops-1 00112233445566778899aabbccddeeff\nops-2 ffeeddccbbaa99887766554433221100\n")
            .unwrap()
    }

    fn signed(key_id: &str) -> AuthorizationRecord {
        let mut r = record();
        r.ownership = Some(OwnershipProof::OperatorSignature {
            key_id: key_id.to_owned(),
            signature: String::new(),
        });
        let sig = keys().sign(key_id, &r).unwrap();
        r.ownership = Some(OwnershipProof::OperatorSignature {
            key_id: key_id.to_owned(),
            signature: sig,
        });
        r
    }

    #[test]
    fn signature_verifies_and_breaks_on_any_edit() {
        let r = signed("ops-1");
        assert_eq!(keys().verify(&r), Ok(()));
        let mut edited = r.clone();
        edited.origins.push("https://other.example.test".to_owned());
        assert_eq!(keys().verify(&edited), Err(AttestationError::Mismatch));
        let mut edited = r.clone();
        edited.authorizer.name = "Mallory".to_owned();
        assert_eq!(keys().verify(&edited), Err(AttestationError::Mismatch));
        // lifecycle state is not part of the statement
        let mut revoked = r;
        revoked.revoked_at = Some(crate::authorization::tests::ts(22));
        assert_eq!(keys().verify(&revoked), Ok(()));
    }

    #[test]
    fn wrong_key_unknown_key_and_unsigned_are_distinguished() {
        let r = signed("ops-1");
        let mut swapped = r.clone();
        if let Some(OwnershipProof::OperatorSignature { key_id, .. }) = &mut swapped.ownership {
            *key_id = "ops-2".to_owned();
        }
        assert_eq!(keys().verify(&swapped), Err(AttestationError::Mismatch));
        let mut unknown = r.clone();
        if let Some(OwnershipProof::OperatorSignature { key_id, .. }) = &mut unknown.ownership {
            *key_id = "ops-9".to_owned();
        }
        assert_eq!(
            keys().verify(&unknown),
            Err(AttestationError::UnknownKey("ops-9".to_owned()))
        );
        assert_eq!(keys().verify(&record()), Err(AttestationError::NotSigned));
        let mut not_hex = r;
        if let Some(OwnershipProof::OperatorSignature { signature, .. }) = &mut not_hex.ownership {
            *signature = "zz".to_owned();
        }
        assert_eq!(keys().verify(&not_hex), Err(AttestationError::NotHex));
        assert_eq!(
            OperatorKeys::new().verify(&signed("ops-1")),
            Err(AttestationError::UnknownKey("ops-1".to_owned()))
        );
    }

    #[test]
    fn keys_file_is_validated_and_never_printed() {
        assert!(OperatorKeys::parse("only-an-id\n").is_err());
        assert!(OperatorKeys::parse("k nothex\n").is_err());
        assert!(OperatorKeys::parse("k 0011\n").is_err(), "short key");
        let k = keys();
        let shown = format!("{k:?}");
        assert!(shown.contains("ops-1") && !shown.contains("00112233"), "{shown}");
        assert!(OperatorKeys::parse("# nothing\n\n").unwrap().is_empty());
    }
}
