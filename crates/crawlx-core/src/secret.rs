//! Secret boundaries. `SecretOr<T>` lets credential values flow to
//! the browser without entering logs, prompts, artifacts or telemetry.

use std::fmt;

mod json;
pub use json::contains_secret_bytes;
mod redact;
pub use redact::{
    register_secret, BoundedScrubError, Redacted, Redactor, DENY_NAMES, MIN_REGISTERED_SECRET_LEN, REDACTED,
};
mod stream;
pub use stream::{SecretByteScanner, SecretScanError, SecretScanLimits, SecretScanMode};

/// Either a plain value or a secret that must never be displayed.
#[derive(Clone)]
pub enum SecretOr<T: zeroize::Zeroize + Clone> {
    /// Non-sensitive value that may be displayed and serialized as is.
    Plain(T),
    /// Sensitive value: zeroized on drop, redacted in `Debug` and serialization.
    Secret(zeroize::Zeroizing<T>),
}

impl<T: zeroize::Zeroize + Clone> SecretOr<T> {
    /// Wrap a secret value; it is zeroized on drop.
    #[must_use]
    pub fn secret(value: T) -> Self {
        Self::Secret(zeroize::Zeroizing::new(value))
    }

    /// True when the value is secret.
    #[must_use]
    pub const fn is_secret(&self) -> bool {
        matches!(self, Self::Secret(_))
    }

    /// Expose the value for use at the browser boundary only.
    #[must_use]
    pub fn expose(&self) -> &T {
        match self {
            Self::Plain(v) => v,
            Self::Secret(s) => s,
        }
    }
    /// The value if it is not secret, `None` for a secret.
    #[must_use]
    pub const fn plain(&self) -> Option<&T> {
        match self {
            Self::Plain(v) => Some(v),
            Self::Secret(_) => None,
        }
    }
}

impl<T: zeroize::Zeroize + Clone> fmt::Debug for SecretOr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(_) => f.write_str("SecretOr::Plain(..)"),
            Self::Secret(_) => f.write_str("SecretOr::Secret([REDACTED])"),
        }
    }
}

impl<T: zeroize::Zeroize + Clone + serde::Serialize> serde::Serialize for SecretOr<T> {
    /// Secrets serialize as the literal string `[REDACTED]`; plain values as themselves.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Plain(v) => v.serialize(s),
            Self::Secret(_) => s.serialize_str("[REDACTED]"),
        }
    }
}

/// A reference to a credential (`vault://...`), never the value.
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Debug)]
#[serde(transparent)]
pub struct CredentialRef(pub String);

impl CredentialRef {
    /// Scheme of the reference (`vault`, `env`, `k8s`, ...).
    #[must_use]
    pub fn scheme(&self) -> Option<&str> {
        self.0.split_once("://").map(|(s, _)| s)
    }
}

/// Resolves a credential reference immediately before use.
#[async_trait::async_trait]
pub trait SecretResolver: Send + Sync {
    /// Look up the value behind `reference`.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::CoreError`] if the reference cannot be resolved.
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, crate::error::CoreError>;
}

pub(crate) mod private {
    pub trait Sealed {}

    impl Sealed for super::Redacted<String> {}
    impl Sealed for super::Redacted<Vec<u8>> {}
    impl<T: super::SecretFree + ?Sized> Sealed for &T {}
    impl<T: super::SecretFree + ?Sized> Sealed for Box<T> {}
    impl<T: super::SecretFree + ?Sized> Sealed for std::sync::Arc<T> {}
}

/// Sealed marker for immutable output of the shared redactor or core AEAD sealing.
///
/// Raw containers, typed secrets and caller-defined wrappers cannot cross the
/// artifact sink. Redaction approval cannot be deserialized or mutated.
///
/// ```compile_fail
/// use crawlx_core::secret::{SecretFree, SecretOr};
/// struct WrappedSecret(SecretOr<String>);
/// impl SecretFree for WrappedSecret {}
/// ```
///
/// Raw strings are not approved:
/// ```compile_fail
/// use crawlx_core::secret::SecretFree;
/// fn approved<T: SecretFree + ?Sized>(_: &T) {}
/// approved(&String::from("raw-secret"));
/// ```
///
/// Neither are raw byte vectors:
/// ```compile_fail
/// use crawlx_core::secret::SecretFree;
/// fn approved<T: SecretFree + ?Sized>(_: &T) {}
/// approved(&b"raw-secret".to_vec());
/// ```
///
/// Nor borrowed byte slices:
/// ```compile_fail
/// use crawlx_core::secret::SecretFree;
/// fn approved<T: SecretFree + ?Sized>(_: &T) {}
/// approved(&b"raw-secret"[..]);
/// ```
///
/// Nor borrowed strings:
/// ```compile_fail
/// use crawlx_core::secret::SecretFree;
/// fn approved<T: SecretFree + ?Sized>(_: &T) {}
/// approved("raw-secret");
/// ```
pub trait SecretFree: private::Sealed {
    /// Check retention classification before sending approved bytes to a storage backend.
    ///
    /// # Errors
    /// Returns retention denial when a sealed credential payload is downgraded.
    fn check_class(&self, _class: crate::repo::Sensitivity) -> Result<(), crate::StoreError> {
        Ok(())
    }
}

impl SecretFree for Redacted<String> {}
impl SecretFree for Redacted<Vec<u8>> {}
impl<T: SecretFree + ?Sized> SecretFree for &T {
    fn check_class(&self, class: crate::repo::Sensitivity) -> Result<(), crate::StoreError> {
        (**self).check_class(class)
    }
}
impl<T: SecretFree + ?Sized> SecretFree for Box<T> {
    fn check_class(&self, class: crate::repo::Sensitivity) -> Result<(), crate::StoreError> {
        (**self).check_class(class)
    }
}
impl<T: SecretFree + ?Sized> SecretFree for std::sync::Arc<T> {
    fn check_class(&self, class: crate::repo::Sensitivity) -> Result<(), crate::StoreError> {
        (**self).check_class(class)
    }
}

/// Typed write side of an [`ArtifactStore`](crate::repo::ArtifactStore): `put`
/// accepts only [`SecretFree`] payloads. The store itself takes raw bytes; this
/// wrapper is the boundary callers that hold typed values must cross.
#[derive(Clone, Copy)]
pub struct ArtifactSink<'s> {
    store: &'s dyn crate::repo::ArtifactStore,
}

impl fmt::Debug for ArtifactSink<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArtifactSink(..)")
    }
}

impl<'s> ArtifactSink<'s> {
    /// A sink over `store`.
    #[must_use]
    pub const fn over(store: &'s dyn crate::repo::ArtifactStore) -> Self {
        Self { store }
    }

    /// Store `body` for `run` under `class` (see [`ArtifactStore::put`](crate::repo::ArtifactStore::put)).
    ///
    /// # Errors
    /// Whatever the underlying store returns.
    pub async fn put<B>(
        &self,
        run: crate::ids::CrawlRunId,
        class: crate::repo::Sensitivity,
        content_type: &str,
        body: &B,
    ) -> Result<crate::ids::ArtifactRef, crate::error::StoreError>
    where
        B: SecretFree + AsRef<[u8]> + ?Sized,
    {
        body.check_class(class)?;
        self.store.put(run, class, content_type, body.as_ref()).await
    }

    /// Store an approved payload without extending its source deadline.
    ///
    /// # Errors
    /// Returns unsupported, expired, quota or backend errors from the artifact store.
    pub async fn put_until<B>(
        &self,
        run: crate::CrawlRunId,
        class: crate::repo::Sensitivity,
        content_type: &str,
        body: &B,
        expires_at: crate::Timestamp,
    ) -> Result<crate::ArtifactRef, crate::StoreError>
    where
        B: SecretFree + AsRef<[u8]> + ?Sized,
    {
        body.check_class(class)?;
        self.store
            .put_until(run, class, content_type, body.as_ref(), expires_at)
            .await
    }

    /// Store a rendition of `page`, preserving the store's zero-data-retention routing.
    ///
    /// ```compile_fail
    /// use crawlx_core::{CrawlRunId, repo::{ArtifactStore, Sensitivity}, secret::{ArtifactSink, SecretOr}};
    /// async fn write(store: &dyn ArtifactStore, run: CrawlRunId, value: SecretOr<String>) {
    ///     ArtifactSink::over(store).
    /// put_page(run, 1, Sensitivity::Content, "text/plain", &value).await;
    /// }
    /// ```
    ///
    /// # Errors
    /// Whatever [`ArtifactStore::put_page`](crate::repo::ArtifactStore::put_page) returns.
    pub async fn put_page<B>(
        &self,
        run: crate::ids::CrawlRunId,
        page: i64,
        class: crate::repo::Sensitivity,
        content_type: &str,
        body: &B,
    ) -> Result<crate::ids::ArtifactRef, crate::error::StoreError>
    where
        B: SecretFree + AsRef<[u8]> + ?Sized,
    {
        body.check_class(class)?;
        self.store
            .put_page(run, page, class, content_type, body.as_ref())
            .await
    }

    /// Store a named dataset rendition through the same compile-time secret exclusion boundary.
    ///
    /// # Errors
    /// Returns retention, quota or backend errors from the artifact store.
    pub async fn put_dataset<B>(
        &self,
        run: crate::ids::CrawlRunId,
        page: i64,
        rendition: &str,
        content_type: &str,
        body: &B,
    ) -> Result<crate::ids::ArtifactRef, crate::error::StoreError>
    where
        B: SecretFree + AsRef<[u8]> + ?Sized,
    {
        body.check_class(crate::repo::Sensitivity::Content)?;
        self.store
            .put_dataset(run, page, rendition, content_type, body.as_ref())
            .await
    }
    /// Store a named approved rendition without extending its source deadline.
    ///
    /// # Errors
    /// Returns unsupported, expired, quota or backend errors.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_dataset_until<B>(
        &self,
        run: crate::CrawlRunId,
        page: i64,
        rendition: &str,
        content_type: &str,
        body: &B,
        deadline: crate::Timestamp,
    ) -> Result<crate::ArtifactRef, crate::StoreError>
    where
        B: SecretFree + AsRef<[u8]> + ?Sized,
    {
        body.check_class(crate::repo::Sensitivity::Content)?;
        self.store
            .put_dataset_until(run, page, rendition, content_type, body.as_ref(), deadline)
            .await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn secret_never_prints() {
        let s = SecretOr::secret("hunter2".to_owned());
        assert!(!format!("{s:?}").contains("hunter2"));
        assert_eq!(serde_json::to_string(&s).ok().as_deref(), Some("\"[REDACTED]\""));
        assert_eq!(s.expose(), "hunter2");
        let p = SecretOr::Plain("x".to_owned());
        assert_eq!(serde_json::to_string(&p).ok().as_deref(), Some("\"x\""));
        assert!(!format!("{p:?}").contains("\"x\""));
        let bytes = SecretOr::secret(b"typed-secret-byte-canary".to_vec());
        assert_eq!(format!("{bytes:?}"), "SecretOr::Secret([REDACTED])");
    }
}

/// Startup errors for the operator-provisioned request identity key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RequestIdentityKeyError {
    /// Both input forms were set; no precedence can silently select a different identity.
    #[error("request identity key requires exactly one of CRAWLX_REQUEST_IDENTITY_KEY and CRAWLX_REQUEST_IDENTITY_KEY_FILE")]
    Ambiguous,
    /// The configured file could not be opened, inspected or read.
    #[error("request identity key file is unavailable")]
    File(#[source] std::io::Error),
    /// The opened descriptor does not name a regular, non-writable-by-others file.
    #[error("request identity key file must be regular and not group- or world-writable")]
    UnsafeFile,
    /// The key is not exactly 32 bytes encoded as hexadecimal text.
    #[error("request identity key requires exactly 64 hexadecimal characters")]
    Invalid,
}

/// Load the shared API/worker request identity key without exposing its value.
///
/// An absent key disables identity-dependent features. Inline and file inputs are mutually
/// exclusive, including empty inputs. Files accept exactly 64 hexadecimal characters with
/// at most one final LF. Symlinks support Kubernetes projected secrets; security checks use
/// the opened descriptor, never a separate path lookup. No key is generated automatically.
///
/// # Errors
/// Rejects ambiguous, unreadable, non-regular, writable-by-others or malformed inputs.
pub fn request_identity_key_from_lookup(
    getenv: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<SecretOr<[u8; 32]>>, RequestIdentityKeyError> {
    use std::io::Read as _;
    let inline = getenv("CRAWLX_REQUEST_IDENTITY_KEY").map(SecretOr::secret);
    let file = getenv("CRAWLX_REQUEST_IDENTITY_KEY_FILE");
    let value = match (inline, file) {
        (Some(_), Some(_)) => return Err(RequestIdentityKeyError::Ambiguous),
        (None, None) => return Ok(None),
        (Some(value), None) => value,
        (None, Some(path)) => {
            let descriptor = rustix::fs::open(
                path.as_str(),
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| RequestIdentityKeyError::File(std::io::Error::from(error)))?;
            let mut file = std::fs::File::from(descriptor);
            let metadata = file.metadata().map_err(RequestIdentityKeyError::File)?;
            if !metadata.is_file() {
                return Err(RequestIdentityKeyError::UnsafeFile);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if metadata.permissions().mode() & 0o022 != 0 {
                    return Err(RequestIdentityKeyError::UnsafeFile);
                }
            }
            let mut bytes = zeroize::Zeroizing::new([0_u8; 66]);
            let mut count = 0;
            while count < bytes.len() {
                let read = file
                    .read(&mut bytes[count..])
                    .map_err(RequestIdentityKeyError::File)?;
                if read == 0 {
                    break;
                }
                count += read;
            }
            if count == 65 && bytes[64] == b'\n' {
                count = 64;
            }
            if count != 64 {
                return Err(RequestIdentityKeyError::Invalid);
            }
            let text = std::str::from_utf8(&bytes[..count]).map_err(|_| RequestIdentityKeyError::Invalid)?;
            SecretOr::secret(text.to_owned())
        }
    };
    let decoded =
        crate::hash::Digest::from_hex(value.expose()).map_err(|_| RequestIdentityKeyError::Invalid)?;
    Ok(Some(SecretOr::secret(decoded.0)))
}

#[cfg(test)]
mod request_identity_key_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn absent_inline_and_ambiguous_inputs_have_no_fallback() {
        assert!(request_identity_key_from_lookup(&|_| None).unwrap().is_none());
        let key = "7a".repeat(32);
        let loaded = request_identity_key_from_lookup(&|name| {
            (name == "CRAWLX_REQUEST_IDENTITY_KEY").then(|| key.clone())
        })
        .unwrap()
        .unwrap();
        assert_eq!(loaded.expose(), &[0x7a; 32]);
        assert!(!format!("{loaded:?}").contains(&key));
        assert!(matches!(
            request_identity_key_from_lookup(&|_| Some(String::new())),
            Err(RequestIdentityKeyError::Ambiguous)
        ));
        for invalid in ["", "ab", &"g".repeat(64), &format!("{key}\n")] {
            assert!(matches!(
                request_identity_key_from_lookup(&|name| {
                    (name == "CRAWLX_REQUEST_IDENTITY_KEY").then(|| invalid.to_owned())
                }),
                Err(RequestIdentityKeyError::Invalid)
            ));
        }
    }

    #[test]
    fn file_input_is_bounded_and_errors_are_redacted() {
        let path = std::env::temp_dir().join(format!("crawlx-identity-key-{}", uuid::Uuid::now_v7()));
        let lookup = |name: &str| {
            (name == "CRAWLX_REQUEST_IDENTITY_KEY_FILE").then(|| path.to_string_lossy().into_owned())
        };
        for suffix in ["", "\n"] {
            std::fs::write(&path, format!("{}{suffix}", "19".repeat(32))).unwrap();
            assert_eq!(
                request_identity_key_from_lookup(&lookup)
                    .unwrap()
                    .unwrap()
                    .expose(),
                &[0x19; 32]
            );
        }
        for invalid in ["ab".repeat(33), "invalid-secret-canary".repeat(100)] {
            std::fs::write(&path, invalid).unwrap();
            let error = request_identity_key_from_lookup(&lookup).unwrap_err();
            assert!(matches!(error, RequestIdentityKeyError::Invalid));
            assert!(!format!("{error:?}").contains("canary"));
        }
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            request_identity_key_from_lookup(&lookup),
            Err(RequestIdentityKeyError::File(_))
        ));
    }

    #[test]
    fn fifo_input_is_refused_without_waiting_for_a_writer() {
        let path = std::env::temp_dir().join(format!("crawlx-identity-fifo-{}", uuid::Uuid::now_v7()));
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        let result = request_identity_key_from_lookup(&|name| {
            (name == "CRAWLX_REQUEST_IDENTITY_KEY_FILE").then(|| path.to_string_lossy().into_owned())
        });
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(result, Err(RequestIdentityKeyError::UnsafeFile)));
    }
}
