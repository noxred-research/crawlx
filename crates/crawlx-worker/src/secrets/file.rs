//! `file:///abs/path`: a file on the worker host, refused when it is world-readable.

use super::{strip_scheme, SecretError};
use async_trait::async_trait;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::CoreError;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt as _;

const MAX_SECRET_BYTES: u64 = 64 * 1024;

/// Resolves `file:///abs/path` references. The path must be absolute; on unix a file with
/// the `o+r` bit set is refused ([`SecretError::WorldReadable`]). Only regular files of
/// at most 64 KiB are accepted. Exactly one trailing newline (`\n` or `\r\n`) is dropped.
#[derive(Clone, Copy, Debug, Default)]
pub struct FileSecretResolver;

impl FileSecretResolver {
    /// Contents of the file named by `reference`.
    ///
    /// # Errors
    /// [`SecretError::UnsupportedScheme`] for another scheme, [`SecretError::Malformed`]
    /// for a relative path, [`SecretError::WorldReadable`], [`SecretError::FileUnreadable`]
    /// and [`SecretError::Empty`] when the file holds nothing but the newline.
    pub async fn lookup(&self, reference: &CredentialRef) -> Result<SecretOr<String>, SecretError> {
        let raw = strip_scheme(reference, "file")?;
        let path = Path::new(raw);
        if raw.is_empty() || !path.is_absolute() {
            return Err(SecretError::Malformed {
                scheme: "file",
                reason: "path must be absolute (file:///...)",
            });
        }
        let unreadable = |source: std::io::Error| SecretError::FileUnreadable {
            path: PathBuf::from(path),
            source,
        };
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(
            i32::try_from(rustix::fs::OFlags::NONBLOCK.bits())
                .map_err(|_| unreadable(std::io::Error::other("nonblocking open flags unavailable")))?,
        );
        // Inspect the opened descriptor, not the name: projected Secret symlinks remain
        // supported, but a name swap cannot bypass the type and permission checks.
        let file = options.open(path).await.map_err(unreadable)?;
        let meta = file.metadata().await.map_err(unreadable)?;
        if !meta.is_file() || meta.len() > MAX_SECRET_BYTES {
            return Err(unreadable(std::io::Error::other(
                "secret must be a regular file of at most 64 KiB",
            )));
        }
        refuse_world_readable(path, &meta)?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        file.take(MAX_SECRET_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(unreadable)?;
        if bytes.len() > usize::try_from(MAX_SECRET_BYTES).unwrap_or(0) {
            return Err(unreadable(std::io::Error::other("secret exceeds 64 KiB")));
        }
        let mut text = std::str::from_utf8(&bytes)
            .map_err(|_| unreadable(std::io::Error::other("secret is not UTF-8")))?
            .to_owned();
        if text.ends_with('\n') {
            text.pop();
            if text.ends_with('\r') {
                text.pop();
            }
        }
        if text.is_empty() {
            return Err(SecretError::Empty {
                reference: reference.0.clone(),
            });
        }
        Ok(SecretOr::secret(text))
    }
}

#[cfg(unix)]
fn refuse_world_readable(path: &Path, meta: &std::fs::Metadata) -> Result<(), SecretError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o004 != 0 {
        return Err(SecretError::WorldReadable {
            path: PathBuf::from(path),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn refuse_world_readable(_path: &Path, _meta: &std::fs::Metadata) -> Result<(), SecretError> {
    Ok(())
}

#[async_trait]
impl SecretResolver for FileSecretResolver {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        Ok(self.lookup(reference).await?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn write(dir: &Path, name: &str, body: &str, mode: u32) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        p
    }

    fn reference(p: &Path) -> CredentialRef {
        CredentialRef(format!("file://{}", p.display()))
    }
    #[tokio::test]
    async fn rejects_non_regular_and_oversized_secret_files() {
        let dir = tempfile::tempdir().unwrap();
        let error = FileSecretResolver
            .lookup(&reference(dir.path()))
            .await
            .err()
            .unwrap();
        assert!(matches!(error, SecretError::FileUnreadable { .. }));
        let body = "x".repeat(usize::try_from(MAX_SECRET_BYTES).unwrap() + 1);
        let path = write(dir.path(), "oversized", &body, 0o600);
        assert!(matches!(
            FileSecretResolver.lookup(&reference(&path)).await,
            Err(SecretError::FileUnreadable { .. })
        ));
    }

    #[tokio::test]
    async fn reads_private_file_and_trims_one_newline() {
        let dir = tempfile::tempdir().unwrap();
        let r = FileSecretResolver;
        let p = write(dir.path(), "cred", "alice:pw\n", 0o600);
        let v = r.resolve(&reference(&p)).await.unwrap();
        assert!(v.is_secret());
        assert_eq!(v.expose(), "alice:pw");
        let p = write(dir.path(), "crlf", "alice:pw\r\n", 0o640);
        assert_eq!(r.lookup(&reference(&p)).await.unwrap().expose(), "alice:pw");
        let p = write(dir.path(), "two", "alice:pw\n\n", 0o600);
        assert_eq!(r.lookup(&reference(&p)).await.unwrap().expose(), "alice:pw\n");
        let p = write(dir.path(), "empty", "\n", 0o600);
        assert!(matches!(
            r.lookup(&reference(&p)).await,
            Err(SecretError::Empty { .. })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_world_readable_file_without_reading_it() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "leaky", "alice:pw\n", 0o644);
        let err = FileSecretResolver.lookup(&reference(&p)).await.err().unwrap();
        assert!(matches!(&err, SecretError::WorldReadable { mode: 0o644, .. }));
        assert!(!err.to_string().contains("alice"));
        let core = CoreError::from(err).to_string();
        assert!(core.contains("world-readable") && !core.contains("alice"));
    }

    #[tokio::test]
    async fn rejects_relative_and_missing_paths() {
        let r = FileSecretResolver;
        assert!(matches!(
            r.lookup(&CredentialRef("file://relative/cred".to_owned())).await,
            Err(SecretError::Malformed { scheme: "file", .. })
        ));
        assert!(matches!(
            r.lookup(&CredentialRef("file://".to_owned())).await,
            Err(SecretError::Malformed { .. })
        ));
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("absent");
        assert!(matches!(
            r.lookup(&reference(&p)).await,
            Err(SecretError::FileUnreadable { .. })
        ));
        assert!(matches!(
            r.lookup(&CredentialRef("env://X".to_owned())).await,
            Err(SecretError::UnsupportedScheme { .. })
        ));
    }
}
