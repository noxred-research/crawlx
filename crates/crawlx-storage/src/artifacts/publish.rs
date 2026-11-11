//! Anonymous same-filesystem object staging with atomic, non-overwriting publication.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

/// A private inode that gains its first filesystem name only after complete publication.
///
/// Unsupported filesystems fail closed; no named plaintext staging fallback exists.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub struct AnonymousArtifactFile {
    file: File,
    directory: File,
    path: PathBuf,
}

impl AnonymousArtifactFile {
    /// Allocate a linkable anonymous file on the destination directory's filesystem.
    /// Call this blocking filesystem operation from a blocking task in asynchronous code.
    ///
    /// # Errors
    /// Returns directory, anonymous-file capability, or descriptor-opening errors.
    pub fn new_in(directory: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{open, openat, Mode, OFlags};
            use std::os::fd::AsRawFd as _;
            let directory = File::from(open(
                directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let file = File::from(openat(
                &directory,
                ".",
                OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?);
            let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
            Ok(Self {
                file,
                directory,
                path,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = directory;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "anonymous artifact publication requires Linux",
            ))
        }
    }

    /// Borrow the writable descriptor.
    #[must_use]
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Borrow the held descriptor.
    #[must_use]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Borrow a generated descriptor path while this owner remains alive.
    /// This path never grants authority to follow untrusted archive import paths.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sync approved bytes and atomically create one final name in the held directory.
    /// Existing destinations remain untouched; callers may separately prove identical retries.
    /// Call this blocking filesystem operation from a blocking task in asynchronous code.
    ///
    /// # Errors
    /// Returns sync, publication, unsupported-platform or invalid-basename errors.
    pub fn publish(self, name: &OsStr) -> io::Result<()> {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact destination must be a basename",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{linkat, AtFlags, CWD};
            self.file.sync_all()?;
            linkat(CWD, &self.path, &self.directory, name, AtFlags::SYMLINK_FOLLOW)?;
            self.directory.sync_all()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "anonymous artifact publication requires Linux",
            ))
        }
    }

    pub(super) fn publish_identical(self, name: &OsStr, size: u64) -> io::Result<()> {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let mut approved = self.file.try_clone()?;
        let directory = self.directory.try_clone()?;
        match self.publish(name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                #[cfg(target_os = "linux")]
                {
                    use rustix::fs::{openat, Mode, OFlags};
                    let mut existing = File::from(openat(
                        &directory,
                        name,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?);
                    let metadata = existing.metadata()?;
                    if !metadata.is_file() || metadata.len() != size || approved.metadata()?.len() != size {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "immutable artifact content conflict",
                        ));
                    }
                    approved.seek(SeekFrom::Start(0))?;
                    let mut remaining = size;
                    let mut left = [0u8; 32 * 1024];
                    let mut right = [0u8; 32 * 1024];
                    while remaining != 0 {
                        let count = usize::try_from(remaining.min(32 * 1024)).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "artifact comparison bound")
                        })?;
                        approved.read_exact(&mut left[..count])?;
                        existing.read_exact(&mut right[..count])?;
                        if left[..count] != right[..count] {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "immutable artifact content conflict",
                            ));
                        }
                        remaining -= u64::try_from(count).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "artifact comparison bound")
                        })?;
                    }
                    directory.sync_all()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (approved, directory, size);
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::Write as _;

    #[test]
    fn uncommitted_sensitive_bytes_never_gain_a_directory_entry() {
        let directory = tempfile::tempdir().unwrap();
        let mut staged = AnonymousArtifactFile::new_in(directory.path()).unwrap();
        staged
            .file_mut()
            .write_all(b"approved sensitive evidence")
            .unwrap();
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        drop(staged);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn publication_is_complete_and_never_replaces_an_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let mut staged = AnonymousArtifactFile::new_in(directory.path()).unwrap();
        staged
            .file_mut()
            .write_all(b"approved sensitive evidence")
            .unwrap();
        staged.publish(OsStr::new("object")).unwrap();
        let expected = std::fs::read(directory.path().join("object")).unwrap();
        assert_eq!(expected, b"approved sensitive evidence");
        let mut replacement = AnonymousArtifactFile::new_in(directory.path()).unwrap();
        replacement.file_mut().write_all(b"different bytes").unwrap();
        assert_eq!(
            replacement.publish(OsStr::new("object")).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(directory.path().join("object")).unwrap(), expected);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn immutable_artifact_retries_compare_bytes_without_changing_raw_mutable_writes() {
        use crate::artifacts::{ArtifactBlobs as _, FsBlobs};
        use bytes::Bytes;
        use crawlx_core::StoreError;
        let directory = tempfile::tempdir().unwrap();
        let blobs = FsBlobs::open(directory.path()).await.unwrap();
        let key = "content/object";
        blobs
            .put_immutable_shared(key, Bytes::from_static(b"approved"))
            .await
            .unwrap();
        blobs
            .put_immutable_shared(key, Bytes::from_static(b"approved"))
            .await
            .unwrap();
        assert!(matches!(
            blobs
                .put_immutable_shared(key, Bytes::from_static(b"different"))
                .await,
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(blobs.get(key).await.unwrap().unwrap(), b"approved");
        blobs.put(key, b"raw mutable replacement").await.unwrap();
        assert_eq!(blobs.get(key).await.unwrap().unwrap(), b"raw mutable replacement");

        let mut source = AnonymousArtifactFile::new_in(directory.path()).unwrap();
        source.file_mut().write_all(b"approved file").unwrap();
        let file_key = "sensitive/file";
        blobs
            .put_immutable_file(file_key, source.path(), 13)
            .await
            .unwrap();
        blobs
            .put_immutable_file(file_key, source.path(), 13)
            .await
            .unwrap();
        assert_eq!(blobs.get(file_key).await.unwrap().unwrap(), b"approved file");
        assert!(matches!(
            blobs.put_immutable_file(file_key, source.path(), 12).await,
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(blobs.list("").await.unwrap().len(), 2);
    }
}
