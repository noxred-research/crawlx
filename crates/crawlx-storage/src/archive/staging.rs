//! Anonymous archive sources. Descriptor paths are generated here, never from archive input.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// An unlinked archive spool whose descriptor stays alive through publication.
///
/// The path is only for trusted, internal path-based writers and artifact storage.
/// It must never be used to grant magic-link access to untrusted archive imports.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub struct StagedFile {
    file: File,
    path: PathBuf,
}

impl StagedFile {
    /// Create an anonymous spool without writing bytes to any named temporary file.
    ///
    /// # Errors
    /// Returns storage errors, or fails closed when descriptor paths are unsupported.
    pub fn new() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;
            let file = tempfile::tempfile()?;
            let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
            // Require the internal descriptor bridge before accepting sensitive bytes.
            File::open(&path)?;
            Ok(Self { file, path })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "anonymous archive staging requires descriptor paths",
            ))
        }
    }

    /// Borrow the held writable descriptor.
    #[must_use]
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Borrow the held descriptor.
    #[must_use]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Borrow the internally generated descriptor path while this owner remains alive.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open an independent reader starting at offset zero, without sharing seek position.
    ///
    /// # Errors
    /// Returns descriptor-opening errors.
    pub fn reader(&self) -> io::Result<File> {
        File::open(&self.path)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::{Read as _, Seek as _, Write as _};
    use std::os::unix::fs::MetadataExt as _;

    #[test]
    fn unlinked_source_holds_exact_bytes_and_independent_reader_until_drop() {
        let mut staged = StagedFile::new().unwrap();
        staged.file_mut().write_all(b"archive\0bytes\xff").unwrap();
        assert_eq!(staged.file().metadata().unwrap().nlink(), 0);
        let position = staged.file_mut().stream_position().unwrap();
        let mut bytes = Vec::new();
        staged.reader().unwrap().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"archive\0bytes\xff");
        assert_eq!(staged.file_mut().stream_position().unwrap(), position);
        let path = staged.path().to_owned();
        let mut reader = staged.reader().unwrap();
        drop(staged);
        // The descriptor number may be reused by another thread once the owner drops, so the
        // path must no longer resolve to the staged inode rather than to nothing at all.
        let staged_inode = reader.metadata().unwrap().ino();
        assert!(!std::fs::metadata(&path).is_ok_and(|meta| meta.ino() == staged_inode));
        bytes.clear();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"archive\0bytes\xff");
        assert_eq!(reader.metadata().unwrap().nlink(), 0);
    }
}
