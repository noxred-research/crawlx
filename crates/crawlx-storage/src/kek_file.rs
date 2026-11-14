//! Operator-provisioned local key-encryption-key (KEK) file for self-hosted key custody.
//!
//! The file holds one KEK per line as `<key-id>:<64 hexadecimal characters>` (32 bytes).
//! Blank lines and lines starting with `#` are ignored. The **first** key is the primary:
//! every new wrap uses it. Every listed key can still unwrap, so rotation is: add a new key
//! on top, re-wrap what must outlive the old key, then delete the old line. Key ids are
//! non-secret labels (`A-Z a-z 0-9 . _ -`, at most [`MAX_KEY_ID_BYTES`] bytes), stored next to
//! each wrapped data key so the right KEK is found at unwrap time.
//!
//! The file is read through its opened descriptor and refused unless it is a regular file with
//! no group or other permission bits (mode `0600` or `0400`). Symlinks (projected secrets)
//! are followed. Nothing is generated: a missing, unreadable, oversized, empty or malformed
//! file, a repeated key id or a key that is not exactly 32 bytes fails closed. Key bytes and
//! the file buffer are zeroized on drop and never formatted.

use std::{fmt, io::Read as _, path::Path};
use zeroize::Zeroizing;

/// Longest key id, in bytes.
pub const MAX_KEY_ID_BYTES: usize = 64;
/// Most keys one file may hold.
pub const MAX_KEYS: usize = 64;
/// Largest accepted file, in bytes.
const MAX_FILE_BYTES: usize = 64 * 1024;

/// Startup failures while loading a KEK file. Messages never include key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KekFileError {
    /// The file could not be opened, inspected or read.
    #[error("key-encryption-key file is unavailable")]
    File(#[source] std::io::Error),
    /// The opened descriptor is not a regular file reserved to its owner.
    #[error("key-encryption-key file must be a regular file with mode 0600 (no group or other access)")]
    UnsafeFile,
    /// The file exceeds the size bound.
    #[error("key-encryption-key file exceeds 65536 bytes")]
    TooLarge,
    /// The file lists no key.
    #[error("key-encryption-key file lists no key")]
    Empty,
    /// A line is not `<key-id>:<64 hexadecimal characters>` or the key id is invalid.
    #[error("key-encryption-key file line {line} must be `<key-id>:<64 hexadecimal characters>`")]
    Malformed {
        /// One-based line number.
        line: usize,
    },
    /// Two lines use the same key id.
    #[error("key-encryption-key file repeats a key id (line {line})")]
    DuplicateId {
        /// One-based line number of the repeat.
        line: usize,
    },
    /// The file lists more keys than allowed.
    #[error("key-encryption-key file lists more than 64 keys")]
    TooManyKeys,
}

struct Kek {
    id: String,
    key: Zeroizing<[u8; 32]>,
}

/// The loaded key set: the primary key for new wraps, every key for unwrapping.
pub struct KekFile {
    keys: Vec<Kek>,
}

impl fmt::Debug for KekFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KekFile([REDACTED])")
    }
}

/// Is `id` a valid key id?
#[must_use]
pub fn is_valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_KEY_ID_BYTES
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

impl KekFile {
    /// Load and validate the KEK file at `path`.
    ///
    /// # Errors
    /// Returns [`KekFileError`] for any unreadable, unsafe, oversized, empty or malformed file.
    pub fn load(path: &Path) -> Result<Self, KekFileError> {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| KekFileError::File(std::io::Error::from(error)))?;
        let file = std::fs::File::from(descriptor);
        let metadata = file.metadata().map_err(KekFileError::File)?;
        {
            use std::os::unix::fs::PermissionsExt as _;
            if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(KekFileError::UnsafeFile);
            }
        }
        // Capacity covers the bound plus the probe byte, so reading never reallocates a
        // buffer that holds key text.
        let mut text = Zeroizing::new(Vec::with_capacity(MAX_FILE_BYTES + 1));
        file.take(MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut text)
            .map_err(KekFileError::File)?;
        if text.len() > MAX_FILE_BYTES {
            return Err(KekFileError::TooLarge);
        }
        Self::parse(&text)
    }

    fn parse(text: &[u8]) -> Result<Self, KekFileError> {
        let text = std::str::from_utf8(text).map_err(|_| KekFileError::Malformed { line: 1 })?;
        let mut keys: Vec<Kek> = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let raw = raw.trim();
            if raw.is_empty() || raw.starts_with('#') {
                continue;
            }
            let (id, hex_key) = raw.split_once(':').ok_or(KekFileError::Malformed { line })?;
            if !is_valid_key_id(id) {
                return Err(KekFileError::Malformed { line });
            }
            let mut key = Zeroizing::new([0_u8; 32]);
            hex::decode_to_slice(hex_key, key.as_mut()).map_err(|_| KekFileError::Malformed { line })?;
            if keys.iter().any(|kek| kek.id == id) {
                return Err(KekFileError::DuplicateId { line });
            }
            if keys.len() == MAX_KEYS {
                return Err(KekFileError::TooManyKeys);
            }
            keys.push(Kek {
                id: id.to_owned(),
                key,
            });
        }
        if keys.is_empty() {
            return Err(KekFileError::Empty);
        }
        Ok(Self { keys })
    }

    /// The key id and key new wraps use (the first line of the file).
    #[must_use]
    pub fn primary(&self) -> (&str, &[u8; 32]) {
        let kek = &self.keys[0];
        (&kek.id, &kek.key)
    }

    /// The key listed under `id`, if any.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&[u8; 32]> {
        self.keys.iter().find(|kek| kek.id == id).map(|kek| &*kek.key)
    }

    /// Ids of every listed key, primary first.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|kek| kek.id.as_str())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn write(dir: &tempfile::TempDir, body: &str, mode: u32) -> std::path::PathBuf {
        let path = dir.path().join("kek");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn first_key_is_primary_and_every_key_unwraps() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, &format!("# rotation\nnew-2:{B}\n\nold.1:{A}\n"), 0o600);
        let keks = KekFile::load(&path).unwrap();
        assert_eq!(keks.primary().0, "new-2");
        assert_eq!(keks.primary().1, &[0xbb; 32]);
        assert_eq!(keks.get("old.1"), Some(&[0xaa; 32]));
        assert_eq!(keks.get("gone"), None);
        assert_eq!(keks.ids().collect::<Vec<_>>(), ["new-2", "old.1"]);
        assert_eq!(format!("{keks:?}"), "KekFile([REDACTED])");
    }

    #[test]
    fn owner_read_only_mode_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        assert!(KekFile::load(&write(&dir, &format!("k:{A}"), 0o400)).is_ok());
    }

    #[test]
    fn group_or_other_access_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o640, 0o604, 0o660, 0o644, 0o666, 0o602] {
            let path = write(&dir, &format!("k:{A}"), mode);
            assert!(
                matches!(KekFile::load(&path), Err(KekFileError::UnsafeFile)),
                "mode {mode:o}"
            );
        }
    }

    #[test]
    fn missing_or_non_regular_paths_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            KekFile::load(&dir.path().join("absent")),
            Err(KekFileError::File(_))
        ));
        assert!(matches!(KekFile::load(dir.path()), Err(KekFileError::UnsafeFile)));
    }

    #[test]
    fn malformed_content_fails_closed_without_echoing_key_text() {
        let dir = tempfile::tempdir().unwrap();
        let short = format!("k:{}", &A[..62]);
        let long = format!("k:{A}00");
        let not_hex = format!("k:{}", "g".repeat(64));
        let cases = [
            ("", 0),
            ("# only a comment\n\n", 0),
            ("no-separator", 1),
            (short.as_str(), 1),
            (long.as_str(), 1),
            (not_hex.as_str(), 1),
            (":aaaa", 1),
            ("bad id:aaaa", 1),
        ];
        for (body, line) in cases {
            let path = write(&dir, body, 0o600);
            let error = KekFile::load(&path).unwrap_err();
            match (body.trim().is_empty() || body.starts_with('#'), &error) {
                (true, KekFileError::Empty) => {}
                (false, KekFileError::Malformed { line: got }) => assert_eq!(*got, line, "{body}"),
                other => panic!("{body:?}: {other:?}"),
            }
            assert!(!error.to_string().contains(&A[..16]), "{error}");
        }
    }

    #[test]
    fn duplicate_ids_oversize_and_too_many_keys_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let duplicate = write(&dir, &format!("k:{A}\nk:{B}\n"), 0o600);
        assert!(matches!(
            KekFile::load(&duplicate),
            Err(KekFileError::DuplicateId { line: 2 })
        ));
        let oversize = write(&dir, &"#".repeat(MAX_FILE_BYTES + 1), 0o600);
        assert!(matches!(KekFile::load(&oversize), Err(KekFileError::TooLarge)));
        let many: String = (0..=MAX_KEYS).map(|n| format!("k{n}:{A}\n")).collect();
        assert!(matches!(
            KekFile::load(&write(&dir, &many, 0o600)),
            Err(KekFileError::TooManyKeys)
        ));
        let long_id = "x".repeat(MAX_KEY_ID_BYTES + 1);
        assert!(matches!(
            KekFile::load(&write(&dir, &format!("{long_id}:{A}"), 0o600)),
            Err(KekFileError::Malformed { line: 1 })
        ));
    }
}
