//! Operator-provisioned local key-encryption-key (KEK) file for self-hosted key custody.
//!
//! The file holds one KEK per line as `<key-id>:<64 hexadecimal characters>` (32 bytes).
//! Blank lines and lines starting with `#` are ignored. The **first** key is the primary:
//! every new wrap uses it. Every listed key can still unwrap, so rotation is: add a new key
//! on top, re-wrap what must outlive the old key, then delete the old line. Key ids are
//! non-secret labels (`A-Z a-z 0-9 . _ -`, at most [`MAX_KEY_ID_BYTES`] bytes), stored next to
//! each wrapped data key so the right KEK is found at unwrap time.
//!
//! The file is read through its opened descriptor (symlinks, as in projected secret volumes, are
//! followed, so the target's metadata is checked) and refused unless it is a regular file whose
//! mode is either owner-only (no group or other bits, `0600` or `0400`) or group-readable
//! (`0440`: read for owner and group and nothing else) with the file's group the process's
//! effective or a supplementary group and its owner the process user or root. The second form
//! is what a Kubernetes secret volume looks like under `fsGroup` (kubelet writes the file as root
//! and adds group read). Nothing is generated: a missing, unreadable, oversized, empty or malformed
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
    /// The opened descriptor is not a regular file with an accepted owner, group and mode.
    #[error(
        "key-encryption-key file has mode {mode:04o} and gid {gid}: it must be a regular file with mode 0600 or 0400, or \
         mode 0440 with a group of this process (owned by this user or root); no group write or execute and no other access"
    )]
    UnsafeFile {
        /// Permission bits of the opened file.
        mode: u32,
        /// Group id of the opened file.
        gid: u32,
    },
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

/// The user and groups of this process, which decide whether a group-readable file is trusted.
struct ProcessIdentity {
    uid: u32,
    groups: Vec<u32>,
}

impl ProcessIdentity {
    fn current() -> Self {
        let mut groups = vec![rustix::process::getegid().as_raw()];
        groups.extend(
            rustix::process::getgroups()
                .unwrap_or_default()
                .into_iter()
                .map(rustix::process::Gid::as_raw),
        );
        Self {
            uid: rustix::process::getuid().as_raw(),
            groups,
        }
    }
}

/// Is a file with permission bits `mode`, owner `uid` and group `gid` an acceptable KEK file?
///
/// Owner-only files (`mode & 0o077 == 0`) always are. Read access for owner and group and nothing
/// else (`0440`, or the group alone: `mode & !0o440 == 0`) is accepted when the group belongs to this process and the owner is this user or root: that is
/// how a Kubernetes secret volume under `fsGroup` is presented. Anything else is refused.
fn mode_is_accepted(mode: u32, uid: u32, gid: u32, process: &ProcessIdentity) -> bool {
    if mode & 0o077 == 0 {
        return true;
    }
    mode & !0o440 == 0 && (uid == process.uid || uid == 0) && process.groups.contains(&gid)
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
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            let mode = metadata.permissions().mode() & 0o7777;
            let process = ProcessIdentity::current();
            if !metadata.is_file() || !mode_is_accepted(mode, metadata.uid(), metadata.gid(), &process) {
                return Err(KekFileError::UnsafeFile {
                    mode,
                    gid: metadata.gid(),
                });
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
        // an earlier call may have left a read-only file
        let _ = std::fs::remove_file(&path);
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
    fn group_read_with_one_of_our_groups_is_accepted_for_a_file_we_own() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, &format!("k:{A}"), 0o440);
        // a new file takes the effective group of this process
        assert!(KekFile::load(&path).is_ok());
    }

    #[test]
    fn modes_beyond_owner_only_or_group_read_are_refused_with_the_mode_and_gid_named() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [
            0o640, 0o604, 0o660, 0o644, 0o666, 0o602, 0o444, 0o450, 0o441, 0o540,
        ] {
            let path = write(&dir, &format!("k:{A}"), mode);
            let error = KekFile::load(&path).unwrap_err();
            let KekFileError::UnsafeFile { mode: seen, gid } = error else {
                panic!("mode {mode:o}: {error:?}");
            };
            assert_eq!(seen, mode);
            let text = error.to_string();
            assert!(text.contains(&format!("mode {mode:04o}")), "{text}");
            assert!(text.contains(&format!("gid {gid}")), "{text}");
        }
    }

    #[test]
    fn symlinks_are_judged_by_their_target() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        for (mode, accepted) in [(0o400, true), (0o440, true), (0o640, false), (0o444, false)] {
            let target = write(&dir, &format!("k:{A}"), mode);
            let target = {
                let kept = dir.path().join(format!("target-{mode:o}"));
                std::fs::rename(&target, &kept).unwrap();
                kept
            };
            let link = dir.path().join(format!("link-{mode:o}"));
            symlink(&target, &link).unwrap();
            assert_eq!(KekFile::load(&link).is_ok(), accepted, "mode {mode:o}");
        }
    }

    #[test]
    fn acceptance_depends_on_mode_owner_and_group() {
        let process = ProcessIdentity {
            uid: 10001,
            groups: vec![10001, 2000],
        };
        // (mode, owner, group, accepted)
        for (mode, uid, gid, accepted) in [
            (0o400, 10001, 10001, true),
            (0o600, 10001, 99, true),
            (0o400, 0, 99, true),
            (0o440, 0, 10001, true),
            (0o440, 10001, 2000, true),
            (0o440, 10001, 99, false),
            (0o440, 4242, 10001, false),
            (0o640, 0, 10001, false),
            (0o460, 0, 10001, false),
            (0o441, 0, 10001, false),
            (0o444, 0, 10001, false),
            (0o2440, 0, 10001, false),
        ] {
            assert_eq!(
                mode_is_accepted(mode, uid, gid, &process),
                accepted,
                "mode {mode:o} uid {uid} gid {gid}"
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
        assert!(matches!(
            KekFile::load(dir.path()),
            Err(KekFileError::UnsafeFile { .. })
        ));
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
