//! Local corpus access requires an operator-held directory descriptor, never a tenant path.

use super::{ProtocolError, ProtocolResource};
use bytes::Bytes;
use percent_encoding::percent_decode_str;
use rustix::fs::{fstat, open, openat, Dir, FileType, Mode, OFlags};
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Pinned operator directory. Relative component opens reject symlinks atomically.
#[derive(Debug)]
pub struct FileCorpus {
    root: Arc<OwnedFd>,
    max_children: usize,
}
impl FileCorpus {
    /// Read the kernel-resolved directory label from the pinned descriptor without reopening its pathname.
    ///
    /// This is an operator display/exclusion hint, not acquisition or authorization authority.
    /// Renames may change the label; callers requiring race-free identity must use descriptor-based checks.
    ///
    /// # Errors
    /// Fails if procfs cannot resolve the descriptor or its label is not an absolute live path.
    pub fn canonical_root(&self) -> Result<PathBuf, ProtocolError> {
        let label = std::fs::read_link(format!("/proc/self/fd/{}", self.root.as_raw_fd()))?;
        if !label.is_absolute() || label.as_os_str().as_encoded_bytes().ends_with(b" (deleted)") {
            return Err(ProtocolError::Refused("corpus root label unavailable"));
        }
        Ok(label)
    }

    /// Parse before URL normalization can erase `localhost` authority or parent segments.
    ///
    /// # Errors
    /// Refuses any authority, traversal, encoded separator escape, backslash, query or fragment.
    pub fn parse_url(input: &str) -> Result<Url, ProtocolError> {
        if input.len() > 16_384 || !input.starts_with("file:///") || input.contains(['?', '#']) {
            return Err(ProtocolError::Refused("root-relative file URL required"));
        }
        let path = percent_decode_str(&input[7..])
            .decode_utf8()
            .map_err(|_| ProtocolError::Refused("file path encoding"))?;
        if path.contains(['\\', '\0']) || path.split('/').any(|part| matches!(part, "." | "..")) {
            return Err(ProtocolError::Refused("file traversal"));
        }
        Url::parse(input).map_err(|_| ProtocolError::Refused("file URL syntax"))
    }

    /// Open an operator-approved root once. Never call this using public API data.
    ///
    /// # Errors
    /// Refuses a non-directory root, symlink root, zero or excessive child limit, or I/O failure.
    pub fn open(root: &Path, max_children: usize) -> Result<Self, ProtocolError> {
        if !(1..=4096).contains(&max_children) {
            return Err(ProtocolError::Limit);
        }
        let fd = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        Ok(Self {
            root: Arc::new(fd),
            max_children,
        })
    }

    /// Read a regular file or enumerate bounded direct children without following symlinks.
    ///
    /// # Errors
    /// Refuses hosts, credentials, queries, fragments, traversal, special files, symlinks, cancellation and bounds.
    pub async fn acquire(
        &self,
        url: &Url,
        max_bytes: u32,
        deadline: Duration,
        cancel: &CancellationToken,
    ) -> Result<ProtocolResource, ProtocolError> {
        if url.scheme() != "file"
            || url.host_str().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ProtocolError::Refused("file URL components"));
        }
        if max_bytes == 0
            || max_bytes > 67_108_864
            || deadline.is_zero()
            || deadline > Duration::from_secs(90)
        {
            return Err(ProtocolError::Limit);
        }
        let decoded = percent_decode_str(url.path())
            .decode_utf8()
            .map_err(|_| ProtocolError::Refused("file path encoding"))?;
        let components: Vec<String> = decoded
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if components.len() > 128
            || components
                .iter()
                .any(|s| matches!(s.as_str(), "." | "..") || s.contains(['\\', '\0']))
        {
            return Err(ProtocolError::Refused("file traversal"));
        }
        let root = Arc::clone(&self.root);
        let max_children = self.max_children;
        let url = url.clone();
        let stop = cancel.child_token();
        let worker_stop = stop.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            let mut current = openat(
                root.as_ref(),
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)?;
            for (index, component) in components.iter().enumerate() {
                if worker_stop.is_cancelled() {
                    return Err(ProtocolError::Cancelled);
                }
                // O_PATH classifies special nodes without opening a device or FIFO for I/O.
                let mut flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                if index + 1 < components.len() {
                    flags |= OFlags::DIRECTORY;
                }
                current = openat(&current, component.as_str(), flags, Mode::empty())
                    .map_err(std::io::Error::from)?;
            }
            let stat = fstat(&current).map_err(std::io::Error::from)?;
            let kind = FileType::from_raw_mode(stat.st_mode);
            if (kind == FileType::Directory && !url.path().ends_with('/'))
                || (kind == FileType::RegularFile && url.path().ends_with('/'))
            {
                return Err(ProtocolError::Refused(
                    "corpus file or directory URL suffix mismatch",
                ));
            }
            let filesystem = rustix::fs::fstatfs(&current).map_err(std::io::Error::from)?;
            // Local kernel filesystems only. Network/FUSE mounts cannot promise bounded cancellation.
            if !matches!(
                filesystem.f_type,
                0xef53 | 0x5846_5342 | 0x9123_683e | 0x0102_1994 | 0x794c_7630
            ) {
                return Err(ProtocolError::CapabilityUnavailable(
                    "local kernel corpus filesystem",
                ));
            }
            let mut children = Vec::new();
            let mut denied_children = Vec::new();
            let body = if kind == FileType::RegularFile {
                if stat.st_size < 0
                    || u64::try_from(stat.st_size).map_err(|_| ProtocolError::Limit)? > u64::from(max_bytes)
                {
                    return Err(ProtocolError::Limit);
                }
                // Linux's descriptor magic link reopens the already pinned regular inode, not a replaceable corpus pathname.
                let mut file = std::fs::File::open(format!("/proc/self/fd/{}", current.as_raw_fd()))?;
                let mut body = Vec::new();
                let mut chunk = [0_u8; 8192];
                loop {
                    if worker_stop.is_cancelled() {
                        return Err(ProtocolError::Cancelled);
                    }
                    let n = file.read(&mut chunk)?;
                    if n == 0 {
                        break;
                    }
                    if body.len().saturating_add(n)
                        > usize::try_from(max_bytes).map_err(|_| ProtocolError::Limit)?
                    {
                        return Err(ProtocolError::Limit);
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                Bytes::from(body)
            } else if kind == FileType::Directory {
                let directory_fd = openat(
                    &current,
                    ".",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(std::io::Error::from)?;
                let directory = Dir::new(directory_fd).map_err(std::io::Error::from)?;
                for entry in directory {
                    if worker_stop.is_cancelled() {
                        return Err(ProtocolError::Cancelled);
                    }
                    let entry = entry.map_err(std::io::Error::from)?;
                    let name = entry
                        .file_name()
                        .to_str()
                        .map_err(|_| ProtocolError::Refused("file name encoding"))?;
                    if matches!(name, "." | "..") {
                        continue;
                    }
                    if children.len().saturating_add(denied_children.len()) == max_children {
                        return Err(ProtocolError::Limit);
                    }
                    // Opening the child, not trusting d_type, closes symlink/replacement races.
                    let child = openat(
                        &current,
                        name,
                        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(std::io::Error::from)?;
                    let kind = FileType::from_raw_mode(fstat(&child).map_err(std::io::Error::from)?.st_mode);
                    let mut child_url = url.clone();
                    child_url
                        .path_segments_mut()
                        .map_err(|_| ProtocolError::Refused("file URL"))?
                        .pop_if_empty()
                        .push(name);
                    if kind != FileType::RegularFile && kind != FileType::Directory {
                        denied_children.push(child_url);
                        continue;
                    }
                    if kind == FileType::Directory {
                        child_url
                            .path_segments_mut()
                            .map_err(|_| ProtocolError::Refused("file URL"))?
                            .push("");
                    }
                    children.push(child_url);
                }
                children.sort_by(|a, b| a.as_str().cmp(b.as_str()));
                denied_children.sort_by(|a, b| a.as_str().cmp(b.as_str()));
                Bytes::new()
            } else {
                return Err(ProtocolError::Refused("special corpus file"));
            };
            let decoded_bytes = body.len();
            Ok(ProtocolResource {
                final_url: Some(url),
                target_status: None,
                gateway_status: None,
                media_type: None,
                body,
                children,
                denied_children,
                build_digest: "native-file-v1".to_owned(),
                network_requests: 0,
                decoded_bytes,
                redirects: Vec::new(),
            })
        });
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                stop.cancel(); task.abort(); let _ = task.await; Err(ProtocolError::Cancelled)
            },
            () = tokio::time::sleep(deadline) => {
                stop.cancel(); task.abort(); let _ = task.await; Err(ProtocolError::Deadline)
            },
            result = &mut task => result.map_err(|_| ProtocolError::Refused("corpus worker failed"))?,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[tokio::test]
    async fn corpus_refuses_symlinks_and_bounds_children() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"never return").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), root.path().join("escape")).unwrap();
        let corpus = FileCorpus::open(root.path(), 1).unwrap();
        let cancel = CancellationToken::new();
        assert!(corpus
            .acquire(
                &Url::parse("file:///escape").unwrap(),
                100,
                Duration::from_secs(1),
                &cancel
            )
            .await
            .is_err());
        assert!(corpus
            .acquire(
                &Url::parse("file://remote/escape").unwrap(),
                100,
                Duration::from_secs(1),
                &cancel
            )
            .await
            .is_err());
        assert!(corpus
            .acquire(
                &Url::parse("file:///%2e%2e%2fsecret").unwrap(),
                100,
                Duration::from_secs(1),
                &cancel
            )
            .await
            .is_err());
    }
    #[test]
    fn raw_file_admission_rejects_authority_and_normalized_traversal() {
        for input in [
            "file://localhost/a",
            "file://remote/a",
            "file:///../a",
            "file:///%2e%2e/a",
            "file:///%2e%2e%2fa",
            "file:///a%5cb",
            "file:///a?x=1",
        ] {
            assert!(FileCorpus::parse_url(input).is_err(), "{input}");
        }
        assert!(FileCorpus::parse_url("file:///allowed/a.html").is_ok());
    }
    #[tokio::test]
    async fn directory_children_and_regular_file_bytes_are_finite() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a.html"), b"<p>owned corpus</p>").unwrap();
        std::fs::write(root.path().join("b.html"), b"<p>second</p>").unwrap();
        let corpus = FileCorpus::open(root.path(), 1).unwrap();
        let token = CancellationToken::new();
        assert!(matches!(
            corpus
                .acquire(
                    &FileCorpus::parse_url("file:///").unwrap(),
                    4096,
                    Duration::from_secs(1),
                    &token
                )
                .await,
            Err(ProtocolError::Limit)
        ));
        let resource = corpus
            .acquire(
                &FileCorpus::parse_url("file:///a.html").unwrap(),
                4096,
                Duration::from_secs(1),
                &token,
            )
            .await
            .unwrap();
        assert_eq!(resource.body.as_ref(), b"<p>owned corpus</p>");
        assert_eq!(resource.target_status, None);
        assert!(matches!(
            corpus
                .acquire(
                    &FileCorpus::parse_url("file:///a.html").unwrap(),
                    1,
                    Duration::from_secs(1),
                    &token
                )
                .await,
            Err(ProtocolError::Limit)
        ));
    }
    #[tokio::test]
    async fn fifo_and_device_are_classified_without_opening_for_io() {
        let root = tempfile::tempdir().unwrap();
        let root_fd = open(root.path(), OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        rustix::fs::mkfifoat(&root_fd, "pipe", Mode::RUSR | Mode::WUSR).unwrap();
        let corpus = FileCorpus::open(root.path(), 1).unwrap();
        let token = CancellationToken::new();
        assert!(matches!(
            corpus
                .acquire(
                    &FileCorpus::parse_url("file:///pipe").unwrap(),
                    4096,
                    Duration::from_secs(1),
                    &token
                )
                .await,
            Err(ProtocolError::Refused("special corpus file"))
        ));
        let devices = FileCorpus::open(Path::new("/dev"), 1).unwrap();
        assert!(matches!(
            devices
                .acquire(
                    &FileCorpus::parse_url("file:///null").unwrap(),
                    4096,
                    Duration::from_secs(1),
                    &token
                )
                .await,
            Err(ProtocolError::Refused("special corpus file"))
        ));
    }
}
