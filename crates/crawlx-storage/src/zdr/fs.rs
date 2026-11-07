//! Crash-safe page files; every entry point is called from `spawn_blocking`.

use super::{BufferLimits, BufferedPage, PageKey, PageMeta, Pages, DEFAULT_TTL};
use crawlx_core::{CrawlRunId, StoreError, TenantId};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::{File, FileTimes, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

// Headers contain only routing/accounting fields. The payload adds at most this much
// metadata to four JSON bytes per content byte (e.g. `255,`). Both reads are bounded.
const MAX_HEADER_BYTES: u64 = 64 * 1024;
const MAX_PAYLOAD_METADATA_BYTES: u64 = 1024 * 1024;

pub(super) fn initialize(root: &Path) -> Result<(), StoreError> {
    private_directory(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    let lock_path = root.join(".lock");
    reject_symlink(&lock_path)?;
    let _lock = private_file(&lock_path, false)?;
    Ok(())
}

pub(super) fn validate_runtime_root(base: &Path) -> Result<(), StoreError> {
    private_directory(base)?;
    let base = std::fs::canonicalize(base).map_err(io_error)?;
    #[cfg(target_os = "linux")]
    {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").map_err(io_error)?;
        require_memory_mount(&base, &mountinfo)?;
        // Validate the child too: an independently mounted zdr/ must not hide a
        // persistent filesystem beneath an otherwise memory-backed base.
        let root = base.join("zdr");
        private_directory(&root)?;
        let root = std::fs::canonicalize(root).map_err(io_error)?;
        require_memory_mount(&root, &mountinfo)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = base;
        Err(StoreError::RetentionDenied(
            "production zdr delivery requires Linux tmpfs/ramfs mount validation".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn require_memory_mount(root: &Path, mountinfo: &str) -> Result<(), StoreError> {
    let mut selected: Option<(usize, u64, &str)> = None;
    for line in mountinfo.lines() {
        let Some((mount, filesystem)) = line.split_once(" - ") else {
            return Err(StoreError::Backend("invalid Linux mountinfo record".into()));
        };
        let mut fields = mount.split_whitespace();
        let id: u64 = fields
            .next()
            .ok_or_else(|| StoreError::Backend("missing mount id".into()))?
            .parse()
            .map_err(|error| StoreError::Backend(format!("invalid mount id: {error}")))?;
        let mount_path = fields
            .nth(3)
            .ok_or_else(|| StoreError::Backend("missing mount path".into()))?;
        let mount_path = mount_path
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        let filesystem = filesystem
            .split_whitespace()
            .next()
            .ok_or_else(|| StoreError::Backend("missing filesystem type".into()))?;
        let path = Path::new(&mount_path);
        if root.starts_with(path) {
            let specificity = path.components().count();
            if selected.is_none_or(|(depth, old_id, _)| (specificity, id) > (depth, old_id)) {
                selected = Some((specificity, id, filesystem));
            }
        }
    }
    match selected {
        Some((_, _, "tmpfs" | "ramfs")) => Ok(()),
        _ => Err(StoreError::RetentionDenied(
            "CRAWLX_ZDR_DIR must use a shared tmpfs or ramfs mount, not persistent artifact storage".into(),
        )),
    }
}
fn private_directory(path: &Path) -> Result<(), StoreError> {
    reject_symlink(path)?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(io_error)?;
    if !std::fs::symlink_metadata(path).map_err(io_error)?.is_dir() {
        return Err(StoreError::Backend("zdr namespace is not a directory".into()));
    }
    Ok(())
}

fn private_file(path: &Path, exclusive: bool) -> Result<File, StoreError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if exclusive {
        options.create_new(true);
    } else {
        options.create(true).truncate(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(io_error)?;
    if !file.metadata().map_err(io_error)?.is_file() {
        return Err(StoreError::Backend("zdr entry is not a regular file".into()));
    }
    Ok(file)
}

fn reject_symlink(path: &Path) -> Result<(), StoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(StoreError::Backend("zdr namespace contains a symlink".into()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn io_error(error: std::io::Error) -> StoreError {
    // StoreError currently exposes string-backed filesystem errors (unlike Database).
    StoreError::Backend(format!("zdr filesystem operation failed: {error}"))
}

fn serialization_error(_error: impl std::fmt::Display) -> StoreError {
    // Decoder messages can quote arbitrary strings from sensitive page payloads.
    StoreError::Serialization("invalid zdr page encoding or metadata".into())
}

pub(super) struct FilesystemPages {
    root: PathBuf,
    metadata: BTreeMap<PageKey, PageMeta>,
    limits: BufferLimits,
    // One independently opened description per operation: never clone a locked File.
    // Drop closes it and releases the OS lock, including unwinding and process death.
    _lock: File,
}

impl FilesystemPages {
    pub(super) fn open(root: &Path, limits: BufferLimits) -> Result<Self, StoreError> {
        reject_symlink(root)?;
        let lock_path = root.join(".lock");
        reject_symlink(&lock_path)?;
        let lock = private_file(&lock_path, false)?;
        // File::lock is stable since Rust 1.89; workspace MSRV is 1.97.
        lock.lock().map_err(io_error)?;
        let mut pages = Self {
            root: root.to_owned(),
            metadata: BTreeMap::new(),
            limits,
            _lock: lock,
        };
        pages.scan()?;
        Ok(pages)
    }

    fn path(&self, key: &PageKey) -> PathBuf {
        self.root
            .join(key.0.to_string())
            .join(key.1.to_string())
            .join(format!("{}.json", key.2))
    }

    fn scan(&mut self) -> Result<(), StoreError> {
        let mut malformed = None;
        for tenant_entry in std::fs::read_dir(&self.root).map_err(io_error)? {
            let tenant_entry = tenant_entry.map_err(io_error)?;
            if tenant_entry.file_name() == ".lock" {
                continue;
            }
            if remove_orphan_temp(&tenant_entry)? {
                continue;
            }
            require_directory(&tenant_entry)?;
            let tenant: TenantId = tenant_entry
                .file_name()
                .to_str()
                .ok_or_else(|| serialization_error("non-UTF-8 tenant directory"))?
                .parse()
                .map_err(serialization_error)?;
            for run_entry in std::fs::read_dir(tenant_entry.path()).map_err(io_error)? {
                let run_entry = run_entry.map_err(io_error)?;
                if remove_orphan_temp(&run_entry)? {
                    continue;
                }
                require_directory(&run_entry)?;
                let run: CrawlRunId = run_entry
                    .file_name()
                    .to_str()
                    .ok_or_else(|| serialization_error("non-UTF-8 run directory"))?
                    .parse()
                    .map_err(serialization_error)?;
                for page_entry in std::fs::read_dir(run_entry.path()).map_err(io_error)? {
                    let page_entry = page_entry.map_err(io_error)?;
                    if remove_orphan_temp(&page_entry)? {
                        continue;
                    }
                    if !page_entry.file_type().map_err(io_error)?.is_file() {
                        return Err(serialization_error("page entry is not a regular file"));
                    }
                    let path = page_entry.path();
                    let page: i64 = path
                        .file_stem()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| serialization_error("invalid page filename"))?
                        .parse()
                        .map_err(serialization_error)?;
                    if path.extension().is_none_or(|extension| extension != "json") {
                        return Err(serialization_error("invalid page extension"));
                    }
                    let decoded = read_header(&path).and_then(|meta| {
                        if meta.key() != (tenant, run, page) || path != self.path(&meta.key()) {
                            return Err(serialization_error("page namespace does not match header"));
                        }
                        validate_metadata(&meta)?;
                        Ok(meta)
                    });
                    let meta = match decoded {
                        Ok(meta) => meta,
                        Err(error @ StoreError::Serialization(_)) => {
                            // Corrupt headers must not block cleanup indefinitely. Delete
                            // every corrupt page, then report the failure to the caller.
                            std::fs::remove_file(&path).map_err(io_error)?;
                            malformed = Some(error);
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    if self.metadata.insert(meta.key(), meta).is_some() {
                        return Err(serialization_error("duplicate page namespace"));
                    }
                }
            }
        }
        malformed.map_or(Ok(()), Err)
    }
}

impl Pages for FilesystemPages {
    fn metadata(&self) -> &BTreeMap<PageKey, PageMeta> {
        &self.metadata
    }

    fn load(&self, key: &PageKey) -> Result<Option<BufferedPage>, StoreError> {
        let Some(meta) = self.metadata.get(key) else {
            return Ok(None);
        };
        if meta.bytes > self.limits.max_bytes {
            return Err(StoreError::RetentionDenied(
                "zdr page exceeds configured read capacity".into(),
            ));
        }
        let path = self.path(key);
        let file = File::open(&path).map_err(io_error)?;
        let max_payload = u64::try_from(meta.bytes)
            .map_err(serialization_error)?
            .checked_mul(4)
            .and_then(|n| n.checked_add(MAX_PAYLOAD_METADATA_BYTES))
            .ok_or_else(|| serialization_error("page payload limit overflow"))?;
        if file.metadata().map_err(io_error)?.len() > max_payload.saturating_add(MAX_HEADER_BYTES) {
            return Err(serialization_error("page file exceeds bounded payload size"));
        }
        let mut reader = BufReader::new(file);
        let header = read_header_from(&mut reader)?;
        if &header != meta {
            return Err(serialization_error("page header changed under lock"));
        }
        let mut deserializer = serde_json::Deserializer::from_reader(reader.take(max_payload));
        let page = BufferedPage::deserialize(&mut deserializer).map_err(json_io_error)?;
        deserializer.end().map_err(json_io_error)?;
        let mut expected = PageMeta::from_page(&page, meta.sequence);
        // Older volatile headers lacked descriptors. Their existing digest validation remains.
        if meta.content_metadata.is_empty() {
            expected.content_metadata.clear();
        }
        if expected != *meta || page.blobs.is_empty() {
            return Err(serialization_error("page payload does not match header"));
        }
        for blob in page.blobs.values() {
            if blob.artifact.digest
                != crawlx_core::hash::Digest::of(crate::artifacts::DIGEST_DOMAIN, &blob.bytes)
            {
                return Err(serialization_error("page content digest does not match"));
            }
        }
        Ok(Some(page))
    }

    fn put(&mut self, meta: PageMeta, page: BufferedPage) -> Result<(), StoreError> {
        let header = serde_json::to_vec(&meta).map_err(serialization_error)?;
        if u64::try_from(header.len()).map_err(serialization_error)? >= MAX_HEADER_BYTES {
            return Err(StoreError::RetentionDenied(
                "zdr page metadata exceeds header capacity".into(),
            ));
        }
        let path = self.path(&meta.key());
        let tenant_dir = self.root.join(meta.tenant.to_string());
        let run_dir = tenant_dir.join(meta.run.to_string());
        private_directory(&tenant_dir)?;
        private_directory(&run_dir)?;
        let temp_path = run_dir.join(format!(".page-{}.tmp", crawlx_core::ArtifactId::new()));
        let mut file = private_file(&temp_path, true)?;
        // Restore first-insert mtime before commit. A writer can crash while a
        // temporary's mtime is newer, so the independent locked sweeper must also
        // remove orphan temporaries, rather than relying solely on file age.
        let times = FileTimes::new().set_modified(std::time::SystemTime::from(meta.inserted_at));
        file.set_times(times).map_err(io_error)?;
        let result: Result<(), StoreError> = (|| {
            file.write_all(&header).map_err(io_error)?;
            file.write_all(b"\n").map_err(io_error)?;
            let limit = u64::try_from(meta.bytes)
                .map_err(serialization_error)?
                .checked_mul(4)
                .and_then(|n| n.checked_add(MAX_PAYLOAD_METADATA_BYTES))
                .ok_or_else(|| serialization_error("page payload limit overflow"))?;
            let mut writer = BoundedWriter {
                writer: &mut file,
                remaining: limit,
            };
            serde_json::to_writer(&mut writer, &page).map_err(json_io_error)?;
            file.set_times(times).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            std::fs::rename(&temp_path, &path).map_err(io_error)?;
            Ok(())
        })();
        if result.is_err() {
            // Cleanup failures must surface too, rather than silently leaving content.
            match std::fs::remove_file(&temp_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        result?;
        self.metadata.insert(meta.key(), meta);
        Ok(())
    }

    fn remove(&mut self, key: &PageKey) -> Result<bool, StoreError> {
        if !self.metadata.contains_key(key) {
            return Ok(false);
        }
        let path = self.path(key);
        std::fs::remove_file(&path).map_err(io_error)?;
        self.metadata.remove(key);
        // Empty namespaces carry no content. Keep them until the scan finishes; this
        // also avoids invalidating another directory iterator during a purge.
        Ok(true)
    }
}

fn require_directory(entry: &std::fs::DirEntry) -> Result<(), StoreError> {
    if entry.file_type().map_err(io_error)?.is_dir() {
        Ok(())
    } else {
        Err(serialization_error("zdr namespace entry is not a directory"))
    }
}

fn remove_orphan_temp(entry: &std::fs::DirEntry) -> Result<bool, StoreError> {
    let name = entry.file_name();
    let Some(name) = name.to_str() else {
        return Ok(false);
    };
    if !name.starts_with(".page-") || !name.ends_with(".tmp") {
        return Ok(false);
    }
    if !entry.file_type().map_err(io_error)?.is_file() {
        return Err(serialization_error("zdr temporary entry is not a regular file"));
    }
    // No live writer can own this file while we hold the namespace lock.
    std::fs::remove_file(entry.path()).map_err(io_error)?;
    Ok(true)
}

fn read_header(path: &Path) -> Result<PageMeta, StoreError> {
    read_header_from(&mut BufReader::new(File::open(path).map_err(io_error)?))
}

fn read_header_from(reader: &mut impl BufRead) -> Result<PageMeta, StoreError> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_HEADER_BYTES)
        .read_until(b'\n', &mut bytes)
        .map_err(io_error)?;
    if bytes.last() != Some(&b'\n') {
        return Err(serialization_error("missing or oversized page header"));
    }
    serde_json::from_slice(&bytes).map_err(serialization_error)
}

fn validate_metadata(meta: &PageMeta) -> Result<(), StoreError> {
    let ttl = chrono::Duration::from_std(DEFAULT_TTL).map_err(serialization_error)?;
    let latest = meta
        .inserted_at
        .checked_add_signed(ttl)
        .ok_or_else(|| serialization_error("page expiry timestamp overflow"))?;
    if meta.expires_at < meta.inserted_at || meta.expires_at > latest || meta.artifacts.is_empty() {
        return Err(serialization_error("invalid page lifetime or artifact metadata"));
    }
    Ok(())
}

struct BoundedWriter<W> {
    writer: W,
    remaining: u64,
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let len = u64::try_from(bytes.len()).map_err(std::io::Error::other)?;
        if len > self.remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "zdr payload metadata exceeds capacity",
            ));
        }
        let written = self.writer.write(bytes)?;
        self.remaining = self
            .remaining
            .saturating_sub(u64::try_from(written).map_err(std::io::Error::other)?);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

fn json_io_error(error: serde_json::Error) -> StoreError {
    match error.io_error_kind() {
        Some(std::io::ErrorKind::InvalidInput) => {
            StoreError::RetentionDenied("zdr page payload metadata exceeds capacity".into())
        }
        Some(_) => StoreError::Backend("zdr page I/O failed".into()),
        None => serialization_error(error),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn runtime_mount_validation_uses_most_specific_mount() {
        let mounts = "1 0 0:1 / / rw - overlay overlay rw\n\
            2 1 0:2 / /run rw - tmpfs tmpfs rw\n\
            3 2 8:1 / /run/persistent rw - ext4 /dev/example rw\n";
        assert!(require_memory_mount(Path::new("/run/crawlx/zdr"), mounts).is_ok());
        assert!(require_memory_mount(Path::new("/run/persistent/zdr"), mounts).is_err());
        assert!(require_memory_mount(Path::new("/runner/zdr"), mounts).is_err());
        assert!(require_memory_mount(Path::new("/var/lib/crawlx"), mounts).is_err());
    }

    #[test]
    fn runtime_mount_validation_decodes_mountinfo_path_escapes() {
        let mounts = "1 0 0:1 / / rw - overlay overlay rw\n\
            2 1 0:2 / /volatile\\040delivery rw - tmpfs tmpfs rw\n";
        assert!(require_memory_mount(Path::new("/volatile delivery/zdr"), mounts).is_ok());
        assert!(require_memory_mount(Path::new("/volatile/zdr"), mounts).is_err());
    }
}
