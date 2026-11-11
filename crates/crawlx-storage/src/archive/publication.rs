//! Manifest-last native bundle publication and bounded, ownership-proven crash recovery.
//!
//! The private state journal is deletion authority; archive manifests never are. Archive bytes
//! travel only from held anonymous descriptors to create-new final members. A sentinel makes
//! every intermediate state unreadable, including the manifest-fsync/sentinel-unlink gap.

use super::{collection, staging::StagedFile, ArchiveError, Limits};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
#[cfg(any(test, all(feature = "chaos", debug_assertions)))]
use std::io::Write as _;
use std::io::{Read, Seek as _};
use std::path::{Path, PathBuf};

/// Complete native bundle fixity manifest, separate from capture metadata.
pub const MANIFEST: &str = "publication.json";
const SENTINEL: &str = ".incomplete";
const MAX_METADATA: u64 = 262_144;
const MAX_JOURNALS: usize = 256;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Member {
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    export_id: String,
    files: Vec<Member>,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u32,
    token: String,
    export_id: String,
    pid: u32,
    start: String,
    boot: String,
    parent: PathBuf,
    parent_identity: Identity,
    name: String,
    stage: String,
    files: Vec<String>,
}

/// Result of one bounded recovery pass. Foreign, active and changed directories stay untouched.
#[derive(Debug, Default, Clone, Copy, Serialize)]
#[must_use]
#[non_exhaustive]
pub struct RecoveryReport {
    /// Incomplete owned bundles erased.
    pub erased: usize,
    /// Fully fixed bundles committed by removing their sentinel.
    pub completed: usize,
    /// Active, foreign, replaced or otherwise unprovable entries left untouched.
    pub refused: usize,
}

fn invalid(message: &'static str) -> ArchiveError {
    ArchiveError::Invalid(message)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use rustix::fs::{mkdirat, openat, renameat_with, statat, unlinkat, AtFlags, Mode, OFlags, RenameFlags};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;

    fn open_root(path: &Path) -> std::io::Result<File> {
        use rustix::fs::{openat2, ResolveFlags, CWD};
        openat2(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .map_err(std::io::Error::from)
    }

    pub(super) fn identity(file: &File) -> Result<Identity, ArchiveError> {
        let metadata = file.metadata()?;
        Ok(Identity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn dir_at(root: &File, name: &str) -> Result<File, ArchiveError> {
        openat(
            root,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| ArchiveError::Io(error.into()))
    }

    fn create(root: &File, name: &str) -> Result<File, ArchiveError> {
        openat(
            root,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(|error| ArchiveError::Io(error.into()))
    }

    fn exists(root: &File, name: &str) -> Result<bool, ArchiveError> {
        match statat(root, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(ArchiveError::Io(error.into())),
        }
    }

    fn remove(root: &File, name: &str, directory: bool) -> Result<(), ArchiveError> {
        unlinkat(
            root,
            name,
            if directory {
                AtFlags::REMOVEDIR
            } else {
                AtFlags::empty()
            },
        )
        .map_err(|error| ArchiveError::Io(error.into()))
    }

    fn names(root: &File) -> Result<Vec<String>, ArchiveError> {
        let mut result = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", root.as_raw_fd()))? {
            if result.len() >= MAX_JOURNALS.max(Limits::default().resources * 8) {
                return Err(ArchiveError::Limit("publication directory entries"));
            }
            result.push(
                entry?
                    .file_name()
                    .into_string()
                    .map_err(|_| invalid("non-UTF8 publication entry"))?,
            );
        }
        result.sort();
        Ok(result)
    }

    fn json<T: serde::de::DeserializeOwned>(root: &File, name: &str) -> Result<T, ArchiveError> {
        let file = collection::open_confined_regular_at(root, name)?;
        if file.metadata()?.len() > MAX_METADATA {
            return Err(ArchiveError::Limit("publication metadata bytes"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_METADATA + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_METADATA {
            return Err(ArchiveError::Limit("publication metadata bytes"));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write_json(root: &File, name: &str, value: &impl Serialize) -> Result<(), ArchiveError> {
        let mut file = create(root, name)?;
        serde_json::to_writer(&mut file, value)?;
        file.sync_all()?;
        root.sync_all()?;
        Ok(())
    }

    fn secure_directory(path: &Path) -> Result<File, ArchiveError> {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    open_root(parent)?.sync_all()?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        check_private(open_root(path)?)
    }

    fn check_private(file: File) -> Result<File, ArchiveError> {
        let metadata = file.metadata()?;
        if metadata.uid() != rustix::process::getuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(invalid("publication state directory is not private"));
        }
        Ok(file)
    }

    fn state_home() -> Result<PathBuf, ArchiveError> {
        let state = match std::env::var_os("XDG_STATE_HOME").filter(|path| !path.is_empty()) {
            Some(path) => PathBuf::from(path),
            None => PathBuf::from(
                std::env::var_os("HOME").ok_or_else(|| invalid("publication state home unavailable"))?,
            )
            .join(".local/state"),
        };
        if !state.is_absolute() {
            return Err(invalid("publication state home must be absolute"));
        }
        Ok(state)
    }

    pub(super) fn journal_root() -> Result<File, ArchiveError> {
        let state = state_home()?;
        // These are user state directories, never an output-controlled cache or archive tree.
        std::fs::create_dir_all(&state)?;
        let app = state.join("crawlx");
        secure_directory(&app)?;
        secure_directory(&app.join("archive-publications"))
    }

    pub(super) fn recovery_root() -> Result<Option<File>, ArchiveError> {
        if std::env::var_os("XDG_STATE_HOME").is_none() && std::env::var_os("HOME").is_none() {
            return Ok(None);
        }
        let app = state_home()?.join("crawlx");
        let directory = match open_root(&app) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        match dir_at(&directory, "archive-publications") {
            Ok(file) => {
                check_private(directory)?;
                Ok(Some(check_private(file)?))
            }
            Err(ArchiveError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn process_start(pid: u32) -> Result<String, ArchiveError> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let (_, fields) = stat
            .rsplit_once(')')
            .ok_or_else(|| invalid("invalid process identity"))?;
        fields
            .split_whitespace()
            .nth(19)
            .map(str::to_owned)
            .ok_or_else(|| invalid("missing process start identity"))
    }

    fn boot() -> Result<String, ArchiveError> {
        Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned())
    }

    fn member_hash(mut input: File, limit: u64) -> Result<(u64, String), ArchiveError> {
        let mut hash = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = [0u8; 32 * 1024];
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            bytes = bytes
                .checked_add(u64::try_from(count).map_err(|_| ArchiveError::Limit("publication bytes"))?)
                .ok_or(ArchiveError::Limit("publication bytes"))?;
            if bytes > limit {
                return Err(ArchiveError::Limit("publication bytes"));
            }
            hash.update(&buffer[..count]);
        }
        Ok((bytes, hex::encode(hash.finalize())))
    }

    fn valid_manifest(root: &File, limits: Limits) -> Result<Manifest, ArchiveError> {
        let manifest: Manifest = json(root, MANIFEST)?;
        if manifest.version != 1
            || manifest.export_id.is_empty()
            || manifest.export_id.len() > 128
            || manifest.files.is_empty()
            || manifest.files.len() > limits.resources
        {
            return Err(invalid("invalid publication manifest"));
        }
        let mut total = 0u64;
        let mut previous: Option<&str> = None;
        for member in &manifest.files {
            super::super::validate_path(&member.path)?;
            if member.path == SENTINEL
                || member.path == MANIFEST
                || member.sha256.len() != 64
                || !member.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || previous.is_some_and(|name| name >= member.path.as_str())
            {
                return Err(invalid("invalid publication member"));
            }
            previous = Some(&member.path);
            total = total
                .checked_add(member.bytes)
                .ok_or(ArchiveError::Limit("publication bytes"))?;
            if total > limits.total_bytes {
                return Err(ArchiveError::Limit("publication bytes"));
            }
            let file = collection::open_confined_regular_at(root, &member.path)?;
            if file.metadata()?.len() != member.bytes {
                return Err(invalid("publication member length mismatch"));
            }
            let (bytes, hash) = member_hash(file, member.bytes)?;
            if bytes != member.bytes || hash != member.sha256 {
                return Err(invalid("publication member fixity mismatch"));
            }
        }
        if !manifest
            .files
            .iter()
            .any(|file| file.path == "crawlx/manifest.json")
        {
            return Err(invalid("native capture manifest missing"));
        }
        let paths: Vec<_> = manifest.files.iter().map(|file| file.path.clone()).collect();
        let (members, directories) = planned_paths(&paths)?;
        inventory(root, "", &members, &directories, &mut Vec::new())?;
        Ok(manifest)
    }

    fn planned_paths(files: &[String]) -> Result<(BTreeSet<String>, BTreeSet<String>), ArchiveError> {
        if files.is_empty() || files.len() > Limits::default().resources {
            return Err(ArchiveError::Limit("publication resources"));
        }
        let mut members = BTreeSet::new();
        let mut directories = BTreeSet::new();
        for path in files {
            super::super::validate_path(path)?;
            if path == SENTINEL || path == MANIFEST || !members.insert(path.clone()) {
                return Err(invalid("reserved or duplicate publication member"));
            }
            let mut prefix = String::new();
            let parts: Vec<_> = path.split('/').collect();
            if parts.len() > 32 {
                return Err(ArchiveError::Limit("publication member depth"));
            }
            for part in &parts[..parts.len() - 1] {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(part);
                directories.insert(prefix.clone());
            }
        }
        if members.iter().any(|name| directories.contains(name)) {
            return Err(invalid("publication file conflicts with directory"));
        }
        Ok((members, directories))
    }

    fn member_parent(root: &File, path: &str) -> Result<(File, String), ArchiveError> {
        let mut directory = root.try_clone()?;
        let mut parts = path.split('/').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                return Ok((directory, part.to_owned()));
            }
            directory = dir_at(&directory, part)?;
        }
        Err(invalid("empty publication path"))
    }

    pub(super) fn publish(
        out: &Path,
        export_id: &str,
        files: &mut [(String, StagedFile)],
        journal: &File,
    ) -> Result<(), ArchiveError> {
        if export_id.is_empty() || export_id.len() > 128 || export_id.chars().any(char::is_control) {
            return Err(invalid("invalid publication export identity"));
        }
        if names(journal)?.len() >= MAX_JOURNALS {
            return Err(ArchiveError::Limit("publication journal entries"));
        }
        let mut paths: Vec<_> = files.iter().map(|(name, _)| name.clone()).collect();
        paths.sort();
        let (_, directories) = planned_paths(&paths)?;
        if !paths.iter().any(|path| path == "crawlx/manifest.json") {
            return Err(invalid("native capture manifest missing"));
        }
        let parent_path = out
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent_path = std::fs::canonicalize(parent_path)?;
        let parent = open_root(&parent_path)?;
        let name = out
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("invalid publication destination"))?;
        super::super::validate_path(name)?;
        if exists(&parent, name)? {
            return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into());
        }
        let token = uuid::Uuid::now_v7().to_string();
        // Only empty directory metadata and the sentinel use this tracked private name.
        // No archive member is created until the sentinel-bearing inode reaches `out`.
        let stage = format!(".crawlx-publication-{token}");
        mkdirat(journal, token.as_str(), Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|error| ArchiveError::Io(error.into()))?;
        journal.sync_all()?;
        let transaction = dir_at(journal, &token)?;
        let lock = create(&transaction, "lock")?;
        lock.lock()?;
        let owner = Owner {
            version: 1,
            token: token.clone(),
            export_id: export_id.to_owned(),
            pid: std::process::id(),
            start: process_start(std::process::id())?,
            boot: boot()?,
            parent: parent_path,
            parent_identity: identity(&parent)?,
            name: name.to_owned(),
            stage: stage.clone(),
            files: paths,
        };
        write_json(&transaction, "owner.json", &owner)?;
        mkdirat(&parent, stage.as_str(), Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|error| ArchiveError::Io(error.into()))?;
        let root = dir_at(&parent, &stage)?;
        write_json(&transaction, "identity.json", &identity(&root)?)?;
        write_json(&root, SENTINEL, &(&token, export_id))?;
        parent.sync_all()?;
        renameat_with(&parent, stage.as_str(), &parent, name, RenameFlags::NOREPLACE)
            .map_err(|error| ArchiveError::Io(error.into()))?;
        parent.sync_all()?;
        checkpoint("sentinel");
        for path in directories {
            let (directory, basename) = member_parent(&root, &path)?;
            mkdirat(
                &directory,
                basename.as_str(),
                Mode::RUSR | Mode::WUSR | Mode::XUSR,
            )
            .map_err(|error| ArchiveError::Io(error.into()))?;
            dir_at(&directory, &basename)?.sync_all()?;
            directory.sync_all()?;
        }
        let mut manifest = Manifest {
            version: 1,
            export_id: export_id.to_owned(),
            files: Vec::with_capacity(files.len()),
        };
        let mut total = 0u64;
        for (name, source) in files {
            let (directory, basename) = member_parent(&root, name)?;
            let mut destination = create(&directory, &basename)?;
            let mut input = source.reader()?;
            let bytes = std::io::copy(
                &mut (&mut input).take(Limits::default().total_bytes + 1),
                &mut destination,
            )?;
            total = total
                .checked_add(bytes)
                .ok_or(ArchiveError::Limit("publication bytes"))?;
            if total > Limits::default().total_bytes {
                return Err(ArchiveError::Limit("publication bytes"));
            }
            destination.sync_all()?;
            directory.sync_all()?;
            destination.rewind()?;
            let (length, sha256) = member_hash(destination.try_clone()?, bytes)?;
            if length != bytes {
                return Err(invalid("publication destination changed"));
            }
            manifest.files.push(Member {
                path: name.clone(),
                bytes,
                sha256,
            });
            checkpoint("member");
        }
        manifest.files.sort_by(|left, right| left.path.cmp(&right.path));
        write_json(&root, MANIFEST, &manifest)?;
        checkpoint("manifest");
        remove(&root, SENTINEL, false)?;
        root.sync_all()?;
        remove_transaction(journal, &token, &transaction)?;
        Ok(())
    }

    fn remove_transaction(journal: &File, token: &str, transaction: &File) -> Result<(), ArchiveError> {
        for name in names(transaction)? {
            if !matches!(name.as_str(), "lock" | "owner.json" | "identity.json") {
                return Err(invalid("unrelated publication journal data"));
            }
            collection::open_confined_regular_at(transaction, &name)?;
        }
        for name in names(transaction)? {
            remove(transaction, &name, false)?;
        }
        transaction.sync_all()?;
        remove(journal, token, true)?;
        journal.sync_all()?;
        Ok(())
    }

    struct OwnedEntry {
        relative: String,
        name: String,
        parent: File,
        identity: Identity,
        directory: bool,
    }

    // Build the entire deletion set before unlinking anything. Only private journal paths grant
    // authority, and any added entry, symlink or special file prevents the whole deletion.
    fn inventory(
        root: &File,
        prefix: &str,
        members: &BTreeSet<String>,
        directories: &BTreeSet<String>,
        found: &mut Vec<OwnedEntry>,
    ) -> Result<(), ArchiveError> {
        for name in names(root)? {
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if directories.contains(&relative) {
                let child = dir_at(root, &name)?;
                inventory(&child, &relative, members, directories, found)?;
                found.push(OwnedEntry {
                    relative,
                    name,
                    parent: root.try_clone()?,
                    identity: identity(&child)?,
                    directory: true,
                });
            } else if members.contains(&relative)
                || (prefix.is_empty() && matches!(name.as_str(), SENTINEL | MANIFEST))
            {
                let child = collection::open_confined_regular_at(root, &name)?;
                found.push(OwnedEntry {
                    relative,
                    name,
                    parent: root.try_clone()?,
                    identity: identity(&child)?,
                    directory: false,
                });
            } else {
                return Err(invalid("unrelated data in owned publication"));
            }
        }
        Ok(())
    }

    fn recover_one(journal: &File, token: &str) -> Result<Option<bool>, ArchiveError> {
        if uuid::Uuid::parse_str(token).is_err() {
            return Err(invalid("foreign publication journal entry"));
        }
        let transaction = dir_at(journal, token)?;
        let metadata = transaction.metadata()?;
        if metadata.uid() != rustix::process::getuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(invalid("foreign publication journal owner"));
        }
        let lock = collection::open_confined_regular_at(&transaction, "lock")?;
        if lock.try_lock().is_err() {
            return Ok(None);
        }
        let owner: Owner = json(&transaction, "owner.json")?;
        if owner.version != 1
            || owner.token != token
            || !owner.parent.is_absolute()
            || owner.name.contains('/')
            || owner.name.is_empty()
            || owner.stage != format!(".crawlx-publication-{token}")
        {
            return Err(invalid("invalid publication owner"));
        }
        super::super::validate_path(&owner.name)?;
        if owner.boot == boot()? && process_start(owner.pid).is_ok_and(|start| start == owner.start) {
            return Ok(None);
        }
        let parent = open_root(&owner.parent)?;
        if identity(&parent)? != owner.parent_identity {
            return Err(invalid("publication parent replaced"));
        }
        let name = if exists(&parent, &owner.stage)? {
            &owner.stage
        } else {
            &owner.name
        };
        if !exists(&parent, name)? {
            remove_transaction(journal, token, &transaction)?;
            return Ok(Some(false));
        }
        let root = dir_at(&parent, name)?;
        let expected: Identity = json(&transaction, "identity.json")?;
        if identity(&root)? != expected {
            return Err(invalid("publication directory replaced"));
        }
        let (members, directories) = planned_paths(&owner.files)?;
        let mut found = Vec::new();
        inventory(&root, "", &members, &directories, &mut found)?;
        if exists(&root, SENTINEL)? {
            let sentinel: (String, String) = json(&root, SENTINEL)?;
            if sentinel != (token.to_owned(), owner.export_id.clone()) {
                return Err(invalid("foreign publication sentinel"));
            }
            if let Ok(manifest) = valid_manifest(&root, Limits::default()) {
                if name == &owner.name
                    && manifest.export_id == owner.export_id
                    && manifest
                        .files
                        .iter()
                        .map(|file| &file.path)
                        .eq(owner.files.iter())
                {
                    if identity(&dir_at(&parent, name)?)? != expected {
                        return Err(invalid("publication directory replaced before commit"));
                    }
                    remove(&root, SENTINEL, false)?;
                    root.sync_all()?;
                    remove_transaction(journal, token, &transaction)?;
                    return Ok(Some(true));
                }
            }
            if identity(&dir_at(&parent, name)?)? != expected {
                return Err(invalid("publication directory replaced before cleanup"));
            }
            for entry in found {
                if entry.relative == SENTINEL {
                    continue;
                }
                let child = if entry.directory {
                    dir_at(&entry.parent, &entry.name)?
                } else {
                    collection::open_confined_regular_at(&entry.parent, &entry.name)?
                };
                if identity(&child)? != entry.identity {
                    return Err(invalid("publication child replaced during cleanup"));
                }
                remove(&entry.parent, &entry.name, entry.directory)?;
                entry.parent.sync_all()?;
            }
            if identity(&dir_at(&parent, name)?)? != expected {
                return Err(invalid("publication directory changed during cleanup"));
            }
            remove(&root, SENTINEL, false)?;
            root.sync_all()?;
            remove(&parent, name, true)?;
            parent.sync_all()?;
            remove_transaction(journal, token, &transaction)?;
            Ok(Some(false))
        } else {
            if found.is_empty() {
                // The only sentinel-free rollback state is an inode-proven empty directory.
                remove(&parent, name, true)?;
                parent.sync_all()?;
                remove_transaction(journal, token, &transaction)?;
                return Ok(Some(false));
            }
            // A crash after commit can leave only the private journal. Never delete a
            // sentinel-free nonempty directory, even when its manifest is now corrupt.
            valid_manifest(&root, Limits::default())?;
            remove_transaction(journal, token, &transaction)?;
            Ok(Some(true))
        }
    }

    pub(super) fn recover(journal: &File) -> Result<RecoveryReport, ArchiveError> {
        let mut report = RecoveryReport::default();
        for token in names(journal)?.into_iter().take(MAX_JOURNALS) {
            match recover_one(journal, &token) {
                Ok(Some(true)) => report.completed += 1,
                Ok(Some(false)) => report.erased += 1,
                Ok(None) | Err(_) => report.refused += 1,
            }
        }
        Ok(report)
    }

    fn guard_directory(mut directory: File, limits: Option<Limits>) -> Result<(), ArchiveError> {
        for _ in 0..256 {
            if exists(&directory, SENTINEL)? {
                return Err(invalid("incomplete native archive publication"));
            }
            if let Some(limits) = limits {
                let has_manifest = exists(&directory, MANIFEST)?;
                let native = exists(&directory, "crawlx/manifest.json")?
                    || (exists(&directory, "archive")? && exists(&directory, "indexes")?);
                if has_manifest || native {
                    valid_manifest(&directory, limits)?;
                }
            }
            let parent = dir_at(&directory, "..")?;
            if identity(&parent)? == identity(&directory)? {
                return Ok(());
            }
            directory = parent;
        }
        Err(ArchiveError::Limit("publication ancestor depth"))
    }

    pub(super) fn guard(path: &Path, limits: Limits) -> Result<(), ArchiveError> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("symlink archive source"));
        }
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = open_root(if metadata.is_dir() { path } else { parent })?;
        guard_directory(directory, Some(limits))
    }

    pub(super) fn open_at(root: &File, relative: &str, limits: Limits) -> Result<File, ArchiveError> {
        super::super::validate_path(relative)?;
        if exists(root, SENTINEL)? {
            return Err(invalid("incomplete native archive publication"));
        }
        let (parent, name) = member_parent(root, relative)?;
        guard_directory(parent.try_clone()?, Some(limits))?;
        let file = collection::open_confined_regular_at(&parent, &name)?;
        // Recheck sentinel state on the same held parent without hashing the bundle twice.
        guard_directory(parent, None)?;
        Ok(file)
    }

    pub(super) fn open_file(path: &Path, limits: Limits) -> Result<File, ArchiveError> {
        if std::fs::symlink_metadata(path)?.is_dir() {
            return open_at(&open_root(path)?, "archive/data.warc.gz", limits);
        }
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("invalid archive filename"))?;
        open_at(&open_root(parent)?, name, limits)
    }
}

/// Publish a new native directory from held anonymous staging files.
///
/// The capture manifest must appear as `crawlx/manifest.json` among `files`. This function
/// adds `publication.json` last and never overwrites an existing output or member. Failed
/// transactions remain journaled and unreadable until an owned recovery pass resolves them.
///
/// # Errors
/// Returns path, bounds, fixity, state-journal or filesystem durability errors. Non-Linux
/// platforms fail closed because descriptor-confined recovery is required.
pub fn publish_bundle(
    out: &Path,
    export_id: &str,
    files: &mut [(String, StagedFile)],
) -> Result<(), ArchiveError> {
    #[cfg(target_os = "linux")]
    {
        platform::publish(out, export_id, files, &platform::journal_root()?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (out, export_id, files);
        Err(ArchiveError::CapabilityUnavailable(
            "native_publication_requires_linux",
        ))
    }
}

/// Resolve at most 256 transactions from the private per-user state journal.
///
/// A held lock and PID/start/boot identity exclude live publishers. Directory inode identity,
/// sentinel ownership and a complete allowlisted inventory precede any deletion. Valid complete
/// fixities roll forward; invalid or incomplete owned publications roll back. Foreign, replaced,
/// symlinked or augmented trees remain untouched. No archive manifest grants deletion authority.
///
/// # Errors
/// Returns errors opening the private journal. Individual unprovable entries are refused and counted.
pub fn recover_owned() -> Result<RecoveryReport, ArchiveError> {
    #[cfg(target_os = "linux")]
    {
        match platform::recovery_root()? {
            Some(root) => platform::recover(&root),
            None => Ok(RecoveryReport::default()),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(RecoveryReport::default())
    }
}

/// Refuse partial native bundles, including attempts to open standalone members inside them.
///
/// Standalone WARC/WACZ files remain supported. A native bundle requires a complete fixity manifest
/// and must have no sentinel, even if its manifest and every listed file already validate.
///
/// # Errors
/// Returns incomplete publication, malformed manifest, aggregate bound, fixity or confined I/O errors.
pub fn ensure_complete(path: &Path, limits: Limits) -> Result<(), ArchiveError> {
    #[cfg(target_os = "linux")]
    {
        platform::guard(path, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, limits);
        Err(ArchiveError::CapabilityUnavailable(
            "native_publication_guard_requires_linux",
        ))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn open_complete_at(root: &File, relative: &str, limits: Limits) -> Result<File, ArchiveError> {
    platform::open_at(root, relative, limits)
}

#[cfg(target_os = "linux")]
pub(crate) fn open_complete_file(path: &Path, limits: Limits) -> Result<File, ArchiveError> {
    platform::open_file(path, limits)
}

#[cfg(any(test, all(feature = "chaos", debug_assertions)))]
#[allow(clippy::unwrap_used)]
fn checkpoint(name: &str) {
    if std::env::var("CRAWLX_PUBLICATION_TEST_STOP").as_deref() == Ok(name) {
        println!("publication checkpoint {name}");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
}
#[cfg(not(any(test, all(feature = "chaos", debug_assertions))))]
fn checkpoint(_name: &str) {}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::io::{BufRead as _, BufReader};
    use std::os::unix::fs::{symlink, DirBuilderExt as _};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    struct Crash {
        temp: tempfile::TempDir,
        child: Child,
    }
    impl Crash {
        fn start(point: &str) -> Self {
            let temp = tempfile::tempdir().unwrap();
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(temp.path().join("journal"))
                .unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "archive::publication::tests::publication_subprocess",
                    "--nocapture",
                ])
                .env("CRAWLX_PUBLICATION_TEST_ROOT", temp.path())
                .env("CRAWLX_PUBLICATION_TEST_STOP", point)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    if line.unwrap().contains("publication checkpoint") {
                        sender.send(()).unwrap();
                        return;
                    }
                }
            });
            let result = Self { temp, child };
            receiver
                .recv_timeout(Duration::from_secs(30))
                .expect("publication checkpoint");
            result
        }
        fn out(&self) -> PathBuf {
            self.temp.path().join("bundle")
        }
        fn journal(&self) -> File {
            collection::open_confined_root(&self.temp.path().join("journal")).unwrap()
        }
        fn kill(&mut self) {
            self.child.kill().unwrap();
            let status = self.child.wait().unwrap();
            use std::os::unix::process::ExitStatusExt as _;
            assert_eq!(status.signal(), Some(9));
        }
        fn recover(&self) -> RecoveryReport {
            platform::recover(&self.journal()).unwrap()
        }
    }
    impl Drop for Crash {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn publication_subprocess() {
        let Some(root) = std::env::var_os("CRAWLX_PUBLICATION_TEST_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let mut files = Vec::new();
        for (name, bytes) in [
            ("archive/data.warc.gz", b"held anonymous archive bytes".as_slice()),
            ("crawlx/manifest.json", b"{}".as_slice()),
            ("indexes/index.cdxj", b"index".as_slice()),
        ] {
            let mut source = StagedFile::new().unwrap();
            source.file_mut().write_all(bytes).unwrap();
            files.push((name.to_owned(), source));
        }
        let journal = collection::open_confined_root(&root.join("journal")).unwrap();
        platform::publish(&root.join("bundle"), "export-1", &mut files, &journal).unwrap();
    }

    #[test]
    fn sigkill_before_manifest_erases_owned_bundle_and_readers_refuse_midpublication() {
        for point in ["sentinel", "member"] {
            let mut crash = Crash::start(point);
            assert!(ensure_complete(&crash.out(), Limits::default())
                .unwrap_err()
                .to_string()
                .contains("incomplete"));
            if point == "member" {
                let member = crash.out().join("archive/data.warc.gz");
                assert!(ensure_complete(&member, Limits::default())
                    .unwrap_err()
                    .to_string()
                    .contains("incomplete"));
                let error = collection::ArchiveCollection::open(&member, None, vec![], Limits::default())
                    .err()
                    .unwrap();
                assert!(error.to_string().contains("incomplete"));
                let dependency = collection::ApprovedLocalDependency::open(
                    "00000000-0000-8000-8000-000000000001".parse().unwrap(),
                    &crash.out(),
                    Path::new("archive/data.warc.gz"),
                    &"0".repeat(64),
                    Limits::default(),
                )
                .err()
                .unwrap();
                assert!(dependency.to_string().contains("incomplete"));
            }
            assert_eq!(crash.recover().refused, 1, "live publisher must not be erased");
            crash.kill();
            assert_eq!(crash.recover().erased, 1);
            assert!(!crash.out().exists());
            assert_eq!(
                std::fs::read_dir(crash.temp.path().join("journal"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }

    #[test]
    fn sigkill_after_manifest_fsync_rolls_forward_only_complete_fixities() {
        let mut crash = Crash::start("manifest");
        assert!(ensure_complete(&crash.out(), Limits::default()).is_err());
        crash.kill();
        assert_eq!(crash.recover().completed, 1);
        assert!(!crash.out().join(SENTINEL).exists());
        ensure_complete(&crash.out(), Limits::default()).unwrap();
        ensure_complete(&crash.out().join("archive/data.warc.gz"), Limits::default()).unwrap();
    }

    #[test]
    fn partial_invalid_missing_manifest_or_bad_fixity_roll_back() {
        for fault in [
            "missing",
            "partial",
            "invalid",
            "missing-file",
            "corrupt-file",
            "traversal",
        ] {
            let mut crash = Crash::start("manifest");
            crash.kill();
            let manifest = crash.out().join(MANIFEST);
            match fault {
                "missing" => std::fs::remove_file(manifest).unwrap(),
                "partial" => std::fs::write(manifest, b"{\"version\":").unwrap(),
                "invalid" => std::fs::write(manifest, b"{}").unwrap(),
                "missing-file" => std::fs::remove_file(crash.out().join("archive/data.warc.gz")).unwrap(),
                "corrupt-file" => {
                    std::fs::write(crash.out().join("archive/data.warc.gz"), b"corrupt").unwrap()
                }
                "traversal" => {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
                    value["files"][0]["path"] = serde_json::Value::String("../unrelated".into());
                    std::fs::write(manifest, serde_json::to_vec(&value).unwrap()).unwrap();
                    std::fs::write(crash.temp.path().join("unrelated"), b"must survive").unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(crash.recover().erased, 1, "{fault}");
            assert!(!crash.out().exists(), "{fault}");
            if fault == "traversal" {
                assert_eq!(
                    std::fs::read(crash.temp.path().join("unrelated")).unwrap(),
                    b"must survive"
                );
            }
        }
    }

    #[test]
    fn recovery_refuses_foreign_symlink_replaced_and_augmented_trees() {
        for fault in ["sentinel", "symlink", "replacement", "extra", "member-symlink"] {
            let mut crash = Crash::start("member");
            crash.kill();
            let out = crash.out();
            match fault {
                "sentinel" => std::fs::write(out.join(SENTINEL), b"[\"foreign\",\"export-1\"]").unwrap(),
                "symlink" => {
                    std::fs::rename(&out, crash.temp.path().join("original")).unwrap();
                    symlink(crash.temp.path().join("original"), &out).unwrap();
                }
                "replacement" => {
                    std::fs::rename(&out, crash.temp.path().join("original")).unwrap();
                    std::fs::create_dir(&out).unwrap();
                    std::fs::write(out.join("unrelated"), b"must survive").unwrap();
                }
                "extra" => std::fs::write(out.join("unrelated"), b"must survive").unwrap(),
                "member-symlink" => {
                    std::fs::remove_file(out.join("archive/data.warc.gz")).unwrap();
                    std::fs::write(crash.temp.path().join("unrelated"), b"must survive").unwrap();
                    symlink(
                        crash.temp.path().join("unrelated"),
                        out.join("archive/data.warc.gz"),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(crash.recover().refused, 1, "{fault}");
            assert!(out.exists(), "{fault}");
        }
    }

    #[test]
    fn missing_manifest_and_any_sentinel_refuse_completed_bundle_members() {
        let mut crash = Crash::start("manifest");
        crash.kill();
        assert_eq!(crash.recover().completed, 1);
        std::fs::remove_file(crash.out().join(MANIFEST)).unwrap();
        assert!(ensure_complete(&crash.out().join("archive/data.warc.gz"), Limits::default()).is_err());
        std::fs::write(crash.out().join(SENTINEL), b"foreign").unwrap();
        assert!(ensure_complete(&crash.out().join("archive/data.warc.gz"), Limits::default()).is_err());
    }

    #[test]
    fn create_new_never_overwrites_existing_destination() {
        let mut crash = Crash::start("manifest");
        crash.kill();
        assert_eq!(crash.recover().completed, 1);
        let original = std::fs::read(crash.out().join("archive/data.warc.gz")).unwrap();
        let mut files = Vec::new();
        for name in ["archive/data.warc.gz", "crawlx/manifest.json"] {
            let mut source = StagedFile::new().unwrap();
            source.file_mut().write_all(b"replacement").unwrap();
            files.push((name.to_owned(), source));
        }
        assert!(platform::publish(&crash.out(), "export-2", &mut files, &crash.journal()).is_err());
        assert_eq!(
            std::fs::read(crash.out().join("archive/data.warc.gz")).unwrap(),
            original
        );
    }
}
