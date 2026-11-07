//! Tenant-bound, root-confined local dependency bundles and one shared offline collection reader.
//!
//! Dependencies are explicit file capabilities pinned by SHA-256. Record IDs and URLs never open files
//! or sockets. Missing local records remain unavailable; no HTTP dependency fallback exists.

use super::{
    cdxj,
    resolver::{Catalog, RecordLocation, ResolvedPayload},
    wacz, warc, ArchiveError, Limits,
};
use crawlx_core::TenantId;
use flate2::{Compression, GzBuilder};
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use zip::ZipArchive;

/// Explicit tenant-bound authority to read one SHA-256-pinned local dependency file.
/// Fields stay private so consumers cannot turn a WARC record URI into filesystem authority.
pub struct ApprovedLocalDependency {
    tenant: TenantId,
    file: File,
    hash: String,
    seal: FileSeal,
}

#[derive(Clone, PartialEq, Eq)]
struct FileSeal {
    length: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    identity: (u64, u64),
    #[cfg(unix)]
    changed: (i64, i64),
}
impl FileSeal {
    fn capture(file: &File) -> Result<Self, ArchiveError> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(ArchiveError::Invalid("archive source is not a regular file"));
        }
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            identity: (metadata.dev(), metadata.ino()),
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
    fn check(&self, file: &File) -> Result<(), ArchiveError> {
        if Self::capture(file)? != *self {
            return Err(ArchiveError::Invalid("approved archive source changed"));
        }
        Ok(())
    }
}

fn file_hash(file: &mut File, limit: u64) -> Result<(String, FileSeal), ArchiveError> {
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit {
        return Err(ArchiveError::Limit("dependency input bytes"));
    }
    let seal = FileSeal::capture(file)?;
    file.rewind()?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 32 * 1024];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or(ArchiveError::Limit("dependency input bytes"))?;
        if count > limit {
            return Err(ArchiveError::Limit("dependency input bytes"));
        }
        hash.update(&buffer[..n]);
    }
    file.rewind()?;
    seal.check(file)?;
    Ok((format!("sha256:{}", hex::encode(hash.finalize())), seal))
}

/// Open a regular file beneath an authorized root without following symlinks or blocking on FIFOs.
///
/// # Errors
/// Preserves operating-system I/O errors, including `NotFound`; invalid paths and special files fail closed.
#[cfg(target_os = "linux")]
pub(crate) fn open_confined_regular(root: &Path, relative: &str) -> std::io::Result<File> {
    open_confined_regular_at(&open_confined_root(root)?, relative)
}

/// Pin an authorized directory without following its final path component.
///
/// # Errors
/// Preserves operating-system errors; symlinked or non-directory roots are refused.
#[cfg(target_os = "linux")]
pub(crate) fn open_confined_root(root: &Path) -> std::io::Result<File> {
    use rustix::fs::{open, Mode, OFlags};
    open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
}

/// Open a regular child beneath an already-pinned root descriptor.
///
/// # Errors
/// Preserves operating-system errors; traversal, symlinks and special files are refused.
#[cfg(target_os = "linux")]
pub(crate) fn open_confined_regular_at(root: &File, relative: &str) -> std::io::Result<File> {
    use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
    super::validate_path(relative).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid confined relative path")
    })?;
    let file = openat2(
        root,
        relative,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(file);
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "confined source is not a regular file",
        ));
    }
    Ok(file)
}
#[cfg(target_os = "linux")]
fn confined_file(root: &Path, relative: &str) -> Result<File, ArchiveError> {
    open_confined_regular(root, relative).map_err(ArchiveError::Io)
}
#[cfg(not(target_os = "linux"))]
fn confined_file(_root: &Path, _relative: &str) -> Result<File, ArchiveError> {
    Err(ArchiveError::CapabilityUnavailable(
        "root_confined_dependency_requires_linux_openat2",
    ))
}

impl ApprovedLocalDependency {
    /// Approve one relative local file under the caller's authorized directory capability.
    ///
    /// The caller supplies tenant authority; API callers must derive it from authentication.
    /// SHA-256 pins the complete source file before any parser staging. Symlinks, traversal,
    /// special files and remote endpoints are refused, including races beneath the opened root.
    ///
    /// # Errors
    /// Returns capability, path, size, file fixity or I/O errors. Never performs network access.
    pub fn open(
        tenant: TenantId,
        root: &Path,
        relative: &Path,
        expected_sha256: &str,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        let relative = relative
            .to_str()
            .ok_or(ArchiveError::Invalid("dependency path is not UTF8"))?;
        if relative.contains("://") {
            return Err(ArchiveError::CapabilityUnavailable(
                "external_http_dependency_unavailable_no_network_fallback",
            ));
        }
        super::validate_path(relative)?;
        let expected = expected_sha256.strip_prefix("sha256:").unwrap_or(expected_sha256);
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ArchiveError::Invalid("dependency requires an exact SHA-256 pin"));
        }
        let mut file = confined_file(root, relative)?;
        let (hash, seal) = file_hash(&mut file, limits.total_bytes)?;
        if !hash[7..].eq_ignore_ascii_case(expected) {
            return Err(ArchiveError::Invalid("dependency file fixity mismatch"));
        }
        check_native_tenant(&mut file, Some(tenant), limits)?;
        seal.check(&file)?;
        Ok(Self {
            tenant,
            file,
            hash,
            seal,
        })
    }

    /// Admitted encoded source length, for monotonic caller budgets before approving more files.
    #[must_use]
    pub const fn encoded_bytes(&self) -> u64 {
        self.seal.length
    }
}

fn is_zip(file: &mut File) -> Result<bool, ArchiveError> {
    file.rewind()?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    file.rewind()?;
    Ok(magic == *b"PK\x03\x04")
}
fn check_native_tenant(
    file: &mut File,
    tenant: Option<TenantId>,
    limits: Limits,
) -> Result<(), ArchiveError> {
    if !is_zip(file)? {
        return Ok(());
    }
    let (mut zip, _) = wacz::open_zip(&mut *file, limits)?;
    if zip.len() > limits.resources + 2 {
        return Err(ArchiveError::Limit("dependency ZIP resources"));
    }
    if wacz::native_tenant(&mut zip, limits)?
        .is_some_and(|owner| tenant.is_some_and(|tenant| owner != tenant))
    {
        return Err(ArchiveError::Invalid("dependency native tenant mismatch"));
    }
    drop(zip);
    file.rewind()?;
    Ok(())
}

enum SourceContent {
    Wacz {
        zip: ZipArchive<File>,
        inspection: wacz::Inspection,
    },
    Warc {
        file: File,
        compressed: bool,
        records: Vec<warc::RecordSummary>,
    },
}
struct Source {
    content: SourceContent,
    hash: String,
    bytes: u64,
    guard: File,
    seal: FileSeal,
}

fn read_block(
    sources: &mut [Source],
    location: &RecordLocation,
    limits: Limits,
) -> Result<Vec<u8>, ArchiveError> {
    let source = sources
        .get_mut(location.source)
        .ok_or(ArchiveError::Invalid("record source unavailable"))?;
    source.seal.check(&source.guard)?;
    let bytes = match &mut source.content {
        SourceContent::Wacz { zip, .. } => {
            wacz::block_in_zip(zip, &location.filename, &location.record, limits)
        }
        SourceContent::Warc { file, compressed, .. } => {
            if !location.filename.is_empty() {
                return Err(ArchiveError::Invalid("standalone member namespace mismatch"));
            }
            warc::block_at(file, &location.record, *compressed, limits)
        }
    }?;
    source.seal.check(&source.guard)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn sealed_snapshot(bytes: &[u8]) -> Result<File, ArchiveError> {
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
    let fd = memfd_create(
        "crawlx-archive-snapshot",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(|_| ArchiveError::CapabilityUnavailable("sealed_archive_snapshot_unavailable"))?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )
    .map_err(|_| ArchiveError::CapabilityUnavailable("immutable_archive_snapshot_unavailable"))?;
    file.rewind()?;
    Ok(file)
}
#[cfg(not(target_os = "linux"))]
fn sealed_snapshot(_bytes: &[u8]) -> Result<File, ArchiveError> {
    Err(ArchiveError::CapabilityUnavailable(
        "sealed_archive_snapshot_requires_linux_memfd",
    ))
}

/// Fully closed, bounded offline record graph over already-open local sources.
/// Keeps only record descriptors and open readers; never buffers a collection's payloads.
pub struct ArchiveCollection {
    sources: Vec<Source>,
    catalog: Catalog,
    limits: Limits,
    tenant: Option<TenantId>,
}

impl ArchiveCollection {
    fn primary_budget(
        tenant: Option<TenantId>,
        dependencies: &[ApprovedLocalDependency],
        limits: Limits,
    ) -> Result<u64, ArchiveError> {
        if dependencies.len() >= limits.resources {
            return Err(ArchiveError::Limit("dependency source count"));
        }
        if !dependencies.is_empty() && tenant.is_none() {
            return Err(ArchiveError::Invalid(
                "explicit dependency bundles require tenant authority",
            ));
        }
        if dependencies
            .iter()
            .any(|dependency| Some(dependency.tenant) != tenant)
        {
            return Err(ArchiveError::Invalid("dependency tenant authority mismatch"));
        }
        let bytes = dependencies.iter().try_fold(0u64, |bytes, dependency| {
            bytes
                .checked_add(dependency.encoded_bytes())
                .ok_or(ArchiveError::Limit("dependency encoded bytes"))
        })?;
        limits
            .total_bytes
            .checked_sub(bytes)
            .ok_or(ArchiveError::Limit("collection encoded bytes"))
    }

    /// Open and validate a local primary archive plus explicitly approved dependency files.
    ///
    /// Closure spans WARC files inside WACZ and these explicit bundles only. A dependency URI
    /// never authorizes a read. Tenant mismatches, ambiguous record IDs, missing records, loops,
    /// malformed segments, digest mismatches and dangling CDX ranges fail before returning.
    ///
    /// # Errors
    /// Returns bounded format, custody, path, privacy-authority, dependency or I/O errors.
    pub fn open(
        primary: &Path,
        tenant: Option<TenantId>,
        dependencies: Vec<ApprovedLocalDependency>,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        if primary.to_str().is_some_and(|path| path.contains("://")) {
            return Err(ArchiveError::CapabilityUnavailable(
                "external_http_dependency_unavailable_no_network_fallback",
            ));
        }
        let budget = Self::primary_budget(tenant, &dependencies, limits)?;
        let mut primary = regular_primary(primary)?;
        check_native_tenant(&mut primary, tenant, limits)?;
        let (hash, seal) = file_hash(&mut primary, budget)?;
        Self::build(primary, hash, seal, tenant, dependencies, limits)
    }

    /// Validate an owned immutable in-memory archive without writing raw content to disk.
    ///
    /// The source becomes a Linux anonymous memfd sealed against writes, growth, shrink and
    /// seal removal. WACZ validation streams members directly; no extraction spool exists.
    ///
    /// # Errors
    /// Returns the same validation errors as [`Self::open`], source bounds, or a missing memfd capability.
    pub fn from_snapshot(
        snapshot: Vec<u8>,
        tenant: Option<TenantId>,
        dependencies: Vec<ApprovedLocalDependency>,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        let budget = Self::primary_budget(tenant, &dependencies, limits)?;
        if snapshot.len() as u64 > budget {
            return Err(ArchiveError::Limit("archive snapshot bytes"));
        }
        let hash = warc::digest(&snapshot);
        let primary = sealed_snapshot(&snapshot)?;
        drop(snapshot);
        let seal = FileSeal::capture(&primary)?;
        Self::build(primary, hash, seal, tenant, dependencies, limits)
    }

    fn build(
        mut primary: File,
        hash: String,
        seal: FileSeal,
        tenant: Option<TenantId>,
        dependencies: Vec<ApprovedLocalDependency>,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        check_native_tenant(&mut primary, tenant, limits)?;
        let mut inputs = vec![(primary, hash, seal)];
        for dependency in dependencies {
            inputs.push((dependency.file, dependency.hash, dependency.seal));
        }
        let mut sources = Vec::with_capacity(inputs.len());
        let mut entries = Vec::new();
        let mut encoded = 0u64;
        let mut expanded = 0u64;
        let mut resources = 0usize;
        for (mut file, hash, seal) in inputs {
            seal.check(&file)?;
            let guard = file.try_clone()?;
            let bytes = file.metadata()?.len();
            encoded = encoded
                .checked_add(bytes)
                .ok_or(ArchiveError::Limit("collection encoded bytes"))?;
            if encoded > limits.total_bytes {
                return Err(ArchiveError::Limit("collection encoded bytes"));
            }
            let mut remaining = limits;
            remaining.expanded_bytes = limits
                .expanded_bytes
                .checked_sub(expanded)
                .ok_or(ArchiveError::Limit("collection expanded bytes"))?;
            remaining.records = limits
                .records
                .checked_sub(
                    u32::try_from(entries.len())
                        .map_err(|_| ArchiveError::Limit("collection record count"))?,
                )
                .ok_or(ArchiveError::Limit("collection record count"))?;
            let source = sources.len();
            let content = if is_zip(&mut file)? {
                let inspection = wacz::inspect_fragment(&mut file, remaining)?;
                if inspection
                    .tenant
                    .is_some_and(|owner| tenant.is_some_and(|tenant| owner != tenant))
                {
                    return Err(ArchiveError::Invalid("archive tenant mismatch"));
                }
                resources = resources
                    .checked_add(inspection.resources.len())
                    .ok_or(ArchiveError::Limit("collection resources"))?;
                if resources > limits.resources {
                    return Err(ArchiveError::Limit("collection resources"));
                }
                for resource in &inspection.resources {
                    expanded = expanded
                        .checked_add(resource.bytes)
                        .ok_or(ArchiveError::Limit("collection expanded bytes"))?;
                }
                entries.extend(wacz::locations(&inspection, source));
                SourceContent::Wacz {
                    zip: wacz::open_zip(file, remaining)?.0,
                    inspection,
                }
            } else {
                let mut magic = [0u8; 2];
                file.read_exact(&mut magic)?;
                file.rewind()?;
                let compressed = magic == [0x1f, 0x8b];
                let records = warc::scan(&mut file, compressed, remaining)?;
                entries.extend(records.iter().cloned().map(|record| RecordLocation {
                    source,
                    filename: String::new(),
                    record,
                }));
                SourceContent::Warc {
                    file,
                    compressed,
                    records,
                }
            };
            for location in entries.iter().filter(|entry| entry.source == source) {
                expanded = expanded
                    .checked_add(location.record.uncompressed_length)
                    .ok_or(ArchiveError::Limit("collection expanded bytes"))?;
            }
            if expanded > limits.expanded_bytes {
                return Err(ArchiveError::Limit("collection expanded bytes"));
            }
            seal.check(&guard)?;
            sources.push(Source {
                content,
                hash,
                bytes,
                guard,
                seal,
            });
        }
        let mut catalog = Catalog::new(entries, limits)?;
        catalog.validate(&mut |location| read_block(&mut sources, location, limits))?;
        for (index, source) in sources.iter_mut().enumerate() {
            match &mut source.content {
                SourceContent::Wacz { zip, inspection } => {
                    wacz::normalize(inspection, &catalog, index)?;
                    inspection.indexed = wacz::validate_indexes(zip, inspection, limits)?;
                }
                SourceContent::Warc { records, .. } => {
                    for record in records {
                        *record = catalog.location(&record.id)?.record.clone();
                    }
                }
            }
        }
        for source in &sources {
            source.seal.check(&source.guard)?;
        }
        Ok(Self {
            sources,
            catalog,
            limits,
            tenant,
        })
    }

    /// Record descriptors in primary/dependency, filename and physical member order.
    #[must_use]
    pub fn records(&self) -> Vec<RecordLocation> {
        let mut records = self.catalog.locations().cloned().collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.source
                .cmp(&right.source)
                .then(left.filename.cmp(&right.filename))
                .then(left.record.offset.cmp(&right.record.offset))
        });
        records
    }

    /// Primary WACZ package metadata; absent for standalone WARC.
    #[must_use]
    pub fn primary_package(&self) -> Option<&wacz::Inspection> {
        match self.sources.first().map(|source| &source.content) {
            Some(SourceContent::Wacz { inspection, .. }) => Some(inspection),
            _ => None,
        }
    }

    /// Whether raw container bytes omit opaque comments/extensions/gaps and may enter the copy gate.
    #[must_use]
    pub fn raw_copy_approved(&self) -> bool {
        self.primary_package()
            .is_none_or(|package| package.zip_metadata_retention_approved)
    }

    /// Resolve a physical member to its full logical payload and actual baseline provenance.
    ///
    /// # Errors
    /// Returns bounded materialization, fixity or I/O errors. Missing bytes never trigger network access.
    pub fn payload(&mut self, record_id: &str) -> Result<ResolvedPayload, ArchiveError> {
        let limits = self.limits;
        let sources = &mut self.sources;
        self.catalog
            .materialize(record_id, &mut |location| read_block(sources, location, limits))
    }

    /// Whether all stored physical records satisfy the conservative text-only import gate.
    #[must_use]
    pub fn retention_approved(&self) -> bool {
        self.catalog
            .locations()
            .all(|entry| entry.record.retention_approved)
    }

    /// Number of approved external source bundles, excluding the primary archive.
    #[must_use]
    pub fn dependency_count(&self) -> usize {
        self.sources.len().saturating_sub(1)
    }

    /// Whole-file SHA-256 of the immutable or mutation-guarded primary source.
    #[must_use]
    pub fn primary_sha256(&self) -> &str {
        &self.sources[0].hash
    }

    /// Whole-file SHA-256 pins in primary-then-explicit-dependency order.
    pub fn source_sha256(&self) -> impl Iterator<Item = &str> {
        self.sources.iter().map(|source| source.hash.as_str())
    }

    /// Stream primary package metadata through a caller's privacy gate using the same approved handle.
    ///
    /// Archive WARC resources are excluded; they already have record-level privacy classification.
    ///
    /// # Errors
    /// Returns callback, input-mutation or ZIP errors. Never reopens a caller-controlled pathname.
    pub fn primary_metadata(
        &mut self,
        check: &mut impl FnMut(&str, &mut dyn Read) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        if !self.raw_copy_approved() {
            return Err(ArchiveError::CapabilityUnavailable(
                "opaque_zip_metadata_requires_closed_rewrite",
            ));
        }
        let source = self
            .sources
            .first_mut()
            .ok_or(ArchiveError::Invalid("primary archive unavailable"))?;
        source.seal.check(&source.guard)?;
        if let SourceContent::Wacz { zip, .. } = &mut source.content {
            for index in 0..zip.len() {
                let mut entry = zip.by_index(index)?;
                let name = entry.name()?.into_owned();
                if !name.starts_with("archive/") {
                    check(&name, &mut entry)?;
                }
            }
        }
        source.seal.check(&source.guard)?;
        Ok(())
    }

    /// Copy the exact approved primary bytes after the caller's content/metadata privacy gate.
    ///
    /// # Errors
    /// Returns source mutation/fixity, output bounds or I/O errors. Callers must publish atomically.
    pub fn copy_primary<W: Write>(&mut self, output: &mut W) -> Result<u64, ArchiveError> {
        if !self.raw_copy_approved() || !self.retention_approved() {
            return Err(ArchiveError::CapabilityUnavailable(
                "raw_archive_copy_not_retention_approved",
            ));
        }
        let source = self
            .sources
            .first_mut()
            .ok_or(ArchiveError::Invalid("primary archive unavailable"))?;
        source.seal.check(&source.guard)?;
        let position = source.guard.stream_position()?;
        source.guard.rewind()?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 32 * 1024];
        let mut count = 0u64;
        loop {
            let n = source.guard.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            count = count
                .checked_add(n as u64)
                .ok_or(ArchiveError::Limit("primary copy bytes"))?;
            if count > self.limits.total_bytes {
                return Err(ArchiveError::Limit("primary copy bytes"));
            }
            hash.update(&buffer[..n]);
            output.write_all(&buffer[..n])?;
        }
        source.guard.seek(SeekFrom::Start(position))?;
        source.seal.check(&source.guard)?;
        if count != source.bytes || format!("sha256:{}", hex::encode(hash.finalize())) != source.hash {
            return Err(ArchiveError::Invalid("primary source changed while copying"));
        }
        Ok(count)
    }

    /// Build a self-contained WACZ with every physical dependency member and regenerated indexes.
    ///
    /// The caller supplies private retention-approved scratch storage and atomically publishes the
    /// returned completed output. Physical WARC members remain intact; no chronological event is
    /// deduplicated. Plain WARC records gain independent gzip framing without rewriting their bytes.
    ///
    /// # Errors
    /// Refuses unapproved content, missing tenant authority, limits, source mutation or I/O failures.
    pub fn write_closed_wacz<W: Write + Seek>(
        &mut self,
        output: W,
        scratch: &Path,
    ) -> Result<W, ArchiveError> {
        if !self.retention_approved() {
            return Err(ArchiveError::CapabilityUnavailable(
                "dependency_content_not_retention_approved",
            ));
        }
        let tenant = self.tenant.ok_or(ArchiveError::Invalid(
            "closed dependency import requires tenant authority",
        ))?;
        let warc_path = scratch.join("data.warc.gz");
        let index_path = scratch.join("index.cdxj");
        let pages_path = scratch.join("pages.jsonl");
        let closure_path = scratch.join("dependency-closure.json");
        let mut data = File::create(&warc_path)?;
        let mut pages = File::create(&pages_path)?;
        pages.write_all(b"{\"format\":\"json-pages-1.0\",\"id\":\"pages\",\"title\":\"Imported closed archive resources\"}\n")?;
        let mut sorter = cdxj::Sorter::new()?;
        let records = self.records();
        for location in &records {
            let offset = data.stream_position()?;
            let source = self
                .sources
                .get_mut(location.source)
                .ok_or(ArchiveError::Invalid("record source unavailable"))?;
            source.seal.check(&source.guard)?;
            match &mut source.content {
                SourceContent::Wacz { zip, .. } => {
                    let mut member = zip.by_name_seek(&location.filename)?;
                    copy_member(
                        &mut member,
                        &location.record,
                        location.filename.ends_with(".gz"),
                        &mut data,
                    )?;
                }
                SourceContent::Warc { file, compressed, .. } => {
                    copy_member(file, &location.record, *compressed, &mut data)?
                }
            }
            source.seal.check(&source.guard)?;
            let end = data.stream_position()?;
            if end > self.limits.total_bytes {
                return Err(ArchiveError::Limit("closed archive bytes"));
            }
            let mut record = location.record.clone();
            record.offset = offset;
            record.length = end
                .checked_sub(offset)
                .ok_or(ArchiveError::Limit("member range"))?;
            if matches!(
                record.record_type.as_str(),
                "response" | "resource" | "conversion" | "revisit"
            ) && record.segment_number.is_none_or(|number| number == 1)
            {
                sorter.push(cdxj::Entry::from_record(&record, "data.warc.gz")?.line(&record)?)?;
                if let Some(url) = record.target.as_ref() {
                    serde_json::to_writer(
                        &mut pages,
                        &serde_json::json!({"id":record.id,"url":url,"ts":warc::date(record.date)}),
                    )?;
                    pages.write_all(b"\n")?;
                }
            }
        }
        data.flush()?;
        pages.flush()?;
        sorter.finish(&mut File::create(&index_path)?)?;
        serde_json::to_writer(
            File::create(&closure_path)?,
            &serde_json::json!({"schemaVersion":1,"tenant":tenant,
            "complete":false,"sources":self.sources.iter().map(|source| serde_json::json!({"hash":source.hash,"bytes":source.bytes})).collect::<Vec<_>>(),
            "omissions":["source_package_metadata_not_copied","original_capture_completeness_unproven"],"networkAccess":false}),
        )?;
        let created = records
            .iter()
            .map(|location| location.record.date)
            .min()
            .ok_or(ArchiveError::Invalid("empty closed archive"))?;
        wacz::write(
            output,
            &[
                ("archive/data.warc.gz".into(), warc_path),
                ("indexes/index.cdxj".into(), index_path),
                ("pages/pages.jsonl".into(), pages_path),
                ("crawlx/dependency-closure.json".into(), closure_path),
            ],
            &warc::date(created),
            self.limits,
        )
    }
}

fn copy_member<R: Read + Seek, W: Write>(
    input: &mut R,
    record: &warc::RecordSummary,
    compressed: bool,
    output: &mut W,
) -> Result<(), ArchiveError> {
    input.seek(SeekFrom::Start(record.offset))?;
    let mut range = input.take(record.length);
    let copied = if compressed {
        std::io::copy(&mut range, output)?
    } else {
        let mut member = GzBuilder::new().mtime(0).write(output, Compression::default());
        let copied = std::io::copy(&mut range, &mut member)?;
        member.finish()?;
        copied
    };
    if copied != record.length {
        return Err(ArchiveError::Invalid("source member changed while importing"));
    }
    Ok(())
}

#[cfg(unix)]
fn regular_primary(path: &Path) -> Result<File, ArchiveError> {
    use rustix::fs::{open, Mode, OFlags};
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ArchiveError::Io(std::io::Error::from(error)))?;
    let file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(ArchiveError::Invalid("primary archive is not a regular file"));
    }
    Ok(file)
}
#[cfg(not(unix))]
fn regular_primary(_path: &Path) -> Result<File, ArchiveError> {
    Err(ArchiveError::CapabilityUnavailable(
        "safe_regular_archive_file_authority_unavailable",
    ))
}
