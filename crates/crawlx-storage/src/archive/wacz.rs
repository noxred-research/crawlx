//! WACZ 1.1.1 package construction and hostile-input validation. No replay or live refetch.

use super::{cdxj, validate_path, warc, ArchiveError, Limits};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

/// WACZ resource fixity. Manifest and manifest-digest are excluded to avoid self-reference.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    /// Resource basename.
    pub name: String,
    /// Validated relative package path.
    pub path: String,
    /// SHA-256 of the resource's uncompressed ZIP bytes.
    pub hash: String,
    /// Uncompressed ZIP resource length (gzip WARC bytes remain compressed here).
    pub bytes: u64,
}

/// Normative WACZ datapackage fields plus crawlx capture omissions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataPackage {
    /// Always data-package.
    pub profile: String,
    /// Always 1.1.1 for this writer.
    pub wacz_version: String,
    /// Every data resource in this ZIP.
    pub resources: Vec<Resource>,
    /// Human-readable description.
    #[serde(default)]
    pub title: String,
    /// Actual retained source time, not a fabricated recrawl time.
    #[serde(default)]
    pub created: String,
    /// Native codec provenance.
    #[serde(default)]
    pub software: String,
}

/// Fully validated offline package descriptors.
#[derive(Clone, Debug, Serialize)]
pub struct Inspection {
    /// Pinned format version.
    pub format: String,
    /// Every validated data resource.
    pub resources: Vec<Resource>,
    /// Records, grouped by their actual WARC member filename.
    pub records: BTreeMap<String, Vec<warc::RecordSummary>>,
    /// Validated CDXJ range count.
    pub indexed: u64,
    /// Validated page entry-point count.
    pub pages: u64,
    /// Native tenant binding when the package carries a crawlx manifest.
    pub tenant: Option<crawlx_core::TenantId>,
    /// Native source run, when present.
    pub run: Option<crawlx_core::CrawlRunId>,
    /// Whether opaque ZIP metadata is absent and an immutable raw copy may pass the text import gate.
    pub zip_metadata_retention_approved: bool,
}

fn stream_hash(
    input: &mut impl Read,
    output: &mut impl Write,
    max: u64,
) -> Result<(u64, String), ArchiveError> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 32 * 1024];
    let mut size = 0u64;
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        size = size
            .checked_add(n as u64)
            .ok_or(ArchiveError::Limit("resource bytes"))?;
        if size > max {
            return Err(ArchiveError::Limit("resource bytes"));
        }
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    Ok((size, format!("sha256:{}", hex::encode(hash.finalize()))))
}

/// Build a deterministic ZIP64-capable WACZ. All resources precede the final manifest pair.
///
/// The caller publishes the completed file atomically only after this function succeeds.
/// Files must already be retention approved. No collection-sized buffer is allocated.
///
/// # Errors
/// Rejects unsafe/duplicate paths, missing normative resources, limits or source/output errors.
pub fn write<W: Write + Seek>(
    output: W,
    files: &[(String, PathBuf)],
    created: &str,
    limits: Limits,
) -> Result<W, ArchiveError> {
    if files.len() > limits.resources {
        return Err(ArchiveError::Limit("ZIP resource count"));
    }
    let mut zip = ZipWriter::new(output);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o600)
        .large_file(true);
    let mut resources = Vec::with_capacity(files.len());
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    for (path, source) in files {
        validate_path(path)?;
        if matches!(path.as_str(), "datapackage.json" | "datapackage-digest.json")
            || !paths.insert(path.as_str())
        {
            return Err(ArchiveError::Invalid("duplicate or reserved resource path"));
        }
        zip.start_file(path, options)?;
        let (bytes, hash) = stream_hash(&mut File::open(source)?, &mut zip, limits.total_bytes)?;
        total = total
            .checked_add(bytes)
            .ok_or(ArchiveError::Limit("package bytes"))?;
        if total > limits.total_bytes {
            return Err(ArchiveError::Limit("package bytes"));
        }
        resources.push(Resource {
            name: path
                .rsplit('/')
                .next()
                .ok_or(ArchiveError::Invalid("invalid resource path"))?
                .into(),
            path: path.clone(),
            hash,
            bytes,
        });
    }
    if !paths.contains("pages/pages.jsonl")
        || !paths.iter().any(|p| p.starts_with("archive/"))
        || !paths.iter().any(|p| p.starts_with("indexes/"))
    {
        return Err(ArchiveError::Invalid("missing WACZ required resource"));
    }
    resources.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = DataPackage {
        profile: "data-package".into(),
        wacz_version: "1.1.1".into(),
        resources,
        title: "crawlx retained representations (not a complete wire capture)".into(),
        created: created.into(),
        software: concat!(
            "crawlx ",
            env!("CARGO_PKG_VERSION"),
            " native offline archive codec"
        )
        .into(),
    };
    let bytes = serde_json::to_vec(&manifest)?;
    zip.start_file("datapackage.json", options)?;
    zip.write_all(&bytes)?;
    zip.start_file("datapackage-digest.json", options)?;
    serde_json::to_writer(
        &mut zip,
        &serde_json::json!({"path":"datapackage.json", "hash":warc::digest(&bytes)}),
    )?;
    let mut output = zip.finish()?;
    if output.stream_position()? > limits.total_bytes {
        return Err(ArchiveError::Limit("package encoded bytes"));
    }
    output.flush()?;
    Ok(output)
}

fn bounded_read<R: Read>(input: R, max: u64) -> Result<Vec<u8>, ArchiveError> {
    let mut bytes = Vec::new();
    input.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(ArchiveError::Limit("metadata bytes"));
    }
    Ok(bytes)
}
fn read_json<R: Read, T: serde::de::DeserializeOwned>(input: R, max: u64) -> Result<T, ArchiveError> {
    Ok(serde_json::from_slice(&bounded_read(input, max)?)?)
}

fn pages<R: BufRead>(
    mut reader: R,
    limits: Limits,
    targets: &BTreeSet<(String, chrono::DateTime<chrono::Utc>)>,
) -> Result<u64, ArchiveError> {
    let mut count = 0u64;
    let mut first = true;
    loop {
        let mut line = Vec::new();
        loop {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                break;
            }
            let n = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |v| v + 1);
            if line.len().saturating_add(n) as u64 > limits.record_bytes {
                return Err(ArchiveError::Limit("page line bytes"));
            }
            line.extend_from_slice(&available[..n]);
            reader.consume(n);
            if line.ends_with(b"\n") {
                break;
            }
        }
        if line.is_empty() {
            break;
        }
        let row: serde_json::Value = serde_json::from_slice(&line)?;
        if first && row.get("format").and_then(serde_json::Value::as_str) == Some("json-pages-1.0") {
            first = false;
            continue;
        }
        first = false;
        let url = row
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or(ArchiveError::Invalid("page URL missing"))?;
        url::Url::parse(url).map_err(|_| ArchiveError::Invalid("invalid page URL"))?;
        let date = chrono::DateTime::parse_from_rfc3339(
            row.get("ts")
                .and_then(serde_json::Value::as_str)
                .ok_or(ArchiveError::Invalid("page capture date missing"))?,
        )
        .map_err(|_| ArchiveError::Invalid("invalid page capture date"))?
        .with_timezone(&chrono::Utc);
        if !targets.contains(&(url.to_owned(), date)) {
            return Err(ArchiveError::Invalid("page entry point has no archived resource"));
        }
        count += 1;
        if count > u64::from(limits.records) {
            return Err(ArchiveError::Limit("page count"));
        }
    }
    Ok(count)
}

/// Validate a WACZ, all fixities, every WARC member and all index ranges before returning.
///
/// Validation streams fixity and ZIP members without extracting content to disk. Nothing executes content.
///
/// # Errors
/// Rejects hostile paths, bombs, malformed resources, fixity/range/dependency mismatches or limits.
pub fn inspect<R: Read + Seek>(mut input: R, limits: Limits) -> Result<Inspection, ArchiveError> {
    let mut inspection = inspect_fragment(&mut input, limits)?;
    let mut catalog = super::resolver::Catalog::new(locations(&inspection, 0), limits)?;
    let (mut zip, _) = open_zip(&mut input, limits)?;
    catalog.validate(&mut |location| block_in_zip(&mut zip, &location.filename, &location.record, limits))?;
    normalize(&mut inspection, &catalog, 0)?;
    inspection.indexed = validate_indexes(&mut zip, &inspection, limits)?;
    Ok(inspection)
}

pub(super) fn inspect_fragment<R: Read + Seek>(
    mut input: R,
    limits: Limits,
) -> Result<Inspection, ArchiveError> {
    let length = input.seek(SeekFrom::End(0))?;
    if length > limits.total_bytes {
        return Err(ArchiveError::Limit("ZIP input bytes"));
    }
    input.seek(SeekFrom::Start(0))?;
    let (mut zip, zip_metadata_retention_approved) = open_zip(input, limits)?;
    if zip.len() > limits.resources + 2 {
        return Err(ArchiveError::Limit("ZIP resource count"));
    }
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        let name = entry.name()?.into_owned();
        validate_path(&name)?;
        if !names.insert(name.clone()) {
            return Err(ArchiveError::Invalid("duplicate ZIP path"));
        }
        if entry.is_dir() || entry.unix_mode().is_some_and(|mode| mode & 0o170000 == 0o120000) {
            return Err(ArchiveError::Invalid("ZIP directory or symlink forbidden"));
        }
        // Small metadata gets 1 MiB slack; larger DEFLATE resources may expand at most 128-fold.
        if entry.size() > limits.total_bytes
            || entry.size()
                > entry
                    .compressed_size()
                    .saturating_mul(128)
                    .saturating_add(1_048_576)
        {
            return Err(ArchiveError::Limit("ZIP expansion ratio"));
        }
        if (name.starts_with("archive/") || name.ends_with(".cdx.gz"))
            && entry.compression() != CompressionMethod::Stored
        {
            return Err(ArchiveError::Invalid(
                "compressed archive resources must use ZIP STORE",
            ));
        }
        total = total
            .checked_add(entry.size())
            .ok_or(ArchiveError::Limit("ZIP expanded bytes"))?;
        if total > limits.expanded_bytes {
            return Err(ArchiveError::Limit("ZIP expanded bytes"));
        }
    }
    let manifest_bytes = bounded_read(zip.by_name("datapackage.json")?, limits.record_bytes)?;
    let manifest: DataPackage = serde_json::from_slice(&manifest_bytes)?;
    if manifest.profile != "data-package"
        || manifest.wacz_version != "1.1.1"
        || manifest.resources.len() > limits.resources
    {
        return Err(ArchiveError::Invalid("unsupported WACZ manifest"));
    }
    let fixity: serde_json::Value = read_json(zip.by_name("datapackage-digest.json")?, limits.header_bytes)?;
    if fixity.get("path").and_then(serde_json::Value::as_str) != Some("datapackage.json")
        || fixity.get("hash").and_then(serde_json::Value::as_str)
            != Some(warc::digest(&manifest_bytes).as_str())
    {
        return Err(ArchiveError::Invalid("WACZ manifest fixity mismatch"));
    }
    let mut listed = BTreeSet::new();
    for resource in &manifest.resources {
        validate_path(&resource.path)?;
        if !listed.insert(resource.path.clone())
            || matches!(
                resource.path.as_str(),
                "datapackage.json" | "datapackage-digest.json"
            )
        {
            return Err(ArchiveError::Invalid("duplicate or recursive manifest resource"));
        }
        let mut entry = zip.by_name(&resource.path)?;
        if entry.size() != resource.bytes {
            return Err(ArchiveError::Invalid("resource size mismatch"));
        }
        let (bytes, hash) = stream_hash(&mut entry, &mut std::io::sink(), resource.bytes)?;
        if bytes != resource.bytes || hash != resource.hash {
            return Err(ArchiveError::Invalid("resource fixity mismatch"));
        }
    }
    names.remove("datapackage.json");
    names.remove("datapackage-digest.json");
    if names != listed {
        return Err(ArchiveError::Invalid("manifest does not cover every resource"));
    }
    let mut records = BTreeMap::new();
    let mut members = BTreeMap::new();
    let mut record_count = 0u64;
    let mut expanded = total;
    for resource in &manifest.resources {
        let name = &resource.path;
        if let Some(filename) = name.strip_prefix("archive/") {
            if !filename.ends_with(".warc.gz") && !filename.ends_with(".warc") {
                return Err(ArchiveError::Invalid("unsupported archive resource"));
            }
            let rows = warc::scan(zip.by_name_seek(name)?, name.ends_with(".gz"), limits)?;
            record_count = record_count
                .checked_add(rows.len() as u64)
                .ok_or(ArchiveError::Limit("record count"))?;
            if record_count > u64::from(limits.records) {
                return Err(ArchiveError::Limit("record count"));
            }
            for row in &rows {
                expanded = expanded
                    .checked_add(row.uncompressed_length)
                    .ok_or(ArchiveError::Limit("nested expanded bytes"))?;
                if expanded > limits.expanded_bytes {
                    return Err(ArchiveError::Limit("nested expanded bytes"));
                }
                members.insert((filename.to_owned(), row.offset), row.clone());
            }
            records.insert(name.clone(), rows);
        }
    }
    if records.is_empty() {
        return Err(ArchiveError::Invalid("WACZ archive missing"));
    }
    let targets = members
        .values()
        .filter_map(|record| record.target.as_ref().map(|url| (url.clone(), record.date)))
        .collect();
    if !listed.contains("pages/pages.jsonl") {
        return Err(ArchiveError::Invalid("WACZ pages missing"));
    }
    let pages = pages(
        BufReader::new(zip.by_name("pages/pages.jsonl")?),
        limits,
        &targets,
    )?;
    let native: Option<crawlx_core::archive::ArchiveManifestV1> = if listed.contains("crawlx/manifest.json") {
        Some(read_json(
            zip.by_name("crawlx/manifest.json")?,
            limits.record_bytes,
        )?)
    } else {
        None
    };
    if native
        .as_ref()
        .is_some_and(|manifest| manifest.schema_version != 1)
    {
        return Err(ArchiveError::Invalid("unsupported native archive manifest"));
    }
    Ok(Inspection {
        format: "wacz/1.1.1".into(),
        resources: manifest.resources,
        records,
        indexed: 0,
        pages,
        tenant: native_tenant(&mut zip, limits)?,
        run: native.as_ref().map(|manifest| manifest.run),
        zip_metadata_retention_approved,
    })
}

pub(super) fn native_tenant<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    limits: Limits,
) -> Result<Option<crawlx_core::TenantId>, ArchiveError> {
    let mut owner = None;
    for path in ["crawlx/manifest.json", "crawlx/dependency-closure.json"] {
        if zip.index_for_name(path).is_none() {
            continue;
        }
        let binding: serde_json::Value = read_json(zip.by_name(path)?, limits.record_bytes)?;
        if binding.get("schemaVersion").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(ArchiveError::Invalid("unsupported native tenant binding schema"));
        }
        let tenant = binding
            .get("tenant")
            .and_then(serde_json::Value::as_str)
            .ok_or(ArchiveError::Invalid("native tenant binding missing"))?
            .parse::<crawlx_core::TenantId>()
            .map_err(|_| ArchiveError::Invalid("native tenant binding invalid"))?;
        if owner.is_some_and(|owner| owner != tenant) {
            return Err(ArchiveError::Invalid("conflicting native tenant bindings"));
        }
        owner = Some(tenant);
    }
    Ok(owner)
}

pub(super) fn locations(
    inspection: &Inspection,
    source: usize,
) -> impl Iterator<Item = super::resolver::RecordLocation> + '_ {
    inspection.records.iter().flat_map(move |(filename, records)| {
        records
            .iter()
            .cloned()
            .map(move |record| super::resolver::RecordLocation {
                source,
                filename: filename.clone(),
                record,
            })
    })
}

pub(super) fn normalize(
    inspection: &mut Inspection,
    catalog: &super::resolver::Catalog,
    source: usize,
) -> Result<(), ArchiveError> {
    for (filename, records) in &mut inspection.records {
        for record in records {
            let location = catalog.location(&record.id)?;
            if location.source != source || location.filename != *filename {
                return Err(ArchiveError::Invalid("record custody mismatch"));
            }
            *record = location.record.clone();
        }
    }
    Ok(())
}

pub(super) fn validate_indexes<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    inspection: &Inspection,
    limits: Limits,
) -> Result<u64, ArchiveError> {
    let mut members = BTreeMap::new();
    for (filename, records) in &inspection.records {
        let filename = filename
            .strip_prefix("archive/")
            .ok_or(ArchiveError::Invalid("unsafe archive member namespace"))?;
        for record in records {
            members.insert((filename.to_owned(), record.offset), record.clone());
        }
    }
    let mut count = 0u64;
    let mut indexes = 0usize;
    for resource in &inspection.resources {
        if !resource.path.starts_with("indexes/") {
            continue;
        }
        indexes += 1;
        let entry = zip.by_name(&resource.path)?;
        let rows = if resource.path.ends_with(".gz") {
            cdxj::validate(
                BufReader::new(flate2::read::MultiGzDecoder::new(entry)),
                &members,
                limits,
            )?
        } else {
            cdxj::validate(BufReader::new(entry), &members, limits)?
        };
        count = count
            .checked_add(rows)
            .ok_or(ArchiveError::Limit("index count"))?;
        if count > u64::from(limits.records) {
            return Err(ArchiveError::Limit("index count"));
        }
    }
    if indexes == 0 {
        return Err(ArchiveError::Invalid("WACZ index missing"));
    }
    Ok(count)
}

pub(super) fn block_in_zip<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    filename: &str,
    record: &warc::RecordSummary,
    limits: Limits,
) -> Result<Vec<u8>, ArchiveError> {
    validate_path(filename)?;
    if !filename.starts_with("archive/") {
        return Err(ArchiveError::Invalid("record is outside archive namespace"));
    }
    let mut entry = zip.by_name_seek(filename)?;
    warc::block_at(&mut entry, record, filename.ends_with(".gz"), limits)
}

/// Locate an actual payload in an already validated package. Revalidates the selected range.
///
/// # Errors
/// Rejects absent members, tampered ranges, malformed WARC or payload limits.
pub fn payload<R: Read + Seek>(
    mut input: R,
    filename: &str,
    record: &warc::RecordSummary,
    limits: Limits,
) -> Result<Vec<u8>, ArchiveError> {
    validate_path(filename)?;
    if record.segment_number.is_none() && !matches!(record.record_type.as_str(), "revisit" | "continuation") {
        let (mut zip, _) = open_zip(input, limits)?;
        let mut entry = zip.by_name_seek(filename)?;
        return warc::payload_at(&mut entry, record, filename.ends_with(".gz"), limits);
    }
    let inspection = inspect(&mut input, limits)?;
    let catalog = super::resolver::Catalog::new(locations(&inspection, 0), limits)?;
    let actual = catalog.location(&record.id)?;
    if actual.filename != filename
        || actual.record.offset != record.offset
        || actual.record.length != record.length
    {
        return Err(ArchiveError::Invalid("indexed member custody mismatch"));
    }
    let (mut zip, _) = open_zip(input, limits)?;
    Ok(catalog
        .materialize(&record.id, &mut |location| {
            block_in_zip(&mut zip, &location.filename, &location.record, limits)
        })?
        .bytes)
}

pub(super) fn open_zip<R: Read + Seek>(
    mut input: R,
    limits: Limits,
) -> Result<(ZipArchive<R>, bool), ArchiveError> {
    let metadata_approved = super::zip_bounds::preflight(&mut input, limits)?;
    Ok((ZipArchive::new(input)?, metadata_approved))
}
