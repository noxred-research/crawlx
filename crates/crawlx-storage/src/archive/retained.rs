//! Offline local artifact reads using the existing object-first index and object-key convention.

use super::{ArchiveError, Limits};
use crate::artifact_custody::{ciphertext_bound, open_sealed_bytes, ArtifactCustody};
use crate::artifact_key_crypto::ArtifactKeys;
use crate::artifacts::{object_key, ArtifactRow};
use crate::custody::encrypted_object_key;
use crawlx_core::hash::Digest;
use crawlx_core::repo::Sensitivity;
use crawlx_core::{ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
fn pinned_root(root: &Path) -> Result<File, ArchiveError> {
    super::collection::open_confined_root(root).map_err(ArchiveError::Io)
}
#[cfg(not(target_os = "linux"))]
fn pinned_root(_root: &Path) -> Result<File, ArchiveError> {
    Err(ArchiveError::CapabilityUnavailable(
        "retained_artifact_reads_require_linux_openat2",
    ))
}
#[cfg(target_os = "linux")]
fn regular_inside(root: &File, relative: &str) -> Result<File, ArchiveError> {
    super::collection::open_confined_regular_at(root, relative).map_err(ArchiveError::Io)
}
#[cfg(not(target_os = "linux"))]
fn regular_inside(_root: &File, _relative: &str) -> Result<File, ArchiveError> {
    Err(ArchiveError::CapabilityUnavailable(
        "retained_artifact_reads_require_linux_openat2",
    ))
}
fn bounded(file: File, max: u64) -> Result<Vec<u8>, ArchiveError> {
    let mut bytes = Vec::new();
    let bound = max
        .checked_add(1)
        .ok_or(ArchiveError::Limit("retained artifact bytes"))?;
    file.take(bound).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(ArchiveError::Limit("retained artifact bytes"));
    }
    Ok(bytes)
}

/// Read an explicitly selected local report file, or `report.json` beneath a selected directory.
///
/// Returns its lexical location for adjacent artifact-store selection; that location is never
/// used to reopen the report. The bounded bytes come from a nonblocking, opened regular descriptor.
///
/// # Errors
/// Rejects symlinks, special files, inaccessible roots and reports larger than 32 MiB.
pub fn read_local_report(source: &Path) -> Result<(PathBuf, Vec<u8>), ArchiveError> {
    let metadata = std::fs::symlink_metadata(source)?;
    let report = if metadata.is_dir() {
        source.join("report.json")
    } else {
        source.to_owned()
    };
    let parent = report
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let root = pinned_root(parent)?;
    let name = report
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ArchiveError::Invalid("report filename is not valid UTF-8"))?;
    let file = regular_inside(&root, name)?;
    Ok((report, bounded(file, 33_554_432)?))
}

/// Retained bounded text bytes, kept separate from serializable archive metadata.
pub struct RetainedText {
    /// Owned source bytes; archive redaction still precedes any spool or output digest.
    pub bytes: Vec<u8>,
    /// Retained MIME type from the artifact store, not a guessed origin response header.
    pub content_type: String,
}

/// Read a retained content artifact, checking tenant/run, expiry, key, size and digest before use.
///
/// Uses the actual `_index/<artifact>.json` rows of `FsArtifactStore`; never scans unrelated objects.
/// Only bounded `content` text representations may enter the offline exporter. Sensitive/binary
/// capture needs a separate capability; this function does not grant one.
///
/// # Errors
/// Rejects foreign/expired/sensitive artifacts, unsafe paths, oversized or corrupt objects.
pub fn read(
    root: &Path,
    artifact: &ArtifactRef,
    tenant: TenantId,
    run: CrawlRunId,
    now: Timestamp,
    limits: Limits,
) -> Result<RetainedText, ArchiveError> {
    // Pin the store once. Index and object reads use the same descriptor-rooted authority,
    // never canonicalize/check a pathname and reopen it after an attacker can replace it.
    let root = pinned_root(root)?;
    let row = index_row(&root, artifact, tenant, run, limits)?;
    if row.object_key.starts_with("encrypted/") {
        // Sealed ciphertext needs wrapped-key custody; the legacy reader has none and never guesses.
        return Err(ArchiveError::CapabilityUnavailable(
            "sealed_artifact_requires_custody",
        ));
    }
    if row.object_key != object_key(row.sensitivity, tenant, run, &row.digest) {
        return Err(ArchiveError::Invalid(
            "artifact is not approved for this tenant and run",
        ));
    }
    approve(&row, now, limits)?;
    let object = regular_inside(&root, &row.object_key)?;
    let bytes = bounded(object, limits.record_bytes)?;
    if bytes.len() as u64 != row.size_bytes
        || Digest::of(crate::artifacts::DIGEST_DOMAIN, &bytes) != row.digest
    {
        return Err(ArchiveError::Invalid("retained artifact fixity mismatch"));
    }
    Ok(RetainedText {
        bytes,
        content_type: row.content_type,
    })
}

/// [`read`] that also serves encrypted artifacts of a local store.
///
/// Rows without encrypted custody take the legacy path unchanged. For a sealed row the stored
/// ciphertext is read through the same pinned, confined descriptors with a size bound derived
/// from the catalog row, verified against its custody ciphertext identity, authenticated frame
/// by frame, and its plaintext digest and size are checked against the row before any byte is
/// returned. Any tampering, truncation or key failure returns an error and no bytes.
///
/// # Errors
/// Everything [`read`] rejects, plus unavailable keys/custody and ciphertext or plaintext
/// verification failures.
#[allow(clippy::too_many_arguments)]
pub async fn read_sealed(
    root: &Path,
    artifact: &ArtifactRef,
    tenant: TenantId,
    run: CrawlRunId,
    now: Timestamp,
    limits: Limits,
    custody: &dyn ArtifactCustody,
    keys: &dyn ArtifactKeys,
) -> Result<RetainedText, ArchiveError> {
    let sealed = custody
        .custody(tenant, run, artifact.id)
        .await
        .map_err(store_refusal)?;
    let owned_root = root.to_owned();
    let owned_artifact = artifact.clone();
    let Some(sealed) = sealed else {
        return tokio::task::spawn_blocking(move || {
            read(&owned_root, &owned_artifact, tenant, run, now, limits)
        })
        .await
        .map_err(|_| ArchiveError::Invalid("retained artifact read task failed"))?;
    };
    let identity = sealed.ciphertext;
    let (row, ciphertext) = tokio::task::spawn_blocking(move || {
        let root = pinned_root(&owned_root)?;
        let row = index_row(&root, &owned_artifact, tenant, run, limits)?;
        if row.object_key != encrypted_object_key(tenant, run, row.id, identity.digest) {
            return Err(ArchiveError::Invalid(
                "artifact is not approved for this tenant and run",
            ));
        }
        approve(&row, now, limits)?;
        let ceiling =
            ciphertext_bound(row.size_bytes).map_err(|_| ArchiveError::Limit("retained artifact bytes"))?;
        if identity.size_bytes > ceiling {
            return Err(ArchiveError::Limit("retained artifact bytes"));
        }
        let object = regular_inside(&root, &row.object_key)?;
        let bytes = bounded(object, identity.size_bytes)?;
        Ok((row, bytes))
    })
    .await
    .map_err(|_| ArchiveError::Invalid("retained artifact read task failed"))??;
    let plaintext = open_sealed_bytes(keys, ciphertext, &row, &sealed)
        .await
        .map_err(store_refusal)?;
    Ok(RetainedText {
        bytes: plaintext.to_vec(),
        content_type: row.content_type,
    })
}

fn store_refusal(error: StoreError) -> ArchiveError {
    match error {
        StoreError::Unavailable(_) | StoreError::AccessDenied(_) => {
            ArchiveError::CapabilityUnavailable("sealed_artifact_custody_unavailable")
        }
        _ => ArchiveError::Invalid("retained artifact fixity mismatch"),
    }
}

fn index_row(
    root: &File,
    artifact: &ArtifactRef,
    tenant: TenantId,
    run: CrawlRunId,
    limits: Limits,
) -> Result<ArtifactRow, ArchiveError> {
    let index = regular_inside(root, &format!("_index/{}.json", artifact.id))?;
    let row: ArtifactRow = serde_json::from_slice(&bounded(index, limits.header_bytes)?)?;
    if row.id != artifact.id || row.tenant != tenant || row.run != run || row.digest != artifact.digest {
        return Err(ArchiveError::Invalid(
            "artifact is not approved for this tenant and run",
        ));
    }
    Ok(row)
}

fn approve(row: &ArtifactRow, now: Timestamp, limits: Limits) -> Result<(), ArchiveError> {
    if row.sensitivity != Sensitivity::Content {
        return Err(ArchiveError::CapabilityUnavailable(
            "sensitive_artifact_archive_policy_unavailable",
        ));
    }
    if row.expires_at.is_some_and(|expiry| expiry <= now) {
        return Err(ArchiveError::CapabilityUnavailable("retained_artifact_expired"));
    }
    let mime = row.content_type.split(';').next().unwrap_or("").trim();
    if !mime.starts_with("text/")
        && !matches!(
            mime,
            "application/json" | "application/xml" | "application/xhtml+xml" | "application/javascript"
        )
    {
        return Err(ArchiveError::CapabilityUnavailable(
            "raw_binary_archive_privacy_policy_unavailable",
        ));
    }
    if row.size_bytes > limits.record_bytes {
        return Err(ArchiveError::Limit("retained artifact bytes"));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn pinned_directory_and_open_child_survive_pathname_replacement_without_following_it() {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("store");
        let outside = parent.path().join("outside");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(root_path.join("payload"), b"approved").unwrap();
        std::fs::write(outside.join("payload"), b"foreign canary").unwrap();
        let root = pinned_root(&root_path).unwrap();
        let opened = regular_inside(&root, "payload").unwrap();
        // Deterministically perform the pathname swap between descriptor acquisition and read.
        std::fs::rename(&root_path, parent.path().join("retired")).unwrap();
        symlink(&outside, &root_path).unwrap();
        assert_eq!(bounded(opened, 64).unwrap(), b"approved");
        assert_eq!(
            bounded(regular_inside(&root, "payload").unwrap(), 64).unwrap(),
            b"approved"
        );
        assert!(pinned_root(&root_path).is_err());
        let retired = parent.path().join("retired");
        let opened = regular_inside(&root, "payload").unwrap();
        std::fs::rename(retired.join("payload"), retired.join("old-payload")).unwrap();
        symlink(outside.join("payload"), retired.join("payload")).unwrap();
        assert_eq!(bounded(opened, 64).unwrap(), b"approved");
        assert!(regular_inside(&root, "payload").is_err());
    }

    #[test]
    fn retained_artifact_index_and_object_refuse_symlinks_and_fifos_even_with_valid_fixity() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let tenant: TenantId = "00000000-0000-8000-8000-000000000001".parse().unwrap();
        let run: CrawlRunId = "00000000-0000-8000-8000-000000000002".parse().unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-04T12:34:56Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let body = b"approved retained payload";
        let artifact = ArtifactRef {
            id: "00000000-0000-8000-8000-000000000003".parse().unwrap(),
            digest: Digest::of(crate::artifacts::DIGEST_DOMAIN, body),
        };
        let key = object_key(Sensitivity::Content, tenant, run, &artifact.digest);
        let row = ArtifactRow {
            id: artifact.id,
            tenant,
            run,
            kind: "html".into(),
            bucket: "local".into(),
            object_key: key.clone(),
            size_bytes: body.len() as u64,
            digest: artifact.digest,
            content_type: "text/html".into(),
            sensitivity: Sensitivity::Content,
            created_at: now,
            expires_at: None,
        };
        let index = root.join(format!("_index/{}.json", artifact.id));
        let object = root.join(&key);
        std::fs::create_dir_all(index.parent().unwrap()).unwrap();
        std::fs::create_dir_all(object.parent().unwrap()).unwrap();
        std::fs::write(&index, serde_json::to_vec(&row).unwrap()).unwrap();
        std::fs::write(&object, body).unwrap();
        assert_eq!(
            read(root, &artifact, tenant, run, now, Limits::default())
                .unwrap()
                .bytes,
            body
        );
        for path in [&index, &object] {
            let backup = path.with_extension("approved-backup");
            std::fs::rename(path, &backup).unwrap();
            symlink(&backup, path).unwrap();
            assert!(read(root, &artifact, tenant, run, now, Limits::default()).is_err());
            std::fs::remove_file(path).unwrap();
            let parent = File::open(path.parent().unwrap()).unwrap();
            rustix::fs::mknodat(
                &parent,
                path.file_name().unwrap(),
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                0,
            )
            .unwrap();
            // No FIFO writer: blocking open would hang. NONBLOCK admission must reject its type.
            assert!(read(root, &artifact, tenant, run, now, Limits::default()).is_err());
            std::fs::remove_file(path).unwrap();
            std::fs::rename(&backup, path).unwrap();
        }
    }
}
