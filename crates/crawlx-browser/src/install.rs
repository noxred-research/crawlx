//! Chromium auto-download: the compatibility flags download a browser by default, crawlx
//! only when asked (`crawlx browser install`, `WorkerConfig.auto_download_chromium`).
//!
//! What is downloaded is the Chrome-for-Testing archive `chromium-pin.toml` names
//! (`download_url`), and it is unpacked only after its SHA-256 equals the pinned `sha256`:
//! a mirror or a man in the middle that serves anything else is refused and leaves nothing
//! behind. The layout is the one `ci/fetch-chromium.sh` writes, so both tools share one cache:
//!
//! ```text
//! <cache>/<version>/            unpacked archive (chrome-linux64/chrome, ...)
//! <cache>/<version>/.sha256     digest the unpacked tree was verified against
//! ```
//!
//! `<cache>` is `CRAWLX_CHROMIUM_CACHE` or `.cache/chromium` (`--chromium-cache`).
//! [`crate::launch::find_executable`] falls back to the newest cached build when no
//! system Chromium is installed.

use crate::pin::{self, ChromiumPin, PinError};
use futures::StreamExt as _;
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;

/// Environment variable naming the cache directory (also read by `ci/fetch-chromium.sh`).
pub const CACHE_ENV: &str = "CRAWLX_CHROMIUM_CACHE";
/// Cache directory when nothing else is configured, relative to the working directory.
pub const DEFAULT_CACHE_DIR: &str = ".cache/chromium";
/// Name of the file recording the digest an unpacked tree was verified against.
pub const STAMP_FILE: &str = ".sha256";

/// Longest wait for the next chunk of the download.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest archive that is downloaded (Chrome for Testing is about 150 MiB).
const MAX_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Largest unpacked size (Chrome for Testing is about 600 MiB).
const MAX_UNPACKED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Serializes installs inside one process: a burst of browser launches downloads once.
static INSTALL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Why an install failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InstallError {
    /// The pin file could not be found or parsed.
    #[error("{0}")]
    Pin(#[from] PinError),
    /// The pin has no archive to download.
    #[error("the pin names no download_url and sha256; a packaged build is verified by version only and cannot be installed")]
    NoArchive,
    /// The pin's digest is not 64 hexadecimal characters.
    #[error("sha256 {0:?} is not a 64-character hex digest")]
    BadDigest(String),
    /// `--version` differs from the pin and no digest was given for it.
    #[error(
        "version {requested} is not the pinned {pinned} and has no known digest; pass --sha256 to install it"
    )]
    UnpinnedVersion {
        /// Version asked for.
        requested: String,
        /// Version in the pin file.
        pinned: String,
    },
    /// The pin targets another platform than this process runs on.
    #[error("the pin targets {pin_os}/{pin_arch}, this is {os}/{arch}")]
    WrongPlatform {
        /// `os` of the pin.
        pin_os: String,
        /// `arch` of the pin.
        pin_arch: String,
        /// Operating system of this process.
        os: &'static str,
        /// CPU architecture of this process.
        arch: &'static str,
    },
    /// The download failed (connection, status, size or stalled transfer).
    #[error("download of {url} failed: {reason}")]
    Download {
        /// Archive URL (without credentials).
        url: String,
        /// What went wrong.
        reason: String,
    },
    /// The archive's digest is not the expected one; nothing was unpacked.
    #[error("sha256 mismatch for {url}: expected {expected}, got {actual}; nothing was unpacked")]
    DigestMismatch {
        /// Archive URL (without credentials).
        url: String,
        /// Digest the pin names.
        expected: String,
        /// Digest of the downloaded bytes.
        actual: String,
    },
    /// The archive could not be unpacked, or holds no `chrome` executable.
    #[error("cannot unpack the archive: {0}")]
    Unpack(String),
    /// A file system operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// What to install.
#[derive(Clone, Debug)]
pub struct InstallRequest<'a> {
    /// The pin naming the archive and its digest.
    pub pin: &'a ChromiumPin,
    /// Cache root (`<cache>/<version>` receives the build).
    pub cache_root: &'a Path,
    /// A version other than the pinned one (`--version`); its archive URL is the pin's with the
    /// pinned version replaced, and `sha256` must then be given.
    pub version: Option<&'a str>,
    /// Digest for [`Self::version`] (`--sha256`); ignored for the pinned version.
    pub sha256: Option<&'a str>,
}

/// A build in the cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    /// The `chrome` executable.
    pub binary: PathBuf,
    /// Version directory name.
    pub version: String,
    /// `false` when the cache already held the build and nothing was downloaded.
    pub downloaded: bool,
}

/// The cache directory: `CRAWLX_CHROMIUM_CACHE`, else [`DEFAULT_CACHE_DIR`].
#[must_use]
pub fn default_cache_root() -> PathBuf {
    std::env::var_os(CACHE_ENV).map_or_else(|| PathBuf::from(DEFAULT_CACHE_DIR), PathBuf::from)
}

/// The pin an install uses: `pin_file` when given, else [`ChromiumPin::load_or_embedded`].
///
/// # Errors
/// The [`PinError`] of reading or parsing the chosen file.
pub fn pin_for_install(pin_file: Option<&Path>) -> Result<ChromiumPin, PinError> {
    match pin_file {
        Some(path) => ChromiumPin::load(path),
        None => ChromiumPin::load_or_embedded(),
    }
}

fn is_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// First executable file named `chrome` below `dir` (any depth, sorted for determinism).
fn find_binary(dir: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut entries: Vec<_> = std::fs::read_dir(dir).ok()?.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in &entries {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_file()
            && entry.file_name() == "chrome"
            && entry
                .metadata()
                .is_ok_and(|m| m.permissions().mode() & 0o100 != 0)
        {
            return Some(path);
        }
    }
    entries
        .iter()
        .filter(|e| e.file_type().is_ok_and(|k| k.is_dir()))
        .find_map(|e| find_binary(&e.path()))
}

/// The cached binary of `version` when its stamp equals `sha256` (any stamp when `None`).
#[must_use]
pub fn cached_binary(cache_root: &Path, version: &str, sha256: Option<&str>) -> Option<PathBuf> {
    let dir = cache_root.join(version);
    let stamp = std::fs::read_to_string(dir.join(STAMP_FILE)).ok()?;
    if sha256.is_some_and(|want| !stamp.trim().eq_ignore_ascii_case(want)) {
        return None;
    }
    find_binary(&dir)
}

/// The newest verified build in `cache_root` (highest four-part version directory with a stamp
/// and an executable), `None` when the cache holds none.
#[must_use]
pub fn find_cached(cache_root: &Path) -> Option<PathBuf> {
    let mut versions: Vec<([u32; 4], String)> = std::fs::read_dir(cache_root)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            Some((pin::parse_version(&name)?, name))
        })
        .collect();
    versions.sort();
    versions
        .iter()
        .rev()
        .find_map(|(_, name)| cached_binary(cache_root, name, None))
}

/// The archive URL for `version`: the pin's, with the pinned version replaced.
fn archive_url(pin: &ChromiumPin, version: &str) -> String {
    if version == pin.version {
        pin.download_url.clone()
    } else {
        pin.download_url.replace(&pin.version, version)
    }
}

/// Download the archive of `request`, verify its digest and unpack it into
/// `<cache>/<version>`. A cache that already holds a build stamped with the digest is reused
/// without touching the network.
///
/// # Errors
/// [`InstallError`]: no archive in the pin, a digest that is not hexadecimal, a version without a
/// digest, another platform, a failed or oversized download, a digest mismatch (nothing is
/// unpacked), or an archive that cannot be unpacked or holds no `chrome`.
pub async fn install(request: InstallRequest<'_>) -> Result<Installed, InstallError> {
    let pin = request.pin;
    let version = request.version.unwrap_or(&pin.version).to_owned();
    if pin.download_url.is_empty() {
        return Err(InstallError::NoArchive);
    }
    let expected = if version == pin.version {
        if pin.sha256.is_empty() {
            return Err(InstallError::NoArchive);
        }
        pin.sha256.to_ascii_lowercase()
    } else {
        request
            .sha256
            .ok_or_else(|| InstallError::UnpinnedVersion {
                requested: version.clone(),
                pinned: pin.version.clone(),
            })?
            .to_ascii_lowercase()
    };
    if !is_hex_digest(&expected) {
        return Err(InstallError::BadDigest(expected));
    }
    if (!pin.os.is_empty() && pin.os != std::env::consts::OS)
        || (!pin.arch.is_empty() && pin.arch != std::env::consts::ARCH)
    {
        return Err(InstallError::WrongPlatform {
            pin_os: pin.os.clone(),
            pin_arch: pin.arch.clone(),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        });
    }

    let _guard = INSTALL_LOCK.lock().await;
    if let Some(binary) = cached_binary(request.cache_root, &version, Some(&expected)) {
        return Ok(Installed {
            binary,
            version,
            downloaded: false,
        });
    }
    tokio::fs::create_dir_all(request.cache_root).await?;
    // dropped (and deleted) on every exit: a refused archive leaves nothing behind
    let work = tempfile::Builder::new()
        .prefix(".download.")
        .tempdir_in(request.cache_root)?;
    let url = archive_url(pin, &version);
    let archive = work.path().join("chrome.zip");
    let actual = download(&url, &archive).await?;
    if actual != expected {
        return Err(InstallError::DigestMismatch {
            url,
            expected,
            actual,
        });
    }
    let unpacked = work.path().join("unpacked");
    let (zip_path, target) = (archive.clone(), unpacked.clone());
    tokio::task::spawn_blocking(move || unpack(&zip_path, &target))
        .await
        .map_err(|e| InstallError::Unpack(e.to_string()))??;
    if find_binary(&unpacked).is_none() {
        return Err(InstallError::Unpack(
            "the archive has no executable `chrome`".to_owned(),
        ));
    }
    std::fs::write(unpacked.join(STAMP_FILE), format!("{expected}\n"))?;
    let dest = request.cache_root.join(&version);
    if dest.exists() {
        std::fs::remove_dir_all(&dest)?;
    }
    std::fs::rename(&unpacked, &dest)?;
    let binary = find_binary(&dest)
        .ok_or_else(|| InstallError::Unpack("the installed tree has no executable `chrome`".to_owned()))?;
    Ok(Installed {
        binary,
        version,
        downloaded: true,
    })
}

/// `scheme://host[:port]/path` of `url` without credentials or query, for messages.
fn display_url(url: &str) -> String {
    url::Url::parse(url).map_or_else(
        |_| "<invalid url>".to_owned(),
        |mut u| {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.to_string()
        },
    )
}

/// Stream `url` into `dest`, hashing as it goes; returns the lowercase hex SHA-256.
#[allow(
    clippy::disallowed_types,
    reason = "Chromium download transport boundary constructs the raw HTTP client"
)]
async fn download(url: &str, dest: &Path) -> Result<String, InstallError> {
    let fail = |reason: String| InstallError::Download {
        url: display_url(url),
        reason,
    };
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| fail(e.to_string()))?;
    let response = client.get(url).send().await.map_err(|e| fail(e.to_string()))?;
    if !response.status().is_success() {
        return Err(fail(format!("status {}", response.status())));
    }
    if response.content_length().is_some_and(|n| n > MAX_ARCHIVE_BYTES) {
        return Err(fail("the archive is larger than 2 GiB".to_owned()));
    }
    let mut file = tokio::fs::File::create(dest).await?;
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut stream = response.bytes_stream();
    loop {
        let next = tokio::time::timeout(CHUNK_TIMEOUT, stream.next())
            .await
            .map_err(|_| fail("the transfer stalled".to_owned()))?;
        let Some(chunk) = next else { break };
        let chunk = chunk.map_err(|e| fail(e.to_string()))?;
        total = total.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if total > MAX_ARCHIVE_BYTES {
            return Err(fail("the archive is larger than 2 GiB".to_owned()));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Unpack `archive` below `target`, refusing entries that escape it and archives that grow
/// past [`MAX_UNPACKED_BYTES`]. Unix permissions of the entries are kept (`chrome` must stay
/// executable).
fn unpack(archive: &Path, target: &Path) -> Result<(), InstallError> {
    use std::os::unix::fs::PermissionsExt as _;
    let unpack_err = |e: &dyn std::fmt::Display| InstallError::Unpack(e.to_string());
    let file = std::fs::File::open(archive)?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| unpack_err(&e))?;
    std::fs::create_dir_all(target)?;
    let mut written: u64 = 0;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(|e| unpack_err(&e))?;
        let relative = entry
            .enclosed_name()
            .ok_or_else(|| InstallError::Unpack(format!("entry {:?} escapes the target", entry.name())))?;
        let out = target.join(relative);
        if entry.is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        written = written.saturating_add(entry.size());
        if written > MAX_UNPACKED_BYTES {
            return Err(InstallError::Unpack(
                "the archive unpacks to more than 4 GiB".to_owned(),
            ));
        }
        if entry.is_symlink() {
            let mut link = String::new();
            std::io::Read::read_to_string(&mut entry, &mut link)?;
            let safe = !link.starts_with('/') && !link.split('/').any(|part| part == "..");
            if !safe {
                return Err(InstallError::Unpack(format!(
                    "symbolic link {:?} points outside the target",
                    entry.name()
                )));
            }
            std::os::unix::fs::symlink(link, &out)?;
            continue;
        }
        let mut dest = std::fs::File::create(&out)?;
        std::io::copy(&mut entry, &mut dest)?;
        if let Some(mode) = entry.unix_mode() {
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode & 0o777))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn archive_url_swaps_only_the_version() {
        let pin = ChromiumPin {
            version: "155.0.8059.84".to_owned(),
            cdp_revision: String::new(),
            chromiumoxide: String::new(),
            os: String::new(),
            arch: String::new(),
            download_url: "https://dl.test/155.0.8059.84/linux64/chrome-linux64.zip".to_owned(),
            sha256: "0".repeat(64),
        };
        assert_eq!(archive_url(&pin, "155.0.8059.84"), pin.download_url);
        assert_eq!(
            archive_url(&pin, "156.0.1.2"),
            "https://dl.test/156.0.1.2/linux64/chrome-linux64.zip"
        );
    }

    #[test]
    fn credentials_and_query_never_reach_a_message() {
        let shown = display_url("https://user:pw@dl.test/a.zip?token=secret");
        assert_eq!(shown, "https://dl.test/a.zip");
    }

    #[test]
    fn find_cached_prefers_the_highest_stamped_version() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        for v in ["155.0.8059.84", "156.0.1.2", "9.9.9.9"] {
            let dir = root.path().join(v).join("chrome-linux64");
            std::fs::create_dir_all(&dir).unwrap();
            let bin = dir.join("chrome");
            std::fs::write(&bin, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            // 156 has no stamp: it is not a verified build
            if v != "156.0.1.2" {
                std::fs::write(root.path().join(v).join(STAMP_FILE), "ab\n").unwrap();
            }
        }
        let found = find_cached(root.path()).unwrap();
        assert!(
            found.ends_with("155.0.8059.84/chrome-linux64/chrome"),
            "{found:?}"
        );
        assert!(find_cached(&root.path().join("missing")).is_none());
    }
}
