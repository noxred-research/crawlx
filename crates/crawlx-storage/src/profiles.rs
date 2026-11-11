//! Fenced encrypted profile import/export/inspect/delete.
//! Native bundles are authenticated file maps, never executable tar archives.
//! Database ciphertext is separate from general artifact exports. Plaintext only lives
//! in the caller's bounded memory or an explicitly leased temporary browser directory.
//!
//! Production custody uses complete supported storage-state JSON through
//! `crate::custody::profiles`, with independently wrapped keys per generation.
//! Arbitrary directory bundles are unavailable for custody runs and namespaces.

use crate::backend::strategy::Conn;
use crate::codec::{from_json, to_json};
use crate::custody::frag;
use crate::leases::SessionLease;
use crate::session_binding::lock_lease_on;
use crate::sql::{stmt, Sql, SqlRow};
use crate::store::Store;
use crawlx_core::hash::Digest;
use crawlx_core::{PrincipalId, StoreError, TenantId, Timestamp};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Component, Path};

/// Hard plaintext byte bound; callers may narrow it, never widen it.
pub const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum encrypted wire representation.
pub const MAX_BUNDLE_BYTES: usize = 32 * 1024 * 1024;
/// Maximum files or directories in a bundle.
pub const MAX_PROFILE_FILES: usize = 4096;
/// Plaintext runtime copies live only on this checked Linux tmpfs mount.
pub const PROFILE_RUNTIME_ROOT: &str = "/dev/shm";
const RUNTIME_PREFIX: &str = "crawlx-profile-lease-";
const RUNTIME_MANIFEST: &str = ".crawlx-profile-lease.json";

/// Secret-free crash-reaping descriptor, written before any decrypted profile bytes.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ProfileRuntimeLease {
    /// Database/schema/server identity; one cluster cannot reap another cluster's copies.
    pub authority: Digest,
    /// Tenant whose existing session lease owns this temporary directory.
    pub tenant: TenantId,
    /// Owning role slot.
    pub session: crawlx_core::SessionId,
    /// Existing session fence, never a new lock.
    pub fence: i64,
}

impl ProfileRuntimeLease {
    /// Describe a copy owned by the existing scheduler lease.
    #[must_use]
    pub fn new(authority: Digest, tenant: TenantId, lease: &SessionLease) -> Self {
        Self {
            authority,
            tenant,
            session: lease.session.id,
            fence: lease.fencing_token,
        }
    }
}

/// Retention-approved immutable profile namespace and compatibility descriptor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ProfileScopeV1 {
    /// Owning tenant.
    pub tenant: TenantId,
    /// Exact role; same profile name under another role is a distinct namespace.
    pub principal: PrincipalId,
    /// Validated public profile name.
    pub name: String,
    /// Canonical origins this profile may access.
    pub allowed_origins: BTreeSet<String>,
    /// Actual browser-family/build digest.
    pub backend_build: Digest,
    /// Stable authorized egress identity digest.
    pub egress: Digest,
}

impl ProfileScopeV1 {
    /// Construct and validate the exact retained-profile namespace.
    ///
    /// # Errors
    /// Rejects invalid names, origins and bounded-scope violations.
    pub fn new(
        tenant: TenantId,
        principal: PrincipalId,
        name: String,
        allowed_origins: BTreeSet<String>,
        backend_build: Digest,
        egress: Digest,
    ) -> Result<Self, StoreError> {
        let scope = Self {
            tenant,
            principal,
            name,
            allowed_origins,
            backend_build,
            egress,
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Validate canonical origins and bounded public identifiers.
    ///
    /// # Errors
    /// Rejects ambiguous origins, credentials, unsafe names and excessive origin sets.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.name.is_empty()
            || self.name.len() > 128
            || !self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || self.principal.0.is_empty()
            || self.principal.0.len() > 128
            || self.allowed_origins.is_empty()
            || self.allowed_origins.len() > 64
        {
            return Err(invalid("invalid profile scope"));
        }
        for origin in &self.allowed_origins {
            let parsed = url::Url::parse(origin).map_err(|_| invalid("invalid profile origin"))?;
            if !matches!(parsed.scheme(), "http" | "https")
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.origin().ascii_serialization() != *origin
            {
                return Err(invalid("profile origins must be canonical HTTP origins"));
            }
        }
        Ok(())
    }
}

/// Complete, bounded version-one cookie and web-storage state, never a directory.
///
/// Construction rejects unknown fields, unsupported cookie attributes, duplicate
/// identities, out-of-scope origins and values exceeding shared registry limits.
/// Debug output never includes browser state. Custody acquisition releases this
/// value only after every opaque cookie/storage name and value is registered.
#[must_use]
#[non_exhaustive]
pub struct SupportedStorageState {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    document: StorageDocument,
}

/// Maximum complete supported storage export, including JSON framing.
pub const MAX_STORAGE_STATE_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageDocument {
    version: u32,
    cookies: Vec<StorageCookie>,
    origins: Vec<StorageOrigin>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StorageCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    expires: f64,
    size: u64,
    http_only: bool,
    secure: bool,
    session: bool,
    #[serde(default, deserialize_with = "present_storage_attribute")]
    same_site: Option<CookieSameSite>,
    priority: CookiePriority,
    #[serde(default)]
    same_party: bool,
    source_scheme: CookieSourceScheme,
    source_port: i32,
    #[serde(default, deserialize_with = "present_storage_attribute")]
    partition_key: Option<StoragePartitionKey>,
    #[serde(default)]
    partition_key_opaque: bool,
}

fn present_storage_attribute<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
enum CookieSameSite {
    Strict,
    Lax,
    None,
}

#[derive(Deserialize)]
enum CookiePriority {
    Low,
    Medium,
    High,
}

#[derive(Deserialize)]
enum CookieSourceScheme {
    Unset,
    NonSecure,
    Secure,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StoragePartitionKey {
    top_level_site: String,
    has_cross_site_ancestor: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageOrigin {
    origin: String,
    local: Vec<(String, String)>,
    session: Vec<(String, String)>,
}

impl Drop for StorageCookie {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.name.zeroize();
        self.value.zeroize();
        self.domain.zeroize();
        self.path.zeroize();
        if let Some(partition) = &mut self.partition_key {
            partition.top_level_site.zeroize();
        }
    }
}

impl Drop for StorageOrigin {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.origin.zeroize();
        for (key, value) in self.local.iter_mut().chain(&mut self.session) {
            key.zeroize();
            value.zeroize();
        }
    }
}

impl std::fmt::Debug for SupportedStorageState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SupportedStorageState")
            .field("bytes", &self.bytes.len())
            .field("cookies", &self.document.cookies.len())
            .field("origins", &self.document.origins.len())
            .finish_non_exhaustive()
    }
}

impl SupportedStorageState {
    /// Validate a complete supported browser export under its exact origin scope.
    ///
    /// This proves schema support, not that the browser read every document.
    /// Producers must use the strict profile export, never redacted checkpoints.
    ///
    /// # Errors
    /// Rejects malformed, excessive, ambiguous, unsupported or out-of-scope state.
    pub fn parse(bytes: &[u8], scope: &ProfileScopeV1) -> Result<Self, StoreError> {
        scope.validate()?;
        if bytes.is_empty() || bytes.len() > MAX_STORAGE_STATE_BYTES {
            return Err(invalid("profile storage state exceeds bound"));
        }
        let document: StorageDocument = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid or unsupported profile storage state"))?;
        if document.version != 1 || document.cookies.len() > 256 || document.origins.len() > 64 {
            return Err(invalid("unsupported profile storage state version or count"));
        }
        let mut cookie_ids = BTreeSet::new();
        for cookie in &document.cookies {
            // Protocol attributes are typed metadata, not opaque application values.
            // Unsupported attributes must not be silently discarded by browser import.
            let _attributes = (
                &cookie.priority,
                &cookie.same_site,
                &cookie.source_scheme,
                cookie.http_only,
            );
            if cookie.name.is_empty()
                || !cookie
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                || cookie.domain.is_empty()
                || cookie.domain.len() > 253
                || cookie.domain.bytes().any(|b| b.is_ascii_control())
                || !cookie.path.starts_with('/')
                || cookie.path.len() > 4096
                || cookie.path.bytes().any(|b| b.is_ascii_control())
                || !cookie.expires.is_finite()
                || (cookie.session && cookie.expires > 0.0)
                || cookie.value.bytes().any(|byte| byte.is_ascii_control())
                || (cookie
                    .same_site
                    .as_ref()
                    .is_some_and(|site| matches!(site, CookieSameSite::None))
                    && !cookie.secure)
                || (!cookie.session && cookie.expires <= 0.0)
                || cookie.size > 32 * 1024
                || cookie.same_party
                || cookie.partition_key_opaque
                || !(cookie.source_port == -1 || (1..=65535).contains(&cookie.source_port))
            {
                return Err(invalid("unsupported profile cookie"));
            }
            let domain = cookie.domain.strip_prefix('.').unwrap_or(&cookie.domain);
            let allowed = scope.allowed_origins.iter().any(|origin| {
                url::Url::parse(origin).is_ok_and(|url| {
                    url.host_str() == Some(domain) && (!cookie.secure || url.scheme() == "https")
                })
            });
            if !allowed {
                return Err(invalid("profile cookie domain outside allowed origins"));
            }
            let partition = cookie.partition_key.as_ref();
            if partition.is_some_and(|key| !scope.allowed_origins.contains(&key.top_level_site)) {
                return Err(invalid("profile cookie partition outside allowed origins"));
            }
            if !cookie_ids.insert((
                &cookie.name,
                &cookie.domain,
                &cookie.path,
                partition.map(|key| (&key.top_level_site, key.has_cross_site_ancestor)),
            )) {
                return Err(invalid("duplicate profile cookie"));
            }
        }
        let mut origins = BTreeSet::new();
        let mut entries = 0usize;
        for origin in &document.origins {
            if !scope.allowed_origins.contains(&origin.origin) || !origins.insert(&origin.origin) {
                return Err(invalid("duplicate or out-of-scope profile storage origin"));
            }
            for storage in [&origin.local, &origin.session] {
                let mut keys = BTreeSet::new();
                for (key, _) in storage {
                    if !keys.insert(key) {
                        return Err(invalid("duplicate profile web-storage key"));
                    }
                }
                entries = entries
                    .checked_add(storage.len())
                    .ok_or_else(|| invalid("profile storage count overflow"))?;
            }
        }
        if entries > 256 {
            return Err(invalid("profile storage entry count exceeded"));
        }
        let state = Self {
            bytes: zeroize::Zeroizing::new(bytes.to_vec()),
            document,
        };
        let values = state.opaque_values();
        if values.len() > 256
            || values.iter().any(|value| value.len() > 16 * 1024)
            || values.iter().map(|value| value.len()).sum::<usize>() > MAX_STORAGE_STATE_BYTES
        {
            return Err(invalid("profile opaque values exceed shared registry bounds"));
        }
        Ok(state)
    }

    /// Borrow the fully validated, secret-bearing JSON for browser import.
    ///
    /// Call only after custody acquisition registered its complete opaque values.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return distinct opaque names and values in deterministic registration order.
    ///
    /// Cookie domain/path and enum fields are validated protocol metadata; origins
    /// must already belong to the explicit public scope. Application-controlled
    /// cookie names/values and both web-storage names/values are secret-bearing.
    pub(crate) fn opaque_values(&self) -> BTreeSet<&str> {
        self.document
            .cookies
            .iter()
            .flat_map(|cookie| [cookie.name.as_str(), cookie.value.as_str()])
            .chain(self.document.origins.iter().flat_map(|origin| {
                origin
                    .local
                    .iter()
                    .chain(&origin.session)
                    .flat_map(|(key, value)| [key.as_str(), value.as_str()])
            }))
            .filter(|value| !value.is_empty())
            .collect()
    }
}

/// Plaintext file map. Debug deliberately never includes file content or paths.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileFiles {
    files: BTreeMap<String, Vec<u8>>,
}

impl std::fmt::Debug for ProfileFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileFiles")
            .field("files", &self.files.len())
            .finish_non_exhaustive()
    }
}

fn invalid(message: &str) -> StoreError {
    StoreError::Conflict(message.to_owned())
}

fn validate_file(path: &str, executable_approved: bool) -> Result<(), StoreError> {
    if path.is_empty()
        || path.len() > 1024
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || path.split('/').count() > 16
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || Path::new(path)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(invalid("profile path traversal denied"));
    }
    if path
        .split('/')
        .any(|part| part.starts_with("Singleton") || part == "DevToolsActivePort" || part == RUNTIME_MANIFEST)
    {
        return Err(invalid("profile process files forbidden"));
    }
    // Preferences can enable extensions, proxy changes or startup commands. Importing them
    // requires explicit operator approval, not a filename-based trust assumption.
    if !executable_approved
        && path.split('/').any(|part| {
            matches!(
                part,
                "Extensions" | "Preferences" | "Secure Preferences" | "Local State"
            )
        })
    {
        return Err(invalid(
            "profile executable preferences require operator approval",
        ));
    }
    Ok(())
}

impl ProfileFiles {
    /// Validate an in-memory file map before encryption or browser use.
    ///
    /// # Errors
    /// Rejects traversal, special process files, executable preferences without approval,
    /// prefix collisions, excessive files, depth and total bytes.
    pub fn new(files: BTreeMap<String, Vec<u8>>, executable_approved: bool) -> Result<Self, StoreError> {
        if files.len() > MAX_PROFILE_FILES {
            return Err(invalid("profile file count exceeded"));
        }
        let mut bytes = 0usize;
        for (path, content) in &files {
            validate_file(path, executable_approved)?;
            bytes = bytes
                .checked_add(content.len())
                .ok_or_else(|| invalid("profile byte limit exceeded"))?;
            if bytes > MAX_PROFILE_BYTES {
                return Err(invalid("profile byte limit exceeded"));
            }
            let mut prefix = path.as_str();
            while let Some((parent, _)) = prefix.rsplit_once('/') {
                if files.contains_key(parent) {
                    return Err(invalid("profile file/directory collision"));
                }
                prefix = parent;
            }
        }
        Ok(Self { files })
    }

    /// Read a bounded operator-selected directory without symlinks, hardlinks or special files.
    /// Call from blocking admission, never from an async runtime thread.
    ///
    /// # Errors
    /// Returns validation/I/O errors, including mutable/symlink sources and size overflow.
    #[cfg(target_os = "linux")]
    pub fn read_directory(root: &Path, executable_approved: bool) -> Result<Self, StoreError> {
        use rustix::fs::{open, openat2, Mode, OFlags, ResolveFlags};
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        fn visit(
            root: &std::fs::File,
            directory: std::fs::File,
            relative: &Path,
            out: &mut BTreeMap<String, Vec<u8>>,
            bytes: &mut usize,
            seen: &mut usize,
            depth: u8,
        ) -> Result<(), StoreError> {
            if depth > 16 {
                return Err(invalid("profile directory depth exceeded"));
            }
            // Enumerate the opened directory, never a raceable pathname. openat2 below
            // independently anchors each child to the same original root descriptor.
            let listing =
                std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd())).map_err(io)?;
            let remaining_entries = MAX_PROFILE_FILES.saturating_sub(*seen);
            let mut entries = listing
                .take(remaining_entries.saturating_add(1))
                .collect::<Result<Vec<_>, _>>()
                .map_err(io)?;
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                *seen = seen
                    .checked_add(1)
                    .ok_or_else(|| invalid("profile entry count exceeded"))?;
                if *seen > MAX_PROFILE_FILES {
                    return Err(invalid("profile entry count exceeded"));
                }
                let basename = entry.file_name();
                if basename.to_str().is_some_and(|name| {
                    name.starts_with("Singleton") || name == "DevToolsActivePort" || name == RUNTIME_MANIFEST
                }) {
                    continue; // Runtime process handles are never profile content.
                }
                let path = relative.join(basename);
                let fd = openat2(
                    root,
                    &path,
                    OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(|_| invalid("profile path is inaccessible, symlinked or outside its root"))?;
                let file = std::fs::File::from(fd);
                let metadata = file.metadata().map_err(io)?;
                if metadata.is_dir() {
                    visit(root, file, &path, out, bytes, seen, depth.saturating_add(1))?;
                } else if metadata.is_file() {
                    if metadata.nlink() != 1 {
                        return Err(invalid("profile hardlink denied"));
                    }
                    let remaining = MAX_PROFILE_BYTES
                        .checked_sub(*bytes)
                        .ok_or_else(|| invalid("profile bytes exceeded"))?;
                    let mut content = Vec::new();
                    file.take(
                        u64::try_from(remaining)
                            .map_err(|_| invalid("profile bytes exceeded"))?
                            .saturating_add(1),
                    )
                    .read_to_end(&mut content)
                    .map_err(io)?;
                    *bytes = bytes
                        .checked_add(content.len())
                        .ok_or_else(|| invalid("profile bytes exceeded"))?;
                    if *bytes > MAX_PROFILE_BYTES {
                        return Err(invalid("profile bytes exceeded"));
                    }
                    let name = path
                        .to_str()
                        .ok_or_else(|| invalid("non-UTF8 profile filename"))?
                        .to_owned();
                    out.insert(name, content);
                } else {
                    return Err(invalid("profile special file denied"));
                }
            }
            Ok(())
        }
        let fd = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| invalid("profile root must be an accessible nonsymlink directory"))?;
        let root = std::fs::File::from(fd);
        let mut files = BTreeMap::new();
        visit(
            &root,
            root.try_clone().map_err(io)?,
            Path::new(""),
            &mut files,
            &mut 0,
            &mut 0,
            0,
        )?;
        Self::new(files, executable_approved)
    }

    /// Reject disk profile materialization where the required beneath/no-symlink open is absent.
    ///
    /// # Errors
    /// Always returns unsupported on non-Linux platforms; never follows unchecked paths.
    #[cfg(not(target_os = "linux"))]
    pub fn read_directory(_root: &Path, _executable_approved: bool) -> Result<Self, StoreError> {
        Err(invalid("profile directory import requires Linux openat2"))
    }

    /// Materialize in a private temporary directory, deleted on cancellation/drop.
    ///
    /// # Errors
    /// Returns validation or local filesystem errors; never overwrites an existing profile.
    pub fn materialize(
        &self,
        root: &Path,
        lease: &ProfileRuntimeLease,
        executable_approved: bool,
    ) -> Result<tempfile::TempDir, StoreError> {
        let dir = tempfile::Builder::new()
            .prefix(RUNTIME_PREFIX)
            .tempdir_in(root)
            .map_err(io)?;
        // Publishing this descriptor before secrets makes even a mid-copy crash reapable.
        let descriptor =
            serde_json::to_vec(lease).map_err(|error| StoreError::Serialization(error.to_string()))?;
        std::fs::write(dir.path().join(RUNTIME_MANIFEST), descriptor).map_err(io)?;
        for (path, bytes) in &self.files {
            validate_file(path, executable_approved)?;
            let destination = dir.path().join(path);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).map_err(io)?;
            }
            std::fs::write(destination, bytes).map_err(io)?;
        }
        Ok(dir)
    }
}

fn io(error: std::io::Error) -> StoreError {
    StoreError::Backend(format!("profile filesystem operation failed: {}", error.kind()))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    version: u8,
    scope: ProfileScopeV1,
    generation: u64,
    expires_at: Timestamp,
    files: ProfileFiles,
}

/// Legacy directory-bundle AEAD key, never production retained-profile custody.
/// Production custody uses independently wrapped ArtifactKeys per generation.
pub struct ProfileCipher {
    key: LessSafeKey,
}

impl ProfileCipher {
    /// Create an AES-256-GCM key from exactly 32 secret bytes.
    ///
    /// # Errors
    /// Rejects invalid key lengths. Key material is never included in an error.
    pub fn new(key: &[u8]) -> Result<Self, StoreError> {
        Ok(Self {
            key: LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM, key)
                    .map_err(|_| invalid("profile encryption key must be 32 bytes"))?,
            ),
        })
    }

    /// Encrypt an approved native profile bundle. Expiry and compatibility are authenticated.
    ///
    /// # Errors
    /// Rejects invalid scope, sizes, encryption failures or expired/nonpositive generations.
    pub fn seal(
        &self,
        scope: &ProfileScopeV1,
        generation: u64,
        expires_at: Timestamp,
        files: ProfileFiles,
    ) -> Result<Vec<u8>, StoreError> {
        scope.validate()?;
        if generation == 0 {
            return Err(invalid("profile generation must be positive"));
        }
        let mut nonce = [0u8; 12];
        // Cryptographic nonces deliberately use OS entropy, never the deterministic crawl RNG.
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| invalid("profile encryption entropy unavailable"))?;
        let mut plaintext = serde_json::to_vec(&Payload {
            version: 1,
            scope: scope.clone(),
            generation,
            expires_at,
            files,
        })
        .map_err(|_| invalid("profile bundle encoding failed"))?;
        if plaintext.len() > MAX_BUNDLE_BYTES - 64 {
            return Err(invalid("profile bundle bytes exceeded"));
        }
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(b"crawlx/profile-bundle/v1"),
                &mut plaintext,
            )
            .map_err(|_| invalid("profile encryption failed"))?;
        let mut bundle = Vec::with_capacity(16 + plaintext.len());
        bundle.extend_from_slice(b"CXP1");
        bundle.extend_from_slice(&nonce);
        bundle.extend_from_slice(&plaintext);
        Ok(bundle)
    }

    fn open(
        &self,
        bytes: &[u8],
        scope: &ProfileScopeV1,
        now: Timestamp,
        executable_approved: bool,
    ) -> Result<Payload, StoreError> {
        scope.validate()?;
        if bytes.len() < 32 || bytes.len() > MAX_BUNDLE_BYTES || &bytes[..4] != b"CXP1" {
            return Err(invalid("invalid encrypted profile bundle"));
        }
        let nonce: [u8; 12] = bytes[4..16]
            .try_into()
            .map_err(|_| invalid("invalid profile nonce"))?;
        let mut ciphertext = bytes[16..].to_vec();
        let plaintext = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(b"crawlx/profile-bundle/v1"),
                &mut ciphertext,
            )
            .map_err(|_| invalid("profile authentication failed"))?;
        let payload: Payload =
            serde_json::from_slice(plaintext).map_err(|_| invalid("invalid native profile payload"))?;
        if payload.version != 1
            || payload.scope != *scope
            || payload.generation == 0
            || payload.expires_at <= now
        {
            return Err(invalid("profile compatibility, generation or expiry conflict"));
        }
        let files = ProfileFiles::new(payload.files.files, executable_approved)?;
        Ok(Payload { files, ..payload })
    }
}

/// Secret-free result of inspect/import. File names and cookies are not disclosed.
#[derive(Clone, Serialize, Debug)]
#[non_exhaustive]
pub struct ProfileInspection {
    /// Exact compatibility scope.
    pub scope: ProfileScopeV1,
    /// Explicit generation.
    pub generation: u64,
    /// Encrypted bundle digest; pins import/export bytes, not secret content.
    pub digest: Digest,
    /// Secret expiry, never implicitly extended.
    pub expires_at: Timestamp,
    /// Validated file count.
    pub files: usize,
}

/// Legacy directory-bundle service, unavailable for runs or rows using custody.
pub struct BrowserProfileRepo<'a, B: Sql> {
    store: &'a Store<B>,
    cipher: &'a ProfileCipher,
}

async fn legacy_profile_mode<B: Sql>(
    conn: &mut Conn<B>,
    lease: &SessionLease,
    scope: &ProfileScopeV1,
) -> Result<(), StoreError> {
    let custody = stmt!(
        B,
        "SELECT EXISTS(SELECT 1 FROM run_secret_authority WHERE tenant_id=$1 AND run_id=$2 \
         UNION ALL SELECT 1 FROM browser_profiles WHERE tenant_id=$1 AND principal=$3 \
         AND name=$4 AND custody_format<>0) AS v"
    )
    .uuid(scope.tenant.0)
    .uuid(lease.session.run.0)
    .text(&scope.principal.0)
    .text(&scope.name)
    .fetch_one(conn)
    .await?
    .bool("v")?;
    if custody {
        return Err(StoreError::Unavailable(
            "profile_unavailable: arbitrary directory bundles are unavailable in custody mode".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn audit_profile<B: Sql>(
    conn: &mut Conn<B>,
    lease: &SessionLease,
    scope: &ProfileScopeV1,
    event: &str,
    generation: u64,
) -> Result<(), StoreError> {
    crate::retention::append_audit_in::<B>(
        conn,
        Some(scope.tenant.0),
        Some(lease.session.run.0),
        &lease.worker.to_string(),
        event,
        serde_json::json!({
            "profile": Digest::of("crawlx/profile-audit-name/v1", scope.name.as_bytes()),
            "generation": generation, "leaseFence": lease.fencing_token,
        }),
    )
    .await
}

/// A different live session still holds the profile under its own unexpired fence.
async fn held_elsewhere<B: Sql>(
    conn: &mut Conn<B>,
    session: uuid::Uuid,
    fence: i64,
) -> Result<bool, StoreError> {
    stmt!(
        B,
        format!(
            "SELECT EXISTS(SELECT 1 FROM crawl_sessions WHERE session_id=$1 AND fencing_token=$2 AND lease_expires_at>{}) AS v",
            frag::clock::<B>()
        )
    )
    .uuid(session)
    .i64(fence)
    .fetch_one(conn)
    .await?
    .bool("v")
}

/// Replace the profile row of `scope` with `generation`, only when it still holds
/// `expected_generation` (or does not exist); `true` when this call wrote it.
#[allow(
    clippy::too_many_arguments,
    reason = "every column of the generation is explicit"
)]
async fn write_generation<B: Sql>(
    conn: &mut Conn<B>,
    lease: &SessionLease,
    scope: &ProfileScopeV1,
    scope_json: &serde_json::Value,
    generation: i64,
    expected_generation: i64,
    bytes: &[u8],
    digest: &Digest,
    expires_at: Timestamp,
    existed: bool,
) -> Result<bool, StoreError> {
    if B::KIND == crate::backend::BackendKind::MariaDb {
        // No conditional upsert: the row is already locked, so update or insert by what the
        // locked read found.
        let changed = if existed {
            stmt!(B, "UPDATE browser_profiles SET generation=$4,scope=$5,encrypted_bundle=$6,digest=$7,expires_at=$8,owner_run=$9,session_id=$10,lease_fence=$11 \
                WHERE tenant_id=$1 AND principal=$2 AND name=$3 AND generation=$12")
                .uuid(scope.tenant.0).text(&scope.principal.0).text(&scope.name).i64(generation)
                .json(scope_json).bytes(bytes).bytes(digest.0.as_slice()).ts(expires_at)
                .uuid(lease.session.run.0).uuid(lease.session.id.0).i64(lease.fencing_token)
                .i64(expected_generation).execute(conn).await?
        } else {
            stmt!(B, "INSERT INTO browser_profiles(tenant_id,principal,name,generation,scope,encrypted_bundle,digest,expires_at,owner_run,session_id,lease_fence) \
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
                .uuid(scope.tenant.0).text(&scope.principal.0).text(&scope.name).i64(generation)
                .json(scope_json).bytes(bytes).bytes(digest.0.as_slice()).ts(expires_at)
                .uuid(lease.session.run.0).uuid(lease.session.id.0).i64(lease.fencing_token)
                .execute(conn).await?
        };
        return Ok(changed == 1);
    }
    // The PK serializes concurrent creates even when there was no row to lock.
    let result = stmt!(B, "INSERT INTO browser_profiles(tenant_id,principal,name,generation,scope,encrypted_bundle,digest,expires_at,owner_run,session_id,lease_fence) \
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(tenant_id,principal,name) DO UPDATE \
        SET generation=EXCLUDED.generation,scope=EXCLUDED.scope,encrypted_bundle=EXCLUDED.encrypted_bundle,digest=EXCLUDED.digest, \
        expires_at=EXCLUDED.expires_at,owner_run=EXCLUDED.owner_run,session_id=EXCLUDED.session_id,lease_fence=EXCLUDED.lease_fence \
        WHERE browser_profiles.generation=$12")
        .uuid(scope.tenant.0).text(&scope.principal.0).text(&scope.name).i64(generation)
        .json(scope_json).bytes(bytes).bytes(digest.0.as_slice()).ts(expires_at)
        .uuid(lease.session.run.0).uuid(lease.session.id.0).i64(lease.fencing_token)
        .i64(expected_generation).execute(conn).await?;
    Ok(result == 1)
}

impl<'a, B: Sql> BrowserProfileRepo<'a, B> {
    /// Compose with the existing repository and an operator-provided secret key.
    #[must_use]
    pub fn new(store: &'a Store<B>, cipher: &'a ProfileCipher) -> Self {
        Self { store, cipher }
    }

    /// Import digest-pinned ciphertext only after explicit retained-profile approval.
    /// Expected generation zero creates a profile; otherwise the next generation must equal old + 1.
    ///
    /// # Errors
    /// Rejects ZDR, stale lease, principal crossover, unsafe files, expiry, unresolved writes
    /// by either owner and generation conflicts.
    #[allow(
        clippy::too_many_arguments,
        reason = "digest pin, expected generation and two independent operator approvals must remain explicit security inputs"
    )]
    pub async fn import(
        &self,
        lease: &SessionLease,
        scope: &ProfileScopeV1,
        bytes: &[u8],
        pinned: Digest,
        expected_generation: u64,
        retained_profile_approved: bool,
        executable_approved: bool,
    ) -> Result<ProfileInspection, StoreError> {
        if !retained_profile_approved || Digest::of("crawlx/profile-bundle/v1", bytes) != pinned {
            return Err(invalid("profile retention approval or digest pin missing"));
        }
        if scope.principal != lease.session.role {
            return Err(invalid("profile principal conflict"));
        }
        let mut tx = self.store.begin_write().await?;
        let now = lock_lease_on::<B>(tx.conn(), lease, scope.tenant).await?;
        legacy_profile_mode::<B>(tx.conn(), lease, scope).await?;
        let row = stmt!(
            B,
            "SELECT retention_mode::text AS mode, expires_at FROM crawl_runs WHERE run_id=$1"
        )
        .uuid(lease.session.run.0)
        .fetch_one(tx.conn())
        .await?;
        let mode: String = row.text("mode")?;
        let run_expiry: Option<Timestamp> = row.opt_ts("expires_at")?;
        if mode == "zdr" {
            return Err(invalid("retention_denied: durable profiles forbidden under zdr"));
        }
        let payload = self.cipher.open(bytes, scope, now, executable_approved)?;
        if run_expiry.is_none_or(|expiry| payload.expires_at > expiry) {
            return Err(invalid("profile expiry exceeds owning run retention"));
        }
        if expected_generation.checked_add(1) != Some(payload.generation) {
            return Err(invalid("profile generation conflict"));
        }
        let existing = stmt!(
            B,
            format!(
                "SELECT generation, scope, session_id, lease_fence FROM browser_profiles WHERE tenant_id=$1 AND principal=$2 AND name=$3{}",
                frag::update::<B>()
            )
        )
        .uuid(scope.tenant.0)
        .text(&scope.principal.0)
        .text(&scope.name)
        .fetch_optional(tx.conn())
        .await?;
        let existed = existing.is_some();
        if let Some(existing) = existing {
            let generation: i64 = existing.i64("generation")?;
            let stored_scope: ProfileScopeV1 = from_json(existing.json("scope")?)?;
            if u64::try_from(generation).ok() != Some(expected_generation) || stored_scope != *scope {
                return Err(invalid("profile generation conflict"));
            }
            let session: uuid::Uuid = existing.uuid("session_id")?;
            let fence: i64 = existing.i64("lease_fence")?;
            // Keep the profile row locked while checking both journals. Do not lock the
            // prior session here: acquisition already locks the incoming session first.
            let uncertain = stmt!(
                B,
                "SELECT EXISTS(SELECT 1 FROM actions a JOIN crawl_runs r ON r.run_id=a.run_id \
                 WHERE r.tenant_id=$1 AND a.session_id IN ($2,$3) AND a.status IN ('intended','unknown')) AS v"
            )
            .uuid(scope.tenant.0)
            .uuid(session)
            .uuid(lease.session.id.0)
            .fetch_one(tx.conn())
            .await?
            .bool("v")?;
            if uncertain {
                return Err(invalid("profile generation conflict: unresolved write"));
            }
            if (session != lease.session.id.0 || fence != lease.fencing_token)
                && held_elsewhere::<B>(tx.conn(), session, fence).await?
            {
                return Err(invalid("profile lease conflict"));
            }
        } else if expected_generation != 0 {
            return Err(invalid("profile generation conflict"));
        }
        let generation =
            i64::try_from(payload.generation).map_err(|_| invalid("profile generation exhausted"))?;
        let prior =
            i64::try_from(expected_generation).map_err(|_| invalid("profile generation exhausted"))?;
        let scope_json = to_json(scope)?;
        let written = write_generation::<B>(
            tx.conn(),
            lease,
            scope,
            &scope_json,
            generation,
            prior,
            bytes,
            &pinned,
            payload.expires_at,
            existed,
        )
        .await?;
        if !written {
            return Err(invalid("profile generation conflict"));
        }
        audit_profile::<B>(tx.conn(), lease, scope, "profile.import", payload.generation).await?;
        tx.commit().await?;
        Ok(ProfileInspection {
            scope: scope.clone(),
            generation: payload.generation,
            digest: pinned,
            expires_at: payload.expires_at,
            files: payload.files.files.len(),
        })
    }

    /// Retrieve pinned ciphertext and validate it under the exact requested scope.
    ///
    /// # Errors
    /// Rejects stale leases, incompatible scopes, expired artifacts and generation conflicts.
    pub async fn export(
        &self,
        lease: &SessionLease,
        scope: &ProfileScopeV1,
        generation: u64,
        executable_approved: bool,
    ) -> Result<(ProfileInspection, Vec<u8>), StoreError> {
        if scope.principal != lease.session.role {
            return Err(invalid("profile principal conflict"));
        }
        let mut tx = self.store.begin_write().await?;
        let now = lock_lease_on::<B>(tx.conn(), lease, scope.tenant).await?;
        legacy_profile_mode::<B>(tx.conn(), lease, scope).await?;
        let row = stmt!(B, "SELECT encrypted_bundle,digest,scope FROM browser_profiles WHERE tenant_id=$1 AND principal=$2 AND name=$3 AND generation=$4 AND expires_at>$5")
            .uuid(scope.tenant.0).text(&scope.principal.0).text(&scope.name)
            .i64(i64::try_from(generation).map_err(|_| invalid("profile generation exhausted"))?).ts(now)
            .fetch_optional(tx.conn()).await?.ok_or_else(|| invalid("profile unavailable"))?;
        let bytes: Vec<u8> = row.bytes("encrypted_bundle")?;
        let payload = self.cipher.open(&bytes, scope, now, executable_approved)?;
        if payload.generation != generation {
            return Err(invalid("profile generation conflict"));
        }
        let digest = Digest::of("crawlx/profile-bundle/v1", &bytes);
        let stored_digest: Vec<u8> = row.bytes("digest")?;
        if stored_digest.as_slice() != digest.0 {
            return Err(invalid("profile digest mismatch"));
        }
        audit_profile::<B>(tx.conn(), lease, scope, "profile.export", generation).await?;
        tx.commit().await?;
        Ok((
            ProfileInspection {
                scope: scope.clone(),
                generation,
                digest,
                expires_at: payload.expires_at,
                files: payload.files.files.len(),
            },
            bytes,
        ))
    }

    /// Attach the profile to an already-live session fence and decrypt into bounded memory.
    /// A different live holder causes an explicit conflict; there is no shared-directory fallback.
    ///
    /// # Errors
    /// Rejects stale leases, incompatible profiles, concurrent live holders and cross-session
    /// transfers whose prior owner has unresolved writes. Same-session fenced recovery is allowed.
    pub async fn acquire(
        &self,
        lease: &SessionLease,
        scope: &ProfileScopeV1,
        executable_approved: bool,
    ) -> Result<Option<(ProfileInspection, ProfileFiles)>, StoreError> {
        scope.validate()?;
        if scope.principal != lease.session.role {
            return Err(invalid("profile principal conflict"));
        }
        let mut tx = self.store.begin_write().await?;
        let now = lock_lease_on::<B>(tx.conn(), lease, scope.tenant).await?;
        legacy_profile_mode::<B>(tx.conn(), lease, scope).await?;
        let row = stmt!(
            B,
            format!(
                "SELECT encrypted_bundle,digest,scope,session_id,lease_fence FROM browser_profiles WHERE tenant_id=$1 AND principal=$2 AND name=$3{}",
                frag::update::<B>()
            )
        )
        .uuid(scope.tenant.0)
        .text(&scope.principal.0)
        .text(&scope.name)
        .fetch_optional(tx.conn())
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let session: uuid::Uuid = row.uuid("session_id")?;
        let fence: i64 = row.i64("lease_fence")?;
        if (session != lease.session.id.0 || fence != lease.fencing_token)
            && held_elsewhere::<B>(tx.conn(), session, fence).await?
        {
            return Err(invalid("profile lease conflict"));
        }
        if session != lease.session.id.0 {
            // A recovering worker must restore its own profile before reconciliation.
            // Cross-session transfer cannot detach that profile from an unresolved write.
            // Read without prior-session/action locks to preserve lease/profile lock ordering.
            let uncertain = stmt!(
                B,
                "SELECT EXISTS(SELECT 1 FROM actions a JOIN crawl_runs r ON r.run_id=a.run_id \
                 WHERE r.tenant_id=$1 AND a.session_id=$2 AND a.status IN ('intended','unknown')) AS v"
            )
            .uuid(scope.tenant.0)
            .uuid(session)
            .fetch_one(tx.conn())
            .await?
            .bool("v")?;
            if uncertain {
                return Err(invalid("profile lease conflict: unresolved write"));
            }
        }
        let bytes: Vec<u8> = row.bytes("encrypted_bundle")?;
        let payload = self.cipher.open(&bytes, scope, now, executable_approved)?;
        let digest = Digest::of("crawlx/profile-bundle/v1", &bytes);
        let stored_digest: Vec<u8> = row.bytes("digest")?;
        if stored_digest.as_slice() != digest.0 {
            return Err(invalid("profile digest mismatch"));
        }
        stmt!(B, "UPDATE browser_profiles SET session_id=$4,lease_fence=$5 WHERE tenant_id=$1 AND principal=$2 AND name=$3")
            .uuid(scope.tenant.0).text(&scope.principal.0).text(&scope.name).uuid(lease.session.id.0).i64(lease.fencing_token)
            .execute(tx.conn()).await?;
        audit_profile::<B>(tx.conn(), lease, scope, "profile.acquire", payload.generation).await?;
        tx.commit().await?;
        let inspection = ProfileInspection {
            scope: scope.clone(),
            generation: payload.generation,
            digest,
            expires_at: payload.expires_at,
            files: payload.files.files.len(),
        };
        Ok(Some((inspection, payload.files)))
    }

    /// Inspect validated metadata without exposing browser secrets or archive URLs.
    ///
    /// # Errors
    /// Returns the same strict errors as export; never returns another principal's profile.
    pub async fn inspect(
        &self,
        lease: &SessionLease,
        scope: &ProfileScopeV1,
        generation: u64,
        executable_approved: bool,
    ) -> Result<ProfileInspection, StoreError> {
        Ok(self
            .export(lease, scope, generation, executable_approved)
            .await?
            .0)
    }

    /// Delete actual ciphertext, not just mark a catalog row invisible.
    ///
    /// # Errors
    /// Rejects stale session fences or a stale expected generation.
    pub async fn delete(
        &self,
        lease: &SessionLease,
        scope: &ProfileScopeV1,
        generation: u64,
    ) -> Result<(), StoreError> {
        scope.validate()?;
        if scope.principal != lease.session.role {
            return Err(invalid("profile principal conflict"));
        }
        let mut tx = self.store.begin_write().await?;
        lock_lease_on::<B>(tx.conn(), lease, scope.tenant).await?;
        legacy_profile_mode::<B>(tx.conn(), lease, scope).await?;
        let scope_json = to_json(scope)?;
        let result = stmt!(B, "DELETE FROM browser_profiles WHERE tenant_id=$1 AND principal=$2 AND name=$3 AND generation=$4 AND scope=$5")
            .uuid(scope.tenant.0).text(&scope.principal.0).text(&scope.name)
            .i64(i64::try_from(generation).map_err(|_| invalid("profile generation exhausted"))?)
            .json(&scope_json)
            .execute(tx.conn()).await?;
        if result != 1 {
            return Err(invalid("profile generation conflict"));
        }
        audit_profile::<B>(tx.conn(), lease, scope, "profile.delete", generation).await?;
        tx.commit().await?;
        self.store.reap_profile_directories().await?;
        Ok(())
    }
}

impl<B: Sql> Store<B> {
    /// Stable database authority for local temporary-profile crash records.
    ///
    /// # Errors
    /// Returns database or canonical-serialization errors.
    pub async fn profile_authority(&self) -> Result<Digest, StoreError> {
        use crate::backend::BackendKind;
        let identity: serde_json::Value = match B::KIND {
            BackendKind::Postgres => stmt!(
                B,
                "SELECT jsonb_build_array(current_database(), current_schema(), inet_server_addr()::text, inet_server_port()) AS v"
            )
            .fetch_one_pool(&self.pool)
            .await?
            .json("v")?,
            BackendKind::MariaDb => {
                let row = stmt!(B, "SELECT DATABASE() AS name, @@hostname AS host, CAST(@@port AS SIGNED) AS port")
                    .fetch_one_pool(&self.pool)
                    .await?;
                serde_json::json!(["mariadb", row.text("name")?, row.text("host")?, row.i64("port")?])
            }
            BackendKind::Sqlite => {
                let row = stmt!(B, "SELECT file AS path FROM pragma_database_list WHERE name = 'main'")
                    .fetch_one_pool(&self.pool)
                    .await?;
                serde_json::json!(["sqlite", row.text("path")?])
            }
        };
        Digest::of_value("crawlx/profile-database-authority/v1", &identity)
            .map_err(|error| StoreError::Serialization(error.to_string()))
    }

    /// Remove expired/revoked/purged profile ciphertext, with no plaintext spool.
    ///
    /// # Errors
    /// Returns database errors; a failed deletion remains retryable on the next sweep.
    pub async fn reap_profiles(&self) -> Result<u64, StoreError> {
        let now = frag::clock::<B>();
        let sql = if frag::is_pg::<B>() {
            format!("DELETE FROM browser_profiles p USING crawl_runs r WHERE p.owner_run=r.run_id AND \
            (p.expires_at<={now} OR r.purge_requested_at IS NOT NULL OR r.cancel_requested_at IS NOT NULL \
             OR r.status IN ('failed','cancelled') OR EXISTS(SELECT 1 FROM authorization_records a WHERE a.record_id=r.authorization_record_id \
               AND (a.revoked_at IS NOT NULL OR a.valid_to<={now})))")
        } else {
            format!("DELETE FROM browser_profiles WHERE EXISTS(SELECT 1 FROM crawl_runs r WHERE r.run_id=browser_profiles.owner_run AND \
            (browser_profiles.expires_at<={now} OR r.purge_requested_at IS NOT NULL OR r.cancel_requested_at IS NOT NULL \
             OR r.status IN ('failed','cancelled') OR EXISTS(SELECT 1 FROM authorization_records a WHERE a.record_id=r.authorization_record_id \
               AND (a.revoked_at IS NOT NULL OR a.valid_to<={now}))))")
        };
        stmt!(B, sql).execute_write(&self.pool).await
    }

    /// Reap this host's expired/crashed/revoked temporary copies using live database fences.
    /// No process is signalled. An inaccessible external resource remains separately quarantined.
    ///
    /// # Errors
    /// Returns filesystem/database errors, or an explicit bounded-directory admission error.
    pub async fn reap_profile_directories(&self) -> Result<u64, StoreError> {
        use tokio::io::AsyncReadExt as _;
        let authority = self.profile_authority().await?;
        let mut listing = match tokio::fs::read_dir(PROFILE_RUNTIME_ROOT).await {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(io(error)),
        };
        let mut seen = 0usize;
        let mut erased = 0u64;
        while let Some(entry) = listing.next_entry().await.map_err(io)? {
            let name = entry.file_name();
            if !name.to_str().is_some_and(|name| name.starts_with(RUNTIME_PREFIX)) {
                continue;
            }
            seen = seen.saturating_add(1);
            if seen > MAX_PROFILE_FILES {
                return Err(invalid("profile crash-reaper directory count exceeded"));
            }
            let kind = entry.file_type().await.map_err(io)?;
            if !kind.is_dir() || kind.is_symlink() {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if entry.metadata().await.map_err(io)?.uid() != rustix::process::getuid().as_raw() {
                    continue;
                }
            }
            let path = entry.path();
            let manifest = path.join(RUNTIME_MANIFEST);
            let descriptor = match tokio::fs::symlink_metadata(&manifest).await {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    let file = tokio::fs::File::open(&manifest).await.map_err(io)?;
                    let mut bytes = Vec::new();
                    file.take(4097).read_to_end(&mut bytes).await.map_err(io)?;
                    if bytes.len() > 4096 {
                        return Err(invalid("profile runtime descriptor exceeds bound"));
                    }
                    Some(
                        serde_json::from_slice::<ProfileRuntimeLease>(&bytes)
                            .map_err(|_| invalid("invalid profile runtime descriptor"))?,
                    )
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // A crash before the descriptor cannot have written secrets. Give a
                    // concurrent creator a minute before removing its empty allocation.
                    let metadata = entry.metadata().await.map_err(io)?;
                    if metadata.modified().map_err(io)?.elapsed().unwrap_or_default()
                        < std::time::Duration::from_secs(60)
                    {
                        continue;
                    }
                    None
                }
                Ok(_) => {
                    return Err(invalid(
                        "profile runtime descriptor symlink or special file denied",
                    ))
                }
                Err(error) => return Err(io(error)),
            };
            let live = if let Some(descriptor) = descriptor {
                if descriptor.authority != authority {
                    continue;
                }
                if crate::tenant::current().is_some_and(|tenant| tenant != descriptor.tenant) {
                    continue;
                }
                let now = frag::clock::<B>();
                stmt!(B, format!("SELECT EXISTS(SELECT 1 FROM crawl_sessions s JOIN crawl_runs r USING(run_id) \
                    JOIN browser_profiles p ON p.session_id=s.session_id AND p.lease_fence=s.fencing_token \
                    WHERE s.session_id=$1 AND s.fencing_token=$2 AND r.tenant_id=$3 \
                    AND s.lease_expires_at>{now} AND p.expires_at>{now} \
                    AND s.status IN ('running','recovering') AND r.status IN ('queued','running') \
                    AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL \
                    AND NOT EXISTS(SELECT 1 FROM authorization_records a WHERE a.record_id=r.authorization_record_id \
                      AND (a.revoked_at IS NOT NULL OR a.valid_to<={now}))) AS v"))
                    .uuid(descriptor.session.0).i64(descriptor.fence).uuid(descriptor.tenant.0)
                    .fetch_one_pool(&self.pool).await?.bool("v")?
            } else {
                false
            };
            if !live {
                match tokio::fs::remove_dir_all(path).await {
                    Ok(()) => erased = erased.saturating_add(1),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(io(error)),
                }
            }
        }
        Ok(erased)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    fn scope() -> ProfileScopeV1 {
        ProfileScopeV1 {
            tenant: TenantId::new(),
            principal: PrincipalId("reader".into()),
            name: "fixture".into(),
            allowed_origins: BTreeSet::from(["https://example.test".into()]),
            backend_build: Digest::of("build", b"1"),
            egress: Digest::of("egress", b"approved"),
        }
    }
    #[test]
    fn encrypted_profile_rejects_wrong_principal_build_tampering_and_expiry() {
        let cipher = ProfileCipher::new(&[7; 32]).unwrap();
        let scope = scope();
        let now = chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap();
        let bytes = cipher
            .seal(
                &scope,
                1,
                now + chrono::Duration::seconds(10),
                ProfileFiles::new(
                    BTreeMap::from([("Default/Cookies".into(), b"secret-cookie-canary".to_vec())]),
                    false,
                )
                .unwrap(),
            )
            .unwrap();
        assert!(!bytes
            .windows(b"secret-cookie-canary".len())
            .any(|value| value == b"secret-cookie-canary"));
        assert_eq!(
            cipher.open(&bytes, &scope, now, false).unwrap().files.files["Default/Cookies"],
            b"secret-cookie-canary"
        );
        let mut wrong = scope.clone();
        wrong.principal = PrincipalId("admin".into());
        assert!(cipher.open(&bytes, &wrong, now, false).is_err());
        wrong = scope.clone();
        wrong.backend_build = Digest::of("build", b"2");
        assert!(cipher.open(&bytes, &wrong, now, false).is_err());
        assert!(cipher
            .open(&bytes, &scope, now + chrono::Duration::seconds(10), false)
            .is_err());
        let mut tampered = bytes;
        tampered[20] ^= 1;
        assert!(cipher.open(&tampered, &scope, now, false).is_err());
    }
    #[test]
    fn native_bundle_denies_tar_escape_special_files_and_preferences() {
        for path in [
            "../Cookies",
            "/tmp/Cookies",
            "a/../../b",
            "a\\Cookies",
            "Default/../Cookies",
            "SingletonLock",
            "Default/Preferences",
        ] {
            assert!(
                ProfileFiles::new(BTreeMap::from([(path.into(), vec![1])]), false).is_err(),
                "{path}"
            );
        }
        assert!(ProfileFiles::new(
            BTreeMap::from([("Default".into(), vec![]), ("Default/Cookies".into(), vec![])]),
            true
        )
        .is_err());
        let cipher = ProfileCipher::new(&[1; 32]).unwrap();
        assert!(cipher
            .open(
                b"not-an-encrypted-tar-profile-bundle",
                &scope(),
                chrono::Utc::now(),
                false
            )
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn profile_directory_reader_denies_symlink_and_hardlink_secret_escape() {
        let source = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"unrelated-secret").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), source.path().join("Cookies")).unwrap();
        assert!(ProfileFiles::read_directory(source.path(), false).is_err());
        std::fs::remove_file(source.path().join("Cookies")).unwrap();
        std::fs::hard_link(outside.path().join("secret"), source.path().join("Cookies")).unwrap();
        assert!(ProfileFiles::read_directory(source.path(), false).is_err());
    }

    #[test]
    fn profile_file_count_and_plaintext_byte_limits_are_enforced_before_encryption() {
        let files = (0..=MAX_PROFILE_FILES)
            .map(|index| (format!("file-{index}"), Vec::new()))
            .collect();
        assert!(ProfileFiles::new(files, false).is_err());
        assert!(ProfileFiles::new(
            BTreeMap::from([("Cookies".into(), vec![0; MAX_PROFILE_BYTES + 1])]),
            false
        )
        .is_err());
    }
}
