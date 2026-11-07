//! Native offline WARC/WACZ replay. This is not action replay.
//!
//! All input is validated before the listener opens. Only an owned literal loopback
//! origin is reachable through the checked proxy. Archived headers, profiles and
//! credentials are never installed. The clean-room URL mapper uses no replay engine.

use crawlx_core::browser::{BrowserContext, BrowserError, ContextConfig, NavigationGuard, NavigationVerdict};
use crawlx_core::observation::{BrowserBuildInfo, QuiescencePolicy};
use crawlx_core::page_op::{PageOp, PageOpResult, ShotSpec};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{SessionId, TenantId};
use crawlx_policy::egress::EgressPolicy;
use crawlx_policy::fixture_evaluation::{FixtureEvaluationLease, FixtureEvaluationScope};
use crawlx_storage::archive::collection::{ApprovedLocalDependency, ArchiveCollection};
use crawlx_storage::archive::{ArchiveError, Limits};
use hmac::Mac as _;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroize as _;

/// The mapper/security policy revision, included in every baseline.
pub const REPLAY_POLICY: &str = "crawlx-native-offline-replay/v1";
/// Maximum combined encoded primary/dependency input bytes for this local renderer.
pub const MAX_ENCODED_BYTES: u64 = 64 * 1024 * 1024;
const MEMORY_BYTES: usize = 64 * 1024 * 1024;
const CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const REQUEST_LIMIT: usize = 10_000;
const LEDGER_PATH_BYTES: usize = 8 * 1024 * 1024;
const MISSING_BODY: &[u8] = b"archive resource missing; live network fallback is disabled";
const METHOD_BODY: &[u8] = b"archive replay only serves GET and HEAD";
static MISSING_DIGEST: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| digest(MISSING_BODY));
static METHOD_DIGEST: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| digest(METHOD_BODY));
static EMPTY_DIGEST: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| digest(&[]));
static ROOT_URLS: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
    std::sync::LazyLock::new(|| regex::Regex::new(r#"([\"'])/([^/\"'])"#));
static ABSOLUTE_URLS: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"https?://[^\s\"'<>\)\\]+|//[A-Za-z0-9][^\s\"'<>\)\\]*"#)
    });

/// Offline replay errors. Payloads and secret-bearing URLs are not error messages.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplayError {
    /// Archive validation or bounded payload retrieval failed.
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    /// Local file/socket access failed.
    #[error("offline replay I/O failed")]
    Io(#[from] std::io::Error),
    /// Browser work failed without a live fallback.
    #[error(transparent)]
    Browser(#[from] BrowserError),
    /// Input, policy, budget or isolation requirement was not satisfied.
    #[error("offline replay refused: {0}")]
    Refused(&'static str),
    /// A structured task failed.
    #[error("offline replay task failed")]
    Join(#[from] tokio::task::JoinError),
    /// Owned pool could not confirm browser resource death.
    #[error("offline replay cleanup failed")]
    Cleanup(#[source] crate::error::SessionError),
    /// The operating system did not supply cryptographic capability entropy.
    #[error("offline replay capability entropy unavailable")]
    Entropy(#[source] rand::Error),
    /// Secret request controls could not be installed.
    #[error("offline replay request controls failed")]
    Controls(#[from] crawlx_core::CoreError),
}

/// Recorded, distinct QA resource. Bytes stay in memory until the caller's content sink.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ReplayCapture {
    /// Fixed phase name, never an archive-controlled path.
    pub kind: String,
    /// Stored-byte SHA-256.
    pub digest: String,
    /// PNG or normalized UTF-8 text.
    pub media_type: String,
    /// Captured length.
    pub length: usize,
    /// True when the phase hit its text capture cap; QA never calls that a full match.
    #[serde(default)]
    pub truncated: bool,
    /// Actual bytes. JSON manifests do not embed content.
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

/// Actual served resource result, including missing resources. URLs remain content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ReplayResource {
    /// Mapped path, excluding ephemeral listener port.
    pub path: String,
    /// Actual local status. Missing archive assets return 404.
    pub status: u16,
    /// Original recorded status, absent for WARC resources.
    pub recorded_status: Option<u16>,
    /// Digest of served bytes after explicit URL mapping.
    pub digest: String,
}

/// One selected archived page and its separate captures.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ReplayPage {
    /// Stable ordinal within the sampled page list.
    pub ordinal: usize,
    /// Archive target identity, never a live navigation destination.
    pub target: String,
    /// Initial/final text and viewport/full-page/final screenshots.
    pub captures: Vec<ReplayCapture>,
}

/// Actual offline execution provenance and results.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ReplayReport {
    /// Manifest schema.
    pub schema_version: u8,
    /// Exact encoded archive SHA-256.
    pub archive_digest: String,
    /// Exact approved dependency bundle SHA-256 pins, in caller-supplied order.
    pub dependency_digests: Vec<String>,
    /// Native mapper and isolation policy pin.
    pub policy: String,
    /// Actual worker build.
    pub build: String,
    /// Actual browser/CDP pin, not a caller assertion.
    pub browser: BrowserBuildInfo,
    /// Deterministic sampling seed.
    pub seed: CrawlSeed,
    /// Optional bounded regex over original page URLs, applied before seeded sampling.
    /// Absent in older manifests means no filter.
    #[serde(default)]
    pub page_filter: Option<String>,
    /// Width and height used by the browser.
    pub viewport: (u32, u32),
    /// Sampled pages.
    pub pages: Vec<ReplayPage>,
    /// Sorted actual local responses, preserving repeated request counts.
    pub resources: Vec<ReplayResource>,
    /// Actual proxy refusals. Refusals never cause a network fallback.
    pub denied_requests: u64,
    /// Last bounded redacted proxy refusals, without timestamps or request headers.
    /// This is diagnostic evidence; `denied_requests` remains the complete counter.
    #[serde(default)]
    pub denial_evidence: Vec<String>,
    /// Explicit fidelity restrictions, never a claim of complete capture.
    pub limitations: Vec<String>,
}

#[derive(Debug)]
struct Asset {
    target: String,
    mime: String,
    status: Option<u16>,
    captured_at: chrono::DateTime<chrono::Utc>,
    body: Vec<u8>,
}

/// Fully validated, privacy-approved in-memory archive. No listener exists during validation.
#[derive(Debug)]
#[non_exhaustive]
pub struct ReplayArchive {
    digest: String,
    dependency_digests: Vec<String>,
    assets: BTreeMap<String, Asset>,
    origins: BTreeMap<String, usize>,
    pages: Vec<String>,
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn executable_build(cancel: &CancellationToken) -> Result<String, ReplayError> {
    // Linux /proc pins the running image even if its pathname is concurrently replaced.
    #[cfg(target_os = "linux")]
    let mut input = File::open("/proc/self/exe")?;
    #[cfg(not(target_os = "linux"))]
    let mut input = File::open(std::env::current_exe()?)?;
    let maximum = 4_294_967_296u64;
    if input.metadata()?.len() > maximum {
        return Err(ReplayError::Refused("runtime executable pin bound"));
    }
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 32768];
    let mut total = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Err(ReplayError::Refused("cancelled"));
        }
        let count = input.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| ReplayError::Refused("executable byte count"))?)
            .ok_or(ReplayError::Refused("executable byte count"))?;
        if total > maximum {
            return Err(ReplayError::Refused("runtime executable pin bound"));
        }
        hash.update(&bytes[..count]);
    }
    Ok(format!(
        "crawlx-worker/{};host-executable-sha256:{:x}",
        env!("CARGO_PKG_VERSION"),
        hash.finalize()
    ))
}

impl ReplayArchive {
    /// Validate WARC/WACZ framing, all digests, relationships and WACZ index ranges,
    /// then materialize bounded approved replay resources. No source URL is fetched.
    ///
    /// # Errors
    /// Rejects invalid archives, secrets/binary data without approval, incomplete
    /// representations, non-HTTP targets, tenant mismatches and memory overflows.
    pub fn from_snapshot(
        snapshot: Vec<u8>,
        tenant: TenantId,
        dependencies: Vec<ApprovedLocalDependency>,
    ) -> Result<Self, ReplayError> {
        if snapshot.len() > MEMORY_BYTES {
            return Err(ReplayError::Refused("64 MiB encoded archive snapshot bound"));
        }
        let mut limits = Limits::default();
        limits.total_bytes = MAX_ENCODED_BYTES;
        let mut collection = ArchiveCollection::from_snapshot(snapshot, Some(tenant), dependencies, limits)?;
        let archive_digest = collection.primary_sha256().to_owned();
        let dependency_digests = collection.source_sha256().skip(1).map(str::to_owned).collect();
        let mut assets = BTreeMap::<String, Asset>::new();
        let mut origins = BTreeMap::new();
        let mut size = 0usize;
        for location in collection.records() {
            let record = &location.record;
            if !matches!(
                record.record_type.as_str(),
                "response" | "resource" | "conversion" | "revisit"
            ) {
                continue;
            }
            let Some(target) = &record.target else {
                continue;
            };
            let mut url = Url::parse(target).map_err(|_| ReplayError::Refused("invalid target"))?;
            if !matches!(url.scheme(), "http" | "https")
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(ReplayError::Refused("target must be credential-free HTTP(S)"));
            }
            url.set_fragment(None);
            if url
                .query()
                .is_some_and(|query| query.split('&').any(private_query_field))
            {
                return Err(ReplayError::Refused("sensitive decoded archive URL parameter"));
            }
            if url.as_str().len() > 8192 {
                return Err(ReplayError::Refused("archive resource URL bound"));
            }
            let identity = url.to_string();
            if assets
                .get(&identity)
                .is_some_and(|asset| asset.captured_at > record.date)
            {
                continue;
            }
            let payload = collection.payload(&record.id)?;
            if !payload.requested.retention_approved || !payload.source.retention_approved {
                return Err(ReplayError::Refused(
                    "logical resource failed validated text-only privacy policy",
                ));
            }
            if payload.requested.truncated || payload.source.truncated {
                return Err(ReplayError::Refused(
                    "truncated archive representation is not a complete replay resource",
                ));
            }
            let body = payload.bytes;
            let previous = assets.remove(&identity).map_or(0, |asset| asset.body.len());
            size = size
                .checked_sub(previous)
                .and_then(|size| size.checked_add(body.len()))
                .ok_or(ReplayError::Refused("memory bound"))?;
            if size > MEMORY_BYTES {
                return Err(ReplayError::Refused("64 MiB materialized replay bound"));
            }
            origins.insert(url.origin().ascii_serialization(), 0);
            let mime = payload.source.mime;
            approve_body(&mime, &body)?;
            assets.insert(
                identity,
                Asset {
                    target: target.clone(),
                    mime,
                    status: record.status,
                    captured_at: record.date,
                    body,
                },
            );
        }
        let pages: Vec<_> = assets
            .iter()
            .filter(|(_, asset)| {
                asset
                    .mime
                    .split(';')
                    .next()
                    .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/html"))
            })
            .map(|(url, _)| url.clone())
            .collect();
        for (index, id) in origins.values_mut().enumerate() {
            *id = index;
        }
        if pages.is_empty() {
            return Err(ReplayError::Refused("archive has no retained HTML entry point"));
        }
        Ok(Self {
            digest: archive_digest,
            dependency_digests,
            assets,
            origins,
            pages,
        })
    }

    fn mapped(&self, url: &Url) -> String {
        match self.origins.get(&url.origin().ascii_serialization()) {
            Some(index) => format!(
                "/r/{index}{}{}",
                url.path(),
                url.query().map_or_else(String::new, |q| format!("?{q}"))
            ),
            None => format!(
                "/missing/{}",
                digest(url.as_str().as_bytes()).trim_start_matches("sha256:")
            ),
        }
    }

    fn rewritten(&self, asset: &Asset) -> Result<Vec<u8>, ReplayError> {
        let text = std::str::from_utf8(&asset.body)
            .map_err(|_| ReplayError::Refused("binary replay capability unavailable"))?;
        let base = Url::parse(&asset.target).map_err(|_| ReplayError::Refused("invalid base"))?;
        // A bounded textual URL map is deliberately not a general JavaScript interpreter.
        // Computed/encoded external URLs are refused at the actual proxy boundary.
        let roots = ROOT_URLS
            .as_ref()
            .map_err(|_| ReplayError::Refused("mapper expression"))?;
        let prefix = self
            .origins
            .get(&base.origin().ascii_serialization())
            .ok_or(ReplayError::Refused("unknown origin"))?;
        let rooted = roots.replace_all(text, |caps: &regex::Captures<'_>| {
            format!("{}/r/{prefix}/{}", &caps[1], &caps[2])
        });
        let absolute = ABSOLUTE_URLS
            .as_ref()
            .map_err(|_| ReplayError::Refused("mapper expression"))?;
        let output = absolute.replace_all(&rooted, |caps: &regex::Captures<'_>| {
            base.join(&caps[0])
                .map_or_else(|_| "/missing/invalid-url".into(), |u| self.mapped(&u))
        });
        if output.len() > CAPTURE_BYTES {
            return Err(ReplayError::Refused("rewritten resource byte bound"));
        }
        Ok(output.into_owned().into_bytes())
    }
}

#[derive(Debug)]
struct ListenerLease {
    address: SocketAddr,
    live: AtomicBool,
}
impl FixtureEvaluationLease for ListenerLease {
    fn address(&self) -> SocketAddr {
        self.address
    }
    fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
    fn revoke(&self) {
        self.live.store(false, Ordering::Release);
    }
}

struct RevokeLeaseOnDrop(Arc<ListenerLease>);
impl Drop for RevokeLeaseOnDrop {
    fn drop(&mut self) {
        self.0.revoke();
    }
}

#[derive(Debug)]
struct ExactGuard(FixtureEvaluationScope);
#[async_trait::async_trait]
impl NavigationGuard for ExactGuard {
    async fn check(&self, url: &Url) -> NavigationVerdict {
        if self.0.permits_url(url) {
            NavigationVerdict::Allow
        } else {
            NavigationVerdict::RobotsBlocked {
                reason: "offline_archive_external_denied",
            }
        }
    }
    fn intercepts_subresources(&self) -> bool {
        true
    }
    async fn check_subresource(&self, url: &Url) -> NavigationVerdict {
        self.check(url).await
    }
}

const ACCESS_HEADER: &str = "x-crawlx-replay-capability";
const ACCESS_DOMAIN: &[u8] = b"crawlx/offline-replay-listener-access/v1";
type AccessMac = hmac::Hmac<Sha256>;

#[derive(Debug)]
struct LocalAccess {
    value: crawlx_core::SecretOr<String>,
    proof: crawlx_core::SecretOr<[u8; 32]>,
}

impl LocalAccess {
    fn new() -> Result<Self, ReplayError> {
        let mut entropy = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut *entropy)
            .map_err(ReplayError::Entropy)?;
        let mut value = String::with_capacity(64);
        for byte in entropy.iter() {
            write!(&mut value, "{byte:02x}").map_err(|_| ReplayError::Refused("capability encoding"))?;
        }
        let mut mac = AccessMac::new_from_slice(value.as_bytes())
            .map_err(|_| ReplayError::Refused("capability key"))?;
        mac.update(ACCESS_DOMAIN);
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&mac.finalize().into_bytes());
        Ok(Self {
            value: crawlx_core::SecretOr::secret(value),
            proof: crawlx_core::SecretOr::secret(proof),
        })
    }

    fn accepts(&self, request: &str) -> bool {
        let mut presented = None;
        for line in request
            .split("\r\n\r\n")
            .next()
            .unwrap_or_default()
            .lines()
            .skip(1)
        {
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case(ACCESS_HEADER) {
                    if presented.is_some() {
                        return false;
                    }
                    presented = Some(value.trim());
                }
            }
        }
        let Some(value) = presented.filter(|value| value.len() == 64) else {
            return false;
        };
        let Ok(mut mac) = AccessMac::new_from_slice(value.as_bytes()) else {
            return false;
        };
        mac.update(ACCESS_DOMAIN);
        // verify_slice compares the fixed-size proof in constant time; no secret string equality.
        mac.verify_slice(self.proof.expose()).is_ok()
    }

    async fn controls(&self) -> Result<crawlx_core::request_controls::RequestControls, ReplayError> {
        let mut fetch = crawlx_core::config::Fetch::default();
        fetch
            .extra_headers
            .insert(ACCESS_HEADER, self.value.expose().clone());
        let controls =
            crawlx_core::request_controls::RequestControls::resolve(&fetch, "127.0.0.1", None).await;
        if let Some(mut temporary) = fetch.extra_headers.insert(ACCESS_HEADER, String::new()) {
            temporary.zeroize();
        }
        Ok(controls?)
    }
}

#[derive(Debug, Default)]
struct ReplayLedger {
    events: Vec<ReplayResource>,
    path_bytes: usize,
    exhausted: bool,
}

#[derive(Debug)]
struct Server {
    scope: FixtureEvaluationScope,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    resources: Arc<parking_lot::Mutex<ReplayLedger>>,
    access: Arc<LocalAccess>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.scope.revoke();
        self.cancel.cancel();
        self.task.abort();
    }
}

impl Server {
    async fn start(archive: &ReplayArchive) -> Result<Self, ReplayError> {
        // Eager mapping completes before binding: serving cannot discover a late corrupt resource.
        let mut assets = BTreeMap::new();
        let mut size = 0usize;
        for asset in archive.assets.values() {
            let url = Url::parse(&asset.target).map_err(|_| ReplayError::Refused("invalid target"))?;
            let body = archive.rewritten(asset)?;
            size = size
                .checked_add(body.len())
                .ok_or(ReplayError::Refused("mapped memory bound"))?;
            if size > MEMORY_BYTES {
                return Err(ReplayError::Refused("64 MiB mapped replay bound"));
            }
            let digest = digest(&body);
            assets.insert(
                archive.mapped(&url),
                ServedAsset {
                    mime: asset.mime.clone(),
                    status: asset.status,
                    body,
                    digest,
                },
            );
        }
        let access = Arc::new(LocalAccess::new()?);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let lease = Arc::new(ListenerLease {
            address: listener.local_addr()?,
            live: AtomicBool::new(true),
        });
        let scope =
            FixtureEvaluationScope::new(lease.clone()).ok_or(ReplayError::Refused("owned listener scope"))?;
        let cancel = CancellationToken::new();
        let resources = Arc::new(parking_lot::Mutex::new(ReplayLedger::default()));
        let task = tokio::spawn(serve(
            listener,
            Arc::new(assets),
            resources.clone(),
            cancel.clone(),
            lease,
            access.clone(),
        ));
        Ok(Self {
            scope,
            cancel,
            task,
            resources,
            access,
        })
    }

    async fn stop(&mut self) -> Result<(), ReplayError> {
        self.scope.revoke();
        self.cancel.cancel();
        match tokio::time::timeout(Duration::from_secs(2), &mut self.task).await {
            Ok(result) => {
                result?;
            }
            Err(_) => {
                self.task.abort();
                let _ = (&mut self.task).await;
                return Err(ReplayError::Refused("listener cleanup deadline"));
            }
        }
        Ok(())
    }
}

struct ServedAsset {
    mime: String,
    status: Option<u16>,
    body: Vec<u8>,
    digest: String,
}
type ServedAssets = BTreeMap<String, ServedAsset>;

async fn serve(
    listener: TcpListener,
    assets: Arc<ServedAssets>,
    resources: Arc<parking_lot::Mutex<ReplayLedger>>,
    cancel: CancellationToken,
    lease: Arc<ListenerLease>,
    access: Arc<LocalAccess>,
) {
    // Revoke before the listener argument drops, including panic/task-abort paths.
    let _revoke = RevokeLeaseOnDrop(lease.clone());
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept(), if connections.len() < 16 => {
                let Ok((socket, _)) = accepted else { break; };
                let assets = assets.clone();
                let resources = resources.clone();
                let access = access.clone();
                connections.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(5), respond(socket, &assets, &resources, &access)).await;
                });
            }
        }
    }
    lease.revoke();
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn respond(
    mut socket: TcpStream,
    assets: &ServedAssets,
    resources: &parking_lot::Mutex<ReplayLedger>,
    access: &LocalAccess,
) -> Result<(), std::io::Error> {
    let mut request = zeroize::Zeroizing::new(Vec::with_capacity(2048));
    let mut buf = zeroize::Zeroizing::new([0u8; 1024]);
    loop {
        let n = socket.read(&mut *buf).await?;
        if n == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buf[..n]);
        if request.len() > 16 * 1024 {
            return Ok(());
        }
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let Ok(text) = std::str::from_utf8(&request) else {
        return Ok(());
    };
    if !access.accepts(text) {
        socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n").await?;
        return socket.shutdown().await;
    }
    let mut line = text.lines().next().unwrap_or_default().split_whitespace();
    let method = line.next().unwrap_or_default();
    let path = line.next().unwrap_or_default();
    if !path.starts_with('/') || path.starts_with("//") {
        return Ok(());
    }
    let (mime, recorded_status, body, status, entity_digest) = if !matches!(method, "GET" | "HEAD") {
        (
            "text/plain; charset=utf-8",
            None,
            METHOD_BODY,
            405,
            METHOD_DIGEST.as_str(),
        )
    } else {
        match assets.get(path) {
            Some(asset) => (
                asset.mime.as_str(),
                asset.status,
                asset.body.as_slice(),
                asset
                    .status
                    .filter(|s| (200..=599).contains(s) && !matches!(s, 204 | 304))
                    .unwrap_or(200),
                asset.digest.as_str(),
            ),
            None => (
                "text/plain; charset=utf-8",
                None,
                MISSING_BODY,
                404,
                MISSING_DIGEST.as_str(),
            ),
        }
    };
    {
        let approved_path = redacted_resource_path(path);
        let mut ledger = resources.lock();
        let next_bytes = ledger
            .path_bytes
            .checked_add(approved_path.len())
            .filter(|bytes| *bytes <= LEDGER_PATH_BYTES);
        if ledger.events.len() >= REQUEST_LIMIT || next_bytes.is_none() {
            ledger.exhausted = true;
            return Ok(());
        }
        if let Some(bytes) = next_bytes {
            ledger.path_bytes = bytes;
        }
        let served_digest = if method == "HEAD" {
            EMPTY_DIGEST.as_str()
        } else {
            entity_digest
        };
        ledger.events.push(ReplayResource {
            path: approved_path,
            status,
            recorded_status,
            digest: served_digest.to_owned(),
        });
    }
    let mime = if mime.bytes().all(|b| (32..127).contains(&b)) {
        mime
    } else {
        "application/octet-stream"
    };
    // No archived Set-Cookie, Location, Refresh, CSP, auth or content-disposition survives.
    // Sandbox denies forms, popups and downloads; workers cannot spawn network clients.
    let headers = format!("HTTP/1.1 {status} Replay\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-src 'self'; worker-src 'none'; object-src 'none'; base-uri 'self'; form-action 'none'; sandbox allow-scripts allow-same-origin\r\n\r\n", body.len());
    socket.write_all(headers.as_bytes()).await?;
    if method != "HEAD" {
        socket.write_all(body).await?;
    }
    socket.shutdown().await
}

/// Capture only through the guarded BrowserContext interface.
async fn capture_page(
    context: &mut dyn BrowserContext,
    ordinal: usize,
    target: String,
    url: &Url,
) -> Result<ReplayPage, ReplayError> {
    let options = crawlx_url::CanonicalizeOptions {
        query_policy: crawlx_core::config::QueryPolicy::KeepAll,
        ..Default::default()
    };
    let mut canonical = crawlx_url::Canonicalizer::canonicalize_url(url, &options)
        .map_err(|_| ReplayError::Refused("local canonical URL"))?;
    // Replay addresses exact validated archive identities, not frontier query normalization.
    canonical.url = url.clone();
    canonical.key = crawlx_core::hash::Digest::of(crawlx_url::KEY_DOMAIN, url.as_str().as_bytes());
    context.navigate(&canonical).await?;
    if context.settle(QuiescencePolicy::default()).await?.settle_timeout {
        return Err(ReplayError::Refused("initial readiness deadline"));
    }
    let mut captures = vec![
        text_capture(context, "initial_text").await?,
        shot(context, "viewport", false).await?,
    ];
    if context.settle(QuiescencePolicy::default()).await?.settle_timeout {
        return Err(ReplayError::Refused("final readiness deadline"));
    }
    captures.push(shot(context, "full_page", true).await?);
    captures.push(text_capture(context, "final_text").await?);
    captures.push(shot(context, "final", true).await?);
    Ok(ReplayPage {
        ordinal,
        target,
        captures,
    })
}

async fn text_capture(context: &mut dyn BrowserContext, kind: &str) -> Result<ReplayCapture, ReplayError> {
    let result = context.page_op(PageOp::EvaluateScript {
        script: "(() => { const text = document.body?.innerText || ''; return {text: text.slice(0, 65536), truncated: text.length > 65536}; })()".to_owned(),
    }).await?;
    let PageOpResult::Json(serde_json::Value::Object(mut value)) = result else {
        return Err(ReplayError::Refused("text capture unavailable"));
    };
    let Some(serde_json::Value::String(text)) = value.remove("text") else {
        return Err(ReplayError::Refused("text capture unavailable"));
    };
    let Some(serde_json::Value::Bool(truncated)) = value.remove("truncated") else {
        return Err(ReplayError::Refused("text completeness unavailable"));
    };
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let redactor = crawlx_telemetry::redact::Redactor::new();
    let approved = redactor
        .scrub_session_queries(&redactor.scrub(&normalized))
        .into_owned();
    approve_body("text/plain", approved.as_bytes())?;
    let mut captured = capture(kind, "text/plain", approved.into_bytes());
    captured.truncated = truncated;
    Ok(captured)
}
async fn shot(
    context: &mut dyn BrowserContext,
    kind: &str,
    full_page: bool,
) -> Result<ReplayCapture, ReplayError> {
    if full_page {
        let dimensions = context
            .page_op(PageOp::EvaluateScript {
                script: "[document.documentElement.scrollWidth, document.documentElement.scrollHeight]"
                    .into(),
            })
            .await?;
        let PageOpResult::Json(serde_json::Value::Array(size)) = dimensions else {
            return Err(ReplayError::Refused("screenshot dimensions unavailable"));
        };
        let pixels = size
            .first()
            .and_then(serde_json::Value::as_u64)
            .zip(size.get(1).and_then(serde_json::Value::as_u64))
            .and_then(|(width, height)| width.checked_mul(height));
        if !pixels.is_some_and(|pixels| pixels > 0 && pixels <= 16_777_216) {
            return Err(ReplayError::Refused("full-page screenshot pixel bound"));
        }
    }
    let result = context
        .page_op(PageOp::Screenshot(ShotSpec {
            full_page,
            ..ShotSpec::default()
        }))
        .await?;
    let PageOpResult::Bytes {
        bytes,
        content_type: "image/png",
    } = result
    else {
        return Err(ReplayError::Refused("PNG capture unavailable"));
    };
    if bytes.len() > CAPTURE_BYTES {
        return Err(ReplayError::Refused("screenshot byte bound"));
    }
    Ok(capture(kind, "image/png", bytes))
}
fn capture(kind: &str, mime: &str, bytes: Vec<u8>) -> ReplayCapture {
    ReplayCapture {
        kind: kind.into(),
        digest: digest(&bytes),
        media_type: mime.into(),
        length: bytes.len(),
        truncated: false,
        bytes,
    }
}

fn private_query_field(field: &str) -> bool {
    let Some((name, value)) = url::form_urlencoded::parse(field.as_bytes()).next() else {
        return false;
    };
    let redactor = crawlx_telemetry::redact::Redactor::new();
    crate::capture::sensitive_field(&name)
        || [name.as_ref(), value.as_ref()].into_iter().any(|part| {
            redactor.scrub(part) != part || !crawlx_extract::secrets::detect(&[0; 32], &[], part).is_empty()
        })
}

fn redacted_resource_path(path: &str) -> String {
    let redactor = crawlx_telemetry::redact::Redactor::new();
    let approved = redactor.scrub_session_queries(&redactor.scrub(path)).into_owned();
    let Some(question) = approved.find('?') else {
        return approved;
    };
    let mut output: Option<String> = None;
    let mut offset = question + 1;
    for (index, field) in approved[question + 1..].split('&').enumerate() {
        let private = private_query_field(field);
        let creating = private && output.is_none();
        if creating {
            let mut bytes = String::with_capacity(approved.len());
            bytes.push_str(&approved[..offset]);
            output = Some(bytes);
        }
        if let Some(bytes) = &mut output {
            if !creating && index > 0 {
                bytes.push('&');
            }
            bytes.push_str(if private { "[REDACTED]" } else { field });
        }
        // Each field and separator came from the bounded request target.
        offset += field.len() + 1;
    }
    output.unwrap_or(approved)
}

pub(crate) fn approve_body(mime: &str, bytes: &[u8]) -> Result<(), ReplayError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ReplayError::Refused("binary retention capability unavailable"))?;
    let redactor = crawlx_telemetry::redact::Redactor::new();
    if text
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
        || redactor.scrub(text) != text
        || redactor.scrub_session_queries(text) != text
        || !crawlx_extract::secrets::detect(&[0; 32], &[], text).is_empty()
    {
        return Err(ReplayError::Refused("resource failed canonical secret exclusion"));
    }
    let json = mime.to_ascii_lowercase().contains("json") || text.trim_start().starts_with(['{', '[']);
    if json {
        let value = serde_json::from_str(text).map_err(|_| ReplayError::Refused("invalid JSON resource"))?;
        if crate::capture::sensitive_json_fields(&value) {
            return Err(ReplayError::Refused("sensitive JSON resource"));
        }
    } else if text
        .split(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '_' | '-'))
        .any(crate::capture::sensitive_field)
    {
        return Err(ReplayError::Refused("credential-bearing resource field"));
    }
    Ok(())
}

fn select_pages<'a>(
    pages: &'a [String],
    seed: CrawlSeed,
    sample: usize,
    page_filter: Option<&String>,
) -> Result<Vec<&'a String>, ReplayError> {
    if !(1..=32).contains(&sample) {
        return Err(ReplayError::Refused("sample must be 1..32"));
    }
    let include = page_filter.map_or(&[][..], std::slice::from_ref);
    let filter = crawlx_policy::scope::UrlPatterns::new(include, &[])
        .map_err(|_| ReplayError::Refused("invalid or over-limit page filter"))?;
    if let Some(pattern) = page_filter {
        approve_body("text/plain", pattern.as_bytes())?;
    }
    let mut selected: Vec<_> = pages
        .iter()
        .filter(|url| filter.check(url).is_ok())
        .map(|url| (seed.derive("archive-qa-sample", &[url.as_bytes()]), url))
        .collect();
    if selected.is_empty() {
        return Err(ReplayError::Refused("no HTML pages match replay selection"));
    }
    selected.sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
    selected.truncate(sample);
    selected.sort_unstable_by(|left, right| left.1.cmp(right.1));
    Ok(selected.into_iter().map(|(_, url)| url).collect())
}

/// Validate and render local archive pages without live network access.
///
/// The backend gets a fresh temporary profile, no extensions or imported storage,
/// no auto-download and no unpinned/attached-browser exception. Cancellation and
/// every failure close the context, stop the backend and revoke the listener.
///
/// # Errors
/// Returns validation, isolation, browser, timeout, cancellation or cleanup failures.
pub async fn replay(
    archive: ReplayArchive,
    seed: CrawlSeed,
    sample: usize,
    page_filter: Option<String>,
    cancel: CancellationToken,
) -> Result<ReplayReport, ReplayError> {
    if cancel.is_cancelled() {
        return Err(ReplayError::Refused("cancelled"));
    }
    let selected = select_pages(&archive.pages, seed, sample, page_filter.as_ref())?;
    let pin_cancel = cancel.clone();
    let actual_build = tokio::task::spawn_blocking(move || executable_build(&pin_cancel)).await??;
    let mut server = Server::start(&archive).await?;
    let mut policy = EgressPolicy::new(false).with_seed_port(server.scope.origin());
    policy
        .extra_allow
        .push(ipnet::IpNet::from(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)));
    policy.fixture_scope = Some(server.scope.clone());
    let proxy = crawlx_fetch::egress::EgressProxy::serve(
        Arc::new(policy),
        Arc::new(crawlx_fetch::resolver::StaticResolver::new()),
    )
    .await
    .map_err(|_| ReplayError::Refused("checked replay proxy unavailable"))?;
    let mut launch = crawlx_browser::LaunchConfig::new();
    launch.egress_proxy_port = Some(proxy.port());
    launch.allow_unpinned = false;
    launch.auto_download_chromium = false;
    launch.unsafe_no_sandbox_for_ci = false;
    launch.isolated_environment = true;
    // A browser-default startup tab and background services are not archive
    // resources. Disable their producers; keep every proxy refusal in QA.
    launch.extra_args = [
        "--no-startup-window",
        "--disable-background-mode",
        "--disable-component-extensions-with-background-pages",
        "--disable-client-side-phishing-detection",
        "--disable-domain-reliability",
        "--safebrowsing-disable-auto-update",
        "--metrics-recording-only",
        "--disable-features=OptimizationHints,MediaRouter,AutofillServerCommunication,CertificateTransparencyComponentUpdater,InterestFeedContentSuggestions",
    ].into_iter().map(str::to_owned).collect();
    let pool = crate::pool::BrowserPool::new(
        launch,
        crate::pool::PoolConfig {
            max_browsers: 1,
            contexts_per_browser: 1,
        },
    );
    let mut config = ContextConfig::new(SessionId::new());
    config.max_tabs = 1;
    config.viewport = crawlx_core::observation::Viewport {
        width: 1280,
        height: 720,
    };
    config.egress_proxy_port = Some(proxy.port());
    config.navigation_guard = Some(Arc::new(ExactGuard(server.scope.clone())));
    config.console_capture = false;
    config.request_controls = server.access.controls().await?;
    let pooled = tokio::select! {
        () = cancel.cancelled() => return Err(ReplayError::Refused("cancelled")),
        value = pool.acquire(config, true) => value?,
    };
    let (mut context, build, lease) = pooled.into_parts();
    let render = async {
        if !build.pinned || build.attached {
            return Err(ReplayError::Refused("pinned owned Chromium required"));
        }
        let mut pages = Vec::with_capacity(selected.len());
        let mut captured_bytes = 0usize;
        for (ordinal, target) in selected.into_iter().enumerate() {
            let original = Url::parse(target).map_err(|_| ReplayError::Refused("page target"))?;
            let url = server
                .scope
                .origin()
                .join(&archive.mapped(&original))
                .map_err(|_| ReplayError::Refused("mapped page"))?;
            let page = capture_page(context.as_mut(), ordinal, target.clone(), &url).await?;
            for capture in &page.captures {
                captured_bytes = captured_bytes
                    .checked_add(capture.bytes.len())
                    .ok_or(ReplayError::Refused("capture total byte bound"))?;
            }
            if captured_bytes > MEMORY_BYTES {
                return Err(ReplayError::Refused("64 MiB total capture byte bound"));
            }
            pages.push(page);
        }
        Ok::<_, ReplayError>(pages)
    };
    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => Err(ReplayError::Refused("cancelled")),
        result = tokio::time::timeout(Duration::from_secs(90), render) => result.unwrap_or(Err(ReplayError::Refused("90 second replay deadline"))),
    };
    let closed = tokio::time::timeout(Duration::from_secs(2), context.close()).await;
    let context_closed = matches!(&closed, Ok(Ok(())));
    // Pool release confirms whole-process death, including context-close failures.
    // Never drop a shutdown future and claim resource death.
    lease
        .release(context_closed)
        .await
        .map_err(ReplayError::Cleanup)?;
    let denied_requests = proxy.denials();
    let denial_evidence = proxy
        .denied_events()
        .into_iter()
        .rev()
        .take(32)
        .map(|event| {
            // Policy rule names include "authorization"; they are typed metadata,
            // not content. Omit them rather than weaken the canonical content gate.
            let detail = format!("{} {}:{}", event.method, event.host, event.port);
            let redactor = crawlx_telemetry::redact::Redactor::new();
            let detail: String = redactor.scrub(&detail).chars().take(512).collect();
            if approve_body("text/plain", detail.as_bytes()).is_ok() {
                detail
            } else {
                "refusal_details_redacted".into()
            }
        })
        .collect();
    let dialed = proxy.dialed_hosts();
    proxy.shutdown().await;
    server.stop().await?;
    if dialed
        .iter()
        .any(|(host, port)| host != "127.0.0.1" || Some(*port) != server.scope.origin().port())
    {
        return Err(ReplayError::Refused("proxy dial escaped owned listener"));
    }
    if !context_closed {
        return Err(ReplayError::Refused("context cleanup failed"));
    }
    let mut resources = {
        let ledger = server.resources.lock();
        if ledger.exhausted {
            return Err(ReplayError::Refused(
                "request count or redacted resource metadata bound reached",
            ));
        }
        ledger.events.clone()
    };
    resources.sort_by(|a, b| (&a.path, a.status, &a.digest).cmp(&(&b.path, b.status, &b.digest)));
    Ok(ReplayReport {
        schema_version: 1,
        archive_digest: archive.digest,
        policy: REPLAY_POLICY.into(),
        build: actual_build,
        browser: build,
        dependency_digests: archive.dependency_digests,
        seed,
        page_filter,
        viewport: (1280, 720),
        pages: result?,
        resources,
        denied_requests,
        denial_evidence,
        limitations: vec![
            "available retained representations only; no original-wire/completeness claim".into(),
            "bounded textual URL mapping; computed external URLs denied, not fetched".into(),
            "latest WARC-Date per target; equal dates use deterministic filename/member order".into(),
            "text capture cap is explicit; truncated text comparisons are not evaluated".into(),
            "workers, forms, popups, downloads, stored credentials and archived response headers disabled"
                .into(),
            "binary replay requires a separate approved retention capability".into(),
        ],
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn url_filter_precedes_seeded_sampling_and_is_order_independent() {
        let pages = vec![
            "https://fixture.example.test/a".to_owned(),
            "https://fixture.example.test/b".to_owned(),
            "https://fixture.example.test/c".to_owned(),
        ];
        let seed = CrawlSeed(7);
        let unfiltered = select_pages(&pages, seed, 1, None).unwrap();
        let target = pages.iter().find(|url| *url != unfiltered[0]).unwrap();
        let only_target = format!("^{}$", regex::escape(target));
        assert_eq!(
            select_pages(&pages, seed, 1, Some(&only_target)).unwrap(),
            [target]
        );

        let all = r"/[abc]$".to_owned();
        let selected = select_pages(&pages, seed, 2, Some(&all)).unwrap();
        let mut reversed = pages.clone();
        reversed.reverse();
        assert_eq!(selected, select_pages(&reversed, seed, 2, Some(&all)).unwrap());
    }

    #[test]
    fn invalid_private_and_zero_match_filters_fail_selection() {
        let pages = vec!["https://fixture.example.test/a".to_owned()];
        for filter in ["[", "password=private-value", "/absent$"] {
            assert!(matches!(
                select_pages(&pages, CrawlSeed(0), 1, Some(&filter.to_owned())),
                Err(ReplayError::Refused(_))
            ));
        }
        let oversized = "a".repeat(65_537);
        assert!(matches!(
            select_pages(&pages, CrawlSeed(0), 1, Some(&oversized)),
            Err(ReplayError::Refused(_))
        ));
    }

    fn archive() -> ReplayArchive {
        let bytes = b"<!doctype html><html><body><h1>Owned replay content</h1></body></html>";
        let header = crawlx_storage::archive::warc::RecordHeader {
            fields: BTreeMap::from([
                ("WARC-Type".into(), "resource".into()),
                (
                    "WARC-Record-ID".into(),
                    "<urn:uuid:00000000-0000-8000-8000-000000000001>".into(),
                ),
                ("WARC-Date".into(), "2026-11-04T12:34:56.789Z".into()),
                ("WARC-Target-URI".into(), "https://fixture.example.test/".into()),
                ("Content-Type".into(), "text/html".into()),
            ]),
            payload_offset: 0,
        };
        let mut file = std::io::Cursor::new(Vec::new());
        crawlx_storage::archive::warc::write_record(
            &mut file,
            &header,
            &mut std::io::Cursor::new(bytes),
            u64::try_from(bytes.len()).unwrap(),
            Limits::default(),
        )
        .unwrap();
        ReplayArchive::from_snapshot(
            file.into_inner(),
            "00000000-0000-8000-8000-000000000002".parse().unwrap(),
            Vec::new(),
        )
        .unwrap()
    }

    async fn exchange(address: SocketAddr, request: &str) -> Vec<u8> {
        let mut socket = TcpStream::connect(address).await.unwrap();
        socket.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let mut bounded = socket.take(4097);
        tokio::time::timeout(Duration::from_secs(1), bounded.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        response
    }

    #[tokio::test]
    async fn listener_refuses_other_local_clients_and_revokes_its_owned_origin() {
        let mut server = Server::start(&archive()).await.unwrap();
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, server.scope.origin().port().unwrap()));
        let no_capability = format!("GET /r/0/ HTTP/1.1\r\nHost: {address}\r\n\r\n");
        assert!(exchange(address, &no_capability)
            .await
            .starts_with(b"HTTP/1.1 403"));
        let mut wrong = zeroize::Zeroizing::new(server.access.value.expose().clone());
        let replacement = if wrong.starts_with('0') { "1" } else { "0" };
        wrong.replace_range(..1, replacement);
        let wrong_request = zeroize::Zeroizing::new(format!(
            "GET /r/0/ HTTP/1.1\r\nHost: {address}\r\n{ACCESS_HEADER}: {}\r\n\r\n",
            wrong.as_str()
        ));
        assert!(exchange(address, &wrong_request)
            .await
            .starts_with(b"HTTP/1.1 403"));
        let authorized = zeroize::Zeroizing::new(format!(
            "GET /r/0/ HTTP/1.1\r\nHost: {address}\r\n{ACCESS_HEADER}: {}\r\n\r\n",
            server.access.value.expose()
        ));
        let response = exchange(address, &authorized).await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(String::from_utf8(response)
            .unwrap()
            .contains("Owned replay content"));
        assert_eq!(server.resources.lock().events.len(), 1);
        let mut policy = EgressPolicy::new(false);
        policy.fixture_scope = Some(server.scope.clone());
        let proxy = crawlx_fetch::egress::EgressProxy::serve(
            Arc::new(policy),
            Arc::new(crawlx_fetch::resolver::StaticResolver::new()),
        )
        .await
        .unwrap();
        let proxy_address = SocketAddr::from((Ipv4Addr::LOCALHOST, proxy.port()));
        assert!(exchange(proxy_address, "CONNECT Background.Example.Test:443 HTTP/1.1\r\nHost: Background.Example.Test:443\r\nConnection: close\r\n\r\n")
            .await.starts_with(b"HTTP/1.1 403"));
        assert_eq!(proxy.denials(), 1);
        assert!(proxy.dialed_hosts().is_empty());
        let denied = proxy.denied_events();
        assert_eq!(denied[0].host, "background.example.test");
        assert_eq!(denied[0].port, 443);
        assert_eq!(denied[0].rule, "authorization_scope");
        proxy.shutdown().await;
        let scope = server.scope.clone();
        server.stop().await.unwrap();
        assert!(!scope.is_live());
        assert!(TcpStream::connect(address).await.is_err());
    }
}
