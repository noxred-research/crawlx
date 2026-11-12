//! Explicitly approved native FTP reads: anonymous or credential-reference login, binary file
//! reads and bounded directory discovery. Passive mode only; every data connection must reach the
//! checked control peer, never an address the server names.

use super::{ProtocolError, ProtocolResource};
use crate::{governor::Origin, OriginGovernor, Resolver};
use bytes::Bytes;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_policy::egress::EgressPolicy;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;
use url::Url;

const MAX_LISTING_LINE: usize = 4096;
const MAX_ENTRY_NAME: usize = 255;
const MAX_CREDENTIAL_BYTES: usize = 256;

/// Operator-only authority for native FTP acquisition.
///
/// An origin without a credential reference is read anonymously. An origin with one logs in with the
/// resolved secret pair and never falls back to anonymous access. Directory targets need an approved
/// [`FtpRecursion`] bound. The control channel is plain FTP: only register origins reachable over a
/// network the operator already trusts for that traffic.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct FtpRegistry {
    /// Exact canonical FTP origins; paths never grant authority to another origin.
    pub origins: BTreeSet<String>,
    /// Explicit approved run-policy revisions.
    pub policy_digests: BTreeSet<String>,
    /// Secret references by exact registered origin; the values never appear in configuration.
    #[serde(default)]
    pub credential_refs: BTreeMap<String, FtpCredentialRef>,
    /// Approved directory discovery bounds; absent means directory targets are refused.
    #[serde(default)]
    pub recursion: Option<FtpRecursion>,
    #[serde(skip)]
    logins: Arc<BTreeMap<String, FtpLogin>>,
}

/// References to the user name and password of one registered origin.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct FtpCredentialRef {
    /// Secret reference resolving to the account name.
    pub username_ref: String,
    /// Secret reference resolving to the password.
    pub password_ref: String,
}

impl FtpCredentialRef {
    /// Name the secrets by reference.
    #[must_use]
    pub fn new(username_ref: impl Into<String>, password_ref: impl Into<String>) -> Self {
        Self {
            username_ref: username_ref.into(),
            password_ref: password_ref.into(),
        }
    }
}

/// Approved directory discovery bounds for one registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct FtpRecursion {
    /// Directory levels listed below the requested directory; deeper directories are only reported.
    pub max_depth: u8,
    /// Listed entries across the whole discovery, including refused ones.
    pub max_entries: u32,
}

impl FtpRecursion {
    /// Bound one discovery by depth and total entries.
    #[must_use]
    pub const fn new(max_depth: u8, max_entries: u32) -> Self {
        Self {
            max_depth,
            max_entries,
        }
    }
}

/// Resolved account. `SecretOr` zeroizes the values and keeps them out of `Debug` output.
#[derive(Clone, Debug)]
struct FtpLogin {
    username: SecretOr<String>,
    password: SecretOr<String>,
}

/// One acquisition's identity and bounds.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct FtpRequest<'a> {
    /// File target, or a directory target (trailing slash) when recursion is approved.
    pub url: &'a Url,
    /// Approved run-policy revision.
    pub policy_digest: &'a str,
    /// Aggregate bytes read from data connections.
    pub max_bytes: u32,
    /// Whole operation ceiling.
    pub deadline: Duration,
    /// Data transfers allowed, one per listed directory or file.
    pub max_requests: u32,
}

impl<'a> FtpRequest<'a> {
    /// A request allowed 64 data transfers.
    #[must_use]
    pub const fn new(url: &'a Url, policy_digest: &'a str, max_bytes: u32, deadline: Duration) -> Self {
        Self {
            url,
            policy_digest,
            max_bytes,
            deadline,
            max_requests: 64,
        }
    }

    /// Cap the data transfers, for callers sharing a run-wide request allowance.
    #[must_use]
    pub const fn with_max_requests(mut self, max_requests: u32) -> Self {
        self.max_requests = max_requests;
        self
    }
}

/// Checked network facilities one acquisition runs through.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct FtpNetwork<'a> {
    /// Egress policy for control and data peers.
    pub policy: &'a EgressPolicy,
    /// Checked name resolution.
    pub resolver: &'a dyn Resolver,
    /// Shared per-origin admission.
    pub governor: &'a Arc<OriginGovernor>,
}

impl<'a> FtpNetwork<'a> {
    /// Bind policy, resolver and governor.
    #[must_use]
    pub const fn new(
        policy: &'a EgressPolicy,
        resolver: &'a dyn Resolver,
        governor: &'a Arc<OriginGovernor>,
    ) -> Self {
        Self {
            policy,
            resolver,
            governor,
        }
    }
}

impl std::fmt::Debug for FtpNetwork<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpNetwork").finish_non_exhaustive()
    }
}

impl FtpRegistry {
    /// Register approved origins and policy revisions; anonymous and file-only until extended.
    #[must_use]
    pub fn new(origins: BTreeSet<String>, policy_digests: BTreeSet<String>) -> Self {
        Self {
            origins,
            policy_digests,
            ..Self::default()
        }
    }

    /// Approve directory discovery within `recursion`.
    #[must_use]
    pub fn with_recursion(mut self, recursion: FtpRecursion) -> Self {
        self.recursion = Some(recursion);
        self
    }

    /// Log in to `origin` with the secrets behind `credential`, once resolved.
    #[must_use]
    pub fn with_credential_ref(mut self, origin: impl Into<String>, credential: FtpCredentialRef) -> Self {
        self.credential_refs.insert(origin.into(), credential);
        self
    }

    /// Whether any origin logs in with credentials.
    #[must_use]
    pub fn has_credentials(&self) -> bool {
        !self.credential_refs.is_empty()
    }

    /// Whether `url`'s origin logs in with credentials instead of anonymously.
    #[must_use]
    pub fn uses_credentials(&self, url: &Url) -> bool {
        crawlx_core::protocol::protocol_origin(url)
            .is_some_and(|origin| self.credential_refs.contains_key(&origin))
    }

    /// Whether `url` names a directory (trailing slash) rather than a file.
    #[must_use]
    pub fn is_directory(url: &Url) -> bool {
        url.path().ends_with('/')
    }

    /// Validate the bounded operator registration without opening sockets.
    ///
    /// # Errors
    /// Refuses empty, oversized, noncanonical or non-FTP origin registrations, credential
    /// references for unregistered origins and out-of-range recursion bounds.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.origins.is_empty()
            || self.origins.len() > 64
            || self.policy_digests.is_empty()
            || self.policy_digests.len() > 64
            || self
                .policy_digests
                .iter()
                .any(|id| id.is_empty() || id.len() > 128)
            || self.origins.iter().any(|origin| {
                origin.len() > 512
                    || Url::parse(origin).ok().is_none_or(|url| {
                        url.scheme() != "ftp"
                            || !url.username().is_empty()
                            || url.password().is_some()
                            || crawlx_core::protocol::protocol_origin(&url).as_ref() != Some(origin)
                    })
            })
        {
            return Err(ProtocolError::Refused("FTP registry bounds or origin"));
        }
        if self.credential_refs.len() > 64
            || self.credential_refs.iter().any(|(origin, refs)| {
                !self.origins.contains(origin)
                    || ![&refs.username_ref, &refs.password_ref].iter().all(|reference| {
                        !reference.is_empty()
                            && reference.len() <= 512
                            && CredentialRef((*reference).clone()).scheme().is_some()
                    })
            })
        {
            return Err(ProtocolError::Refused("FTP credential registration"));
        }
        if self
            .recursion
            .is_some_and(|r| !(1..=8).contains(&r.max_depth) || !(1..=4096).contains(&r.max_entries))
        {
            return Err(ProtocolError::Refused("FTP recursion bounds"));
        }
        Ok(())
    }

    /// Resolve every credential reference once, before any run uses the registry.
    ///
    /// The secrets stay inside the registry; no error, `Debug` output or resource carries them.
    ///
    /// # Errors
    /// Refuses an unresolvable reference, an empty or oversized value, or a value holding control
    /// characters (command injection), without naming the reference or the value.
    pub async fn resolve_credentials(&mut self, resolver: &dyn SecretResolver) -> Result<(), ProtocolError> {
        let mut logins = BTreeMap::new();
        for (origin, refs) in &self.credential_refs {
            let username = resolve_secret(resolver, &refs.username_ref).await?;
            let password = resolve_secret(resolver, &refs.password_ref).await?;
            logins.insert(origin.clone(), FtpLogin { username, password });
        }
        self.logins = Arc::new(logins);
        Ok(())
    }

    /// Admit an exact approved target and policy before DNS or connection work.
    ///
    /// # Errors
    /// Refuses URL credentials, command injection, traversal, unknown authority and directories
    /// when recursion is not approved.
    pub fn admit(&self, url: &Url, policy_digest: &str) -> Result<(), ProtocolError> {
        self.admitted_path(url, policy_digest).map(|_| ())
    }

    fn admitted_path<'a>(
        &self,
        url: &'a Url,
        policy_digest: &str,
    ) -> Result<std::borrow::Cow<'a, str>, ProtocolError> {
        let origin = crawlx_core::protocol::protocol_origin(url);
        if url.scheme() != "ftp"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !origin
                .as_ref()
                .is_some_and(|origin| self.origins.contains(origin))
            || !self.policy_digests.contains(policy_digest)
        {
            return Err(ProtocolError::CapabilityUnavailable(
                "approved FTP origin and policy",
            ));
        }
        let path = percent_encoding::percent_decode_str(url.path())
            .decode_utf8()
            .map_err(|_| ProtocolError::Refused("FTP path encoding"))?;
        if path.len() > 4096
            || (path.ends_with('/') && self.recursion.is_none())
            || path.bytes().any(|byte| byte.is_ascii_control() || byte == b'\\')
            || path.split('/').any(|part| matches!(part, "." | ".."))
            || path.contains(';')
        {
            return Err(ProtocolError::Refused("FTP file path"));
        }
        Ok(path)
    }

    /// Read one complete binary-mode file, or discover the files below an approved directory, with
    /// separately checked control and passive data sockets.
    ///
    /// A file target returns its bytes. A directory target (trailing slash) returns no body: its
    /// `children` are the in-scope files found by listing up to the approved depth (plus directories
    /// at the depth limit, unlisted and ending in `/`), sorted, and `denied_children` the entries that
    /// are out of scope, not regular files or directories, or unsafely named. Exceeding the entry cap,
    /// the byte cap or the transfer allowance fails the whole discovery.
    ///
    /// Cancellation drops both owned sockets and the origin permit. Failed or partial transfers
    /// return errors, never a complete resource. No filesystem spool or helper task is created.
    ///
    /// # Errors
    /// Refuses missing authority, an unresolved credential, passive bounce, disallowed peers/ports,
    /// malformed replies, incomplete transfer, byte/entry/deadline exhaustion and cancellation.
    pub async fn acquire(
        &self,
        request: &FtpRequest<'_>,
        network: &FtpNetwork<'_>,
        cancel: &CancellationToken,
    ) -> Result<ProtocolResource, ProtocolError> {
        let FtpRequest {
            url,
            policy_digest,
            max_bytes,
            deadline,
            max_requests,
        } = *request;
        let FtpNetwork {
            policy,
            resolver,
            governor,
        } = *network;
        // Decode once: the authorized effective path is exactly the path sent to RETR/MLSD.
        let path = self.admitted_path(url, policy_digest)?;
        if max_bytes == 0
            || max_bytes > 67_108_864
            || max_requests == 0
            || deadline.is_zero()
            || deadline > Duration::from_secs(90)
        {
            return Err(ProtocolError::Limit);
        }
        let origin =
            crawlx_core::protocol::protocol_origin(url).ok_or(ProtocolError::Refused("FTP origin"))?;
        // Fail closed: a credentialed origin never degrades to anonymous access.
        let login = if self.credential_refs.contains_key(&origin) {
            Some(
                self.logins
                    .get(&origin)
                    .ok_or(ProtocolError::CapabilityUnavailable("FTP credential unresolved"))?,
            )
        } else {
            None
        };
        let operation = async {
            if !scope_allows(policy, url, &path) {
                return Err(ProtocolError::Refused("FTP authorization"));
            }
            let host = url.host_str().ok_or(ProtocolError::Refused("FTP host"))?;
            let port = url
                .port_or_known_default()
                .ok_or(ProtocolError::Refused("FTP port"))?;
            policy
                .check_host(host)
                .and_then(|()| policy.check_port(port))
                .map_err(|_| ProtocolError::Refused("FTP control policy"))?;
            let addresses = resolver.resolve(host).await?;
            policy
                .check_all(host, &addresses)
                .map_err(|_| ProtocolError::Refused("FTP DNS policy"))?;
            let ip = addresses.first().ok_or(ProtocolError::Refused("FTP empty DNS"))?;
            let _permit = governor
                .acquire(&Origin::new(&origin))
                .await
                .map_err(|_| ProtocolError::Refused("origin admission unavailable"))?;
            let control_socket = SocketAddr::new(*ip, port);
            let control = tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(control_socket))
                .await
                .map_err(|_| ProtocolError::Deadline)??;
            if control.peer_addr()? != control_socket {
                return Err(ProtocolError::Refused("FTP control peer"));
            }
            let mut control = BufReader::new(control);
            expect(&mut control, &[220]).await?;
            authenticate(&mut control, login).await?;
            let build_digest = if login.is_some() {
                "native-ftp-credential-v1"
            } else {
                "native-ftp-v1"
            };
            if FtpRegistry::is_directory(url) {
                let limits = self.recursion.ok_or(ProtocolError::Refused("FTP file path"))?;
                let discovery = Discovery {
                    ip: *ip,
                    policy,
                    limits,
                    max_bytes,
                    max_listings: max_requests,
                };
                let found = discovery.run(&mut control, url, &path).await?;
                return Ok(ProtocolResource {
                    final_url: Some(url.clone()),
                    target_status: None,
                    gateway_status: None,
                    media_type: None,
                    decoded_bytes: found.bytes,
                    body: Bytes::new(),
                    children: found.children,
                    denied_children: found.denied,
                    network_requests: found.listings,
                    build_digest: build_digest.to_owned(),
                    redirects: Vec::new(),
                });
            }
            expect_command(&mut control, "TYPE I", &[200]).await?;
            let mut data = open_data(&mut control, *ip, policy).await?;
            expect_command(&mut control, &format!("RETR {path}"), &[125, 150]).await?;
            let body = read_bounded(
                &mut data,
                usize::try_from(max_bytes).map_err(|_| ProtocolError::Limit)?,
            )
            .await?;
            drop(data);
            expect(&mut control, &[226, 250]).await?;
            Ok(ProtocolResource {
                final_url: Some(url.clone()),
                target_status: None,
                gateway_status: None,
                media_type: None,
                decoded_bytes: body.len(),
                body: Bytes::from(body),
                children: Vec::new(),
                denied_children: Vec::new(),
                network_requests: 1,
                build_digest: build_digest.to_owned(),
                redirects: Vec::new(),
            })
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(ProtocolError::Cancelled),
            result = tokio::time::timeout(deadline, operation) => result.map_err(|_| ProtocolError::Deadline)?,
        }
    }
}

async fn resolve_secret(
    resolver: &dyn SecretResolver,
    reference: &str,
) -> Result<SecretOr<String>, ProtocolError> {
    let value = resolver
        .resolve(&CredentialRef(reference.to_owned()))
        .await
        .map_err(|_| ProtocolError::Refused("FTP credential unavailable"))?;
    let text = value.expose();
    if text.is_empty() || text.len() > MAX_CREDENTIAL_BYTES || text.chars().any(char::is_control) {
        return Err(ProtocolError::Refused("FTP credential value"));
    }
    Ok(value)
}

/// Authorization-record scope for both the URL as written and its decoded effective path, so
/// decoding can never weaken a path exclusion.
fn scope_allows(policy: &EgressPolicy, url: &Url, decoded_path: &str) -> bool {
    let Some(scope) = &policy.record_scope else {
        return true;
    };
    if scope.check_request(url).is_err() {
        return false;
    }
    if decoded_path == url.path() {
        return true;
    }
    let mut effective = url.clone();
    effective.set_path(decoded_path);
    scope.check_request(&effective).is_ok()
}

/// Anonymous login, or login with resolved secrets. Replies are never surfaced: a server may echo
/// the account or password into its refusal text.
async fn authenticate(
    control: &mut BufReader<TcpStream>,
    login: Option<&FtpLogin>,
) -> Result<(), ProtocolError> {
    let Some(login) = login else {
        let (code, _) = command(control, "USER anonymous").await?;
        return match code {
            230 => Ok(()),
            331 => expect_command(control, "PASS anonymous@", &[230])
                .await
                .map(|_| ()),
            _ => Err(ProtocolError::Refused("FTP anonymous login")),
        };
    };
    // The command text holds the secret; `SecretOr` zeroizes it on drop.
    let user = SecretOr::secret(format!("USER {}", login.username.expose()));
    let (code, _) = command(control, user.expose()).await?;
    match code {
        230 => Ok(()),
        331 => {
            let pass = SecretOr::secret(format!("PASS {}", login.password.expose()));
            let (code, _) = command(control, pass.expose()).await?;
            if code == 230 {
                Ok(())
            } else {
                Err(ProtocolError::Refused("FTP login rejected"))
            }
        }
        _ => Err(ProtocolError::Refused("FTP login rejected")),
    }
}

/// Negotiate passive mode and connect. The data peer is always the already checked control peer:
/// an address the server names (PASV) is accepted only if it equals it, so a hostile or
/// misconfigured server cannot redirect transfers to a third party (FTP bounce).
async fn open_data(
    control: &mut BufReader<TcpStream>,
    control_ip: IpAddr,
    policy: &EgressPolicy,
) -> Result<TcpStream, ProtocolError> {
    let (code, line) = command(control, "EPSV").await?;
    let data_socket = match code {
        229 => SocketAddr::new(control_ip, epsv_port(&line)?),
        500 | 501 | 502 | 504 | 522 if control_ip.is_ipv4() => {
            let (_, line) = expect_command(control, "PASV", &[227]).await?;
            let socket = pasv_socket(&line)?;
            if socket.ip() != control_ip {
                return Err(ProtocolError::Refused("FTP passive bounce"));
            }
            socket
        }
        _ => return Err(ProtocolError::Refused("FTP passive negotiation")),
    };
    policy
        .check_ip(data_socket.ip())
        .and_then(|()| policy.check_port(data_socket.port()))
        .map_err(|_| ProtocolError::Refused("FTP data policy"))?;
    let data = tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(data_socket))
        .await
        .map_err(|_| ProtocolError::Deadline)??;
    if data.peer_addr()? != data_socket {
        return Err(ProtocolError::Refused("FTP data peer"));
    }
    Ok(data)
}

async fn read_bounded(data: &mut TcpStream, limit: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut body = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let count = data.read(&mut chunk).await?;
        if count == 0 {
            return Ok(body);
        }
        if body.len().saturating_add(count) > limit {
            return Err(ProtocolError::Limit);
        }
        body.extend_from_slice(&chunk[..count]);
    }
}

/// Breadth-first MLSD discovery over one control session.
struct Discovery<'a> {
    ip: IpAddr,
    policy: &'a EgressPolicy,
    limits: FtpRecursion,
    max_bytes: u32,
    max_listings: u32,
}

struct Found {
    children: Vec<Url>,
    denied: Vec<Url>,
    listings: u32,
    bytes: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EntryKind {
    File,
    Dir,
    /// `cdir`/`pdir`: the listed directory and its parent, never entries.
    Relative,
    Other,
}

impl Discovery<'_> {
    async fn run(
        &self,
        control: &mut BufReader<TcpStream>,
        root: &Url,
        root_path: &str,
    ) -> Result<Found, ProtocolError> {
        let mut found = Found {
            children: Vec::new(),
            denied: Vec::new(),
            listings: 0,
            bytes: 0,
        };
        let mut bytes_left = usize::try_from(self.max_bytes).map_err(|_| ProtocolError::Limit)?;
        let mut entries = 0_u32;
        let mut visited = BTreeSet::from([root_path.to_owned()]);
        let mut queue = VecDeque::from([(root.clone(), root_path.to_owned(), 0_u8)]);
        while let Some((dir_url, dir_path, depth)) = queue.pop_front() {
            if found.listings >= self.max_listings {
                return Err(ProtocolError::Limit);
            }
            found.listings += 1;
            let mut data = open_data(control, self.ip, self.policy).await?;
            let argument = if dir_path.len() > 1 {
                dir_path.trim_end_matches('/')
            } else {
                dir_path.as_str()
            };
            expect_command(control, &format!("MLSD {argument}"), &[125, 150]).await?;
            let listing = read_bounded(&mut data, bytes_left).await?;
            drop(data);
            expect(control, &[226, 250]).await?;
            bytes_left -= listing.len();
            found.bytes = found.bytes.saturating_add(listing.len());
            let mut listed = parse_mlsd(&listing)?;
            listed.sort_by(|a, b| a.1.cmp(&b.1));
            for (kind, name) in listed {
                if kind == EntryKind::Relative {
                    continue;
                }
                entries = entries.saturating_add(1);
                if entries > self.limits.max_entries {
                    return Err(ProtocolError::Limit);
                }
                // Traversal spellings are an attack indicator, not an unusual file name.
                if matches!(name.as_str(), "." | "..") || name.contains('/') {
                    return Err(ProtocolError::Refused("FTP listing name"));
                }
                let mut child_url = dir_url.clone();
                let mut child_path = format!("{dir_path}{name}");
                {
                    let mut segments = child_url
                        .path_segments_mut()
                        .map_err(|_| ProtocolError::Refused("FTP URL"))?;
                    segments.pop_if_empty().push(&name);
                    if kind == EntryKind::Dir {
                        segments.push("");
                    }
                }
                if kind == EntryKind::Dir {
                    child_path.push('/');
                }
                let unusual = name.len() > MAX_ENTRY_NAME
                    || name.chars().any(char::is_control)
                    || name.contains(['\\', ';']);
                let listable = matches!(kind, EntryKind::File | EntryKind::Dir);
                if unusual || !listable || !scope_allows(self.policy, &child_url, &child_path) {
                    found.denied.push(child_url);
                } else if kind == EntryKind::File {
                    found.children.push(child_url);
                } else if depth < self.limits.max_depth {
                    if visited.insert(child_path.clone()) {
                        queue.push_back((child_url, child_path, depth + 1));
                    }
                } else {
                    found.children.push(child_url);
                }
            }
        }
        found.children.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        found.denied.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(found)
    }
}

/// RFC 3659 `MLSD` data: `fact=value;...; name`, CRLF terminated, classified by the `type` fact.
fn parse_mlsd(listing: &[u8]) -> Result<Vec<(EntryKind, String)>, ProtocolError> {
    let text = std::str::from_utf8(listing).map_err(|_| ProtocolError::Refused("FTP listing encoding"))?;
    if !text.is_empty() && !text.ends_with("\r\n") {
        return Err(ProtocolError::Refused("FTP listing framing"));
    }
    let mut entries = Vec::new();
    for line in text.split_terminator("\r\n") {
        if line.len() > MAX_LISTING_LINE {
            return Err(ProtocolError::Refused("FTP listing line"));
        }
        let (facts, name) = line
            .split_once(' ')
            .filter(|(_, name)| !name.is_empty())
            .ok_or(ProtocolError::Refused("FTP listing line"))?;
        let kind = facts
            .split(';')
            .filter_map(|fact| fact.split_once('='))
            .find(|(key, _)| key.eq_ignore_ascii_case("type"))
            .map_or(EntryKind::Other, |(_, value)| {
                match value.to_ascii_lowercase().as_str() {
                    "file" => EntryKind::File,
                    "dir" => EntryKind::Dir,
                    "cdir" | "pdir" => EntryKind::Relative,
                    _ => EntryKind::Other,
                }
            });
        entries.push((kind, name.to_owned()));
    }
    Ok(entries)
}

async fn command(control: &mut BufReader<TcpStream>, value: &str) -> Result<(u16, Vec<u8>), ProtocolError> {
    control.get_mut().write_all(value.as_bytes()).await?;
    control.get_mut().write_all(b"\r\n").await?;
    reply(control).await
}

async fn expect_command(
    control: &mut BufReader<TcpStream>,
    value: &str,
    codes: &[u16],
) -> Result<(u16, Vec<u8>), ProtocolError> {
    let result = command(control, value).await?;
    if !codes.contains(&result.0) {
        return Err(ProtocolError::Refused("FTP command rejected"));
    }
    Ok(result)
}

async fn expect(control: &mut BufReader<TcpStream>, codes: &[u16]) -> Result<(), ProtocolError> {
    if !codes.contains(&reply(control).await?.0) {
        return Err(ProtocolError::Refused("FTP transfer reply"));
    }
    Ok(())
}

// RFC 959 framing: finite aggregate bytes and lines, including multiline greetings.
async fn reply(control: &mut BufReader<TcpStream>) -> Result<(u16, Vec<u8>), ProtocolError> {
    let mut prefix: Option<[u8; 3]> = None;
    let mut total = 0_usize;
    for _ in 0..64 {
        let mut line = Vec::new();
        let count = (&mut *control).take(4097).read_until(b'\n', &mut line).await?;
        total = total.saturating_add(count);
        if count == 0 || count > 4096 || total > 16_384 || !line.ends_with(b"\r\n") {
            return Err(ProtocolError::Refused("FTP reply framing"));
        }
        if let Some(expected) = prefix {
            if line.get(..3) != Some(expected.as_slice()) || line.get(3) != Some(&b' ') {
                continue;
            }
        } else {
            if line.len() < 6 || !line[..3].iter().all(u8::is_ascii_digit) || !matches!(line[3], b' ' | b'-')
            {
                return Err(ProtocolError::Refused("FTP reply code"));
            }
            if line[3] == b'-' {
                prefix = Some([line[0], line[1], line[2]]);
                continue;
            }
        }
        let code =
            u16::from(line[0] - b'0') * 100 + u16::from(line[1] - b'0') * 10 + u16::from(line[2] - b'0');
        return Ok((code, line));
    }
    Err(ProtocolError::Limit)
}

fn passive_tuple(line: &[u8]) -> Result<&str, ProtocolError> {
    let text = std::str::from_utf8(line).map_err(|_| ProtocolError::Refused("FTP passive encoding"))?;
    let (_, suffix) = text
        .split_once('(')
        .ok_or(ProtocolError::Refused("FTP passive tuple"))?;
    let (tuple, _) = suffix
        .split_once(')')
        .ok_or(ProtocolError::Refused("FTP passive tuple"))?;
    Ok(tuple)
}

fn epsv_port(line: &[u8]) -> Result<u16, ProtocolError> {
    let tuple = passive_tuple(line)?.as_bytes();
    let delimiter = *tuple.first().ok_or(ProtocolError::Refused("FTP EPSV tuple"))?;
    if !(33..=126).contains(&delimiter)
        || tuple.len() < 5
        || tuple[1..3] != [delimiter; 2]
        || tuple.last() != Some(&delimiter)
    {
        return Err(ProtocolError::Refused("FTP EPSV tuple"));
    }
    let port = std::str::from_utf8(&tuple[3..tuple.len() - 1])
        .ok()
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(ProtocolError::Refused("FTP passive port"))?;
    Ok(port)
}

fn pasv_socket(line: &[u8]) -> Result<SocketAddr, ProtocolError> {
    let mut values = [0_u8; 6];
    let mut parts = passive_tuple(line)?.split(',');
    for value in &mut values {
        *value = parts
            .next()
            .filter(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|part| part.parse().ok())
            .ok_or(ProtocolError::Refused("FTP PASV tuple"))?;
    }
    let port = u16::from(values[4]) * 256 + u16::from(values[5]);
    if parts.next().is_some() || port == 0 {
        return Err(ProtocolError::Refused("FTP PASV tuple"));
    }
    Ok(SocketAddr::new(
        std::net::Ipv4Addr::new(values[0], values[1], values[2], values[3]).into(),
        port,
    ))
}

#[cfg(test)]
#[path = "ftp_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ftp_session_tests.rs"]
mod session_tests;
