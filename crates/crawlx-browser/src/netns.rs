//! Verified anonymous network-namespace launch contract.
//!
//! The deployment helper installs a default-drop firewall before a
//! capability-cleared, non-root gate can exec Chromium. Only loopback TCP proxy
//! and CDP endpoints exist. Unix-domain relays cross the namespace boundary;
//! there is no veth, default route, DNS allowance, or second proxy authority.
//! This is not a filesystem sandbox beyond what each mode states below.
//!
//! Two operator-selected modes share one evidence protocol:
//!
//! * [`NamespaceMode::Privileged`]: the worker runs as root (so its process-group
//!   guard can kill privileged supervisors) and Chromium runs as a configured
//!   non-root host identity in an `unshare --net` namespace.
//! * [`NamespaceMode::Rootless`]: the worker runs as an ordinary user. The helper
//!   creates a user namespace whose root is the worker itself and whose other ids
//!   are the worker's `/etc/subuid` and `/etc/subgid` ranges. Chromium runs under a
//!   distinct subordinate kernel identity that never aliases the worker, in a
//!   private mount namespace over a size-bounded tmpfs profile, with its own sandbox.
//!   The worker owns the user namespace and therefore keeps signal and `/proc`
//!   authority over every namespaced process.
//!
//! In both modes the worker re-reads the actual process identity from `/proc`
//! after the helper's evidence and again after Chromium's DevTools endpoint appears.

use serde::Deserialize;
use serde_json::{json, Value};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdout, Command};

/// Namespace evidence protocol version produced by `crawlx-netns-helper.py`.
const PROTOCOL_VERSION: u8 = 2;
/// Highest namespace-internal id the rootless helper maps (`65535` is excluded as `-1`).
const ROOTLESS_MAX_ID: u32 = 65_534;
/// Executables rootless mode needs beyond the privileged set; checked at preflight.
const ROOTLESS_TOOLS: [&str; 3] = ["/usr/bin/newuidmap", "/usr/bin/newgidmap", "/usr/bin/mount"];

/// How the browser namespace is created and which kernel identity runs Chromium.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NamespaceMode {
    /// Root worker, `unshare --net`, Chromium as a configured non-root host identity.
    Privileged,
    /// Non-root worker, user + network + mount namespaces, subordinate Chromium identity.
    Rootless,
}

impl NamespaceMode {
    /// Stable helper and evidence spelling of the mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Privileged => "privileged",
            Self::Rootless => "rootless",
        }
    }
}

/// Operator-only configuration for the installed namespace helper.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct NamespaceConfig {
    /// Absolute path to the installed `crawlx-netns-helper.py` executable.
    pub helper: PathBuf,
    /// Namespace creation mode; the worker's own privileges must match it.
    pub mode: NamespaceMode,
    /// Non-root identity for Chromium: a host id (privileged) or a namespace id (rootless).
    pub browser_uid: u32,
    /// Non-root primary group for Chromium; supplementary groups are cleared.
    pub browser_gid: u32,
}

impl NamespaceConfig {
    /// Privileged mode: select the installed helper and unprivileged host identity.
    #[must_use]
    pub fn new(helper: PathBuf, browser_uid: u32, browser_gid: u32) -> Self {
        Self {
            helper,
            mode: NamespaceMode::Privileged,
            browser_uid,
            browser_gid,
        }
    }

    /// Rootless mode: select the helper and the namespace-internal Chromium identity.
    ///
    /// Both ids must lie in `1..=65534`; the helper maps them onto the worker's
    /// subordinate id ranges.
    #[must_use]
    pub fn rootless(helper: PathBuf, browser_uid: u32, browser_gid: u32) -> Self {
        Self {
            helper,
            mode: NamespaceMode::Rootless,
            browser_uid,
            browser_gid,
        }
    }

    fn identity_in_range(&self) -> bool {
        let maximum = match self.mode {
            NamespaceMode::Privileged => u32::MAX - 1,
            NamespaceMode::Rootless => ROOTLESS_MAX_ID,
        };
        (1..=maximum).contains(&self.browser_uid) && (1..=maximum).contains(&self.browser_gid)
    }

    /// Check operator configuration without spawning any browser process.
    ///
    /// # Errors
    /// Rejects relative or writable helper paths, root or out-of-range browser
    /// identities, a worker whose privileges do not match the mode (privileged
    /// requires root; rootless refuses root), and missing rootless prerequisites
    /// (user namespaces, `newuidmap`, `newgidmap`, `mount`).
    pub async fn preflight(&self) -> Result<(), NamespaceError> {
        if !self.helper.is_absolute() || !self.identity_in_range() {
            return Err(NamespaceError::Contract(
                "absolute helper and non-root browser identity required",
            ));
        }
        let status = tokio::fs::read_to_string("/proc/self/status").await?;
        let worker = effective_uid(&status);
        match self.mode {
            NamespaceMode::Privileged => {
                if worker != Some(0) {
                    return Err(NamespaceError::Contract(
                        "namespace mode requires a root worker for group cleanup",
                    ));
                }
            }
            NamespaceMode::Rootless => {
                if worker.is_none_or(|uid| uid == 0) {
                    return Err(NamespaceError::Contract(
                        "rootless namespace mode refuses a root worker; use privileged mode",
                    ));
                }
                require_rootless_host().await?;
            }
        }
        let mut current = Some(self.helper.as_path());
        while let Some(path) = current {
            let meta = tokio::fs::symlink_metadata(path).await?;
            if meta.file_type().is_symlink()
                || !trusted_owner(self.mode, worker, meta.uid())
                || meta.mode() & 0o022 != 0
            {
                return Err(NamespaceError::Contract(match self.mode {
                    NamespaceMode::Privileged => "helper and parent directories must be root-owned and not writable by others",
                    NamespaceMode::Rootless => "helper and parent directories must be owned by root or the worker and not writable by others",
                }));
            }
            if path == self.helper && (!meta.is_file() || meta.mode() & 0o111 == 0) {
                return Err(NamespaceError::Contract(
                    "namespace helper must be an executable regular file",
                ));
            }
            current = path.parent();
        }
        Ok(())
    }

    pub(crate) fn command(&self, executable: &Path, flags: &[String], profile: &Path, proxy: u16) -> Command {
        let mut command = Command::new(&self.helper);
        command
            .arg("launch")
            .arg("--isolation")
            .arg(self.mode.as_str())
            .arg("--uid")
            .arg(self.browser_uid.to_string())
            .arg("--gid")
            .arg(self.browser_gid.to_string())
            .arg("--proxy-port")
            .arg(proxy.to_string())
            .arg("--profile")
            .arg(profile)
            .arg("--")
            .arg(executable)
            .args(flags);
        command
    }
}

/// Fail-closed namespace configuration, evidence, or operating-system failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NamespaceError {
    /// The operator configuration or helper evidence violated the contract.
    #[error("namespace contract rejected: {0}")]
    Contract(&'static str),
    /// An operating-system operation failed.
    #[error("namespace operating-system operation failed")]
    Io(#[from] std::io::Error),
    /// The bounded helper evidence was not the supported schema.
    #[error("namespace evidence could not be decoded")]
    Evidence(#[from] serde_json::Error),
}

/// Verified identity and endpoints of an owned namespace launch.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct NamespaceLaunch {
    /// Mode this launch was created and verified under.
    pub mode: NamespaceMode,
    /// Actual gate/Chromium process ID; exec preserves this identity.
    pub browser_pid: u32,
    /// Kernel network-namespace inode, independently read from `/proc`.
    pub namespace_inode: u64,
    /// Kernel user-namespace inode, independently read from `/proc`.
    pub user_namespace_inode: u64,
    /// TCP proxy endpoint inside Chromium's loopback namespace.
    pub proxy_port: u16,
    /// TCP CDP endpoint inside Chromium's loopback namespace.
    pub cdp_port: u16,
    /// Worker-loopback relay endpoint used by the CDP client.
    pub host_cdp_port: u16,
    /// Kernel user id of Chromium as seen from the worker's namespace.
    pub host_uid: u32,
    /// Kernel group id of Chromium as seen from the worker's namespace.
    pub host_gid: u32,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    version: u8,
    isolation: String,
    browser_pid: u32,
    namespace_inode: u64,
    user_namespace_inode: u64,
    proxy_port: u16,
    cdp_port: u16,
    host_cdp_port: u16,
    uid: u32,
    gid: u32,
    host_uid: u32,
    host_gid: u32,
    interfaces: Vec<String>,
    routes: Vec<Route>,
    firewall: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    family: u8,
    dst: String,
    kind: String,
    dev: String,
}

/// The worker's own namespace inodes and kernel identity, read from `/proc/self`.
#[derive(Clone, Copy, Debug)]
struct WorkerView {
    net_inode: u64,
    user_inode: u64,
    uid: u32,
    gid: u32,
}

impl WorkerView {
    async fn read() -> Result<Self, NamespaceError> {
        let status = tokio::fs::read_to_string("/proc/self/status").await?;
        Ok(Self {
            net_inode: tokio::fs::metadata("/proc/self/ns/net").await?.ino(),
            user_inode: tokio::fs::metadata("/proc/self/ns/user").await?.ino(),
            uid: effective_uid(&status).ok_or(NamespaceError::Contract("worker identity unreadable"))?,
            gid: effective_id(&status, "Gid:")
                .ok_or(NamespaceError::Contract("worker identity unreadable"))?,
        })
    }
}

impl Evidence {
    fn validate(
        self,
        config: &NamespaceConfig,
        proxy: u16,
        worker: &WorkerView,
    ) -> Result<NamespaceLaunch, NamespaceError> {
        if self.version != PROTOCOL_VERSION
            || self.isolation != config.mode.as_str()
            || self.browser_pid == 0
            || self.namespace_inode == 0
            || self.namespace_inode == worker.net_inode
            || self.uid != config.browser_uid
            || self.gid != config.browser_gid
            || self.proxy_port != proxy
            || [self.proxy_port, self.cdp_port, self.host_cdp_port].contains(&0)
            || self.proxy_port == 53
            || self.cdp_port == 53
            || self.proxy_port == self.cdp_port
            || self.interfaces != ["lo"]
            || self.routes.is_empty()
        {
            return Err(NamespaceError::Contract(
                "namespace identity or endpoints mismatch",
            ));
        }
        match config.mode {
            NamespaceMode::Privileged => {
                if self.user_namespace_inode != worker.user_inode
                    || self.host_uid != self.uid
                    || self.host_gid != self.gid
                {
                    return Err(NamespaceError::Contract("privileged namespace identity mismatch"));
                }
            }
            NamespaceMode::Rootless => {
                // A distinct user namespace and a kernel identity that is neither root
                // nor the worker: Chromium must never share ptrace/signal/file authority.
                if self.user_namespace_inode == 0
                    || self.user_namespace_inode == worker.user_inode
                    || [self.host_uid, self.host_gid].contains(&0)
                    || self.host_uid == worker.uid
                    || self.host_gid == worker.gid
                {
                    return Err(NamespaceError::Contract("rootless namespace identity mismatch"));
                }
            }
        }
        for route in &self.routes {
            let allowed = match route.family {
                4 => ["127.0.0.0/8", "127.0.0.1", "127.255.255.255"].contains(&route.dst.as_str()),
                6 => route.dst == "::1",
                _ => false,
            };
            if !allowed || route.dev != "lo" || !matches!(route.kind.as_str(), "local" | "broadcast") {
                return Err(NamespaceError::Contract("non-loopback route present"));
            }
        }
        if self.firewall != firewall_snapshot(proxy, self.cdp_port) {
            return Err(NamespaceError::Contract(
                "firewall differs from exact proxy/CDP allowlist",
            ));
        }
        Ok(NamespaceLaunch {
            mode: config.mode,
            browser_pid: self.browser_pid,
            namespace_inode: self.namespace_inode,
            user_namespace_inode: self.user_namespace_inode,
            proxy_port: self.proxy_port,
            cdp_port: self.cdp_port,
            host_cdp_port: self.host_cdp_port,
            host_uid: self.host_uid,
            host_gid: self.host_gid,
            uid: self.uid,
            gid: self.gid,
        })
    }
}

impl NamespaceLaunch {
    /// Revalidate the actual process identity after exec and before CDP exposure.
    ///
    /// # Errors
    /// Rejects disappeared processes, namespace changes, root/capability-bearing
    /// processes, retained supplementary groups, missing no-new-privileges, a
    /// process outside the owned group, and (rootless) any user-namespace identity
    /// map under which Chromium could alias the worker.
    pub async fn verify_process(&self, group: u32) -> Result<(), NamespaceError> {
        let pid = self.browser_pid;
        let namespace = tokio::fs::metadata(format!("/proc/{pid}/ns/net")).await?;
        let user_namespace = tokio::fs::metadata(format!("/proc/{pid}/ns/user")).await?;
        let status = tokio::fs::read_to_string(format!("/proc/{pid}/status")).await?;
        let stat = tokio::fs::read_to_string(format!("/proc/{pid}/stat")).await?;
        if namespace.ino() != self.namespace_inode
            || user_namespace.ino() != self.user_namespace_inode
            || all_ids(&status, "Uid:") != Some([self.host_uid; 4])
            || all_ids(&status, "Gid:") != Some([self.host_gid; 4])
            || field(&status, "Groups:") != Some("")
            || !zero_capabilities(&status)
            || field(&status, "NoNewPrivs:") != Some("1")
            || process_group(&stat) != Some(group)
        {
            return Err(NamespaceError::Contract(
                "actual browser process identity changed",
            ));
        }
        let worker = WorkerView::read().await?;
        match self.mode {
            NamespaceMode::Privileged => {
                if user_namespace.ino() != worker.user_inode
                    || self.host_uid != self.uid
                    || self.host_gid != self.gid
                {
                    return Err(NamespaceError::Contract(
                        "actual browser process identity changed",
                    ));
                }
            }
            NamespaceMode::Rootless => {
                if user_namespace.ino() == worker.user_inode {
                    return Err(NamespaceError::Contract(
                        "actual browser process identity changed",
                    ));
                }
                let uid_map = tokio::fs::read_to_string(format!("/proc/{pid}/uid_map")).await?;
                let gid_map = tokio::fs::read_to_string(format!("/proc/{pid}/gid_map")).await?;
                let identity =
                    rootless_identity(&uid_map, &gid_map, worker.uid, worker.gid, self.uid, self.gid)?;
                if identity != (self.host_uid, self.host_gid) {
                    return Err(NamespaceError::Contract(
                        "actual browser process identity changed",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Confirm the verified process execed the configured Chromium executable.
    ///
    /// The inode and device are compared, so a read-only bind mount of the same
    /// installation (rootless mode) satisfies this while any other file does not.
    ///
    /// # Errors
    /// Rejects a missing process or executable, or a different executable inode.
    pub async fn verify_executable(&self, executable: &Path) -> Result<(), NamespaceError> {
        let actual = tokio::fs::metadata(format!("/proc/{}/exe", self.browser_pid)).await?;
        let expected = tokio::fs::metadata(executable).await?;
        if actual.ino() != expected.ino() || actual.dev() != expected.dev() {
            return Err(NamespaceError::Contract(
                "namespace process did not exec configured Chromium",
            ));
        }
        Ok(())
    }

    pub(crate) fn relay_url(&self, original: &str) -> Result<String, NamespaceError> {
        let mut url =
            url::Url::parse(original).map_err(|_| NamespaceError::Contract("invalid CDP endpoint"))?;
        if url.scheme() != "ws"
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(self.cdp_port)
            || !url.path().starts_with("/devtools/browser/")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(NamespaceError::Contract(
                "CDP endpoint differs from namespace allowlist",
            ));
        }
        url.set_port(Some(self.host_cdp_port))
            .map_err(|()| NamespaceError::Contract("invalid CDP relay port"))?;
        Ok(url.into())
    }
}

pub(crate) async fn attest_and_release(
    config: &NamespaceConfig,
    proxy: u16,
    child: &mut Child,
    output: ChildStdout,
) -> Result<(NamespaceLaunch, BufReader<ChildStdout>), NamespaceError> {
    let mut output = BufReader::new(output);
    let mut bytes = Vec::new();
    (&mut output).take(65_537).read_until(b'\n', &mut bytes).await?;
    if bytes.len() > 65_536 || bytes.last() != Some(&b'\n') {
        return Err(NamespaceError::Contract(
            "missing or oversized namespace evidence",
        ));
    }
    let evidence: Evidence = serde_json::from_slice(&bytes)?;
    let launch = evidence.validate(config, proxy, &WorkerView::read().await?)?;
    let group = child
        .id()
        .ok_or(NamespaceError::Contract("helper process disappeared"))?;
    launch.verify_process(group).await?;
    child
        .stdin
        .as_mut()
        .ok_or(NamespaceError::Contract("namespace release pipe missing"))?
        .write_all(b"RELEASE\n")
        .await?;
    Ok((launch, output))
}

async fn require_rootless_host() -> Result<(), NamespaceError> {
    let limit = tokio::fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .await
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok());
    if limit.is_none_or(|value| value == 0) {
        return Err(NamespaceError::Contract(
            "rootless namespace mode requires user namespaces (user.max_user_namespaces > 0)",
        ));
    }
    for tool in ROOTLESS_TOOLS {
        match tokio::fs::metadata(tool).await {
            Ok(meta) if meta.is_file() && meta.mode() & 0o111 != 0 => {}
            _ => {
                return Err(NamespaceError::Contract(
                    "rootless namespace mode requires /usr/bin/newuidmap, /usr/bin/newgidmap and /usr/bin/mount",
                ));
            }
        }
    }
    Ok(())
}

/// Whether `owner` may own the helper and its parent directories in `mode`.
fn trusted_owner(mode: NamespaceMode, worker: Option<u32>, owner: u32) -> bool {
    owner == 0 || (mode == NamespaceMode::Rootless && worker == Some(owner))
}

/// One `inside outside count` line of a kernel `uid_map` or `gid_map`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdRange {
    inside: u64,
    outside: u64,
    count: u64,
}

fn parse_id_map(text: &str) -> Option<Vec<IdRange>> {
    text.lines()
        .map(|line| {
            let mut parts = line.split_whitespace().map(str::parse::<u64>);
            let range = IdRange {
                inside: parts.next()?.ok()?,
                outside: parts.next()?.ok()?,
                count: parts.next()?.ok()?,
            };
            parts.next().is_none().then_some(range)
        })
        .collect()
}

fn map_id(ranges: &[IdRange], inside: u32) -> Option<u32> {
    let inside = u64::from(inside);
    ranges.iter().find_map(|range| {
        let offset = inside
            .checked_sub(range.inside)
            .filter(|offset| *offset < range.count)?;
        u32::try_from(range.outside.checked_add(offset)?).ok()
    })
}

/// Host-view kernel identity of a rootless namespace browser id.
///
/// Namespace root must be exactly the worker (the namespace owner), the browser id
/// must map through a different range, and no other range may reach the worker's
/// kernel uid/gid. Chromium therefore never shares a kernel identity with the
/// worker, its credentials, files, or ptrace/signal authority.
fn rootless_identity(
    uid_map: &str,
    gid_map: &str,
    owner_uid: u32,
    owner_gid: u32,
    uid: u32,
    gid: u32,
) -> Result<(u32, u32), NamespaceError> {
    fn reject() -> NamespaceError {
        NamespaceError::Contract("rootless identity map aliases the worker or is malformed")
    }
    let mut result = [0_u32; 2];
    for (slot, (text, owner, id)) in result
        .iter_mut()
        .zip([(uid_map, owner_uid, uid), (gid_map, owner_gid, gid)])
    {
        let ranges = parse_id_map(text).ok_or_else(reject)?;
        let root = IdRange {
            inside: 0,
            outside: u64::from(owner),
            count: 1,
        };
        if ranges.first() != Some(&root) || id == 0 {
            return Err(reject());
        }
        let host = map_id(&ranges, id)
            .filter(|host| *host != owner)
            .ok_or_else(reject)?;
        let aliases = ranges.iter().skip(1).any(|range| {
            let owner = u64::from(owner);
            range.outside <= owner && owner < range.outside.saturating_add(range.count)
        });
        if aliases {
            return Err(reject());
        }
        *slot = host;
    }
    Ok((result[0], result[1]))
}

fn field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key).map(str::trim))
}

fn effective_id(status: &str, key: &str) -> Option<u32> {
    field(status, key)?.split_whitespace().nth(1)?.parse().ok()
}

fn effective_uid(status: &str) -> Option<u32> {
    effective_id(status, "Uid:")
}

/// The real, effective, saved and filesystem ids of a `Uid:`/`Gid:` status line.
fn all_ids(status: &str, key: &str) -> Option<[u32; 4]> {
    let mut parts = field(status, key)?.split_whitespace().map(str::parse::<u32>);
    let ids = [
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
    ];
    parts.next().is_none().then_some(ids)
}

fn zero_capabilities(status: &str) -> bool {
    ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
        .iter()
        .all(|key| field(status, key).and_then(|value| u64::from_str_radix(value, 16).ok()) == Some(0))
}

fn process_group(stat: &str) -> Option<u32> {
    stat.rsplit_once(") ")?.1.split_whitespace().nth(2)?.parse().ok()
}

fn firewall_snapshot(proxy: u16, cdp: u16) -> Value {
    let mut ports = [proxy, cdp];
    ports.sort_unstable();
    let mut objects = vec![json!({"table": {"family": "inet", "name": "crawlx"}})];
    for chain in ["input", "output", "forward"] {
        objects.push(
            json!({"chain": {"family": "inet", "table": "crawlx", "name": chain,
            "type": "filter", "hook": chain, "prio": 0, "policy": "drop"}}),
        );
    }
    for chain in ["input", "output"] {
        for direction in ["dport", "sport"] {
            let mut expr = vec![
                json!({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "127.0.0.1"}}),
                json!({"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": direction}}, "right": {"set": ports}}}),
            ];
            if direction == "sport" {
                expr.push(
                    json!({"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": "established"}}),
                );
            }
            expr.push(json!({"accept": null}));
            objects
                .push(json!({"rule": {"family": "inet", "table": "crawlx", "chain": chain, "expr": expr}}));
        }
    }
    Value::Array(objects)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const UID_MAP: &str = "         0       1000          1\n         1     524288      65535\n";

    fn evidence() -> Evidence {
        Evidence {
            version: 2,
            isolation: "privileged".into(),
            browser_pid: 42,
            namespace_inode: 20,
            user_namespace_inode: 5,
            proxy_port: 8080,
            cdp_port: 9222,
            host_cdp_port: 9223,
            uid: 1000,
            gid: 1000,
            host_uid: 1000,
            host_gid: 1000,
            interfaces: vec!["lo".into()],
            routes: vec![Route {
                family: 4,
                dst: "127.0.0.0/8".into(),
                kind: "local".into(),
                dev: "lo".into(),
            }],
            firewall: firewall_snapshot(8080, 9222),
        }
    }

    fn rootless_evidence() -> Evidence {
        Evidence {
            isolation: "rootless".into(),
            user_namespace_inode: 6,
            host_uid: 524_288 + 999,
            host_gid: 524_288 + 999,
            ..evidence()
        }
    }

    fn config() -> NamespaceConfig {
        NamespaceConfig::new("/opt/crawlx/helper".into(), 1000, 1000)
    }

    fn rootless_config() -> NamespaceConfig {
        NamespaceConfig::rootless("/opt/crawlx/helper".into(), 1000, 1000)
    }

    fn worker(net_inode: u64) -> WorkerView {
        WorkerView {
            net_inode,
            user_inode: 5,
            uid: 1000,
            gid: 1000,
        }
    }

    #[test]
    fn rejects_host_namespace_default_route_and_extra_firewall_rule() {
        assert!(evidence().validate(&config(), 8080, &worker(20)).is_err());
        let mut direct = evidence();
        direct.routes[0].dst = "default".into();
        assert!(direct.validate(&config(), 8080, &worker(10)).is_err());
        let mut permissive = evidence();
        permissive
            .firewall
            .as_array_mut()
            .unwrap()
            .push(json!({"accept": null}));
        assert!(permissive.validate(&config(), 8080, &worker(10)).is_err());
    }

    #[test]
    fn rejects_wrong_proxy_dns_root_and_extra_interface() {
        assert!(evidence().validate(&config(), 8081, &worker(10)).is_err());
        let mut dns = evidence();
        dns.cdp_port = 53;
        assert!(dns.validate(&config(), 8080, &worker(10)).is_err());
        let mut root = evidence();
        root.uid = 0;
        assert!(root.validate(&config(), 8080, &worker(10)).is_err());
        let mut uplink = evidence();
        uplink.interfaces.push("eth0".into());
        assert!(uplink.validate(&config(), 8080, &worker(10)).is_err());
    }

    #[test]
    fn accepts_exact_contract_and_rewrites_only_expected_cdp() {
        let launch = evidence().validate(&config(), 8080, &worker(10)).unwrap();
        assert_eq!(
            launch
                .relay_url("ws://127.0.0.1:9222/devtools/browser/id")
                .unwrap(),
            "ws://127.0.0.1:9223/devtools/browser/id"
        );
        for url in [
            "ws://127.0.0.1:9224/devtools/browser/id",
            "ws://192.0.2.1:9222/devtools/browser/id",
            "ws://127.0.0.1:9222/devtools/page/id",
        ] {
            assert!(launch.relay_url(url).is_err());
        }
    }

    #[test]
    fn mode_and_protocol_version_must_match_the_configuration() {
        assert!(rootless_evidence()
            .validate(&config(), 8080, &worker(10))
            .is_err());
        assert!(evidence()
            .validate(&rootless_config(), 8080, &worker(10))
            .is_err());
        let mut old = evidence();
        old.version = 1;
        assert!(old.validate(&config(), 8080, &worker(10)).is_err());
    }

    #[test]
    fn privileged_evidence_must_stay_in_the_workers_user_namespace_and_identity() {
        let mut nested = evidence();
        nested.user_namespace_inode = 99;
        assert!(nested.validate(&config(), 8080, &worker(10)).is_err());
        let mut shifted = evidence();
        shifted.host_uid = 1001;
        assert!(shifted.validate(&config(), 8080, &worker(10)).is_err());
    }

    #[test]
    fn rootless_evidence_requires_distinct_user_namespace_and_subordinate_identity() {
        let launch = rootless_evidence()
            .validate(&rootless_config(), 8080, &worker(10))
            .unwrap();
        assert_eq!(launch.mode, NamespaceMode::Rootless);
        assert_eq!((launch.host_uid, launch.host_gid), (525_287, 525_287));
        let mut same_userns = rootless_evidence();
        same_userns.user_namespace_inode = 5;
        assert!(same_userns
            .validate(&rootless_config(), 8080, &worker(10))
            .is_err());
        let mut aliased = rootless_evidence();
        aliased.host_uid = 1000;
        assert!(aliased.validate(&rootless_config(), 8080, &worker(10)).is_err());
        let mut group_alias = rootless_evidence();
        group_alias.host_gid = 1000;
        assert!(group_alias
            .validate(&rootless_config(), 8080, &worker(10))
            .is_err());
        let mut kernel_root = rootless_evidence();
        kernel_root.host_uid = 0;
        assert!(kernel_root
            .validate(&rootless_config(), 8080, &worker(10))
            .is_err());
        let mut firewall = rootless_evidence();
        firewall
            .firewall
            .as_array_mut()
            .unwrap()
            .push(json!({"accept": null}));
        assert!(firewall.validate(&rootless_config(), 8080, &worker(10)).is_err());
    }

    #[test]
    fn rootless_identity_maps_through_the_subordinate_range() {
        assert_eq!(
            rootless_identity(UID_MAP, UID_MAP, 1000, 1000, 1, 65_534).unwrap(),
            (524_288, 524_288 + 65_533)
        );
        assert_eq!(
            rootless_identity(UID_MAP, UID_MAP, 1000, 1000, 1000, 1000).unwrap(),
            (525_287, 525_287)
        );
    }

    #[test]
    fn rootless_identity_rejects_aliasing_unmapped_foreign_roots_and_malformed_maps() {
        let single = "0 1000 1\n";
        let alias = "0 1000 1\n1 1000 1\n";
        let covering = "0 1000 1\n1 900 200\n";
        let identity = "0 0 4294967295\n";
        for (uid_map, owner, uid) in [
            (UID_MAP, 1000, 0),
            (UID_MAP, 1000, 70_000),
            (UID_MAP, 1001, 1),
            (single, 1000, 1),
            (alias, 1000, 1),
            (covering, 1000, 1),
            (identity, 0, 1),
            ("", 1000, 1),
            ("0 1000\n", 1000, 1),
            ("0 1000 1 7\n", 1000, 1),
            ("zero 1000 1\n", 1000, 1),
        ] {
            assert!(
                rootless_identity(uid_map, UID_MAP, owner, 1000, uid, 1).is_err(),
                "{uid_map:?}"
            );
        }
        assert!(rootless_identity(UID_MAP, UID_MAP, 1000, 1001, 1, 1).is_err());
        assert!(rootless_identity(UID_MAP, UID_MAP, 1000, 1000, 1, 0).is_err());
    }

    #[test]
    fn id_map_parser_and_lookup_use_checked_arithmetic() {
        let ranges = parse_id_map(UID_MAP).unwrap();
        assert_eq!(map_id(&ranges, 65_535), Some(524_288 + 65_534));
        assert_eq!(map_id(&ranges, 65_536), None);
        let huge = parse_id_map("0 4294967295 4294967295\n").unwrap();
        assert_eq!(map_id(&huge, 1), None);
    }

    #[test]
    fn helper_trust_depends_on_mode() {
        assert!(trusted_owner(NamespaceMode::Privileged, Some(0), 0));
        assert!(!trusted_owner(NamespaceMode::Privileged, Some(0), 1000));
        assert!(!trusted_owner(NamespaceMode::Privileged, Some(1000), 1000));
        assert!(trusted_owner(NamespaceMode::Rootless, Some(1000), 1000));
        assert!(trusted_owner(NamespaceMode::Rootless, Some(1000), 0));
        assert!(!trusted_owner(NamespaceMode::Rootless, Some(1000), 1001));
        assert!(!trusted_owner(NamespaceMode::Rootless, None, 1000));
    }

    #[test]
    fn identity_range_depends_on_mode() {
        assert!(config().identity_in_range());
        assert!(NamespaceConfig::new("/h".into(), 70_000, 70_000).identity_in_range());
        assert!(!NamespaceConfig::new("/h".into(), 0, 1).identity_in_range());
        assert!(!NamespaceConfig::new("/h".into(), u32::MAX, 1).identity_in_range());
        assert!(rootless_config().identity_in_range());
        for (uid, gid) in [(0, 1), (1, 0), (65_535, 1), (1, 65_535)] {
            assert!(!NamespaceConfig::rootless("/h".into(), uid, gid).identity_in_range());
        }
    }

    #[tokio::test]
    async fn rootless_preflight_refuses_unusable_configuration_before_any_spawn() {
        let relative = NamespaceConfig::rootless("helper".into(), 1000, 1000);
        assert!(matches!(
            relative.preflight().await,
            Err(NamespaceError::Contract(_))
        ));
        let root = NamespaceConfig::rootless("/missing/helper".into(), 0, 1000);
        assert!(matches!(root.preflight().await, Err(NamespaceError::Contract(_))));
        let command =
            rootless_config().command(Path::new("/x/chrome"), &["--a".to_owned()], Path::new("/p"), 8080);
        let argv: Vec<_> = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(&argv[..4], ["launch", "--isolation", "rootless", "--uid"]);
        assert!(argv.windows(2).any(|pair| pair == ["--profile", "/p"]));
        assert_eq!(&argv[argv.len() - 3..], ["--", "/x/chrome", "--a"]);
    }

    #[test]
    fn reads_group_after_parenthesized_process_name() {
        assert_eq!(
            process_group("42 (name with ) parentheses) S 1 42 42 0"),
            Some(42)
        );
        assert_eq!(effective_uid("Uid:\t1000\t1000\t1000\t1000\n"), Some(1000));
        assert_eq!(all_ids("Uid:\t7\t7\t7\t7\n", "Uid:"), Some([7; 4]));
        assert_eq!(all_ids("Uid:\t7\t7\t0\t7\n", "Uid:"), Some([7, 7, 0, 7]));
        assert_eq!(all_ids("Uid:\t7\t7\t7\n", "Uid:"), None);
        assert_eq!(field("Groups:\t\n", "Groups:"), Some(""));
        assert!(!zero_capabilities("CapEff:\t0000000000000000\n"));
    }
}
