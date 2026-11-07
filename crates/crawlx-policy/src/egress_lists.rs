//! The two deployment-level egress lists:
//!
//! * the **deployment CIDR allowlist** (`egress.deployment_allowlist`): the only private,
//!   loopback or unique-local networks any run of the deployment may reach. A record's
//!   `authorizedNetworks` must lie inside it (admission) and the egress policy re-applies it
//!   to every address (runtime). Unset means the deployment sets no bound; set but empty
//!   means no private network is reachable at all.
//! * the **operator host blocklist** (`egress.operator_blocklist`): hosts (with their
//!   subdomains), IP addresses and CIDRs no run may reach, whatever its record says. It is the
//!   runtime mechanism of a takedown request.
//!
//! [`EgressLists`] is an immutable snapshot with the matching logic; [`SharedEgressLists`] is
//! the live handle every [`crate::EgressPolicy`] holds, so a reload (SIGHUP or the 60 s poll
//! of `crawlx-fetch`) reaches runs that are already in flight on their next connection.

use ipnet::IpNet;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use url::Host;

/// A list entry or file that cannot be parsed. Reloads keep the previous snapshot on error.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ListError {
    /// An allowlist line is not a CIDR or an IP address.
    #[error("allowlist line {line}: {entry:?} is not an IP address or CIDR")]
    Network {
        /// 1-based line number (`0` for an entry that did not come from a file).
        line: usize,
        /// The offending entry.
        entry: String,
    },
    /// A blocklist line is not a host name, an IP address or a CIDR.
    #[error("blocklist line {line}: {entry:?} is not a host name, IP address or CIDR")]
    Host {
        /// 1-based line number (`0` for an entry that did not come from a file).
        line: usize,
        /// The offending entry.
        entry: String,
    },
}

/// Lines of a list file: comments (`#`) and blank lines dropped, `(line number, entry)` kept.
fn entries(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().enumerate().filter_map(|(i, raw)| {
        let entry = raw.split('#').next().unwrap_or("").trim();
        (!entry.is_empty()).then_some((i + 1, entry))
    })
}

fn parse_network(line: usize, entry: &str) -> Result<IpNet, ListError> {
    entry
        .parse::<IpNet>()
        .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| ListError::Network {
            line,
            entry: entry.to_owned(),
        })
}

/// A normalized blocklist host: lowercase ASCII (IDNA), no `*.` prefix, no trailing dot.
fn normalize_host(entry: &str) -> Option<String> {
    let h = entry.trim().trim_start_matches("*.").trim_end_matches('.');
    match Host::parse(h) {
        Ok(Host::Domain(d)) if !d.is_empty() => Some(d.to_ascii_lowercase()),
        _ => None,
    }
}

/// An immutable snapshot of both lists.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct EgressLists {
    allowlist: Option<Vec<IpNet>>,
    blocked_hosts: Vec<String>,
    blocked_nets: Vec<IpNet>,
}

impl EgressLists {
    /// Lists from parsed parts: `allowlist` (`None` = the deployment sets no bound) and
    /// blocklist `entries` (host, `*.host`, IP address or CIDR each).
    ///
    /// # Errors
    /// [`ListError::Host`] for an entry that is none of those.
    pub fn new<I, S>(allowlist: Option<Vec<IpNet>>, blocklist: I) -> Result<Self, ListError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut lists = Self {
            allowlist,
            ..Self::default()
        };
        for entry in blocklist {
            lists.add_blocked(0, entry.as_ref().trim())?;
        }
        Ok(lists)
    }

    fn add_blocked(&mut self, line: usize, entry: &str) -> Result<(), ListError> {
        if let Ok(net) = entry
            .parse::<IpNet>()
            .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
        {
            self.blocked_nets.push(net);
            return Ok(());
        }
        let host = normalize_host(entry).ok_or_else(|| ListError::Host {
            line,
            entry: entry.to_owned(),
        })?;
        if !self.blocked_hosts.contains(&host) {
            self.blocked_hosts.push(host);
        }
        Ok(())
    }

    /// Parse an allowlist file: one CIDR or IP address per line, `#` comments.
    ///
    /// # Errors
    /// [`ListError::Network`] naming the first bad line.
    pub fn parse_allowlist(text: &str) -> Result<Vec<IpNet>, ListError> {
        entries(text).map(|(line, e)| parse_network(line, e)).collect()
    }

    /// Parse a blocklist file: one host, `*.host`, IP address or CIDR per line, `#` comments.
    ///
    /// # Errors
    /// [`ListError::Host`] naming the first bad line.
    pub fn parse_blocklist(text: &str) -> Result<Vec<String>, ListError> {
        let mut lists = Self::default();
        for (line, entry) in entries(text) {
            lists.add_blocked(line, entry)?;
        }
        Ok(lists.blocklist_entries())
    }

    /// The blocklist as entries [`Self::new`] accepts: hosts first, then networks.
    #[must_use]
    pub fn blocklist_entries(&self) -> Vec<String> {
        self.blocked_hosts
            .iter()
            .cloned()
            .chain(self.blocked_nets.iter().map(ToString::to_string))
            .collect()
    }

    /// The deployment allowlist, when the deployment sets one.
    #[must_use]
    pub fn allowlist(&self) -> Option<&[IpNet]> {
        self.allowlist.as_deref()
    }

    /// Is `ip` inside the deployment allowlist? `true` when the deployment sets none.
    #[must_use]
    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        self.allowlist
            .as_ref()
            .is_none_or(|nets| nets.iter().any(|n| n.contains(&ip)))
    }

    /// Does the allowlist contain the whole network `net`? `true` when the deployment sets none.
    #[must_use]
    pub fn allows_network(&self, net: &IpNet) -> bool {
        self.allowlist
            .as_ref()
            .is_none_or(|nets| nets.iter().any(|a| a.contains(net)))
    }

    /// The blocklist entry that matches `host` (the host itself or a subdomain of it).
    #[must_use]
    pub fn blocked_host(&self, host: &str) -> Option<&str> {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        self.blocked_hosts
            .iter()
            .find(|b| h == **b || h.strip_suffix(b.as_str()).is_some_and(|rest| rest.ends_with('.')))
            .map(String::as_str)
    }

    /// Is `ip` inside a blocklisted address or network?
    #[must_use]
    pub fn blocked_ip(&self, ip: IpAddr) -> bool {
        self.blocked_nets.iter().any(|n| n.contains(&ip))
    }

    /// Are both lists empty and unset?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allowlist.is_none() && self.blocked_hosts.is_empty() && self.blocked_nets.is_empty()
    }
}

/// The live lists: cheap to clone, every clone sees [`Self::replace`]. Equality is identity.
#[derive(Clone, Default, Debug)]
pub struct SharedEgressLists {
    inner: Arc<RwLock<Arc<EgressLists>>>,
}

impl SharedEgressLists {
    /// A handle holding `lists`.
    #[must_use]
    pub fn new(lists: EgressLists) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(lists))),
        }
    }

    /// The current snapshot. Hold it for one decision, not across awaits of a long operation.
    #[must_use]
    pub fn snapshot(&self) -> Arc<EgressLists> {
        Arc::clone(&self.inner.read())
    }

    /// Publish `lists` to every holder of this handle.
    pub fn replace(&self, lists: EgressLists) {
        *self.inner.write() = Arc::new(lists);
    }
}

impl PartialEq for SharedEgressLists {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for SharedEgressLists {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allowlist_files_parse_with_comments_and_bare_addresses() {
        let nets =
            EgressLists::parse_allowlist("# staging\n10.20.0.0/16  # lab\n\n127.0.0.1\nfd12::/32\n").unwrap();
        assert_eq!(nets.len(), 3);
        assert_eq!(nets[1].to_string(), "127.0.0.1/32");
        let e = EgressLists::parse_allowlist("10.0.0.0/8\nnot-a-net\n").unwrap_err();
        assert_eq!(
            e,
            ListError::Network {
                line: 2,
                entry: "not-a-net".to_owned()
            }
        );
    }

    #[test]
    fn allowlist_unset_is_unbounded_and_set_is_a_bound() {
        let unset = EgressLists::default();
        assert!(unset.allows_ip(ip("10.1.2.3")));
        assert!(unset.allows_network(&"10.0.0.0/8".parse().unwrap()));
        let set =
            EgressLists::new(Some(vec!["10.20.0.0/16".parse().unwrap()]), Vec::<String>::new()).unwrap();
        assert!(set.allows_ip(ip("10.20.9.9")));
        assert!(!set.allows_ip(ip("10.21.0.1")));
        assert!(set.allows_network(&"10.20.1.0/24".parse().unwrap()));
        assert!(!set.allows_network(&"10.0.0.0/8".parse().unwrap()));
        let empty = EgressLists::new(Some(Vec::new()), Vec::<String>::new()).unwrap();
        assert!(!empty.allows_ip(ip("10.20.9.9")), "set but empty allows nothing");
    }

    #[test]
    fn blocklist_matches_host_and_subdomains_not_suffix_lookalikes() {
        let l = EgressLists::new(
            None,
            ["Blocked.Test", "*.wild.test", "takedown.example.", "bad-ip.test"],
        )
        .unwrap();
        assert_eq!(l.blocked_host("blocked.test"), Some("blocked.test"));
        assert_eq!(l.blocked_host("a.b.blocked.test"), Some("blocked.test"));
        assert_eq!(l.blocked_host("WILD.test."), Some("wild.test"));
        assert_eq!(l.blocked_host("takedown.example"), Some("takedown.example"));
        assert_eq!(l.blocked_host("notblocked.test"), None);
        assert_eq!(l.blocked_host("blocked.test.evil"), None);
    }

    #[test]
    fn blocklist_takes_addresses_and_networks_too() {
        let l = EgressLists::new(None, ["203.0.113.7", "198.51.100.0/24"]).unwrap();
        assert!(l.blocked_ip(ip("203.0.113.7")));
        assert!(l.blocked_ip(ip("198.51.100.200")));
        assert!(!l.blocked_ip(ip("203.0.113.8")));
        assert_eq!(
            l.blocked_host("203.0.113.7"),
            None,
            "addresses are not host names"
        );
    }

    #[test]
    fn blocklist_files_report_the_bad_line_and_round_trip() {
        let entries = EgressLists::parse_blocklist("# takedowns\nbad.test\n10.9.0.0/16 # net\n").unwrap();
        assert_eq!(entries, vec!["bad.test".to_owned(), "10.9.0.0/16".to_owned()]);
        let e = EgressLists::parse_blocklist("ok.test\nbad host\n").unwrap_err();
        assert_eq!(
            e,
            ListError::Host {
                line: 2,
                entry: "bad host".to_owned()
            }
        );
    }

    #[test]
    fn replace_reaches_every_clone_and_equality_is_identity() {
        let a = SharedEgressLists::new(EgressLists::default());
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, SharedEgressLists::new(EgressLists::default()));
        assert!(b.snapshot().blocked_host("x.test").is_none());
        a.replace(EgressLists::new(None, ["x.test"]).unwrap());
        assert!(b.snapshot().blocked_host("x.test").is_some());
        assert!(a.snapshot().blocked_host("sub.x.test").is_some());
    }
}
