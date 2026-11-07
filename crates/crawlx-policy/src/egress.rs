//! SSRF and egress decisions (controls E1, E2, E5, E11).
//!
//! Pure logic: this module classifies IP addresses, hostnames, schemes and
//! ports. It performs no DNS resolution and opens no sockets; the fetch plane
//! resolves, calls [`EgressPolicy::check_all`], then pins the checked
//! addresses (E2/E3). IANA special-purpose ranges live in the const tables
//! [`DENIED_V4`] and [`DENIED_V6`]. Embedded IPv4 forms (IPv4-mapped,
//! NAT64, 6to4, Teredo, deprecated IPv4-compatible) are extracted and
//! classified as the IPv4 address; an embedded address that is itself public
//! stays denied under [`DenyRule::Transition`] because the denied-range
//! table lists those prefixes.

use crate::authorization::{AuthzFailure, RecordScope};
use crate::egress_lists::{EgressLists, SharedEgressLists};
use ipnet::IpNet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use url::{Host, Url};

/// Why an address, host, scheme or port was refused. `as_str` is the
/// `crawlx_egress_denied_total{rule}` label.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DenyRule {
    /// The unspecified address (`0.0.0.0`, `::`).
    Unspecified,
    /// Loopback range (`127.0.0.0/8`, `::1`).
    Loopback,
    /// Private-use ranges (RFC 1918, ...).
    Private,
    /// Link-local ranges (`169.254.0.0/16`, `fe80::/10`).
    LinkLocal,
    /// Carrier-grade NAT shared space (`100.64.0.0/10`).
    CgNat,
    /// IPv6 unique local addresses (`fc00::/7`).
    UniqueLocal,
    /// Multicast ranges.
    Multicast,
    /// Reserved or otherwise non-routable ranges.
    Reserved,
    /// The IPv4 limited broadcast address.
    Broadcast,
    /// Documentation ranges (TEST-NET, `2001:db8::/32`).
    Documentation,
    /// Cloud metadata endpoints: never exemptable.
    Metadata,
    /// Transition mechanisms (mapped, NAT64, 6to4, Teredo, IPv4-compatible).
    Transition,
    /// Pre-resolution hostname deny list (`localhost`, `*.internal`, ...).
    Hostname,
    /// URL scheme is not `http` or `https`.
    Scheme,
    /// Destination port is not allowed.
    Port,
    /// URL carries `user:pass@` credentials.
    Userinfo,
    /// Operator `extra_deny` CIDR.
    Configured,
    /// The destination is outside the target of the run's authorization record:
    /// a redirect, discovered URL or browser request beyond the authorized
    /// origins, URL prefixes or past an excluded path.
    AuthorizationScope,
    /// The destination is on the operator blocklist (`egress.operator_blocklist`, RB-10 step 5).
    Blocklist,
}

impl DenyRule {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link_local",
            Self::CgNat => "cgnat",
            Self::UniqueLocal => "unique_local",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved",
            Self::Broadcast => "broadcast",
            Self::Documentation => "documentation",
            Self::Metadata => "metadata",
            Self::Transition => "transition",
            Self::Hostname => "hostname",
            Self::Scheme => "scheme",
            Self::Port => "port",
            Self::Userinfo => "userinfo",
            Self::Configured => "configured",
            Self::AuthorizationScope => "authorization_scope",
            Self::Blocklist => "operator_blocklist",
        }
    }

    /// Rules an authorization record may exempt (E11). Metadata, link-local,
    /// multicast, reserved and transition ranges can never be exempted.
    const fn exemptable(self) -> bool {
        matches!(
            self,
            Self::Private | Self::CgNat | Self::UniqueLocal | Self::Loopback
        )
    }
}

impl fmt::Display for DenyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An egress refusal.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[error("egress denied ({rule}): {subject} [{range}]")]
pub struct EgressDenied {
    /// Category of the refusal.
    pub rule: DenyRule,
    /// The refused address, host, scheme or port, as text.
    pub subject: String,
    /// Name of the matched range or check (for logs).
    pub range: &'static str,
}

impl EgressDenied {
    fn new(rule: DenyRule, subject: impl Into<String>, range: &'static str) -> Self {
        Self {
            rule,
            subject: subject.into(),
            range,
        }
    }
}

/// One IPv4 special-purpose range.
#[derive(Clone, Copy, Debug)]
pub struct V4Range {
    /// Network address of the range, as four octets.
    pub base: [u8; 4],
    /// Prefix length in bits (`0..=32`).
    pub prefix: u8,
    /// Deny rule reported when an address falls in the range.
    pub rule: DenyRule,
    /// Human-readable range name (for logs and the `range` of [`EgressDenied`]).
    pub name: &'static str,
}

impl V4Range {
    const fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix as u32)
        };
        (u32::from_be_bytes(ip.octets()) & mask) == (u32::from_be_bytes(self.base) & mask)
    }
}

/// One IPv6 special-purpose range.
#[derive(Clone, Copy, Debug)]
pub struct V6Range {
    /// Network address of the range, as eight 16-bit groups.
    pub base: [u16; 8],
    /// Prefix length in bits (`0..=128`).
    pub prefix: u8,
    /// Deny rule reported when an address falls in the range.
    pub rule: DenyRule,
    /// Human-readable range name (for logs and the `range` of [`EgressDenied`]).
    pub name: &'static str,
}

impl V6Range {
    const fn contains(&self, ip: Ipv6Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u128::MAX << (128 - self.prefix as u32)
        };
        (u128::from_be_bytes(ip.octets()) & mask)
            == (u128::from_be_bytes(
                Ipv6Addr::new(
                    self.base[0],
                    self.base[1],
                    self.base[2],
                    self.base[3],
                    self.base[4],
                    self.base[5],
                    self.base[6],
                    self.base[7],
                )
                .octets(),
            ) & mask)
    }
}

/// IPv4 deny table (IANA IPv4 Special-Purpose Address Registry plus cloud
/// metadata hosts). First match wins, so specific entries precede broad ones.
pub const DENIED_V4: &[V4Range] = &[
    V4Range {
        base: [169, 254, 169, 254],
        prefix: 32,
        rule: DenyRule::Metadata,
        name: "metadata 169.254.169.254",
    },
    V4Range {
        base: [100, 100, 100, 200],
        prefix: 32,
        rule: DenyRule::Metadata,
        name: "metadata 100.100.100.200 (Alibaba)",
    },
    V4Range {
        base: [192, 0, 0, 192],
        prefix: 32,
        rule: DenyRule::Metadata,
        name: "metadata 192.0.0.192 (Oracle)",
    },
    V4Range {
        base: [255, 255, 255, 255],
        prefix: 32,
        rule: DenyRule::Broadcast,
        name: "limited broadcast 255.255.255.255/32",
    },
    V4Range {
        base: [0, 0, 0, 0],
        prefix: 8,
        rule: DenyRule::Unspecified,
        name: "this network 0.0.0.0/8",
    },
    V4Range {
        base: [10, 0, 0, 0],
        prefix: 8,
        rule: DenyRule::Private,
        name: "private 10.0.0.0/8",
    },
    V4Range {
        base: [100, 64, 0, 0],
        prefix: 10,
        rule: DenyRule::CgNat,
        name: "shared address space 100.64.0.0/10",
    },
    V4Range {
        base: [127, 0, 0, 0],
        prefix: 8,
        rule: DenyRule::Loopback,
        name: "loopback 127.0.0.0/8",
    },
    V4Range {
        base: [169, 254, 0, 0],
        prefix: 16,
        rule: DenyRule::LinkLocal,
        name: "link-local 169.254.0.0/16",
    },
    V4Range {
        base: [172, 16, 0, 0],
        prefix: 12,
        rule: DenyRule::Private,
        name: "private 172.16.0.0/12",
    },
    V4Range {
        base: [192, 0, 0, 0],
        prefix: 24,
        rule: DenyRule::Reserved,
        name: "IETF protocol assignments 192.0.0.0/24",
    },
    V4Range {
        base: [192, 0, 2, 0],
        prefix: 24,
        rule: DenyRule::Documentation,
        name: "TEST-NET-1 192.0.2.0/24",
    },
    V4Range {
        base: [192, 88, 99, 0],
        prefix: 24,
        rule: DenyRule::Transition,
        name: "6to4 relay anycast 192.88.99.0/24",
    },
    V4Range {
        base: [192, 168, 0, 0],
        prefix: 16,
        rule: DenyRule::Private,
        name: "private 192.168.0.0/16",
    },
    V4Range {
        base: [198, 18, 0, 0],
        prefix: 15,
        rule: DenyRule::Reserved,
        name: "benchmarking 198.18.0.0/15",
    },
    V4Range {
        base: [198, 51, 100, 0],
        prefix: 24,
        rule: DenyRule::Documentation,
        name: "TEST-NET-2 198.51.100.0/24",
    },
    V4Range {
        base: [203, 0, 113, 0],
        prefix: 24,
        rule: DenyRule::Documentation,
        name: "TEST-NET-3 203.0.113.0/24",
    },
    V4Range {
        base: [224, 0, 0, 0],
        prefix: 4,
        rule: DenyRule::Multicast,
        name: "multicast 224.0.0.0/4",
    },
    V4Range {
        base: [240, 0, 0, 0],
        prefix: 4,
        rule: DenyRule::Reserved,
        name: "reserved 240.0.0.0/4",
    },
];

/// IPv6 deny table (IANA IPv6 Special-Purpose Address Registry plus cloud
/// metadata). First match wins.
pub const DENIED_V6: &[V6Range] = &[
    V6Range {
        base: [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254],
        prefix: 128,
        rule: DenyRule::Metadata,
        name: "metadata fd00:ec2::254 (AWS)",
    },
    V6Range {
        base: [0, 0, 0, 0, 0, 0, 0, 0],
        prefix: 128,
        rule: DenyRule::Unspecified,
        name: "unspecified ::/128",
    },
    V6Range {
        base: [0, 0, 0, 0, 0, 0, 0, 1],
        prefix: 128,
        rule: DenyRule::Loopback,
        name: "loopback ::1/128",
    },
    V6Range {
        base: [0, 0, 0, 0, 0, 0xffff, 0, 0],
        prefix: 96,
        rule: DenyRule::Transition,
        name: "IPv4-mapped ::ffff:0:0/96",
    },
    V6Range {
        base: [0, 0, 0, 0, 0, 0, 0, 0],
        prefix: 96,
        rule: DenyRule::Transition,
        name: "IPv4-compatible ::/96",
    },
    V6Range {
        base: [0x64, 0xff9b, 0, 0, 0, 0, 0, 0],
        prefix: 96,
        rule: DenyRule::Transition,
        name: "NAT64 64:ff9b::/96",
    },
    V6Range {
        base: [0x64, 0xff9b, 1, 0, 0, 0, 0, 0],
        prefix: 48,
        rule: DenyRule::Transition,
        name: "local-use NAT64 64:ff9b:1::/48",
    },
    V6Range {
        base: [0x100, 0, 0, 0, 0, 0, 0, 0],
        prefix: 64,
        rule: DenyRule::Reserved,
        name: "discard-only 100::/64",
    },
    V6Range {
        base: [0x2001, 0, 0, 0, 0, 0, 0, 0],
        prefix: 32,
        rule: DenyRule::Transition,
        name: "Teredo 2001::/32",
    },
    V6Range {
        base: [0x2001, 0x2, 0, 0, 0, 0, 0, 0],
        prefix: 48,
        rule: DenyRule::Reserved,
        name: "benchmarking 2001:2::/48",
    },
    V6Range {
        base: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 0],
        prefix: 32,
        rule: DenyRule::Documentation,
        name: "documentation 2001:db8::/32",
    },
    V6Range {
        base: [0x2001, 0, 0, 0, 0, 0, 0, 0],
        prefix: 23,
        rule: DenyRule::Reserved,
        name: "IETF protocol assignments 2001::/23",
    },
    V6Range {
        base: [0x2002, 0, 0, 0, 0, 0, 0, 0],
        prefix: 16,
        rule: DenyRule::Transition,
        name: "6to4 2002::/16",
    },
    V6Range {
        base: [0x3fff, 0, 0, 0, 0, 0, 0, 0],
        prefix: 20,
        rule: DenyRule::Documentation,
        name: "documentation 3fff::/20",
    },
    V6Range {
        base: [0x5f00, 0, 0, 0, 0, 0, 0, 0],
        prefix: 16,
        rule: DenyRule::Reserved,
        name: "SRv6 SIDs 5f00::/16",
    },
    V6Range {
        base: [0xfc00, 0, 0, 0, 0, 0, 0, 0],
        prefix: 7,
        rule: DenyRule::UniqueLocal,
        name: "unique-local fc00::/7",
    },
    V6Range {
        base: [0xfe80, 0, 0, 0, 0, 0, 0, 0],
        prefix: 10,
        rule: DenyRule::LinkLocal,
        name: "link-local fe80::/10",
    },
    V6Range {
        base: [0xfec0, 0, 0, 0, 0, 0, 0, 0],
        prefix: 10,
        rule: DenyRule::Reserved,
        name: "site-local fec0::/10 (deprecated)",
    },
    V6Range {
        base: [0xff00, 0, 0, 0, 0, 0, 0, 0],
        prefix: 8,
        rule: DenyRule::Multicast,
        name: "multicast ff00::/8",
    },
];

/// Cloud metadata hostnames (denied before resolution, never exemptable).
const METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.goog", "instance-data"];

/// Host suffixes denied before resolution unless private networks are
/// authorized (resolved addresses are still range-checked).
const INTERNAL_SUFFIXES: &[&str] = &[".localhost", ".internal", ".local"];

/// Ports always allowed (E1).
pub const DEFAULT_PORTS: &[u16] = &[80, 443];

#[derive(Clone, Copy)]
struct Classified {
    rule: DenyRule,
    name: &'static str,
    /// Address the rule was derived from (the embedded IPv4 when one was extracted).
    basis: IpAddr,
}

fn classify_v4(ip: Ipv4Addr) -> Option<(DenyRule, &'static str)> {
    DENIED_V4
        .iter()
        .find(|r| r.contains(ip))
        .map(|r| (r.rule, r.name))
}

/// IPv4 addresses embedded in a transition-mechanism IPv6 address.
fn embedded_v4(ip: Ipv6Addr) -> Vec<Ipv4Addr> {
    let s = ip.segments();
    let o = ip.octets();
    let tail = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    let mut out = Vec::new();
    // ::ffff:a.b.c.d, ::a.b.c.d, 64:ff9b::a.b.c.d
    let mapped_or_compat = s[..5] == [0, 0, 0, 0, 0] && (s[5] == 0xffff || s[5] == 0);
    let nat64 = s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0];
    if mapped_or_compat || nat64 {
        out.push(tail);
    } else if s[0] == 0x2002 {
        // 6to4: 2002:AABB:CCDD::/48 embeds a.b.c.d
        out.push(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    } else if s[0] == 0x2001 && s[1] == 0 {
        // Teredo: server in bits 32..64, client obfuscated (bitwise NOT) in the last 32.
        out.push(Ipv4Addr::new(o[4], o[5], o[6], o[7]));
        out.push(Ipv4Addr::new(!o[12], !o[13], !o[14], !o[15]));
    }
    out
}

fn classify(ip: IpAddr) -> Option<Classified> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4).map(|(rule, name)| Classified {
            rule,
            name,
            basis: ip,
        }),
        IpAddr::V6(v6) => {
            let (table_rule, table_name) = DENIED_V6
                .iter()
                .find(|r| r.contains(v6))
                .map(|r| (r.rule, r.name))?;
            // A more specific verdict from an embedded IPv4 wins (mapped 127.0.0.1 is Loopback).
            if table_rule == DenyRule::Transition {
                for v4 in embedded_v4(v6) {
                    if let Some((rule, name)) = classify_v4(v4) {
                        return Some(Classified {
                            rule,
                            name,
                            basis: IpAddr::V4(v4),
                        });
                    }
                }
            }
            Some(Classified {
                rule: table_rule,
                name: table_name,
                basis: ip,
            })
        }
    }
}

/// Classify an address against the built-in deny table (no policy options).
#[must_use]
pub fn classify_ip(ip: IpAddr) -> Option<DenyRule> {
    classify(ip).map(|c| c.rule)
}

/// Egress policy for one run (or deployment). Cheap to clone; `Send + Sync`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EgressPolicy {
    /// Honor private-range exemptions (only meaningful with an authorization
    /// record, which admission enforces). When `extra_allow` is empty every
    /// exemptable private range is allowed; otherwise only `extra_allow`.
    pub allow_private: bool,
    /// Authorized networks (`authorizedNetworks`, E11). Exempts only private,
    /// CGNAT, unique-local and loopback ranges; never metadata or link-local.
    pub extra_allow: Vec<IpNet>,
    /// Always denied (`Configured`), checked before any allowance.
    pub extra_deny: Vec<IpNet>,
    /// Ports allowed in addition to 80 and 443 (E1: ports present in the seed URL).
    pub extra_ports: Vec<u16>,
    /// The target of the run's authorization record: every host and URL the run touches must
    /// lie inside it ([`DenyRule::AuthorizationScope`]). `None` for runs without a record.
    pub record_scope: Option<Arc<RecordScope>>,
    /// Additional live exact-listener restriction for isolated fixture experiments.
    /// This only narrows egress and does not grant model authority.
    pub fixture_scope: Option<crate::fixture_evaluation::FixtureEvaluationScope>,
    /// The live deployment lists: the CIDR allowlist that bounds every private-range
    /// exemption and the operator blocklist. `None` applies neither.
    pub lists: Option<SharedEgressLists>,
    /// Private, loopback and unique-local destinations inside the deployment allowlist are
    /// exempt without a record (`test_environment` runs: the deployment named those networks
    /// explicitly). Meaningless without [`Self::lists`] holding an allowlist.
    pub deployment_exempt: bool,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self::new(false)
    }
}

impl EgressPolicy {
    /// Strict policy; `allow_private` toggles private-range exemption.
    #[must_use]
    pub const fn new(allow_private: bool) -> Self {
        Self {
            allow_private,
            extra_allow: Vec::new(),
            extra_deny: Vec::new(),
            extra_ports: Vec::new(),
            record_scope: None,
            fixture_scope: None,
            lists: None,
            deployment_exempt: false,
        }
    }

    /// Allow the seed URL's explicit port (E1).
    #[must_use]
    pub fn with_seed_port(mut self, seed: &Url) -> Self {
        if let Some(p) = seed.port() {
            if !self.extra_ports.contains(&p) {
                self.extra_ports.push(p);
            }
        }
        self
    }

    /// Bound the policy to the target of an authorization record.
    #[must_use]
    pub fn with_record_scope(mut self, scope: RecordScope) -> Self {
        self.record_scope = Some(Arc::new(scope));
        self
    }

    /// Attach the live deployment lists.
    #[must_use]
    pub fn with_lists(mut self, lists: SharedEgressLists) -> Self {
        self.lists = Some(lists);
        self
    }

    fn snapshot(&self) -> Option<Arc<EgressLists>> {
        self.lists.as_ref().map(SharedEgressLists::snapshot)
    }

    fn deployment_allows_exemption(&self, lists: Option<&EgressLists>) -> bool {
        self.deployment_exempt
            && lists
                .and_then(EgressLists::allowlist)
                .is_some_and(|a| !a.is_empty())
    }

    fn private_exempt(&self, lists: Option<&EgressLists>) -> bool {
        self.allow_private || !self.extra_allow.is_empty() || self.deployment_allows_exemption(lists)
    }

    /// Is `ip` (an exemptable private address) exempt? Record networks and `allow_private`
    /// are bounded by the deployment allowlist; a `test_environment` run needs no record for
    /// an address the allowlist names.
    fn exempt_ip(&self, ip: IpAddr, lists: Option<&EgressLists>) -> bool {
        let in_allowlist = lists
            .and_then(EgressLists::allowlist)
            .is_some_and(|nets| nets.iter().any(|n| n.contains(&ip)));
        if self.deployment_exempt && in_allowlist {
            return true;
        }
        let by_record = if self.extra_allow.is_empty() {
            self.allow_private
        } else {
            self.extra_allow.iter().any(|n| n.contains(&ip))
        };
        by_record && lists.is_none_or(|l| l.allows_ip(ip))
    }

    /// Check one resolved or literal address (E5, E11).
    ///
    /// # Errors
    /// [`EgressDenied`] naming the matched rule.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), EgressDenied> {
        if self
            .fixture_scope
            .as_ref()
            .is_some_and(|scope| !scope.permits_ip(ip))
        {
            return Err(EgressDenied::new(
                DenyRule::AuthorizationScope,
                ip.to_string(),
                "fixture listener scope inactive or address mismatch",
            ));
        }
        let cls = classify(ip);
        let basis = cls.map_or(ip, |c| c.basis);
        if self
            .extra_deny
            .iter()
            .any(|n| n.contains(&ip) || n.contains(&basis))
        {
            return Err(EgressDenied::new(
                DenyRule::Configured,
                ip.to_string(),
                "extra_deny",
            ));
        }
        let lists = self.snapshot();
        if lists
            .as_deref()
            .is_some_and(|l| l.blocked_ip(ip) || l.blocked_ip(basis))
        {
            return Err(EgressDenied::new(
                DenyRule::Blocklist,
                ip.to_string(),
                "operator blocklist",
            ));
        }
        match cls {
            None => Ok(()),
            Some(c) if c.rule.exemptable() && self.exempt_ip(c.basis, lists.as_deref()) => Ok(()),
            Some(c) => Err(EgressDenied::new(c.rule, ip.to_string(), c.name)),
        }
    }

    /// Pre-resolution hostname check (E1). IP literals (including WHATWG
    /// legacy decimal/octal/hex IPv4 forms) are routed through [`Self::check_ip`].
    ///
    /// # Errors
    /// [`EgressDenied`] for a denied name, literal or unparsable host.
    pub fn check_host(&self, host: &str) -> Result<(), EgressDenied> {
        let trimmed = host.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return Err(EgressDenied::new(DenyRule::Hostname, host, "empty host"));
        }
        if let Ok(addr) = trimmed.parse::<IpAddr>() {
            return match addr {
                IpAddr::V4(v4) => self.check_host_value(&Host::<&str>::Ipv4(v4)),
                IpAddr::V6(v6) => self.check_host_value(&Host::<&str>::Ipv6(v6)),
            };
        }
        match Host::parse(trimmed) {
            Ok(h) => self.check_host_value(&h),
            Err(_) => Err(EgressDenied::new(DenyRule::Hostname, host, "unparsable host")),
        }
    }

    /// The egress rules for one host, then the record bound: a metadata address stays a
    /// `metadata` denial, never an `authorization_scope` one.
    fn check_host_value<S: AsRef<str>>(&self, host: &Host<S>) -> Result<(), EgressDenied> {
        match host {
            Host::Ipv4(v4) => self.check_ip(IpAddr::V4(*v4))?,
            Host::Ipv6(v6) => self.check_ip(IpAddr::V6(*v6))?,
            Host::Domain(d) => self.check_domain(d.as_ref())?,
        }
        if let Some(scope) = &self.record_scope {
            if !scope.contains_host(host) {
                return Err(EgressDenied::new(
                    DenyRule::AuthorizationScope,
                    host.to_string(),
                    "authorization record scope",
                ));
            }
        }
        Ok(())
    }

    fn check_domain(&self, domain: &str) -> Result<(), EgressDenied> {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        if METADATA_HOSTS.contains(&d.as_str()) {
            return Err(EgressDenied::new(DenyRule::Metadata, d, "metadata hostname"));
        }
        let lists = self.snapshot();
        if lists.as_deref().is_some_and(|l| l.blocked_host(&d).is_some()) {
            return Err(EgressDenied::new(DenyRule::Blocklist, d, "operator blocklist"));
        }
        let internal = d == "localhost" || INTERNAL_SUFFIXES.iter().any(|s| d.ends_with(s));
        if internal && !self.private_exempt(lists.as_deref()) {
            return Err(EgressDenied::new(DenyRule::Hostname, d, "internal hostname"));
        }
        Ok(())
    }

    /// Check a name together with every address it resolved to: any denied
    /// address denies the name (E2).
    ///
    /// # Errors
    /// [`EgressDenied`] for the name or the first denied address.
    pub fn check_all(&self, host: &str, addrs: &[IpAddr]) -> Result<(), EgressDenied> {
        self.check_host(host)?;
        addrs.iter().try_for_each(|a| self.check_ip(*a))
    }

    /// Only `http` and `https` (E1).
    ///
    /// # Errors
    /// [`EgressDenied`] with [`DenyRule::Scheme`].
    pub fn check_scheme(&self, scheme: &str) -> Result<(), EgressDenied> {
        if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
            Ok(())
        } else {
            Err(EgressDenied::new(
                DenyRule::Scheme,
                scheme,
                "scheme not http/https",
            ))
        }
    }

    /// Ports 80 and 443 plus `extra_ports` (E1).
    ///
    /// # Errors
    /// [`EgressDenied`] with [`DenyRule::Port`].
    pub fn check_port(&self, port: u16) -> Result<(), EgressDenied> {
        if self
            .fixture_scope
            .as_ref()
            .is_some_and(|scope| !scope.permits_port(port))
        {
            return Err(EgressDenied::new(
                DenyRule::AuthorizationScope,
                port.to_string(),
                "fixture listener scope inactive or port mismatch",
            ));
        }
        if DEFAULT_PORTS.contains(&port) || self.extra_ports.contains(&port) {
            Ok(())
        } else {
            Err(EgressDenied::new(
                DenyRule::Port,
                port.to_string(),
                "port not allowed",
            ))
        }
    }

    /// All pre-resolution checks for a URL: scheme, userinfo, port, host (E1).
    ///
    /// # Errors
    /// [`EgressDenied`] naming the first failed check.
    pub fn check_url(&self, url: &Url) -> Result<(), EgressDenied> {
        if self
            .fixture_scope
            .as_ref()
            .is_some_and(|scope| !scope.permits_url(url))
        {
            return Err(EgressDenied::new(
                DenyRule::AuthorizationScope,
                url.as_str(),
                "fixture listener scope inactive or origin mismatch",
            ));
        }
        self.check_scheme(url.scheme())?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(EgressDenied::new(
                DenyRule::Userinfo,
                url.host_str().unwrap_or_default(),
                "userinfo present",
            ));
        }
        let Some(host) = url.host() else {
            return Err(EgressDenied::new(
                DenyRule::Hostname,
                url.as_str(),
                "missing host",
            ));
        };
        let port = url.port_or_known_default().unwrap_or(0);
        self.check_port(port)?;
        self.check_host_value(&host)?;
        if let Some(scope) = &self.record_scope {
            scope.check_request(url).map_err(|e| {
                EgressDenied::new(
                    DenyRule::AuthorizationScope,
                    url.as_str(),
                    match e {
                        AuthzFailure::Excluded(_) => "authorization record excluded path",
                        _ => "authorization record scope",
                    },
                )
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::egress_lists::{EgressLists, SharedEgressLists};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rule(p: &EgressPolicy, s: &str) -> Option<DenyRule> {
        p.check_ip(ip(s)).err().map(|e| e.rule)
    }

    #[test]
    fn every_denied_v4_range_is_denied_at_base_and_last_address() {
        let p = EgressPolicy::new(false);
        for r in DENIED_V4 {
            let base = Ipv4Addr::from(r.base);
            assert!(p.check_ip(IpAddr::V4(base)).is_err(), "{} base", r.name);
            let last = u32::from_be_bytes(r.base) | u32::MAX.checked_shr(r.prefix.into()).unwrap_or(0);
            assert!(
                p.check_ip(IpAddr::V4(Ipv4Addr::from(last))).is_err(),
                "{} last",
                r.name
            );
        }
    }

    #[test]
    fn every_denied_v6_range_is_denied_at_base() {
        let p = EgressPolicy::new(false);
        for r in DENIED_V6 {
            let base = Ipv6Addr::new(
                r.base[0], r.base[1], r.base[2], r.base[3], r.base[4], r.base[5], r.base[6], r.base[7],
            );
            assert!(p.check_ip(IpAddr::V6(base)).is_err(), "{}", r.name);
        }
    }

    #[test]
    fn named_ranges_map_to_rules() {
        let p = EgressPolicy::new(false);
        for (addr, want) in [
            ("0.0.0.0", DenyRule::Unspecified),
            ("0.1.2.3", DenyRule::Unspecified),
            ("10.1.2.3", DenyRule::Private),
            ("172.16.0.1", DenyRule::Private),
            ("172.31.255.255", DenyRule::Private),
            ("192.168.1.1", DenyRule::Private),
            ("100.64.0.1", DenyRule::CgNat),
            ("100.127.255.254", DenyRule::CgNat),
            ("127.0.0.1", DenyRule::Loopback),
            ("127.255.255.255", DenyRule::Loopback),
            ("169.254.1.1", DenyRule::LinkLocal),
            ("224.0.0.1", DenyRule::Multicast),
            ("239.255.255.255", DenyRule::Multicast),
            ("240.0.0.1", DenyRule::Reserved),
            ("255.255.255.255", DenyRule::Broadcast),
            ("192.0.2.1", DenyRule::Documentation),
            ("198.51.100.7", DenyRule::Documentation),
            ("203.0.113.9", DenyRule::Documentation),
            ("198.18.0.1", DenyRule::Reserved),
            ("198.19.255.255", DenyRule::Reserved),
            ("::", DenyRule::Unspecified),
            ("::1", DenyRule::Loopback),
            ("fc00::1", DenyRule::UniqueLocal),
            ("fdff::1", DenyRule::UniqueLocal),
            ("fe80::1", DenyRule::LinkLocal),
            ("ff02::1", DenyRule::Multicast),
            ("2001:db8::1", DenyRule::Documentation),
        ] {
            assert_eq!(rule(&p, addr), Some(want), "{addr}");
        }
    }

    #[test]
    fn public_addresses_pass() {
        let p = EgressPolicy::new(false);
        for a in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "172.15.255.255",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "169.253.1.1",
            "198.17.255.255",
            "198.20.0.1",
            "2606:4700:4700::1111",
            "2a00:1450:4001::1",
        ] {
            assert!(p.check_ip(ip(a)).is_ok(), "{a}");
        }
    }

    #[test]
    fn metadata_always_denied_even_with_allow_private_and_allowlist() {
        let mut p = EgressPolicy::new(true);
        p.extra_allow = vec![
            "169.254.0.0/16".parse().unwrap(),
            "100.64.0.0/10".parse().unwrap(),
            "fd00::/8".parse().unwrap(),
        ];
        for a in [
            "169.254.169.254",
            "100.100.100.200",
            "fd00:ec2::254",
            "192.0.0.192",
        ] {
            assert_eq!(rule(&p, a), Some(DenyRule::Metadata), "{a}");
        }
        assert_eq!(
            rule(&EgressPolicy::new(true), "169.254.169.254"),
            Some(DenyRule::Metadata)
        );
    }

    #[test]
    fn allow_private_exempts_private_but_not_link_local_or_multicast() {
        let p = EgressPolicy::new(true);
        for a in [
            "10.0.0.5",
            "192.168.1.1",
            "172.20.0.1",
            "100.64.0.9",
            "127.0.0.1",
            "fd12::1",
        ] {
            assert!(p.check_ip(ip(a)).is_ok(), "{a}");
        }
        for a in [
            "169.254.1.1",
            "fe80::1",
            "224.0.0.1",
            "ff02::1",
            "0.0.0.0",
            "240.0.0.1",
            "192.0.2.1",
        ] {
            assert!(p.check_ip(ip(a)).is_err(), "{a}");
        }
    }

    #[test]
    fn authorized_networks_restrict_the_exemption() {
        let mut p = EgressPolicy::new(true);
        p.extra_allow = vec!["10.20.0.0/16".parse().unwrap()];
        assert!(p.check_ip(ip("10.20.3.4")).is_ok());
        assert_eq!(rule(&p, "10.21.0.1"), Some(DenyRule::Private));
        assert_eq!(rule(&p, "192.168.0.1"), Some(DenyRule::Private));
        // list without allow_private still exempts exactly the list
        let mut q = EgressPolicy::new(false);
        q.extra_allow = vec!["10.20.0.0/16".parse().unwrap()];
        assert!(q.check_ip(ip("10.20.3.4")).is_ok());
    }

    #[test]
    fn extra_deny_wins_over_allow() {
        let mut p = EgressPolicy::new(true);
        p.extra_deny = vec!["8.8.8.0/24".parse().unwrap(), "10.0.0.7/32".parse().unwrap()];
        assert_eq!(rule(&p, "8.8.8.8"), Some(DenyRule::Configured));
        assert_eq!(rule(&p, "10.0.0.7"), Some(DenyRule::Configured));
        assert!(p.check_ip(ip("10.0.0.8")).is_ok());
    }

    #[test]
    fn ipv4_mapped_and_embedded_forms() {
        let p = EgressPolicy::new(false);
        assert_eq!(rule(&p, "::ffff:127.0.0.1"), Some(DenyRule::Loopback));
        assert_eq!(rule(&p, "::ffff:10.0.0.1"), Some(DenyRule::Private));
        assert_eq!(rule(&p, "::ffff:169.254.169.254"), Some(DenyRule::Metadata));
        assert_eq!(rule(&p, "::ffff:a9fe:a9fe"), Some(DenyRule::Metadata));
        assert_eq!(rule(&p, "::ffff:8.8.8.8"), Some(DenyRule::Transition));
        assert_eq!(rule(&p, "64:ff9b::7f00:1"), Some(DenyRule::Loopback));
        assert_eq!(rule(&p, "64:ff9b::808:808"), Some(DenyRule::Transition));
        assert_eq!(rule(&p, "2002:7f00:1::"), Some(DenyRule::Loopback));
        assert_eq!(rule(&p, "2002:0808:0808::1"), Some(DenyRule::Transition));
        assert_eq!(rule(&p, "::7f00:1"), Some(DenyRule::Loopback));
        // Teredo client 127.0.0.1 is stored as !127.0.0.1 = 128.255.255.254
        assert_eq!(
            rule(&p, "2001:0:4136:e378:8000:63bf:80ff:fffe"),
            Some(DenyRule::Loopback)
        );
        assert_eq!(
            rule(&p, "2001:0:4136:e378:8000:63bf:f7f7:f7f7"),
            Some(DenyRule::Transition)
        );
    }

    #[test]
    fn mapped_private_is_exempt_only_when_authorized() {
        let mut p = EgressPolicy::new(false);
        p.extra_allow = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(p.check_ip(ip("::ffff:10.1.1.1")).is_ok());
        assert!(p.check_ip(ip("::ffff:192.168.1.1")).is_err());
        // transition prefix with a public embedded address is never exempt
        assert!(EgressPolicy::new(true).check_ip(ip("::ffff:8.8.8.8")).is_err());
    }

    #[test]
    fn scheme_and_port_checks() {
        let p = EgressPolicy::new(false);
        assert!(p.check_scheme("http").is_ok());
        assert!(p.check_scheme("HTTPS").is_ok());
        for s in ["file", "ftp", "gopher", "data", "javascript", "ws"] {
            assert_eq!(p.check_scheme(s).unwrap_err().rule, DenyRule::Scheme, "{s}");
        }
        assert!(p.check_port(80).is_ok());
        assert!(p.check_port(443).is_ok());
        assert_eq!(p.check_port(22).unwrap_err().rule, DenyRule::Port);
        assert_eq!(p.check_port(8080).unwrap_err().rule, DenyRule::Port);
        let q = EgressPolicy {
            extra_ports: vec![8080],
            ..EgressPolicy::new(false)
        };
        assert!(q.check_port(8080).is_ok());
    }

    #[test]
    fn seed_port_is_allowed_via_builder() {
        let seed = Url::parse("https://example.com:8443/").unwrap();
        let p = EgressPolicy::new(false).with_seed_port(&seed);
        assert!(p.check_url(&seed).is_ok());
        assert!(p
            .check_url(&Url::parse("https://example.com:9443/").unwrap())
            .is_err());
    }

    #[test]
    fn hostname_deny_list() {
        let p = EgressPolicy::new(false);
        for h in [
            "localhost",
            "LOCALHOST",
            "localhost.",
            "foo.localhost",
            "db.internal",
            "metadata.google.internal",
            "printer.local",
        ] {
            assert!(p.check_host(h).is_err(), "{h}");
        }
        assert_eq!(
            p.check_host("metadata.google.internal").unwrap_err().rule,
            DenyRule::Metadata
        );
        for h in [
            "example.com",
            "localhost.example.com",
            "internal.example.com",
            "notlocal.com",
        ] {
            assert!(p.check_host(h).is_ok(), "{h}");
        }
    }

    #[test]
    fn internal_hostnames_exempt_with_private_but_metadata_never() {
        let p = EgressPolicy::new(true);
        assert!(p.check_host("staging.internal").is_ok());
        assert!(p.check_host("localhost").is_ok());
        assert_eq!(
            p.check_host("metadata.google.internal").unwrap_err().rule,
            DenyRule::Metadata
        );
    }

    #[test]
    fn ip_literal_hosts_in_all_encodings_are_checked() {
        let p = EgressPolicy::new(false);
        for h in [
            "127.0.0.1",
            "2130706433",
            "0x7f.0.0.1",
            "0177.0.0.1",
            "127.1",
            "[::1]",
            "::1",
            "[::ffff:7f00:1]",
            "0xa9fea9fe",
        ] {
            assert!(p.check_host(h).is_err(), "{h}");
        }
        assert!(p.check_host("8.8.8.8").is_ok());
    }

    #[test]
    fn check_url_pre_resolution() {
        let p = EgressPolicy::new(false);
        let ok = |s: &str| p.check_url(&Url::parse(s).unwrap());
        assert!(ok("https://example.com/a?b=1").is_ok());
        assert!(ok("http://example.com:80/").is_ok());
        assert_eq!(ok("ftp://example.com/").unwrap_err().rule, DenyRule::Scheme);
        assert_eq!(ok("file:///etc/passwd").unwrap_err().rule, DenyRule::Scheme);
        assert_eq!(
            ok("https://user:pw@example.com/").unwrap_err().rule,
            DenyRule::Userinfo
        );
        assert_eq!(
            ok("https://user@example.com/").unwrap_err().rule,
            DenyRule::Userinfo
        );
        assert_eq!(ok("http://example.com:22/").unwrap_err().rule, DenyRule::Port);
        assert_eq!(
            ok("http://169.254.169.254/latest/meta-data").unwrap_err().rule,
            DenyRule::Metadata
        );
        assert_eq!(ok("http://2130706433/").unwrap_err().rule, DenyRule::Loopback);
        assert_eq!(ok("http://[::1]/").unwrap_err().rule, DenyRule::Loopback);
        assert_eq!(ok("http://localhost/").unwrap_err().rule, DenyRule::Hostname);
        assert_eq!(
            ok("http://[::ffff:127.0.0.1]/").unwrap_err().rule,
            DenyRule::Loopback
        );
    }

    #[test]
    fn check_all_denies_mixed_answers() {
        let p = EgressPolicy::new(false);
        assert!(p
            .check_all("example.com", &[ip("93.184.216.34"), ip("2606:2800:220:1::1")])
            .is_ok());
        let e = p
            .check_all("evil.example", &[ip("93.184.216.34"), ip("10.0.0.1")])
            .unwrap_err();
        assert_eq!(e.rule, DenyRule::Private);
        assert!(p.check_all("localhost", &[ip("93.184.216.34")]).is_err());
    }

    #[test]
    fn rule_labels_are_stable() {
        assert_eq!(DenyRule::CgNat.as_str(), "cgnat");
        assert_eq!(DenyRule::UniqueLocal.to_string(), "unique_local");
        let e = EgressPolicy::new(false).check_ip(ip("127.0.0.1")).unwrap_err();
        assert!(e.to_string().contains("loopback"));
    }

    // ---- authorization record scope, deployment lists ----

    fn record_scope() -> RecordScope {
        let mut r = crate::authorization::tests::record();
        r.origins = vec![
            "https://staging.example.test".to_owned(),
            "http://127.0.0.1:8080".to_owned(),
        ];
        r.excluded_paths = vec!["/billing/*".to_owned()];
        r.scope()
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn record_scope_denies_hosts_urls_and_redirect_targets_outside_the_target() {
        let p = EgressPolicy::new(false).with_record_scope(record_scope());
        assert!(p.check_url(&url("https://staging.example.test/app")).is_ok());
        assert!(p.check_host("staging.example.test").is_ok());
        for out in [
            "https://prod.example.test/",
            "https://staging.example.test/billing/pay",
            "http://staging.example.test/",
            "https://example.test/",
            "https://cdn.other.test/lib.js",
        ] {
            let e = p.check_url(&url(out)).unwrap_err();
            assert_eq!(e.rule, DenyRule::AuthorizationScope, "{out}");
        }
        let e = p.check_host("prod.example.test").unwrap_err();
        assert_eq!(e.rule, DenyRule::AuthorizationScope);
        assert_eq!(e.rule.as_str(), "authorization_scope");
        // the run's own robots.txt fetch is part of obeying it
        assert!(p
            .check_url(&url("https://staging.example.test/robots.txt"))
            .is_ok());
    }

    #[test]
    fn record_scope_never_widens_the_egress_rules() {
        let mut p = EgressPolicy::new(false).with_record_scope(record_scope());
        p.extra_ports = vec![8080];
        // the record names loopback, but private ranges need `allowPrivateNetworks` + networks
        assert_eq!(
            p.check_url(&url("http://127.0.0.1:8080/")).unwrap_err().rule,
            DenyRule::Loopback
        );
        let mut open = EgressPolicy::new(true).with_record_scope(record_scope());
        open.extra_allow = vec!["127.0.0.0/8".parse().unwrap()];
        open.extra_ports = vec![8080];
        assert!(open.check_url(&url("http://127.0.0.1:8080/x")).is_ok());
        // an in-record host on a denied range, and metadata, keep their own rule
        let mut meta_scope = crate::authorization::tests::record();
        meta_scope.origins = vec!["http://169.254.169.254".to_owned()];
        let p = EgressPolicy::new(true).with_record_scope(meta_scope.scope());
        assert_eq!(
            p.check_url(&url("http://169.254.169.254/latest"))
                .unwrap_err()
                .rule,
            DenyRule::Metadata
        );
        // a metadata address outside the record is a metadata denial, not a scope denial
        let p = EgressPolicy::new(false).with_record_scope(record_scope());
        assert_eq!(
            p.check_url(&url("http://169.254.169.254/")).unwrap_err().rule,
            DenyRule::Metadata
        );
    }

    #[test]
    fn record_scope_covers_ip_literal_hosts_in_every_notation() {
        let mut r = crate::authorization::tests::record();
        r.origins = vec!["http://[::1]:9000".to_owned(), "http://127.0.0.1:8080".to_owned()];
        let mut p = EgressPolicy::new(true).with_record_scope(r.scope());
        p.extra_ports = vec![9000, 8080];
        assert!(p.check_host("127.0.0.1").is_ok());
        assert!(p.check_host("[::1]").is_ok());
        assert_eq!(
            p.check_host("127.0.0.2").unwrap_err().rule,
            DenyRule::AuthorizationScope
        );
        assert_eq!(
            p.check_host("2130706434").unwrap_err().rule,
            DenyRule::AuthorizationScope
        );
    }

    fn live(allowlist: Option<&[&str]>, blocklist: &[&str]) -> SharedEgressLists {
        SharedEgressLists::new(
            EgressLists::new(
                allowlist.map(|a| a.iter().map(|n| n.parse().unwrap()).collect()),
                blocklist.iter().copied(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn operator_blocklist_denies_hosts_subdomains_and_addresses_before_anything_else() {
        let l = live(None, &["blocked.test", "203.0.113.0/24"]);
        let p = EgressPolicy::new(false).with_lists(l.clone());
        for host in ["blocked.test", "www.blocked.test", "A.B.Blocked.Test."] {
            let e = p.check_host(host).unwrap_err();
            assert_eq!(e.rule, DenyRule::Blocklist, "{host}");
            assert_eq!(e.rule.as_str(), "operator_blocklist");
        }
        assert!(p.check_host("notblocked.test").is_ok());
        assert_eq!(
            p.check_ip(ip("203.0.113.9")).unwrap_err().rule,
            DenyRule::Blocklist
        );
        assert!(p.check_ip(ip("8.8.8.8")).is_ok());
        // a resolved answer inside a blocked network denies the name (E2)
        assert_eq!(
            p.check_all("fine.test", &[ip("93.184.216.34"), ip("203.0.113.1")])
                .unwrap_err()
                .rule,
            DenyRule::Blocklist
        );
        assert_eq!(
            p.check_url(&url("https://www.blocked.test/")).unwrap_err().rule,
            DenyRule::Blocklist
        );
    }

    #[test]
    fn blocklist_reload_reaches_a_policy_already_in_use() {
        let l = live(None, &[]);
        let p = EgressPolicy::new(false).with_lists(l.clone());
        let clone = p.clone();
        assert!(p.check_host("takedown.test").is_ok());
        l.replace(EgressLists::new(None, ["takedown.test"]).unwrap());
        assert_eq!(
            p.check_host("takedown.test").unwrap_err().rule,
            DenyRule::Blocklist
        );
        assert_eq!(
            clone.check_host("x.takedown.test").unwrap_err().rule,
            DenyRule::Blocklist
        );
        l.replace(EgressLists::default());
        assert!(p.check_host("takedown.test").is_ok());
    }

    #[test]
    fn deployment_allowlist_bounds_record_networks_at_runtime() {
        let l = live(Some(&["10.20.0.0/16"]), &[]);
        let mut p = EgressPolicy::new(true).with_lists(l);
        p.extra_allow = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(p.check_ip(ip("10.20.5.5")).is_ok());
        assert_eq!(
            p.check_ip(ip("10.99.5.5")).unwrap_err().rule,
            DenyRule::Private,
            "record is wider than the deployment"
        );
        // allow_private with no networks is bounded the same way
        let mut q = EgressPolicy::new(true).with_lists(live(Some(&["10.20.0.0/16"]), &[]));
        assert!(q.check_ip(ip("10.20.0.1")).is_ok());
        assert!(q.check_ip(ip("192.168.0.1")).is_err());
        // with an unset allowlist nothing changes
        q.lists = Some(live(None, &[]));
        assert!(q.check_ip(ip("192.168.0.1")).is_ok());
        // an internal hostname passes only when private ranges are exempt at all
        let strict = EgressPolicy::new(false).with_lists(live(Some(&["127.0.0.0/8"]), &[]));
        assert_eq!(
            strict.check_host("localhost").unwrap_err().rule,
            DenyRule::Hostname
        );
    }

    #[test]
    fn deployment_exempt_lets_a_run_without_a_record_reach_only_named_networks() {
        let mut p = EgressPolicy::new(false).with_lists(live(Some(&["127.0.0.0/8", "10.20.0.0/16"]), &[]));
        assert!(
            p.check_ip(ip("127.0.0.1")).is_err(),
            "off unless the run is test_environment"
        );
        p.deployment_exempt = true;
        assert!(p.check_ip(ip("127.0.0.1")).is_ok());
        assert!(p.check_ip(ip("10.20.7.7")).is_ok());
        assert!(p.check_host("localhost").is_ok());
        assert_eq!(p.check_ip(ip("10.21.0.1")).unwrap_err().rule, DenyRule::Private);
        assert_eq!(
            p.check_ip(ip("169.254.169.254")).unwrap_err().rule,
            DenyRule::Metadata
        );
        assert_eq!(p.check_ip(ip("fe80::1")).unwrap_err().rule, DenyRule::LinkLocal);
        // an empty or unset allowlist exempts nothing
        p.lists = Some(live(Some(&[]), &[]));
        assert!(p.check_ip(ip("127.0.0.1")).is_err());
        assert!(p.check_host("localhost").is_err());
        p.lists = None;
        assert!(p.check_ip(ip("127.0.0.1")).is_err());
    }
}
