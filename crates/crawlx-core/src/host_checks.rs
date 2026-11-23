//! Host checks: opt-in, single-request probes of an origin (`scope.hostChecks`).
//!
//! A check records neutral facts about how an origin answers one request: a status class and
//! the reason a request was not sent. It never records a finding, a score or a severity. The
//! types here are the configuration key, the verdict vocabulary and the record stored as the
//! `host_check` run event and reported in the run report.

use serde::{Deserialize, Serialize};

/// Event kind under which a finished check is stored.
pub const HOST_CHECK_EVENT: &str = "host_check";

/// An entry of `scope.hostChecks`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum HostCheck {
    /// One request to a random path no page links to: does the origin answer a missing path
    /// with a success status.
    #[serde(rename = "soft_404")]
    Soft404,
}

impl HostCheck {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Soft404 => "soft_404",
        }
    }
}

/// The outcome of one host check, in the vocabulary of that check.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum HostCheckVerdict {
    /// `soft_404`: the random path answered with a 2xx status.
    #[serde(rename = "soft_404")]
    Soft404,
    /// `soft_404`: the random path answered 404 or 410.
    #[serde(rename = "not_soft_404")]
    NotSoft404,
    /// The check could not decide: no request was sent, the request failed, or the answer was
    /// not one the check classifies.
    #[serde(rename = "inconclusive")]
    Inconclusive,
}

/// Why a check is [`HostCheckVerdict::Inconclusive`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HostCheckReason {
    /// Scope refused the URL; nothing was sent.
    Scope,
    /// `robots.txt` disallows the URL; nothing was sent.
    Robots,
    /// `robots.txt` could not be read, so the URL was not requested.
    RobotsUnavailable,
    /// The egress policy refused the request.
    Egress,
    /// The run's authorization did not permit a request; nothing was sent.
    Authorization,
    /// The run's request budget for the probe could not be set up; nothing was sent.
    Budget,
    /// The request was sent and did not complete.
    RequestFailed,
    /// The origin answered with a status the check does not classify.
    UnclassifiedStatus,
}

/// One finished host check, as stored in the `host_check` event and the run report.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct HostCheckRecord {
    /// Which check ran.
    pub check: HostCheck,
    /// The probed origin (`scheme://host[:port]`).
    pub origin: String,
    /// The URL the check requests (or would have requested).
    pub url: String,
    /// A request was sent.
    pub requested: bool,
    /// Status of the answer, when one arrived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// What the check found.
    pub verdict: HostCheckVerdict,
    /// Why the verdict is inconclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<HostCheckReason>,
    /// Stable error code of a failed request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

impl HostCheckRecord {
    /// A check whose request was refused or never sent.
    #[must_use]
    pub fn not_sent(check: HostCheck, origin: &str, url: &str, reason: HostCheckReason) -> Self {
        Self {
            check,
            origin: origin.to_owned(),
            url: url.to_owned(),
            requested: false,
            status: None,
            verdict: HostCheckVerdict::Inconclusive,
            reason: Some(reason),
            error_code: None,
        }
    }
}
