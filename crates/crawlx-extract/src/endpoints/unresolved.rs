//! Explicit outcomes for URL expressions the static JavaScript pass cannot resolve.
//!
//! The AST pass never evaluates script code. When the URL position of a request
//! site (`fetch(url)`, `xhr.open("GET", cfg.url)`, `location = next()`) holds an
//! expression that is not a constant, the miner used to drop the site or guess a
//! route pattern. It now keeps reporting the endpoint it could derive and adds a
//! typed [`UnresolvedEndpoint`] per unresolved sub-expression: what kind of
//! expression it was, where it sits in the script, and whether an endpoint was
//! still emitted (`partial`).
//!
//! The list is bounded by [`crate::endpoints::DiscoveryOptions::max_unresolved`];
//! outcomes beyond the bound are counted in
//! [`DiscoveryReport::unresolved_dropped`], never listed.

use http::Method;
use serde::{Deserialize, Serialize};

use super::{DiscoveredEndpoint, EndpointSource};

/// Default cap on [`UnresolvedEndpoint`] outcomes per response.
pub const DEFAULT_MAX_UNRESOLVED: usize = 1_000;

/// Why a URL sub-expression could not be resolved statically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UnresolvedKind {
    /// An identifier without a single constant binding: a parameter, a
    /// reassigned or redeclared variable, a global, or a chain too deep to follow.
    Variable,
    /// The result of a function call that is not a transparent string wrapper.
    Call,
    /// A member access such as `cfg.url` or `routes["home"]`.
    Member,
    /// Any other expression: conditional, arithmetic, object, function, `this`.
    Expression,
}

/// Which text of the response a [`SourceSpan`] indexes into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScriptOrigin {
    /// The response body itself is the script.
    ScriptFile,
    /// The text of one inline `<script>` element.
    InlineScript,
    /// The value of one `on…` event-handler attribute.
    EventHandler,
    /// A handler string found inside another script (`setAttribute("onclick", …)`).
    NestedHandler,
}

/// Half-open byte range `[start, end)` into the script text named by
/// [`ScriptOrigin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceSpan {
    /// First byte of the expression.
    pub start: u32,
    /// One past the last byte of the expression.
    pub end: u32,
}

/// One URL sub-expression of a request site that could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UnresolvedEndpoint {
    /// Matcher that read the request site (`js/fetch`, `js/xhr`, …).
    pub source: EndpointSource,
    /// Method the site requests, as far as it is known statically.
    #[serde(with = "super::method_serde")]
    pub method: Method,
    /// What kind of expression stayed unresolved.
    pub kind: UnresolvedKind,
    /// Where the unresolved expression sits.
    pub span: SourceSpan,
    /// Which script text `span` indexes into.
    pub origin: ScriptOrigin,
    /// An endpoint was still emitted for the site (placeholder segments or a
    /// dropped unknown prefix); `false` when the site yielded no endpoint.
    pub partial: bool,
    /// Crawl depth of the site (input depth + 1), like [`DiscoveredEndpoint::depth`].
    pub depth: u32,
}

/// Endpoints plus the unresolved outcomes found alongside them.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DiscoveryReport {
    /// What [`crate::endpoints::discover_with`] returns.
    pub endpoints: Vec<DiscoveredEndpoint>,
    /// Unresolved URL sub-expressions, in script order, at most
    /// [`crate::endpoints::DiscoveryOptions::max_unresolved`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved: Vec<UnresolvedEndpoint>,
    /// Outcomes beyond the cap that were counted but not listed.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unresolved_dropped: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Bounded collector shared by every script of one response.
#[derive(Debug)]
pub(super) struct UnresolvedLog {
    items: Vec<UnresolvedEndpoint>,
    cap: usize,
    dropped: usize,
}

impl UnresolvedLog {
    pub(super) fn new(cap: usize) -> Self {
        Self {
            items: Vec::new(),
            cap,
            dropped: 0,
        }
    }

    pub(super) fn push(&mut self, item: UnresolvedEndpoint) {
        if self.items.len() < self.cap {
            self.items.push(item);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    pub(super) fn finish(self, endpoints: Vec<DiscoveredEndpoint>) -> DiscoveryReport {
        DiscoveryReport {
            endpoints,
            unresolved: self.items,
            unresolved_dropped: self.dropped,
        }
    }
}
