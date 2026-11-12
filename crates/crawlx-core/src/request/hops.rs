//! Typed hop kinds, the hop path a request carries, and the limits on it.
//!
//! A hop path records how a URL was reached from the seed, one symbol per hop: `L` a followed
//! link, `E` an embedded resource, `P` a prerequisite of the page that needs it, `R` a redirect.
//! It is descriptive evidence plus a bound: it never grants permission to fetch. Every hop target
//! still passes scope, robots, authorization and the origin governor, and an out-of-scope target
//! is refused whatever its kind.

use super::{RequestEnvelopeV1, RequestError};
use serde::{Deserialize, Serialize};
use url::Url;

/// Metadata key under which a request envelope carries its hop path.
pub const HOP_PATH_KEY: &str = "hop_path";
/// Longest hop path an envelope may carry.
pub const MAX_HOP_PATH: usize = 64;

/// How a URL was reached from the page that named it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HopKindV1 {
    /// A hyperlink the crawl follows to another page.
    Link,
    /// A resource the page embeds (image, frame, object).
    Embed,
    /// A script or stylesheet the page needs to render.
    Prerequisite,
    /// The target of a redirect response.
    Redirect,
}

impl HopKindV1 {
    /// The one-letter symbol of this kind in a hop path.
    #[must_use]
    pub const fn symbol(self) -> char {
        match self {
            Self::Link => 'L',
            Self::Embed => 'E',
            Self::Prerequisite => 'P',
            Self::Redirect => 'R',
        }
    }

    /// Stable `snake_case` name, identical to the serde form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Embed => "embed",
            Self::Prerequisite => "prerequisite",
            Self::Redirect => "redirect",
        }
    }

    /// The kind a path symbol stands for.
    #[must_use]
    pub const fn from_symbol(symbol: char) -> Option<Self> {
        match symbol {
            'L' => Some(Self::Link),
            'E' => Some(Self::Embed),
            'P' => Some(Self::Prerequisite),
            'R' => Some(Self::Redirect),
            _ => None,
        }
    }

    /// Whether the hop depends on the page before it instead of being navigation of its own.
    #[must_use]
    pub const fn transitive(self) -> bool {
        !matches!(self, Self::Link)
    }
}

/// The hops from the seed to a request, oldest first. The seed's path is empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HopPathV1(String);

impl TryFrom<String> for HopPathV1 {
    type Error = RequestError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if text.len() > MAX_HOP_PATH || !text.chars().all(|c| HopKindV1::from_symbol(c).is_some()) {
            return Err(RequestError::InvalidMetadata);
        }
        Ok(Self(text))
    }
}

impl From<HopPathV1> for String {
    fn from(path: HopPathV1) -> Self {
        path.0
    }
}

impl HopPathV1 {
    /// The hop symbols as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hops in the path.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the seed's empty path.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// This path followed by one more hop, or `None` when the result would exceed
    /// [`MAX_HOP_PATH`].
    #[must_use]
    pub fn pushed(&self, kind: HopKindV1) -> Option<Self> {
        (self.0.len() < MAX_HOP_PATH).then(|| {
            let mut next = self.0.clone();
            next.push(kind.symbol());
            Self(next)
        })
    }

    /// Hops of `kind` in the path.
    #[must_use]
    pub fn count(&self, kind: HopKindV1) -> usize {
        let symbol = kind.symbol();
        self.0.chars().filter(|c| *c == symbol).count()
    }

    /// Consecutive transitive hops (everything but links) at the end of the path.
    #[must_use]
    pub fn transitive_run(&self) -> usize {
        self.0
            .chars()
            .rev()
            .take_while(|c| *c != HopKindV1::Link.symbol())
            .count()
    }
}

/// Why a hop was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HopDenialV1 {
    /// The path would be longer than `maxHops`.
    TooManyHops,
    /// More embeds, prerequisites and redirects in a row than `maxTransitiveHops`.
    TooManyTransitiveHops,
    /// A path segment repeats more often than `maxRepeatedSegments`.
    PathologicalPath,
    /// Embedded resources are not followed by this crawl.
    EmbedsNotFollowed,
    /// Prerequisites are not followed by this crawl.
    PrerequisitesNotFollowed,
}

impl HopDenialV1 {
    /// Stable denial code recorded in discovery counters.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooManyHops => "hop_limit",
            Self::TooManyTransitiveHops => "transitive_hop_limit",
            Self::PathologicalPath => "pathological_path",
            Self::EmbedsNotFollowed => "embed_not_followed",
            Self::PrerequisitesNotFollowed => "prerequisite_not_followed",
        }
    }
}

/// `scope.hops`: which typed hops a crawl follows and how long a hop chain may grow.
///
/// Links are always followed (subject to `maxDiscoveryDepth` and scope). Embeds and
/// prerequisites are followed only when asked for. The limits end calendar-style traps that
/// keep producing new URLs without ever reaching new content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct HopPolicyV1 {
    /// Exactly one.
    pub version: u16,
    /// Fetch resources a page embeds (default false).
    pub follow_embeds: bool,
    /// Fetch scripts and stylesheets a page needs (default false).
    pub follow_prerequisites: bool,
    /// Longest hop path, `1..=64` (default 32).
    pub max_hops: u16,
    /// Most embeds, prerequisites and redirects in a row, `0..=64` (default 3).
    pub max_transitive_hops: u8,
    /// Most times one path segment may repeat in a URL; `0` is off (default 3).
    pub max_repeated_segments: u8,
}

impl Default for HopPolicyV1 {
    fn default() -> Self {
        Self {
            version: 1,
            follow_embeds: false,
            follow_prerequisites: false,
            max_hops: 32,
            max_transitive_hops: 3,
            max_repeated_segments: 3,
        }
    }
}

impl HopPolicyV1 {
    /// A policy with the given chain and repetition limits that follows links only.
    #[must_use]
    pub const fn new(max_hops: u16, max_transitive_hops: u8, max_repeated_segments: u8) -> Self {
        Self {
            version: 1,
            follow_embeds: false,
            follow_prerequisites: false,
            max_hops,
            max_transitive_hops,
            max_repeated_segments,
        }
    }

    /// This policy, also following embedded resources and/or prerequisites.
    #[must_use]
    pub const fn following(mut self, embeds: bool, prerequisites: bool) -> Self {
        self.follow_embeds = embeds;
        self.follow_prerequisites = prerequisites;
        self
    }

    /// Check the bounds.
    ///
    /// # Errors
    /// An unsupported version or a limit outside its range.
    pub fn validate(&self) -> Result<(), RequestError> {
        if self.version != 1
            || !(1..=64).contains(&self.max_hops)
            || usize::from(self.max_transitive_hops) > MAX_HOP_PATH
        {
            return Err(RequestError::InvalidMetadata);
        }
        Ok(())
    }

    /// The hop path of a request reached from `parent`'s path by one `kind` hop to `url`.
    ///
    /// # Errors
    /// The first limit the hop breaks.
    pub fn admit(&self, parent: &HopPathV1, kind: HopKindV1, url: &Url) -> Result<HopPathV1, HopDenialV1> {
        match kind {
            HopKindV1::Embed if !self.follow_embeds => return Err(HopDenialV1::EmbedsNotFollowed),
            HopKindV1::Prerequisite if !self.follow_prerequisites => {
                return Err(HopDenialV1::PrerequisitesNotFollowed);
            }
            _ => {}
        }
        let path = parent.pushed(kind).ok_or(HopDenialV1::TooManyHops)?;
        if path.len() > usize::from(self.max_hops) {
            return Err(HopDenialV1::TooManyHops);
        }
        if path.transitive_run() > usize::from(self.max_transitive_hops) {
            return Err(HopDenialV1::TooManyTransitiveHops);
        }
        if self.max_repeated_segments > 0 && repeated_segments(url) > usize::from(self.max_repeated_segments)
        {
            return Err(HopDenialV1::PathologicalPath);
        }
        Ok(path)
    }
}

/// The most times any one non-empty path segment occurs in `url`.
#[must_use]
pub fn repeated_segments(url: &Url) -> usize {
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for segment in url.path().split('/').filter(|segment| !segment.is_empty()) {
        *counts.entry(segment).or_default() += 1;
    }
    counts.values().copied().max().unwrap_or(0)
}

impl RequestEnvelopeV1 {
    /// The hops that led to this request; empty for a seed or a request without a recorded path.
    #[must_use]
    pub fn hop_path(&self) -> HopPathV1 {
        self.metadata
            .get(HOP_PATH_KEY)
            .and_then(serde_json::Value::as_str)
            .and_then(|text| HopPathV1::try_from(text.to_owned()).ok())
            .unwrap_or_default()
    }

    /// Record the hops that led to this request.
    pub fn set_hop_path(&mut self, path: &HopPathV1) {
        self.metadata.insert(
            HOP_PATH_KEY.to_owned(),
            serde_json::Value::String(path.as_str().to_owned()),
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    #[test]
    fn paths_are_bounded_typed_and_round_trip() {
        let mut path = HopPathV1::default();
        for kind in [
            HopKindV1::Link,
            HopKindV1::Embed,
            HopKindV1::Prerequisite,
            HopKindV1::Redirect,
        ] {
            path = path.pushed(kind).unwrap();
        }
        assert_eq!(path.as_str(), "LEPR");
        assert_eq!(path.transitive_run(), 3);
        assert_eq!(path.count(HopKindV1::Link), 1);
        let wire = serde_json::to_string(&path).unwrap();
        assert_eq!(wire, "\"LEPR\"");
        assert_eq!(serde_json::from_str::<HopPathV1>(&wire).unwrap(), path);
        assert!(serde_json::from_str::<HopPathV1>("\"LX\"").is_err());
        assert!(serde_json::from_str::<HopPathV1>(&format!("\"{}\"", "L".repeat(65))).is_err());
        let full = HopPathV1::try_from("L".repeat(MAX_HOP_PATH)).unwrap();
        assert!(full.pushed(HopKindV1::Link).is_none());
    }

    #[test]
    fn policy_admits_typed_hops_and_stops_chains_and_traps() {
        let policy = HopPolicyV1 {
            follow_embeds: true,
            max_hops: 4,
            max_transitive_hops: 1,
            max_repeated_segments: 2,
            ..HopPolicyV1::default()
        };
        let seed = HopPathV1::default();
        let page = url("https://a.test/page");
        let link = policy.admit(&seed, HopKindV1::Link, &page).unwrap();
        let embed = policy
            .admit(&link, HopKindV1::Embed, &url("https://a.test/i.png"))
            .unwrap();
        assert_eq!(embed.as_str(), "LE");
        assert_eq!(
            policy.admit(&embed, HopKindV1::Redirect, &page),
            Err(HopDenialV1::TooManyTransitiveHops)
        );
        assert_eq!(
            policy.admit(&link, HopKindV1::Prerequisite, &page),
            Err(HopDenialV1::PrerequisitesNotFollowed)
        );
        assert_eq!(
            HopPolicyV1::default().admit(&link, HopKindV1::Embed, &page),
            Err(HopDenialV1::EmbedsNotFollowed)
        );
        let deep = HopPathV1::try_from("LLLL".to_owned()).unwrap();
        assert_eq!(
            policy.admit(&deep, HopKindV1::Link, &page),
            Err(HopDenialV1::TooManyHops)
        );
        assert_eq!(
            policy.admit(&link, HopKindV1::Link, &url("https://a.test/c/c/c/d")),
            Err(HopDenialV1::PathologicalPath)
        );
        assert!(policy
            .admit(&link, HopKindV1::Link, &url("https://a.test/c/c/d"))
            .is_ok());
        assert!(HopPolicyV1 {
            max_hops: 0,
            ..HopPolicyV1::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn the_envelope_carries_its_path_in_validated_metadata() {
        let parsed = url("https://a.test/");
        let canonical = crate::url::CanonicalUrl {
            key: crate::hash::Digest::of("test/url", parsed.as_str().as_bytes()),
            origin: parsed.origin().ascii_serialization(),
            route_template: crate::url::RouteTemplate(parsed.path().to_owned()),
            params: Vec::new(),
            url: parsed,
        };
        let mut request = RequestEnvelopeV1::get(canonical, 1, None);
        assert!(request.hop_path().is_empty());
        let path = HopPathV1::try_from("LE".to_owned()).unwrap();
        request.set_hop_path(&path);
        request.validate().unwrap();
        assert_eq!(request.hop_path(), path);
        request
            .metadata
            .insert(HOP_PATH_KEY.to_owned(), serde_json::json!("not a path"));
        assert!(request.validate().is_err());
    }
}
