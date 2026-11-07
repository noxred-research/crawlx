//! URL value types shared across planes. Computation lives in `crawlx-url`;
//! this module only defines the shapes.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A URL after canonicalization and query-parameter classification.
/// `key` is what dedupe and the frontier use; `url` is what gets fetched.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct CanonicalUrl {
    /// The fetchable canonical URL (tracking and session parameters removed).
    pub url: url::Url,
    /// Dedupe key: `BLAKE3("crawlx/canonical-url/v1", canonical string)`.
    pub key: crate::hash::Digest,
    /// Origin (`scheme://host[:port]`) for politeness and scope.
    pub origin: String,
    /// Route template with resource-id slots, e.g. `/invoice/:id`.
    pub route_template: RouteTemplate,
    /// Classified parameters in canonical order.
    pub params: Vec<ClassifiedParam>,
}

impl CanonicalUrl {
    /// Route key used by observations and state signatures.
    #[must_use]
    pub fn route_key(&self) -> RouteKey {
        RouteKey {
            origin: self.origin.clone(),
            template: self.route_template.clone(),
            query_schema: self
                .params
                .iter()
                .filter(|p| p.class.kept())
                .map(|p| (p.name.clone(), p.class))
                .collect(),
        }
    }
}

impl fmt::Display for CanonicalUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.url, f)
    }
}

/// Query-parameter class. Unknown parameters default to `Filter`
/// because dropping a functional parameter silently merges resources.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ParamClass {
    /// Identifies a resource (e.g. `?id=42`); kept, with the value replaced by a keyed hash.
    ResourceId,
    /// Selects a page or position (e.g. pagination); kept with the raw value.
    Navigation,
    /// Narrows or orders a result set; kept with a bucketed value. Default for unknown parameters.
    Filter,
    /// Campaign or analytics parameter; dropped from the canonical URL.
    Tracking,
    /// Session or auth token; dropped from the canonical URL.
    Session,
    /// Parameter that selects an action (e.g. `?action=delete`); kept with the raw value.
    ActionBearing,
}

impl ParamClass {
    /// Is the parameter kept in the canonical URL?
    #[must_use]
    pub const fn kept(self) -> bool {
        !matches!(self, Self::Tracking | Self::Session)
    }

    /// Stable string form (also used in the database).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResourceId => "resource_id",
            Self::Navigation => "navigation",
            Self::Filter => "filter",
            Self::Tracking => "tracking",
            Self::Session => "session",
            Self::ActionBearing => "action_bearing",
        }
    }
}

impl std::str::FromStr for ParamClass {
    type Err = crate::error::CoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "resource_id" => Self::ResourceId,
            "navigation" => Self::Navigation,
            "filter" => Self::Filter,
            "tracking" => Self::Tracking,
            "session" => Self::Session,
            "action_bearing" => Self::ActionBearing,
            other => {
                return Err(crate::error::CoreError::UnknownEnum {
                    kind: "ParamClass",
                    value: other.to_owned(),
                })
            }
        })
    }
}

/// One classified query parameter.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct ClassifiedParam {
    /// Parameter name as it appeared in the URL.
    pub name: String,
    /// Class the parameter was assigned.
    pub class: ParamClass,
    /// Value bucket: raw for `Navigation`/`ActionBearing`, bucketed for
    /// `Filter`, a keyed hash for `ResourceId`, `None` when dropped.
    pub value: Option<String>,
}

/// Path with resource-id slots, e.g. `/invoice/:id`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct RouteTemplate(pub String);

impl fmt::Display for RouteTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Route template plus classified query schema.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct RouteKey {
    /// Origin (`scheme://host[:port]`) the route belongs to.
    pub origin: String,
    /// Path template with resource-id slots, e.g. `/invoice/:id`.
    pub template: RouteTemplate,
    /// Kept query parameters as `(name, class)` pairs in canonical order, without values.
    pub query_schema: Vec<(String, ParamClass)>,
}

impl RouteKey {
    /// Digest for use inside state signatures.
    #[must_use]
    pub fn digest(&self) -> crate::hash::Digest {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.origin.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(self.template.0.as_bytes());
        for (n, c) in &self.query_schema {
            bytes.push(0);
            bytes.extend_from_slice(n.as_bytes());
            bytes.push(b'=');
            bytes.extend_from_slice(c.as_str().as_bytes());
        }
        crate::hash::Digest::of("crawlx/route-key/v1", &bytes)
    }
}
