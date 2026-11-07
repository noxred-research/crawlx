//! Durable semantic identity and the coverage unit.

use crate::hash::Digest;
use crate::ids::{ActionContextId, PrincipalId, StateClusterId};
use crate::url::RouteTemplate;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Durable semantic key of a control. Hashed with BLAKE3 under
/// `crawlx/element-identity/v1`; never contains runtime handles.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct ElementIdentityV1 {
    /// Frame lineage as a list of frame-identity digests (main frame = empty).
    pub frame_lineage: Vec<String>,
    /// ARIA role of the element (e.g. `button`, `link`, `textbox`).
    pub role: String,
    /// Accessible name with digits, dates, relative times and whitespace runs stripped.
    pub normalized_accessible_name: String,
    /// Ancestor roles with `generic`/`group`/`none`/`presentation` removed.
    pub stable_ancestor_role_path: Vec<String>,
    /// Nearest named container signature (heading/landmark/link name), truncated.
    pub container_signature: Option<String>,
    /// Link-like elements: canonical destination after query classification.
    pub destination_key: Option<String>,
    /// Label signature for form controls.
    pub label_signature: Option<String>,
    /// `type`/`inputmode`/`role` refinement for controls.
    pub control_type: Option<String>,
}

impl ElementIdentityV1 {
    /// Domain-separation tag mixed into the identity hash.
    pub const DOMAIN: &'static str = "crawlx/element-identity/v1";

    /// Stable hash of the identity.
    ///
    /// # Errors
    /// Returns the CBOR serialization error if the identity cannot be encoded.
    pub fn hash(&self) -> Result<ElementIdentityHash, ciborium::ser::Error<std::io::Error>> {
        Ok(ElementIdentityHash(Digest::of_value(Self::DOMAIN, self)?))
    }
}

/// `BLAKE3` over `ElementIdentityV1`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ElementIdentityHash(pub Digest);

impl fmt::Debug for ElementIdentityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ElementIdentityHash({})", &self.0.to_hex()[..12])
    }
}

impl fmt::Display for ElementIdentityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// The kind of interaction (the `BrowserAction` vocabulary, collapsed).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Pointer click (`BrowserAction::Click`).
    Click,
    /// Keyboard activation of a focused control (`BrowserAction::KeyboardActivate`).
    KeyboardActivate,
    /// Text entry (`BrowserAction::Type`).
    Type,
    /// Option selection in a `<select>`/listbox (`BrowserAction::Select`).
    Select,
    /// Checkbox/radio/switch state change (`BrowserAction::SetChecked`).
    SetChecked,
    /// Range input value change (`BrowserAction::SetRange`).
    SetRange,
    /// Pointer hover (`BrowserAction::Hover`).
    Hover,
    /// Drag and drop (`BrowserAction::Drag`).
    Drag,
    /// File upload (`BrowserAction::Upload`).
    Upload,
    /// Wheel scroll (`BrowserAction::Scroll`).
    Scroll,
    /// Key chord sequence (`BrowserAction::Keys`).
    Keys,
    /// Navigation to a URL (`BrowserAction::Navigate`).
    Navigate,
    /// Switch to another tab (`BrowserAction::SwitchTab`).
    SwitchTab,
    /// Close a tab (`BrowserAction::CloseTab`).
    CloseTab,
    /// Scripted DOM click, only when explicitly allowed (`BrowserAction::SyntheticClick`).
    SyntheticClick,
    /// Explicit provider solve and widget callback delivery (`BrowserAction::SolveCaptcha`).
    SolveCaptcha,
}

impl ActionKind {
    /// Idempotent kinds may be retried after reconciliation and tolerate
    /// mutation drift.
    #[must_use]
    pub const fn is_idempotent(self) -> bool {
        matches!(
            self,
            Self::Hover | Self::Scroll | Self::Navigate | Self::SwitchTab | Self::CloseTab | Self::Keys
        )
    }

    /// Stable `snake_case` name, identical to the serde form and the stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Click => "click",
            Self::KeyboardActivate => "keyboard_activate",
            Self::Type => "type",
            Self::Select => "select",
            Self::SetChecked => "set_checked",
            Self::SetRange => "set_range",
            Self::Hover => "hover",
            Self::Drag => "drag",
            Self::Upload => "upload",
            Self::Scroll => "scroll",
            Self::Keys => "keys",
            Self::Navigate => "navigate",
            Self::SwitchTab => "switch_tab",
            Self::CloseTab => "close_tab",
            Self::SyntheticClick => "synthetic_click",
            Self::SolveCaptcha => "solve_captcha",
        }
    }
}

/// Deterministic value partition, e.g. `email:valid_new_user`.
/// `none` for actions without an input.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct InputClass(pub String);

impl InputClass {
    /// The input class of actions that take no input.
    #[must_use]
    pub fn none() -> Self {
        Self("none".to_owned())
    }
    /// Input class for the value partition `partition` of an input `kind`, rendered as `kind:partition`.
    #[must_use]
    pub fn new(kind: &str, partition: &str) -> Self {
        Self(format!("{kind}:{partition}"))
    }
}

/// Who owns the resource the action targets.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResourceContext {
    /// The principal's own resource.
    Own,
    /// A resource owned by a different user holding the same role.
    OtherUserSameRole,
    /// A resource owned by a user with a higher-privileged role.
    HigherRole,
    /// A resource shared between users (e.g. a public or team-wide object).
    Shared,
    /// The action does not target an owned resource.
    #[default]
    None,
}

impl ResourceContext {
    /// Stable `snake_case` name, identical to the serde form and the stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Own => "own",
            Self::OtherUserSameRole => "other_user_same_role",
            Self::HigherRole => "higher_role",
            Self::Shared => "shared",
            Self::None => "none",
        }
    }
}

/// The unit of coverage, novelty and frontier reasoning.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct ActionContextKey {
    /// Principal (user/role identity) performing the action.
    pub principal: PrincipalId,
    /// Normalized route of the page the action is on, with variable segments templated.
    pub route_template: RouteTemplate,
    /// Hash of the target element's durable identity.
    pub element: ElementIdentityHash,
    /// What kind of interaction is performed.
    pub action_kind: ActionKind,
    /// Partition of the input value used (`none` when the action has no input).
    pub input_class: InputClass,
    /// Ownership relation between the principal and the targeted resource.
    pub resource_context: ResourceContext,
    /// Cluster of equivalent page states the action was observed in.
    pub state_cluster: StateClusterId,
}

/// Mutually exclusive coverage classification shared by storage readers and strategies.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CoverageStatus {
    /// At least one trusted, reachable execution.
    Exercised,
    /// Executed only outside the trusted, reachable lane.
    DiagnosticOnly,
    /// Cross-principal context unavailable under per-role replicas.
    NotObservable,
    /// Known, observable and never exercised.
    Uncovered,
}

impl CoverageStatus {
    /// Classify one key; successful trusted evidence takes precedence over isolation.
    #[must_use]
    pub const fn classify(
        key: &ActionContextKey,
        isolation: crate::config::TargetIsolation,
        trusted: u32,
        diagnostic: u32,
    ) -> Self {
        if trusted > 0 {
            Self::Exercised
        } else if !key.is_observable(isolation) {
            Self::NotObservable
        } else if diagnostic > 0 {
            Self::DiagnosticOnly
        } else {
            Self::Uncovered
        }
    }

    /// Stable wire and report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exercised => "exercised",
            Self::DiagnosticOnly => "diagnostic_only",
            Self::NotObservable => "not_observable",
            Self::Uncovered => "uncovered",
        }
    }
}

impl ActionContextKey {
    /// Domain-separation tag mixed into the action-context id hash.
    pub const DOMAIN: &'static str = "crawlx/action-context/v1";

    /// Whether isolation permits observing this resource class.
    #[must_use]
    pub const fn is_observable(&self, isolation: crate::config::TargetIsolation) -> bool {
        match isolation {
            crate::config::TargetIsolation::Shared => true,
            crate::config::TargetIsolation::PerRoleReplica => {
                matches!(
                    self.resource_context,
                    ResourceContext::Own | ResourceContext::None
                )
            }
        }
    }

    /// Reserved route-level cluster used only after the cardinality limit.
    /// Other dimensions, including input partition and ownership class, remain unchanged.
    #[must_use]
    pub fn coarsened_cluster(&self) -> StateClusterId {
        Self::coarsened_route_cluster(&self.route_template)
    }

    /// Reserved route-level state id; this is never a reversible observation cluster.
    #[must_use]
    pub fn coarsened_route_cluster(route: &RouteTemplate) -> StateClusterId {
        let bytes = Digest::of("crawlx/coarsened-route-cluster/v1", route.0.as_bytes()).truncate16();
        StateClusterId(uuid::Uuid::from_bytes(bytes))
    }

    /// Whether the key explicitly uses the reserved route-level cluster.
    #[must_use]
    pub fn is_coarsened(&self) -> bool {
        self.state_cluster == self.coarsened_cluster()
    }

    /// Deterministic 16-byte id: BLAKE3 over domain-tagged canonical bytes.
    /// The encoding is length-prefixed so it is injective over the fields.
    #[must_use]
    pub fn id(&self) -> ActionContextId {
        let mut buf = Vec::with_capacity(160);
        push_field(&mut buf, self.principal.0.as_bytes());
        push_field(&mut buf, self.route_template.0.as_bytes());
        push_field(&mut buf, &self.element.0 .0);
        push_field(&mut buf, self.action_kind.as_str().as_bytes());
        push_field(&mut buf, self.input_class.0.as_bytes());
        push_field(&mut buf, self.resource_context.as_str().as_bytes());
        push_field(&mut buf, self.state_cluster.0.as_bytes());
        ActionContextId(Digest::of(Self::DOMAIN, &buf).truncate16())
    }

    /// Domain-separation tag of [`Self::family_id`].
    pub const FAMILY_DOMAIN: &'static str = "crawlx/action-family/v1";

    /// The key's id without its state cluster: one id for the same action (principal, route
    /// template, element, kind, input class, resource context) in every cluster. The
    /// enablement graph pools edge evidence over a family to generalize a route-level edge;
    /// it is never a coverage key.
    #[must_use]
    pub fn family_id(&self) -> ActionContextId {
        let mut buf = Vec::with_capacity(144);
        push_field(&mut buf, self.principal.0.as_bytes());
        push_field(&mut buf, self.route_template.0.as_bytes());
        push_field(&mut buf, &self.element.0 .0);
        push_field(&mut buf, self.action_kind.as_str().as_bytes());
        push_field(&mut buf, self.input_class.0.as_bytes());
        push_field(&mut buf, self.resource_context.as_str().as_bytes());
        ActionContextId(Digest::of(Self::FAMILY_DOMAIN, &buf).truncate16())
    }
}

fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    // u32 length prefix keeps the encoding injective
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use proptest::prelude::*;

    fn key(p: &str, r: &str, ic: &str) -> ActionContextKey {
        ActionContextKey {
            principal: PrincipalId(p.to_owned()),
            route_template: RouteTemplate(r.to_owned()),
            element: ElementIdentityHash(Digest::of("t", b"btn")),
            action_kind: ActionKind::Click,
            input_class: InputClass(ic.to_owned()),
            resource_context: ResourceContext::Own,
            state_cluster: StateClusterId(uuid::Uuid::nil()),
        }
    }

    const GOLDEN_ACTION_CONTEXT_ID: &str = "9c3e3abf7682386734cddaacab7c5859";

    #[test]
    fn golden_id_is_stable() {
        // Pinned so that any change to the canonical encoding is visible in review.
        let id = key("member", "/invoice/:id", "none").id();
        assert_eq!(id.to_string(), GOLDEN_ACTION_CONTEXT_ID);
    }

    proptest! {
        #[test]
        fn boundary_shift_changes_id(a in "[a-z]{1,8}", b in "[a-z]{1,8}") {
            // moving a character across the principal/route boundary must change the id
            let k1 = key(&a, &b, "none");
            let mut moved_a = a.clone();
            let c = moved_a.pop().map(|c| c.to_string()).unwrap_or_default();
            let k2 = key(&moved_a, &format!("{c}{b}"), "none");
            prop_assert_ne!(k1.id(), k2.id());
        }
    }
}
