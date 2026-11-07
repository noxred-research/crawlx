//! Optional, in-memory evidence of the actions actually sent to the browser.
//! Runtime handles and secret values never enter the evidence. Enable only for bounded
//! benchmark runs; production has no recorder and pays no serialization or allocation cost.

use crawlx_core::action::BrowserAction;
use crawlx_core::hash::Digest;
use crawlx_core::identity::ActionContextKey;
use crawlx_core::observation::{ObservationBundle, RuntimeLocator};
use crawlx_core::{ActionId, SessionId};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// One performed action, without run-specific identifiers or runtime handles.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TraceStep {
    /// Semantic action identity, including its input partition.
    pub key: ActionContextKey,
    /// Digest of actual nonsecret parameters; `None` means evidence was unavailable.
    pub parameters_digest: Option<Digest>,
}

/// Internal journal join for a recorded action.
#[derive(Debug)]
#[non_exhaustive]
pub struct PerformedStep {
    /// Session that sent the action.
    pub session: SessionId,
    /// Journal row whose action was sent.
    pub action: ActionId,
    /// Comparable, secret-free action evidence.
    pub step: TraceStep,
}

/// Opt-in collector. Dropped proposals and denied actions never reach this collector.
#[derive(Default)]
pub struct ActionTrace {
    steps: Mutex<Vec<PerformedStep>>,
}

impl ActionTrace {
    /// Take the bounded benchmark trace in actual perform order without copying it.
    #[must_use]
    pub fn take(&self) -> Vec<PerformedStep> {
        std::mem::take(&mut *self.steps.lock())
    }

    pub(crate) fn record(
        &self,
        session: SessionId,
        action: ActionId,
        key: &ActionContextKey,
        browser_action: &BrowserAction,
        observed: Option<&ObservationBundle>,
    ) {
        let parameters_digest = parameter_digest(browser_action, observed);
        self.steps.lock().push(PerformedStep {
            session,
            action,
            step: TraceStep {
                key: key.clone(),
                parameters_digest,
            },
        });
    }
}

fn parameter_digest(action: &BrowserAction, observed: Option<&ObservationBundle>) -> Option<Digest> {
    // Never serialize runtime locators. The semantic source is in TraceStep::key;
    // secondary nodes and tabs use their position in the recorded observation.
    let node = |target: &RuntimeLocator| {
        observed?.ax.nodes.iter().position(|node| {
            node.locator.tab == target.tab
                && node.locator.frame == target.frame
                && node.locator.backend_node_id == target.backend_node_id
        })
    };
    let tab = |target: &crawlx_core::TabId| observed?.tabs.iter().position(|tab| &tab.id == target);
    let kind = action.kind();
    match action {
        BrowserAction::Click {
            button, modifiers, ..
        } => digest_parameters(kind, &(button, modifiers)),
        BrowserAction::Type {
            value, clear_first, ..
        } => digest_parameters(kind, &(value.plain()?, clear_first)),
        BrowserAction::Select { options, .. } => digest_parameters(kind, options),
        BrowserAction::SetChecked { checked, .. } => digest_parameters(kind, checked),
        BrowserAction::SetRange { value, .. } if value.is_finite() => digest_parameters(kind, value),
        BrowserAction::SetRange { .. } => None,
        BrowserAction::Drag { destination, .. } => digest_parameters(kind, &node(destination)?),
        BrowserAction::Upload { fixture, .. } => digest_parameters(kind, fixture),
        BrowserAction::Scroll { container, delta } => {
            if !delta.dx.is_finite() || !delta.dy.is_finite() {
                return None;
            }
            let container = match container {
                Some(target) => Some(node(target)?),
                None => None,
            };
            digest_parameters(kind, &(container, delta))
        }
        BrowserAction::Keys { sequence } => digest_parameters(kind, sequence),
        BrowserAction::Navigate { url } => digest_parameters(kind, url),
        BrowserAction::SwitchTab { tab: target } | BrowserAction::CloseTab { tab: target } => {
            digest_parameters(kind, &tab(target)?)
        }
        BrowserAction::KeyboardActivate { .. }
        | BrowserAction::Hover { .. }
        | BrowserAction::SyntheticClick { .. }
        | BrowserAction::SolveCaptcha => digest_parameters(kind, &()),
    }
}

fn digest_parameters<T: Serialize + ?Sized>(
    kind: crawlx_core::identity::ActionKind,
    parameters: &T,
) -> Option<Digest> {
    serde_json::to_vec(&(kind, parameters))
        .ok()
        .map(|bytes| Digest::of("crawlx/performed-action-parameters/v1", &bytes))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::action::{KeyChord, Modifiers};

    #[test]
    fn actual_values_and_order_are_not_replaced_by_control_set_equality() {
        let keys = |key: &str| BrowserAction::Keys {
            sequence: vec![KeyChord {
                key: key.to_owned(),
                modifiers: Modifiers::default(),
            }],
        };
        assert_ne!(
            parameter_digest(&keys("a"), None),
            parameter_digest(&keys("b"), None)
        );
        let a = parameter_digest(&keys("a"), None);
        let b = parameter_digest(&keys("b"), None);
        assert_ne!(vec![a, b], vec![b, a]);
    }

    #[test]
    fn plain_values_are_hashed_and_secret_values_are_never_evidence() {
        use crawlx_core::{BackendNodeId, FrameId, ObservationEpoch, SecretOr, TabId};
        let target = RuntimeLocator {
            tab: TabId("runtime-tab-canary".to_owned()),
            frame: FrameId("runtime-frame-canary".to_owned()),
            backend_node_id: BackendNodeId(1),
            object_id: None,
            ax_node_id: None,
            epoch: ObservationEpoch::default(),
        };
        let plain = BrowserAction::Type {
            target: target.clone(),
            value: SecretOr::Plain("typed-value-canary".to_owned()),
            clear_first: true,
        };
        let digest = parameter_digest(&plain, None).unwrap();
        let evidence = serde_json::to_string(&digest).unwrap();
        assert!(!evidence.contains("typed-value-canary"));
        assert!(!evidence.contains("runtime-tab-canary"));
        let secret = BrowserAction::Type {
            target,
            value: SecretOr::secret("credential-canary".to_owned()),
            clear_first: true,
        };
        assert!(parameter_digest(&secret, None).is_none());
        let BrowserAction::Type { value, .. } = &secret else {
            unreachable!()
        };
        assert_eq!(
            value.expose(),
            "credential-canary",
            "recording must not mutate browser input"
        );
    }
}
