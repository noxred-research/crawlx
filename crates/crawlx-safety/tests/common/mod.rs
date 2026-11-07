//! Shared fixtures for the integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::TimeZone as _;
use crawlx_core::action::{BrowserAction, PointerButton};
use crawlx_core::config::{DestructiveActions, LaunchProfile, SafetyProfile};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::identity::{ActionContextKey, ElementIdentityHash, InputClass, ResourceContext};
use crawlx_core::ids::{BackendNodeId, FixtureFileId, FrameId, PrincipalId, StateClusterId, TabId};
use crawlx_core::observation::{LiveTargetFacts, RuntimeLocator};
use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
use crawlx_core::repo::SafetyContext;
use crawlx_core::safety::RiskClass;
use crawlx_core::time::ManualClock;
use crawlx_core::url::RouteTemplate;
use crawlx_safety::{KernelConfig, SafetyKernel, SinkSpec, TestSinks};
use std::sync::Arc;

pub const SEED: &str = "https://app.example.com";
pub const PAGE: &str = "https://app.example.com/projects";

pub const PROFILES: [SafetyProfile; 3] = [
    SafetyProfile::ReadOnly,
    SafetyProfile::TestEnvironment,
    SafetyProfile::AuthorizedSecurityTest,
];

pub fn locator() -> RuntimeLocator {
    RuntimeLocator {
        tab: TabId("tab-1".into()),
        frame: FrameId("main".into()),
        backend_node_id: BackendNodeId(42),
        object_id: None,
        ax_node_id: None,
        epoch: ObservationEpoch::default(),
    }
}

/// A proposal + context under construction.
#[derive(Clone)]
pub struct Case {
    pub profile: SafetyProfile,
    pub action: BrowserAction,
    pub facts: LiveTargetFacts,
    pub in_scope: bool,
    pub form_hint: Option<String>,
    pub resource: ResourceContext,
    pub hinted: Option<RiskClass>,
    pub input_class: InputClass,
    pub has_sinks: bool,
    pub destructive_ok: bool,
}

impl Case {
    pub fn new(profile: SafetyProfile, action: BrowserAction) -> Self {
        Self {
            profile,
            action,
            facts: LiveTargetFacts {
                current_url: PAGE.into(),
                ..LiveTargetFacts::default()
            },
            in_scope: true,
            form_hint: None,
            resource: ResourceContext::Own,
            hinted: None,
            input_class: InputClass::none(),
            has_sinks: true,
            destructive_ok: true,
        }
    }

    pub fn click(role: &str, name: &str) -> Self {
        let mut c = Self::new(
            SafetyProfile::ReadOnly,
            BrowserAction::Click {
                target: locator(),
                button: PointerButton::Left,
                modifiers: crawlx_core::action::Modifiers::default(),
            },
        );
        c.facts.role = Some(role.into());
        c.facts.name = Some(name.into());
        c
    }

    pub fn hover() -> Self {
        let mut c = Self::new(
            SafetyProfile::ReadOnly,
            BrowserAction::Hover { target: locator() },
        );
        c.facts.role = Some("button".into());
        c.facts.name = Some("Menu".into());
        c
    }

    pub fn upload() -> Self {
        let mut c = Self::new(
            SafetyProfile::ReadOnly,
            BrowserAction::Upload {
                target: locator(),
                fixture: FixtureFileId("avatar.png".into()),
            },
        );
        c.facts.role = Some("button".into());
        c.facts.name = Some("Choose file".into());
        c
    }

    pub fn named(mut self, role: &str, name: &str) -> Self {
        self.facts.role = Some(role.into());
        self.facts.name = Some(name.into());
        self
    }

    pub fn profile(mut self, p: SafetyProfile) -> Self {
        self.profile = p;
        self
    }

    pub fn action(mut self, a: BrowserAction) -> Self {
        self.action = a;
        self
    }

    pub fn href(mut self, h: &str) -> Self {
        self.facts.href = Some(h.into());
        self
    }

    pub fn tag(mut self, t: &str) -> Self {
        self.facts.tag = Some(t.into());
        self
    }

    pub fn attr(mut self, k: &str, v: &str) -> Self {
        self.facts.attributes.insert(k.into(), v.into());
        self
    }

    pub fn url(mut self, u: &str) -> Self {
        self.facts.current_url = u.into();
        self
    }

    pub fn hint(mut self, c: RiskClass) -> Self {
        self.hinted = Some(c);
        self
    }

    pub fn form(mut self, h: &str) -> Self {
        self.form_hint = Some(h.into());
        self
    }

    pub fn resource(mut self, r: ResourceContext) -> Self {
        self.resource = r;
        self
    }

    pub fn input(mut self, kind: &str, partition: &str) -> Self {
        self.input_class = InputClass::new(kind, partition);
        self
    }

    pub fn out_of_scope(mut self) -> Self {
        self.in_scope = false;
        self
    }

    pub fn no_sinks(mut self) -> Self {
        self.has_sinks = false;
        self
    }

    pub fn no_destructive_option(mut self) -> Self {
        self.destructive_ok = false;
        self
    }

    pub fn build(&self) -> (ActionProposal, SafetyContext) {
        let key = ActionContextKey {
            principal: PrincipalId("member".into()),
            route_template: RouteTemplate("/projects".into()),
            element: ElementIdentityHash(Digest::of("t", b"element")),
            action_kind: self.action.kind(),
            input_class: self.input_class.clone(),
            resource_context: self.resource,
            state_cluster: StateClusterId(uuid::Uuid::nil()),
        };
        let proposal = ActionProposal {
            key,
            action: self.action.clone(),
            epoch: ObservationEpoch::default(),
            strategy: "test",
            strategy_version: 1,
            confidence: 0.9,
            expected: ExpectedEffect::default(),
            hinted_risk: self.hinted,
            model_decision: None,
            summary: "test action".into(),
        };
        let ctx = SafetyContext {
            profile: self.profile,
            has_test_sinks: self.has_sinks,
            destructive_approval_allowed: self.destructive_ok,
            principal: PrincipalId("member".into()),
            seed_origin: SEED.into(),
            in_scope: self.in_scope,
            target: self.facts.clone(),
            form_hint: self.form_hint.clone(),
        };
        (proposal, ctx)
    }
}

pub fn config(profile: SafetyProfile) -> KernelConfig {
    KernelConfig {
        profile,
        launch_profile: LaunchProfile::Standard,
        has_test_sinks: true,
        destructive_approval: DestructiveActions::Approval,
        seed_origin: SEED.into(),
        policy_version: 7,
    }
}

pub fn kernel(profile: SafetyProfile) -> SafetyKernel {
    SafetyKernel::new(config(profile))
        .unwrap()
        .with_test_sinks(verified_sinks())
}

pub fn manual_clock() -> ManualClock {
    ManualClock::new(chrono::Utc.with_ymd_and_hms(2026, 5, 1, 8, 0, 0).unwrap())
}

pub fn kernel_with_clock(profile: SafetyProfile, clock: &ManualClock) -> SafetyKernel {
    SafetyKernel::new_with_clock(config(profile), Arc::new(clock.clone()))
        .unwrap()
        .with_test_sinks(verified_sinks())
}

pub fn verified_sinks() -> TestSinks {
    TestSinks {
        email: Some(SinkSpec {
            address: format!("{SEED}/sink"),
            verified_at: Some(chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
            expires_at: chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
        }),
        ..TestSinks::default()
    }
}

/// Classify `case` with the default classifier and return the class.
pub fn class_of(case: &Case) -> RiskClass {
    let (p, c) = case.build();
    crawlx_safety::classify(&p, &c).risk
}
