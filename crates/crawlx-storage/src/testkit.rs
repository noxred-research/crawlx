//! Fixtures for tests of this crate and of downstream crates (scheduler, worker,
//! strategies). Everything here is deterministic apart from fresh UUIDv7 ids.

#[cfg(feature = "fake-kms")]
pub mod fake_kms;
#[cfg(feature = "fake-s3")]
pub mod fake_s3;

use chrono::Utc;
use crawlx_core::action::BrowserAction;
use crawlx_core::counters::{PlaneCounters, RunStatus};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::identity::{ActionContextKey, ActionKind, ElementIdentityHash, InputClass, ResourceContext};
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
use crawlx_core::repo::{CrawlRun, CrawlSession, NewState, SessionStatus};
use crawlx_core::safety::{RiskClass, SafetyDecision, SafetyVerdict};
use crawlx_core::state::{MaskSet, StateSignature};
use crawlx_core::url::{CanonicalUrl, RouteTemplate};
use crawlx_core::{
    CrawlRunId, CreateCrawl, LaunchProfile, PrincipalId, SafetyDecisionId, SessionId, StateClusterId,
    StateId, TenantId,
};

/// Parse `s` as a URL, falling back to `https://example.test/` when it is invalid.
///
/// # Panics
/// Never in practice: the fallback is a valid static literal. This is the single place
/// in the testkit that may panic; the fixture APIs return plain values, not `Result`.
#[allow(
    clippy::expect_used,
    reason = "test fixtures return plain values; the static fallback URL literal is always valid"
)]
fn parse_or_example(s: &str) -> url::Url {
    url::Url::parse(s).unwrap_or_else(|_| url::Url::parse("https://example.test/").expect("static url"))
}

/// A minimal `CreateCrawl` for `seed` with the given roles (empty = anonymous only).
///
/// An unparsable `seed` falls back to `https://example.test/`.
#[must_use]
pub fn create_crawl(seed: &str, roles: &[&str], runs_per_role: u8) -> CreateCrawl {
    let url = parse_or_example(seed);
    let mut cfg = CreateCrawl::new(url);
    cfg.runs_per_role = runs_per_role;
    cfg.roles = roles
        .iter()
        .map(|r| crawlx_core::config::Role {
            name: (*r).to_owned(),
            credential_ref: None,
            login_plan: None,
            replica_base_url: None,
        })
        .collect();
    cfg
}

/// A queued run for `cfg`.
#[must_use]
pub fn crawl_run(tenant: TenantId, cfg: CreateCrawl) -> CrawlRun {
    let config_digest = cfg
        .digest()
        .unwrap_or_else(|_| Digest::of("crawlx/testkit", b"config"));
    CrawlRun {
        id: CrawlRunId::new(),
        tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: cfg.effective_seed(),
        config: cfg,
        config_digest,
        policy_version: 1,
        counters: PlaneCounters::default(),
        // millisecond precision: what PostgreSQL round-trips
        created_at: chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
            .unwrap_or_default(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    }
}

/// Pending sessions for `n_roles × runs` with `schedule_slot = (run_index-1)*n_roles + role_ordinal`.
#[must_use]
pub fn sessions(run: CrawlRunId, n_roles: u16, runs: u16) -> Vec<CrawlSession> {
    let mut out = Vec::new();
    for run_index in 1..=runs {
        for role in 0..n_roles {
            out.push(CrawlSession {
                id: SessionId::new(),
                run,
                role: PrincipalId(format!("role{role}")),
                run_index,
                schedule_slot: u32::from(run_index - 1) * u32::from(n_roles) + u32::from(role),
                status: SessionStatus::Pending,
                browser: None,
                action_seq: 0,
            });
        }
    }
    out
}

/// The build a session records at launch: a pinned `chromium_version` / `cdp_revision` on the
/// standard profile with console capture.
#[must_use]
pub fn browser_build(chromium_version: &str, cdp_revision: &str) -> BrowserBuildInfo {
    BrowserBuildInfo {
        chromium_version: chromium_version.to_owned(),
        cdp_revision: cdp_revision.to_owned(),
        user_agent: "crawlx-test".to_owned(),
        pinned: true,
        launch_profile: LaunchProfile::Standard,
        console_capture: true,
        attached: false,
    }
}

/// Canonical URL for tests (no query classification: `crawlx-url` owns that).
///
/// An unparsable `s` falls back to `https://example.test/`.
#[must_use]
pub fn canonical_url(s: &str) -> CanonicalUrl {
    let url = parse_or_example(s);
    let origin = url.origin().ascii_serialization();
    CanonicalUrl {
        key: Digest::of("crawlx/canonical-url/v1", url.as_str().as_bytes()),
        route_template: RouteTemplate(url.path().to_owned()),
        origin,
        params: Vec::new(),
        url,
    }
}

/// An `allow` verdict with a fresh decision id.
#[must_use]
pub fn allow_verdict() -> SafetyVerdict {
    verdict(SafetyDecision::Allow)
}

/// A verdict with `decision`.
#[must_use]
pub fn verdict(decision: SafetyDecision) -> SafetyVerdict {
    SafetyVerdict {
        decision_id: SafetyDecisionId::new(),
        decision,
        risk_class: RiskClass::NavigationReveal,
        rules: vec!["testkit".to_owned()],
        approval: None,
    }
}

/// A `Navigate` proposal whose context key is unique per `n`.
#[must_use]
pub fn proposal(principal: &str, cluster: StateClusterId, n: u32) -> ActionProposal {
    let key = ActionContextKey {
        principal: PrincipalId(principal.to_owned()),
        route_template: RouteTemplate("/".to_owned()),
        element: ElementIdentityHash(Digest::of("crawlx/testkit/element", &n.to_le_bytes())),
        action_kind: ActionKind::Navigate,
        input_class: InputClass::none(),
        resource_context: ResourceContext::None,
        state_cluster: cluster,
    };
    ActionProposal {
        key,
        action: BrowserAction::Navigate {
            url: parse_or_example("https://example.test/next"),
        },
        epoch: ObservationEpoch {
            navigation_seq: 1,
            document_seq: 1,
            mutation_seq: 0,
        },
        strategy: "interaction_bfs",
        strategy_version: 1,
        confidence: 0.5,
        expected: ExpectedEffect::default(),
        hinted_risk: None,
        model_decision: None,
        summary: format!("testkit proposal {n}"),
    }
}

/// A signature distinguished by `n`.
#[must_use]
pub fn signature(n: u64) -> StateSignature {
    StateSignature {
        version: StateSignature::VERSION,
        route_key: Digest::of("crawlx/testkit/route", &n.to_le_bytes()),
        semantic_affordance_minhash: (0..8).map(|i| n.wrapping_mul(31).wrapping_add(i)).collect(),
        dom_structure_simhash: n.wrapping_mul(0x9e37_79b9_7f4a_7c15),
        visible_element_identity_digest: Digest::of("crawlx/testkit/visible", &n.to_le_bytes()),
        frame_tree_digest: Digest::of("crawlx/testkit/frames", &n.to_le_bytes()),
        network_operation_digest: Digest::of("crawlx/testkit/net", &n.to_le_bytes()),
        visual_phash: Some(n),
        browser_storage_digest: None,
    }
}

/// A new state in `cluster` (`new_cluster` marks it as the cluster prototype).
#[must_use]
pub fn new_state(
    session: SessionId,
    cluster: StateClusterId,
    new_cluster: bool,
    n: u64,
    epoch: ObservationEpoch,
) -> NewState {
    NewState {
        id: StateId::new(),
        session,
        epoch,
        url: canonical_url("https://example.test/page"),
        signature: signature(n),
        masks: MaskSet::default(),
        cluster,
        cluster_similarity: if new_cluster { 1.0 } else { 0.9 },
        cluster_is_new: new_cluster,
        artifacts: Vec::new(),
        // millisecond precision: what PostgreSQL round-trips
        observed_at: chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
            .unwrap_or_default(),
    }
}
