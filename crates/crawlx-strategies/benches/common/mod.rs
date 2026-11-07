//! Fixture shared by the `crawlx-strategies` benches: a 2k-control page built like the
//! crate's test fixture, an allow-all safety gate and a `DecisionContext` over the real
//! discovery and identity pipeline.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::ids::{AxNodeId, BackendNodeId, FrameId, SessionId, TabId};
use crawlx_core::observation::{
    AxNode, BoundingBox, DomNodeSupplement, FrameInfo, LiveTargetFacts, ObservationBundle, RuntimeLocator,
};
use crawlx_core::proposal::ActionProposal;
use crawlx_core::repo::{SafetyContext, SafetyGate};
use crawlx_core::safety::{RiskClass, SafetyDecision, SafetyVerdict};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{PrincipalId, SafetyDecisionId, SafetyProfile, StateClusterId, Timestamp};
use crawlx_elements::{
    CandidateDiscovery, DiscoveryConfig, IdentityResolver, InMemoryIdentityIndex, MatchWeights,
};
use crawlx_graph::EnablementGraph;
use crawlx_strategies::{DecisionContext, DecisionContextBuilder, FrontierStats, LedgerView};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

pub const ORIGIN: &str = "https://app.example";
pub const CANDIDATES: usize = 2_000;

/// Letters for index `i` ("a", "b", ... "z", "ba", ...): identity names strip digits.
pub fn letters(mut i: usize) -> String {
    let mut s = String::new();
    loop {
        s.insert(0, char::from(b'a' + u8::try_from(i % 26).unwrap()));
        i /= 26;
        if i == 0 {
            return s;
        }
    }
}

pub fn locator(backend: i64) -> RuntimeLocator {
    RuntimeLocator {
        tab: TabId("tab".into()),
        frame: FrameId("main".into()),
        backend_node_id: BackendNodeId(backend),
        object_id: None,
        ax_node_id: Some(AxNodeId(format!("ax{backend}"))),
        epoch: ObservationEpoch::default(),
    }
}

pub fn ax(id: i64, parent: Option<i64>, role: &str, name: &str) -> AxNode {
    AxNode {
        locator: locator(id),
        role: role.to_owned(),
        name: (!name.is_empty()).then(|| name.to_owned()),
        description: None,
        value: None,
        ignored: false,
        focusable: false,
        disabled: false,
        expanded: None,
        checked: None,
        properties: BTreeMap::new(),
        parent: parent.map(|p| AxNodeId(format!("ax{p}"))),
        children: Vec::new(),
        bbox: None,
    }
}

/// A page with `n` buttons and links, built like the crate's test fixture.
pub fn bundle(n: usize) -> ObservationBundle {
    let base = url::Url::parse(ORIGIN).unwrap();
    let canonical =
        Canonicalizer::canonicalize(&format!("{ORIGIN}/app"), &base, &CanonicalizeOptions::default())
            .unwrap();
    let mut b = ObservationBundle::empty(SessionId(Uuid::from_u128(7)), TabId("tab".into()), canonical);
    b.captured_at = Timestamp::default();
    b.frames.push(FrameInfo {
        id: FrameId("main".into()),
        parent: None,
        url: format!("{ORIGIN}/app"),
        same_origin: true,
        lineage: Vec::new(),
    });
    let mut nodes: Vec<AxNode> = vec![ax(1, None, "RootWebArea", "App"), ax(2, Some(1), "main", "App")];
    for i in 0..n {
        let id = 10 + 10 * i64::try_from(i).unwrap();
        let (role, tag, attrs): (&str, &str, Vec<(String, String)>) = if i % 3 == 0 {
            ("link", "a", vec![("href".into(), format!("/items/{}", i % 97))])
        } else {
            ("button", "button", vec![("type".into(), "button".into())])
        };
        let mut node = ax(id, Some(2), role, &letters(i));
        node.focusable = true;
        let bbox = BoundingBox {
            x: 20.0,
            y: 100.0 + 40.0 * i as f64,
            width: 120.0,
            height: 32.0,
        };
        node.bbox = Some(bbox);
        nodes.push(node);
        b.dom_supplement.nodes.insert(
            id,
            DomNodeSupplement {
                tag: tag.to_owned(),
                attributes: attrs.into_iter().collect(),
                bbox: Some(bbox),
                ..DomNodeSupplement::default()
            },
        );
    }
    for i in 2..nodes.len() {
        let child = nodes[i].locator.ax_node_id.clone().unwrap();
        nodes[1].children.push(child);
    }
    nodes[0].children.push(AxNodeId("ax2".into()));
    b.ax.nodes = nodes;
    b
}

pub struct AllowAll;

impl SafetyGate for AllowAll {
    fn classify(&self, _p: &ActionProposal, _c: &SafetyContext) -> SafetyVerdict {
        SafetyVerdict {
            decision_id: SafetyDecisionId::new(),
            decision: SafetyDecision::Allow,
            risk_class: RiskClass::NavigationReveal,
            rules: vec!["bench".to_owned()],
            approval: None,
        }
    }
}

pub fn safety_ctx() -> SafetyContext {
    SafetyContext {
        profile: SafetyProfile::ReadOnly,
        has_test_sinks: false,
        destructive_approval_allowed: false,
        principal: PrincipalId("member".into()),
        seed_origin: ORIGIN.to_owned(),
        in_scope: true,
        target: LiveTargetFacts::default(),
        form_hint: None,
    }
}

/// The cluster id every bench context is decided in.
pub fn cluster() -> StateClusterId {
    StateClusterId(Uuid::from_bytes({
        let d = Digest::of("bench/cluster", b"/app");
        let mut b = [0_u8; 16];
        b.copy_from_slice(&d.0[..16]);
        b
    }))
}

pub fn context<'a>(
    bundle: Arc<ObservationBundle>,
    ledger: &'a dyn LedgerView,
    graph: &'a EnablementGraph,
    frontier: &'a FrontierStats,
) -> DecisionContext<'a> {
    let candidates = CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default());
    let resolver = IdentityResolver::with_destination(bundle.url.url.clone(), CanonicalizeOptions::default());
    let mut index = InMemoryIdentityIndex::new();
    let resolved: Vec<_> = candidates
        .iter()
        .map(|c| {
            let r = resolver
                .resolve(&c.descriptor, &index, &MatchWeights::default())
                .unwrap();
            index.record(&r);
            r
        })
        .collect();
    DecisionContextBuilder::new(
        bundle,
        PrincipalId("member".into()),
        cluster(),
        CrawlSeed(42),
        ledger,
        graph,
        frontier,
    )
    .candidates(candidates, resolved)
    .build()
    .unwrap()
}
