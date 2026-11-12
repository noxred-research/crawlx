//! Test fixtures: synthetic bundles built through the real discovery and
//! identity pipeline, a scripted safety gate and a scripted decision engine.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::context::{BudgetView, DecisionContext};
use crate::exploration::{ExplorationConfig, ExplorationState, OutcomeReport, RoundInput};
use crate::frontier::{enumerate_actions, EnumInput};
use crate::switching::Phase;
use async_trait::async_trait;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::ids::{AxNodeId, BackendNodeId, FrameId, SessionId, TabId};
use crawlx_core::observation::{
    AxNode, BoundingBox, DomNodeSupplement, FrameInfo, LiveTargetFacts, ObservationBundle, RuntimeLocator,
};
use crawlx_core::repo::{SafetyContext, SafetyGate};
use crawlx_core::safety::{RiskClass, SafetyDecision, SafetyVerdict};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{
    ActionContextKey, ActionKind, CrawlRunId, ElementIdentityHash, PrincipalId, RouteTemplate,
    SafetyDecisionId, SafetyProfile, StateClusterId, Timestamp, TrustLane,
};
use crawlx_elements::{
    Candidate, CandidateDiscovery, DiscoveryConfig, IdentityResolver, MatchWeights, ResolvedElement,
};
use crawlx_graph::Confounders;
use crawlx_model::typed::{TypedAnswer, TypedDecision, TypedDecisionRequest};
use crawlx_model::{CandidateRef, DecisionEngine, ModelError, ModelId};
use crawlx_safety::{KernelConfig, SafetyKernel};
use crawlx_state::OutcomeClass;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

pub const ORIGIN: &str = "https://app.example";

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

/// One control on a synthetic page.
#[derive(Clone, Debug)]
pub struct Spec {
    role: &'static str,
    name: String,
    tag: &'static str,
    attrs: Vec<(String, String)>,
    container: Option<String>,
    visible: bool,
    dialog: bool,
    cursor: Option<&'static str>,
    listeners: Vec<String>,
}

impl Spec {
    fn base(role: &'static str, name: &str, tag: &'static str, attrs: Vec<(String, String)>) -> Self {
        Self {
            role,
            name: name.to_owned(),
            tag,
            attrs,
            container: None,
            visible: true,
            dialog: false,
            cursor: None,
            listeners: Vec::new(),
        }
    }

    pub fn button(name: &str) -> Self {
        Self::base("button", name, "button", vec![("type".into(), "button".into())])
    }

    pub fn textbox(name: &str, attrs: &[(&str, &str)]) -> Self {
        Self::base(
            "textbox",
            name,
            "input",
            attrs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }

    pub fn checkbox(name: &str) -> Self {
        Self::base(
            "checkbox",
            name,
            "input",
            vec![("type".into(), "checkbox".into())],
        )
    }

    pub fn link(name: &str, href: &str) -> Self {
        Self::base("link", name, "a", vec![("href".into(), href.to_owned())])
    }

    /// A control of an arbitrary ARIA `role` on `tag`, for widgets without a dedicated builder.
    pub fn widget(role: &'static str, name: &str, tag: &'static str, attrs: &[(&str, &str)]) -> Self {
        Self::base(
            role,
            name,
            tag,
            attrs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }

    /// A generic `div` drag handle (`cursor: grab`), as on a kanban board.
    pub fn card(name: &str) -> Self {
        let mut s = Self::base("generic", name, "div", Vec::new());
        s.cursor = Some("grab");
        s
    }

    /// A generic `div` drop zone (`dragover`/`drop` listeners).
    pub fn drop_zone(name: &str) -> Self {
        let mut s = Self::base("generic", name, "div", Vec::new());
        s.listeners = vec!["dragover".into(), "drop".into()];
        s
    }

    pub fn hidden(mut self) -> Self {
        self.visible = false;
        self
    }

    /// Put the control under a named container (a `listitem` with a heading).
    pub fn in_container(mut self, name: &str) -> Self {
        self.container = Some(name.to_owned());
        self
    }

    /// Put the control inside the page's open modal dialog (`role=dialog`, `aria-modal`).
    pub fn in_dialog(mut self) -> Self {
        self.dialog = true;
        self
    }

    /// Add an HTML attribute.
    pub fn attr(mut self, k: &str, v: &str) -> Self {
        self.attrs.push((k.to_owned(), v.to_owned()));
        self
    }
}

fn locator(backend: i64) -> RuntimeLocator {
    RuntimeLocator {
        tab: TabId("tab".into()),
        frame: FrameId("main".into()),
        backend_node_id: BackendNodeId(backend),
        object_id: None,
        ax_node_id: Some(AxNodeId(format!("ax{backend}"))),
        epoch: ObservationEpoch::default(),
    }
}

fn ax(id: i64, parent: Option<i64>, role: &str, name: &str) -> AxNode {
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

/// Build a bundle for `path` on [`ORIGIN`] containing `specs`.
pub fn build_bundle(path: &str, specs: &[Spec], now: Timestamp) -> ObservationBundle {
    let base = url::Url::parse(ORIGIN).unwrap();
    let canonical =
        Canonicalizer::canonicalize(&format!("{ORIGIN}{path}"), &base, &CanonicalizeOptions::default())
            .unwrap();
    let mut b = ObservationBundle::empty(SessionId(Uuid::from_u128(7)), TabId("tab".into()), canonical);
    b.captured_at = now;
    b.frames.push(FrameInfo {
        id: FrameId("main".into()),
        parent: None,
        url: format!("{ORIGIN}{path}"),
        same_origin: true,
        lineage: Vec::new(),
    });
    let mut nodes: Vec<AxNode> = vec![ax(1, None, "RootWebArea", "App"), ax(2, Some(1), "main", "App")];
    if specs.iter().any(|s| s.dialog) {
        let mut d = ax(3, Some(1), "dialog", "Confirm");
        d.properties.insert("modal".into(), "true".into());
        d.bbox = Some(BoundingBox {
            x: 300.0,
            y: 200.0,
            width: 400.0,
            height: 300.0,
        });
        nodes.push(d);
    }
    for (i, s) in specs.iter().enumerate() {
        let base_id = 10 + 10 * i64::try_from(i).unwrap();
        let mut parent = if s.dialog { 3 } else { 2 };
        if let Some(c) = &s.container {
            nodes.push(ax(base_id, Some(parent), "listitem", ""));
            nodes.push(ax(base_id + 1, Some(base_id), "heading", c));
            parent = base_id;
        }
        let id = base_id + 2;
        let mut n = ax(id, Some(parent), s.role, &s.name);
        n.focusable = true;
        let bbox = if s.visible {
            BoundingBox {
                x: 20.0,
                y: 100.0 + 40.0 * i as f64,
                width: 120.0,
                height: 32.0,
            }
        } else {
            BoundingBox::default()
        };
        n.bbox = Some(bbox);
        nodes.push(n);
        let dom = DomNodeSupplement {
            tag: s.tag.to_owned(),
            attributes: s.attrs.iter().cloned().collect(),
            bbox: Some(bbox),
            cursor: s.cursor.map(str::to_owned),
            listeners: s.listeners.clone(),
            ..DomNodeSupplement::default()
        };
        b.dom_supplement.nodes.insert(id, dom);
    }
    // link children to parents
    let ids: Vec<(String, Option<String>)> = nodes
        .iter()
        .map(|n| {
            (
                n.locator.ax_node_id.clone().unwrap().0,
                n.parent.clone().map(|p| p.0),
            )
        })
        .collect();
    for (child, parent) in ids {
        if let Some(p) = parent {
            if let Some(pn) = nodes
                .iter_mut()
                .find(|n| n.locator.ax_node_id.as_ref().unwrap().0 == p)
            {
                pn.children.push(AxNodeId(child));
            }
        }
    }
    b.ax.nodes = nodes;
    b
}

pub fn cluster_n(n: u128) -> StateClusterId {
    StateClusterId(Uuid::from_u128(n))
}

fn cluster_for(path: &str) -> StateClusterId {
    let d = Digest::of("test/cluster", path.as_bytes());
    let mut b = [0_u8; 16];
    b.copy_from_slice(&d.0[..16]);
    StateClusterId(Uuid::from_bytes(b))
}

/// A synthetic app page plus the exploration state that has observed it.
pub struct Fixture {
    pub bundle: ObservationBundle,
    pub candidates: Vec<Candidate>,
    pub resolved: Vec<ResolvedElement>,
    cluster: StateClusterId,
    path: String,
    state: ExplorationState,
    clock_ms: i64,
    names: BTreeMap<ElementIdentityHash, String>,
    after_ingested: bool,
    pub profile: SafetyProfile,
}

impl Fixture {
    pub fn new(specs: &[Spec]) -> Self {
        Self::with_seed(specs, CrawlSeed(42))
    }

    pub fn with_seed(specs: &[Spec], seed: CrawlSeed) -> Self {
        let principal = PrincipalId("member".into());
        let state = ExplorationState::new(
            CrawlRunId(Uuid::from_u128(1)),
            principal,
            seed,
            ExplorationConfig::default(),
        );
        let mut f = Self {
            bundle: build_bundle("/app", &[], Timestamp::default()),
            candidates: Vec::new(),
            resolved: Vec::new(),
            cluster: cluster_for("/app"),
            path: "/app".to_owned(),
            state,
            clock_ms: 1_000,
            names: BTreeMap::new(),
            after_ingested: false,
            profile: SafetyProfile::ReadOnly,
        };
        f.observe_at("/app", specs);
        f
    }

    fn now(&mut self) -> Timestamp {
        self.clock_ms += 1_000;
        Timestamp::from_timestamp_millis(self.clock_ms).unwrap()
    }

    fn discover(
        &self,
        path: &str,
        specs: &[Spec],
        now: Timestamp,
    ) -> (ObservationBundle, Vec<Candidate>, Vec<ResolvedElement>) {
        let bundle = build_bundle(path, specs, now);
        let candidates = CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default());
        let resolver =
            IdentityResolver::with_destination(bundle.url.url.clone(), CanonicalizeOptions::default());
        let resolved = candidates
            .iter()
            .map(|c| {
                resolver
                    .resolve(
                        &c.descriptor,
                        self.state.identity_index(),
                        &MatchWeights::default(),
                    )
                    .unwrap()
            })
            .collect();
        (bundle, candidates, resolved)
    }

    /// Observe `specs` on the current page (same cluster).
    pub fn observe(&mut self, specs: &[Spec]) {
        let path = self.path.clone();
        self.observe_at(&path, specs);
    }

    /// Navigate to `path` (its own cluster) and ingest the observation.
    pub fn observe_at(&mut self, path: &str, specs: &[Spec]) -> StateClusterId {
        let now = self.now();
        let (bundle, candidates, resolved) = self.discover(path, specs, now);
        let cluster = cluster_for(path);
        self.state
            .ingest_observation(&bundle, &candidates, &resolved, cluster, now);
        for (c, r) in candidates.iter().zip(&resolved) {
            self.names
                .entry(r.hash)
                .or_insert_with(|| c.descriptor.accessible_name.clone().unwrap_or_default());
        }
        self.bundle = bundle;
        self.candidates = candidates;
        self.resolved = resolved;
        self.cluster = cluster;
        self.path = path.to_owned();
        cluster
    }

    /// Alias of [`Self::observe_at`]: a page the crawl has seen.
    pub fn add_page(&mut self, path: &str, specs: &[Spec]) -> StateClusterId {
        self.observe_at(path, specs)
    }

    /// Ingest an "opened menu" observation: the current page plus `names`
    /// (never-seen items). The current page stays the fixture's page.
    pub fn reveal_items(&mut self, names: &[&str]) -> Vec<ElementIdentityHash> {
        let now = self.now();
        let mut specs: Vec<Spec> = self
            .candidates
            .iter()
            .map(|c| match c.descriptor.role.as_str() {
                "button" => Spec::button(c.descriptor.accessible_name.as_deref().unwrap_or("")),
                other => panic!("reveal_items supports button pages, got {other}"),
            })
            .collect();
        specs.extend(names.iter().map(|n| Spec::button(n)));
        let (bundle, candidates, resolved) = self.discover(&self.path.clone(), &specs, now);
        let open = self.open_cluster();
        self.state
            .ingest_observation(&bundle, &candidates, &resolved, open, now);
        let mut out = Vec::new();
        for (c, r) in candidates.iter().zip(&resolved) {
            let name = c.descriptor.accessible_name.clone().unwrap_or_default();
            self.names.entry(r.hash).or_insert_with(|| name.clone());
            if names.iter().any(|n| *n == name) {
                out.push(r.hash);
            }
        }
        self.after_ingested = true;
        out
    }

    /// Cluster of the "opened menu" state.
    pub fn open_cluster(&self) -> StateClusterId {
        cluster_n(77)
    }

    pub fn cluster(&self) -> StateClusterId {
        self.cluster
    }

    pub fn cluster_n(&self, n: u128) -> StateClusterId {
        cluster_n(n)
    }

    pub fn route(&self) -> RouteTemplate {
        self.bundle.route.template.clone()
    }

    pub fn state(&self) -> &ExplorationState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut ExplorationState {
        &mut self.state
    }

    /// All keyed actions of the current page.
    pub fn actions(&self) -> Vec<crate::frontier::KeyedAction> {
        enumerate_actions(&EnumInput {
            principal: self.state.principal(),
            route: &self.bundle.route.template,
            cluster: self.cluster,
            profile: self.profile,
            candidates: &self.candidates,
            resolved: &self.resolved,
            include_keys: false,
            modal: crate::frontier::modal_scope(&self.bundle, &self.candidates).as_ref(),
        })
    }

    pub fn index_of(&self, name: &str) -> usize {
        self.candidates
            .iter()
            .position(|c| c.descriptor.accessible_name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("no candidate named {name}"))
    }

    pub fn name_of(&self, h: &ElementIdentityHash) -> String {
        self.names.get(h).cloned().unwrap_or_default()
    }

    /// The key of `name`'s `kind` action on the current page.
    pub fn key(&self, name: &str, kind: ActionKind) -> ActionContextKey {
        let idx = self.index_of(name);
        self.actions()
            .into_iter()
            .find(|a| a.candidate == idx && a.key.action_kind == kind)
            .unwrap_or_else(|| panic!("no {kind:?} action for {name}"))
            .key
    }

    pub fn ctx(&self) -> DecisionContext<'_> {
        self.ctx_with(Phase::Greedy, BudgetView::default())
    }

    pub fn ctx_with_phase(&self, phase: Phase) -> DecisionContext<'_> {
        self.ctx_with(phase, BudgetView::default())
    }

    pub fn ctx_with(&self, phase: Phase, budget: BudgetView) -> DecisionContext<'_> {
        self.state
            .context(
                RoundInput::new(
                    Arc::new(self.bundle.clone()),
                    self.candidates.clone(),
                    self.resolved.clone(),
                    self.cluster,
                    0,
                    self.profile,
                    budget,
                    self.bundle.captured_at,
                )
                .with_phase(phase),
            )
            .unwrap()
    }

    /// Execute `key` as the trusted/diagnostic lane reports it: the after
    /// observation (current page, or the one `reveal_items` ingested) lands in
    /// `after`, then the outcome is ingested.
    pub fn exec(
        &mut self,
        key: &ActionContextKey,
        after: StateClusterId,
        revealed: &[ElementIdentityHash],
        lane: TrustLane,
    ) {
        let now = self.now();
        if !std::mem::take(&mut self.after_ingested) {
            let (b, c, r) = (
                self.bundle.clone(),
                self.candidates.clone(),
                self.resolved.clone(),
            );
            self.state.ingest_observation(&b, &c, &r, after, now);
        }
        self.state.ingest_outcome(&OutcomeReport {
            key: key.clone(),
            outcome: OutcomeClass {
                after_route_template: self.bundle.route.template.clone(),
                after_cluster_family: None,
                network_operation_digest: None,
                status_class: 2,
                unreliable: false,
            },
            lane,
            succeeded: true,
            before: key.state_cluster,
            after,
            revealed: revealed.to_vec(),
            baseline_revealed: Vec::new(),
            confounders: Confounders::default(),
            new_operation: false,
            now,
        });
    }

    /// Record a trusted/diagnostic execution without touching the observation.
    pub fn exercise(&mut self, key: &ActionContextKey, lane: TrustLane) {
        let cluster = self.cluster;
        self.exec(key, cluster, &[], lane);
    }

    pub fn mark_risk(&mut self, key: &ActionContextKey, risk: RiskClass) {
        let frontier = self.state.frontier_mut();
        frontier.risk.insert(key.id(), risk);
        frontier.element_risk.insert((key.element, key.action_kind), risk);
    }

    pub fn clear_risk(&mut self) {
        let frontier = self.state.frontier_mut();
        frontier.risk.clear();
        frontier.element_risk.clear();
    }

    pub fn block(&mut self, key: &ActionContextKey) {
        self.state.mark_blocked(key.id());
    }

    pub fn mark_url_visited(&mut self, url: &str) {
        self.state.frontier_mut().visited_urls.insert(url.to_owned());
    }

    pub fn set_paper_compat(&mut self) {
        self.state.frontier_mut().cfg.paper_compat = true;
    }

    pub fn safety_ctx(&self) -> SafetyContext {
        SafetyContext {
            profile: SafetyProfile::ReadOnly,
            has_test_sinks: false,
            destructive_approval_allowed: false,
            principal: self.state.principal().clone(),
            seed_origin: ORIGIN.to_owned(),
            in_scope: true,
            target: LiveTargetFacts::default(),
            form_hint: None,
        }
    }

    pub fn kernel(&self) -> SafetyKernel {
        SafetyKernel::new(KernelConfig {
            profile: SafetyProfile::ReadOnly,
            launch_profile: crawlx_core::LaunchProfile::Standard,
            has_test_sinks: false,
            destructive_approval: crawlx_core::config::DestructiveActions::Deny,
            seed_origin: ORIGIN.to_owned(),
            policy_version: 1,
        })
        .unwrap()
    }
}

/// A safety gate with scripted per-element decisions and risk classes.
pub struct ScriptedGate {
    decisions: BTreeMap<ElementIdentityHash, SafetyDecision>,
    risks: BTreeMap<ElementIdentityHash, RiskClass>,
    calls: AtomicUsize,
}

impl ScriptedGate {
    pub fn allow_all() -> Self {
        Self {
            decisions: BTreeMap::new(),
            risks: BTreeMap::new(),
            calls: AtomicUsize::new(0),
        }
    }

    pub fn with_decision(mut self, e: ElementIdentityHash, d: SafetyDecision) -> Self {
        self.decisions.insert(e, d);
        self
    }

    pub fn with_risk(mut self, e: ElementIdentityHash, r: RiskClass) -> Self {
        self.risks.insert(e, r);
        self
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SafetyGate for ScriptedGate {
    fn classify(&self, p: &crawlx_core::ActionProposal, _c: &SafetyContext) -> SafetyVerdict {
        self.calls.fetch_add(1, Ordering::SeqCst);
        SafetyVerdict {
            decision_id: SafetyDecisionId::new(),
            decision: self
                .decisions
                .get(&p.key.element)
                .copied()
                .unwrap_or(SafetyDecision::Allow),
            risk_class: self
                .risks
                .get(&p.key.element)
                .copied()
                .unwrap_or(RiskClass::NavigationReveal),
            rules: vec!["scripted".to_owned()],
            approval: None,
        }
    }
}

/// A decision engine that answers `next_action` with scripted probabilities.
pub struct ProbEngine {
    favourite: Option<(usize, f32)>,
    model: ModelId,
    seen: Arc<Mutex<Vec<TypedDecisionRequest>>>,
}

impl ProbEngine {
    pub fn favouring(index: usize, p: f32) -> Self {
        Self {
            favourite: Some((index, p)),
            model: ModelId::new("test", "prob", "digest", "cal1"),
            seen: Arc::default(),
        }
    }

    pub fn uniform() -> Self {
        Self {
            favourite: None,
            model: ModelId::new("test", "prob", "digest", "cal1"),
            seen: Arc::default(),
        }
    }

    pub fn requests(&self) -> Vec<TypedDecisionRequest> {
        self.seen.lock().clone()
    }
}

#[async_trait]
impl DecisionEngine for ProbEngine {
    async fn decide(&self, req: TypedDecisionRequest) -> Result<TypedDecision, ModelError> {
        self.seen.lock().push(req.clone());
        let n = req.state.value().candidates.len();
        let probs: Vec<f32> = match self.favourite {
            Some((i, p)) if n > 1 && i < n => (0..n)
                .map(|j| if j == i { p } else { (1.0 - p) / (n as f32 - 1.0) })
                .collect(),
            _ => vec![1.0 / n as f32; n],
        };
        let answers = req
            .questions
            .iter()
            .map(|q| TypedAnswer::Choice {
                id: q.id().to_owned(),
                probs: probs
                    .iter()
                    .enumerate()
                    .map(|(i, p)| (CandidateRef(u32::try_from(i).unwrap()), *p))
                    .collect(),
                none_p: 0.0,
                selected: None,
            })
            .collect();
        Ok(TypedDecision {
            answers,
            abstained: Vec::new(),
            latency_ms: 1,
            model: self.model.clone(),
        })
    }

    fn id(&self) -> &ModelId {
        &self.model
    }
}
