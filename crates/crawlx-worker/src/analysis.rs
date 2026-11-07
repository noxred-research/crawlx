//! Off-actor analysis of an immutable observation: masks, fingerprint,
//! cluster attachment and the artifacts that accompany a persisted state; plus the run's
//! split-on-contradiction loop: reliable action outcomes are kept
//! per cluster as evidence, `Splitter::check` is asked after every outcome, and a split is
//! persisted through `StateRepo::apply_split` before the in-memory index applies it.

use crawlx_core::config::{Capture, CaptureMode, ScreenshotMode};
use crawlx_core::observation::{FingerprintInput, ObservationBundle};
use crawlx_core::repo::{
    ArtifactStore, ClusterSplitRecord, NewState, Sensitivity, SplitApplied, SplitMember, SplitSuccessor,
    StateRepo,
};
use crawlx_core::secret::{ArtifactSink, Redacted, Redactor};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{
    ActionContextId, ArtifactRef, Clock, CrawlRunId, SessionId, StateClusterId, StateId, StoreError,
    Timestamp,
};
use crawlx_state::{
    Attachment, ClusterConfig, ClusterIndex, Contradiction, Fingerprinter, MaskBuilder, MaskConfig,
    OutcomeClass, SplitPlan, SplitResult, Splitter, StateProfile,
};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

/// Reliable outcomes kept per cluster as split evidence; the oldest are dropped past this.
pub const MAX_OUTCOMES_PER_CLUSTER: usize = 256;

/// One reliable action outcome: the state the action started from, its context, what it led to.
type Evidence = (StateId, ActionContextId, OutcomeClass);

/// A split this process applied to the store and its index. Sessions re-key their
/// in-memory ledgers from it the way the store re-keyed `action_contexts`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AppliedSplit {
    /// The superseded cluster.
    pub source: StateClusterId,
    /// Version of `source` the split was computed against.
    pub source_version: u32,
    /// Successors in group order (the first took the dominant outcome's members).
    pub successors: Vec<StateClusterId>,
    /// Successor of every moved member state.
    pub members: BTreeMap<StateId, StateClusterId>,
    /// Successor of every action context with before-state evidence in this process: the
    /// successor most of its actions' before-states moved to (ties: the first successor).
    pub contexts: BTreeMap<ActionContextId, StateClusterId>,
    /// The contradiction that justified the split.
    pub evidence: Contradiction,
    /// What the store changed.
    pub applied: SplitApplied,
}

impl AppliedSplit {
    /// Successor an action context keyed to the source moves to (the store's rule: majority
    /// of its actions' before-states; the first successor without evidence).
    #[must_use]
    pub fn successor_of_context(&self, context: ActionContextId) -> StateClusterId {
        self.contexts.get(&context).copied().unwrap_or(self.successors[0])
    }

    /// Successor `state` moved to, if it was a member of the source.
    #[must_use]
    pub fn successor_of_state(&self, state: StateId) -> Option<StateClusterId> {
        self.members.get(&state).copied()
    }
}

/// Mints cluster ids; `primed` ids are handed out first so a split applied to the store can
/// be replayed into the index with the same ids.
struct IdMint {
    primed: VecDeque<StateClusterId>,
    next: Box<dyn FnMut() -> StateClusterId + Send>,
}

impl IdMint {
    fn mint(&mut self) -> StateClusterId {
        self.primed.pop_front().unwrap_or_else(|| (self.next)())
    }
}

struct Inner {
    index: ClusterIndex,
    /// Reliable outcomes of each cluster's members in arrival order, bounded per cluster.
    outcomes: BTreeMap<StateClusterId, Vec<Evidence>>,
    /// `(cluster, version)` pairs whose split the store refused: its membership differs from
    /// this process's view (another worker attached states), never retried at that version.
    refused: BTreeSet<(StateClusterId, u32)>,
    /// Splits applied in this process, in order.
    splits: Vec<Arc<AppliedSplit>>,
}

/// Cluster index shared by every session of a run (state clusters are per run).
#[derive(Clone)]
pub struct RunClusters {
    inner: Arc<Mutex<Inner>>,
    mint: Arc<Mutex<IdMint>>,
    cfg: ClusterConfig,
    splitter: Splitter,
    /// One split at a time per run: the plan, the store transaction and the index update of a
    /// split are serialized across sessions.
    split_gate: Arc<tokio::sync::Mutex<()>>,
}

impl Default for RunClusters {
    fn default() -> Self {
        Self::new()
    }
}

impl RunClusters {
    #[must_use]
    /// New.
    pub fn new() -> Self {
        Self::with_mint(Box::new(StateClusterId::new))
    }

    /// An index whose cluster ids derive from `seed` and the order clusters are created in, so
    /// the same seed over the same observations yields the same ids in every run. Decisions
    /// hash and order by these ids, so random ones would make every run decide differently.
    ///
    /// `salt` keeps ids globally unique when several runs share one store (cluster ids are
    /// primary keys in PostgreSQL); an in-memory run passes an empty salt. Only one process
    /// may mint ids of a run this way: concurrent workers on one run use [`Self::new`].
    #[must_use]
    pub fn seeded(seed: CrawlSeed, salt: &[u8]) -> Self {
        let salt = salt.to_vec();
        let mut ordinal = 0_u64;
        Self::with_mint(Box::new(move || {
            let bytes = seed.derive("state-cluster", &[&salt, &ordinal.to_le_bytes()]);
            ordinal += 1;
            let mut id = [0_u8; 16];
            id.copy_from_slice(&bytes[..16]);
            StateClusterId(uuid::Builder::from_random_bytes(id).into_uuid())
        }))
    }

    fn with_mint(next: Box<dyn FnMut() -> StateClusterId + Send>) -> Self {
        let mint = Arc::new(Mutex::new(IdMint {
            primed: VecDeque::new(),
            next,
        }));
        let source = Arc::clone(&mint);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                index: ClusterIndex::with_id_source(move || source.lock().mint()),
                outcomes: BTreeMap::new(),
                refused: BTreeSet::new(),
                splits: Vec::new(),
            })),
            mint,
            cfg: ClusterConfig::default(),
            splitter: Splitter::default(),
            split_gate: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Register clusters persisted by another worker or an earlier session. Their members are
    /// unknown here, so they attach but never split in this process.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn sync(&self, states: &dyn StateRepo, run: CrawlRunId) -> Result<usize, StoreError> {
        let persisted = states.list_clusters(run).await?;
        let mut inner = self.inner.lock();
        let mut added = 0;
        for (id, signature, size) in persisted {
            if inner.index.get(id).is_none() {
                inner.index.restore(id, 1, signature, size);
                added += 1;
            }
        }
        Ok(added)
    }

    /// Active clusters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().index.active_len()
    }

    #[must_use]
    /// Is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Splits applied in this process after the first `seen`, in order.
    #[must_use]
    pub fn splits_since(&self, seen: usize) -> Vec<Arc<AppliedSplit>> {
        self.inner.lock().splits.get(seen..).unwrap_or_default().to_vec()
    }

    /// Number of splits applied in this process.
    #[must_use]
    pub fn splits_applied(&self) -> usize {
        self.inner.lock().splits.len()
    }

    fn attach(&self, state: StateId, profile: &StateProfile) -> Attachment {
        self.inner.lock().index.attach(state, profile, &self.cfg)
    }

    /// Keep one action outcome as split evidence: the action ran in `context` from `before`,
    /// a member of `cluster` (or of the successor `before` moved to, when `cluster` was split
    /// meanwhile). Unreliable outcomes (settle timeout, late traffic) are never evidence.
    pub fn note_outcome(
        &self,
        before: StateId,
        cluster: StateClusterId,
        context: ActionContextId,
        outcome: &OutcomeClass,
    ) {
        if outcome.unreliable {
            return;
        }
        let mut inner = self.inner.lock();
        let Some(cluster) = Self::holder_of(&inner.index, cluster, before) else {
            return;
        };
        let log = inner.outcomes.entry(cluster).or_default();
        log.push((before, context, outcome.clone()));
        if log.len() > MAX_OUTCOMES_PER_CLUSTER {
            let excess = log.len() - MAX_OUTCOMES_PER_CLUSTER;
            log.drain(..excess);
        }
    }

    /// The active cluster holding `state`, starting from `cluster` and following split
    /// successors; `None` when no active cluster of the chain lists the state.
    fn holder_of(index: &ClusterIndex, cluster: StateClusterId, state: StateId) -> Option<StateClusterId> {
        let c = index.get(cluster)?;
        if c.is_active() {
            return Some(cluster);
        }
        c.superseded_by.iter().copied().find_map(|s| {
            let lists_state = index
                .get(s)
                .is_some_and(|sc| sc.members.iter().any(|m| m.state == state));
            lists_state.then(|| Self::holder_of(index, s, state)).flatten()
        })
    }

    /// Ask the splitter whether the evidence of `cluster` contradicts, and if so apply the
    /// split to the store first (`StateRepo::apply_split`, which re-keys `action_contexts`)
    /// and then to the index with the same successor ids. A refusal by the store
    /// (`Conflict`/`NotFound`: the persisted membership differs from this process's view)
    /// parks the cluster version and returns `None`; any other store error is returned.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn try_split(
        &self,
        states: &dyn StateRepo,
        run: CrawlRunId,
        cluster: StateClusterId,
        now: Timestamp,
    ) -> Result<Option<Arc<AppliedSplit>>, StoreError> {
        let _gate = self.split_gate.lock().await;
        let Some((plan, ids, result)) = self.plan_split(cluster, now) else {
            return Ok(None);
        };
        let record = split_record(run, &plan, &result, now);
        let applied = match states.apply_split(&record).await {
            Ok(applied) => applied,
            Err(e @ (StoreError::Conflict(_) | StoreError::NotFound { .. })) => {
                tracing::warn!(
                    cluster = %plan.source,
                    version = plan.source_version,
                    error = %e,
                    "state cluster split refused by the store; not retried at this version"
                );
                self.inner
                    .lock()
                    .refused
                    .insert((plan.source, plan.source_version));
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let split = self.apply_to_index(&plan, &ids, &result, applied, now);
        tracing::info!(
            cluster = %split.source,
            successors = split.successors.len(),
            memberships_moved = applied.memberships_moved,
            action_contexts_rekeyed = applied.action_contexts_rekeyed,
            context = %split.evidence.action_context,
            "state cluster split"
        );
        Ok(Some(split))
    }

    /// The plan, the successor ids and the materialized result for `cluster`, when its
    /// evidence contradicts and this process knows every member.
    fn plan_split(
        &self,
        cluster: StateClusterId,
        now: Timestamp,
    ) -> Option<(SplitPlan, Vec<StateClusterId>, SplitResult)> {
        let inner = self.inner.lock();
        let c = inner.index.get(cluster)?;
        if !c.is_active()
            || c.members.len() < 2
            || usize::try_from(c.size).ok() != Some(c.members.len())
            || inner.refused.contains(&(cluster, c.version))
        {
            return None;
        }
        let plan = self
            .splitter
            .check(c, inner.outcomes.get(&cluster).map_or(&[][..], Vec::as_slice))?;
        let ids: Vec<StateClusterId> = {
            let mut mint = self.mint.lock();
            plan.groups.iter().map(|_| mint.mint()).collect()
        };
        let mut next = ids.iter().copied();
        let mut take = || next.next().unwrap_or_else(StateClusterId::new);
        let result = Splitter::apply(&plan, &mut take, now);
        Some((plan, ids, result))
    }

    /// Replay the persisted split into the index with the ids the store knows, carry the
    /// evidence over to the successors and record the split for the sessions' ledgers.
    fn apply_to_index(
        &self,
        plan: &SplitPlan,
        ids: &[StateClusterId],
        result: &SplitResult,
        applied: SplitApplied,
        now: Timestamp,
    ) -> Arc<AppliedSplit> {
        let mut inner = self.inner.lock();
        self.mint.lock().primed.extend(ids.iter().copied());
        if let Err(e) = inner.index.split(plan, now) {
            // unreachable under the split gate; the store is the source of truth either way
            tracing::error!(cluster = %plan.source, error = %e, "persisted split not applied to the index");
            self.mint.lock().primed.clear();
        }
        let members: BTreeMap<StateId, StateClusterId> = result
            .superseded
            .iter()
            .map(|m| (m.state, m.to_cluster))
            .collect();
        let successors: Vec<StateClusterId> = result.clusters.iter().map(|c| c.id).collect();
        let mut tally: BTreeMap<ActionContextId, BTreeMap<StateClusterId, u32>> = BTreeMap::new();
        for (state, context, outcome) in inner.outcomes.remove(&plan.source).unwrap_or_default() {
            let Some(to) = members.get(&state).copied() else {
                continue;
            };
            *tally.entry(context).or_default().entry(to).or_insert(0) += 1;
            inner
                .outcomes
                .entry(to)
                .or_default()
                .push((state, context, outcome));
        }
        let contexts = tally
            .into_iter()
            .map(|(context, by_successor)| {
                let mut best = (successors[0], 0_u32);
                for s in &successors {
                    let n = by_successor.get(s).copied().unwrap_or(0);
                    if n > best.1 {
                        best = (*s, n);
                    }
                }
                (context, best.0)
            })
            .collect();
        let split = Arc::new(AppliedSplit {
            source: plan.source,
            source_version: plan.source_version,
            successors,
            members,
            contexts,
            evidence: plan.evidence.clone(),
            applied,
        });
        inner.splits.push(Arc::clone(&split));
        split
    }
}

/// The persisted form of a materialized split.
fn split_record(
    run: CrawlRunId,
    plan: &SplitPlan,
    result: &SplitResult,
    now: Timestamp,
) -> ClusterSplitRecord {
    ClusterSplitRecord {
        run,
        source: plan.source,
        source_version: plan.source_version,
        successors: result
            .clusters
            .iter()
            .map(|c| SplitSuccessor {
                cluster: c.id,
                version: c.version,
                prototype: c.members.first().map_or(StateId(uuid::Uuid::nil()), |m| m.state),
                signature: c.prototype.signature.clone(),
                members: c
                    .members
                    .iter()
                    .map(|m| SplitMember {
                        state: m.state,
                        similarity: m.similarity,
                    })
                    .collect(),
            })
            .collect(),
        decided_at: now,
    }
}

/// Result of analyzing one bundle.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Analyzed {
    /// The state row to persist (`StateRepo::put_state` or the T2 `after_state`).
    pub state: NewState,
    /// Profile.
    pub profile: StateProfile,
    /// Review.
    pub review: bool,
}

impl Analyzed {
    #[must_use]
    /// Cluster.
    pub fn cluster(&self) -> StateClusterId {
        self.state.cluster
    }
}

/// Fingerprints observations of one session against the run's cluster index.
pub struct StateAnalyzer {
    run: CrawlRunId,
    session: SessionId,
    fingerprinter: Fingerprinter,
    masks: MaskConfig,
    clusters: RunClusters,
    artifacts: Arc<dyn ArtifactStore>,
    clock: Arc<dyn Clock>,
    capture: Capture,
    controls: crawlx_core::request_controls::RequestControls,
    captcha_secrets: crawlx_core::captcha::CaptchaSecrets,
}

impl StateAnalyzer {
    #[must_use]
    /// Create an analyzer with the run's resolved controls and dynamic-secret registry.
    pub fn new(
        run: CrawlRunId,
        session: SessionId,
        clusters: RunClusters,
        artifacts: Arc<dyn ArtifactStore>,
        clock: Arc<dyn Clock>,
        capture: Capture,
        secrets: (
            &crawlx_core::request_controls::RequestControls,
            &crawlx_core::captcha::CaptchaSecrets,
        ),
    ) -> Self {
        Self {
            run,
            session,
            fingerprinter: Fingerprinter::default(),
            masks: MaskConfig::default(),
            clusters,
            artifacts,
            clock,
            capture,
            controls: secrets.0.clone(),
            captcha_secrets: secrets.1.clone(),
        }
    }

    #[must_use]
    /// Clusters.
    pub fn clusters(&self) -> &RunClusters {
        &self.clusters
    }

    /// Mask, fingerprint, attach to a cluster and store artifacts. Artifact failures are logged
    /// and do not fail the analysis (a state without artifacts is still a state). The
    /// fingerprint and the cluster decision are timed (`fingerprint.duration`,
    /// `cluster.decision.duration`).
    pub async fn analyze(&self, bundle: &ObservationBundle) -> Analyzed {
        let masks = MaskBuilder::build(bundle, &[], &self.masks);
        let metrics = Metrics::global();
        let fingerprint_started = Instant::now();
        let profile = self.fingerprinter.profile(bundle, &masks);
        metrics
            .histogram(names::FINGERPRINT_DURATION)
            .observe_duration(fingerprint_started.elapsed(), &[]);
        let id = StateId::new();
        let decision_started = Instant::now();
        let attachment = self.clusters.attach(id, &profile);
        metrics
            .histogram(names::CLUSTER_DECISION_DURATION)
            .observe_duration(decision_started.elapsed(), &[]);
        let novel = attachment.decision.created_new;
        let artifacts = self.store_artifacts(bundle, novel).await;
        let observed_at = if bundle.captured_at == crawlx_core::Timestamp::default() {
            self.clock.now()
        } else {
            bundle.captured_at
        };
        Analyzed {
            state: NewState {
                id,
                session: self.session,
                epoch: bundle.epoch,
                url: bundle.url.clone(),
                signature: profile.signature.clone(),
                masks,
                cluster: attachment.decision.cluster,
                cluster_similarity: attachment.decision.similarity,
                cluster_is_new: novel,
                artifacts,
                observed_at,
            },
            profile,
            review: attachment.review,
        }
    }

    /// Fold one analysis into the state metrics of `role`: a suspected false merge
    /// (`states.false_merge_suspects`, the attachment's review flag) and the run's current
    /// cluster count (`states.clusters`).
    pub fn record_metrics(&self, analyzed: &Analyzed, role: &str) {
        let metrics = Metrics::global();
        let labels = &[("role", role)];
        if analyzed.review {
            metrics
                .counter(names::STATES_FALSE_MERGE_SUSPECTS)
                .inc_by(1, labels);
        }
        let clusters = u32::try_from(self.clusters.len()).unwrap_or(u32::MAX);
        metrics
            .gauge(names::STATES_CLUSTERS)
            .set(f64::from(clusters), labels);
    }

    async fn store_artifacts(&self, bundle: &ObservationBundle, novel: bool) -> Vec<(String, ArtifactRef)> {
        let want = |mode: CaptureMode| match mode {
            CaptureMode::Off => false,
            CaptureMode::Checkpoint => novel,
            CaptureMode::EveryState => true,
        };
        let mut out = Vec::new();
        let redactor = Redactor::new();
        let approve_raw = |kind: &str, bytes: &[u8]| {
            if kind == "ax_tree" {
                return Err(StoreError::RetentionDenied(
                    "fingerprint input requires typed capture".into(),
                ));
            }
            if kind == "dom_snapshot" {
                let observed = String::from_utf8_lossy(bytes);
                let projected = self.captcha_secrets.redact_if_present(&observed).map_err(|_| {
                    StoreError::RetentionDenied("state artifact secret registry unavailable".into())
                })?;
                let bytes = redactor.scrub_bytes(projected.as_bytes(), self.controls.secret_values());
                return redactor.redact_artifact(bytes.as_ref());
            }
            crate::capture::check_run_secrets(bytes, &self.controls, Some(&self.captcha_secrets))?;
            redactor.verify_binary(bytes)
        };
        let put =
            |kind: &str, content_type: &'static str, approved: Result<Redacted<Vec<u8>>, StoreError>| {
                let artifacts = Arc::clone(&self.artifacts);
                let run = self.run;
                let kind = kind.to_owned();
                async move {
                    let stored = match approved {
                        Ok(bytes) => {
                            ArtifactSink::over(artifacts.as_ref())
                                .put(run, Sensitivity::Sensitive, content_type, &bytes)
                                .await
                        }
                        Err(error) => Err(error),
                    };
                    match stored {
                        Ok(r) => Some((kind, r)),
                        Err(e) => {
                            tracing::warn!(error = %e, %kind, "state artifact not stored");
                            None
                        }
                    }
                }
            };
        if want(self.capture.dom_snapshot) {
            let approved = ax_json(bundle).and_then(|bytes| {
                crate::capture::check_run_secrets(
                    bytes.as_ref(),
                    &self.controls,
                    Some(&self.captcha_secrets),
                )?;
                Ok(bytes)
            });
            out.extend(put("ax_tree", "application/json", approved).await);
            for (kind, bytes) in &bundle.raw_artifacts {
                out.extend(put(kind, "application/octet-stream", approve_raw(kind, bytes)).await);
            }
        }
        let shot = match self.capture.screenshot {
            ScreenshotMode::Off => false,
            ScreenshotMode::OnNovelState => novel,
            ScreenshotMode::EveryState => true,
        };
        if shot {
            if let Some(r) = &bundle.screenshot {
                out.push(("screenshot".to_owned(), r.clone()));
            }
        }
        if let Some(r) = &bundle.dom_snapshot {
            out.push(("dom_snapshot".to_owned(), r.clone()));
        }
        out
    }
}

/// JSON of the `ax_tree` state artifact: the [`FingerprintInput`] the stored signature was
/// computed from (roles, names, geometry, tree links, supplement, frame URLs, network
/// operations); no runtime handles. `crawlx-bench verify-trail` recomputes the signature
/// from it. Unused DOM ancestor text is excluded at the typed capture boundary.
///
/// # Errors
/// Rejects invalid geometry, serialization failures and remaining secrets. No empty or
/// scrubbed-digest fallback is retained when the source cannot be represented faithfully.
pub fn ax_json(bundle: &ObservationBundle) -> Result<Redacted<Vec<u8>>, StoreError> {
    let mut input = FingerprintInput::from_bundle(bundle);
    let mut boxes = input
        .nodes
        .iter()
        .filter_map(|node| node.bbox)
        .chain(input.supplement.values().filter_map(|node| node.bbox));
    if !boxes.all(|bbox| {
        [bbox.x, bbox.y, bbox.width, bbox.height]
            .into_iter()
            .all(f64::is_finite)
    }) {
        return Err(StoreError::RetentionDenied(
            "fingerprint source contains invalid geometry".into(),
        ));
    }
    let redactor = Redactor::new();
    let project_query = |text: &mut String| {
        if let std::borrow::Cow::Owned(projected) = redactor.scrub_session_queries(text) {
            *text = projected;
        }
    };
    // These metadata fields do not enter a fingerprint. Frame hashing ignores queries.
    // Never rewrite AX names, roles, operations, canonical keys or classified view values:
    // if those contain credentials, approval must fail instead of changing the decision.
    for text in input.title.iter_mut().chain(input.frame_urls.iter_mut()) {
        project_query(text);
    }
    for node in &mut input.nodes {
        for text in node
            .description
            .iter_mut()
            .chain(node.value.iter_mut())
            .chain(node.properties.values_mut())
        {
            project_query(text);
        }
    }
    for supplement in input.supplement.values_mut() {
        for text in supplement.attributes.values_mut() {
            project_query(text);
        }
    }
    let bytes = serde_json::to_vec(&input).map_err(|error| StoreError::Serialization(error.to_string()))?;
    redactor.verify_canonical_owned(bytes)
}
