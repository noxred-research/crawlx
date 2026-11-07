//! A self-contained exploration driver for ablation baselines (A1–A7).
//!
//! The driver programs against `BrowserBackend`, so the same loop runs over
//! `crawlx_browser::FakeBackend` (deterministic, no browser) and `ChromiumBackend` (real
//! gym pages). Its policy is the paper's layered queue `Score(e) = W + 0.3·Z + E`
//! ([`crate::policy`]) plus a document-order frontier for the
//! discovery-only variants and a recorded-reachability bonus for the graph variant.
//! Variants that need forms, phase-2 pathfinding, the model cascade or several roles run
//! through the worker instead (`crawlx_worker`), never through this driver.
//!
//! The driver has no safety kernel. It therefore refuses fixtures that declare forbidden
//! backend effects (`g25`, `a2`, ...); those belong to the safety suites.
//!
//! Every decision is recorded as a [`TraceStep`], so any run can be replayed offline with
//! [`crate::replay::ReplayHarness`].

use crate::ablation::AblationVariant;
use crate::error::BenchError;
use crate::gym::manifest::{FixtureManifest, Mechanism};
use crate::policy::{Cand, PolicyState};
use crate::replay::{Outcome, Snapshot, SnapshotControl, Trace, TraceStep, TRACE_VERSION};
use crate::scorecard::{DiscoveredTarget, RunRows};
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::browser::{BrowserBackend, BrowserContext, ContextConfig};
use crawlx_core::config::SafetyProfile;
use crawlx_core::counters::ActionStatus;
use crawlx_core::hash::Digest;
use crawlx_core::identity::{ActionContextKey, ActionKind, ElementIdentityHash, InputClass, ResourceContext};
use crawlx_core::ids::{ActionId, CrawlRunId, PrincipalId, SafetyDecisionId, SessionId, StateClusterId};
use crawlx_core::observation::{ObservationSpec, QuiescencePolicy, Revalidation, RuntimeLocator};
use crawlx_core::repo::ActionRecord;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::time::{Clock, SystemClock};
use crawlx_core::BrowserError;
use crawlx_elements::{CandidateDiscovery, DiscoveryConfig, IdentityBuilder, Rung};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::collections::{BTreeMap, BTreeSet};

/// Driver limits.
#[derive(Clone, Debug)]
pub struct DriverConfig {
    /// Upper bound on performed actions.
    pub max_actions: usize,
    /// An identity is exercised at most this many times (`W` layer cap); 1 means once each.
    pub max_layer: u32,
    /// Quiescence policy applied after every action and navigation before observing again.
    pub settle: QuiescencePolicy,
    /// Loopback egress proxy port for real-browser runs.
    pub egress_proxy_port: Option<u16>,
    /// Allow fixtures with `forbidden_ops` (only with an external safety gate in front).
    pub allow_unsafe_fixtures: bool,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            max_actions: 80,
            max_layer: 1,
            settle: QuiescencePolicy::default(),
            egress_proxy_port: None,
            allow_unsafe_fixtures: false,
        }
    }
}

const fn mechanism_of(r: Rung) -> Mechanism {
    match r {
        Rung::Ax | Rung::Native => Mechanism::Ax,
        Rung::FocusCursor => Mechanism::Cursor,
        Rung::Listener => Mechanism::Listener,
    }
}

/// Deterministic cluster id for a route (the driver has no state clustering).
pub(crate) fn cluster_of(route: &str) -> StateClusterId {
    let d = Digest::of("crawlx/bench/driver-cluster", route.as_bytes());
    StateClusterId::from(uuid::Uuid::from_bytes(d.truncate16()))
}

struct Page {
    cands: Vec<Cand<RuntimeLocator>>,
    meta: Vec<CandMeta>,
    url: String,
    title: Option<String>,
    route_template: crawlx_core::url::RouteTemplate,
    cluster: StateClusterId,
}

/// Per-candidate facts the trace and the action rows need.
struct CandMeta {
    context_id: String,
    role: String,
    name: Option<String>,
}

/// Mutable run state threaded through [`observe`].
struct Seen {
    ever: BTreeSet<ElementIdentityHash>,
    labels: BTreeMap<ElementIdentityHash, Option<String>>,
    unsupported: BTreeSet<String>,
}

/// Run one variant over the fixture entry page and return the rows a scorecard needs.
///
/// # Errors
/// Unsupported variant/fixture combinations ([`BenchError::Ablation`]) and browser failures.
pub async fn run_variant(
    backend: &dyn BrowserBackend,
    variant: &AblationVariant,
    manifest: &FixtureManifest,
    base_url: &str,
    seed: u64,
    cfg: &DriverConfig,
) -> Result<RunRows, BenchError> {
    run_variant_traced(backend, variant, manifest, base_url, seed, cfg)
        .await
        .map(|(rows, _)| rows)
}

/// As [`run_variant`], also returning the recorded decision trace.
///
/// # Errors
/// See [`run_variant`].
pub async fn run_variant_traced(
    backend: &dyn BrowserBackend,
    variant: &AblationVariant,
    manifest: &FixtureManifest,
    base_url: &str,
    seed: u64,
    cfg: &DriverConfig,
) -> Result<(RunRows, Trace), BenchError> {
    if let Some(unsupported) = variant.needs_worker() {
        return Err(BenchError::Ablation(format!(
            "variant {} needs {unsupported}; run it through crawlx_worker",
            variant.id
        )));
    }
    if !variant.browser {
        return Err(BenchError::Ablation(format!(
            "variant {} is URL-plane only; it has no browser driver",
            variant.id
        )));
    }
    if !cfg.allow_unsafe_fixtures && !manifest.expected.forbidden_ops.is_empty() {
        return Err(BenchError::Ablation(format!(
            "fixture {} declares forbidden backend effects and the driver has no safety kernel",
            manifest.id
        )));
    }

    // DOM id -> (control id, logical id). Selectors of the form `#<id>` match the `id` attribute.
    let by_dom_id: BTreeMap<&str, (&str, &str)> = manifest
        .controls
        .iter()
        .filter_map(|c| {
            c.selector.strip_prefix('#').map(|id| {
                (
                    id,
                    (c.id.as_str(), c.logical_id.as_deref().unwrap_or(c.id.as_str())),
                )
            })
        })
        .collect();
    let crawl_seed = CrawlSeed(seed);
    let clock = SystemClock;
    let entry = url::Url::parse(&manifest.entry_url(base_url))?;
    let entry = Canonicalizer::canonicalize_url(&entry, &CanonicalizeOptions::default())?;

    let mut ctx_cfg = ContextConfig::new(SessionId::new());
    ctx_cfg.egress_proxy_port = cfg.egress_proxy_port;
    let session = ctx_cfg.session_id;
    let mut ctx = backend.new_context(ctx_cfg).await?;
    ctx.navigate(&entry).await?;

    let run = CrawlRunId::new();
    let mut rows = RunRows::new(&manifest.id, seed, variant.id, SafetyProfile::ReadOnly);
    let mut trace = Trace {
        version: TRACE_VERSION,
        fixture: manifest.id.clone(),
        seed,
        variant: variant.id.to_owned(),
        steps: Vec::new(),
    };
    let mut policy = PolicyState::default();
    let flags = variant.policy_flags();
    let mut seen = Seen {
        ever: BTreeSet::new(),
        labels: BTreeMap::new(),
        unsupported: BTreeSet::new(),
    };
    let discovery_cfg = DiscoveryConfig {
        max_rung: variant.max_rung(),
        ..DiscoveryConfig::default()
    };

    let mut page = observe(
        ctx.as_mut(),
        &discovery_cfg,
        variant,
        &by_dom_id,
        &mut rows,
        &mut seen,
    )
    .await?;

    for step in 0..cfg.max_actions {
        let ranked = policy.rank(flags, &page.cands, crawl_seed, cfg.max_layer);
        let Some(pick) = ranked.first().copied() else {
            break;
        };
        let pick_index = pick.order;
        let pick = pick.clone();
        rows.proposals.total += 1;
        let epoch = ctx.current_epoch();
        match ctx.revalidate(&pick.locator, epoch).await? {
            Revalidation::Actionable { .. } => {}
            Revalidation::StaleEpoch { .. } | Revalidation::Detached | Revalidation::IdentityChanged => {
                rows.proposals.stale_dropped += 1;
                page = observe(
                    ctx.as_mut(),
                    &discovery_cfg,
                    variant,
                    &by_dom_id,
                    &mut rows,
                    &mut seen,
                )
                .await?;
                continue;
            }
            Revalidation::NotVisible
            | Revalidation::Disabled
            | Revalidation::Obscured { .. }
            | Revalidation::Unstable => {
                policy.mark_unavailable(pick.hash);
                continue;
            }
        }
        let before: BTreeSet<ElementIdentityHash> = page.cands.iter().map(|c| c.hash).collect();
        let seen_before = seen.ever.clone();
        let snapshot = Snapshot {
            url: page.url.clone(),
            title: page.title.clone(),
            controls: page
                .cands
                .iter()
                .zip(&page.meta)
                .map(|(c, m)| SnapshotControl {
                    context_id: m.context_id.clone(),
                    identity: c.hash.0.to_hex(),
                    family: c.family.clone(),
                    control: c.label.clone(),
                    role: m.role.clone(),
                    name: m.name.clone(),
                })
                .collect(),
        };
        let chosen_ctx = page.meta[pick_index].context_id.clone();
        let proposed_at = clock.now();
        let receipt = match ctx
            .perform(BrowserAction::Click {
                target: pick.locator.clone(),
                button: PointerButton::Left,
                modifiers: Modifiers::default(),
            })
            .await
        {
            Ok(r) => r,
            Err(BrowserError::StaleLocator(_)) => {
                rows.proposals.stale_dropped += 1;
                page = observe(
                    ctx.as_mut(),
                    &discovery_cfg,
                    variant,
                    &by_dom_id,
                    &mut rows,
                    &mut seen,
                )
                .await?;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        rows.settles.push(ctx.settle(cfg.settle).await?);
        rows.actions.push(ActionRecord {
            id: ActionId::new(),
            run,
            session,
            seq: step as u64 + 1,
            key: ActionContextKey {
                principal: PrincipalId::anonymous(),
                route_template: page.route_template.clone(),
                element: pick.hash,
                action_kind: ActionKind::Click,
                input_class: InputClass::none(),
                resource_context: ResourceContext::None,
                state_cluster: page.cluster,
            },
            status: ActionStatus::Succeeded,
            attempt: 1,
            strategy: "gym-baseline".to_owned(),
            strategy_version: 1,
            epoch,
            lane: Some(receipt.lane),
            fidelity: Some(receipt.fidelity),
            safety_decision: SafetyDecisionId::new(),
            model_decision: None,
            before_state: None,
            reconcile_resolution: None,
            proposed_at,
            intended_at: Some(proposed_at),
            finished_at: Some(clock.now()),
            trace_id: None,
        });

        page = observe(
            ctx.as_mut(),
            &discovery_cfg,
            variant,
            &by_dom_id,
            &mut rows,
            &mut seen,
        )
        .await?;

        // Novel reveal episode: a never-before-seen identity appeared that was absent before.
        let novel: Vec<ElementIdentityHash> = page
            .cands
            .iter()
            .map(|c| c.hash)
            .filter(|h| !before.contains(h) && !seen_before.contains(h))
            .collect();
        policy.record(pick.hash, &pick.family, &novel);
        if let Some(src) = &pick.label {
            for n in &novel {
                if let Some(Some(dst)) = seen.labels.get(n) {
                    rows.recorded_edges.push((src.clone(), dst.clone()));
                }
            }
        }

        trace.steps.push(TraceStep {
            snapshot,
            chosen: chosen_ctx,
            outcome: Outcome {
                succeeded: true,
                revealed: novel.iter().map(|h| h.0.to_hex()).collect(),
                lane: receipt.lane,
            },
        });
    }

    rows.unsupported_reported = seen.unsupported.into_iter().collect();
    ctx.close().await?;
    Ok((rows, trace))
}

async fn observe(
    ctx: &mut dyn BrowserContext,
    discovery_cfg: &DiscoveryConfig,
    variant: &AblationVariant,
    by_dom_id: &BTreeMap<&str, (&str, &str)>,
    rows: &mut RunRows,
    seen: &mut Seen,
) -> Result<Page, BenchError> {
    let canon = CanonicalizeOptions::default();
    let label_of = |attrs: &BTreeMap<String, String>| {
        attrs
            .get("id")
            .and_then(|id| by_dom_id.get(id.as_str()))
            .map(|(c, l)| ((*c).to_owned(), (*l).to_owned()))
    };
    let bundle = ctx.observe(ObservationSpec::default()).await?;
    let discovery = CandidateDiscovery::discover_report(&bundle, discovery_cfg);
    for u in &discovery.unsupported {
        if let Some((id, _)) = bundle
            .dom_supplement
            .nodes
            .get(&u.locator.backend_node_id.0)
            .and_then(|n| label_of(&n.attributes))
        {
            seen.unsupported.insert(id);
        }
    }
    let route = bundle.url.url.path().to_owned();
    let cluster = cluster_of(&route);
    let mut cands = Vec::new();
    let mut meta = Vec::new();
    for c in &discovery.candidates {
        if !c.evidence.visible || !c.evidence.enabled {
            continue;
        }
        let destination = IdentityBuilder::destination_key(&c.descriptor, &bundle.url.url, &canon);
        let mut identity = IdentityBuilder::build(&c.descriptor, destination);
        if !variant.identity_container {
            identity.container_signature = None;
        }
        let hash = IdentityBuilder::hash(&identity)?;
        // Template instances share one identity; the baseline policy tells siblings
        // apart by their document-order ordinal, so it selects on the instance hash.
        let mut instance_input = hash.0 .0.to_vec();
        instance_input.extend_from_slice(&c.descriptor.instance_ordinal.to_le_bytes());
        let inst = ElementIdentityHash(Digest::of("crawlx/bench/instance", &instance_input));
        let (label, logical) = label_of(&c.descriptor.attributes).unzip();
        if let Some(l) = &logical {
            rows.identity_observations.push((hash, l.clone()));
        }
        if seen.ever.insert(inst) {
            seen.labels.insert(inst, label.clone());
            rows.discovered.push(DiscoveredTarget {
                control: label.clone(),
                mechanism: mechanism_of(c.rung),
            });
        }
        let family = format!(
            "{}|{}",
            identity.role,
            identity.stable_ancestor_role_path.join(">")
        );
        let key = ActionContextKey {
            principal: PrincipalId::anonymous(),
            route_template: bundle.url.route_template.clone(),
            element: inst,
            action_kind: ActionKind::Click,
            input_class: InputClass::none(),
            resource_context: ResourceContext::None,
            state_cluster: cluster,
        };
        meta.push(CandMeta {
            context_id: key.id().to_string(),
            role: identity.role.clone(),
            name: c.descriptor.accessible_name.clone(),
        });
        cands.push(Cand {
            hash: inst,
            label,
            family,
            locator: c.descriptor.locator.clone(),
            order: cands.len(),
        });
    }
    Ok(Page {
        cands,
        meta,
        url: bundle.url.url.to_string(),
        title: bundle.title.clone(),
        route_template: bundle.url.route_template.clone(),
        cluster,
    })
}
