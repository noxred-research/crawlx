//! Split on contradiction.
//!
//! When members of one cluster respond to the *same* action context with
//! different outcomes, the cluster merged states that behave differently. The
//! plan partitions the members into two new cluster versions and supersedes
//! the old memberships. Raw `states` are never rewritten, so a split is
//! reversible and the evidence stays queryable.

use crate::cluster::{score, Cluster, Member, Prototype};
use crate::minhash::union_into;
use crawlx_core::hash::Digest;
use crawlx_core::url::RouteTemplate;
use crawlx_core::{ActionContextId, StateClusterId, StateId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What an action led to. Ordered so ties between equally
/// frequent outcomes break deterministically.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct OutcomeClass {
    /// Route template of the page the action landed on.
    pub after_route_template: RouteTemplate,
    /// Cluster family of the resulting state, when known.
    pub after_cluster_family: Option<StateClusterId>,
    /// Digest of the network operations the action triggered, when any were observed.
    pub network_operation_digest: Option<Digest>,
    /// HTTP status class of the main operation (2, 3, 4, 5; 0 unknown).
    pub status_class: u8,
    /// Outcome observed with `settle_timeout` or `late` traffic: excluded from counting.
    pub unreliable: bool,
}

/// Split thresholds (planning defaults).
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SplitConfig {
    /// The runner-up outcome must have at least this many observations.
    pub min_second_count: u32,
    /// ...and at least this share of the context's observations.
    pub min_second_fraction: f64,
}

impl Default for SplitConfig {
    fn default() -> Self {
        Self {
            min_second_count: 2,
            min_second_fraction: 0.20,
        }
    }
}

/// The evidence behind a split.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Contradiction {
    /// Action context in which members saw different outcomes.
    pub action_context: ActionContextId,
    /// Most and second-most frequent outcomes with their counts.
    pub outcomes: [(OutcomeClass, u32); 2],
    /// Reliable outcomes observed for the context across the cluster.
    pub total: u32,
}

/// A computed, not yet applied, partition of one cluster version.
#[derive(Clone, PartialEq, Debug)]
pub struct SplitPlan {
    /// Cluster being split.
    pub source: StateClusterId,
    /// Version of `source` the plan was computed against; applying it to any other version fails.
    pub source_version: u32,
    /// Outcome divergence that justifies the split.
    pub evidence: Contradiction,
    /// Members following the dominant outcome / the runner-up outcome.
    pub groups: [Vec<Member>; 2],
}

/// A membership moved by a split; the old row is superseded, not deleted.
#[derive(Clone, Copy, PartialEq, Debug)]
#[non_exhaustive]
pub struct MembershipChange {
    /// The moved state.
    pub state: StateId,
    /// Cluster the state leaves.
    pub from_cluster: StateClusterId,
    /// Version of the leaving cluster the old membership belongs to.
    pub from_version: u32,
    /// New cluster taking the state over.
    pub to_cluster: StateClusterId,
    /// Version of the new cluster (`from_version + 1`).
    pub to_version: u32,
    /// Weighted score of the state against the new cluster's recomputed prototype, in `[0, 1]`.
    pub similarity: f32,
    /// Caller-supplied decision time; this crate never reads the clock.
    pub decided_at: Timestamp,
}

/// Product of applying a plan.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct SplitResult {
    /// The new cluster versions, one per non-empty group, in group order.
    pub clusters: Vec<Cluster>,
    /// One entry per moved member, in the order of `clusters` then member order.
    pub superseded: Vec<MembershipChange>,
}

/// Detects contradictions and builds split plans.
#[derive(Clone, Copy, Debug, Default)]
pub struct Splitter {
    config: SplitConfig,
}

impl Splitter {
    /// Splitter with the given thresholds.
    #[must_use]
    pub const fn new(config: SplitConfig) -> Self {
        Self { config }
    }

    /// Look for a contradiction among `outcomes` of `cluster`'s members.
    ///
    /// For each action context the reliable outcomes are counted; when the
    /// runner-up has at least `min_second_count` observations and at least
    /// `min_second_fraction` of the total, members are partitioned: members
    /// that saw the dominant outcome seed group 0, those that saw the runner-up
    /// seed group 1 (a member that saw both follows its more frequent one,
    /// ties to group 0), and every other member joins the seed group with the
    /// higher mean similarity (ties to group 0). Outcomes of non-members are
    /// ignored. The context with the largest runner-up count wins (ties by id).
    #[must_use]
    pub fn check(
        &self,
        cluster: &Cluster,
        outcomes: &[(StateId, ActionContextId, OutcomeClass)],
    ) -> Option<SplitPlan> {
        if !cluster.is_active() || cluster.members.len() < 2 {
            return None;
        }
        let member_pos: BTreeMap<StateId, usize> = cluster
            .members
            .iter()
            .enumerate()
            .map(|(i, m)| (m.state, i))
            .collect();

        let mut per_ctx: BTreeMap<ActionContextId, Vec<(usize, &OutcomeClass)>> = BTreeMap::new();
        for (state, ctx, outcome) in outcomes {
            if outcome.unreliable {
                continue;
            }
            if let Some(&pos) = member_pos.get(state) {
                per_ctx.entry(*ctx).or_default().push((pos, outcome));
            }
        }

        struct Best<'a> {
            ctx: ActionContextId,
            top: &'a OutcomeClass,
            second: &'a OutcomeClass,
            counts: (u32, u32),
            total: u32,
        }
        let mut best: Option<Best<'_>> = None;
        for (ctx, rows) in &per_ctx {
            let mut counts: BTreeMap<&OutcomeClass, u32> = BTreeMap::new();
            for (_, o) in rows {
                *counts.entry(*o).or_insert(0) += 1;
            }
            let mut ranked: Vec<(&OutcomeClass, u32)> = counts.into_iter().collect();
            ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            let [(top, n1), (second, n2), ..] = ranked.as_slice() else {
                continue;
            };
            let total = u32::try_from(rows.len()).unwrap_or(u32::MAX);
            if *n2 < self.config.min_second_count
                || f64::from(*n2) / f64::from(total) < self.config.min_second_fraction - 1e-9
            {
                continue;
            }
            if best.as_ref().is_none_or(|b| *n2 > b.counts.1) {
                best = Some(Best {
                    ctx: *ctx,
                    top,
                    second,
                    counts: (*n1, *n2),
                    total,
                });
            }
        }
        let best = best?;

        // seed groups from the members' own outcomes for the chosen context
        let rows = per_ctx.get(&best.ctx)?;
        let mut tally: BTreeMap<usize, (u32, u32)> = BTreeMap::new();
        for (pos, o) in rows {
            let t = tally.entry(*pos).or_insert((0, 0));
            if *o == best.top {
                t.0 += 1;
            } else if *o == best.second {
                t.1 += 1;
            }
        }
        let mut seeds: [Vec<usize>; 2] = [Vec::new(), Vec::new()];
        for (pos, (a, b)) in &tally {
            if *a == 0 && *b == 0 {
                continue;
            }
            seeds[usize::from(b > a)].push(*pos);
        }
        if seeds[0].is_empty() || seeds[1].is_empty() {
            return None;
        }

        // remaining members join the seed group with the higher mean similarity
        let seeded: Vec<bool> = {
            let mut v = vec![false; cluster.members.len()];
            for p in seeds.iter().flatten() {
                v[*p] = true;
            }
            v
        };
        let seed_protos: [Vec<Prototype>; 2] = [
            seeds[0]
                .iter()
                .map(|p| Prototype::from_profile(&cluster.members[*p].profile))
                .collect(),
            seeds[1]
                .iter()
                .map(|p| Prototype::from_profile(&cluster.members[*p].profile))
                .collect(),
        ];
        let mut assign: Vec<usize> = vec![0; cluster.members.len()];
        for p in &seeds[1] {
            assign[*p] = 1;
        }
        for (i, m) in cluster.members.iter().enumerate() {
            if seeded[i] {
                continue;
            }
            let mean = |protos: &[Prototype]| -> f32 {
                if protos.is_empty() {
                    return 0.0;
                }
                protos.iter().map(|p| score(&m.profile.signature, p)).sum::<f32>() / protos.len() as f32
            };
            let (a, b) = (mean(&seed_protos[0]), mean(&seed_protos[1]));
            assign[i] = usize::from(b > a);
        }

        let mut groups: [Vec<Member>; 2] = [Vec::new(), Vec::new()];
        for (i, m) in cluster.members.iter().enumerate() {
            groups[assign[i]].push(m.clone());
        }
        Some(SplitPlan {
            source: cluster.id,
            source_version: cluster.version,
            evidence: Contradiction {
                action_context: best.ctx,
                outcomes: [
                    (best.top.clone(), best.counts.0),
                    (best.second.clone(), best.counts.1),
                ],
                total: best.total,
            },
            groups,
        })
    }

    /// Materialize `plan`: two new cluster versions (`source_version + 1`)
    /// with recomputed prototypes, and the superseded membership changes.
    /// Ids come from `ids`; `decided_at` stamps the membership decisions.
    #[must_use]
    pub fn apply(
        plan: &SplitPlan,
        ids: &mut dyn FnMut() -> StateClusterId,
        decided_at: Timestamp,
    ) -> SplitResult {
        let to_version = plan.source_version.saturating_add(1);
        let mut clusters = Vec::with_capacity(2);
        let mut superseded = Vec::new();
        for group in &plan.groups {
            let id = ids();
            let Some(first) = group.first() else { continue };
            let mut prototype = Prototype::from_profile(&first.profile);
            for m in group.iter().skip(1) {
                union_into(
                    &mut prototype.minhash_union,
                    &m.profile.signature.semantic_affordance_minhash,
                );
            }
            let members: Vec<Member> = group
                .iter()
                .map(|m| Member {
                    state: m.state,
                    profile: m.profile.clone(),
                    similarity: score(&m.profile.signature, &prototype),
                })
                .collect();
            for m in &members {
                superseded.push(MembershipChange {
                    state: m.state,
                    from_cluster: plan.source,
                    from_version: plan.source_version,
                    to_cluster: id,
                    to_version,
                    similarity: m.similarity,
                    decided_at,
                });
            }
            clusters.push(Cluster {
                id,
                version: to_version,
                prototype,
                size: u32::try_from(members.len()).unwrap_or(u32::MAX),
                members,
                near_of: Some(plan.source),
                superseded_by: Vec::new(),
            });
        }
        SplitResult { clusters, superseded }
    }
}
