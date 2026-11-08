//! A/B arms over strategy versions.
//!
//! A crawl may register several versions of one strategy name. The arm a role session runs
//! is a deterministic function of `(crawl_seed, role, run index, strategy name)` over the
//! configured arm weights — never random at runtime — so a rerun with the same seed and
//! weights reproduces the same arm per `(role, run index)`.
//!
//! [`ArmAssignment`] is the pure weights-only function; [`ArmedStrategy`] binds each arm to
//! a built [`Strategy`] and picks the one a session should run.

use crate::error::StrategyError;
use crate::Strategy;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::PrincipalId;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Purpose tag of the seed-derived RNG; part of the on-disk contract (a change re-assigns
/// every arm of every recorded run).
const PURPOSE: &str = "ab-arm/v1";

/// One registered version of a strategy and its relative weight.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct Arm {
    /// `Strategy::version()` of this arm.
    pub version: u32,
    /// Relative weight, `> 0`; the share of `(role, run index)` slots this arm receives.
    pub weight: u32,
}

/// Deterministic arm assignment for one strategy name over weighted versions.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ArmAssignment {
    name: &'static str,
    /// Sorted by version (determinism: the cumulative-weight walk is a pure function of inputs).
    arms: Vec<Arm>,
    total_weight: u64,
}

impl ArmAssignment {
    /// Weighted arms for strategy `name`.
    ///
    /// # Errors
    /// [`StrategyError::Internal`] when `arms` is empty, an arm has weight zero or two arms
    /// carry the same version.
    pub fn new(name: &'static str, arms: impl IntoIterator<Item = Arm>) -> Result<Self, StrategyError> {
        let mut sorted: Vec<Arm> = arms.into_iter().collect();
        sorted.sort_by_key(|a| a.version);
        if sorted.is_empty() {
            return Err(StrategyError::Internal(format!(
                "strategy {name}: no arms registered"
            )));
        }
        let mut total_weight = 0u64;
        for pair in sorted.windows(2) {
            if pair[0].version == pair[1].version {
                return Err(StrategyError::Internal(format!(
                    "strategy {name}: version {} registered twice",
                    pair[0].version
                )));
            }
        }
        for arm in &sorted {
            if arm.weight == 0 {
                return Err(StrategyError::Internal(format!(
                    "strategy {name} v{}: arm weight must be positive",
                    arm.version
                )));
            }
            total_weight = total_weight.saturating_add(u64::from(arm.weight));
        }
        Ok(Self {
            name,
            arms: sorted,
            total_weight,
        })
    }

    /// Strategy name the arms belong to.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The arms, sorted by version.
    #[must_use]
    pub fn arms(&self) -> &[Arm] {
        &self.arms
    }

    /// The arm `role`'s `run_index`-th session runs under `seed`.
    ///
    /// A deterministic hash of `(crawl_seed, role, run index, strategy name)` over the arm
    /// weights: the seed-derived RNG draws one `u64` and the cumulative-weight walk maps it to
    /// an arm. Same inputs, same arm, in every process.
    #[must_use]
    pub fn for_role(&self, seed: CrawlSeed, role: &PrincipalId, run_index: u16) -> Arm {
        let draw = seed
            .rng(
                PURPOSE,
                &[self.name.as_bytes(), role.0.as_bytes(), &run_index.to_le_bytes()],
            )
            .next_u64();
        let mut point = draw % self.total_weight;
        for arm in &self.arms {
            let weight = u64::from(arm.weight);
            if point < weight {
                return *arm;
            }
            point -= weight;
        }
        // Unreachable: `point < total_weight` and the weights sum to `total_weight`.
        self.arms[self.arms.len() - 1]
    }
}

/// Several versions of one strategy name, each bound to an arm weight.
pub struct ArmedStrategy {
    name: &'static str,
    /// Version → (weight, strategy); `BTreeMap` so the registry order is deterministic.
    versions: BTreeMap<u32, (u32, Arc<dyn Strategy>)>,
}

impl ArmedStrategy {
    /// An empty arm set for strategy `name`.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            versions: BTreeMap::new(),
        }
    }

    /// Register `strategy` as an arm with `weight`.
    ///
    /// # Errors
    /// [`StrategyError::Internal`] when the strategy's name differs from this set's name,
    /// its version is already registered or `weight` is zero.
    pub fn register(&mut self, strategy: Arc<dyn Strategy>, weight: u32) -> Result<(), StrategyError> {
        if strategy.name() != self.name {
            return Err(StrategyError::Internal(format!(
                "arm set {} cannot hold strategy {}",
                self.name,
                strategy.name()
            )));
        }
        if weight == 0 {
            return Err(StrategyError::Internal(format!(
                "strategy {} v{}: arm weight must be positive",
                self.name,
                strategy.version()
            )));
        }
        let version = strategy.version();
        if self.versions.contains_key(&version) {
            return Err(StrategyError::Internal(format!(
                "strategy {} v{version} registered twice",
                self.name
            )));
        }
        self.versions.insert(version, (weight, strategy));
        Ok(())
    }

    /// Strategy name of every arm.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The registered versions, ascending.
    pub fn versions(&self) -> impl Iterator<Item = u32> + '_ {
        self.versions.keys().copied()
    }

    /// The weights-only assignment over the registered arms.
    ///
    /// # Errors
    /// [`StrategyError::Internal`] when no arm is registered.
    pub fn assignment(&self) -> Result<ArmAssignment, StrategyError> {
        ArmAssignment::new(
            self.name,
            self.versions.iter().map(|(version, (weight, _))| Arm {
                version: *version,
                weight: *weight,
            }),
        )
    }

    /// The arm and strategy `role`'s `run_index`-th session runs under `seed`.
    ///
    /// # Errors
    /// [`StrategyError::Internal`] when no arm is registered.
    pub fn pick(
        &self,
        seed: CrawlSeed,
        role: &PrincipalId,
        run_index: u16,
    ) -> Result<(Arm, Arc<dyn Strategy>), StrategyError> {
        let arm = self.assignment()?.for_role(seed, role, run_index);
        let (_, strategy) = self.versions.get(&arm.version).ok_or_else(|| {
            StrategyError::Internal(format!(
                "strategy {} v{} vanished from the arm set",
                self.name, arm.version
            ))
        })?;
        Ok((arm, Arc::clone(strategy)))
    }
}

impl std::fmt::Debug for ArmedStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let arms: Vec<(u32, u32)> = self.versions.iter().map(|(v, (w, _))| (*v, *w)).collect();
        f.debug_struct("ArmedStrategy")
            .field("name", &self.name)
            .field("arms", &arms)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::context::DecisionContext;
    use crate::interaction_bfs::{BfsConfig, InteractionBfs, NAME};
    use crate::testutil::{Fixture, Spec};
    use async_trait::async_trait;
    use crawlx_core::proposal::ActionProposal;

    /// The same logic published under another version (a candidate arm).
    struct Versioned {
        inner: InteractionBfs,
        version: u32,
    }

    #[async_trait]
    impl Strategy for Versioned {
        async fn propose(&self, ctx: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
            let mut out = self.inner.propose(ctx).await?;
            for p in &mut out {
                p.strategy_version = self.version;
            }
            Ok(out)
        }
        fn name(&self) -> &'static str {
            self.inner.name()
        }
        fn version(&self) -> u32 {
            self.version
        }
    }

    fn two_arms() -> ArmedStrategy {
        let mut set = ArmedStrategy::new(NAME);
        set.register(Arc::new(InteractionBfs::new(BfsConfig::default())), 1)
            .unwrap();
        set.register(
            Arc::new(Versioned {
                inner: InteractionBfs::new(BfsConfig::default()),
                version: 2,
            }),
            1,
        )
        .unwrap();
        set
    }

    fn role(name: &str) -> PrincipalId {
        PrincipalId(name.to_owned())
    }

    /// Arms for seed 42, equal weights, computed once and pinned: a rerun in any process
    /// must reproduce them (A/B reproducibility).
    const PINNED: [(&str, u16, u32); 9] = [
        ("member", 1, 1),
        ("member", 2, 2),
        ("member", 3, 2),
        ("admin", 1, 1),
        ("admin", 2, 1),
        ("admin", 3, 1),
        ("anonymous", 1, 2),
        ("anonymous", 2, 1),
        ("anonymous", 3, 2),
    ];

    #[test]
    fn two_registered_versions_are_assigned_deterministically_from_seed_role_and_run_index() {
        let set = two_arms();
        assert_eq!(set.versions().collect::<Vec<_>>(), vec![1, 2]);
        let assignment = set.assignment().unwrap();
        for (role_name, run_index, expected) in PINNED {
            let arm = assignment.for_role(CrawlSeed(42), &role(role_name), run_index);
            assert_eq!(
                arm.version, expected,
                "seed 42 / {role_name} / run {run_index}: expected v{expected}, got v{}",
                arm.version
            );
            let (picked, strategy) = set.pick(CrawlSeed(42), &role(role_name), run_index).unwrap();
            assert_eq!(picked, arm);
            assert_eq!(strategy.version(), expected);
            assert_eq!(strategy.name(), NAME);
        }
    }

    #[test]
    fn assignment_is_a_pure_function_of_its_inputs() {
        let a = two_arms().assignment().unwrap();
        let b = ArmAssignment::new(
            NAME,
            [
                Arm {
                    version: 2,
                    weight: 1,
                },
                Arm {
                    version: 1,
                    weight: 1,
                },
            ],
        )
        .unwrap();
        assert_eq!(a, b, "registration order does not matter");
        let mut by_arm = BTreeMap::<u32, u32>::new();
        for run_index in 1..=200u16 {
            for role_name in ["member", "admin"] {
                let x = a.for_role(CrawlSeed(42), &role(role_name), run_index);
                let y = b.for_role(CrawlSeed(42), &role(role_name), run_index);
                assert_eq!(x, y);
                *by_arm.entry(x.version).or_default() += 1;
            }
        }
        assert!(
            by_arm.len() == 2 && by_arm.values().all(|n| *n > 100),
            "{by_arm:?}"
        );
        // another seed, role, run index or strategy name moves at least one assignment
        let seeds: Vec<u32> = (1..=50u16)
            .map(|i| a.for_role(CrawlSeed(43), &role("member"), i).version)
            .collect();
        let base: Vec<u32> = (1..=50u16)
            .map(|i| a.for_role(CrawlSeed(42), &role("member"), i).version)
            .collect();
        assert_ne!(seeds, base);
        let other_name = ArmAssignment::new("state_novelty", a.arms().iter().copied()).unwrap();
        let renamed: Vec<u32> = (1..=50u16)
            .map(|i| other_name.for_role(CrawlSeed(42), &role("member"), i).version)
            .collect();
        assert_ne!(renamed, base);
    }

    #[test]
    fn weights_shift_the_split_and_a_single_arm_always_wins() {
        let heavy = ArmAssignment::new(
            NAME,
            [
                Arm {
                    version: 1,
                    weight: 9,
                },
                Arm {
                    version: 2,
                    weight: 1,
                },
            ],
        )
        .unwrap();
        let v2 = (1..=1000u16)
            .filter(|i| heavy.for_role(CrawlSeed(7), &role("member"), *i).version == 2)
            .count();
        assert!((50..=160).contains(&v2), "v2 won {v2} of 1000 at weight 1/10");
        let single = ArmAssignment::new(
            NAME,
            [Arm {
                version: 3,
                weight: 1,
            }],
        )
        .unwrap();
        assert!((1..=100u16).all(|i| single.for_role(CrawlSeed(7), &role("member"), i).version == 3));
    }

    #[test]
    fn invalid_arm_sets_are_rejected() {
        assert!(ArmAssignment::new(NAME, []).is_err());
        assert!(ArmAssignment::new(
            NAME,
            [Arm {
                version: 1,
                weight: 0
            }]
        )
        .is_err());
        assert!(ArmAssignment::new(
            NAME,
            [
                Arm {
                    version: 1,
                    weight: 1
                },
                Arm {
                    version: 1,
                    weight: 2
                }
            ]
        )
        .is_err());
        let mut set = ArmedStrategy::new(NAME);
        assert!(set.assignment().is_err());
        assert!(set.pick(CrawlSeed(1), &role("member"), 1).is_err());
        let bfs = || Arc::new(InteractionBfs::new(BfsConfig::default()));
        assert!(set.register(bfs(), 0).is_err());
        set.register(bfs(), 1).unwrap();
        let Err(err) = set.register(bfs(), 1) else {
            panic!("same version registered twice");
        };
        assert!(err.to_string().contains("registered twice"), "{err}");
        let Err(err) = set.register(Arc::new(crate::novelty::StateNovelty::default()), 1) else {
            panic!("another strategy name accepted");
        };
        assert!(err.to_string().contains("cannot hold"), "{err}");
    }

    #[tokio::test]
    async fn the_picked_arm_attributes_its_proposals_to_its_own_version() {
        let set = two_arms();
        let f = Fixture::new(&[Spec::button("Open"), Spec::button("Next")]);
        let ctx = f.ctx();
        for (role_name, run_index, expected) in PINNED {
            let (arm, strategy) = set.pick(CrawlSeed(42), &role(role_name), run_index).unwrap();
            let props = strategy.propose(&ctx).await.unwrap();
            assert!(!props.is_empty());
            assert!(props.iter().all(|p| p.strategy_version == arm.version));
            assert_eq!(arm.version, expected);
        }
    }
}
