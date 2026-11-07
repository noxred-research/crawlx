//! Ablation matrix A0–A12 and its runner.
//!
//! Each row is a configuration of the same binary (`bench.variant`); every row inherits the
//! previous capability unless stated. [`matrix`] is the table; [`AblationRunner`] executes
//! variants through a [`VariantExecutor`] and scores each run against the gym ledger:
//!
//! * [`BrowserExecutor`]: the self-contained driver ([`crate::driver`]) over any
//!   `BrowserBackend` against a live gym (real Chromium or `FakeBackend`), ledger = the gym's;
//! * [`FakeExecutor`]: the driver over a `FakeBackend` scripted from the manifest, with the
//!   ledger derived from the fake's performed-action log (a simulated gym, no network).
//!
//! Variants whose capability lives in the worker (phase-2 pathfinding, forms, model cascade,
//! multi-role, LLM planner) report [`AblationVariant::needs_worker`]; the drivers here refuse
//! them rather than silently running a weaker configuration.

use crate::driver::{self, DriverConfig};
use crate::error::BenchError;
use crate::gym::ledger::Ledger;
use crate::gym::manifest::{ExpectedClass, FixtureManifest};
use crate::gym::server::GymHandle;
use crate::policy::PolicyFlags;
use crate::scorecard::{RunRows, Scorecard};
use crate::stats::{Direction, PairedComparison, StatsError, DEFAULT_LEVEL, DEFAULT_RESAMPLES};
use async_trait::async_trait;
use crawlx_browser::fake::{FakeAxSpec, FakeBackend, FakeEffect, FakePage, FakeScript};
use crawlx_core::browser::BrowserBackend;
use crawlx_core::config::{CrawlMode, CreateCrawl, LlmPlannerMode, StrategyName, System1Mode};
use crawlx_core::counters::Counters;
use crawlx_elements::Rung;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Arc;

/// One row of the ablation table.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AblationVariant {
    /// `A0`..`A12`.
    pub id: &'static str,
    /// Configuration in words.
    pub name: &'static str,
    /// The question the row answers.
    pub question: &'static str,
    /// Runs a browser at all (false for the URL-plane-only row).
    pub browser: bool,
    /// `dynamic.strategies` of the request.
    pub strategies: Vec<StrategyName>,
    /// Candidates from the accessibility tree.
    pub ax: bool,
    /// Candidates from event listeners and cursor/focus evidence.
    pub listeners: bool,
    /// Container text participates in element identity.
    pub identity_container: bool,
    /// Frontier is the interaction-count queue `Q*` with only `W`.
    pub w_only: bool,
    /// Structural repetition term `0.3·Z`.
    pub z: bool,
    /// Reveal bonus `E`.
    pub e: bool,
    /// Enablement graph: recorded reachability (`graph` policy term) steers the frontier.
    pub graph: bool,
    /// Phase-2 pathfinding: the worker plans multi-step paths through the enablement graph.
    pub phase2: bool,
    /// Form filling with deterministic value partitions.
    pub forms: bool,
    /// System-1 model mode.
    pub model: System1Mode,
    /// Round-robin multi-role.
    pub multi_role: bool,
    /// LLM planner mode.
    pub llm_planner: LlmPlannerMode,
}

impl AblationVariant {
    /// The frontier is a scored queue (otherwise: document order).
    #[must_use]
    pub const fn queue_active(&self) -> bool {
        self.w_only || self.z || self.e || self.graph
    }

    /// The queue-score terms this row enables.
    #[must_use]
    pub const fn policy_flags(&self) -> PolicyFlags {
        PolicyFlags {
            queue: self.queue_active(),
            z: self.z,
            e: self.e,
            graph: self.graph,
        }
    }

    /// Highest discovery rung consulted.
    #[must_use]
    pub const fn max_rung(&self) -> Rung {
        if self.listeners {
            Rung::Listener
        } else {
            Rung::Ax
        }
    }

    /// Capability the in-crate driver cannot provide, if any.
    #[must_use]
    pub fn needs_worker(&self) -> Option<&'static str> {
        if self.phase2 {
            Some("phase-2 pathfinding")
        } else if self.forms {
            Some("form filling")
        } else if self.model != System1Mode::Off {
            Some("the model cascade")
        } else if self.multi_role {
            Some("multi-role scheduling")
        } else if self.llm_planner != LlmPlannerMode::Off {
            Some("the LLM planner")
        } else {
            None
        }
    }

    /// Write the request-level part of the variant into `req` (mode, strategies, model, planner, roles).
    pub fn apply(&self, req: &mut CreateCrawl) {
        req.mode = if self.browser {
            CrawlMode::Dynamic
        } else {
            CrawlMode::Static
        };
        req.dynamic.enabled = self.browser;
        req.dynamic.strategies.clone_from(&self.strategies);
        req.dynamic.system1_mode = self.model;
        req.dynamic.llm_planner = self.llm_planner;
        if self.multi_role {
            req.runs_per_role = req.runs_per_role.max(2);
        }
    }
}

struct Row(AblationVariant);

fn variant(
    id: &'static str,
    name: &'static str,
    question: &'static str,
    prev: Option<&AblationVariant>,
) -> Row {
    let mut v = prev.cloned().unwrap_or(AblationVariant {
        id,
        name,
        question,
        browser: true,
        strategies: Vec::new(),
        ax: false,
        listeners: false,
        identity_container: false,
        w_only: false,
        z: false,
        e: false,
        graph: false,
        phase2: false,
        forms: false,
        model: System1Mode::Off,
        multi_role: false,
        llm_planner: LlmPlannerMode::Off,
    });
    v.id = id;
    v.name = name;
    v.question = question;
    Row(v)
}

/// The A0–A12 ablation table.
#[must_use]
pub fn matrix() -> Vec<AblationVariant> {
    let a0 = {
        let mut r = variant(
            "A0",
            "URL plane only (mode: static)",
            "what does sitemap + link BFS recover without a browser?",
            None,
        )
        .0;
        r.browser = false;
        r
    };
    let a1 = {
        let mut r = variant("A1", "AX only", "coverage from semantic browser data alone", None).0;
        r.ax = true;
        r.strategies = vec![StrategyName::InteractionBfs];
        r
    };
    let a2 = {
        let mut r = variant(
            "A2",
            "A1 + listeners",
            "what do non-semantic clickables add?",
            Some(&a1),
        )
        .0;
        r.listeners = true;
        r
    };
    let a3 = {
        let mut r = variant(
            "A3",
            "A2 + container identity",
            "collision reduction vs split increase",
            Some(&a2),
        )
        .0;
        r.identity_container = true;
        r
    };
    let a4 = {
        let mut r = variant(
            "A4",
            "W only (interaction-count queue, Q* layer)",
            "simple frequency BFS baseline",
            Some(&a3),
        )
        .0;
        r.w_only = true;
        r
    };
    let a5 = {
        let mut r = variant(
            "A5",
            "A4 + Z (structural repetition term)",
            "does path repetition penalty improve diverse coverage?",
            Some(&a4),
        )
        .0;
        r.w_only = false;
        r.z = true;
        r
    };
    let a6 = {
        let mut r = variant(
            "A6",
            "A5 + E (reveal bonus)",
            "does the bonus improve depth efficiently?",
            Some(&a5),
        )
        .0;
        r.e = true;
        r
    };
    let a7 = {
        let mut r = variant(
            "A7",
            "A6 + enablement graph",
            "does recorded reachability matter beyond revisiting triggers?",
            Some(&a6),
        )
        .0;
        // Recorded reachability steers the frontier (the `graph` queue term; in the worker the
        // exploration state's reveal episodes). Path planning toward hidden targets is A8.
        r.graph = true;
        r
    };
    let a8 = {
        let mut r = variant(
            "A8",
            "A7 + phase-2 pathfinding",
            "hidden functionality uniquely recovered",
            Some(&a7),
        )
        .0;
        // `enablement` is the worker's phase-2 pathfinding: it plans paths over the graph
        // toward identities seen earlier but not visible now and proposes the next step.
        r.phase2 = true;
        r.strategies.push(StrategyName::Enablement);
        r
    };
    let a9 = {
        let mut r = variant(
            "A9",
            "A8 + forms (deterministic value partitions)",
            "form success and validation coverage",
            Some(&a8),
        )
        .0;
        r.forms = true;
        r
    };
    let a10 = {
        let mut r = variant(
            "A10",
            "A9 + model (System-1 shadow to advisory)",
            "coverage gain per model dollar and per second",
            Some(&a9),
        )
        .0;
        r.model = System1Mode::Advisory;
        r.strategies.push(StrategyName::System1);
        r
    };
    let a11 = {
        let mut r = variant(
            "A11",
            "A10 + multi-role (round-robin)",
            "authorization-relevant coverage that only cross-user state exposes",
            Some(&a10),
        )
        .0;
        r.multi_role = true;
        r
    };
    let a12 = {
        let mut r = variant(
            "A12",
            "A11 + LLM planner (stalled_only)",
            "marginal value of the planner after deterministic crawling",
            Some(&a11),
        )
        .0;
        r.llm_planner = LlmPlannerMode::StalledOnly;
        r
    };
    let mut all = vec![a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12];
    // `ax` stays on for every browser row after A1.
    for v in &mut all {
        v.ax = v.browser;
    }
    all
}

/// The variant with this id.
#[must_use]
pub fn find(id: &str) -> Option<AblationVariant> {
    matrix().into_iter().find(|v| v.id.eq_ignore_ascii_case(id))
}

/// Actions spent per hidden target reached (hidden-target recovery uses at most the
/// baseline's actions-to-reach). A hidden target is a
/// manifest control behind a precondition (`requires` non-empty) that counts as a ground-truth
/// target; it is reached when the gym ledger saw its handler run from a trusted event.
#[derive(Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize, Debug)]
#[non_exhaustive]
pub struct Efficiency {
    /// Executed actions of the run (journal rows past `proposed`).
    pub actions: u64,
    /// Ground-truth controls with a non-empty `requires`.
    pub hidden_total: u64,
    /// Hidden targets exercised from a trusted event.
    pub hidden_reached: u64,
    /// `hidden_reached / hidden_total`; `None` when the fixture hides nothing.
    pub hidden_recall: Option<f64>,
    /// `actions / hidden_reached`; `None` when no hidden target was reached.
    pub actions_per_hidden_target: Option<f64>,
}

impl Efficiency {
    /// Compute from the manifest, the run's action rows and the scorecard's trusted-exercised set.
    #[must_use]
    pub fn compute(manifest: &FixtureManifest, rows: &RunRows, scorecard: &Scorecard) -> Self {
        let hidden: BTreeSet<&str> = manifest
            .controls
            .iter()
            .filter(|c| !c.requires.is_empty())
            .filter(|c| c.expected == ExpectedClass::Actionable)
            .filter(|c| c.mechanism != crate::gym::manifest::Mechanism::Unsupported)
            .filter(|c| rows.stealth || !c.stealth_only)
            .map(|c| c.id.as_str())
            .collect();
        let reached = scorecard
            .coverage
            .exercised
            .iter()
            .filter(|id| hidden.contains(id.as_str()))
            .count();
        // Journal rows that went past `proposed`: the worker journals a `proposed` row for
        // candidates the arbiter dropped (stale epoch, revalidation) without executing them.
        let actions = rows
            .actions
            .iter()
            .filter(|a| a.status != crawlx_core::counters::ActionStatus::Proposed)
            .count() as u64;
        let hidden_total = hidden.len() as u64;
        let hidden_reached = reached as u64;
        // Counts are far below 2^53; the casts are exact.
        Self {
            actions,
            hidden_total,
            hidden_reached,
            hidden_recall: (hidden_total > 0).then(|| hidden_reached as f64 / hidden_total as f64),
            actions_per_hidden_target: (hidden_reached > 0).then(|| actions as f64 / hidden_reached as f64),
        }
    }
}

/// One executed (variant, seed).
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct VariantOutcome {
    /// Variant id (`A0`..`A12`) that was executed.
    pub variant: &'static str,
    /// Seed the fixture and the run were driven with.
    pub seed: u64,
    /// Metrics of the run scored against the manifest and the gym ledger.
    pub scorecard: Scorecard,
    /// URL-plane counters, for the static row.
    pub url_counters: Option<Counters>,
    /// Actions per hidden target reached.
    pub efficiency: Efficiency,
}

/// All outcomes of a matrix run over one fixture.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct AblationReport {
    /// Id of the fixture the matrix was run over.
    pub fixture: String,
    /// One outcome per executed variant and seed, in execution order.
    pub outcomes: Vec<VariantOutcome>,
}

impl AblationReport {
    /// Mean trusted coverage and AUC per variant over its seeds, in matrix order.
    #[must_use]
    pub fn means(&self) -> Vec<(&'static str, f64, f64)> {
        let mut by: BTreeMap<&'static str, Vec<&VariantOutcome>> = BTreeMap::new();
        for o in &self.outcomes {
            by.entry(o.variant).or_default().push(o);
        }
        let mut out: Vec<(&'static str, f64, f64)> = by
            .into_iter()
            .map(|(v, os)| {
                let n = os.len() as f64;
                (
                    v,
                    os.iter().map(|o| o.scorecard.coverage.trusted).sum::<f64>() / n,
                    os.iter().map(|o| o.scorecard.coverage.auc).sum::<f64>() / n,
                )
            })
            .collect();
        out.sort_by_key(|(v, _, _)| v.trim_start_matches('A').parse::<u32>().unwrap_or(u32::MAX));
        out
    }

    /// Per-variant efficiency over its seeds, in matrix order: `(variant, mean hidden
    /// recall, mean actions per hidden target)`. A mean is `None` when no seed of the variant
    /// has the value (no hidden target in the fixture, or none reached by any seed).
    #[must_use]
    pub fn efficiency_means(&self) -> Vec<(&'static str, Option<f64>, Option<f64>)> {
        let mut by: BTreeMap<&'static str, Vec<&Efficiency>> = BTreeMap::new();
        for o in &self.outcomes {
            by.entry(o.variant).or_default().push(&o.efficiency);
        }
        let mean = |xs: Vec<f64>| (!xs.is_empty()).then(|| xs.iter().sum::<f64>() / xs.len() as f64);
        let mut out: Vec<(&'static str, Option<f64>, Option<f64>)> = by
            .into_iter()
            .map(|(v, es)| {
                (
                    v,
                    mean(es.iter().filter_map(|e| e.hidden_recall).collect()),
                    mean(es.iter().filter_map(|e| e.actions_per_hidden_target).collect()),
                )
            })
            .collect();
        out.sort_by_key(|(v, _, _)| v.trim_start_matches('A').parse::<u32>().unwrap_or(u32::MAX));
        out
    }

    /// Paired comparison of `candidate` against `baseline` over the seeds both ran:
    /// trusted coverage, AUC (higher is better) and `T80` (lower is better,
    /// only over seeds where both reached 80%). Pairs are matched by seed, in `baseline`
    /// seed order.
    ///
    /// # Errors
    /// [`BenchError::Ablation`] when a variant has no outcomes, [`BenchError::Stats`] when
    /// fewer than two seeds are shared or a statistic cannot be computed.
    pub fn compare_paired(&self, baseline: &str, candidate: &str) -> Result<PairedReport, BenchError> {
        let of = |id: &str| -> BTreeMap<u64, &VariantOutcome> {
            self.outcomes
                .iter()
                .filter(|o| o.variant.eq_ignore_ascii_case(id))
                .map(|o| (o.seed, o))
                .collect()
        };
        let (a, b) = (of(baseline), of(candidate));
        if a.is_empty() || b.is_empty() {
            return Err(BenchError::Ablation(format!(
                "paired comparison needs outcomes for both `{baseline}` and `{candidate}`"
            )));
        }
        let seeds: Vec<u64> = a.keys().filter(|s| b.contains_key(s)).copied().collect();
        let pick = |m: &BTreeMap<u64, &VariantOutcome>, f: fn(&Scorecard) -> f64| -> Vec<f64> {
            seeds.iter().map(|s| f(&m[s].scorecard)).collect()
        };
        let compare = |metric: &str, f: fn(&Scorecard) -> f64, dir: Direction| {
            PairedComparison::compute(
                metric,
                &seeds,
                &pick(&a, f),
                &pick(&b, f),
                dir,
                DEFAULT_RESAMPLES,
                DEFAULT_LEVEL,
            )
        };
        let coverage = compare(
            "coverage.trusted",
            |s| s.coverage.trusted,
            Direction::HigherIsBetter,
        )?;
        let auc = compare("coverage.auc", |s| s.coverage.auc, Direction::HigherIsBetter)?;
        let t80_seeds: Vec<u64> = seeds
            .iter()
            .filter(|s| a[s].scorecard.coverage.t80.is_some() && b[s].scorecard.coverage.t80.is_some())
            .copied()
            .collect();
        let t80_of = |m: &BTreeMap<u64, &VariantOutcome>| -> Vec<f64> {
            t80_seeds
                .iter()
                // Interaction counts are far below 2^53; the cast is exact.
                .map(|s| {
                    m[s].scorecard.coverage.t80.map_or(f64::NAN, |t| {
                        #[allow(clippy::cast_precision_loss)]
                        let t = t as f64;
                        t
                    })
                })
                .collect()
        };
        let t80 = match PairedComparison::compute(
            "t80",
            &t80_seeds,
            &t80_of(&a),
            &t80_of(&b),
            Direction::LowerIsBetter,
            DEFAULT_RESAMPLES,
            DEFAULT_LEVEL,
        ) {
            Ok(c) => Some(c),
            Err(StatsError::TooFew { .. }) => None,
            Err(e) => return Err(e.into()),
        };
        Ok(PairedReport {
            fixture: self.fixture.clone(),
            baseline: baseline.to_owned(),
            candidate: candidate.to_owned(),
            seeds,
            coverage,
            auc,
            t80,
        })
    }

    /// Markdown table, one line per (variant, seed).
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut s = format!(
            "# Ablation: {}\n\n| Variant | Seed | Coverage (trusted) | AUC | T80 | Target recall | Collision | Split | Unauthorized | Hidden recall | Actions/hidden |\n|---|---|---|---|---|---|---|---|---|---|---|\n",
            self.fixture
        );
        for o in &self.outcomes {
            let sc = &o.scorecard;
            let (c, sp) = sc.identity.map_or(("n/a".to_owned(), "n/a".to_owned()), |i| {
                (format!("{:.3}", i.collision_rate), format!("{:.3}", i.split_rate))
            });
            let eff = &o.efficiency;
            let _ = writeln!(
                s,
                "| {} | {} | {:.3} | {:.3} | {} | {:.3} | {c} | {sp} | {} | {} | {} |",
                o.variant,
                o.seed,
                sc.coverage.trusted,
                sc.coverage.auc,
                sc.coverage.t80.map_or("n/a".to_owned(), |t| t.to_string()),
                sc.targets.overall.recall,
                sc.safety.unauthorized,
                eff.hidden_recall.map_or("n/a".to_owned(), |r| format!("{r:.3}")),
                eff.actions_per_hidden_target
                    .map_or("n/a".to_owned(), |a| format!("{a:.2}")),
            );
        }
        s
    }
}

/// A paired baseline-vs-candidate comparison.
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct PairedReport {
    /// Fixture both variants ran on.
    pub fixture: String,
    /// Baseline variant id.
    pub baseline: String,
    /// Candidate variant id.
    pub candidate: String,
    /// Seeds shared by both variants, in order.
    pub seeds: Vec<u64>,
    /// Trusted action-context coverage.
    pub coverage: PairedComparison,
    /// Coverage AUC.
    pub auc: PairedComparison,
    /// `T80`, when at least two shared seeds reached 80% under both variants.
    pub t80: Option<PairedComparison>,
}

impl PairedReport {
    /// The verdict on the primary metric (trusted coverage).
    #[must_use]
    pub fn is_improvement(&self) -> bool {
        self.coverage.is_improvement()
    }

    /// Markdown table of the comparisons.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut s = format!(
            "# Paired: {} vs {} on {} ({} seeds)\n\n| Metric | Pairs | Mean diff | 95% CI | Wilcoxon p | Verdict |\n|---|---|---|---|---|---|\n",
            self.candidate,
            self.baseline,
            self.fixture,
            self.seeds.len()
        );
        for c in [Some(&self.coverage), Some(&self.auc), self.t80.as_ref()]
            .into_iter()
            .flatten()
        {
            s.push_str(&c.render_markdown_row());
            s.push('\n');
        }
        s
    }
}

/// Runs one variant for one seed and returns the rows plus the ledger to score against.
#[async_trait]
pub trait VariantExecutor: Send + Sync {
    /// Execute `variant` on `manifest` with `seed`. Implementations restore the gym to the same
    /// baseline before every call (paired-run protocol).
    async fn execute(
        &self,
        variant: &AblationVariant,
        manifest: &FixtureManifest,
        seed: u64,
    ) -> Result<Executed, BenchError>;
}

/// What an executor hands back.
pub struct Executed {
    /// Run rows the scorecard is computed from.
    pub rows: RunRows,
    /// Ground-truth ledger the run is scored against (the gym's, or one derived from a fake backend).
    pub ledger: Arc<Ledger>,
    /// URL-plane counters of the run; `Some` only for the static (non-browser) row.
    pub url_counters: Option<Counters>,
}

/// Executes the matrix.
pub struct AblationRunner<'a> {
    executor: &'a dyn VariantExecutor,
}

impl<'a> AblationRunner<'a> {
    /// Runner that executes variants through `executor`.
    #[must_use]
    pub const fn new(executor: &'a dyn VariantExecutor) -> Self {
        Self { executor }
    }

    /// Run every `variant` for every seed of `seeds` and score each run.
    ///
    /// # Errors
    /// The first executor failure.
    pub async fn run(
        &self,
        variants: &[AblationVariant],
        manifest: &FixtureManifest,
        seeds: &[u64],
    ) -> Result<AblationReport, BenchError> {
        let mut outcomes = Vec::new();
        for v in variants {
            for seed in seeds {
                let ex = self.executor.execute(v, manifest, *seed).await?;
                let scorecard = Scorecard::compute(manifest, &ex.rows, &ex.ledger);
                let efficiency = Efficiency::compute(manifest, &ex.rows, &scorecard);
                outcomes.push(VariantOutcome {
                    variant: v.id,
                    seed: *seed,
                    scorecard,
                    url_counters: ex.url_counters,
                    efficiency,
                });
            }
        }
        Ok(AblationReport {
            fixture: manifest.id.clone(),
            outcomes,
        })
    }

    /// Paired-run protocol: for every seed, execute `baseline` then
    /// `candidate` back to back (the executor restores the gym before each call), then
    /// compare per seed.
    ///
    /// # Errors
    /// The first executor failure, or a statistics failure (fewer than two seeds).
    pub async fn run_paired(
        &self,
        baseline: &AblationVariant,
        candidate: &AblationVariant,
        manifest: &FixtureManifest,
        seeds: &[u64],
    ) -> Result<(AblationReport, PairedReport), BenchError> {
        let mut outcomes = Vec::with_capacity(seeds.len() * 2);
        for seed in seeds {
            for v in [baseline, candidate] {
                let ex = self.executor.execute(v, manifest, *seed).await?;
                let scorecard = Scorecard::compute(manifest, &ex.rows, &ex.ledger);
                let efficiency = Efficiency::compute(manifest, &ex.rows, &scorecard);
                outcomes.push(VariantOutcome {
                    variant: v.id,
                    seed: *seed,
                    scorecard,
                    url_counters: ex.url_counters,
                    efficiency,
                });
            }
        }
        let report = AblationReport {
            fixture: manifest.id.clone(),
            outcomes,
        };
        let paired = report.compare_paired(baseline.id, candidate.id)?;
        Ok((report, paired))
    }
}

/// Driver over a live gym: real Chromium (or any backend that loads the gym's pages).
pub struct BrowserExecutor<'a> {
    /// Browser backend that loads the gym pages (real Chromium or a fake).
    pub backend: &'a dyn BrowserBackend,
    /// Live gym the pages are served from; its ledger is the ground truth.
    pub gym: &'a GymHandle,
    /// Driver limits (action budget, layer cap, settle policy).
    pub config: DriverConfig,
}

#[async_trait]
impl VariantExecutor for BrowserExecutor<'_> {
    async fn execute(
        &self,
        variant: &AblationVariant,
        manifest: &FixtureManifest,
        seed: u64,
    ) -> Result<Executed, BenchError> {
        self.gym.reset(seed);
        let ledger = self.gym.ledger();
        if !variant.browser {
            let crawl = crate::urlplane::crawl(&self.gym.base_url, manifest, 500).await?;
            let rows = RunRows::new(
                &manifest.id,
                seed,
                variant.id,
                crawlx_core::config::SafetyProfile::ReadOnly,
            );
            return Ok(Executed {
                rows,
                ledger,
                url_counters: Some(crawl.counters),
            });
        }
        let rows = driver::run_variant(
            self.backend,
            variant,
            manifest,
            &self.gym.base_url,
            seed,
            &self.config,
        )
        .await?;
        Ok(Executed {
            rows,
            ledger,
            url_counters: None,
        })
    }
}

/// Build a `FakeScript` for `manifest`'s entry page: every control that exists without
/// preconditions is a node, controls with `requires` are revealed by their (last) prerequisite.
///
/// Node keys are the control ids; each carries `id=<control id>` so the driver can label it.
/// A control whose class is not `actionable` is omitted (it is not in the accessibility tree
/// of a covered/hidden/disabled control in a way the fake can model).
///
/// # Errors
/// Never fails today; the `Result` keeps the signature stable for fixtures that need I/O to script.
pub fn script_from_manifest(manifest: &FixtureManifest, base_url: &str) -> Result<FakeScript, BenchError> {
    let url = manifest.entry_url(base_url);
    let spec = |c: &crate::gym::manifest::ControlTruth, y: f64| {
        FakeAxSpec::new(
            c.id.clone(),
            if c.role == "generic" {
                "button"
            } else {
                c.role.as_str()
            },
        )
        .name(c.name.clone().unwrap_or_else(|| c.id.clone()))
        .attr("id", c.selector.trim_start_matches('#'))
        .bbox(10.0, y, 120.0, 24.0)
    };
    let mut page = FakePage::new(&url).title(manifest.title.clone());
    let mut y = 10.0;
    let mut hidden: BTreeMap<&str, Vec<FakeAxSpec>> = BTreeMap::new();
    for c in manifest
        .controls
        .iter()
        .filter(|c| c.expected == ExpectedClass::Actionable && c.page.is_none() && !c.stealth_only)
    {
        y += 30.0;
        match c.requires.last() {
            None => page = page.node(spec(c, y)),
            Some(gate) => hidden.entry(gate.as_str()).or_default().push(spec(c, y)),
        }
    }
    for (gate, nodes) in hidden {
        page = page.on_click(gate, vec![FakeEffect::Reveal(nodes)]);
    }
    let mut script = FakeScript::new();
    script = script.page(page);
    Ok(script)
}

/// Driver over a `FakeBackend` scripted from the manifest; the ledger is derived from the
/// fake's performed-action log (a simulated gym: every performed click is a trusted click).
pub struct FakeExecutor {
    /// Base URL of the simulated gym the manifest paths are resolved against (no network is contacted).
    pub base_url: String,
    /// Driver limits (action budget, layer cap, settle policy).
    pub config: DriverConfig,
}

#[async_trait]
impl VariantExecutor for FakeExecutor {
    async fn execute(
        &self,
        variant: &AblationVariant,
        manifest: &FixtureManifest,
        seed: u64,
    ) -> Result<Executed, BenchError> {
        let ledger = Arc::new(Ledger::default());
        if !variant.browser {
            return Ok(Executed {
                rows: RunRows::new(
                    &manifest.id,
                    seed,
                    variant.id,
                    crawlx_core::config::SafetyProfile::ReadOnly,
                ),
                ledger,
                url_counters: None,
            });
        }
        let script = script_from_manifest(manifest, &self.base_url)?;
        let backend = FakeBackend::new(script);
        let rows =
            driver::run_variant(&backend, variant, manifest, &self.base_url, seed, &self.config).await?;
        for handle in backend.context_handles() {
            for key in handle.performed_keys() {
                if let Some(id) = key.strip_prefix("click:") {
                    ledger.click(&manifest.id, id, true);
                }
            }
        }
        Ok(Executed {
            rows,
            ledger,
            url_counters: None,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn matrix_has_thirteen_variants_with_cumulative_capabilities() {
        let m = matrix();
        assert_eq!(m.len(), 13);
        assert_eq!(
            m.iter().map(|v| v.id).collect::<Vec<_>>(),
            ["A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12"]
        );
        assert!(!m[0].browser && m[1..].iter().all(|v| v.browser && v.ax));
        assert!(!m[1].listeners && m[2].listeners);
        assert!(!m[2].identity_container && m[3].identity_container && m[12].identity_container);
        assert!(m[4].w_only && !m[4].z && m[4].queue_active() && !m[3].queue_active());
        assert!(m[5].z && !m[5].e && m[6].z && m[6].e);
        assert!(!m[6].graph && m[7].graph && m[8].graph);
        assert!(!m[7].phase2 && m[8].phase2);
        assert!(!m[8].forms && m[9].forms);
        assert_eq!(m[9].model, System1Mode::Off);
        assert_eq!(m[10].model, System1Mode::Advisory);
        assert!(!m[10].multi_role && m[11].multi_role);
        assert_eq!(m[11].llm_planner, LlmPlannerMode::Off);
        assert_eq!(m[12].llm_planner, LlmPlannerMode::StalledOnly);
        // Variants A1..A7 are driver-runnable; A8..A12 need the worker.
        assert!(m[..8].iter().all(|v| v.needs_worker().is_none()));
        assert!(m[8..].iter().all(|v| v.needs_worker().is_some()));
        assert_eq!(find("a7").unwrap().id, "A7");
        assert!(find("A13").is_none());
    }

    #[test]
    fn apply_maps_variant_to_request() {
        let seed = url::Url::parse("http://127.0.0.1:1/g01/").unwrap();
        let mut req = CreateCrawl::new(seed);
        find("A0").unwrap().apply(&mut req);
        assert_eq!(req.mode, CrawlMode::Static);
        assert!(!req.dynamic.enabled);
        find("A12").unwrap().apply(&mut req);
        assert_eq!(req.mode, CrawlMode::Dynamic);
        assert_eq!(req.dynamic.llm_planner, LlmPlannerMode::StalledOnly);
        assert_eq!(req.dynamic.system1_mode, System1Mode::Advisory);
        assert!(req.dynamic.strategies.contains(&StrategyName::Enablement));
        assert_eq!(req.runs_per_role, 2);
    }
}
