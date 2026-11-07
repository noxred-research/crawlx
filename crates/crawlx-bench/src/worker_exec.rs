//! Worker-driven runs: execute an ablation variant, or any gym fixture, through
//! `crawlx_worker::run_local_with` and turn the [`RunReport`] into scorecard rows.
//!
//! What the worker can and cannot be told: the request-level part of a variant
//! (`AblationVariant::apply`: mode, strategies, model, planner, roles) and the queue weights
//! (`AblationVariant::queue_cfg`: `Z` and `E` terms) reach the worker. Discovery rung and
//! container identity (A1–A3) are not worker options; those rows run through
//! [`crate::ablation::BrowserExecutor`] instead, and this executor refuses them.
//!
//! Authored component experiments use the private configured executor in this module's tests.
//! Their explicit test-only G1 status is not deployment admission or signed milestone evidence.

use crate::ablation::{AblationVariant, Executed, VariantExecutor};
use crate::error::BenchError;
use crate::gym::manifest::{FixtureManifest, Mechanism};
use crate::gym::server::GymHandle;
use crate::scorecard::{DiscoveredTarget, RunRows};
use async_trait::async_trait;
use crawlx_browser::launch::find_executable;
use crawlx_browser::LaunchConfig;
use crawlx_core::config::{CreateCrawl, SafetyProfile};
use crawlx_core::ids::AuthorizationRecordId;
use crawlx_fetch::StaticResolver;
use crawlx_strategies::frontier::QueueCfg;
use crawlx_url::TrailingSlash;
use crawlx_worker::{
    run_local_with, DriverConfig, EgressConfig, LocalRun, ModelConfig, RunReport, WorkerConfig,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Register a real verified authorization record for a fixture run's selected reference.
/// Explicit records and sources remain unchanged, including deliberately invalid ones.
#[must_use]
pub fn authorize_fixture(mut local: LocalRun) -> LocalRun {
    use crawlx_core::{Clock as _, SystemClock, TenantId};
    let Some(id) = local.crawl.safety.authorization_record_ref else {
        return local;
    };
    if local.authorization.is_some() || local.authorization_source.is_some() {
        return local;
    }
    let now = SystemClock.now();
    let tenant = local
        .stores
        .as_ref()
        .map_or_else(TenantId::new, |stores| stores.tenant);
    let origin = local.crawl.seed_url.origin().ascii_serialization();
    let mut record = crawlx_policy::testkit::sample_record(tenant, now, &[&origin]);
    record.id = id;
    record.verified_at = Some(now);
    record.test_accounts = local
        .crawl
        .roles
        .iter()
        .filter_map(|role| {
            role.credential_ref
                .as_ref()
                .map(|credential| crawlx_policy::authorization::TestAccount {
                    role: role.name.clone(),
                    credential_ref: credential.0.clone(),
                })
        })
        .collect();
    record
        .authorized_networks
        .push(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into());
    record
        .authorized_networks
        .push(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST).into());
    local.authorization = Some(record);
    local
}

impl AblationVariant {
    /// Queue weights of the row for the worker's `InteractionBfs` (`W` is always on).
    #[must_use]
    pub fn queue_cfg(&self) -> QueueCfg {
        QueueCfg {
            z_weight: if self.z { 0.3 } else { 0.0 },
            reveal_bonus: if self.e { 0.8 } else { 0.0 },
            ..QueueCfg::default()
        }
    }
}

/// A request for fixture `manifest` on the gym at `base_url`: seed = entry page, loopback
/// authorized (the fixture network), robots honored, safety `profile`.
///
/// # Errors
/// [`BenchError::Url`] when the entry URL does not parse.
pub fn crawl_request(
    manifest: &FixtureManifest,
    base_url: &str,
    seed: u64,
    profile: SafetyProfile,
) -> Result<CreateCrawl, BenchError> {
    let url = url::Url::parse(&manifest.entry_url(base_url))?;
    Ok(crawl_request_for_url(url, seed, profile))
}

/// Browser-plane strategies the gym measures: the production defaults plus the G1-gated
/// `state_novelty` and `enablement`. Gym runs request them explicitly because they are no
/// longer part of `dynamic.strategies`' default; they need authenticated G1 evidence.
pub const GYM_STRATEGIES: [crawlx_core::config::StrategyName; 4] = [
    crawlx_core::config::StrategyName::InteractionBfs,
    crawlx_core::config::StrategyName::EventDriven,
    crawlx_core::config::StrategyName::StateNovelty,
    crawlx_core::config::StrategyName::Enablement,
];

/// [`crawl_request`] for an arbitrary seed `url` (a recorded gym fixture, an operator-supplied
/// target): loopback and private networks authorized, robots honored, safety `profile`,
/// [`GYM_STRATEGIES`].
#[must_use]
pub fn crawl_request_for_url(url: url::Url, seed: u64, profile: SafetyProfile) -> CreateCrawl {
    let mut req = CreateCrawl::new(url);
    req.seed = Some(seed);
    req.safety.profile = profile;
    req.safety.allow_private_networks = true;
    req.safety.authorization_record_ref = Some(AuthorizationRecordId::new());
    req.politeness.delay_ms = 10;
    req.dynamic.strategies = GYM_STRATEGIES.to_vec();
    // Dropped (denied) actions no longer consume the interaction budget, so bound the wall clock too.
    req.limits.duration_seconds = 20;
    req
}

/// Worker configuration for gym runs: in-memory stores, Chromium from the environment (unpinned
/// allowed), loopback exempt, the manifest's trailing-slash policy, and authenticated deployment
/// gates loaded from the normal gate directory. Test fixtures must opt into their own test status.
///
/// # Errors
/// [`BenchError::Network`] only if the loopback network literal fails to parse.
pub fn worker_config(manifest: &FixtureManifest, artifacts: &Path) -> Result<WorkerConfig, BenchError> {
    worker_config_with(
        crate::urlplane::trailing_slash(manifest.expected.trailing_slash),
        artifacts,
    )
}

/// [`worker_config`] with an explicit trailing-slash policy, for targets that have no manifest.
///
/// # Errors
/// [`BenchError::Network`] only if the loopback network literal fails to parse.
pub fn worker_config_with(
    trailing_slash: TrailingSlash,
    artifacts: &Path,
) -> Result<WorkerConfig, BenchError> {
    let mut cfg = WorkerConfig {
        artifacts_dir: artifacts.to_path_buf(),
        trailing_slash,
        gates: crawlx_worker::Gates::load_default(),
        ..WorkerConfig::default()
    };
    if let Some(exe) = find_executable() {
        let mut launch = LaunchConfig::new();
        launch.executable = exe;
        launch.allow_unpinned = true;
        cfg.launch = launch;
    }
    cfg.egress = EgressConfig {
        extra_allow: vec!["127.0.0.1/32".parse()?],
        resolver: Some(Arc::new(StaticResolver::new())),
        ..EgressConfig::default()
    };
    Ok(cfg)
}

/// Rows of a worker run. The report carries actions, states and the enablement edges the
/// run learned but not the descriptors the harness would label, so discovery is the
/// ledger-confirmed lower bound: every control the gym saw a handler run for counts as found
/// (mechanism `ax`). `recorded_edges` are labelled through `element_labels`; callers that
/// know the identity-to-control map set it and call [`RunRows::label_recorded_edges`]
/// again (the quality gates do), otherwise the edges stay unlabelled and enablement recall
/// is reported as `n/a`.
#[must_use]
pub fn rows_from_report(
    report: &RunReport,
    manifest: &FixtureManifest,
    seed: u64,
    variant: &str,
    profile: SafetyProfile,
    gym: &GymHandle,
) -> RunRows {
    let mut rows = RunRows::new(&manifest.id, seed, variant, profile);
    rows.actions.clone_from(&report.actions);
    rows.edges.clone_from(&report.edges);
    rows.claimed.clone_from(&report.ledger);
    let prefix = format!("/{}", manifest.id);
    rows.state_assignments = report
        .states
        .iter()
        .map(|s| {
            let path = s.url.url.path();
            let rel = path.strip_prefix(prefix.as_str()).unwrap_or(path);
            let rel = if rel.is_empty() { "/" } else { rel };
            let label = match s.url.url.query() {
                Some(q) => format!("{rel}?{q}"),
                None => rel.to_owned(),
            };
            (label, s.cluster)
        })
        .collect();
    rows.discovered = gym
        .ledger()
        .clicked(&manifest.id)
        .into_iter()
        .map(|control| DiscoveredTarget {
            control: Some(control),
            mechanism: Mechanism::Ax,
        })
        .collect();
    rows.label_recorded_edges();
    rows
}

/// Executes variants through the worker against a live gym and real Chromium.
pub struct WorkerExecutor<'a> {
    /// Live gym the worker crawls; its ledger is the ground truth.
    pub gym: &'a GymHandle,
    /// Safety profile the crawl request runs under.
    pub profile: SafetyProfile,
    /// Interaction budget of the run.
    pub interactions: u32,
    /// Wall-clock limit of the run (`limits.duration_seconds`). Efficiency comparisons need it
    /// long enough not to truncate exploration: a run cut by the clock executes as many
    /// actions as its pace allows, so actions per target then measures speed.
    pub duration_seconds: u32,
    /// Root of the worker's filesystem artifact store for this run.
    pub artifacts: PathBuf,
    /// System 1 engine and ceiling for variants that ask for the model (A10 and later); `None`
    /// runs without one, which skips System 1 whatever the variant requests.
    pub model: Option<ModelConfig>,
}

#[async_trait]
impl VariantExecutor for WorkerExecutor<'_> {
    async fn execute(
        &self,
        variant: &AblationVariant,
        manifest: &FixtureManifest,
        seed: u64,
    ) -> Result<Executed, BenchError> {
        if variant.browser && !(variant.listeners && variant.queue_active()) {
            return Err(BenchError::Ablation(format!(
                "variant {} narrows discovery or has no queue frontier; the worker always runs the full ladder and the layered queue (use BrowserExecutor for A1-A3)",
                variant.id
            )));
        }
        let cfg = worker_config(manifest, &self.artifacts)?;
        self.execute_configured(variant, manifest, seed, cfg).await
    }
}

impl WorkerExecutor<'_> {
    // Keep authored fixture configuration private; public execution always loads deployment gates.
    async fn execute_configured(
        &self,
        variant: &AblationVariant,
        manifest: &FixtureManifest,
        seed: u64,
        mut cfg: WorkerConfig,
    ) -> Result<Executed, BenchError> {
        self.gym.reset(seed);
        let mut req = crawl_request(manifest, &self.gym.base_url, seed, self.profile)?;
        variant.apply(&mut req);
        req.limits.interactions = self.interactions;
        req.limits.duration_seconds = self.duration_seconds;
        req.limits.urls = 200;
        cfg.model.clone_from(&self.model);
        let mut driver = DriverConfig::default();
        driver.exploration.queue = variant.queue_cfg();
        let report = run_local_with(authorize_fixture(LocalRun::new(req, cfg).with_driver(driver))).await?;
        if report.status == crawlx_core::counters::RunStatus::Failed {
            return Err(BenchError::Ablation(format!(
                "fixture {} variant {} failed: {:?}",
                manifest.id, variant.id, report.terminal_reason
            )));
        }
        let rows = rows_from_report(&report, manifest, seed, variant.id, self.profile, self.gym);
        Ok(Executed {
            rows,
            ledger: self.gym.ledger(),
            url_counters: (!variant.browser).then_some(report.counters.urls),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::ablation::{self, AblationRunner, Efficiency};
    use crate::gym::GymServer;

    struct AuthoredExecutor<'a>(WorkerExecutor<'a>);

    #[async_trait]
    impl VariantExecutor for AuthoredExecutor<'_> {
        async fn execute(
            &self,
            variant: &AblationVariant,
            manifest: &FixtureManifest,
            seed: u64,
        ) -> Result<Executed, BenchError> {
            let mut cfg = worker_config(manifest, &self.0.artifacts)?;
            cfg.gates =
                crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus { g1: true, g3: false });
            self.0.execute_configured(variant, manifest, seed, cfg).await
        }
    }

    /// Efficiency: both real worker arms receive the same action and clock budgets.
    /// This authored fixture experiment exercises gated code without claiming G1 promotion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a8_pathfinding_reaches_hidden_targets_at_least_as_efficiently_as_a7() {
        if find_executable().is_none() {
            eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
            return;
        }
        let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (a7, a8) = (ablation::find("A7").unwrap(), ablation::find("A8").unwrap());
        assert!(!a7
            .strategies
            .contains(&crawlx_core::config::StrategyName::Enablement));
        assert!(a8
            .strategies
            .contains(&crawlx_core::config::StrategyName::Enablement));
        let seeds = [1u64, 2];
        let mut comparable = 0;
        for id in ["g21", "g13"] {
            let manifest = FixtureManifest::embedded(id).unwrap();
            let executor = AuthoredExecutor(WorkerExecutor {
                gym: &gym,
                profile: SafetyProfile::TestEnvironment,
                interactions: 60,
                // Keep the clock nonbinding; both arms may spend the same interaction budget.
                duration_seconds: 180,
                artifacts: dir.path().join(id),
                model: None,
            });
            let runner = AblationRunner::new(&executor);
            let (report, paired) = runner.run_paired(&a7, &a8, &manifest, &seeds).await.unwrap();
            eprintln!("{}", report.render_markdown());
            eprintln!("{}", paired.render_markdown());
            let means = report.efficiency_means();
            let of = |v: &str| -> (Option<f64>, Option<f64>) {
                let (_, recall, per) = means.iter().find(|(m, _, _)| *m == v).unwrap();
                (*recall, *per)
            };
            let (a7_recall, a7_per) = of("A7");
            let (a8_recall, a8_per) = of("A8");
            eprintln!("{id}: A7 hidden recall {a7_recall:?} actions/hidden {a7_per:?}; A8 hidden recall {a8_recall:?} actions/hidden {a8_per:?}");
            for o in &report.outcomes {
                let e: &Efficiency = &o.efficiency;
                assert_eq!(o.scorecard.safety.unauthorized, 0);
                assert!(e.hidden_total > 0, "{id} has hidden targets");
                assert!(
                    e.actions > 0,
                    "{id} {} seed {}: no executed action",
                    o.variant,
                    o.seed
                );
            }
            let (a7_recall, a8_recall) = (a7_recall.unwrap(), a8_recall.unwrap());
            assert!(
                a8_recall >= a7_recall,
                "{id}: A8 hidden recall {a8_recall} < A7 {a7_recall}"
            );
            let (Some(a7_per), Some(a8_per)) = (a7_per, a8_per) else {
                eprintln!("{id}: not comparable (a row reached no hidden target)");
                continue;
            };
            comparable += 1;
            assert!(
                a8_per <= a7_per,
                "{id}: A8 actions per hidden target {a8_per} > A7 {a7_per}"
            );
        }
        assert!(comparable >= 1, "no fixture had a defined ratio for both rows");
        gym.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refused_g1_run_returns_failure_instead_of_empty_coverage() {
        if find_executable().is_none() {
            return;
        }
        let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let executor = WorkerExecutor {
            gym: &gym,
            profile: SafetyProfile::TestEnvironment,
            interactions: 10,
            duration_seconds: 20,
            artifacts: dir.path().to_path_buf(),
            model: None,
        };
        let manifest = FixtureManifest::embedded("g21").unwrap();
        let variant = ablation::find("A8").unwrap();
        let mut cfg = worker_config(&manifest, dir.path()).unwrap();
        cfg.gates = crawlx_worker::Gates::none();
        let result = executor.execute_configured(&variant, &manifest, 1, cfg).await;
        // Admission now refuses the gated strategy before a run exists (no empty success).
        assert!(
            matches!(&result, Err(BenchError::Worker(error)) if error.to_string().contains("G1")),
            "expected a G1 admission refusal, got {:?}",
            result.as_ref().err()
        );
        assert!(gym.ledger().clicked("g21").is_empty());
        gym.shutdown().await;
    }
}
