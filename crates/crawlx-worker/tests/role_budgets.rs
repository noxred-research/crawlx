//! A low-demand role returns its unused slice; high-demand roles cannot
//! spend the quota reserved for later turns, including later rounds of the same role.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, Role, StrategyName};
use crawlx_core::proposal::ActionProposal;
use crawlx_core::repo::EventRepo;
use crawlx_core::CreateCrawl;
use crawlx_storage::MemoryStore;
use crawlx_strategies::{BfsConfig, DecisionContext, InteractionBfs, Strategy, StrategyError};
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

struct UnevenDemand(InteractionBfs);

#[async_trait]
impl Strategy for UnevenDemand {
    async fn propose(&self, ctx: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
        if ctx.principal.0 == "low" && ctx.stall.trusted_actions >= 1 {
            Ok(Vec::new())
        } else {
            self.0.propose(ctx).await
        }
    }

    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn version(&self) -> u32 {
        self.0.version()
    }
}

fn mesh() -> FakeScript {
    let path = |i| if i == 0 { "/".to_owned() } else { format!("/p{i}") };
    let mut script = FakeScript::new();
    for i in 0..8 {
        let mut page = FakePage::new(&format!("https://example.test{}", path(i))).title(format!("Page {i}"));
        for j in (0..8).filter(|j| *j != i) {
            let key = format!("to{j}");
            page = page
                .node(FakeAxSpec::link(key.clone(), format!("Go to {j}"), path(j)))
                .on_click(&key, vec![FakeEffect::Navigate(path(j))]);
        }
        script = script.page(page);
    }
    script
}

#[tokio::test]
async fn six_uneven_turns_redistribute_unused_interactions_without_starving_later_roles() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.dynamic.strategies = vec![StrategyName::InteractionBfs];
    crawl.seed = Some(2_021);
    crawl.runs_per_role = 3;
    crawl.limits.interactions = 23;
    crawl.limits.states = 1_000;
    crawl.roles = ["low", "high"]
        .into_iter()
        .map(|name| Role {
            name: name.to_owned(),
            credential_ref: None,
            login_plan: None,
            replica_base_url: None,
        })
        .collect();
    let config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(crawlx_fetch::StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let report = run_local_with(
        LocalRun::new(crawl, config)
            .with_stores(stores)
            .with_backend(Arc::new(FakeBackend::new(mesh())))
            .with_strategies(vec![Arc::new(UnevenDemand(InteractionBfs::new(
                BfsConfig::default(),
            )))]),
    )
    .await
    .unwrap();
    assert!(report.sessions.iter().all(|s| s.status.is_terminal()));
    let events = EventRepo::list_after(store.as_ref(), report.run_id, 0, 10_000)
        .await
        .unwrap();
    let allocations: Vec<_> = events.iter().filter(|e| e.kind == "session.budget").collect();
    assert_eq!(allocations.len(), 6);
    let mut sessions = report.sessions.clone();
    sessions.sort_by_key(|s| s.schedule_slot);
    let mut remaining = 23_u32;
    for (index, session) in sessions.iter().enumerate() {
        let event = allocations
            .iter()
            .find(|e| e.payload["session_id"] == session.id.0.to_string())
            .unwrap();
        let slice = u32::try_from(event.payload["interactions"].as_u64().unwrap()).unwrap();
        assert_eq!(
            slice,
            remaining.div_ceil(u32::try_from(sessions.len() - index).unwrap())
        );
        let used = report
            .actions
            .iter()
            .filter(|a| a.session == session.id && a.intended_at.is_some())
            .fold(0_u32, |n, a| n + u32::from(a.attempt.max(1)));
        assert!(
            used > 0 && used <= slice,
            "role {} round {}: {used}/{slice}",
            session.role.0,
            session.run_index
        );
        if session.role.0 == "low" {
            assert_eq!(used, 1, "low demand must leave quota for later roles");
        } else {
            assert_eq!(used, slice, "high demand must stop at its own slice");
        }
        remaining -= used;
    }
    assert_eq!(remaining, 0);
}
