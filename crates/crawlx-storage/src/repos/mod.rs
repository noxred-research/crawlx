//! Repositories of the `crawlx_core::repo` traits, generic over the storage engine.

pub mod api;
pub mod authorization;
mod checkpoint;
mod edge;
pub(crate) mod effects;
mod event;
mod frontier;
mod identity_alias;
pub mod inspect;
mod intel;
mod journal;
mod ledger;
mod model_decision;
mod page;
mod privacy;
mod run;
mod safety;
mod state;

pub(crate) use journal::{flip_intended_to_unknown, traffic_attribution};
pub(crate) use ledger::{key_from_row, KEY_COLS};
pub(crate) use safety::write_decision;
pub(crate) use state::{pick_successor, split_event};

use crate::codec::{conv, parse_label};
use crate::sql::SqlRow;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::repo::CrawlSession;
use crawlx_core::{CrawlRunId, PrincipalId, SessionId, StoreError};

/// Column list for `crawl_sessions` rows read by [`session_from_row`] (alias `s`).
pub(crate) const SESSION_COLS: &str = "s.session_id, s.run_id, s.session_kind, s.role, s.run_index, s.schedule_slot, s.status, \
    s.browser_build, s.cdp_revision, s.browser_user_agent, s.browser_pinned, s.launch_profile, s.console_capture, s.action_seq";

pub(crate) fn session_from_row<R: SqlRow>(r: &R) -> Result<CrawlSession, StoreError> {
    let browser = match r.opt_text("browser_build")? {
        Some(chromium_version) => Some(BrowserBuildInfo {
            chromium_version,
            cdp_revision: r.opt_text("cdp_revision")?.unwrap_or_default(),
            user_agent: r.opt_text("browser_user_agent")?.unwrap_or_default(),
            pinned: r.opt_bool("browser_pinned")?.unwrap_or(false),
            launch_profile: parse_label(&r.text("launch_profile")?)?,
            console_capture: r.bool("console_capture")?,
            // not persisted (no column yet); attached sessions are
            // worker-local and never pinned
            attached: false,
        }),
        None => None,
    };
    Ok(CrawlSession {
        id: SessionId(r.uuid("session_id")?),
        run: CrawlRunId(r.uuid("run_id")?),
        kind: parse_label(&r.text("session_kind")?)?,
        role: PrincipalId(r.text("role")?),
        run_index: conv(r.i32("run_index")?, "run_index")?,
        schedule_slot: conv(r.i32("schedule_slot")?, "schedule_slot")?,
        status: parse_label(&r.text("status")?)?,
        browser,
        action_seq: conv(r.i64("action_seq")?, "action_seq")?,
    })
}

/// `ON CONFLICT (target) DO UPDATE SET assignments` (`ON DUPLICATE KEY UPDATE` on MariaDB).
/// Assignments may use `Dialect::excluded` for the proposed value.
pub(crate) fn upsert_set<B: crate::backend::Backend>(target: &[&str], assignments: &str) -> String {
    if B::KIND == crate::backend::BackendKind::MariaDb {
        format!("ON DUPLICATE KEY UPDATE {assignments}")
    } else {
        format!("ON CONFLICT ({}) DO UPDATE SET {assignments}", target.join(", "))
    }
}

/// `now()` plus a whole number of hours, written the way each engine spells it. PostgreSQL
/// keeps `now() + interval 'N hours'`.
pub(crate) fn now_plus_hours<B: crate::backend::Backend>(hours: u32) -> String {
    let now = <B::Dialect as crate::backend::Dialect>::now();
    match B::KIND {
        crate::backend::BackendKind::Postgres => format!("{now} + interval '{hours} hours'"),
        crate::backend::BackendKind::MariaDb => format!("DATE_ADD({now}, INTERVAL {hours} HOUR)"),
        _ => format!("{now} + {}", u64::from(hours) * 3_600_000_000),
    }
}

/// The core repositories (runs, pages, states, edges, ledger, safety decisions, events,
/// checkpoints, identity aliases, model decisions) over one database of any engine, as trait
/// objects.
///
/// # Examples
///
/// ```ignore
/// let repos = CoreRepos::open(&database, None)?;
/// repos.runs.create(&run, None).await?;
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct CoreRepos {
    /// [`crawlx_core::repo::RunRepo`].
    pub runs: std::sync::Arc<dyn crawlx_core::repo::RunRepo>,
    /// [`crawlx_core::repo::PageRepo`].
    pub pages: std::sync::Arc<dyn crawlx_core::repo::PageRepo>,
    /// [`crawlx_core::repo::StateRepo`].
    pub states: std::sync::Arc<dyn crawlx_core::repo::StateRepo>,
    /// [`crawlx_core::repo::EdgeStore`].
    pub edges: std::sync::Arc<dyn crawlx_core::repo::EdgeStore>,
    /// [`crawlx_core::repo::LedgerRepo`].
    pub ledger: std::sync::Arc<dyn crawlx_core::repo::LedgerRepo>,
    /// [`crawlx_core::repo::SafetyAudit`].
    pub safety: std::sync::Arc<dyn crawlx_core::repo::SafetyAudit>,
    /// [`crawlx_core::repo::EventRepo`].
    pub events: std::sync::Arc<dyn crawlx_core::repo::EventRepo>,
    /// [`crawlx_core::repo::CheckpointRepo`].
    pub checkpoints: std::sync::Arc<dyn crawlx_core::repo::CheckpointRepo>,
    /// [`crawlx_core::repo::IdentityAliasRepo`].
    pub aliases: std::sync::Arc<dyn crawlx_core::repo::IdentityAliasRepo>,
    /// [`crawlx_core::repo::ModelDecisionRepo`].
    pub models: std::sync::Arc<dyn crawlx_core::repo::ModelDecisionRepo>,
}

impl std::fmt::Debug for CoreRepos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreRepos").finish_non_exhaustive()
    }
}

impl CoreRepos {
    fn over<B: crate::sql::Sql>(store: crate::store::Store<B>) -> Self {
        let store = std::sync::Arc::new(store);
        Self {
            runs: store.clone(),
            pages: store.clone(),
            states: store.clone(),
            edges: store.clone(),
            ledger: store.clone(),
            safety: store.clone(),
            events: store.clone(),
            checkpoints: store.clone(),
            aliases: store.clone(),
            models: store,
        }
    }

    /// The repositories of `database`. `delivery` is the volatile store zero-data-retention
    /// runs park their operational values in; without it such runs fail closed.
    ///
    /// # Errors
    /// Returns the `backend_unimplemented` refusal for an engine this build has no
    /// repositories for.
    pub fn open(
        database: &crate::backend::Database,
        delivery: Option<std::sync::Arc<crate::zdr::DeliveryBuffer>>,
    ) -> Result<Self, crate::backend::BackendRefusal> {
        fn attach<B: crate::sql::Sql>(
            store: &crate::store::Store<B>,
            delivery: Option<std::sync::Arc<crate::zdr::DeliveryBuffer>>,
        ) -> CoreRepos {
            let store = store.clone();
            CoreRepos::over(match delivery {
                Some(delivery) => store.with_delivery_buffer(delivery),
                None => store,
            })
        }
        if let Some(store) = database.as_postgres() {
            return Ok(attach(store, delivery));
        }
        if let Some(store) = database.as_mariadb() {
            return Ok(attach(store, delivery));
        }
        if let Some(store) = database.as_sqlite() {
            return Ok(attach(store, delivery));
        }
        Err(crate::backend::BackendRefusal::unimplemented(
            database.kind(),
            crate::backend::Feature::Repositories.name(),
        ))
    }

    /// The in-memory executable specification as a set of repositories.
    #[must_use]
    pub fn memory(store: std::sync::Arc<crate::memory::MemoryStore>) -> Self {
        Self {
            runs: store.clone(),
            pages: store.clone(),
            states: store.clone(),
            edges: store.clone(),
            ledger: store.clone(),
            safety: store.clone(),
            events: store.clone(),
            checkpoints: store.clone(),
            aliases: store.clone(),
            models: store,
        }
    }
}
