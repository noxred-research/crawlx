//! `crawlx admin` operator commands of the runbooks (`docs/ops/runbooks.md`, RB-01..RB-11) and the
//! strangler engine flag, over PostgreSQL through
//! [`crawlx_storage::AdminOps`]. Ordinary mutations are written to the hash-chained admin audit
//! log as `admin:<operator>` (`--operator`, else `$USER`). The independent safety auditor uses
//! separate limited reader and pause connections, never the operator connection.
//!
//! RB-11 emergency stop: `crawlx admin freeze --all` = `pause --all` + `scheduler.admission =
//! frozen`; `crawlx admin resume --all --admission` reverses both.

use crate::inspect::connect;
use anyhow::{anyhow, bail, Context as _};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand, ValueEnum};
use crawlx_core::{ActionId, CrawlRunId, SystemClock, TenantId, WorkerId};
use crawlx_storage::{
    AdminOps, AdmissionMode, ArtifactBlobs, FsArtifactStore, FsBlobs, Pg, RetentionSweeper, RunSelector,
    S3ArtifactStore, S3Blobs, S3Config, SafetyAuditor, TenantEngine,
};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

/// Connection and operator identity shared by every operator command.
#[derive(Args, Debug)]
pub struct AdminCommon {
    #[arg(long, env = "CRAWLX_DATABASE_URL", global = true)]
    /// Database url (or `CRAWLX_DATABASE_URL_FILE` / `database.url_file`).
    pub database_url: Option<String>,
    /// Operator name recorded in the admin audit log; `$USER` when omitted.
    #[arg(long, env = "CRAWLX_OPERATOR", global = true)]
    pub operator: Option<String>,
}

impl AdminCommon {
    async fn ops(&self) -> anyhow::Result<(Pg, String)> {
        let url = crate::config_check::database_url(self.database_url.as_deref())?;
        let pg = connect(url.as_deref()).await?;
        let operator = self
            .operator
            .clone()
            .or_else(|| std::env::var("USER").ok())
            .unwrap_or_else(|| "unknown".to_owned());
        Ok((pg, operator))
    }
}

/// `--crawl <id> | --tenant <id> | --all`.
#[derive(Args, Debug)]
pub struct Selector {
    /// One crawl run id.
    #[arg(long, value_name = "RUN_ID", conflicts_with_all = ["tenant", "all"])]
    pub crawl: Option<String>,
    /// Every run of one tenant.
    #[arg(long, value_name = "TENANT_ID", conflicts_with = "all")]
    pub tenant: Option<String>,
    /// Every run.
    #[arg(long)]
    pub all: bool,
}

impl Selector {
    fn resolve(&self) -> anyhow::Result<RunSelector> {
        if let Some(c) = &self.crawl {
            return Ok(RunSelector::Crawl(parse_id(c, "run")?));
        }
        if let Some(t) = &self.tenant {
            return Ok(RunSelector::Tenant(parse_id(t, "tenant")?));
        }
        if self.all {
            return Ok(RunSelector::All);
        }
        bail!("pass one of --crawl <id>, --tenant <id> or --all")
    }
}

fn parse_id<T: From<uuid::Uuid>>(s: &str, what: &str) -> anyhow::Result<T> {
    let u: uuid::Uuid = s.parse().map_err(|e| anyhow!("{s:?} is not a {what} id: {e}"))?;
    Ok(T::from(u))
}

/// `crawlx admin pause`.
#[derive(Args, Debug)]
pub struct PauseArgs {
    #[command(flatten)]
    /// Selector.
    pub sel: Selector,
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// `crawlx admin resume`.
#[derive(Args, Debug)]
pub struct ResumeArgs {
    #[command(flatten)]
    /// Selector.
    pub sel: Selector,
    /// Also set `scheduler.admission = open` (undo `freeze` / `drain --admission`).
    #[arg(long)]
    pub admission: bool,
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// Terminal reason of `crawlx admin cancel`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum CancelReason {
    /// Operator decision.
    Cancelled,
    /// Safety-related stop (RB-10, RB-11).
    PolicyStopped,
}

/// `crawlx admin cancel`.
#[derive(Args, Debug)]
pub struct CancelArgs {
    #[command(flatten)]
    /// Selector.
    pub sel: Selector,
    /// Terminal reason recorded on the runs.
    #[arg(long, value_enum, default_value = "cancelled")]
    pub reason: CancelReason,
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// `crawlx admin drain`.
#[derive(Args, Debug)]
pub struct DrainArgs {
    /// Worker id to drain (`workers.worker_id`; see `crawlx admin workers`).
    #[arg(
        long,
        value_name = "WORKER_ID",
        conflicts_with = "admission",
        required_unless_present = "admission"
    )]
    pub worker: Option<String>,
    /// Instead of one worker, set `scheduler.admission = drain`: no new leases anywhere (RB-04, RB-07).
    #[arg(long)]
    pub admission: bool,
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// `crawlx admin freeze` (RB-11 level 2).
#[derive(Args, Debug)]
pub struct FreezeArgs {
    /// Also pause every running crawl (`freeze --all` is the emergency stop).
    #[arg(long)]
    pub all: bool,
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// `crawlx admin reconcile` (RB-02).
#[derive(Args, Debug)]
pub struct ReconcileArgs {
    /// `unknown` action to hand to the reconciler; without it, list the open rows.
    #[arg(long, value_name = "ACTION_ID")]
    pub action: Option<String>,
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// Object store selection shared by `verify-artifacts` and `sweep-retention`.
#[derive(Args, Debug)]
pub struct StoreArgs {
    /// Filesystem artifact store root (what `serve`/`worker --artifacts-dir` use).
    #[arg(
        long,
        default_value = "./crawlx-artifacts",
        value_name = "DIR",
        conflicts_with = "s3_bucket"
    )]
    pub artifacts_dir: PathBuf,
    /// S3-compatible bucket instead (`CRAWLX_S3_*` for region/endpoint/path style).
    #[arg(long, value_name = "BUCKET")]
    pub s3_bucket: Option<String>,
}

impl StoreArgs {
    async fn blobs(&self) -> anyhow::Result<Arc<dyn ArtifactBlobs>> {
        if let Some(bucket) = &self.s3_bucket {
            return Ok(Arc::new(S3Blobs::new(&s3_config(bucket)?)));
        }
        Ok(Arc::new(FsBlobs::open(&self.artifacts_dir).await.with_context(
            || format!("opening {}", self.artifacts_dir.display()),
        )?))
    }
}

fn s3_config(bucket: &str) -> anyhow::Result<S3Config> {
    let mut cfg = match S3Config::from_env() {
        Ok(cfg) => cfg,
        Err(_) => S3Config::new(
            bucket.to_owned(),
            std::env::var("CRAWLX_S3_REGION").unwrap_or_else(|_| "us-east-1".to_owned()),
        ),
    };
    cfg.bucket = bucket.to_owned();
    Ok(cfg)
}

/// `crawlx admin verify-artifacts` (RB-06 step 6).
#[derive(Args, Debug)]
pub struct VerifyArtifactsArgs {
    /// Only rows created at or after this RFC 3339 timestamp (the outage start).
    #[arg(long, value_name = "RFC3339")]
    pub since: Option<DateTime<Utc>>,
    #[command(flatten)]
    /// Store.
    pub store: StoreArgs,
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// `--mode` of `sweep-retention`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum SweepMode {
    /// Expired artifacts, pages and purged runs of every retention mode.
    All,
    /// Only runs with `retention_mode = zdr` (RB-08 step 3; implies the content-first order).
    Zdr,
}

/// `crawlx admin sweep-retention` (RB-08).
#[derive(Args, Debug)]
pub struct SweepRetentionArgs {
    /// What to sweep.
    #[arg(long, value_enum, default_value = "all")]
    pub mode: SweepMode,
    /// Required with `--mode zdr`: delete the content objects of every ZDR run **now**, then
    /// the rows, keeping the structural trail (RB-08 step 3). Recorded in the audit log.
    #[arg(long)]
    pub force: bool,
    /// Also collect orphan objects older than this many seconds.
    #[arg(long, value_name = "SECONDS")]
    pub orphan_grace_s: Option<u64>,
    #[command(flatten)]
    /// Store.
    pub store: StoreArgs,
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// `crawlx admin durability-audit`.
#[derive(Args, Debug)]
pub struct DurabilityAuditArgs {
    /// Only accept-log rows at or after this RFC 3339 timestamp (the outage start).
    #[arg(long, value_name = "RFC3339")]
    pub since: Option<DateTime<Utc>>,
    /// Print one JSON object (`checked`, `missing`, `since`) instead of text.
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// `crawlx admin engine` (per-tenant rollback flag).
#[derive(Args, Debug)]
pub struct EngineArgs {
    /// Tenant id.
    #[arg(long, value_name = "TENANT_ID")]
    pub tenant: String,
    /// New engine; omit to print the current one.
    #[arg(long, value_enum)]
    pub set: Option<EngineArg>,
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// `--set` of `engine`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum EngineArg {
    /// crawlx serves the tenant.
    Crawlx,
    /// The upstream service serves the tenant; crawlx refuses non-shadow compat creates.
    Upstream,
    /// Only mirrored (`X-Crawlx-Shadow: 1`) requests are accepted.
    Shadow,
}

impl From<EngineArg> for TenantEngine {
    fn from(e: EngineArg) -> Self {
        match e {
            EngineArg::Crawlx => Self::Crawlx,
            EngineArg::Upstream => Self::Upstream,
            EngineArg::Shadow => Self::Shadow,
        }
    }
}

/// `crawlx admin workers`.
#[derive(Args, Debug)]
pub struct WorkersArgs {
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// `crawlx admin status`.
#[derive(Args, Debug)]
pub struct StatusArgs {
    #[command(flatten)]
    /// Connection.
    pub common: AdminCommon,
}

/// `crawlx admin safety-audit`, using two independent least-privilege credentials.
#[derive(Args, Debug)]
pub struct SafetyAuditArgs {
    /// Read-only auditor login; never falls back to the operator or worker database URL.
    #[arg(long, env = "CRAWLX_SAFETY_READER_DATABASE_URL", hide_env_values = true)]
    pub reader_database_url: String,
    /// Distinct login with only the safety pause capability.
    #[arg(long, env = "CRAWLX_SAFETY_PAUSE_DATABASE_URL", hide_env_values = true)]
    pub pause_database_url: String,
    /// Emit the full safety audit report as JSON.
    #[arg(long)]
    pub json: bool,
}

/// The operator subcommands.
#[derive(Subcommand, Debug)]
pub enum OpsCommand {
    /// Pause running crawls (`--crawl`, `--tenant`, `--all`); actors stop at the next action boundary.
    Pause(PauseArgs),
    /// Resume paused crawls; `--admission` also reopens the scheduler.
    Resume(ResumeArgs),
    /// Cancel crawls with `cancelled` or `policy_stopped`.
    Cancel(CancelArgs),
    /// Drain one worker (`--worker`) or set `scheduler.admission = drain` (`--admission`).
    Drain(DrainArgs),
    /// Emergency stop (RB-11): `scheduler.admission = frozen`; `--all` also pauses every crawl.
    Freeze(FreezeArgs),
    /// Hand an `unknown` action's session to the reconciler, or list open `intended`/`unknown` rows.
    Reconcile(ReconcileArgs),
    /// Check every live artifact row against the object store (missing object, digest mismatch, orphans).
    VerifyArtifacts(VerifyArtifactsArgs),
    /// Run the retention sweeper now; `--mode zdr --force` deletes ZDR content first (RB-08).
    SweepRetention(SweepRetentionArgs),
    /// Expire shared ephemeral delivery pages and crash leftovers; does not access the database.
    SweepDelivery,
    /// Accepted crawl-job durability audit: every `crawl.accepted` accept-log
    /// row must still have its `crawl_runs` row. SLO = 1 − missing / checked; any missing
    /// row is SEV-1 and exits 1.
    DurabilityAudit(DurabilityAuditArgs),
    /// Independently check action safety evidence and pause violating runs; exit 1 on violations.
    SafetyAudit(SafetyAuditArgs),
    /// Show or set a tenant's `engine` flag (crawlx | upstream | shadow).
    Engine(EngineArgs),
    /// List registered workers, their heartbeat, draining flag and held leases.
    Workers(WorkersArgs),
    /// Admission mode, active crawls and open `intended`/`unknown` actions at a glance.
    Status(StatusArgs),
}

pub(crate) async fn run(cmd: OpsCommand, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    match cmd {
        OpsCommand::SafetyAudit(a) => safety_audit(a, out).await,
        OpsCommand::Pause(a) => {
            let sel = a.sel.resolve()?;
            let (pg, op) = a.common.ops().await?;
            let runs = AdminOps::new(&pg, &op).pause(sel).await?;
            report_runs(out, "paused", &runs)
        }
        OpsCommand::Resume(a) => {
            let sel = a.sel.resolve()?;
            let (pg, op) = a.common.ops().await?;
            let ops = AdminOps::new(&pg, &op);
            if a.admission {
                let before = ops.set_admission(AdmissionMode::Open).await?;
                writeln!(out, "scheduler.admission: {before} -> open")?;
            }
            let runs = ops.resume(sel).await?;
            report_runs(out, "resumed", &runs)
        }
        OpsCommand::Cancel(a) => {
            let sel = a.sel.resolve()?;
            let (pg, op) = a.common.ops().await?;
            let reason = match a.reason {
                CancelReason::Cancelled => "cancelled",
                CancelReason::PolicyStopped => "policy_stopped",
            };
            let runs = AdminOps::new(&pg, &op).cancel(sel, reason).await?;
            report_runs(out, reason, &runs)
        }
        OpsCommand::Drain(a) => {
            let (pg, op) = a.common.ops().await?;
            let ops = AdminOps::new(&pg, &op);
            if a.admission {
                let before = ops.set_admission(AdmissionMode::Drain).await?;
                writeln!(out, "scheduler.admission: {before} -> drain")?;
                return Ok(ExitCode::SUCCESS);
            }
            let worker: WorkerId = parse_id(a.worker.as_deref().unwrap_or_default(), "worker")?;
            let held = ops.drain_worker(worker).await?;
            writeln!(
                out,
                "worker {worker} draining: no new leases from its next heartbeat; {held} session lease(s) hand over at their next action boundary"
            )?;
            Ok(ExitCode::SUCCESS)
        }
        OpsCommand::Freeze(a) => {
            let (pg, op) = a.common.ops().await?;
            let ops = AdminOps::new(&pg, &op);
            let before = ops.set_admission(AdmissionMode::Frozen).await?;
            writeln!(
                out,
                "scheduler.admission: {before} -> frozen (no new leases; actors halt at their next boundary)"
            )?;
            if a.all {
                let runs = ops.pause(RunSelector::All).await?;
                report_runs(out, "paused", &runs)?;
            }
            writeln!(out, "resume with: crawlx admin resume --all --admission")?;
            Ok(ExitCode::SUCCESS)
        }
        OpsCommand::Reconcile(a) => {
            let (pg, op) = a.common.ops().await?;
            let ops = AdminOps::new(&pg, &op);
            match a.action.as_deref() {
                Some(id) => {
                    let action: ActionId = parse_id(id, "action")?;
                    let status = ops.request_reconcile(action).await?;
                    writeln!(
                        out,
                        "action {action}: session is `{status}`; the next worker to claim it restores the checkpoint and reconciles (RB-02 step 3)"
                    )?;
                }
                None => {
                    let rows = ops.open_actions(None).await?;
                    writeln!(out, "{} open action(s)", rows.len())?;
                    for r in rows {
                        writeln!(
                            out,
                            "{}\t{}\trun={}\tsession={} ({})\tintended_at={}",
                            r.id,
                            r.status,
                            r.run,
                            r.session,
                            r.session_status,
                            r.intended_at.map_or_else(|| "-".to_owned(), |t| t.to_rfc3339())
                        )?;
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        OpsCommand::VerifyArtifacts(a) => {
            let (pg, op) = a.common.ops().await?;
            let blobs = a.store.blobs().await?;
            let v = AdminOps::new(&pg, &op)
                .verify_artifacts(blobs.as_ref(), a.since)
                .await?;
            writeln!(
                out,
                "checked {} artifact row(s): {} defect(s), {} orphan object(s)",
                v.checked,
                v.defects.len(),
                v.orphans
            )?;
            for d in &v.defects {
                writeln!(
                    out,
                    "{}\t{}\trun={}\t{}",
                    d.defect, d.artifact_id, d.run, d.object_key
                )?;
            }
            Ok(if v.defects.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        OpsCommand::SweepRetention(a) => sweep_retention(a, out).await,
        OpsCommand::SweepDelivery => {
            let clock: Arc<dyn crawlx_core::Clock> = Arc::new(SystemClock);
            let buffer = crawlx_storage::DeliveryBuffer::open_runtime(
                clock.clone(),
                crawlx_storage::BufferLimits::default(),
            )
            .await?;
            if !buffer.is_enabled() {
                writeln!(out, "delivery_backend=disabled")?;
                return Ok(ExitCode::SUCCESS);
            }
            let removed = buffer.sweep(clock.now()).await?;
            writeln!(out, "expired_delivery_pages={removed}")?;
            Ok(ExitCode::SUCCESS)
        }
        OpsCommand::DurabilityAudit(a) => durability_audit(a, out).await,
        OpsCommand::Engine(a) => {
            let tenant: TenantId = parse_id(&a.tenant, "tenant")?;
            let (pg, op) = a.common.ops().await?;
            match a.set {
                Some(engine) => {
                    let before = AdminOps::new(&pg, &op)
                        .set_tenant_engine(tenant, engine.into())
                        .await?;
                    writeln!(
                        out,
                        "tenant {tenant} engine: {before} -> {}",
                        TenantEngine::from(engine)
                    )?;
                }
                None => {
                    let engine = crawlx_storage::admin::tenant_engine_of(&pg, tenant)
                        .await?
                        .ok_or_else(|| anyhow!("tenant {tenant} does not exist"))?;
                    writeln!(out, "tenant {tenant} engine: {engine}")?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        OpsCommand::Workers(a) => {
            let (pg, op) = a.common.ops().await?;
            let rows = AdminOps::new(&pg, &op).workers().await?;
            writeln!(
                out,
                "worker_id\thostname\tversion\tdraining\tleases\tlast_heartbeat"
            )?;
            for w in rows {
                writeln!(
                    out,
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    w.id,
                    w.hostname,
                    w.version,
                    w.draining,
                    w.leases_held,
                    w.last_heartbeat_at.to_rfc3339()
                )?;
            }
            Ok(ExitCode::SUCCESS)
        }
        OpsCommand::Status(a) => {
            let (pg, op) = a.common.ops().await?;
            let ops = AdminOps::new(&pg, &op);
            let admission = ops.admission().await?;
            let open = ops.open_actions(None).await?;
            let workers = ops.workers().await?;
            let active: i64 = sqlx_count(&pg).await?;
            writeln!(out, "scheduler.admission: {admission}")?;
            writeln!(out, "active crawls: {active}")?;
            writeln!(
                out,
                "workers: {} ({} draining)",
                workers.len(),
                workers.iter().filter(|w| w.draining).count()
            )?;
            writeln!(
                out,
                "open actions: {} intended, {} unknown",
                open.iter().filter(|a| a.status == "intended").count(),
                open.iter().filter(|a| a.status == "unknown").count()
            )?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn sqlx_count(pg: &Pg) -> anyhow::Result<i64> {
    crawlx_storage::admin::active_run_count(pg)
        .await
        .map_err(|e| anyhow!("counting active runs: {e}"))
}

fn report_runs(out: &mut dyn Write, verb: &str, runs: &[CrawlRunId]) -> anyhow::Result<ExitCode> {
    writeln!(out, "{verb}: {} run(s)", runs.len())?;
    for r in runs {
        writeln!(out, "{r}")?;
    }
    Ok(ExitCode::SUCCESS)
}

async fn sweep_retention(a: SweepRetentionArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let (pg, op) = a.common.ops().await?;
    let clock = Arc::new(SystemClock);
    let runs: Arc<dyn crawlx_core::repo::RunRepo> = Arc::new(pg.clone());
    let reaper: Arc<dyn crawlx_storage::ArtifactReaper> = match &a.store.s3_bucket {
        Some(bucket) => Arc::new(
            S3ArtifactStore::new(S3Blobs::new(&s3_config(bucket)?), runs, clock)
                .with_index(Arc::new(pg.clone())),
        ),
        None => Arc::new(
            FsArtifactStore::open(&a.store.artifacts_dir, runs, clock)
                .await?
                .with_index(Arc::new(pg.clone())),
        ),
    };
    let mut sweeper = RetentionSweeper::new(pg.clone()).with_artifacts(reaper);
    if let Some(secs) = a.orphan_grace_s {
        sweeper = sweeper.with_orphan_grace(chrono::Duration::seconds(i64::try_from(secs)?));
    }
    let now = pg.db_now().await?;
    match a.mode {
        SweepMode::All => {
            let r = sweeper.sweep(now).await?;
            writeln!(
                out,
                "swept: {} artifact use(s), {} orphan(s), {} page(s), {} run(s) purged ({} rows)",
                r.artifacts_deleted, r.orphans_collected, r.pages_deleted, r.runs_purged, r.rows_deleted
            )?;
        }
        SweepMode::Zdr => {
            if !a.force {
                bail!("--mode zdr deletes ZDR content immediately; pass --force to confirm (RB-08 step 3)");
            }
            let purged =
                crawlx_storage::admin::force_zdr_sweep(&pg, &sweeper, &format!("admin:{op}")).await?;
            writeln!(out, "zdr: {} run(s) purged, structural trail kept", purged.len())?;
            for r in purged {
                writeln!(out, "{r}")?;
            }
        }
    }
    let overdue = sweeper.overdue_artifacts(now).await?;
    for kind in ["standard", "extended", "zdr"] {
        writeln!(out, "overdue {kind}: {}", overdue.get(kind).copied().unwrap_or(0))?;
    }
    Ok(ExitCode::SUCCESS)
}

/// `crawlx admin durability-audit`: compare the API's append-only accept log
/// against `crawl_runs`, move the two audit counters and fail when any accepted run is gone.
async fn durability_audit(a: DurabilityAuditArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let (pg, op) = a.common.ops().await?;
    let audit = AdminOps::new(&pg, &op).durability_audit(a.since).await?;
    let missing = u64::try_from(audit.missing.len()).unwrap_or(u64::MAX);
    let metrics = Metrics::global();
    metrics
        .counter(names::JOBS_DURABILITY_AUDIT_CHECKED)
        .inc_by(audit.checked, &[]);
    metrics
        .counter(names::JOBS_DURABILITY_AUDIT_MISSING)
        .inc_by(missing, &[]);
    if a.json {
        writeln!(
            out,
            "{}",
            serde_json::json!({ "checked": audit.checked, "missing": audit.missing, "since": a.since })
        )?;
    } else {
        writeln!(out, "checked {} missing {missing}", audit.checked)?;
        for run in &audit.missing {
            writeln!(out, "missing {run}")?;
        }
    }
    Ok(if audit.missing.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

async fn safety_audit(a: SafetyAuditArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let auditor = SafetyAuditor::connect(&a.reader_database_url, &a.pause_database_url).await?;
    let report = auditor.audit().await?;
    let counter = Metrics::global().counter(names::SAFETY_INVARIANT_VIOLATIONS);
    for violation in &report.violations {
        counter.inc_by(1, &[("reason", violation.reason.as_str())]);
    }
    if a.json {
        serde_json::to_writer(&mut *out, &report)?;
        writeln!(out)?;
    } else {
        writeln!(
            out,
            "checked {} violations {} paused {}",
            report.checked,
            report.violations.len(),
            report.paused.len()
        )?;
        for violation in &report.violations {
            writeln!(
                out,
                "tenant {} run {} action {}: {}",
                violation.tenant, violation.run, violation.action, violation.reason
            )?;
        }
        for run in &report.paused {
            writeln!(out, "paused {run}")?;
        }
    }
    Ok(if report.violations.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use clap::Parser;

    #[test]
    fn safety_audit_requires_independent_database_arguments() {
        let parsed = crate::Cli::try_parse_from([
            "crawlx",
            "admin",
            "safety-audit",
            "--reader-database-url",
            "postgres://reader@localhost/crawlx",
            "--pause-database-url",
            "postgres://pauser@localhost/crawlx",
            "--json",
        ])
        .unwrap();
        let crate::Command::Admin(admin) = parsed.command else {
            panic!("expected admin");
        };
        let crate::AdminCommand::Ops(OpsCommand::SafetyAudit(args)) = admin.command else {
            panic!("expected safety-audit");
        };
        assert_eq!(args.reader_database_url, "postgres://reader@localhost/crawlx");
        assert_eq!(args.pause_database_url, "postgres://pauser@localhost/crawlx");
        assert!(args.json);
        assert!(crate::Cli::try_parse_from([
            "crawlx",
            "admin",
            "safety-audit",
            "--database-url",
            "postgres://worker@localhost/crawlx",
        ])
        .is_err());
    }
}
