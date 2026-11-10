//! `crawlx inspect`: read a stored run from PostgreSQL.

use anyhow::{anyhow, Context as _};
use clap::{Args, ValueEnum};
use crawlx_core::counters::ActionStatus;
use crawlx_core::repo::{ActionJournal, ArtifactStore, PageRepo, RunRepo, StateRepo};
use crawlx_core::{CrawlRunId, Timestamp, TrustLane};
use crawlx_storage::trusted::{CoverageRow, LaneFilter, TrafficQuery, TrustedCorpus};
use crawlx_storage::{FsArtifactStore, InspectRepo, Pg, PgConfig, S3ArtifactStore, S3Blobs, S3Config};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

/// What to inspect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum InspectKind {
    /// Run.
    Run,
    /// Pages.
    Pages,
    /// States.
    States,
    /// Epochs.
    Epochs,
    /// Actions.
    Actions,
    /// Transitions.
    Transitions,
    /// Coverage.
    Coverage,
    /// Traffic.
    Traffic,
    /// Trail verifier: check every stored state and correctness invariant.
    /// Exits 1 for violations or unverifiable evidence, including unavailable ZDR content.
    Trail,
}

/// `--lane`: the lanes a corpus read admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum LaneArg {
    /// Only `trusted_ui` rows.
    TrustedUi,
    /// Only `diagnostic` rows.
    Diagnostic,
    /// Both lanes.
    All,
}

impl From<LaneArg> for LaneFilter {
    fn from(lane: LaneArg) -> Self {
        match lane {
            LaneArg::TrustedUi => Self::TrustedUi,
            LaneArg::Diagnostic => Self::Diagnostic,
            LaneArg::All => Self::Both,
        }
    }
}

/// Arguments of `crawlx inspect`.
#[derive(Args, Debug)]
pub struct InspectArgs {
    /// What to print.
    #[arg(value_enum)]
    pub kind: InspectKind,
    /// Run id (UUID).
    pub run_id: String,
    /// `actions`: only this status (`proposed|intended|succeeded|failed|unknown|reconciled`);
    /// the bare flag lists every status.
    #[arg(long, value_name = "STATUS", num_args = 0..=1, value_parser = clap::value_parser!(ActionStatus))]
    pub status: Option<Option<ActionStatus>>,
    /// `traffic`, `coverage`: which lanes to read. `all` is the explicit
    /// both-lanes choice; every row still carries its lane.
    #[arg(long, value_enum, default_value = "all")]
    pub lane: LaneArg,
    /// PostgreSQL URL of the store.
    #[arg(long, env = "CRAWLX_DATABASE_URL")]
    pub database_url: Option<String>,
    /// `trail`: filesystem artifact root used by the writer.
    #[arg(
        long,
        env = "CRAWLX_ARTIFACTS_DIR",
        default_value = "./crawlx-artifacts",
        value_name = "DIR",
        conflicts_with = "s3_bucket"
    )]
    pub artifacts_dir: PathBuf,
    /// `trail`: S3-compatible artifact bucket; `CRAWLX_S3_PROFILE` (standard, compatible, edge,
    /// self-hosted) and the other `CRAWLX_S3_*` variables choose region, endpoint and path style
    /// (docs/ops/object-storage.md).
    #[arg(long, env = "CRAWLX_S3_BUCKET", value_name = "BUCKET")]
    pub s3_bucket: Option<String>,
    /// Print JSON lines instead of `key=value` text.
    #[arg(long)]
    pub json: bool,
}

pub(crate) async fn connect(url: Option<&str>) -> anyhow::Result<Pg> {
    // secrets come from files; `CRAWLX_DATABASE_URL_FILE` / `database.url_file`
    // are the production path, the flag and `CRAWLX_DATABASE_URL` the development one.
    let url = crate::config_check::database_url(url)?.ok_or_else(|| {
        anyhow!(
            "this command reads PostgreSQL: pass --database-url, set CRAWLX_DATABASE_URL, \
             CRAWLX_DATABASE_URL_FILE or database.url_file in crawlx.toml \
             (an in-memory `crawl` writes the same data to DIR/report.json)"
        )
    })?;
    Pg::connect(&url, PgConfig::default())
        .await
        .map_err(|e| anyhow!("connecting to the database: {e}"))
}

pub(crate) fn parse_run(s: &str) -> anyhow::Result<CrawlRunId> {
    s.parse().map_err(|e| anyhow!("{s:?} is not a run id: {e}"))
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_owned(),
        other => other.to_string(),
    }
}

fn print_rows(out: &mut dyn Write, rows: &[Value], json: bool) -> anyhow::Result<()> {
    for row in rows {
        if json {
            writeln!(out, "{row}")?;
        } else if let Some(obj) = row.as_object() {
            let line: Vec<String> = obj.iter().map(|(k, v)| format!("{k}={}", text(v))).collect();
            writeln!(out, "{}", line.join("  "))?;
        } else {
            writeln!(out, "{}", text(row))?;
        }
    }
    Ok(())
}

fn epoch(e: crawlx_core::ObservationEpoch) -> String {
    format!("{}.{}.{}", e.navigation_seq, e.document_seq, e.mutation_seq)
}

async fn run_rows(pg: &Pg, run: CrawlRunId) -> anyhow::Result<Vec<Value>> {
    let r = RunRepo::get(pg, run).await.map_err(|e| anyhow!("{e}"))?;
    let mut rows = vec![json!({
        "run": r.id.0,
        "status": r.status.as_str(),
        "terminal_reason": r.terminal_reason.map(|t| t.as_str()),
        "mode": r.config.mode,
        "profile": r.config.safety.profile.as_str(),
        "seed": r.seed.0,
        "counters": r.counters,
    })];
    for s in RunRepo::list_sessions(pg, run)
        .await
        .map_err(|e| anyhow!("{e}"))?
    {
        rows.push(json!({
            "session": s.id.0,
            "role": s.role.0,
            "run_index": s.run_index,
            "schedule_slot": s.schedule_slot,
            "status": s.status.as_str(),
            "action_seq": s.action_seq,
            "chromium": s.browser.as_ref().map(|b| b.chromium_version.clone()),
            "cdp_revision": s.browser.as_ref().map(|b| b.cdp_revision.clone()),
            "pinned": s.browser.as_ref().map(|b| b.pinned),
            "launch_profile": s.browser.as_ref().map(|b| b.launch_profile.as_str()),
        }));
    }
    Ok(rows)
}

async fn state_rows(pg: &Pg, run: CrawlRunId) -> anyhow::Result<Vec<Value>> {
    let mut rows = Vec::new();
    for s in RunRepo::list_sessions(pg, run)
        .await
        .map_err(|e| anyhow!("{e}"))?
    {
        if let Some(b) = &s.browser {
            rows.push(json!({
                "session": s.id.0,
                "role": s.role.0,
                "chromium": b.chromium_version,
                "cdp_revision": b.cdp_revision,
                "pinned": b.pinned,
            }));
        }
    }
    for st in StateRepo::list_states(pg, run)
        .await
        .map_err(|e| anyhow!("{e}"))?
    {
        rows.push(json!({
            "state": st.id.0,
            "session": st.session.0,
            "cluster": st.cluster.0,
            "novel": st.cluster_is_new,
            "similarity": st.cluster_similarity,
            "epoch": epoch(st.epoch),
            "url": st.url.url.as_str(),
            "masks": st.masks.masked_node_keys.len(),
            "artifacts": st.artifacts.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
            "observed_at": st.observed_at,
        }));
    }
    Ok(rows)
}

async fn action_rows(pg: &Pg, run: CrawlRunId, filter: Option<ActionStatus>) -> anyhow::Result<Vec<Value>> {
    let rows = ActionJournal::list(pg, run, filter)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    Ok(rows
        .into_iter()
        .map(|a| {
            json!({
                "seq": a.seq,
                "action": a.id.0,
                "status": a.status.as_str(),
                "kind": a.key.action_kind.as_str(),
                "lane": a.lane.map(|l| l.as_str()),
                "fidelity": a.fidelity.map(|f| f.as_str()),
                "strategy": format!("{}@{}", a.strategy, a.strategy_version),
                "epoch": epoch(a.epoch),
                "safety_decision": a.safety_decision.0,
                "attempt": a.attempt,
                "reconcile": a.reconcile_resolution.map(|r| r.as_str()),
                "context": a.key.id().to_string(),
                "route": a.key.route_template.0,
            })
        })
        .collect())
}

/// Successful executions of `r` that count under `lane`: only trusted-reachable
/// `trusted_ui` successes for the trusted lane, everything else for the diagnostic lane.
fn exercised_for(r: &CoverageRow, lane: LaneFilter) -> u32 {
    match lane {
        LaneFilter::TrustedUi => r.exercised(TrustLane::TrustedUi),
        LaneFilter::Diagnostic => r.exercised(TrustLane::Diagnostic),
        LaneFilter::Both => r.succeeded(),
    }
}

fn lane_label(lane: LaneFilter) -> &'static str {
    match lane {
        LaneFilter::TrustedUi => TrustLane::TrustedUi.as_str(),
        LaneFilter::Diagnostic => TrustLane::Diagnostic.as_str(),
        LaneFilter::Both => "all",
    }
}

/// Summary row followed by one row per context. Every count comes through `TrustedCorpus`:
/// `trusted` excludes successes from states reachable only through the
/// diagnostic lane, which show up as `trusted_unreachable`.
fn coverage_json(rows: &[CoverageRow], lane: LaneFilter) -> Vec<Value> {
    let exercised = rows.iter().filter(|r| exercised_for(r, lane) > 0).count();
    let diagnostic_only = rows.iter().filter(|r| r.is_diagnostic_only()).count();
    let share = |n: usize| f64::from(u32::try_from(n).unwrap_or(u32::MAX));
    let coverage = if rows.is_empty() {
        0.0
    } else {
        share(exercised) / share(rows.len())
    };
    let mut out = vec![json!({
        "contexts": rows.len(),
        "lane": lane_label(lane),
        "exercised": exercised,
        "diagnostic_only": diagnostic_only,
        "unexercised": rows.len() - exercised,
        "coverage": coverage,
    })];
    out.extend(rows.iter().map(|r| {
        json!({
            "context": r.key.id().to_string(),
            "principal": r.key.principal.0,
            "route": r.key.route_template.0,
            "kind": r.key.action_kind.as_str(),
            "input_class": r.key.input_class.0,
            "exercised": exercised_for(r, lane),
            "trusted": r.trusted_exercised,
            "trusted_unreachable": r.trusted_unreachable,
            "diagnostic": r.diagnostic_exercised,
            "diagnostic_only": r.is_diagnostic_only(),
            "failures": r.failures,
            "denied": r.denied,
            "unknown": r.unknown,
            "first_seen": r.first_seen,
            "last_exercised": r.last_exercised,
        })
    }));
    out
}

async fn coverage_rows(pg: &Pg, run: CrawlRunId, lane: LaneFilter) -> anyhow::Result<Vec<Value>> {
    let rows = TrustedCorpus::new(pg.clone())
        .coverage(run)
        .await
        .context("reading coverage")?;
    Ok(coverage_json(&rows, lane))
}

/// The `epochs` row of one navigation audit event: the epoch triple and the settle
/// summary come out of the worker's payload; missing keys print as `null`.
fn navigation_row(seq: u64, at: Timestamp, payload: &Value) -> Value {
    json!({
        "kind": "navigation",
        "seq": seq,
        "at": at,
        "url": payload["url"],
        "final_url": payload["finalUrl"],
        "status": payload["status"],
        "epoch": format!(
            "{}.{}.{}",
            payload["epoch"]["navigation_seq"], payload["epoch"]["document_seq"], payload["epoch"]["mutation_seq"]
        ),
        "settle_timeout": payload["settle"]["settle_timeout"],
        "waited_ms": payload["settle"]["waited_ms"],
        "blocked_by_egress": payload["blockedByEgress"],
    })
}

async fn epoch_rows(pg: &Pg, run: CrawlRunId) -> anyhow::Result<Vec<Value>> {
    let repo = InspectRepo::new(pg.clone());
    let epochs = repo.epochs(run).await.context("reading network_epochs")?;
    let navigations = repo.navigations(run).await.context("reading navigation events")?;
    let mut out: Vec<Value> = navigations
        .iter()
        .map(|n| navigation_row(n.seq, n.at, &n.payload))
        .collect();
    out.extend(epochs.iter().map(|e| {
        json!({
            "kind": "action",
            "epoch": e.epoch,
            "session": e.session,
            "action": e.action,
            "lane": e.lane.as_str(),
            "started_at": e.started_at,
            "settled_at": e.settled_at,
            "requests": e.request_count,
            "unique_operations": e.unique_operations,
            "settle_timeout": e.settle_timeout,
        })
    }));
    Ok(out)
}

async fn transition_rows(pg: &Pg, run: CrawlRunId) -> anyhow::Result<Vec<Value>> {
    let rows = InspectRepo::new(pg.clone())
        .transitions(run)
        .await
        .context("reading transitions")?;
    Ok(rows
        .iter()
        .map(|t| {
            json!({
                "transition": t.id,
                "session": t.session,
                "before_state": t.before_state,
                "action": t.action,
                "network_epoch": t.network_epoch,
                "after_state": t.after_state,
                "lane": t.lane.as_str(),
                "settle": t.settle_report,
            })
        })
        .collect())
}

async fn traffic_rows(pg: &Pg, run: CrawlRunId, lane: LaneFilter) -> anyhow::Result<Vec<Value>> {
    let rows = TrustedCorpus::new(pg.clone())
        .traffic(run, lane, &TrafficQuery::default())
        .await
        .context("reading traffic_events")?;
    Ok(rows
        .iter()
        .map(|t| {
            json!({
                "at": t.occurred_at,
                "event": t.event_id,
                "epoch": t.epoch,
                "unattributed_reason": t.unattributed_reason.map(|r| r.as_str()),
                "action": t.action,
                "role": t.role,
                "lane": t.lane.as_str(),
                "origin": t.origin,
                "method": t.method,
                "url": t.url_redacted,
                "status": t.status,
                "third_party": t.third_party,
                "late": t.late,
                "trusted_reachable": t.trusted_reachable,
            })
        })
        .collect())
}

async fn page_rows(pg: &Pg, run: CrawlRunId) -> anyhow::Result<Vec<Value>> {
    let pages = PageRepo::list(pg, run).await.map_err(|e| anyhow!("{e}"))?;
    Ok(pages
        .into_iter()
        .map(|p| {
            json!({
                "status": p.status,
                "url": p.url.url.as_str(),
                "title": p.title,
                "content_type": p.content_type,
                "links": p.links.len(),
                "lane": p.lane.as_str(),
                "fetched_at": p.fetched_at,
            })
        })
        .collect())
}

fn trail_s3_config(
    bucket: &str,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> Result<S3Config, crawlx_storage::s3::S3ConfigError> {
    // Inspection only reads objects; writer-only SSE settings do not change GETs.
    S3Config::from_lookup_for_bucket(bucket, getenv)
}

async fn trail_artifacts(
    pg: &Pg,
    run: CrawlRunId,
    args: &InspectArgs,
) -> anyhow::Result<Option<Arc<dyn ArtifactStore>>> {
    let run = RunRepo::get(pg, run).await?;
    if run.config.retention.mode == crawlx_core::config::RetentionMode::Zdr {
        // Durable inspection must not read or consume the ephemeral delivery buffer.
        return Ok(None);
    }
    let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
    let clock = Arc::new(crawlx_core::SystemClock);
    // Sealed artifacts are verified through the catalog; legacy ones keep their plaintext path.
    let (custody, keys) =
        crawlx_worker::config::read_only_custody_from_lookup(pg, &|key| std::env::var(key).ok()).await?;
    let writes = crawlx_storage::CustodyWrites::ReadOnly;
    if let Some(bucket) = &args.s3_bucket {
        let config = trail_s3_config(bucket, &|key| std::env::var(key).ok())?;
        let store = S3ArtifactStore::new(S3Blobs::new(&config)?, runs, clock)
            .with_custody(custody, keys, writes)
            .with_read_scope(run.tenant, run.id);
        Ok(Some(Arc::new(store)))
    } else {
        let store = FsArtifactStore::open(&args.artifacts_dir, runs, clock)
            .await
            .with_context(|| format!("opening artifact root {}", args.artifacts_dir.display()))?
            .with_custody(custody, keys, writes)
            .with_read_scope(run.tenant, run.id);
        Ok(Some(Arc::new(store)))
    }
}

async fn trail_rows(pg: &Pg, run: CrawlRunId, args: &InspectArgs) -> anyhow::Result<(Vec<Value>, bool)> {
    let artifacts = trail_artifacts(pg, run, args).await?;
    let report = crawlx_bench::trail::verify_trail(
        run,
        crawlx_bench::trail::TrailStore::Pg {
            pg,
            artifacts: artifacts.as_deref(),
        },
    )
    .await
    .context("verifying stored trail")?;
    let mut rows = vec![json!({
        "run": report.run.0,
        "violations": report.violations.len(),
        "checked": report.checked,
        "by_rule": report.by_rule(),
        "skipped": report.skipped,
        "skipped_counts": report.skipped_counts,
        "unverifiable": report.unverifiable,
        "clean": report.is_clean(),
    })];
    rows.extend(report.violations.iter().map(|v| {
        let mut row = serde_json::to_value(v).unwrap_or(Value::Null);
        if let Some(obj) = row.as_object_mut() {
            obj.insert("message".to_owned(), Value::String(v.to_string()));
        }
        row
    }));
    Ok((rows, report.is_clean()))
}

pub(crate) async fn run(args: InspectArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let run = parse_run(&args.run_id)?;
    let pg = connect(args.database_url.as_deref()).await?;
    let mut exit = ExitCode::SUCCESS;
    let rows = match args.kind {
        InspectKind::Run => run_rows(&pg, run).await?,
        InspectKind::Pages => page_rows(&pg, run).await?,
        InspectKind::States => state_rows(&pg, run).await?,
        InspectKind::Epochs => epoch_rows(&pg, run).await?,
        InspectKind::Actions => action_rows(&pg, run, args.status.flatten()).await?,
        InspectKind::Transitions => transition_rows(&pg, run).await?,
        InspectKind::Coverage => coverage_rows(&pg, run, args.lane.into()).await?,
        InspectKind::Traffic => traffic_rows(&pg, run, args.lane.into()).await?,
        InspectKind::Trail => {
            let (rows, clean) = trail_rows(&pg, run, &args).await?;
            if !clean {
                exit = ExitCode::FAILURE;
            }
            rows
        }
    };
    print_rows(out, &rows, args.json)?;
    Ok(exit)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::StateClusterId;
    use crawlx_storage::testkit::proposal;

    fn row(key_n: u32, trusted: u32, unreachable: u32, diagnostic: u32, denied: u32) -> CoverageRow {
        let key = proposal("anonymous", StateClusterId::new(), key_n).key;
        CoverageRow {
            key,
            trusted_exercised: trusted,
            trusted_unreachable: unreachable,
            diagnostic_exercised: diagnostic,
            failures: 0,
            denied,
            unknown: 0,
            first_seen: chrono::DateTime::UNIX_EPOCH,
            last_exercised: None,
        }
    }

    #[test]
    fn coverage_summary_counts_per_lane() {
        let rows = vec![
            row(1, 1, 0, 0, 0), // trusted and reachable
            row(2, 0, 1, 0, 0), // native click from a synthetic-only state: diagnostic evidence
            row(3, 0, 0, 2, 0), // synthetic only
            row(4, 0, 0, 0, 3), // denied only
        ];
        let trusted = coverage_json(&rows, LaneFilter::TrustedUi);
        assert_eq!(trusted.len(), 5);
        assert_eq!(trusted[0]["lane"], "trusted_ui");
        assert_eq!(trusted[0]["exercised"], 1);
        assert_eq!(trusted[0]["diagnostic_only"], 2);
        assert_eq!(trusted[0]["unexercised"], 3);
        assert_eq!(trusted[0]["coverage"], 0.25);
        assert_eq!(trusted[2]["exercised"], 0);
        assert_eq!(trusted[2]["trusted_unreachable"], 1);
        assert_eq!(trusted[2]["diagnostic_only"], true);
        assert_eq!(trusted[4]["denied"], 3);

        let diagnostic = coverage_json(&rows, LaneFilter::Diagnostic);
        assert_eq!(diagnostic[0]["lane"], "diagnostic");
        assert_eq!(diagnostic[0]["exercised"], 2);
        assert_eq!(diagnostic[2]["exercised"], 1);

        let all = coverage_json(&rows, LaneFilter::Both);
        assert_eq!(all[0]["lane"], "all");
        assert_eq!(all[0]["exercised"], 3);
        assert_eq!(all[0]["coverage"], 0.75);

        let empty = coverage_json(&[], LaneFilter::TrustedUi);
        assert_eq!(empty[0]["contexts"], 0);
        assert_eq!(empty[0]["coverage"], 0.0);
    }

    #[test]
    fn navigation_row_flattens_the_worker_payload() {
        let payload = json!({
            "url": "https://example.test/",
            "finalUrl": "https://example.test/home",
            "status": 200,
            "epoch": { "navigation_seq": 3, "document_seq": 1, "mutation_seq": 7 },
            "settle": { "settle_timeout": false, "waited_ms": 120 },
            "blockedByEgress": false,
        });
        let row = navigation_row(4, chrono::DateTime::UNIX_EPOCH, &payload);
        assert_eq!(row["kind"], "navigation");
        assert_eq!(row["seq"], 4);
        assert_eq!(row["epoch"], "3.1.7");
        assert_eq!(row["final_url"], "https://example.test/home");
        assert_eq!(row["waited_ms"], 120);
        assert_eq!(row["blocked_by_egress"], false);

        // a navigation that never settled (the waiter failed) prints nulls, not an error
        let row = navigation_row(
            5,
            chrono::DateTime::UNIX_EPOCH,
            &json!({ "url": "https://example.test/" }),
        );
        assert_eq!(row["epoch"], "null.null.null");
        assert!(row["settle_timeout"].is_null());
        assert!(row["final_url"].is_null());
    }

    #[test]
    fn trail_artifact_flags_and_s3_endpoint_are_explicit() {
        use clap::Parser as _;
        let parsed = crate::Cli::try_parse_from([
            "crawlx",
            "inspect",
            "trail",
            "0198c0de-0000-7000-8000-000000000000",
            "--artifacts-dir",
            "/configured/artifacts",
        ])
        .unwrap();
        let crate::Command::Inspect(args) = parsed.command else {
            panic!("inspect command");
        };
        assert_eq!(args.artifacts_dir, PathBuf::from("/configured/artifacts"));
        let parsed = crate::Cli::try_parse_from([
            "crawlx",
            "inspect",
            "trail",
            "0198c0de-0000-7000-8000-000000000000",
            "--s3-bucket",
            "configured-bucket",
        ])
        .unwrap();
        let crate::Command::Inspect(args) = parsed.command else {
            panic!("inspect command");
        };
        assert_eq!(args.s3_bucket.as_deref(), Some("configured-bucket"));
        let config = trail_s3_config(args.s3_bucket.as_deref().unwrap(), &|key| match key {
            "CRAWLX_S3_REGION" => Some("test-region".to_owned()),
            "CRAWLX_S3_ENDPOINT" => Some("http://127.0.0.1:9000".to_owned()),
            "CRAWLX_S3_PATH_STYLE" => Some("true".to_owned()),
            "CRAWLX_S3_ALLOW_HTTP" => Some("true".to_owned()),
            _ => None,
        })
        .unwrap();
        assert_eq!(config.bucket, "configured-bucket");
        assert_eq!(config.region, "test-region");
        assert_eq!(config.endpoint.as_deref(), Some("http://127.0.0.1:9000"));
        assert!(config.path_style);
    }

    #[tokio::test]
    async fn trail_inspection_reads_configured_artifacts_and_reports_missing_content() {
        use clap::Parser as _;
        use crawlx_bench::worker_exec::authorize_fixture;
        use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
        use crawlx_browser::FakeBackend;
        use crawlx_core::config::{CaptureMode, CrawlMode};
        use crawlx_core::{CreateCrawl, SystemClock, TenantId};
        use crawlx_fetch::StaticResolver;
        use crawlx_worker::{run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig};

        let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
            eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
            return;
        };
        let pg = Pg::connect(
            &url,
            PgConfig {
                schema: Some(format!("t_inspect_trail_{}", uuid::Uuid::now_v7().simple())),
                ..PgConfig::default()
            },
        )
        .await
        .unwrap();
        pg.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("configured");
        let artifacts = FsArtifactStore::open(&root, Arc::new(pg.clone()), Arc::new(SystemClock))
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone()));
        let stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), TenantId::new());
        let script = FakeScript::new()
            .page(
                FakePage::new("https://example.test/")
                    .node(FakeAxSpec::link("next", "Next", "/next"))
                    .on_click("next", vec![FakeEffect::Navigate("/next".to_owned())]),
            )
            .page(FakePage::new("https://example.test/next"));
        let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
        crawl.mode = CrawlMode::Dynamic;
        crawl.seed = Some(14);
        crawl.limits.interactions = 2;
        crawl.capture.dom_snapshot = CaptureMode::EveryState;
        let report = run_local_with(authorize_fixture(
            LocalRun::new(
                crawl,
                WorkerConfig {
                    artifacts_dir: root.clone(),
                    checkpoint_keys: Some(Arc::new(
                        crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap(),
                    )),
                    egress: EgressConfig {
                        resolver: Some(Arc::new(StaticResolver::new())),
                        ..EgressConfig::default()
                    },
                    gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
                    ..WorkerConfig::default()
                },
            )
            .with_backend(Arc::new(FakeBackend::new(script)))
            .with_stores(stores),
        ))
        .await
        .unwrap();
        let run_id = report.run_id.to_string();
        let parsed = crate::Cli::try_parse_from([
            "crawlx",
            "inspect",
            "trail",
            &run_id,
            "--artifacts-dir",
            root.to_str().unwrap(),
            "--json",
        ])
        .unwrap();
        let crate::Command::Inspect(mut args) = parsed.command else {
            panic!("inspect command");
        };
        let (rows, clean) = trail_rows(&pg, report.run_id, &args).await.unwrap();
        assert!(clean, "{rows:?}");
        assert!(rows[0]["checked"]["fingerprints_verified"].as_u64().unwrap() > 0);
        assert_eq!(rows[0]["checked"]["fingerprints_unverifiable"], 0);

        args.artifacts_dir = dir.path().join("wrong-root");
        let (rows, clean) = trail_rows(&pg, report.run_id, &args).await.unwrap();
        assert!(!clean, "{rows:?}");
        assert_eq!(rows[0]["violations"], 0);
        assert!(rows[0]["checked"]["fingerprints_unverifiable"].as_u64().unwrap() > 0);
        assert_eq!(rows[0]["clean"], false);
        assert!(rows[0]["unverifiable"]
            .as_object()
            .unwrap()
            .keys()
            .any(|reason| { reason.contains("missing or expired") }));
        pg.drop_schema().await.unwrap();
    }
}
