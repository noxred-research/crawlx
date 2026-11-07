//! `crawlx admin`: operator commands against PostgreSQL.

use crate::inspect::connect;
use anyhow::{anyhow, bail, Context as _};
use chrono::{Days, NaiveDate, Utc};
use clap::{Args, Subcommand};
use crawlx_core::TenantId;
use crawlx_storage::audit::export_key;
use crawlx_storage::{ArtifactBlobs, FsBlobs, MerkleExport, S3Blobs, S3Config};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

/// Arguments of `crawlx admin`.
#[derive(Args, Debug)]
pub struct AdminArgs {
    /// Operator command.
    #[command(subcommand)]
    pub command: AdminCommand,
}

/// `crawlx admin` subcommands.
#[derive(Subcommand, Debug)]
pub enum AdminCommand {
    /// Write the daily Merkle root of a tenant's `audit_events` chain to the audit bucket
    /// (`audit/{tenant}/{yyyy-mm-dd}.json`).
    AuditExport(AuditExportArgs),
    /// Operator commands (pause, resume, cancel, drain, freeze, reconcile, ...).
    #[command(flatten)]
    Ops(crate::admin_ops::OpsCommand),
}

/// Arguments of `crawlx admin audit-export`.
#[derive(Args, Debug)]
pub struct AuditExportArgs {
    /// Tenant id (UUID). Exactly one of `--tenant` and `--all`.
    #[arg(
        long,
        value_name = "TENANT_ID",
        conflicts_with = "all",
        required_unless_present = "all"
    )]
    pub tenant: Option<String>,
    /// Export every tenant that has audit rows on the day.
    #[arg(long)]
    pub all: bool,
    /// UTC day (`YYYY-MM-DD`); yesterday when omitted, the day that just completed.
    #[arg(long, value_name = "DATE")]
    pub day: Option<NaiveDate>,
    /// Directory backend of the audit bucket (`./crawlx-audit`).
    #[arg(
        long,
        value_name = "DIR",
        default_value = "./crawlx-audit",
        conflicts_with = "s3_bucket"
    )]
    pub audit_dir: PathBuf,
    /// S3-compatible audit bucket instead of a directory. Region, endpoint, path style and
    /// SSE come from `CRAWLX_S3_*`; credentials from the SDK environment. Point this at
    /// an object-lock (WORM) bucket in production.
    #[arg(long, value_name = "BUCKET")]
    pub s3_bucket: Option<String>,
    #[arg(long, env = "CRAWLX_DATABASE_URL")]
    /// Database url.
    pub database_url: Option<String>,
}

pub(crate) async fn run(args: AdminArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    match args.command {
        AdminCommand::AuditExport(args) => audit_export(args, out).await,
        AdminCommand::Ops(cmd) => crate::admin_ops::run(cmd, out).await,
    }
}

/// The audit bucket named by the arguments.
async fn audit_blobs(args: &AuditExportArgs) -> anyhow::Result<Arc<dyn ArtifactBlobs>> {
    if let Some(bucket) = &args.s3_bucket {
        let mut cfg = match S3Config::from_env() {
            Ok(cfg) => cfg,
            Err(_) => S3Config::new(
                bucket.clone(),
                std::env::var("CRAWLX_S3_REGION").unwrap_or_else(|_| "us-east-1".to_owned()),
            ),
        };
        cfg.bucket.clone_from(bucket);
        return Ok(Arc::new(S3Blobs::new(&cfg)));
    }
    let fs = FsBlobs::open(&args.audit_dir)
        .await
        .with_context(|| format!("opening audit directory {}", args.audit_dir.display()))?;
    Ok(Arc::new(fs))
}

/// The UTC day before `today`.
fn previous_day(today: NaiveDate) -> anyhow::Result<NaiveDate> {
    today
        .checked_sub_days(Days::new(1))
        .ok_or_else(|| anyhow!("no day before {today}"))
}

async fn audit_export(args: AuditExportArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let day = match args.day {
        Some(d) => d,
        None => previous_day(Utc::now().date_naive())?,
    };
    let pg = connect(args.database_url.as_deref()).await?;
    let blobs = audit_blobs(&args).await?;
    let bucket = blobs.bucket().to_owned();
    let export = MerkleExport::new(pg, blobs);
    let records = if args.all {
        export
            .export_all(day)
            .await
            .map_err(|e| anyhow!("exporting every tenant for {day}: {e}"))?
    } else {
        let Some(tenant) = args.tenant.as_deref() else {
            bail!("pass --tenant <TENANT_ID> or --all");
        };
        let tenant: TenantId = tenant
            .parse()
            .map_err(|e| anyhow!("{tenant:?} is not a tenant id: {e}"))?;
        vec![export
            .export_day(tenant, day)
            .await
            .map_err(|e| anyhow!("exporting tenant {tenant} for {day}: {e}"))?]
    };
    for rec in &records {
        let mut line = serde_json::to_value(rec)?;
        if let Some(obj) = line.as_object_mut() {
            obj.insert("bucket".to_owned(), bucket.clone().into());
            obj.insert("key".to_owned(), export_key(rec.tenant, rec.day).into());
        }
        writeln!(out, "{line}")?;
    }
    if records.is_empty() {
        writeln!(out, "{{\"day\":\"{day}\",\"exported\":0}}")?;
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct T {
        #[command(flatten)]
        admin: AdminArgs,
    }

    #[test]
    fn audit_export_requires_tenant_or_all() {
        assert!(T::try_parse_from(["t", "audit-export", "--day", "2026-01-15"]).is_err());
        assert!(T::try_parse_from(["t", "audit-export", "--tenant", "x", "--all"]).is_err());
        let ok = T::try_parse_from(["t", "audit-export", "--all", "--day", "2026-01-15"]).unwrap();
        let AdminCommand::AuditExport(a) = ok.admin.command else {
            panic!("expected audit-export");
        };
        assert!(a.all);
        assert_eq!(a.day, NaiveDate::from_ymd_opt(2026, 1, 15));
        assert_eq!(a.audit_dir, PathBuf::from("./crawlx-audit"));
    }

    #[test]
    fn previous_day_steps_back_one_utc_day() {
        let d = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();
        assert_eq!(
            previous_day(d).unwrap(),
            NaiveDate::from_ymd_opt(2026, 2, 28).unwrap()
        );
    }
}
