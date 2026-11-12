//! `crawlx cache-import`: offline screening of an exported response cache.
//!
//! Reads one explicit regular JSON file and reports which entries could be imported into a
//! tenant's retained pages and which are refused, and why: another tenant's entry, a private or
//! credential-bearing response, an undeclared header, an unsafe URL, a non-textual or oversized
//! body. The report names entries by position and never echoes a URL, header or body. Storing the
//! accepted entries is [`crawlx_worker::scrape::cache::import_entries`], called by the service that
//! owns the target run's tenant and artifact custody; this command touches no store.

use anyhow::{bail, Context};
use clap::{Args, Subcommand};
use crawlx_core::cache::{CacheExportV1, MAX_CACHE_EXPORT_BYTES};
use crawlx_core::TenantId;
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use tokio::io::AsyncReadExt as _;

/// Screen an exported response cache without loading it into a store.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct CacheImportArgs {
    /// What to do with the export.
    #[command(subcommand)]
    pub command: CacheImportCommand,
}

/// Cache import operations.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum CacheImportCommand {
    /// Report which entries are importable for a tenant; exit two when any entry is refused.
    Inspect(InspectArgs),
}

/// Arguments of `cache-import inspect`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct InspectArgs {
    /// One regular JSON export (version 1), at most 16 MiB; symlinks and special files are refused.
    pub input: PathBuf,
    /// The tenant the entries would be imported for; an entry or export of another tenant is refused.
    #[arg(long)]
    pub tenant: TenantId,
}

async fn read_export(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .context("reading cache export metadata")?;
    if !metadata.file_type().is_file() || metadata.len() > u64::try_from(MAX_CACHE_EXPORT_BYTES)? {
        bail!("cache export must be a regular file no larger than 16 MiB");
    }
    let mut bytes = Vec::new();
    tokio::fs::File::open(path)
        .await
        .context("opening cache export")?
        .take(u64::try_from(MAX_CACHE_EXPORT_BYTES + 1)?)
        .read_to_end(&mut bytes)
        .await
        .context("reading cache export")?;
    Ok(bytes)
}

/// Screen the export of `args` at time `now` and print the report.
///
/// # Errors
/// An unreadable, oversized, malformed or unsupported export (no input text is echoed) or an
/// output error. Refused entries are part of the report and the exit code, not an error.
pub async fn run(args: CacheImportArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let CacheImportCommand::Inspect(args) = args.command;
    let bytes = read_export(&args.input).await?;
    let export = CacheExportV1::parse(&bytes).context("reading the cache export")?;
    let screened = export.screen(args.tenant, chrono::Utc::now());
    let refused: Vec<_> = screened
        .refused
        .iter()
        .map(|row| {
            json!({
                "index": row.index,
                "cause": row.cause.as_str(),
                "reason": row.cause.reason(),
            })
        })
        .collect();
    let accepted_bytes: usize = screened.accepted.iter().map(|entry| entry.body.len()).sum();
    serde_json::to_writer_pretty(
        &mut *out,
        &json!({
            "version": 1,
            "tenant": args.tenant,
            "entries": export.entries.len(),
            "accepted": screened.accepted.len(),
            "acceptedBodyBytes": accepted_bytes,
            "refused": refused,
        }),
    )
    .context("writing the cache import report")?;
    writeln!(out)?;
    Ok(if screened.refused.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const TENANT: &str = "00000000-0000-7000-8000-000000000001";

    fn entry(url: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut value = json!({
            "url": url, "statusCode": 200, "contentType": "text/html",
            "fetchedAt": "2026-01-01T00:00:00Z", "body": "<p>x</p>"
        });
        for (key, field) in extra.as_object().unwrap() {
            value[key] = field.clone();
        }
        value
    }

    async fn inspect(
        document: &serde_json::Value,
        tenant: &str,
    ) -> (anyhow::Result<ExitCode>, serde_json::Value, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        std::fs::write(&path, serde_json::to_vec(document).unwrap()).unwrap();
        let mut out = Vec::new();
        let result = run(
            CacheImportArgs {
                command: CacheImportCommand::Inspect(InspectArgs {
                    input: path,
                    tenant: tenant.parse().unwrap(),
                }),
            },
            &mut out,
        )
        .await;
        let text = String::from_utf8(out).unwrap();
        let report = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
        (result, report, text)
    }

    #[tokio::test]
    async fn a_clean_export_exits_zero_and_reports_counts_only() {
        let document = json!({"version":1,"tenant":TENANT,"entries":[
            entry("https://example.test/a?token=url-canary", json!({})),
            entry("https://example.test/b", json!({"headers":[{"name":"etag","value":"\"v\""}]})),
        ]});
        let (code, report, text) = inspect(&document, TENANT).await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS);
        assert_eq!(
            (report["entries"].as_u64(), report["accepted"].as_u64()),
            (Some(2), Some(2))
        );
        assert_eq!(report["refused"], json!([]));
        assert!(
            !text.contains("url-canary") && !text.contains("example.test"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn private_foreign_and_credential_bearing_entries_exit_two_and_are_named_by_position() {
        let document = json!({"version":1,"tenant":TENANT,"entries":[
            entry("https://example.test/ok", json!({})),
            entry("https://example.test/private?sid=body-canary", json!({"private": true})),
            entry("https://example.test/other", json!({"tenant":"00000000-0000-7000-8000-000000000002"})),
            entry("https://example.test/cookie", json!({"headers":[{"name":"Cookie","value":"sid=header-canary"}]})),
        ]});
        let (code, report, text) = inspect(&document, TENANT).await;
        assert_eq!(code.unwrap(), ExitCode::from(2));
        assert_eq!(report["accepted"], 1);
        let causes: Vec<(u64, &str)> = report["refused"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r["index"].as_u64().unwrap(), r["cause"].as_str().unwrap()))
            .collect();
        assert_eq!(
            causes,
            [(1, "private"), (2, "foreign_tenant"), (3, "unsafe_header")]
        );
        for canary in ["body-canary", "header-canary", "example.test"] {
            assert!(!text.contains(canary), "{canary} leaked: {text}");
        }
    }

    #[tokio::test]
    async fn an_export_of_another_tenant_is_refused_entirely() {
        let document =
            json!({"version":1,"tenant":TENANT,"entries":[entry("https://example.test/a", json!({}))]});
        let (code, report, _) = inspect(&document, "00000000-0000-7000-8000-000000000009").await;
        assert_eq!(code.unwrap(), ExitCode::from(2));
        assert_eq!(report["accepted"], 0);
        assert_eq!(report["refused"][0]["cause"], "foreign_tenant");
    }

    #[tokio::test]
    async fn an_undeclared_field_fails_the_export_without_echoing_it() {
        let document = json!({"version":1,"tenant":TENANT,"entries":[
            entry("https://example.test/a", json!({"cookies":"sid=field-canary"}))]});
        let (result, _, text) = inspect(&document, TENANT).await;
        let error = format!("{:#}", result.unwrap_err());
        assert!(
            !error.contains("field-canary") && !text.contains("field-canary"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn only_a_regular_bounded_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        std::fs::write(&real, b"{}").unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_export(&link).await.is_err(), "a symlink is refused");
        assert!(read_export(dir.path()).await.is_err(), "a directory is refused");
        let big = dir.path().join("big.json");
        std::fs::write(&big, vec![b' '; MAX_CACHE_EXPORT_BYTES + 1]).unwrap();
        assert!(read_export(&big).await.is_err(), "an oversized file is refused");
    }
}
