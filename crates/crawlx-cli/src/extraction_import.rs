//! Offline source-import dispatch for pinned extraction profiles.
//!
//! Called only after migration_inspect's bounded regular-file read. No networking,
//! telemetry initialization, environment secret resolution, package loading, or
//! arbitrary filesystem references occur. Source options never choose an output path.
//!
//! Example declarative input for `crawlx source-import convert profile.json`:
//! ```json
//! {"version":1,"source":"text-precision","sourceVersion":"2.3.1",
//!  "dialect":"library","options":{"url":"https://fixture.test/article",
//!  "fast":true,"include_comments":false,"include_tables":true}}
//! ```
//! `inspect` prints the pinned complete inventory report. `convert` prints the
//! runnable native CreateCrawl only if all requested behavior maps. Otherwise it
//! prints the same typed report and exits two. Omitted settings keep native defaults.
//!
//! Text-precision and news-article profiles require `dialect=library|cli|settings`.
//! The surface-flags profile accepts only the pinned registered CLI dialect; Go SDK object import is
//! unavailable. Every import reports all pinned inventory IDs and original ledger
//! evidence. Whole-family `requiredInventory` requests remain decision-needed unless
//! full semantics are established; one option never proves a whole source family.

use anyhow::Context;
use crawlx_worker::runtime::CpuPool;
use std::{io::Write, num::NonZeroUsize, process::ExitCode};

/// Inspect or convert one already bounded, caller-owned JSON manifest.
///
/// Parsing and selector compilation use the existing bounded CPU pool. The caller
/// retains the regular-file and CLI-only path boundary; no server file API is added.
///
/// # Errors
/// Returns strict schema/version/bounds errors, CPU-task failure, or output I/O errors.
/// Requested unmapped behavior is a typed JSON report with exit code two, not an error
/// string containing raw option values or credentials.
pub async fn run_manifest(bytes: &[u8], convert: bool, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    if bytes.len() > crawlx_core::extraction_import::MAX_MANIFEST_BYTES {
        return Err(crawlx_core::extraction_import::ExtractionImportError::Manifest(
            "manifest exceeds one MiB",
        )
        .into());
    }
    // The dispatcher owns this borrowed bounded buffer; one owned copy is needed
    // to move parsing safely across the blocking-task 'static boundary.
    let bytes = bytes.to_owned();
    let pool = CpuPool::with_permits(NonZeroUsize::MIN);
    let (report, request) = pool
        .run(move || crawlx_extract::extraction_import::inspect(&bytes))
        .await
        .context("extraction import CPU task failed")??;
    if convert && report.convertible {
        serde_json::to_writer_pretty(
            &mut *out,
            &request.context("validated extraction import lacks native request")?,
        )?;
    } else {
        serde_json::to_writer_pretty(&mut *out, &report)?;
    }
    writeln!(out)?;
    Ok(if report.convertible {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::{json, Value};

    #[tokio::test]
    async fn adapter_prints_runnable_native_request_and_complete_pinned_report() {
        let bytes = serde_json::to_vec(
            &json!({"version":1,"source":"text-precision","sourceVersion":"2.3.1","dialect":"library",
            "options":{"url":"https://fixture.test/article","fast":true,"include_comments":false}}),
        )
        .unwrap();
        let mut out = Vec::new();
        assert_eq!(
            run_manifest(&bytes, true, &mut out).await.unwrap(),
            ExitCode::SUCCESS
        );
        let request: crawlx_core::CreateCrawl = serde_json::from_slice(&out).unwrap();
        assert_eq!(request.seed_url.as_str(), "https://fixture.test/article");
        assert_eq!(
            request.scope.strategy,
            crawlx_core::config::CrawlStrategy::BreadthFirst
        );
        assert_eq!(
            request.extract.content.unwrap().fallback,
            crawlx_core::extraction::ContentFallbackV1::None
        );
        out.clear();
        assert_eq!(
            run_manifest(&bytes, false, &mut out).await.unwrap(),
            ExitCode::SUCCESS
        );
        let report: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(report["sourceVersion"], "2.3.1");
        assert_eq!(report["license"], "Apache-2.0");
        assert_eq!(report["sdkAbiCompatible"], false);
        assert!(report["dispositions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == "TP-38"));
    }
    #[tokio::test]
    async fn unknown_unsafe_solver_and_incompatible_outputs_return_typed_report_not_config() {
        for (source, version, dialect, options) in [
            (
                "news-article",
                "0.9.6.1",
                "library",
                json!({"url":"https://fixture.test","requests_params":{"proxies":{"https":"http://secret@proxy.test"}}}),
            ),
            (
                "surface-flags",
                "1.8.0",
                "cli",
                json!({"u":"https://fixture.test","captcha-solver-key":"must-not-appear"}),
            ),
            (
                "text-precision",
                "2.3.1",
                "library",
                json!({"url":"https://fixture.test","output_format":"pickle"}),
            ),
            (
                "text-precision",
                "2.3.1",
                "library",
                json!({"url":"https://fixture.test","execute":"must-not-appear"}),
            ),
        ] {
            let bytes = serde_json::to_vec(&json!({"version":1,"source":source,"sourceVersion":version,"dialect":dialect,"options":options})).unwrap();
            let mut out = Vec::new();
            assert_eq!(
                run_manifest(&bytes, true, &mut out).await.unwrap(),
                ExitCode::from(2)
            );
            let report: Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(report["convertible"], false);
            assert!(report.get("seedUrl").is_none());
            let text = String::from_utf8(out).unwrap();
            assert!(!text.contains("must-not-appear"));
            assert!(!text.contains("secret@proxy.test"));
        }
    }
    #[tokio::test]
    async fn no_source_runtime_or_filesystem_reference_is_resolved() {
        for options in [
            json!({"url":"file:///etc/passwd"}),
            json!({"url":"env://URL"}),
            json!({"url":"https://fixture.test","prune_xpath":"document('file:///etc/passwd')"}),
        ] {
            let bytes = serde_json::to_vec(&json!({"version":1,"source":"text-precision","sourceVersion":"2.3.1","dialect":"library","options":options})).unwrap();
            let mut out = Vec::new();
            assert_eq!(
                run_manifest(&bytes, true, &mut out).await.unwrap(),
                ExitCode::from(2)
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&out).unwrap()["convertible"],
                false
            );
        }
    }
    #[tokio::test]
    async fn registered_source_import_dispatch_reaches_extraction_profile_and_native_api() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.json");
        let bytes = serde_json::to_vec(&json!({"version":1,"source":"text-precision","sourceVersion":"2.3.1","dialect":"library",
            "options":{"url":"https://fixture.test/article","include_comments":false,"prune_xpath":"//aside"}})).unwrap();
        tokio::fs::write(&path, bytes).await.unwrap();
        let mut out = Vec::new();
        let args = crate::migration_inspect::SourceImportArgs {
            command: crate::migration_inspect::SourceImportCommand::Convert(
                crate::migration_inspect::ManifestArgs { manifest: path },
            ),
        };
        assert_eq!(
            crate::migration_inspect::run(args, &mut out).await.unwrap(),
            ExitCode::SUCCESS
        );
        let request: crawlx_core::CreateCrawl = serde_json::from_slice(&out).unwrap();
        let document = crawlx_extract::Extractor::extract(
            crawlx_extract::extraction_import::AUTHORED_ARTICLE_HTML,
            &request.seed_url,
            &crawlx_extract::ExtractOptions {
                content: request.extract.content,
                ..crawlx_extract::ExtractOptions::default()
            },
        )
        .unwrap();
        assert!(document
            .text
            .contains("The neighborhood library opened its lantern workshop"));
        assert!(!document.text.contains("Unrelated shop promotion"));
        assert!(!document.text.contains("A reader asked"));
    }
}
