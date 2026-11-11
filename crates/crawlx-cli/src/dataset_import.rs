//! Safe JSON dataset inspection and authenticated import commands.
//!
//! Reads one explicit regular JSON file, never a storage directory or referenced graph.
//! Inspection stays offline. Apply uses the API's tenant authorization, existing request
//! fence, immutable server-derived deadline and typed artifact/storage composition.

use anyhow::{bail, Context};
use clap::{Args, Subcommand};
use crawlx_core::dataset::import::{commit_import, DatasetImportV1};
use crawlx_core::dataset::DatasetConfigV1;
use crawlx_core::orchestration::{RequestCommitRepo, RequestCommitV1};
use crawlx_core::repo::ArtifactStore;
use crawlx_core::Timestamp;
use std::io::Write;
use std::process::ExitCode;

/// Inspect or apply a safe JSON dataset export without loading a source backend.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct DatasetImportArgs {
    /// Offline inspection or authenticated application.
    #[command(subcommand)]
    pub command: DatasetImportCommand,
}

/// Dataset import operations with explicit run/request authority on apply.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum DatasetImportCommand {
    /// Report provenance and unsupported destructive/backend policies offline.
    Inspect {
        /// One regular JSON file, bounded to one MiB.
        input: std::path::PathBuf,
    },
    /// Commit under an existing admitted request's live fence using the authenticated API.
    Apply(ApplyArgs),
}

/// Operator-owned live request selection; these fields do not create or lease new work.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ApplyArgs {
    /// One regular JSON export, bounded to one MiB.
    pub input: std::path::PathBuf,
    /// Existing admitted run.
    #[arg(long)]
    pub run: crawlx_core::CrawlRunId,
    /// Existing leased request in that run.
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
    pub request_id: i64,
    /// Existing unexpired request lease fence.
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
    pub fence: i64,
    /// Exact current immutable request state version.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub state_version: u64,
    /// API URL and bearer key; no target-site traffic uses this client.
    #[command(flatten)]
    pub api: crate::authz::ApiTarget,
}

async fn read_export(path: &std::path::Path) -> anyhow::Result<bytes::Bytes> {
    use crawlx_fetch::protocol::file::FileCorpus;
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .context("reading dataset export metadata")?;
    if !metadata.file_type().is_file()
        || metadata.len() > u64::try_from(crawlx_core::dataset::import::MAX_IMPORT_BYTES)?
    {
        bail!("dataset export must be a regular file no larger than one MiB");
    }
    let name = path
        .file_name()
        .context("dataset export must name a regular file")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let parent = tokio::fs::canonicalize(parent)
        .await
        .context("opening dataset export directory")?;
    let corpus = FileCorpus::open(&parent, 1)?;
    let mut url = FileCorpus::parse_url("file:///")?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("invalid dataset export path"))?
        .push(name.to_str().context("dataset export filename must be UTF-8")?);
    let resource = corpus
        .acquire(
            &url,
            u32::try_from(crawlx_core::dataset::import::MAX_IMPORT_BYTES)?,
            std::time::Duration::from_secs(30),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await?;
    if !resource.children.is_empty() || url.path().ends_with('/') {
        bail!("dataset export must be a regular file");
    }
    Ok(resource.body)
}

fn endpoint(args: &ApplyArgs) -> anyhow::Result<url::Url> {
    let mut url = url::Url::parse(&args.api.api_url).context("invalid API URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("API URL must be absolute HTTP(S) without credentials");
    }
    url.set_query(None);
    url.set_fragment(None);
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("invalid API path"))?
        .pop_if_empty()
        .extend(["v1", "crawls", &args.run.to_string(), "datasets", "import"]);
    url.query_pairs_mut()
        .append_pair("requestId", &args.request_id.to_string())
        .append_pair("fence", &args.fence.to_string())
        .append_pair("stateVersion", &args.state_version.to_string());
    Ok(url)
}

/// Read one capability-confined regular file, then inspect offline or apply through the API.
///
/// # Errors
/// Returns unsafe/nonregular/oversized input, policy conflicts, transport/authentication,
/// live-fence/CAS, privacy or retention errors. API content and credentials are never echoed.
pub async fn run(args: DatasetImportArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    match args.command {
        DatasetImportCommand::Inspect { input } => inspect_manifest(&read_export(&input).await?, out),
        DatasetImportCommand::Apply(args) => {
            let bytes = read_export(&args.input).await?;
            let report = DatasetImportV1::parse(&bytes)?.inspect();
            if !report.incompatibilities.is_empty() {
                return inspect_manifest(&bytes, out);
            }
            let key = args
                .api
                .api_key
                .as_deref()
                .filter(|key| !key.trim().is_empty())
                .context("authenticated dataset import requires an API key")?;
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()?;
            let response = client
                .post(endpoint(&args)?)
                .bearer_auth(key)
                .header("Content-Type", "application/json")
                .body(bytes)
                .send()
                .await
                .map_err(|error| error.without_url())?;
            let status = response.status();
            // Never echo a remote body: it could contain item data or provider diagnostics.
            if !status.is_success() {
                bail!(
                    "dataset import API rejected request with status {}",
                    status.as_u16()
                );
            }
            serde_json::to_writer_pretty(
                &mut *out,
                &serde_json::json!({
                    "committed":true, "requestId":args.request_id, "itemCount":report.item_count,
                    "completeCoverage":false, "possibleOmissions":report.possible_omissions,
                }),
            )?;
            writeln!(out)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Inspect bounded JSON bytes without echoing imported values or creating storage.
///
/// The caller reuses the CLI's regular-file, bounded read before invoking this helper.
/// Returns exit code two for explicit destructive/backend incompatibilities.
///
/// # Errors
/// Returns malformed/bounded input or output errors. No raw input appears in diagnostics.
pub fn inspect_manifest(bytes: &[u8], out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let report = DatasetImportV1::parse(bytes)
        .context("reading bounded dataset export")?
        .inspect();
    serde_json::to_writer_pretty(&mut *out, &report).context("writing dataset import report")?;
    writeln!(out)?;
    Ok(if report.incompatibilities.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

/// Apply bounded JSON through the existing artifact sink and authoritative request commit.
///
/// CLI composition must authorize tenant/run access and obtain a real request lease first.
/// This does not fabricate crawl requests, replace PostgreSQL, purge state, or write files.
/// The supplied commit retains caller-owned state CAS, children, page and delivery intents.
///
/// # Errors
/// Returns invalid export/policy/schema or existing privacy, retention, quota and fence errors.
pub async fn commit_manifest(
    bytes: &[u8],
    datasets: &DatasetConfigV1,
    commit: RequestCommitV1,
    deadline: Timestamp,
    artifacts: &dyn ArtifactStore,
    authority: &dyn RequestCommitRepo,
) -> anyhow::Result<()> {
    let import = DatasetImportV1::parse(bytes).context("reading bounded dataset export")?;
    commit_import(import, datasets, commit, deadline, artifacts, authority)
        .await
        .context("committing dataset export under request fence")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "version":1,
            "source":{"backend":"redis","version":"8.0","experimental":true,"dedupe":"approximate"},
            "policy":{"purgeOnStart":false,"sharedFilesystemQueue":false,"authoritativeBackend":"postgre_sql"},
            "dataset":"records","schemaVersion":"json_object_v1","batch":"export-1",
            "items":[{"key":"one","value":{"text":"private-import-canary"}}]
        })
    }

    #[test]
    fn inspection_reports_omissions_without_item_content() {
        let mut out = Vec::new();
        assert_eq!(
            inspect_manifest(&serde_json::to_vec(&fixture()).unwrap(), &mut out).unwrap(),
            ExitCode::SUCCESS
        );
        let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(report["experimental"], true);
        assert_eq!(report["possibleOmissions"], true);
        assert_eq!(report["completeCoverage"], false);
        assert!(!String::from_utf8(out).unwrap().contains("private-import-canary"));
    }

    #[test]
    fn destructive_policy_is_explicit_and_nonzero() {
        let mut value = fixture();
        value["policy"]["purgeOnStart"] = true.into();
        let mut out = Vec::new();
        assert_eq!(
            inspect_manifest(&serde_json::to_vec(&value).unwrap(), &mut out).unwrap(),
            ExitCode::from(2)
        );
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("destructive_purge_on_start"));
    }

    #[test]
    fn rejects_opaque_object_and_oversize_without_output() {
        for bytes in [
            b"opaque serialized object".to_vec(),
            vec![b' '; crawlx_core::dataset::import::MAX_IMPORT_BYTES + 1],
        ] {
            let mut out = Vec::new();
            let error = inspect_manifest(&bytes, &mut out).unwrap_err();
            assert!(out.is_empty());
            assert!(!format!("{error:?}").contains("opaque serialized object"));
        }
    }

    #[tokio::test]
    async fn apply_sends_authenticated_bounded_json_with_real_request_selection() {
        use wiremock::matchers::{header, method, path, query_param};
        let server = wiremock::MockServer::start().await;
        let run_id = crawlx_core::CrawlRunId(uuid::Uuid::from_u128(1));
        wiremock::Mock::given(method("POST"))
            .and(path(format!("/v1/crawls/{run_id}/datasets/import")))
            .and(query_param("requestId", "7"))
            .and(query_param("fence", "11"))
            .and(query_param("stateVersion", "3"))
            .and(header("authorization", "Bearer fixture-api-key"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data":{"itemCount":1,"completeCoverage":false}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), serde_json::to_vec(&fixture()).unwrap()).unwrap();
        let args = DatasetImportArgs {
            command: DatasetImportCommand::Apply(ApplyArgs {
                input: file.path().to_owned(),
                run: run_id,
                request_id: 7,
                fence: 11,
                state_version: 3,
                api: crate::authz::ApiTarget {
                    api_url: server.uri(),
                    api_key: Some("fixture-api-key".into()),
                },
            }),
        };
        let mut out = Vec::new();
        assert_eq!(run(args, &mut out).await.unwrap(), ExitCode::SUCCESS);
        let receipt: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(receipt["committed"], true);
        assert!(!String::from_utf8(out).unwrap().contains("private-import-canary"));
    }

    #[tokio::test]
    async fn offline_input_refuses_directories_and_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        assert!(read_export(directory.path()).await.is_err());
        #[cfg(unix)]
        {
            let file = directory.path().join("input.json");
            std::fs::write(&file, serde_json::to_vec(&fixture()).unwrap()).unwrap();
            let link = directory.path().join("link.json");
            std::os::unix::fs::symlink(file, &link).unwrap();
            assert!(read_export(&link).await.is_err());
        }
    }
}
