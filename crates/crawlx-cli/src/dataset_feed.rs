//! Stream local CSV/XML seed rows into an existing admitted run.
//!
//! Each bounded request batch advances the existing frontier loader cursor atomically. The
//! local checkpoint is that same cursor, written only after acknowledgment. Replaying a batch
//! after a lost acknowledgment uses its deterministic receipt key. No source URL is fetched here;
//! normal worker authorization, robots and checked egress govern every imported request.

use anyhow::{bail, Context as _};
use clap::{Args, ValueEnum};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::LoaderCursorV1;
use crawlx_url::feed_stream::{
    CsvTemplate, FeedRowStream, FeedTemplate, RowOutcome, StreamLimits, XmlField, XmlName, XmlTemplate,
};
use serde_json::{json, Value};
use std::io::{Read, Seek, SeekFrom, Take, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use url::Url;

const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Local source representation; templates are declarative, never executable.
#[derive(Clone, Copy, Debug, ValueEnum)]
#[non_exhaustive]
pub enum FeedFormat {
    /// CSV with a header naming the URL column.
    Csv,
    /// XML rows selected by element local name and optional namespace URI.
    Xml,
}

/// Stream seed proposals into an existing run whose producer remains open.
#[derive(Clone, Debug, Args)]
#[non_exhaustive]
pub struct FeedImportArgs {
    /// Local regular file; source bytes are capped at 64 MiB.
    pub input: PathBuf,
    /// Existing admitted run identifier.
    #[arg(long)]
    pub run: crawlx_core::CrawlRunId,
    /// Current positive producer epoch of the admitted run; initial epoch is one.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..))]
    pub producer_epoch: u64,
    /// Source format.
    #[arg(long, value_enum)]
    pub format: FeedFormat,
    /// Stable source identifier, reused with the same run on restart.
    #[arg(long)]
    pub source: String,
    /// Existing loader-cursor checkpoint, atomically replaced after each acknowledged batch.
    #[arg(long)]
    pub cursor_file: PathBuf,
    /// CSV header or XML child element holding each URL.
    #[arg(long, default_value = "url")]
    pub url_field: String,
    /// XML row element local name.
    #[arg(long, default_value = "item")]
    pub item_element: String,
    /// XML namespace URI of both row and URL elements; absent means no namespace.
    #[arg(long)]
    pub namespace: Option<String>,
    /// Rows per transaction, also counting malformed rows; cannot exceed run queue batch size.
    #[arg(long, default_value_t = 128, value_parser = clap::value_parser!(u16).range(1..=128))]
    pub batch_size: u16,
    /// API connection and bearer key; no target-site traffic uses this client.
    #[command(flatten)]
    pub api: crate::authz::ApiTarget,
}

fn template(args: &FeedImportArgs) -> anyhow::Result<FeedTemplate> {
    Ok(match args.format {
        FeedFormat::Csv => FeedTemplate::Csv(
            CsvTemplate::with_header()
                .map_column(&args.url_field, "url")
                .require("url"),
        ),
        FeedFormat::Xml => {
            let name = |local: &str| match &args.namespace {
                Some(namespace) => XmlName::namespaced(namespace, local),
                None => XmlName::local(local),
            };
            FeedTemplate::Xml(XmlTemplate::new(
                name(&args.item_element),
                vec![XmlField::element("url", vec![name(&args.url_field)]).required()],
            )?)
        }
    })
}

struct Source {
    rows: FeedRowStream<Take<std::fs::File>>,
    cursor: Option<LoaderCursorV1>,
    source: String,
    digest: Digest,
    identity_file: std::fs::File,
    identity: std::fs::Metadata,
}

struct Batch {
    requests: Vec<Value>,
    next: LoaderCursorV1,
    malformed: u64,
    invalid_urls: u64,
    rows: usize,
}

fn unchanged(file: &std::fs::File, original: &std::fs::Metadata) -> anyhow::Result<()> {
    let current = file.metadata()?;
    let same = current.len() == original.len() && current.modified()? == original.modified()?;
    #[cfg(unix)]
    let same = {
        use std::os::unix::fs::MetadataExt as _;
        same && current.dev() == original.dev()
            && current.ino() == original.ino()
            && current.ctime() == original.ctime()
            && current.ctime_nsec() == original.ctime_nsec()
    };
    if !same {
        bail!("feed source changed while importing");
    }
    Ok(())
}

fn open(args: &FeedImportArgs) -> anyhow::Result<Source> {
    if args.source.is_empty()
        || args.source.len() > 128
        || !args.source.bytes().all(|byte| byte.is_ascii_graphic())
    {
        bail!("source must contain 1..=128 printable ASCII bytes");
    }
    if args.input == args.cursor_file {
        bail!("source and cursor paths must differ");
    }
    let mut file = std::fs::File::open(&args.input).context("opening feed source")?;
    let identity = file.metadata()?;
    if !identity.is_file() {
        bail!("feed source must be a regular file");
    }
    if identity.len() > MAX_SOURCE_BYTES {
        bail!("feed source exceeds 64 MiB");
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crawlx/feed-import-bytes/v1");
    hasher.update(&[0]);
    let mut buffer = [0u8; 64 * 1024];
    let mut length = 0u64;
    let mut bounded = (&mut file).take(MAX_SOURCE_BYTES + 1);
    loop {
        let read = bounded.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        length = length.saturating_add(u64::try_from(read)?);
        if length > MAX_SOURCE_BYTES {
            bail!("feed source exceeds 64 MiB");
        }
        hasher.update(&buffer[..read]);
    }
    unchanged(&file, &identity)?;
    if length != identity.len() {
        bail!("feed source changed while hashing");
    }
    file.seek(SeekFrom::Start(0))?;
    let template = template(args)?;
    let digest = Digest::of_value(
        "crawlx/feed-import-source/v1",
        &(
            Digest(*hasher.finalize().as_bytes()),
            match args.format {
                FeedFormat::Csv => "csv",
                FeedFormat::Xml => "xml",
            },
            &args.url_field,
            &args.item_element,
            &args.namespace,
            args.run,
            args.producer_epoch,
            args.batch_size,
        ),
    )?;
    let cursor: Option<LoaderCursorV1> = match std::fs::File::open(&args.cursor_file) {
        Ok(file) => Some(serde_json::from_reader(file.take(4097)).context("reading feed cursor")?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if cursor
        .as_ref()
        .is_some_and(|cursor| cursor.source != args.source || cursor.source_digest != digest)
    {
        bail!("feed source or parser configuration changed during resume");
    }
    let identity_file = file.try_clone()?;
    let mut rows = FeedRowStream::new(file.take(length), &template, StreamLimits::default())?;
    if let Some(cursor) = &cursor {
        for _ in 0..cursor.position {
            rows.next().context("feed cursor exceeds source")??;
        }
    }
    unchanged(&identity_file, &identity)?;
    Ok(Source {
        rows,
        cursor,
        source: args.source.clone(),
        digest,
        identity_file,
        identity,
    })
}

impl Source {
    fn batch(&mut self, limit: usize) -> anyhow::Result<Option<Batch>> {
        unchanged(&self.identity_file, &self.identity)?;
        let mut batch = Batch {
            requests: Vec::with_capacity(limit),
            next: LoaderCursorV1::new(
                self.source.clone(),
                self.digest,
                self.cursor.as_ref().map_or(0, |cursor| cursor.position),
            ),
            malformed: 0,
            invalid_urls: 0,
            rows: 0,
        };
        for row in self.rows.by_ref().take(limit) {
            let row = row?;
            batch.rows += 1;
            batch.next.position = row.cursor.row_index;
            match row.outcome {
                RowOutcome::Row(fields) => {
                    let url = fields.get("url").and_then(|value| Url::parse(value.trim()).ok());
                    match url {
                        Some(url)
                            if matches!(url.scheme(), "http" | "https")
                                && url.username().is_empty()
                                && url.password().is_none()
                                && url.as_str().len() <= 4096 =>
                        {
                            batch.requests.push(json!({"url":url}))
                        }
                        _ => batch.invalid_urls += 1,
                    }
                }
                RowOutcome::Malformed(_) => batch.malformed += 1,
                _ => bail!("unsupported feed row outcome"),
            }
        }
        unchanged(&self.identity_file, &self.identity)?;
        // Pin empty sources too, without creating a competing checkpoint scheme.
        Ok((batch.rows > 0 || self.cursor.is_none()).then_some(batch))
    }
}

fn checkpoint(path: &Path, cursor: &LoaderCursorV1) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(file.as_file_mut(), cursor)?;
    file.as_file_mut().sync_all()?;
    file.persist(path).context("replacing feed cursor")?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn endpoint(args: &FeedImportArgs) -> anyhow::Result<Url> {
    let mut url = Url::parse(&args.api.api_url).context("invalid API URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("API URL must be an absolute HTTP(S) URL without credentials");
    }
    url.set_query(None);
    url.set_fragment(None);
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("API URL cannot carry a path"))?
        .pop_if_empty()
        .extend(["v1", "crawls", &args.run.to_string(), "requests"]);
    Ok(url)
}

async fn append(
    http: &reqwest::Client,
    endpoint: &Url,
    args: &FeedImportArgs,
    source: &Source,
    batch: &Batch,
) -> anyhow::Result<Value> {
    let key = Digest::of_value(
        "crawlx/feed-import-batch/v1",
        &(args.run, args.producer_epoch, &source.cursor, &batch.next),
    )?
    .to_hex();
    let mut request = http
        .post(endpoint.clone())
        .header("Idempotency-Key", key)
        .json(&json!({
            "producerEpoch":args.producer_epoch,"requests":batch.requests,
            "expectedCursor":source.cursor,"nextCursor":batch.next,
        }));
    if let Some(key) = &args.api.api_key {
        request = request.bearer_auth(key);
    }
    let mut response = request.send().await.map_err(|error| error.without_url())?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.without_url())? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            bail!("feed import API response exceeds one MiB");
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        // API errors may quote content; do not echo them or bearer/URL information.
        bail!("feed import API rejected batch with status {}", status.as_u16());
    }
    let receipt: Value = serde_json::from_slice(&bytes).context("invalid feed import receipt")?;
    let acknowledged: crawlx_core::orchestration::RequestBatchReceiptV1 = serde_json::from_value(
        receipt
            .get("data")
            .cloned()
            .context("feed import response lacks a batch receipt")?,
    )
    .context("invalid feed import batch receipt")?;
    if acknowledged.cursor.as_ref() != Some(&batch.next) {
        bail!("feed import acknowledgment does not match the proposed cursor");
    }
    Ok(receipt)
}

/// Import bounded seed batches using the admitted request API and durable loader CAS.
///
/// # Errors
/// Rejects invalid source/template/checkpoints, changed sources, API policy/CAS failures, and I/O errors.
pub async fn run(args: FeedImportArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let endpoint = endpoint(&args)?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()?;
    let pool = crawlx_worker::runtime::CpuPool::with_permits(std::num::NonZeroUsize::MIN);
    let mut source = pool
        .run({
            let args = args.clone();
            move || open(&args)
        })
        .await
        .context("feed import CPU task failed")??;
    loop {
        let limit = usize::from(args.batch_size);
        let (returned, batch) = pool
            .run(move || {
                let batch = source.batch(limit);
                (source, batch)
            })
            .await
            .context("feed import CPU task failed")?;
        source = returned;
        let Some(batch) = batch? else {
            break;
        };
        let receipt = append(&http, &endpoint, &args, &source, &batch).await?;
        let path = args.cursor_file.clone();
        let next = batch.next.clone();
        pool.run(move || checkpoint(&path, &next))
            .await
            .context("feed cursor CPU task failed")??;
        source.cursor = Some(batch.next);
        serde_json::to_writer(
            &mut *out,
            &json!({
                "position":source.cursor.as_ref().map(|cursor| cursor.position),
                "rows":batch.rows,"malformed":batch.malformed,"invalidUrls":batch.invalid_urls,
                "inserted":receipt["data"]["inserted"].as_array().map(Vec::len),
                "duplicates":receipt["data"]["duplicates"],
            }),
        )?;
        writeln!(out)?;
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn args(input: PathBuf, cursor_file: PathBuf) -> FeedImportArgs {
        FeedImportArgs {
            input,
            cursor_file,
            run: crawlx_core::CrawlRunId::new(),
            producer_epoch: 1,
            format: FeedFormat::Csv,
            source: "local-feed".into(),
            url_field: "url".into(),
            item_element: "item".into(),
            namespace: None,
            batch_size: 128,
            api: crate::authz::ApiTarget {
                api_url: "http://127.0.0.1:8080".into(),
                api_key: None,
            },
        }
    }

    #[test]
    fn producer_epoch_defaults_to_one_and_rejects_zero() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Command {
            #[command(flatten)]
            args: FeedImportArgs,
        }
        let input = [
            "feed-import",
            "feed.csv",
            "--run",
            "00000000-0000-0000-0000-000000000001",
            "--format",
            "csv",
            "--source",
            "fixture",
            "--cursor-file",
            "cursor.json",
        ];
        assert_eq!(Command::try_parse_from(input).unwrap().args.producer_epoch, 1);
        assert!(Command::try_parse_from(input.into_iter().chain(["--producer-epoch", "0"])).is_err());
    }

    #[tokio::test]
    async fn hundred_thousand_rows_resume_with_atomic_frontier_cursor_and_bounded_batches() {
        use crawlx_core::orchestration::{OrchestrationConfigV1, ProducerModeV1, RequestBatchV1};
        use crawlx_core::repo::{FrontierRepo, RunRepo};
        use crawlx_core::request::RequestEnvelopeV1;
        use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("feed.csv");
        let mut file = std::fs::File::create(&input).unwrap();
        writeln!(file, "url").unwrap();
        for index in 0..100_000 {
            match index {
                17 => writeln!(file).unwrap(),
                30 => writeln!(file, "file:///outside").unwrap(),
                _ => writeln!(file, "https://fixture.test/row/{index}").unwrap(),
            }
        }
        writeln!(file, "\"\"").unwrap();
        drop(file);
        let mut config = create_crawl("https://fixture.test/", &[], 1);
        let mut orchestration = OrchestrationConfigV1::default();
        orchestration.queue.producer_mode = ProducerModeV1::Continuous;
        orchestration.queue.max_pending_entries = 100_000;
        orchestration.queue.max_pending_envelope_bytes = 128 * 1024 * 1024;
        orchestration.queue.batch_size = 128;
        config.orchestration = Some(orchestration);
        let run = crawl_run(crawlx_core::TenantId::new(), config);
        let store = crawlx_storage::MemoryStore::new();
        store.create(&run, None).await.unwrap();
        let mut args = args(input.clone(), dir.path().join("cursor.json"));
        args.run = run.id;
        let transaction = |source: &Source, batch: &Batch| {
            let requests = batch
                .requests
                .iter()
                .map(|proposal| {
                    RequestEnvelopeV1::get(canonical_url(proposal["url"].as_str().unwrap()), 0, None)
                })
                .collect();
            let key = Digest::of_value(
                "crawlx/feed-import-batch/v1",
                &(args.run, args.producer_epoch, &source.cursor, &batch.next),
            )
            .unwrap();
            let mut native = RequestBatchV1::new(run.tenant, run.id, "anonymous".into(), key, requests);
            native.expected_cursor = source.cursor.clone();
            native.next_cursor = Some(batch.next.clone());
            native
        };
        let mut source = open(&args).unwrap();
        while source.cursor.as_ref().map_or(0, |cursor| cursor.position) < 50_000 {
            let batch = source.batch(128).unwrap().unwrap();
            assert!(batch.requests.len() <= 128);
            store.append_batch(transaction(&source, &batch)).await.unwrap();
            source.cursor = Some(batch.next);
        }
        checkpoint(&args.cursor_file, source.cursor.as_ref().unwrap()).unwrap();
        let batch = source.batch(128).unwrap().unwrap();
        let native = transaction(&source, &batch);
        let committed = store.append_batch(native.clone()).await.unwrap();
        assert_eq!(
            store.loader_cursor(run.id, &args.source).await.unwrap(),
            Some(batch.next.clone())
        );
        // Crash after atomic server commit, before the local checkpoint/acknowledgment.
        drop(source);
        let mut source = open(&args).unwrap();
        let replay = source.batch(128).unwrap().unwrap();
        assert_eq!(replay.next, batch.next);
        assert_eq!(
            store.append_batch(transaction(&source, &replay)).await.unwrap(),
            committed
        );
        source.cursor = Some(replay.next);
        let count = store.open_count(run.id).await.unwrap();
        let before = store.loader_cursor(run.id, &args.source).await.unwrap();
        let mut stale = native;
        stale.batch_id = Digest::of("test/feed-stale-batch/v1", b"stale");
        assert!(store.append_batch(stale).await.is_err());
        assert_eq!(store.loader_cursor(run.id, &args.source).await.unwrap(), before);
        assert_eq!(store.open_count(run.id).await.unwrap(), count);
        let mut malformed = 0;
        while let Some(batch) = source.batch(128).unwrap() {
            assert!(batch.requests.len() <= 128);
            malformed += batch.malformed;
            store.append_batch(transaction(&source, &batch)).await.unwrap();
            source.cursor = Some(batch.next);
        }
        assert_eq!(malformed, 1);
        assert_eq!(source.cursor.as_ref().unwrap().position, 100_000);
        assert_eq!(
            store.loader_cursor(run.id, &args.source).await.unwrap(),
            source.cursor
        );
        assert_eq!(store.open_count(run.id).await.unwrap(), 99_998);
        assert!(source.rows.stats().peak_buffered_bytes < 256 * 1024);
        std::fs::write(input, "url\nhttps://fixture.test/changed\n").unwrap();
        assert!(open(&args).is_err());
    }

    #[tokio::test]
    async fn import_drives_authenticated_native_api_and_restarts_without_duplicate_requests() {
        use crawlx_api::{ApiConfig, ApiStore, AppState, Repos, Scope};
        use crawlx_core::orchestration::{OrchestrationConfigV1, ProducerModeV1};
        use crawlx_core::repo::{FrontierRepo, RunRepo};
        use crawlx_storage::testkit::{crawl_run, create_crawl};
        use std::sync::Arc;
        let clock = Arc::new(crawlx_core::time::ManualClock::new(
            "2026-11-10T00:00:00Z".parse().unwrap(),
        ));
        let store = Arc::new(crawlx_storage::MemoryStore::new());
        let artifacts = Arc::new(crawlx_storage::MemoryArtifactStore::in_memory(
            store.clone(),
            clock.clone(),
        ));
        let (repos, api) = Repos::memory_with_api(store.clone(), artifacts);
        let tenant = crawlx_core::TenantId::new();
        let key = crawlx_api::auth::generate_key();
        let record = crawlx_api::auth::key_record(&key, tenant, Scope::all_set()).unwrap();
        api.key_insert(&record, "fixture").await.unwrap();
        let config = ApiConfig {
            rate_limit_per_minute: 0,
            ..ApiConfig::default()
        };
        let state = AppState::builder(
            repos,
            crawlx_api::admission_policy(&config, clock.clone()),
            config,
        )
        .clock(clock)
        .build();
        let mut config = create_crawl("https://fixture.test/", &[], 1);
        let mut orchestration = OrchestrationConfigV1::default();
        orchestration.queue.producer_mode = ProducerModeV1::Continuous;
        config.orchestration = Some(orchestration);
        let stored_run = crawl_run(tenant, config);
        store.create(&stored_run, None).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, crawlx_api::router(state)).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("feed.csv");
        std::fs::write(
            &input,
            "url\nhttps://fixture.test/one\n\"\"\nhttps://fixture.test/one\nhttps://fixture.test/two\n",
        )
        .unwrap();
        let mut args = args(input, dir.path().join("cursor.json"));
        args.run = stored_run.id;
        args.batch_size = 2;
        args.api.api_url = endpoint;
        args.api.api_key = Some(key);
        let mut output = Vec::new();
        assert_eq!(
            super::run(args.clone(), &mut output).await.unwrap(),
            ExitCode::SUCCESS
        );
        let cursor = store
            .loader_cursor(stored_run.id, &args.source)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cursor.position, 4);
        assert_eq!(store.open_count(stored_run.id).await.unwrap(), 2);
        assert_eq!(String::from_utf8(output).unwrap().lines().count(), 2);
        assert_eq!(
            super::run(args.clone(), &mut Vec::new()).await.unwrap(),
            ExitCode::SUCCESS
        );
        assert_eq!(
            store.loader_cursor(stored_run.id, &args.source).await.unwrap(),
            Some(cursor)
        );
        assert_eq!(store.open_count(stored_run.id).await.unwrap(), 2);
        server.abort();
    }

    #[test]
    fn namespaced_xml_resumes_physical_rows_and_detects_live_source_changes() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("feed.xml");
        std::fs::write(
            &input,
            r#"<feed xmlns="urn:fixture:feed">
            <row><url>https://fixture.test/one</url></row><row/>
            <row><url>file:///outside</url></row>
            <row><url>https://fixture.test/two</url></row></feed>"#,
        )
        .unwrap();
        let mut args = args(input.clone(), dir.path().join("cursor.json"));
        args.format = FeedFormat::Xml;
        args.namespace = Some("urn:fixture:feed".into());
        args.item_element = "row".into();
        let mut source = open(&args).unwrap();
        let batch = source.batch(2).unwrap().unwrap();
        assert_eq!(batch.next.position, 2);
        assert_eq!(batch.malformed, 1);
        assert_eq!(batch.requests.len(), 1);
        checkpoint(&args.cursor_file, &batch.next).unwrap();
        drop(source);
        let mut source = open(&args).unwrap();
        let batch = source.batch(2).unwrap().unwrap();
        assert_eq!(batch.next.position, 4);
        assert_eq!(batch.invalid_urls, 1);
        assert_eq!(batch.requests.len(), 1);
        // The parser holds the same descriptor as the verified digest pass.
        std::fs::OpenOptions::new()
            .append(true)
            .open(input)
            .unwrap()
            .write_all(b" ")
            .unwrap();
        assert!(source.batch(2).is_err());
        assert!(open(&args).is_err());
    }
}
