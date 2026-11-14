//! CLI retained-source binding: real native parsing, scope, expiry and zero added acquisition.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_core::acquisition::AcquisitionResultV1;
use crawlx_core::captcha::CaptchaSecrets;
use crawlx_core::custody::{
    ArtifactReadState, CustodyLease, RunSecretAuthority, RunSecretSnapshot, SecretEpoch,
};
use crawlx_core::repo::{ArtifactStore, Sensitivity};
use crawlx_core::{
    ArtifactId, ArtifactRef, Clock as _, CrawlRunId, SecretOr, StoreError, SystemClock, TenantId, Timestamp,
};
use crawlx_extract::pipeline::ParserPipeline;
use crawlx_worker::reparse::{ReparseIntent, ReparseServices, RetainedRepresentation};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

struct FixtureAuthority {
    snapshot: RunSecretSnapshot,
    artifact: ArtifactId,
    finalized: bool,
    lost: bool,
}
#[async_trait]
impl RunSecretAuthority for FixtureAuthority {
    async fn initialize(&self, _: &CustodyLease) -> Result<RunSecretSnapshot, StoreError> {
        Err(StoreError::LeaseLost)
    }
    async fn snapshot(&self, _: &CustodyLease) -> Result<RunSecretSnapshot, StoreError> {
        Err(StoreError::LeaseLost)
    }
    async fn renew_authority(
        &self,
        _: &CustodyLease,
        _: SecretEpoch,
        _: uuid::Uuid,
        _: Timestamp,
    ) -> Result<RunSecretSnapshot, StoreError> {
        Err(StoreError::LeaseLost)
    }
    async fn register(
        &self,
        _: &CustodyLease,
        _: SecretEpoch,
        _: uuid::Uuid,
        _: &SecretOr<String>,
    ) -> Result<RunSecretSnapshot, StoreError> {
        Err(StoreError::LeaseLost)
    }
    async fn retained_snapshot(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        expected: SecretEpoch,
    ) -> Result<RunSecretSnapshot, StoreError> {
        if self.lost
            || tenant != self.snapshot.version.tenant
            || run != self.snapshot.version.run
            || expected != self.snapshot.version
        {
            return Err(StoreError::RetentionDenied(
                "original registry unavailable".into(),
            ));
        }
        Ok(self.snapshot.clone())
    }
    async fn read_state(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: ArtifactId,
    ) -> Result<ArtifactReadState, StoreError> {
        if tenant != self.snapshot.version.tenant
            || run != self.snapshot.version.run
            || artifact != self.artifact
        {
            return Err(StoreError::LeaseLost);
        }
        if self.finalized {
            Ok(ArtifactReadState::Finalized(self.snapshot.version))
        } else {
            Ok(ArtifactReadState::Live(self.snapshot.clone()))
        }
    }
}

struct Source {
    server: MockServer,
    stores: crawlx_worker::Stores,
    intent: ReparseIntent,
    authority: FixtureAuthority,
    _files: tempfile::TempDir,
}
impl Source {
    async fn new(zdr: bool) -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/robots.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_string("User-agent: *\nAllow: /\n"))
            .mount(&server)
            .await;
        let body = format!("<html><head><title>Retained report</title></head><body><article><h1>Retained report</h1><p>{} original-private-value</p></article></body></html>", "Original retained content remains available for offline parsing. ".repeat(30));
        Mock::given(method("GET"))
            .and(path("/page"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html; charset=utf-8")
                    .set_body_string(body),
            )
            .mount(&server)
            .await;
        let files = tempfile::tempdir().unwrap();
        let stores =
            crawlx_worker::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), files.path())
                .await
                .unwrap();
        let record = crawlx_policy::AuthorizationRecord {
            authorized_networks: vec!["127.0.0.0/8".parse().unwrap()],
            ..crawlx_policy::testkit::sample_record(stores.tenant, SystemClock.now(), &[&server.uri()])
        };
        let mut crawl =
            crawlx_core::CreateCrawl::new(url::Url::parse(&format!("{}/page", server.uri())).unwrap());
        crawl.mode = crawlx_core::config::CrawlMode::Static;
        crawl.scope.max_discovery_depth = 0;
        crawl.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
        crawl.scope.known_files.clear();
        crawl.limits.urls = 1;
        crawl.safety.allow_private_networks = true;
        crawl.safety.authorization_record_ref = Some(record.id);
        if zdr {
            crawl.retention.mode = crawlx_core::config::RetentionMode::Zdr;
        }
        let options = crawlx_core::scrape::ScrapeOptions {
            formats: vec![
                crawlx_core::scrape::FormatSpec::RawHtml,
                crawlx_core::scrape::FormatSpec::Markdown,
            ],
            max_age_ms: 0,
            only_main_content: false,
            ..crawlx_core::scrape::ScrapeOptions::default()
        };
        crawl.scrape = Some(crawlx_core::scrape::ScrapeJob::new(
            crawlx_core::scrape::JobKind::Scrape,
            options,
        ));
        let cfg = crawlx_worker::WorkerConfig {
            artifacts_dir: files.path().to_owned(),
            egress: crawlx_worker::EgressConfig {
                extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
                ..Default::default()
            },
            ..crawlx_worker::WorkerConfig::default()
        };
        let report = crawlx_worker::run_local_with(
            crawlx_worker::LocalRun::new(crawl, cfg)
                .with_stores(stores.clone())
                .with_authorization(record),
        )
        .await
        .unwrap();
        let page = report.pages.first().unwrap();
        let acquisition: AcquisitionResultV1 =
            serde_json::from_value(page.metadata["acquisition"].clone()).unwrap();
        // ZDR is refused before source lookup. Use a distinct unreachable artifact only for that refusal case.
        let artifact = acquisition
            .wire_body
            .as_ref()
            .map_or_else(ArtifactId::new, |source| source.id);
        let secrets = CaptchaSecrets::default();
        secrets
            .register(SecretOr::secret("original-private-value".to_owned()))
            .unwrap();
        let snapshot = RunSecretSnapshot::new(
            SecretEpoch::new(stores.tenant, report.run_id, uuid::Uuid::nil(), 1),
            secrets,
        );
        let intent = ReparseIntent::new(
            stores.tenant,
            report.run_id,
            page.frontier_id,
            "anonymous".into(),
            RetainedRepresentation::WireBody,
        );
        let authority = FixtureAuthority {
            snapshot,
            artifact,
            finalized: false,
            lost: false,
        };
        Self {
            server,
            stores,
            intent,
            authority,
            _files: files,
        }
    }
    async fn execute(&self) -> anyhow::Result<String> {
        self.execute_artifacts(self.stores.artifacts.as_ref(), &self.intent)
            .await
    }
    async fn execute_artifacts(
        &self,
        artifacts: &dyn ArtifactStore,
        intent: &ReparseIntent,
    ) -> anyhow::Result<String> {
        let services = ReparseServices {
            runs: self.stores.runs.as_ref(),
            pages: self.stores.pages.as_ref(),
            frontier: self.stores.frontier.as_ref(),
            artifacts,
            clock: &SystemClock,
        };
        let mut out = Vec::new();
        let _exit = crawlx_cli::reparse::execute_with_services(
            &services,
            intent,
            ParserPipeline::new(Default::default()).unwrap(),
            &self.authority,
            &mut out,
            &CancellationToken::new(),
        )
        .await?;
        Ok(String::from_utf8(out).unwrap())
    }
}

#[tokio::test]
async fn retained_source_reparse_runs_real_parser_with_original_privacy_and_no_new_acquisition() {
    let source = Source::new(false).await;
    let requests = source.server.received_requests().await.unwrap().len();
    let output = source.execute().await.unwrap();
    let document: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(document["networkRequests"], 0);
    assert_eq!(document["persisted"], false);
    assert!(document["data"]["text"]
        .as_str()
        .unwrap()
        .contains("Original retained content"));
    assert!(!output.contains("original-private-value"));
    assert!(document["parserDigest"].is_string());
    assert_eq!(source.server.received_requests().await.unwrap().len(), requests);
}

#[tokio::test]
async fn finalized_original_registry_supports_reparse_but_lost_registry_never_becomes_empty() {
    let mut source = Source::new(false).await;
    source.authority.finalized = true;
    assert!(source.execute().await.is_ok());
    source.authority.lost = true;
    assert!(source.execute().await.is_err());
}

struct Expired<'a>(&'a dyn ArtifactStore);
#[async_trait]
impl ArtifactStore for Expired<'_> {
    async fn put(&self, _: CrawlRunId, _: Sensitivity, _: &str, _: &[u8]) -> Result<ArtifactRef, StoreError> {
        panic!("offline reparse must not publish")
    }
    async fn get(&self, _: &ArtifactRef) -> Result<Vec<u8>, StoreError> {
        panic!("expired source must not be read")
    }
    async fn archive_custody(
        &self,
        _: TenantId,
        _: CrawlRunId,
        _: &ArtifactRef,
        _: u64,
    ) -> Result<crawlx_core::archive_catalog::ArchiveCustodyV1, StoreError> {
        let _ = self.0;
        Ok(crawlx_core::archive_catalog::ArchiveCustodyV1::content(Some(
            SystemClock.now() - chrono::Duration::seconds(1),
        )))
    }
}

#[tokio::test]
async fn zdr_expired_and_foreign_sources_fail_without_acquisition() {
    let zdr = Source::new(true).await;
    let before = zdr.server.received_requests().await.unwrap().len();
    assert!(zdr.execute().await.is_err());
    assert_eq!(zdr.server.received_requests().await.unwrap().len(), before);
    let source = Source::new(false).await;
    let before = source.server.received_requests().await.unwrap().len();
    assert!(source
        .execute_artifacts(&Expired(source.stores.artifacts.as_ref()), &source.intent)
        .await
        .is_err());
    let mut foreign = source.intent.clone();
    foreign.tenant = TenantId::new();
    assert!(source
        .execute_artifacts(source.stores.artifacts.as_ref(), &foreign)
        .await
        .is_err());
    foreign = source.intent.clone();
    foreign.principal = "foreign".into();
    assert!(source
        .execute_artifacts(source.stores.artifacts.as_ref(), &foreign)
        .await
        .is_err());
    assert_eq!(source.server.received_requests().await.unwrap().len(), before);
}

#[tokio::test]
async fn precancelled_reparse_reads_no_additional_source_or_target() {
    let source = Source::new(false).await;
    let before = source.server.received_requests().await.unwrap().len();
    let services = ReparseServices {
        runs: source.stores.runs.as_ref(),
        pages: source.stores.pages.as_ref(),
        frontier: source.stores.frontier.as_ref(),
        artifacts: source.stores.artifacts.as_ref(),
        clock: &SystemClock,
    };
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut out = Vec::new();
    assert!(crawlx_cli::reparse::execute_with_services(
        &services,
        &source.intent,
        ParserPipeline::new(Default::default()).unwrap(),
        &source.authority,
        &mut out,
        &cancel,
    )
    .await
    .is_err());
    assert!(out.is_empty());
    assert_eq!(source.server.received_requests().await.unwrap().len(), before);
}
