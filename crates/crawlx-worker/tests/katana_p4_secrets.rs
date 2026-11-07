//! Katana `-kb-validate-secrets` on the static plane: detected tokens are checked against the
//! operator's validator list through the fetch plane; the verdict lands on the finding and the
//! token lands nowhere.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod katana_p4_common;

use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::get;
use axum::Router;
use crawlx_extract::secret_validation::SecretValidators;
use crawlx_extract::SecretKind;
use crawlx_worker::katana::traffic_export::TrafficExportConfig;
use katana_p4_common::{crawl_with, page, page_at, page_paths, Collector, Crawled, Site};
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer as _;

/// Seeded GitHub-style tokens (never real): the provider accepts the first, rejects the second.
/// Assembled from parts so the source holds no contiguous token.
const GOOD: &str = concat!("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
const BAD: &str = concat!("gh", "p_ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrq");
/// A kind the validator list does not cover.
const AWS: &str = concat!("AKIA", "IOSFODNN7EXAMPLE");

/// `/` links to `/second` (the rejected token), `/third` (the accepted token again) and `/aws`.
async fn site() -> Site {
    Site::start(|_| {
        Router::new()
            .route(
                "/",
                get(|| async {
                    page(
                        "Home",
                        &format!(
                            r#"<p>key {GOOD}</p><a href="/second">s</a><a href="/third">t</a><a href="/aws">a</a>"#
                        ),
                    )
                }),
            )
            .route("/second", get(|| async { page("Second", &format!("<p>key {BAD}</p>")) }))
            .route("/third", get(|| async { page("Third", &format!("<p>again {GOOD}</p>")) }))
            .route("/aws", get(|| async { page("Aws", &format!("<p>{AWS}</p>")) }))
            .route(
                "/validate",
                get(|headers: HeaderMap| async move {
                    let bearer = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
                    if bearer == Some(&format!("Bearer {GOOD}")) {
                        StatusCode::OK
                    } else {
                        StatusCode::UNAUTHORIZED
                    }
                }),
            )
    })
    .await
}

/// The operator's validator file for `site`, loaded from disk like the CLI does.
fn validators(site: &Site) -> Arc<SecretValidators> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("validators.json");
    let file = format!(
        r#"{{"version":1,"validators":[{{"kind":"github_token","method":"GET",
            "url":"http://{}/validate?probe=1&token={{token}}",
            "headers":{{"Authorization":"Bearer {{token}}"}},
            "valid_status":[200],"invalid_status":[401],"allow_http":true}}]}}"#,
        site.addr
    );
    std::fs::File::create(&path)
        .unwrap()
        .write_all(file.as_bytes())
        .unwrap();
    Arc::new(SecretValidators::load(&path).unwrap())
}

/// `validators(site)` plus a provider for the AWS kind that nothing listens on, so validating
/// an AWS key fails at the connection and the plane logs the failure (without the key).
fn validators_with_dead_aws_provider(site: &Site) -> Arc<SecretValidators> {
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("validators.json");
    let file = format!(
        r#"{{"version":1,"validators":[
            {{"kind":"github_token","method":"GET",
              "url":"http://{}/validate?probe=1&token={{token}}",
              "headers":{{"Authorization":"Bearer {{token}}"}},
              "valid_status":[200],"invalid_status":[401],"allow_http":true}},
            {{"kind":"aws_access_key_id","method":"GET",
              "url":"http://{dead}/validate?probe=aws&token={{token}}",
              "valid_status":[200],"invalid_status":[403],"allow_http":true}}]}}"#,
        site.addr
    );
    std::fs::File::create(&path)
        .unwrap()
        .write_all(file.as_bytes())
        .unwrap();
    Arc::new(SecretValidators::load(&path).unwrap())
}

async fn validated(site: &Site, validate: bool, list: Option<Arc<SecretValidators>>) -> Crawled {
    crawl_with(
        &site.base,
        move |c| {
            c.extract.detect_secrets = true;
            c.extract.validate_secrets = validate;
        },
        move |cfg| cfg.secret_validators = list,
        |run| run,
    )
    .await
}

fn validations(run: &Crawled, path: &str) -> Vec<(String, String)> {
    page_at(&run.report, path).metadata["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["kind"].as_str().unwrap().to_owned(),
                s["validation"].as_str().unwrap_or("none").to_owned(),
            )
        })
        .collect()
}

/// How a finding's kind reads in the page metadata.
fn kind(k: SecretKind) -> String {
    serde_json::to_value(k).unwrap().as_str().unwrap().to_owned()
}

fn finding(k: SecretKind, validation: &str) -> Vec<(String, String)> {
    vec![(kind(k), validation.to_owned())]
}

#[tokio::test]
async fn findings_are_validated_once_per_token_and_marked() {
    let site = site().await;
    let run = validated(&site, true, Some(validators(&site))).await;
    assert_eq!(validations(&run, "/"), finding(SecretKind::GitHubToken, "valid"));
    assert_eq!(
        validations(&run, "/second"),
        finding(SecretKind::GitHubToken, "invalid")
    );
    assert_eq!(
        validations(&run, "/third"),
        finding(SecretKind::GitHubToken, "valid")
    );
    assert_eq!(
        validations(&run, "/aws"),
        finding(SecretKind::AwsAccessKeyId, "unknown"),
        "no validator for the kind"
    );
    assert_eq!(
        site.count("/validate"),
        2,
        "one request per distinct token: {:?}",
        site.requests()
    );
    assert!(
        !page_paths(&run.report).iter().any(|p| p == "/validate"),
        "a validation is not a page"
    );
}

#[tokio::test]
async fn validation_is_off_unless_requested() {
    let site = site().await;
    let run = validated(&site, false, Some(validators(&site))).await;
    assert_eq!(validations(&run, "/"), finding(SecretKind::GitHubToken, "none"));
    assert_eq!(site.count("/validate"), 0);
}

#[tokio::test]
async fn without_an_operator_list_every_finding_stays_unknown_and_nothing_is_sent() {
    let site = site().await;
    let run = validated(&site, true, None).await;
    assert_eq!(
        validations(&run, "/"),
        finding(SecretKind::GitHubToken, "unknown")
    );
    assert_eq!(
        validations(&run, "/second"),
        finding(SecretKind::GitHubToken, "unknown")
    );
    assert_eq!(site.count("/validate"), 0);
}

/// Collects what `crawlx_*` crates log, at every level.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn the_token_is_neither_stored_nor_logged_nor_exported() {
    let site = site().await;
    let collector = Collector::start().await;
    let logs = LogBuffer::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(logs.clone())
            .with_ansi(false)
            .with_filter(
                Targets::new()
                    .with_target("crawlx_worker", LevelFilter::TRACE)
                    .with_target("crawlx_fetch", LevelFilter::TRACE)
                    .with_target("crawlx_extract", LevelFilter::TRACE),
            ),
    );
    let _guard = tracing::subscriber::set_default(subscriber);
    let list = validators_with_dead_aws_provider(&site);
    let mut export = TrafficExportConfig::new(collector.url.clone());
    export.retry_delays = Vec::new();
    export.flush_interval = Duration::from_secs(3600);
    let run = crawl_with(
        &site.base,
        |c| {
            c.extract.detect_secrets = true;
            c.extract.validate_secrets = true;
        },
        move |cfg| {
            cfg.secret_validators = Some(list);
            cfg.traffic_export = Some(export);
        },
        |run| run,
    )
    .await;
    assert_eq!(site.count("/validate"), 2, "the validator was asked");

    // stored: the findings carry kind, location, keyed hash and length, never the value
    let stored = serde_json::to_string(&run.report).unwrap();
    // the page bodies hold the token as page content; the report metadata does not
    for page in &run.report.pages {
        let metadata = page.metadata.to_string();
        for token in [GOOD, BAD, AWS] {
            assert!(!metadata.contains(token), "{} metadata leaks {token}", page.url);
        }
    }
    for token in [GOOD, BAD] {
        assert!(!stored.contains(token), "the serialized report leaks {token}");
    }
    // stored: the run's event log
    let events = run
        .stores
        .events
        .list_after(run.report.run_id, 0, 10_000)
        .await
        .unwrap();
    for event in &events {
        let payload = serde_json::to_string(event).unwrap();
        for token in [GOOD, BAD] {
            assert!(!payload.contains(token), "event {} leaks a token", event.kind);
        }
    }
    // logged
    let log = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        log.contains("secret validation request failed"),
        "the failed validation is logged, so the capture works:\n{log}"
    );
    for token in [GOOD, BAD, AWS, "validate?probe"] {
        assert!(!log.contains(token), "the log mentions {token}:\n{log}");
    }
    // exported: page fetches only, the validation request is not one
    let exported = collector.exchanges();
    assert!(!exported.is_empty());
    assert!(
        exported
            .iter()
            .all(|(_, target)| !target.starts_with("/validate")),
        "{exported:?}"
    );
    let events = serde_json::to_string(&collector.events()).unwrap();
    assert!(
        !events.contains("Bearer ghp_"),
        "no validation header was exported"
    );
}
