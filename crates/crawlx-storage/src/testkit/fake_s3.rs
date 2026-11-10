//! An in-process S3-compatible server (feature `fake-s3`): `PutObject`, `GetObject`,
//! `HeadObject`, `DeleteObject` and `ListObjectsV2` with continuation tokens, enough for
//! the SDK code path of [`S3Blobs`](crate::s3::S3Blobs). Used by this crate's `tests/s3.rs`
//! and by the crawlx-bench canary scan, which reads every stored object back through
//! [`FakeS3::objects`].

use crate::s3::{S3Blobs, S3Config, Sse};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Router;
use chrono::Utc;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// One recorded request: `(method, key, server-side-encryption header, KMS key-id header)`.
pub type LogEntry = (String, String, Option<String>, Option<String>);

#[derive(Default)]
struct Inner {
    objects: BTreeMap<String, (Vec<u8>, chrono::DateTime<Utc>)>,
    log: Vec<LogEntry>,
}

type Shared = Arc<Mutex<Inner>>;

/// Keys per `ListObjectsV2` page, small so the paginator has to follow continuation tokens.
pub const PAGE: usize = 2;

/// A running fake S3 endpoint.
#[derive(Clone)]
pub struct FakeS3 {
    endpoint: String,
    state: Shared,
}

impl std::fmt::Debug for FakeS3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeS3")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl FakeS3 {
    /// Bind a loopback listener and serve the fake until the runtime stops.
    ///
    /// # Errors
    /// The listener could not be bound.
    pub async fn start() -> std::io::Result<Self> {
        let state: Shared = Arc::default();
        let app = Router::new()
            .route("/{bucket}", get(list_objects))
            .route("/{bucket}/", get(list_objects))
            .route(
                "/{bucket}/{*key}",
                put(put_object)
                    .get(get_object)
                    .head(head_object)
                    .delete(delete_object),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::warn!(error = %e, "fake s3 stopped");
            }
        });
        Ok(Self {
            endpoint: format!("http://{addr}"),
            state,
        })
    }

    /// `http://127.0.0.1:<port>`.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// An [`S3Blobs`] over this endpoint with fixed test credentials and `sse`.
    #[must_use]
    pub fn blobs(&self, sse: Option<Sse>) -> S3Blobs {
        let mut cfg = S3Config::new("artifacts", "us-east-1").with_endpoint(&self.endpoint);
        cfg.sse = sse;
        cfg.max_attempts = 2;
        cfg.attempt_timeout = Duration::from_secs(10);
        let credentials = aws_sdk_s3::config::Credentials::new(
            "test-access-key",
            "test-secret-key",
            None,
            None,
            "crawlx-tests",
        );
        S3Blobs::with_credentials(&cfg, credentials)
    }

    /// Every stored object, by key.
    #[must_use]
    pub fn objects(&self) -> BTreeMap<String, Vec<u8>> {
        self.state
            .lock()
            .objects
            .iter()
            .map(|(k, (bytes, _))| (k.clone(), bytes.clone()))
            .collect()
    }

    /// Stored keys.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.state.lock().objects.keys().cloned().collect()
    }

    /// Requests seen so far, in order.
    #[must_use]
    pub fn log(&self) -> Vec<LogEntry> {
        self.state.lock().log.clone()
    }

    /// Forget the request log (the objects stay).
    pub fn clear_log(&self) {
        self.state.lock().log.clear();
    }
}

fn header(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
}

fn no_such_key() -> Response {
    (
        StatusCode::NOT_FOUND,
        [("content-type", "application/xml")],
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>",
    )
        .into_response()
}

async fn put_object(
    State(s): State<Shared>,
    Path((_bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut g = s.lock();
    g.log.push((
        "PUT".to_owned(),
        key.clone(),
        header(&headers, "x-amz-server-side-encryption"),
        header(&headers, "x-amz-server-side-encryption-aws-kms-key-id"), // wire-compat: S3 protocol header
    ));
    g.objects.insert(key, (body.to_vec(), Utc::now()));
    (StatusCode::OK, [("etag", "\"fake\"")]).into_response()
}

async fn get_object(State(s): State<Shared>, Path((_bucket, key)): Path<(String, String)>) -> Response {
    let mut g = s.lock();
    g.log.push(("GET".to_owned(), key.clone(), None, None));
    match g.objects.get(&key) {
        Some((bytes, _)) => (StatusCode::OK, bytes.clone()).into_response(),
        None => no_such_key(),
    }
}

async fn head_object(State(s): State<Shared>, Path((_bucket, key)): Path<(String, String)>) -> Response {
    let mut g = s.lock();
    g.log.push(("HEAD".to_owned(), key.clone(), None, None));
    match g.objects.get(&key) {
        Some((bytes, _)) => (StatusCode::OK, [("content-length", bytes.len().to_string())]).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn delete_object(State(s): State<Shared>, Path((_bucket, key)): Path<(String, String)>) -> Response {
    let mut g = s.lock();
    g.log.push(("DELETE".to_owned(), key.clone(), None, None));
    g.objects.remove(&key);
    StatusCode::NO_CONTENT.into_response()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

async fn list_objects(
    State(s): State<Shared>,
    Path(bucket): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    let g = s.lock();
    let prefix = q.get("prefix").cloned().unwrap_or_default();
    let after = q.get("continuation-token").cloned();
    let mut page: Vec<(String, usize, String)> = Vec::new();
    let mut next = None;
    for (key, (bytes, modified)) in g.objects.range(prefix.clone()..) {
        if !key.starts_with(&prefix) {
            break;
        }
        if after.as_ref().is_some_and(|a| key <= a) {
            continue;
        }
        if page.len() == PAGE {
            next = page.last().map(|p| p.0.clone());
            break;
        }
        page.push((
            key.clone(),
            bytes.len(),
            modified.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        ));
    }
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    xml.push_str(&format!(
        "<Name>{}</Name><Prefix>{}</Prefix>",
        xml_escape(&bucket),
        xml_escape(&prefix)
    ));
    xml.push_str(&format!(
        "<KeyCount>{}</KeyCount><MaxKeys>{PAGE}</MaxKeys>",
        page.len()
    ));
    xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", next.is_some()));
    if let Some(n) = &next {
        xml.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            xml_escape(n)
        ));
    }
    for (key, size, modified) in &page {
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><Size>{size}</Size><LastModified>{modified}</LastModified><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(key)
        ));
    }
    xml.push_str("</ListBucketResult>");
    (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
}
