//! S3 backend: the SDK code path against the in-process fake S3 of
//! `crawlx_storage::testkit::fake_s3` (always runs) and against a self-hosted S3-compatible
//! server started with docker (skips when docker or the image is unavailable). Profile
//! behavior is in `s3_profiles.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Utc;
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::{ArtifactStore, RunRepo, Sensitivity};
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_storage::artifacts::{ArtifactBlobs, ArtifactReaper as _, LiveArtifacts, ObjectArtifactStore};
use crawlx_storage::s3::{S3Blobs, S3Config, Sse};
use crawlx_storage::testkit::fake_s3::FakeS3;
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::MemoryStore;
use std::sync::Arc;
use std::time::Duration;

async fn fake_s3() -> FakeS3 {
    FakeS3::start().await.unwrap()
}

fn blobs(endpoint: &str, sse: Option<Sse>) -> S3Blobs {
    let mut cfg = S3Config::new("artifacts", "us-east-1").with_endpoint(endpoint);
    cfg.sse = sse;
    cfg.max_attempts = 2;
    cfg.attempt_timeout = Duration::from_secs(10);
    S3Blobs::with_credentials(
        &cfg,
        aws_sdk_s3::config::Credentials::new(
            "test-access-key",
            "test-secret-key",
            None,
            None,
            "crawlx-tests",
        ),
    )
    .unwrap()
}

async fn memory_run(runs: &MemoryStore, tenant: TenantId) -> crawlx_core::CrawlRunId {
    let mut cfg = create_crawl("https://example.test/", &[], 1);
    cfg.retention.mode = RetentionMode::Standard;
    cfg.retention.days = 7;
    let run = crawl_run(tenant, cfg);
    runs.create(&run, None).await.unwrap();
    run.id
}

/// The backend contract every `ArtifactBlobs` implementation must meet, run against a live endpoint.
async fn backend_contract(b: &S3Blobs) {
    assert!(!b.exists("content/a/b/c").await.unwrap());
    assert_eq!(b.get("content/a/b/c").await.unwrap(), None);
    b.put("content/a/b/c", b"hello").await.unwrap();
    b.put("content/a/b/d", b"world").await.unwrap();
    b.put("_index/x.json", b"{}").await.unwrap();
    b.put("sensitive/a/b/e", b"!").await.unwrap();
    b.put("sensitive/a/b/f", b"?").await.unwrap();
    assert!(b.exists("content/a/b/c").await.unwrap());
    assert_eq!(
        b.get("content/a/b/c").await.unwrap().as_deref(),
        Some(&b"hello"[..])
    );
    b.put("content/a/b/c", b"hello again").await.unwrap();
    assert_eq!(
        b.get("content/a/b/c").await.unwrap().as_deref(),
        Some(&b"hello again"[..]),
        "put replaces"
    );
    let keys: Vec<String> = b
        .list("content/")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.key)
        .collect();
    assert_eq!(keys, vec!["content/a/b/c", "content/a/b/d"]);
    let all = b.list("").await.unwrap();
    assert_eq!(all.len(), 5, "pagination follows continuation tokens: {all:?}");
    assert!(all.windows(2).all(|w| w[0].key < w[1].key), "sorted by key");
    let recent = Utc::now() - chrono::Duration::minutes(5);
    assert!(
        all.iter().all(|e| e.modified > recent),
        "last-modified is populated: {all:?}"
    );
    b.delete("content/a/b/c").await.unwrap();
    b.delete("content/a/b/c").await.unwrap(); // missing keys are not an error
    assert!(!b.exists("content/a/b/c").await.unwrap());
    assert_eq!(b.get("content/a/b/c").await.unwrap(), None);
    for k in [
        "content/a/b/d",
        "_index/x.json",
        "sensitive/a/b/e",
        "sensitive/a/b/f",
    ] {
        b.delete(k).await.unwrap();
    }
    assert!(b.list("").await.unwrap().is_empty());
}

#[tokio::test]
async fn fake_s3_backend_contract_and_store_round_trip() {
    let fake = fake_s3().await;
    let endpoint = fake.endpoint().to_owned();
    backend_contract(&fake.blobs(None)).await;
    {
        let log = fake.log();
        let methods: std::collections::BTreeSet<&str> = log.iter().map(|(m, ..)| m.as_str()).collect();
        assert_eq!(methods, ["DELETE", "GET", "HEAD", "PUT"].into_iter().collect());
        assert!(log.iter().all(|(_, _, sse, _)| sse.is_none()), "no SSE requested");
    }
    fake.clear_log();

    // the artifact store on top of it: key layout, PUT-before-index ordering, SSE passthrough
    let runs = Arc::new(MemoryStore::new());
    let tenant = TenantId::new();
    let run = memory_run(&runs, tenant).await;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let store = ObjectArtifactStore::new(
        blobs(
            &endpoint,
            Some(Sse::CloudKms {
                key_id: Some("kms-key-1".to_owned()),
            }),
        ),
        runs.clone(),
        clock,
    );
    let r = store
        .put(run, Sensitivity::Content, "text/markdown", b"# hello")
        .await
        .unwrap();
    assert_eq!(store.get(&r).await.unwrap(), b"# hello");
    let key = format!("content/{tenant}/{run}/{}", r.digest.to_hex());
    let row = store.row(r.id).await.unwrap().unwrap();
    assert_eq!(row.object_key, key, "{{class}}/{{tenant}}/{{run}}/{{blake3}}");
    assert_eq!(row.bucket, "artifacts");
    {
        let log = fake.log();
        let puts: Vec<&str> = log
            .iter()
            .filter(|(m, ..)| m == "PUT")
            .map(|(_, k, ..)| k.as_str())
            .collect();
        assert_eq!(
            puts,
            vec![key.as_str(), format!("_index/{}.json", r.id).as_str()],
            "object PUT precedes the index record (object first, row second)"
        );
        let first_head = log
            .iter()
            .position(|(m, k, ..)| m == "HEAD" && k == &key)
            .unwrap();
        let first_put = log.iter().position(|(m, k, ..)| m == "PUT" && k == &key).unwrap();
        assert!(first_head < first_put, "existence check before the write");
        for (_, k, sse, kms) in log.iter().filter(|(m, ..)| m == "PUT") {
            assert_eq!(sse.as_deref(), Some("aws:kms"), "SSE header on {k}"); // wire-compat: S3 SSE algorithm label
            assert_eq!(kms.as_deref(), Some("kms-key-1"), "KMS key id on {k}");
        }
    }
    // identical content in the run shares one object; the second use only writes its record
    let r2 = store
        .put(run, Sensitivity::Content, "text/markdown", b"# hello")
        .await
        .unwrap();
    assert_ne!(r.id, r2.id);
    assert_eq!(r.digest, r2.digest);
    assert_eq!(
        fake.log()
            .iter()
            .filter(|(m, k, ..)| m == "PUT" && k == &key)
            .count(),
        1,
        "content-addressed object written once"
    );
    // ZDR gate still applies in front of S3
    let mut zdr_cfg = create_crawl("https://example.test/", &[], 1);
    zdr_cfg.retention.mode = RetentionMode::Zdr;
    zdr_cfg.retention.days = 0;
    let zdr = crawl_run(tenant, zdr_cfg);
    runs.create(&zdr, None).await.unwrap();
    assert!(matches!(
        store.put(zdr.id, Sensitivity::Content, "text/html", b"x").await,
        Err(crawlx_core::StoreError::RetentionDenied(_))
    ));
    // reaping removes the object once no use remains
    assert_eq!(store.purge_run(run).await.unwrap(), 2);
    assert!(!store.blobs().exists(&key).await.unwrap());
    assert!(store.blobs().list("").await.unwrap().is_empty());
}

/// Two deployments (and an unprefixed legacy one) share one bucket: each sees only its own keys,
/// lists them without the prefix and deletes only what it owns.
async fn prefix_isolation(endpoint: &str, bucket: &str, access: &str, secret: &str) {
    let creds =
        || aws_sdk_s3::config::Credentials::new(access.to_owned(), secret.to_owned(), None, None, "test");
    let build = |prefix: &str| {
        let mut cfg = S3Config::new(bucket, "us-east-1")
            .with_endpoint(endpoint.to_owned())
            .with_prefix(prefix)
            .unwrap();
        cfg.max_attempts = 2;
        S3Blobs::with_credentials(&cfg, creds()).unwrap()
    };
    let crawlx = build("crawlx");
    let other = build("other/product/");
    let legacy = build("");
    crawlx.put("content/a/x", b"crawlx").await.unwrap();
    other.put("content/a/x", b"other").await.unwrap();
    assert_eq!(
        crawlx.get("content/a/x").await.unwrap().as_deref(),
        Some(&b"crawlx"[..])
    );
    assert_eq!(
        other.get("content/a/x").await.unwrap().as_deref(),
        Some(&b"other"[..])
    );
    assert!(crawlx.exists("content/a/x").await.unwrap());
    let own: Vec<String> = crawlx
        .list("content/")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.key)
        .collect();
    assert_eq!(
        own,
        vec!["content/a/x".to_owned()],
        "keys are listed without the prefix, never another's"
    );
    let all: Vec<String> = legacy
        .list("")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.key)
        .collect();
    assert!(
        all.contains(&"crawlx/content/a/x".to_owned())
            && all.contains(&"other/product/content/a/x".to_owned()),
        "{all:?}"
    );
    assert_eq!(
        legacy.get("crawlx/content/a/x").await.unwrap().as_deref(),
        Some(&b"crawlx"[..])
    );
    crawlx.delete("content/a/x").await.unwrap();
    assert!(!crawlx.exists("content/a/x").await.unwrap());
    assert_eq!(
        other.get("content/a/x").await.unwrap().as_deref(),
        Some(&b"other"[..]),
        "another prefix is untouched"
    );
    other.delete("content/a/x").await.unwrap();
}

#[test]
fn key_prefixes_are_normalized_and_refused_when_unsafe() {
    use crawlx_storage::s3::normalize_prefix;
    assert_eq!(normalize_prefix("").unwrap(), "");
    assert_eq!(normalize_prefix("crawlx").unwrap(), "crawlx/");
    assert_eq!(normalize_prefix("a/b/").unwrap(), "a/b/");
    for bad in ["/abs", "a//b", "a/../b", "./a", "a b", "a*", &"x".repeat(129)] {
        assert!(normalize_prefix(bad).is_err(), "{bad}");
    }
    let from = |value: &str| {
        let value = value.to_owned();
        S3Config::from_lookup(&move |name| match name {
            "CRAWLX_S3_BUCKET" => Some("b".to_owned()),
            "CRAWLX_S3_PREFIX" => Some(value.clone()),
            _ => None,
        })
    };
    assert_eq!(from("crawlx").unwrap().prefix, "crawlx/");
    assert!(from("../x").is_err());
}

#[tokio::test]
async fn fake_s3_prefixes_isolate_deployments_sharing_a_bucket() {
    let server = fake_s3().await;
    prefix_isolation(
        server.endpoint(),
        "artifacts",
        "test-access-key",
        "test-secret-key",
    )
    .await;
}

#[tokio::test]
async fn fake_s3_orphans_are_collected_after_the_grace_period() {
    let fake = fake_s3().await;
    let endpoint = fake.endpoint().to_owned();
    let runs = Arc::new(MemoryStore::new());
    let tenant = TenantId::new();
    let run = memory_run(&runs, tenant).await;
    let store = ObjectArtifactStore::new(blobs(&endpoint, None), runs, Arc::new(SystemClock));
    let referenced = store
        .put(run, Sensitivity::Content, "text/html", b"<p>kept</p>")
        .await
        .unwrap();
    let referenced_key = store.row(referenced.id).await.unwrap().unwrap().object_key;
    // a crash between the object PUT and the row: only the object exists
    let orphan_key = format!("content/{tenant}/{run}/{}", "0".repeat(64));
    store.blobs().put(&orphan_key, b"orphan").await.unwrap();
    let live = LiveArtifacts {
        ids: [referenced.id].into_iter().collect(),
        object_keys: [referenced_key.clone()].into_iter().collect(),
    };
    // inside the grace period nothing moves
    assert_eq!(
        store
            .collect_orphans(&live, Utc::now() - chrono::Duration::hours(1))
            .await
            .unwrap(),
        0
    );
    assert!(store.blobs().exists(&orphan_key).await.unwrap());
    // after it, the orphan goes and the referenced object stays
    assert_eq!(
        store
            .collect_orphans(&live, Utc::now() + chrono::Duration::hours(1))
            .await
            .unwrap(),
        1
    );
    assert!(!store.blobs().exists(&orphan_key).await.unwrap());
    assert!(store.blobs().exists(&referenced_key).await.unwrap());
    assert_eq!(store.get(&referenced).await.unwrap(), b"<p>kept</p>");
}

/// Plain HTTP/1.1 `GET` of `url` (the fake S3 ignores signatures); returns `(status, body)`.
async fn http_get(url: &url::Url) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let host = url.host_str().unwrap();
    let port = url.port().unwrap();
    let mut stream = tokio::net::TcpStream::connect((host, port)).await.unwrap();
    let target = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    };
    stream
        .write_all(
            format!("GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, raw[split + 4..].to_vec())
}

#[tokio::test]
async fn fake_s3_presigns_content_urls_for_at_most_sixty_seconds() {
    let fake = fake_s3().await;
    let endpoint = fake.endpoint().to_owned();
    let runs = Arc::new(MemoryStore::new());
    let tenant = TenantId::new();
    let run = memory_run(&runs, tenant).await;
    let store = ObjectArtifactStore::new(blobs(&endpoint, None), runs, Arc::new(SystemClock));
    let content = store
        .put(run, Sensitivity::Content, "text/markdown", b"# presigned")
        .await
        .unwrap();
    let key = format!("content/{tenant}/{run}/{}", content.digest.to_hex());

    // the TTL is clamped to the documented 60 s even when a caller asks for more
    let url = store
        .presign(&content, Duration::from_secs(600))
        .await
        .unwrap()
        .expect("s3 presigns");
    assert!(url.as_str().starts_with(&endpoint), "{url}");
    assert_eq!(url.path(), format!("/artifacts/{key}"), "path-style bucket/key");
    let query: std::collections::BTreeMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(query.get("X-Amz-Expires").map(String::as_str), Some("60"));
    assert_eq!(
        query.get("X-Amz-Algorithm").map(String::as_str),
        Some("AWS4-HMAC-SHA256") // wire-compat: S3 signature algorithm label
    );
    assert!(query.contains_key("X-Amz-Signature"), "{query:?}");
    assert!(query.contains_key("X-Amz-Date"), "{query:?}");
    assert!(
        query
            .get("X-Amz-Credential")
            .is_some_and(|c| c.starts_with("test-access-key/")),
        "{query:?}"
    );
    assert!(
        !url.as_str().contains("test-secret-key"),
        "the secret never appears in the url"
    );
    // a shorter TTL is kept as asked
    let short = store
        .presign(&content, Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    let q: std::collections::BTreeMap<String, String> = short.query_pairs().into_owned().collect();
    assert_eq!(q.get("X-Amz-Expires").map(String::as_str), Some("5"));
    // fetching the presigned url returns the object bytes without credentials
    let (status, body) = http_get(&url).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"# presigned");

    // only `content` is presigned; sensitive artifacts stay api-proxied
    let sensitive = store
        .put(run, Sensitivity::Sensitive, "image/webp", b"shot")
        .await
        .unwrap();
    assert!(matches!(
        store.presign(&sensitive, Duration::from_secs(60)).await,
        Err(crawlx_core::StoreError::AccessDenied(_))
    ));
    // a purged artifact is not presigned either
    store.purge_run(run).await.unwrap();
    assert!(matches!(
        store.presign(&content, Duration::from_secs(60)).await,
        Err(crawlx_core::StoreError::NotFound { .. })
    ));
}

#[tokio::test]
async fn unreachable_endpoint_is_reported_as_unavailable() {
    // nothing listens here; the SDK retries then gives up with a dispatch failure
    let b = blobs("http://127.0.0.1:9", None);
    match b.exists("content/x").await {
        Err(crawlx_core::StoreError::Unavailable(msg)) => {
            assert!(msg.starts_with("s3 head content/x"), "{msg}");
            assert!(!msg.contains("test-secret-key"), "no credentials in errors");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

// ---- self-hosted server through docker -------------------------------------------

async fn docker(args: &[&str]) -> Result<String, String> {
    let out = tokio::process::Command::new("docker")
        .args(args)
        .output()
        .await
        .map_err(|e| format!("docker not runnable: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

struct Container {
    id: String,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.id])
            .output();
    }
}

/// A server reached at `CRAWLX_TEST_S3_ENDPOINT` (the `integration` CI job's service container;
/// credentials `CRAWLX_TEST_S3_ACCESS_KEY` / `CRAWLX_TEST_S3_SECRET_KEY`, default
/// `crawlx` / `crawlx-secret`). Skips when the variable is unset.
#[tokio::test]
async fn service_endpoint_backend_contract() {
    let Ok(endpoint) = std::env::var("CRAWLX_TEST_S3_ENDPOINT") else {
        eprintln!("skipped: CRAWLX_TEST_S3_ENDPOINT is not set");
        return;
    };
    let access = std::env::var("CRAWLX_TEST_S3_ACCESS_KEY").unwrap_or_else(|_| "crawlx".to_owned());
    let secret = std::env::var("CRAWLX_TEST_S3_SECRET_KEY").unwrap_or_else(|_| "crawlx-secret".to_owned());
    service_contract(&endpoint, &access, &secret).await;
}

#[tokio::test]
async fn self_hosted_backend_contract_when_docker_can_run_it() {
    if docker(&["info"]).await.is_err() {
        eprintln!("skipped: docker daemon is not available");
        return;
    }
    // A server image from a registry that is present or pullable; use whichever is present.
    const IMAGES: [(&str, &[&str]); 2] = [
        ("minio/minio", &["server", "/data"]), // wire-compat: container image name
        ("bitnamilegacy/minio", &[]),          // wire-compat: container image name
    ];
    let mut chosen = None;
    let mut reasons = Vec::new();
    for (image, args) in IMAGES {
        if docker(&["image", "inspect", image]).await.is_ok() {
            chosen = Some((image, args));
            break;
        }
        match docker(&["pull", image]).await {
            Ok(_) => {
                chosen = Some((image, args));
                break;
            }
            Err(e) => reasons.push(format!("{image}: {e}")),
        }
    }
    let Some((image, args)) = chosen else {
        eprintln!(
            "skipped: no server image is present or pullable: {}",
            reasons.join("; ")
        );
        return;
    };
    let mut run_args = vec![
        "run",
        "-d",
        "-p",
        "127.0.0.1:0:9000",
        "-e",
        "MINIO_ROOT_USER=crawlx", // wire-compat: server environment variable
        "-e",
        "MINIO_ROOT_PASSWORD=crawlx-secret", // wire-compat: server environment variable
        image,
    ];
    run_args.extend_from_slice(args);
    let id = match docker(&run_args).await {
        Ok(id) => id,
        Err(e) => {
            eprintln!("skipped: cannot start {image}: {e}");
            return;
        }
    };
    let container = Container { id };
    let port_line = docker(&["port", &container.id, "9000/tcp"])
        .await
        .expect("port mapping");
    let port = port_line
        .lines()
        .find_map(|l| l.rsplit(':').next())
        .expect("host port")
        .to_owned();
    service_contract(&format!("http://127.0.0.1:{port}"), "crawlx", "crawlx-secret").await;
}

/// The backend contract plus the SSE-S3 passthrough against a server at `endpoint`.
async fn service_contract(endpoint: &str, access: &str, secret: &str) {
    let creds =
        || aws_sdk_s3::config::Credentials::new(access.to_owned(), secret.to_owned(), None, None, "test");
    // A bucket per run: the contract lists and empties the whole bucket, so it must not share
    // one with anything else that uses the same server (CLI audit export, other suites).
    let bucket = format!("crawlx-contract-{}", TenantId::new());
    let mut cfg = S3Config::new(&bucket, "us-east-1").with_endpoint(endpoint.to_owned());
    cfg.max_attempts = 3;
    let b = S3Blobs::with_credentials(&cfg, creds()).unwrap();
    // readiness: the bucket create succeeds once the server answers
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        match b.client().create_bucket().bucket(&bucket).send().await {
            Ok(_) => break,
            Err(e)
                if e.as_service_error()
                    .is_some_and(|s| s.is_bucket_already_owned_by_you()) =>
            {
                break;
            }
            Err(e) if tokio::time::Instant::now() < deadline => {
                tracing::debug!(error = %e, "minio not ready");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("server did not become ready: {e}"),
        }
    }
    backend_contract(&b).await;
    prefix_isolation(endpoint, &bucket, access, secret).await;

    // SSE-S3 passthrough: a server without a key service accepts AES256 (SSE-S3) requests
    let sse = S3Blobs::with_credentials(&cfg.clone().with_sse(Sse::Aes256), creds()).unwrap();
    match sse.put("content/sse/a/b", b"x").await {
        Ok(()) => {
            assert_eq!(
                sse.get("content/sse/a/b").await.unwrap().as_deref(),
                Some(&b"x"[..])
            );
            sse.delete("content/sse/a/b").await.unwrap();
        }
        // a server build without an SSE-S3 key rejects the header with a service error, not a crash
        Err(crawlx_core::StoreError::Backend(msg)) => {
            assert!(msg.starts_with("s3 put content/sse/a/b"), "{msg}")
        }
        Err(other) => panic!("unexpected error class: {other:?}"),
    }
    // best-effort: the bucket is empty here, so a failed removal only leaves an empty bucket
    if let Err(e) = b.client().delete_bucket().bucket(&bucket).send().await {
        tracing::debug!(error = %e, "contract bucket not removed");
    }
}
