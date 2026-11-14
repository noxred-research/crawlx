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

// ---- deployment marker --------------------------------------------------------------------

/// A blob store over `endpoint` under `prefix`; `deployment` is the id of the deployment it
/// belongs to, `None` for a process without a database.
fn guarded(endpoint: &str, prefix: &str, deployment: Option<&str>) -> S3Blobs {
    guarded_with(endpoint, prefix, deployment, false)
}

fn guarded_with(endpoint: &str, prefix: &str, deployment: Option<&str>, allow_shared: bool) -> S3Blobs {
    let mut cfg = S3Config::new("artifacts", "us-east-1")
        .with_endpoint(endpoint.to_owned())
        .with_prefix(prefix)
        .unwrap();
    cfg.max_attempts = 2;
    cfg.attempt_timeout = Duration::from_secs(10);
    cfg.allow_shared_prefix = allow_shared;
    let blobs = S3Blobs::with_credentials(
        &cfg,
        aws_sdk_s3::config::Credentials::new(
            "test-access-key",
            "test-secret-key",
            None,
            None,
            "crawlx-tests",
        ),
    )
    .unwrap();
    match deployment {
        Some(id) => blobs.with_deployment(Arc::new(id.to_owned())),
        None => blobs,
    }
}

/// A TCP front for `target` that closes the first `drops` connections without a reply (the
/// SDK reports a dispatch failure) and relays every later one.
async fn flaky_front(target: &str, drops: usize) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = target.trim_start_matches("http://").to_owned();
    tokio::spawn(async move {
        let mut seen = 0usize;
        while let Ok((mut inbound, _)) = listener.accept().await {
            seen += 1;
            if seen <= drops {
                drop(inbound);
                continue;
            }
            let target = target.clone();
            tokio::spawn(async move {
                if let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    format!("http://{address}")
}

#[tokio::test]
async fn the_marker_requests_survive_a_server_that_is_briefly_unreachable() {
    let fake = FakeS3::start().await.unwrap();
    // `guarded` allows 2 SDK attempts per request, so 3 dropped connections defeat the first
    // marker read; the marker retry must carry the claim through
    let front = flaky_front(fake.endpoint(), 3).await;
    let blobs = guarded(&front, "flaky", Some("deployment-one"));
    blobs.put("k", b"v").await.unwrap();
    assert!(
        fake.keys()
            .iter()
            .any(|k| k.ends_with("flaky/.crawlx-deployment")),
        "the claim was written: {:?}",
        fake.keys()
    );

    // a server that never answers still ends in a typed, retryable error after a bounded wait
    let dead = flaky_front(fake.endpoint(), usize::MAX).await;
    let blobs = guarded(&dead, "dead", Some("deployment-one"));
    let error = tokio::time::timeout(Duration::from_secs(60), blobs.put("k", b"v"))
        .await
        .expect("the wait is bounded")
        .unwrap_err();
    assert!(
        matches!(error, crawlx_core::StoreError::Unavailable(_)),
        "{error:?}"
    );
}

fn claimed(error: &crawlx_core::StoreError) -> bool {
    matches!(error, crawlx_core::StoreError::Conflict(message) if message.contains("claimed by another crawlx deployment"))
}

#[tokio::test]
async fn the_first_writer_claims_the_prefix_and_a_second_deployment_is_refused() {
    let fake = fake_s3().await;
    let first = guarded(fake.endpoint(), "shared", Some("deployment-one"));
    let second = guarded(fake.endpoint(), "shared", Some("deployment-two"));
    assert!(fake.keys().is_empty(), "opening a store writes nothing");
    first.put("content/a/x", b"one").await.unwrap();
    let marker: serde_json::Value =
        serde_json::from_slice(&fake.objects()["shared/.crawlx-deployment"]).unwrap();
    assert_eq!(
        marker,
        serde_json::json!({"format": 1, "deployment": "deployment-one", "kind": "deployment"})
    );

    // every mutation by the other deployment is refused, naming the prefix and not the owner
    for error in [
        second.put("content/a/y", b"two").await.unwrap_err(),
        second
            .put_shared("content/a/y", bytes::Bytes::from_static(b"two"))
            .await
            .unwrap_err(),
        second.delete("content/a/x").await.unwrap_err(),
        second.list("").await.unwrap_err(),
        second.claim_prefix().await.unwrap_err(),
    ] {
        assert!(claimed(&error), "{error:?}");
        let message = error.to_string();
        assert!(message.contains("\"shared/\""), "{message}");
        assert!(!message.contains("deployment-one"), "{message}");
    }
    let dir = std::env::temp_dir().join(format!("crawlx-s3-guard-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("archive.bin");
    std::fs::write(&file, b"archive").unwrap();
    assert!(claimed(
        &second.put_file("archive/a", &file, 7).await.unwrap_err()
    ));
    std::fs::remove_dir_all(&dir).unwrap();

    // reads stay possible, and nothing of the other deployment was touched
    assert_eq!(
        second.get("content/a/x").await.unwrap().as_deref(),
        Some(&b"one"[..])
    );
    assert!(second.exists("content/a/x").await.unwrap());
    assert_eq!(second.list("content/").await.unwrap().len(), 1);
    assert!(!fake.keys().contains(&"shared/content/a/y".to_owned()));
    assert!(fake.keys().contains(&"shared/content/a/x".to_owned()));
}

#[tokio::test]
async fn the_same_deployment_reopens_and_other_prefixes_are_independent() {
    let fake = fake_s3().await;
    guarded(fake.endpoint(), "shared", Some("deployment-one"))
        .put("content/a/x", b"one")
        .await
        .unwrap();
    // a restart, a second worker and the CLI of one deployment share the claim
    let again = guarded(fake.endpoint(), "shared", Some("deployment-one"));
    again.claim_prefix().await.unwrap();
    again.put("content/a/y", b"y").await.unwrap();
    assert_eq!(again.list("").await.unwrap().len(), 2);
    again.delete("content/a/x").await.unwrap();
    // another deployment under its own prefix in the same bucket is unaffected
    let other = guarded(fake.endpoint(), "other", Some("deployment-two"));
    other.put("content/a/x", b"two").await.unwrap();
    assert!(fake.keys().contains(&"other/.crawlx-deployment".to_owned()));
    // clones share the claim state: one marker read and no second write
    fake.clear_log();
    let clone = again.clone();
    clone.put("content/a/z", b"z").await.unwrap();
    again.put("content/a/w", b"w").await.unwrap();
    let marker_requests = fake
        .log()
        .iter()
        .filter(|(_, key, ..)| key == "shared/.crawlx-deployment")
        .count();
    assert_eq!(
        marker_requests, 0,
        "a claimed handle does not touch the marker again"
    );
}

#[tokio::test]
async fn the_bucket_root_is_claimed_too_and_existing_objects_are_adopted() {
    let fake = fake_s3().await;
    // objects from before the guard existed: no marker yet
    let legacy = guarded_with(fake.endpoint(), "", None, true);
    legacy.put("content/a/old", b"old").await.unwrap();
    assert!(
        !fake.keys().contains(&".crawlx-deployment".to_owned()),
        "the override writes no marker"
    );
    // the first deployment to write claims the root and adopts what is there
    let first = guarded(fake.endpoint(), "", Some("deployment-one"));
    first.put("content/a/new", b"new").await.unwrap();
    assert!(fake.keys().contains(&".crawlx-deployment".to_owned()));
    assert_eq!(
        first.get("content/a/old").await.unwrap().as_deref(),
        Some(&b"old"[..])
    );
    let second = guarded(fake.endpoint(), "", Some("deployment-two"));
    assert!(claimed(&second.delete("content/a/old").await.unwrap_err()));
    assert!(fake.keys().contains(&"content/a/old".to_owned()));
}

#[tokio::test]
async fn reads_alone_never_create_the_marker() {
    let fake = fake_s3().await;
    let reader = guarded(fake.endpoint(), "shared", Some("deployment-one"));
    assert!(reader.get("content/a/x").await.unwrap().is_none());
    assert!(!reader.exists("content/a/x").await.unwrap());
    assert!(reader.list("content/").await.unwrap().is_empty());
    assert!(
        reader.list("").await.unwrap().is_empty(),
        "an unclaimed prefix may be listed"
    );
    assert!(fake.keys().is_empty());
}

#[tokio::test]
async fn the_override_skips_the_guard() {
    let fake = fake_s3().await;
    guarded(fake.endpoint(), "shared", Some("deployment-one"))
        .put("content/a/x", b"one")
        .await
        .unwrap();
    let blocked = guarded(fake.endpoint(), "shared", Some("deployment-two"));
    assert!(claimed(&blocked.put("content/a/y", b"y").await.unwrap_err()));
    let shared = guarded_with(fake.endpoint(), "shared", Some("deployment-two"), true);
    shared.put("content/a/y", b"y").await.unwrap();
    assert_eq!(shared.list("").await.unwrap().len(), 2);
    shared.delete("content/a/x").await.unwrap();
    let marker: serde_json::Value =
        serde_json::from_slice(&fake.objects()["shared/.crawlx-deployment"]).unwrap();
    assert_eq!(
        marker["deployment"], "deployment-one",
        "the override leaves the marker alone"
    );

    let lookup = |value: &'static str| {
        S3Config::from_lookup(&move |name| match name {
            "CRAWLX_S3_BUCKET" => Some("b".to_owned()),
            "CRAWLX_S3_ALLOW_SHARED_PREFIX" => Some(value.to_owned()),
            _ => None,
        })
    };
    assert!(lookup("1").unwrap().allow_shared_prefix);
    assert!(!lookup("0").unwrap().allow_shared_prefix);
    assert!(lookup("maybe").is_err());
    assert!(
        !S3Config::from_lookup(&|name| (name == "CRAWLX_S3_BUCKET").then(|| "b".to_owned()))
            .unwrap()
            .allow_shared_prefix
    );
}

#[tokio::test]
async fn the_orphan_sweep_neither_lists_nor_deletes_the_marker_and_foreign_sweeps_are_refused() {
    let fake = fake_s3().await;
    let runs = Arc::new(MemoryStore::new());
    let tenant = TenantId::new();
    let run = memory_run(&runs, tenant).await;
    let owner = ObjectArtifactStore::new(
        guarded(fake.endpoint(), "shared", Some("deployment-one")),
        runs.clone(),
        Arc::new(SystemClock),
    );
    let orphan_key = format!("content/{tenant}/{run}/{}", "0".repeat(64));
    owner.blobs().put(&orphan_key, b"orphan").await.unwrap();
    let live = LiveArtifacts {
        ids: Default::default(),
        object_keys: Default::default(),
    };
    let later = Utc::now() + chrono::Duration::hours(1);

    // the other deployment's sweep (grace 0) is refused before it removes anything
    let intruder = ObjectArtifactStore::new(
        guarded(fake.endpoint(), "shared", Some("deployment-two")),
        runs.clone(),
        Arc::new(SystemClock),
    );
    let error = intruder.collect_orphans(&live, later).await.unwrap_err();
    assert!(claimed(&error), "{error:?}");
    assert!(fake.keys().contains(&format!("shared/{orphan_key}")));

    // the owner's sweep collects the orphan and leaves the marker
    assert_eq!(owner.collect_orphans(&live, later).await.unwrap(), 1);
    assert_eq!(fake.keys(), vec!["shared/.crawlx-deployment".to_owned()]);
    assert!(
        owner.blobs().list("").await.unwrap().is_empty(),
        "the marker is never listed"
    );
    let error = owner.blobs().delete(".crawlx-deployment").await.unwrap_err();
    assert!(matches!(error, crawlx_core::StoreError::Conflict(_)), "{error:?}");
    assert!(owner.blobs().put(".crawlx-deployment", b"x").await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_claimers_have_exactly_one_winner() {
    for conditional in [true, false] {
        let fake = fake_s3().await;
        if !conditional {
            fake.without_conditional_writes();
        }
        let claimers: Vec<_> = (0..8)
            .map(|n| {
                let blobs = guarded(fake.endpoint(), "race", Some(&format!("deployment-{n}")));
                tokio::spawn(async move { blobs.claim_prefix().await })
            })
            .collect();
        let mut winners = 0;
        let mut refused = 0;
        for claimer in claimers {
            match claimer.await.unwrap() {
                Ok(()) => winners += 1,
                Err(error) if claimed(&error) => refused += 1,
                Err(error) => panic!("unexpected error: {error:?}"),
            }
        }
        // without conditional writes the claim is write-then-read-back: two claimers can both
        // read their own marker only when their writes and reads interleave, so every claimer
        // that is refused saw a different winner's marker
        if conditional {
            assert_eq!(
                (winners, refused),
                (1, 7),
                "conditional put-if-absent admits one claimer"
            );
        } else {
            assert!(winners >= 1 && winners + refused == 8, "{winners} {refused}");
        }
        // whoever the marker names is the one deployment that can still write
        let marker: serde_json::Value =
            serde_json::from_slice(&fake.objects()["race/.crawlx-deployment"]).unwrap();
        let owner = marker["deployment"].as_str().unwrap().to_owned();
        guarded(fake.endpoint(), "race", Some(&owner))
            .put("content/a/x", b"x")
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_server_without_conditional_writes_still_claims_by_reading_back() {
    let fake = fake_s3().await;
    fake.without_conditional_writes();
    let first = guarded(fake.endpoint(), "shared", Some("deployment-one"));
    first.put("content/a/x", b"one").await.unwrap();
    let second = guarded(fake.endpoint(), "shared", Some("deployment-two"));
    assert!(claimed(&second.put("content/a/y", b"y").await.unwrap_err()));
    assert!(claimed(&second.delete("content/a/x").await.unwrap_err()));
    assert!(fake.keys().contains(&"shared/content/a/x".to_owned()));
}

#[tokio::test]
async fn a_process_without_a_database_claims_softly_and_a_deployment_takes_it_over() {
    let fake = fake_s3().await;
    let local_one = guarded(fake.endpoint(), "shared", None);
    let local_two = guarded(fake.endpoint(), "shared", None);
    local_one.put("content/a/x", b"x").await.unwrap();
    // database-less processes share their claim: a restart can still delete what it wrote
    local_two.put("content/a/y", b"y").await.unwrap();
    local_two.delete("content/a/x").await.unwrap();
    // a deployment takes the claim over
    let deployment = guarded(fake.endpoint(), "shared", Some("deployment-one"));
    deployment.put("content/a/z", b"z").await.unwrap();
    let marker: serde_json::Value =
        serde_json::from_slice(&fake.objects()["shared/.crawlx-deployment"]).unwrap();
    assert_eq!(marker["deployment"], "deployment-one");
    // a database-less process that starts now may still write but no longer delete or sweep
    let late = guarded(fake.endpoint(), "shared", None);
    late.put("content/a/w", b"w").await.unwrap();
    assert!(claimed(&late.delete("content/a/y").await.unwrap_err()));
    assert!(claimed(&late.list("").await.unwrap_err()));
    assert!(fake.keys().contains(&"shared/content/a/y".to_owned()));
}

#[tokio::test]
async fn an_unreadable_marker_fails_closed() {
    let fake = fake_s3().await;
    let blobs = guarded(fake.endpoint(), "shared", Some("deployment-one"));
    // plant garbage where the marker belongs, as a foreign tool or a newer build might
    let planter = guarded_with(fake.endpoint(), "", None, true);
    planter
        .put("shared/.crawlx-deployment", b"not json")
        .await
        .unwrap();
    let error = blobs.put("content/a/x", b"x").await.unwrap_err();
    assert!(
        matches!(&error, crawlx_core::StoreError::Conflict(message) if message.contains("unreadable")),
        "{error:?}"
    );
    planter
        .put(
            "shared/.crawlx-deployment",
            br#"{"format":99,"deployment":"deployment-one","kind":"deployment"}"#,
        )
        .await
        .unwrap();
    assert!(blobs.put("content/a/x", b"x").await.is_err());
    assert!(!fake.keys().contains(&"shared/content/a/x".to_owned()));
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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
/// The deployment marker against a real server: the claim is a conditional write, so of several
/// concurrent claimers exactly one wins, and a second deployment is refused.
async fn deployment_guard_contract(endpoint: &str, bucket: &str, access: &str, secret: &str) {
    let build = |prefix: &str, deployment: &str| {
        let mut cfg = S3Config::new(bucket, "us-east-1")
            .with_endpoint(endpoint.to_owned())
            .with_prefix(prefix)
            .unwrap();
        cfg.max_attempts = 3;
        S3Blobs::with_credentials(
            &cfg,
            aws_sdk_s3::config::Credentials::new(access.to_owned(), secret.to_owned(), None, None, "test"),
        )
        .unwrap()
        .with_deployment(Arc::new(deployment.to_owned()))
    };
    let one = build("guard", "deployment-one");
    one.put("content/a/x", b"one").await.unwrap();
    let two = build("guard", "deployment-two");
    assert!(claimed(&two.put("content/a/y", b"y").await.unwrap_err()));
    assert!(claimed(&two.delete("content/a/x").await.unwrap_err()));
    assert!(claimed(&two.list("").await.unwrap_err()));
    assert_eq!(
        two.get("content/a/x").await.unwrap().as_deref(),
        Some(&b"one"[..])
    );
    build("guard", "deployment-one")
        .put("content/a/z", b"z")
        .await
        .unwrap();
    assert_eq!(one.list("").await.unwrap().len(), 2, "the marker is not listed");

    let claimers: Vec<_> = (0..6)
        .map(|n| {
            let blobs = build("race", &format!("deployment-{n}"));
            tokio::spawn(async move { blobs.claim_prefix().await })
        })
        .collect();
    let mut winners = 0;
    for claimer in claimers {
        match claimer.await.unwrap() {
            Ok(()) => winners += 1,
            Err(error) => assert!(claimed(&error), "{error:?}"),
        }
    }
    assert_eq!(winners, 1, "a conditional put-if-absent admits one claimer");
    one.delete("content/a/x").await.unwrap();
    one.delete("content/a/z").await.unwrap();
}

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
    deployment_guard_contract(endpoint, &bucket, access, secret).await;

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
    // the deployment markers of the guard checks are the only objects left
    if let Ok(listing) = b.client().list_objects_v2().bucket(&bucket).send().await {
        for object in listing.contents() {
            if let Some(key) = object.key() {
                let _ = b.client().delete_object().bucket(&bucket).key(key).send().await;
            }
        }
    }
    // best-effort: the bucket is empty here, so a failed removal only leaves an empty bucket
    if let Err(e) = b.client().delete_bucket().bucket(&bucket).send().await {
        tracing::debug!(error = %e, "contract bucket not removed");
    }
}
