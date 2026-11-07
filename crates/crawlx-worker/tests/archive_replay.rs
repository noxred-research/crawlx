//! Real local WARC/WACZ replay through pinned Chromium. No live origin is fetched.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::seed::CrawlSeed;
use crawlx_storage::archive::{cdxj, wacz, warc, Limits};
use crawlx_worker::archive_qa::compare;
use crawlx_worker::archive_replay::{replay, ReplayArchive};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Write as _};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

fn fixture(root: &Path, html: &str) -> (PathBuf, PathBuf) {
    let warc_path = root.join("data.warc.gz");
    let index_path = root.join("index.cdxj");
    let pages_path = root.join("pages.jsonl");
    let mut output = File::create(&warc_path).unwrap();
    let mut index = cdxj::Sorter::new().unwrap();
    for (ordinal, (target, mime, body)) in [
        (
            "https://retained.example.test/index.html",
            "text/html",
            html.as_bytes(),
        ),
        (
            "https://retained.example.test/style.css",
            "text/css",
            b"h1 { color: rgb(30, 30, 30); }".as_slice(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let header = warc::RecordHeader {
            fields: BTreeMap::from([
                ("WARC-Type".into(), "resource".into()),
                (
                    "WARC-Record-ID".into(),
                    format!("<urn:uuid:00000000-0000-8000-8000-{ordinal:012}>"),
                ),
                ("WARC-Date".into(), "2026-11-04T12:34:56.789Z".into()),
                ("WARC-Target-URI".into(), target.into()),
                ("Content-Type".into(), mime.into()),
            ]),
            payload_offset: 0,
        };
        let record = warc::write_record(
            &mut output,
            &header,
            &mut Cursor::new(body),
            u64::try_from(body.len()).unwrap(),
            Limits::default(),
        )
        .unwrap();
        index
            .push(
                cdxj::Entry::from_record(&record, "data.warc.gz")
                    .unwrap()
                    .line(&record)
                    .unwrap(),
            )
            .unwrap();
    }
    output.flush().unwrap();
    index.finish(&mut File::create(&index_path).unwrap()).unwrap();
    std::fs::write(&pages_path, b"{\"format\":\"json-pages-1.0\",\"id\":\"pages\",\"title\":\"owned fixture\"}\n{\"url\":\"https://retained.example.test/index.html\",\"ts\":\"2026-11-04T12:34:56.789Z\"}\n").unwrap();
    let wacz_path = root.join("fixture.wacz");
    wacz::write(
        File::create(&wacz_path).unwrap(),
        &[
            ("archive/data.warc.gz".into(), warc_path.clone()),
            ("indexes/index.cdxj".into(), index_path),
            ("pages/pages.jsonl".into(), pages_path),
        ],
        "2026-11-04T12:34:56.789Z",
        Limits::default(),
    )
    .unwrap();
    (warc_path, wacz_path)
}

const HTML: &str = "<!doctype html><html><head><link rel='icon' href='data:,'><link rel='stylesheet' href='/style.css'></head><body><h1>Retained fixture</h1><p>Offline only</p><img src='/missing.png' alt='missing archive asset'></body></html>";

fn tenant() -> crawlx_core::TenantId {
    "00000000-0000-8000-8000-000000000001".parse().unwrap()
}

fn open_archive(path: &Path) -> Result<ReplayArchive, crawlx_worker::archive_replay::ReplayError> {
    ReplayArchive::from_snapshot(std::fs::read(path)?, tenant(), Vec::new())
}

#[test]
fn real_warc_and_wacz_inputs_are_validated_before_any_render() {
    let dir = tempfile::tempdir().unwrap();
    let (warc, wacz) = fixture(dir.path(), HTML);
    assert!(open_archive(&warc).is_ok());
    assert!(open_archive(&wacz).is_ok());
    std::fs::write(&warc, b"WARC/1.1\r\nContent-Length: 999999999999\r\n\r\n").unwrap();
    assert!(open_archive(&warc).is_err());
}

#[test]
fn sensitive_json_and_profile_access_are_rejected_before_listener_creation() {
    let dir = tempfile::tempdir().unwrap();
    for body in [
        "<html><body><script>document.cookie</script></body></html>",
        "{\"password\":\"private-value\"}",
    ] {
        let (warc, _) = fixture(dir.path(), body);
        assert!(open_archive(&warc).is_err());
    }
}

#[tokio::test]
async fn pinned_browser_renders_retained_warc_wacz_missing_assets_and_real_baselines() {
    if std::env::var_os("CRAWLX_CHROMIUM_PATH").is_none() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (warc, wacz) = fixture(dir.path(), HTML);
    let first = replay(
        open_archive(&warc).unwrap(),
        CrawlSeed(7),
        1,
        Some(r"/index\.html$".to_owned()),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let second = replay(
        open_archive(&warc).unwrap(),
        CrawlSeed(7),
        1,
        Some(r"/index\.html$".to_owned()),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(first.browser.pinned);
    assert!(!first.browser.attached);
    assert_eq!(first.pages[0].captures.len(), 5);
    assert!(first
        .resources
        .iter()
        .any(|resource| resource.path == "/r/0/missing.png" && resource.status == 404));
    assert!(compare(&second, Some(&first), 0.0, 0.0).unwrap().passed());
    let absent = compare(&first, None, 0.0, 0.0).unwrap();
    assert_eq!(absent.passed, 0);
    assert_eq!(absent.failed, 0);
    assert_eq!(absent.not_evaluated, 8);
    let mut mismatch = first.clone();
    mismatch.resources[0].status = 500;
    assert!(compare(&mismatch, Some(&first), 0.0, 0.0).unwrap().failed > 0);
    let mut different_selection = first.clone();
    different_selection.page_filter = Some(r"/.*\.html$".to_owned());
    let incompatible = compare(&different_selection, Some(&first), 0.0, 0.0).unwrap();
    assert_eq!(
        incompatible
            .comparisons
            .iter()
            .find(|result| result.subject == "pins")
            .unwrap()
            .passed,
        Some(false),
        "different selection policies cannot certify the same QA baseline"
    );
    let mut denied = first.clone();
    denied.denied_requests = first.denied_requests.checked_add(1).unwrap();
    denied.denial_evidence = vec!["GET password=private-value:443 refused".into(); 33];
    let refused = compare(&denied, Some(&first), 0.0, 0.0).unwrap();
    let refusal = refused
        .comparisons
        .iter()
        .find(|result| result.subject == "denied_requests")
        .unwrap();
    assert_eq!(refusal.passed, Some(false));
    assert!(!refusal.reason.contains("private-value"));
    assert!(refusal.reason.contains("refusal_details_redacted"));
    let package = replay(
        open_archive(&wacz).unwrap(),
        CrawlSeed(7),
        1,
        Some(r"/index\.html$".to_owned()),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        package.pages[0]
            .captures
            .iter()
            .find(|c| c.kind == "final_text")
            .unwrap()
            .bytes,
        b"Retained fixture Offline only"
    );
}

#[tokio::test]
async fn computed_private_requests_cannot_reach_another_owned_listener() {
    if std::env::var_os("CRAWLX_CHROMIUM_PATH").is_none() {
        return;
    }
    let canary = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = canary.local_addr().unwrap().port();
    let html = format!("<!doctype html><html><head><link rel='icon' href='data:,'></head><body><h1>Offline fixture</h1><script>fetch(['http:', '', '127.0.0.1:{port}', 'private'].join('/')).catch(() => {{}});</script></body></html>");
    let dir = tempfile::tempdir().unwrap();
    let (warc, _) = fixture(dir.path(), &html);
    let report = replay(
        open_archive(&warc).unwrap(),
        CrawlSeed(5),
        1,
        None,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(report.browser.pinned);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), canary.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn cancelled_replay_does_not_launch_or_leave_a_listener() {
    let dir = tempfile::tempdir().unwrap();
    let (warc, _) = fixture(dir.path(), HTML);
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(
        replay(open_archive(&warc).unwrap(), CrawlSeed(3), 1, None, cancel)
            .await
            .is_err()
    );
}
