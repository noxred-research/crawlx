#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The deployment lists feed: loading, replacement of the static
//! lists by a file, reload by poll and by `reload_now`, the warning on a malformed file, and a
//! policy that observes the reload. The `SIGHUP` path runs in `lists_sighup.rs` (a signal is
//! process-wide).

use crawlx_fetch::lists::{EgressListSource, ListKind, ListReloader, ListsError, Reload};
use crawlx_policy::{DenyRule, EgressPolicy};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::fmt::MakeWriter;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn net(s: &str) -> ipnet::IpNet {
    s.parse().unwrap()
}

fn write(dir: &tempfile::TempDir, name: &str, text: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, text).unwrap();
    path
}

fn rewrite(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
}

/// Captured `tracing` output.
#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

struct LogSink(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogCapture {
    type Writer = LogSink;
    fn make_writer(&'a self) -> Self::Writer {
        LogSink(Arc::clone(&self.0))
    }
}

impl LogCapture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

fn capture_warnings() -> (LogCapture, tracing::subscriber::DefaultGuard) {
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    (capture, tracing::subscriber::set_default(subscriber))
}

/// Wait until `cond` holds, polling every 10 ms for at most five seconds.
async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..500 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn loads_static_lists_and_files_and_a_file_replaces_the_static_list_of_its_kind() {
    let dir = tempfile::tempdir().unwrap();

    // static only
    let source = EgressListSource {
        allowlist_static: Some(vec![net("10.0.0.0/8")]),
        blocklist_static: vec!["static.test".to_owned()],
        ..EgressListSource::default()
    };
    assert!(!source.has_files());
    let lists = source.load().await.unwrap();
    assert_eq!(lists.allowlist().unwrap(), [net("10.0.0.0/8")]);
    assert!(lists.blocked_host("www.static.test").is_some());

    // unset everything: no bound, nothing blocked
    let lists = EgressListSource::default().load().await.unwrap();
    assert!(lists.is_empty());

    // files replace the static lists of their kind (and only theirs)
    let allow = write(
        &dir,
        "allow.txt",
        "# lab\n192.168.0.0/16\n127.0.0.1  # loopback\n",
    );
    let source = EgressListSource {
        allowlist_file: Some(allow.clone()),
        ..source
    };
    assert!(source.has_files());
    let lists = source.load().await.unwrap();
    assert_eq!(
        lists.allowlist().unwrap(),
        [net("192.168.0.0/16"), net("127.0.0.1/32")]
    );
    assert!(
        lists.blocked_host("static.test").is_some(),
        "the blocklist has no file: the static list stays"
    );

    let block = write(&dir, "block.txt", "takedown.test\n*.wild.test\n203.0.113.0/24\n");
    let source = EgressListSource {
        blocklist_file: Some(block),
        ..source
    };
    let lists = source.load().await.unwrap();
    assert!(
        lists.blocked_host("static.test").is_none(),
        "the file replaced the static blocklist"
    );
    assert!(lists.blocked_host("a.takedown.test").is_some());
    assert!(lists.blocked_host("x.wild.test").is_some());
    assert!(lists.blocked_ip(ip("203.0.113.9")));

    // an empty allowlist file is a set, empty list: no private network is reachable
    rewrite(&allow, "# nothing\n");
    let lists = source.load().await.unwrap();
    assert_eq!(lists.allowlist().unwrap().len(), 0);
    assert!(!lists.allows_ip(ip("192.168.1.1")));

    // the blocking loader agrees with the async one
    assert_eq!(source.load_blocking().unwrap(), source.load().await.unwrap());
}

#[tokio::test]
async fn unreadable_and_malformed_files_are_errors_never_empty_lists() {
    let dir = tempfile::tempdir().unwrap();
    let missing = EgressListSource {
        allowlist_file: Some(dir.path().join("nope.txt")),
        ..EgressListSource::default()
    };
    let e = missing.load().await.unwrap_err();
    assert!(matches!(e, ListsError::Read { .. }), "{e}");
    assert_eq!(e.list(), ListKind::DeploymentAllowlist);
    assert!(e.to_string().contains("nope.txt"), "{e}");
    assert!(
        ListReloader::open(missing).await.is_err(),
        "a deployment does not start without its list"
    );

    let bad = write(&dir, "bad.txt", "10.0.0.0/8\nnot-a-network\n");
    let source = EgressListSource {
        allowlist_file: Some(bad),
        ..EgressListSource::default()
    };
    let e = source.load().await.unwrap_err();
    assert_eq!(e.line(), Some(2));
    assert_eq!(e.reason(), "invalid network entry");

    let bytes = dir.path().join("binary.txt");
    std::fs::write(&bytes, [0xff, 0xfe, 0x00]).unwrap();
    let source = EgressListSource {
        blocklist_file: Some(bytes),
        ..EgressListSource::default()
    };
    assert!(matches!(
        source.load().await.unwrap_err(),
        ListsError::Read { .. }
    ));

    let source = EgressListSource {
        blocklist_static: vec!["not a host".to_owned()],
        ..EgressListSource::default()
    };
    let e = source.load().await.unwrap_err();
    assert!(matches!(e, ListsError::Static { .. }), "{e}");
    assert!(e.path().is_none());
}

#[tokio::test]
async fn a_rewritten_file_is_picked_up_by_the_poll() {
    let dir = tempfile::tempdir().unwrap();
    let allow = write(&dir, "allow.txt", "10.0.0.0/8\n");
    let block = write(&dir, "block.txt", "old.test\n");
    let reloader = Arc::new(
        ListReloader::open(EgressListSource {
            allowlist_file: Some(allow.clone()),
            blocklist_file: Some(block.clone()),
            ..EgressListSource::default()
        })
        .await
        .unwrap()
        .with_interval(Duration::from_millis(20)),
    );
    let live = reloader.lists();
    assert!(live.snapshot().blocked_host("old.test").is_some());
    let cancel = CancellationToken::new();
    let task = reloader.spawn(cancel.clone());

    // same length, new content: the digest (and mtime) tell
    rewrite(&block, "new.test\n");
    eventually("the blocklist reload", || {
        live.snapshot().blocked_host("new.test").is_some()
    })
    .await;
    assert!(live.snapshot().blocked_host("old.test").is_none());
    rewrite(&allow, "192.168.0.0/16\n172.16.0.0/12\n");
    eventually("the allowlist reload", || {
        live.snapshot().allowlist().is_some_and(|a| a.len() == 2)
    })
    .await;

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    // after cancel nothing reloads any more
    rewrite(&block, "later.test\n");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(live.snapshot().blocked_host("later.test").is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn poll_once_reports_unchanged_and_reload_now_forces() {
    let dir = tempfile::tempdir().unwrap();
    let block = write(&dir, "block.txt", "a.test\n");
    let reloader = ListReloader::open(EgressListSource {
        blocklist_file: Some(block.clone()),
        ..EgressListSource::default()
    })
    .await
    .unwrap();
    let live = reloader.lists();
    assert_eq!(reloader.poll_once().await.unwrap(), Reload::Unchanged);

    // a replaced snapshot is a different Arc; an unchanged poll keeps the same one
    let before = live.snapshot();
    assert_eq!(reloader.poll_once().await.unwrap(), Reload::Unchanged);
    assert!(Arc::ptr_eq(&before, &live.snapshot()));
    reloader.reload_now().await.unwrap();
    assert!(
        !Arc::ptr_eq(&before, &live.snapshot()),
        "reload_now publishes even without a change"
    );

    rewrite(&block, "b.test\n");
    assert_eq!(reloader.poll_once().await.unwrap(), Reload::Applied);
    assert!(live.snapshot().blocked_host("b.test").is_some());
    assert!(live.snapshot().blocked_host("a.test").is_none());
    assert_eq!(reloader.source().blocklist_file.as_deref(), Some(block.as_path()));
}

#[tokio::test(flavor = "current_thread")]
async fn a_malformed_file_keeps_the_previous_lists_and_warns_without_the_entry() {
    let (logs, _guard) = capture_warnings();
    let dir = tempfile::tempdir().unwrap();
    let block = write(&dir, "block.txt", "kept.test\n");
    let reloader = ListReloader::open(EgressListSource {
        blocklist_file: Some(block.clone()),
        ..EgressListSource::default()
    })
    .await
    .unwrap();
    let live = reloader.lists();

    rewrite(&block, "ok.test\nsuper secret entry\n");
    let e = reloader.poll_once().await.unwrap_err();
    assert_eq!(e.line(), Some(2));
    assert!(
        live.snapshot().blocked_host("kept.test").is_some(),
        "the previous snapshot stays in force"
    );
    assert!(
        live.snapshot().blocked_host("ok.test").is_none(),
        "a half-applied file never publishes"
    );

    let text = logs.text();
    assert!(text.contains("WARN"), "{text}");
    assert!(text.contains("egress list reload failed"), "{text}");
    assert!(text.contains("operator_blocklist"), "{text}");
    assert!(text.contains("block.txt"), "{text}");
    assert!(text.contains("line=2"), "{text}");
    assert!(!text.contains("super secret entry"), "{text}");

    // the same failure again is not warned about again
    let _ = reloader.poll_once().await.unwrap_err();
    assert_eq!(
        logs.text().matches("egress list reload failed").count(),
        1,
        "{}",
        logs.text()
    );

    // a different failure is
    rewrite(&block, "fine.test\nok2.test\nanother bad one\n\n");
    let _ = reloader.poll_once().await.unwrap_err();
    assert_eq!(logs.text().matches("egress list reload failed").count(), 2);

    // fixing the file recovers
    rewrite(&block, "fixed.test\n");
    assert_eq!(reloader.poll_once().await.unwrap(), Reload::Applied);
    assert!(live.snapshot().blocked_host("fixed.test").is_some());
    assert!(live.snapshot().blocked_host("kept.test").is_none());

    // a file that vanishes also keeps the lists; an explicit reload always warns
    std::fs::remove_file(&block).unwrap();
    assert!(matches!(
        reloader.poll_once().await.unwrap_err(),
        ListsError::Read { .. }
    ));
    assert!(live.snapshot().blocked_host("fixed.test").is_some());
    let before = logs.text().matches("egress list reload failed").count();
    let _ = reloader.reload_now().await.unwrap_err();
    assert_eq!(
        logs.text().matches("egress list reload failed").count(),
        before + 1
    );
    assert!(logs.text().contains("file unreadable"));
}

#[tokio::test(flavor = "current_thread")]
async fn a_policy_built_with_the_lists_observes_the_reload() {
    let dir = tempfile::tempdir().unwrap();
    let allow = write(&dir, "allow.txt", "10.0.0.0/8\n");
    let block = write(&dir, "block.txt", "# nothing blocked yet\n");
    let reloader = ListReloader::open(EgressListSource {
        allowlist_file: Some(allow.clone()),
        blocklist_file: Some(block.clone()),
        ..EgressListSource::default()
    })
    .await
    .unwrap();

    let policy = EgressPolicy::new(true).with_lists(reloader.lists());
    let in_flight = policy.clone();
    assert!(policy.check_host("takedown.test").is_ok());
    assert!(policy.check_ip(ip("10.20.5.5")).is_ok());

    // RB-10 step 5: the origin joins the deny list; a policy in use denies it from then on
    rewrite(&block, "takedown.test\n");
    // and the operator narrows the allowlist
    rewrite(&allow, "192.168.0.0/16\n");
    assert_eq!(reloader.poll_once().await.unwrap(), Reload::Applied);
    for p in [&policy, &in_flight] {
        let e = p.check_host("www.takedown.test").unwrap_err();
        assert_eq!(e.rule, DenyRule::Blocklist);
        assert_eq!(p.check_ip(ip("10.20.5.5")).unwrap_err().rule, DenyRule::Private);
        assert!(p.check_ip(ip("192.168.4.4")).is_ok());
    }

    // lifting the entry lifts the denial
    rewrite(&block, "");
    reloader.reload_now().await.unwrap();
    assert!(policy.check_host("takedown.test").is_ok());
}
