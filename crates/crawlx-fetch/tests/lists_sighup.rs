#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `SIGHUP` reloads the deployment lists at once, without waiting for the poll. In its own test
//! binary: a signal is delivered to the whole process, so it must not meet other tests.

#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_the_lists_without_the_poll() {
    use crawlx_fetch::lists::{EgressListSource, ListReloader};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    let dir = tempfile::tempdir().unwrap();
    let block = dir.path().join("block.txt");
    std::fs::write(&block, "before.test\n").unwrap();
    // an hour between polls: only the signal can trigger the second snapshot
    let reloader = Arc::new(
        ListReloader::open(EgressListSource {
            blocklist_file: Some(block.clone()),
            ..EgressListSource::default()
        })
        .await
        .unwrap()
        .with_interval(Duration::from_secs(3600)),
    );
    let live = reloader.lists();
    let cancel = CancellationToken::new();
    // the handler is installed when `spawn` returns, so the signal below cannot kill the process
    let task = reloader.spawn(cancel.clone());

    std::fs::write(&block, "after.test\n").unwrap();
    let status = std::process::Command::new("kill")
        .arg("-HUP")
        .arg(std::process::id().to_string())
        .status()
        .unwrap();
    assert!(status.success(), "kill -HUP: {status}");

    let mut reloaded = false;
    for _ in 0..500 {
        if live.snapshot().blocked_host("after.test").is_some() {
            reloaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(reloaded, "SIGHUP did not reload the blocklist");
    assert!(live.snapshot().blocked_host("before.test").is_none());

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}
