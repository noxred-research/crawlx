//! `ArtifactSink::put` accepts redactor output or sealed ciphertext only.
//! `SecretOr` and `BrowserAction` cannot cross this boundary. Raw containers also
//! fail the core compile-fail doctests; callers cannot assert their own approval.
use crawlx_core::action::BrowserAction;
use crawlx_core::ids::CrawlRunId;
use crawlx_core::repo::{ArtifactStore, Sensitivity};
use crawlx_core::secret::{ArtifactSink, SecretOr};

async fn store_secret(store: &dyn ArtifactStore, run: CrawlRunId, value: SecretOr<String>) {
    let sink = ArtifactSink::over(store);
    let _ = sink.put(run, Sensitivity::Sensitive, "text/plain", &value).await;
}

async fn store_action(store: &dyn ArtifactStore, run: CrawlRunId, action: BrowserAction) {
    let sink = ArtifactSink::over(store);
    let _ = sink.put(run, Sensitivity::Sensitive, "application/json", &action).await;
}

fn main() {}
