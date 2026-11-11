//! Full-request signed network scope, independent of the main-frame robots boundary.
//!
//! CONNECT cannot inspect encrypted URL paths. This guard checks each paused browser
//! request against the same immutable egress policy before the browser dispatches it.
//! The existing proxy still resolves/checks every address and pins the connected peer.
//! Robots checks remain document-only unless an inner guard explicitly opts in to
//! subresource checks; wrapping a robots guard does not expand robots coverage.

use async_trait::async_trait;
use crawlx_core::browser::{NavigationGuard, NavigationVerdict};
use crawlx_policy::egress::EgressPolicy;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use url::Url;

/// `plane` label of the guard's denials, distinct from the egress proxy's `browser` plane.
pub const GUARD_PLANE: &str = "browser_guard";

/// Browser-side URL/origin/path scope over the existing egress authority.
#[non_exhaustive]
pub struct ScopedNetworkGuard {
    policy: EgressPolicy,
    cancel: CancellationToken,
    inner: Option<Arc<dyn NavigationGuard>>,
}

impl std::fmt::Debug for ScopedNetworkGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScopedNetworkGuard")
            .finish_non_exhaustive()
    }
}

impl ScopedNetworkGuard {
    /// Wrap the existing document guard without granting new network authority.
    /// The policy must be the run's already-admitted signed origin/network mapping.
    #[must_use]
    pub fn new(
        policy: EgressPolicy,
        cancel: CancellationToken,
        inner: Option<Arc<dyn NavigationGuard>>,
    ) -> Self {
        Self {
            policy,
            cancel,
            inner,
        }
    }

    /// Whether the request may be dispatched. A policy refusal is counted under
    /// `crawlx.egress.denials{plane="browser_guard",reason}`: this guard refuses before the
    /// browser dispatches, so the egress proxy never sees the request and keeps no record of it.
    fn permits(&self, url: &Url) -> bool {
        if self.cancel.is_cancelled() {
            return false;
        }
        match self.policy.check_url(url) {
            Ok(()) => true,
            Err(denied) => {
                Metrics::global()
                    .counter(names::EGRESS_DENIALS)
                    .inc_by(1, &[("plane", GUARD_PLANE), ("reason", denied.rule.as_str())]);
                tracing::warn!(
                    host = url.host_str().unwrap_or_default(),
                    rule = denied.rule.as_str(),
                    "egress denied (browser network guard)"
                );
                false
            }
        }
    }

    fn finish(&self, url: &Url, verdict: NavigationVerdict) -> NavigationVerdict {
        if self.permits(url) {
            verdict
        } else {
            NavigationVerdict::EgressDenied
        }
    }
}

#[async_trait]
impl NavigationGuard for ScopedNetworkGuard {
    async fn check(&self, url: &Url) -> NavigationVerdict {
        if !self.permits(url) {
            return NavigationVerdict::EgressDenied;
        }
        let verdict = match &self.inner {
            Some(inner) => inner.check(url).await,
            None => NavigationVerdict::Allow,
        };
        self.finish(url, verdict)
    }

    async fn check_request(&self, url: &Url) -> NavigationVerdict {
        if !self.permits(url) {
            return NavigationVerdict::EgressDenied;
        }
        let verdict = match &self.inner {
            Some(inner) => inner.check_request(url).await,
            None => NavigationVerdict::Allow,
        };
        self.finish(url, verdict)
    }

    fn intercepts_subresources(&self) -> bool {
        true
    }

    async fn check_subresource(&self, url: &Url) -> NavigationVerdict {
        if !self.permits(url) {
            return NavigationVerdict::EgressDenied;
        }
        let verdict = match &self.inner {
            Some(inner) if inner.intercepts_subresources() => inner.check_subresource(url).await,
            _ => NavigationVerdict::Allow,
        };
        self.finish(url, verdict)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_policy::scope::ExcludeHosts;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct DocumentRobots(AtomicUsize);

    #[async_trait]
    impl NavigationGuard for DocumentRobots {
        async fn check(&self, _url: &Url) -> NavigationVerdict {
            self.0.fetch_add(1, Ordering::SeqCst);
            NavigationVerdict::RobotsBlocked {
                reason: "owned_robots_denial",
            }
        }
    }

    #[tokio::test]
    async fn all_resource_classes_keep_scope_but_do_not_expand_document_robots() {
        let robots = Arc::new(DocumentRobots::default());
        let policy = EgressPolicy::default()
            .with_host_exclusions(ExcludeHosts::new(&["^blocked\\.test$".into()]).unwrap());
        let guard = ScopedNetworkGuard::new(policy, CancellationToken::new(), Some(robots.clone()));
        assert!(guard.intercepts_subresources());
        let allowed = Url::parse("https://allowed.test/asset.css").unwrap();
        let blocked = Url::parse("https://blocked.test/asset.css").unwrap();
        assert!(matches!(
            guard.check_subresource(&allowed).await,
            NavigationVerdict::Allow
        ));
        assert_eq!(robots.0.load(Ordering::SeqCst), 0);
        assert!(matches!(
            guard.check(&allowed).await,
            NavigationVerdict::RobotsBlocked { .. }
        ));
        assert_eq!(robots.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            guard.check_subresource(&blocked).await,
            NavigationVerdict::EgressDenied
        ));
        assert!(matches!(
            guard.check_request(&blocked).await,
            NavigationVerdict::EgressDenied
        ));
        assert_eq!(robots.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_refused_request_is_counted_by_the_guard_itself() {
        let guard = ScopedNetworkGuard::new(EgressPolicy::default(), CancellationToken::new(), None);
        let denials = Metrics::global().counter(names::EGRESS_DENIALS);
        let labels = [
            ("plane", GUARD_PLANE),
            ("reason", crawlx_policy::egress::DenyRule::Metadata.as_str()),
        ];
        let before = denials.get(&labels);
        let beacon = Url::parse("http://169.254.169.254/latest/icon.png").unwrap();
        assert!(matches!(
            guard.check_subresource(&beacon).await,
            NavigationVerdict::EgressDenied
        ));
        // metrics are process-global and sibling tests deny concurrently: lower bound
        assert!(
            denials.get(&labels) > before,
            "the guard's refusal was not counted"
        );
    }

    #[tokio::test]
    async fn cancellation_and_non_web_schemes_never_dispatch() {
        let cancel = CancellationToken::new();
        let guard = ScopedNetworkGuard::new(EgressPolicy::default(), cancel.clone(), None);
        assert!(matches!(
            guard
                .check_subresource(&Url::parse("file:///tmp/private").unwrap())
                .await,
            NavigationVerdict::EgressDenied
        ));
        cancel.cancel();
        let url = Url::parse("https://allowed.test/").unwrap();
        assert!(matches!(guard.check(&url).await, NavigationVerdict::EgressDenied));
        assert!(matches!(
            guard.check_request(&url).await,
            NavigationVerdict::EgressDenied
        ));
        assert!(matches!(
            guard.check_subresource(&url).await,
            NavigationVerdict::EgressDenied
        ));
    }

    #[derive(Debug)]
    struct CancellingGuard(CancellationToken);

    #[async_trait]
    impl NavigationGuard for CancellingGuard {
        async fn check(&self, _url: &Url) -> NavigationVerdict {
            tokio::task::yield_now().await;
            self.0.cancel();
            NavigationVerdict::Allow
        }

        fn intercepts_subresources(&self) -> bool {
            true
        }

        async fn check_subresource(&self, url: &Url) -> NavigationVerdict {
            self.check(url).await
        }
    }

    #[tokio::test]
    async fn cancellation_while_inner_guard_awaits_never_becomes_allow() {
        let url = Url::parse("https://allowed.test/").unwrap();
        for operation in 0..3 {
            let cancel = CancellationToken::new();
            let inner = Arc::new(CancellingGuard(cancel.clone()));
            let guard = ScopedNetworkGuard::new(EgressPolicy::default(), cancel, Some(inner));
            let verdict = match operation {
                0 => guard.check(&url).await,
                1 => guard.check_request(&url).await,
                _ => guard.check_subresource(&url).await,
            };
            assert!(matches!(verdict, NavigationVerdict::EgressDenied));
        }
    }
}
