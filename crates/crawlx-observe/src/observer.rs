//! The observer: wraps `BrowserContext::observe` and completes the bundle.

use crate::error::ObserveError;
use crate::mutation::VolatileDetector;
use crawlx_core::browser::BrowserContext;
use crawlx_core::observation::{ObservationBundle, ObservationSpec};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::sync::Arc;
use std::time::Instant;

/// Observer configuration.
#[derive(Clone, Debug, Default)]
pub struct ObserverConfig {
    /// Canonicalization (route templates, parameter classes) the bundle's URL and route key
    /// are derived with: the crawl's options, including route slots learned while it runs.
    pub canonicalize: CanonicalizeOptions,
}

/// Per-session observer: numbers bundles, completes derived fields and keeps
/// the previous bundle for diffing.
#[derive(Debug)]
pub struct Observer {
    config: ObserverConfig,
    next_seq: u64,
    previous: Option<Arc<ObservationBundle>>,
}

impl Observer {
    /// Create an observer that numbers bundles from 1 and has no previous bundle.
    #[must_use]
    pub fn new(config: ObserverConfig) -> Self {
        Self {
            config,
            next_seq: 1,
            previous: None,
        }
    }

    /// The last bundle returned by [`Self::observe_shared`] / [`Self::observe`].
    #[must_use]
    pub fn previous(&self) -> Option<&Arc<ObservationBundle>> {
        self.previous.as_ref()
    }

    /// Forget the previous bundle (session restore, tab switch): the next
    /// bundle is not diffed against it.
    pub fn reset(&mut self) {
        self.previous = None;
    }

    /// Observe and return the bundle by value. Clones once to keep the diff
    /// baseline; prefer [`Self::observe_shared`] when the caller shares bundles.
    ///
    /// # Errors
    /// Same as [`Self::observe_shared`].
    pub async fn observe(
        &mut self,
        ctx: &mut dyn BrowserContext,
        spec: &ObservationSpec,
    ) -> Result<ObservationBundle, ObserveError> {
        Ok((*self.observe_shared(ctx, spec).await?).clone())
    }

    /// Observe and return the shared bundle (also kept as [`Self::previous`]).
    ///
    /// 1. `ctx.observe(spec)`;
    /// 2. `seq` is assigned from the per-session counter (the backend's value is discarded);
    /// 3. `url` and `route` are re-derived from the page URL with the configured
    ///    canonicalizer (the backend's own options know neither the crawl's query policy
    ///    nor its learned route templates); a backend route key is kept only when the URL
    ///    cannot be canonicalized;
    /// 4. `mutation.volatile_permille` is derived from the AX diff against the
    ///    previous bundle when both describe the same tab and document;
    /// 5. `cost.wall_ms` is the wall time of this call.
    ///
    /// # Errors
    /// [`ObserveError::Browser`] when `ctx.observe` fails; the previous bundle is kept.
    pub async fn observe_shared(
        &mut self,
        ctx: &mut dyn BrowserContext,
        spec: &ObservationSpec,
    ) -> Result<Arc<ObservationBundle>, ObserveError> {
        let started = Instant::now();
        let mut bundle = ctx.observe(*spec).await?;

        bundle.seq = self.next_seq;
        self.next_seq += 1;

        match Canonicalizer::canonicalize_url(&bundle.url.url, &self.config.canonicalize) {
            Ok(c) => {
                bundle.route = c.route_key();
                bundle.url = c;
            }
            Err(_) if bundle.route.origin.is_empty() && bundle.route.template.0.is_empty() => {
                bundle.route = bundle.url.route_key();
            }
            Err(_) => {}
        }

        bundle.mutation.volatile_permille = match &self.previous {
            Some(prev)
                if spec.ax
                    && prev.tab == bundle.tab
                    && prev.epoch.navigation_seq == bundle.epoch.navigation_seq
                    && prev.epoch.document_seq == bundle.epoch.document_seq =>
            {
                VolatileDetector::volatile_permille(&prev.ax, &bundle.ax)
            }
            _ => 0,
        };

        bundle.cost.wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        let shared = Arc::new(bundle);
        self.previous = Some(Arc::clone(&shared));
        Ok(shared)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::bundle::testutil::{bundle, node, snapshot};
    use crate::spec;
    use crate::testutil::ScriptedContext;
    use crawlx_core::epoch::ObservationEpoch;
    use crawlx_core::url::RouteKey;
    use crawlx_core::RouteTemplate;

    fn with_ax(url: &str, clock: &str, heading: &str) -> ObservationBundle {
        let mut b = bundle(url);
        b.ax = snapshot(vec![
            node("1", None, "RootWebArea", "app"),
            node("2", Some("1"), "heading", heading),
            node("3", Some("1"), "StaticText", clock),
        ]);
        b
    }

    #[tokio::test]
    async fn assigns_seq_and_keeps_previous() {
        let mut ctx = ScriptedContext::new();
        let mut obs = Observer::new(ObserverConfig::default());
        assert!(obs.previous().is_none());
        for want in 1..=3u64 {
            ctx.bundles.push_back(bundle("https://example.com/a"));
            let b = obs.observe(&mut ctx, &spec::after_action()).await.unwrap();
            assert_eq!(b.seq, want);
            assert_eq!(obs.previous().unwrap().seq, want);
        }
        assert_eq!(ctx.observes, 3);
        assert_eq!(ctx.last_spec, Some(spec::after_action()));
        obs.reset();
        assert!(obs.previous().is_none());
    }

    #[tokio::test]
    async fn derives_url_and_route_key_with_the_configured_canonicalizer() {
        let mut ctx = ScriptedContext::new();
        let mut empty = bundle("https://example.com/invoice/8472?utm_source=x&page=2");
        let expected = empty.url.route_key();
        empty.route = RouteKey {
            origin: String::new(),
            template: RouteTemplate(String::new()),
            query_schema: Vec::new(),
        };
        ctx.bundles.push_back(empty);
        let mut obs = Observer::new(ObserverConfig::default());
        let b = obs.observe(&mut ctx, &spec::cheap()).await.unwrap();
        assert_eq!(b.route, expected);
        assert_eq!(b.route.template.0, "/invoice/:id");

        // a backend-provided route key is replaced: the crawl's canonicalizer keys every bundle
        let mut custom = bundle("https://example.com/a");
        custom.route.template = RouteTemplate("/custom".to_owned());
        ctx.bundles.push_back(custom);
        let b = obs.observe(&mut ctx, &spec::cheap()).await.unwrap();
        assert_eq!(b.route.template.0, "/a");
        assert_eq!(b.url.route_template.0, "/a");

        // route slots learned while the crawl runs apply to later bundles
        let config = ObserverConfig::default();
        {
            let mut templater = config.canonicalize.templater.write();
            *templater = crawlx_url::RouteTemplater::new().with_min_distinct(2);
            templater.learn(["/user/alice", "/user/bob"]);
        }
        let mut obs = Observer::new(config);
        ctx.bundles.push_back(bundle("https://example.com/user/carol"));
        let b = obs.observe(&mut ctx, &spec::cheap()).await.unwrap();
        assert_eq!(b.url.route_template.0, "/user/:slug");
        assert_eq!(b.route.template.0, "/user/:slug");
    }

    #[tokio::test]
    async fn derives_volatile_permille_from_previous_bundle() {
        let mut ctx = ScriptedContext::new();
        let mut obs = Observer::new(ObserverConfig::default());
        ctx.bundles
            .push_back(with_ax("https://example.com/", "Updated 10:00", "Dashboard"));
        let first = obs.observe(&mut ctx, &spec::cheap()).await.unwrap();
        assert_eq!(first.mutation.volatile_permille, 0, "no baseline yet");

        // clock ticks only → everything that changed is volatile
        ctx.bundles
            .push_back(with_ax("https://example.com/", "Updated 10:01", "Dashboard"));
        let second = obs.observe(&mut ctx, &spec::cheap()).await.unwrap();
        assert_eq!(second.mutation.volatile_permille, 1000);

        // clock tick plus a real change → half
        ctx.bundles
            .push_back(with_ax("https://example.com/", "Updated 10:02", "Reports"));
        let third = obs.observe(&mut ctx, &spec::cheap()).await.unwrap();
        assert_eq!(third.mutation.volatile_permille, 500);

        // a new document is never diffed against the old one
        let mut nav = with_ax("https://example.com/", "Updated 11:00", "Other");
        nav.epoch = ObservationEpoch {
            navigation_seq: 1,
            document_seq: 1,
            mutation_seq: 0,
        };
        ctx.bundles.push_back(nav);
        let fourth = obs.observe(&mut ctx, &spec::cheap()).await.unwrap();
        assert_eq!(fourth.mutation.volatile_permille, 0);
    }

    #[tokio::test]
    async fn fills_wall_ms_and_keeps_backend_cost() {
        let mut ctx = ScriptedContext::new();
        ctx.delay_ms = 20;
        let mut b = bundle("https://example.com/");
        b.cost.cdp_calls = 7;
        b.cost.bytes = 1234;
        ctx.bundles.push_back(b);
        let mut obs = Observer::new(ObserverConfig::default());
        let shared = obs.observe_shared(&mut ctx, &spec::cheap()).await.unwrap();
        assert!(shared.cost.wall_ms >= 20, "wall_ms = {}", shared.cost.wall_ms);
        assert_eq!((shared.cost.cdp_calls, shared.cost.bytes), (7, 1234));
        assert!(Arc::ptr_eq(&shared, obs.previous().unwrap()));
    }

    #[tokio::test]
    async fn backend_errors_do_not_consume_a_sequence_number() {
        let mut ctx = ScriptedContext::new();
        let mut obs = Observer::new(ObserverConfig::default());
        ctx.fail_observe = true;
        assert!(obs.observe(&mut ctx, &spec::cheap()).await.is_err());
        ctx.fail_observe = false;
        let b = obs.observe(&mut ctx, &spec::cheap()).await.unwrap();
        assert_eq!(b.seq, 1);
    }
}
