//! `url_plane`: the browser plane also covers URLs.
//!
//! Proposes `Navigate` to in-scope link destinations that no observation has
//! visited yet. The key is `(route, link identity, Navigate)`, distinct from a
//! `Click` on the same link, so coverage of "followed the URL" and "clicked
//! the control" stay separate. Scope here is a cheap pre-filter (same origin,
//! optional subdomains / extra hosts); the safety kernel still classifies
//! every proposal's destination.
//!
//! A scripted navigation is a diagnostic-lane action, and browser-native input is
//! the default: while a round is [`Phase::Greedy`] or [`Phase::System1`] (never-exercised
//! keys remain) the trusted click on a link is what follows it, and this strategy
//! stays silent. Its proposals are the recovery phases' fallback once the clicks are exhausted,
//! so a default run does not trade trusted actions for scripted ones.

use crate::context::DecisionContext;
use crate::error::StrategyError;
use crate::frontier::resolve_href;
use crate::switching::Phase;
use crate::utility::micros;
use crate::Strategy;
use async_trait::async_trait;
use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
use crawlx_core::{ActionContextKey, ActionKind, BrowserAction, InputClass, ResourceContext};
use std::collections::BTreeSet;

/// Strategy name recorded in proposal attribution.
pub const NAME: &str = "url_plane";
/// Version of the URL-plane strategy logic, recorded in proposal attribution.
pub const VERSION: u32 = 2;

/// Tuning knobs of [`UrlPlane`].
#[derive(Clone, PartialEq, Debug)]
pub struct UrlPlaneConfig {
    /// Proposals per round.
    pub n: usize,
    /// Also allow subdomains of the page's registrable-looking host (`app.example.com` → `*.example.com`).
    pub allow_subdomains: bool,
    /// Additional allowed hosts.
    pub extra_hosts: Vec<String>,
    /// Constant confidence of the deterministic strategy, in `[0, 1]`.
    pub confidence: f32,
}

impl Default for UrlPlaneConfig {
    fn default() -> Self {
        Self {
            n: 5,
            allow_subdomains: false,
            extra_hosts: Vec::new(),
            confidence: 0.5,
        }
    }
}

/// Strategy that proposes `Navigate` to unvisited, in-scope link destinations.
#[derive(Clone, Debug, Default)]
pub struct UrlPlane {
    cfg: UrlPlaneConfig,
}

fn parent_domain(host: &str) -> &str {
    host.split_once('.').map_or(host, |(_, rest)| rest)
}

impl UrlPlane {
    /// Create the strategy with `cfg`.
    #[must_use]
    pub const fn new(cfg: UrlPlaneConfig) -> Self {
        Self { cfg }
    }

    fn in_scope(&self, page: &url::Url, target: &url::Url) -> bool {
        let (Some(ph), Some(th)) = (page.host_str(), target.host_str()) else {
            return false;
        };
        let same_origin = page.scheme() == target.scheme()
            && ph.eq_ignore_ascii_case(th)
            && page.port_or_known_default() == target.port_or_known_default();
        if same_origin {
            return true;
        }
        if self.cfg.extra_hosts.iter().any(|h| h.eq_ignore_ascii_case(th)) {
            return true;
        }
        if self.cfg.allow_subdomains {
            let root = parent_domain(ph);
            return th.eq_ignore_ascii_case(root)
                || th
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{}", root.to_ascii_lowercase()));
        }
        false
    }

    fn select(&self, ctx: &DecisionContext<'_>) -> Vec<ActionProposal> {
        if matches!(ctx.phase, Phase::Greedy | Phase::System1) {
            return Vec::new();
        }
        let page = &ctx.bundle.url.url;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut found: Vec<(i64, usize, usize, u64, ActionProposal)> = Vec::new();
        for (i, (cand, res)) in ctx.candidates.iter().zip(&ctx.resolved).enumerate() {
            if !cand.evidence.visible || !cand.evidence.enabled {
                continue;
            }
            let Some(href) = cand.descriptor.href.as_deref() else {
                continue;
            };
            let Some(url) = resolve_href(&ctx.bundle, href) else {
                continue;
            };
            let text = url.to_string();
            if !self.in_scope(page, &url) || ctx.frontier.url_visited(&text) || !seen.insert(text.clone()) {
                continue;
            }
            let key = ActionContextKey {
                principal: ctx.principal.clone(),
                route_template: ctx.route().clone(),
                element: res.hash,
                action_kind: ActionKind::Navigate,
                input_class: InputClass::none(),
                resource_context: ResourceContext::None,
                state_cluster: ctx.cluster,
            };
            if !ctx.frontier.is_proposable(&key) {
                continue;
            }
            let depth = url.path_segments().map_or(0, Iterator::count);
            let novelty = ctx.ledger.novelty(&key);
            let tie = ctx.seed.derive("url-plane-tie", &[key.id().0.as_slice()]);
            let mut first = [0_u8; 8];
            first.copy_from_slice(&tie[..8]);
            let proposal = ActionProposal {
                key,
                action: BrowserAction::Navigate { url },
                epoch: ctx.bundle.epoch,
                strategy: NAME,
                strategy_version: VERSION,
                confidence: self.cfg.confidence,
                expected: ExpectedEffect {
                    reveals: Vec::new(),
                    navigates_to: Some(text),
                    mutates_state: false,
                },
                hinted_risk: None,
                model_decision: None,
                summary: format!("navigate link [{}]", &res.hash.to_string()[..12]),
            };
            // never-exercised first, then shallow paths, then candidate order, then seeded tie
            let novelty_q = -micros(novelty);
            found.push((novelty_q, depth, i, u64::from_le_bytes(first), proposal));
        }
        found.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then(a.1.cmp(&b.1))
                .then(a.2.cmp(&b.2))
                .then(a.3.cmp(&b.3))
        });
        found
            .into_iter()
            .map(|(_, _, _, _, p)| p)
            .take(self.cfg.n)
            .collect()
    }
}

#[async_trait]
impl Strategy for UrlPlane {
    async fn propose(&self, ctx: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
        Ok(self.select(ctx))
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn version(&self) -> u32 {
        VERSION
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::testutil::{Fixture, Spec};

    /// The phase this strategy answers in: the recovery fallback.
    const RECOVERY: Phase = Phase::StateRecovery;

    fn urls(props: &[ActionProposal]) -> Vec<String> {
        props
            .iter()
            .map(|p| match &p.action {
                BrowserAction::Navigate { url } => url.to_string(),
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    #[tokio::test]
    async fn proposes_unvisited_in_scope_links_only() {
        let mut f = Fixture::new(&[
            Spec::link("Docs", "/docs"),
            Spec::link("Pricing", "/pricing/plans"),
            Spec::link("Home", "/app"),
            Spec::link("Anchor", "#top"),
            Spec::link("Mail", "mailto:a@b.example"),
            Spec::link("Elsewhere", "https://other.example/x"),
            Spec::button("Open"),
        ]);
        f.mark_url_visited("https://app.example/docs");
        let ctx = f.ctx_with_phase(RECOVERY);
        let props = UrlPlane::default().propose(&ctx).await.unwrap();
        assert_eq!(urls(&props), vec!["https://app.example/pricing/plans".to_owned()]);
        assert!(props
            .iter()
            .all(|p| p.key.action_kind == ActionKind::Navigate && p.strategy == NAME));
    }

    #[tokio::test]
    async fn stays_silent_while_trusted_clicks_remain() {
        let f = Fixture::new(&[
            Spec::link("Docs", "/docs"),
            Spec::link("Pricing", "/pricing/plans"),
        ]);
        let strategy = UrlPlane::default();
        // the same page proposes in the recovery phases: only the phase differs
        assert_eq!(
            strategy.propose(&f.ctx_with_phase(RECOVERY)).await.unwrap().len(),
            2
        );
        assert_eq!(
            strategy
                .propose(&f.ctx_with_phase(Phase::EnablementRecovery))
                .await
                .unwrap()
                .len(),
            2
        );
        for phase in [Phase::Greedy, Phase::System1] {
            let props = strategy.propose(&f.ctx_with_phase(phase)).await.unwrap();
            assert!(
                props.is_empty(),
                "{phase:?} proposes a diagnostic-lane navigation: {props:?}"
            );
        }
    }

    #[tokio::test]
    async fn dedupes_same_destination_and_prefers_unexercised_then_shallow() {
        let f = Fixture::new(&[
            Spec::link("A", "/deep/er/path"),
            Spec::link("B", "/shallow"),
            Spec::link("B again", "/shallow#frag"),
        ]);
        let props = UrlPlane::default()
            .propose(&f.ctx_with_phase(RECOVERY))
            .await
            .unwrap();
        assert_eq!(
            urls(&props),
            vec![
                "https://app.example/shallow".to_owned(),
                "https://app.example/deep/er/path".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn subdomains_and_extra_hosts_are_opt_in() {
        let f = Fixture::new(&[
            Spec::link("Sub", "https://api.example/x"),
            Spec::link("Extra", "https://cdn.test/x"),
        ]);
        assert!(UrlPlane::default()
            .propose(&f.ctx_with_phase(RECOVERY))
            .await
            .unwrap()
            .is_empty());
        let wide = UrlPlane::new(UrlPlaneConfig {
            allow_subdomains: true,
            extra_hosts: vec!["cdn.test".into()],
            ..UrlPlaneConfig::default()
        });
        assert_eq!(wide.propose(&f.ctx_with_phase(RECOVERY)).await.unwrap().len(), 2);
    }
}
