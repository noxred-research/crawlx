//! Reviewed recipe proposals re-enter the URL plane as ordinary discoveries.
//!
//! A recipe selects start requests, page links and sitemap entries and names each one's exact
//! handler route. It grants nothing: every proposal is canonicalized and passes scope, robots,
//! the in-memory admission filter, budgets and the fenced frontier append exactly like a link.
//! Hard denies inside the recipe win over every allow and over every source.

use super::*;
use crate::extension_recipes::{RecipeCandidateKindV1, RecipeCandidateV1, RecipeExecutionError};
use crawlx_core::extension_recipes::{ExtensionRecipeError, RecipeSourceV1};
use crawlx_core::url_graph::MAX_URL_GRAPH_BATCH;

/// Request metadata key carrying a nested sitemap proposal's source depth. It is ordinary
/// bounded metadata, verified against the recipe's own maximum before the document is parsed.
pub(crate) const SITEMAP_DEPTH_KEY: &str = "recipe_sitemap_depth";
/// Request metadata key carrying a publisher language hint, never an admission input.
pub(crate) const LANGUAGE_HINT_KEY: &str = "recipe_language_hint";

impl UrlPlaneRunner {
    /// The run's immutable compiled recipe snapshot.
    pub(crate) fn extension_recipe(&self) -> Option<&Arc<crate::extension_recipes::CompiledExtensionRecipe>> {
        self.recipe.as_ref()
    }

    /// The operator-approved source dispatcher, when one is configured. The field is copied from
    /// `RunContext::source_dispatch` in `with_surface_services`; a runner built without surface
    /// services has none.
    pub(crate) fn source_dispatcher(&self) -> Option<&Arc<crate::source_dispatch::SourceDispatcher>> {
        self.source_dispatch.as_ref()
    }

    /// Whether the recipe has at least one rule for `source`.
    pub(super) fn recipe_has_rules(&self, source: RecipeSourceV1) -> bool {
        self.crawl
            .extension_recipe
            .as_ref()
            .is_some_and(|recipe| recipe.rules.iter().any(|rule| rule.source == source))
    }

    /// Enqueue root sitemap documents as default-route source proposals at depth zero.
    ///
    /// # Errors
    /// Returns the frontier append failure.
    pub(super) async fn discover_recipe_sitemap_roots(
        &self,
        seed: &CanonicalUrl,
        roots: &[String],
    ) -> Result<(), WorkerError> {
        let Some(recipe) = self.recipe.as_ref() else {
            return Ok(());
        };
        let Some(handler) = recipe.pipeline().routes.get("default").copied() else {
            return Ok(());
        };
        for root in roots.iter().take(MAX_SITEMAP_DOCUMENTS) {
            let Ok(url) = Url::parse(root) else { continue };
            let Some((canonical, bearing)) = self.canonicalize(&url) else {
                continue;
            };
            let candidate = RecipeCandidateV1 {
                url,
                route: "default".into(),
                handler,
                kind: RecipeCandidateKindV1::Sitemap,
                sitemap_depth: 0,
                language_hint: None,
                rule_index: None,
            };
            let source = RequestSource {
                tag: "recipe",
                attribute: "sitemap_root",
                source: seed.origin.clone(),
            };
            self.discover_recipe_page(canonical, 1, None, bearing, Some(source), &candidate)
                .await?;
        }
        Ok(())
    }

    /// Whether a fetched XML page is a sitemap the recipe evaluates.
    pub(super) fn recipe_wants_sitemaps(&self) -> bool {
        self.crawl.extension_recipe.as_ref().is_some_and(|recipe| {
            recipe.follow_sitemaps
                || recipe
                    .rules
                    .iter()
                    .any(|rule| rule.source == RecipeSourceV1::Sitemap)
        })
    }

    /// Admit one recipe page proposal with its exact route (and nested-source metadata) intact.
    ///
    /// # Errors
    /// Returns the frontier append failure.
    pub(super) async fn discover_recipe_page(
        &self,
        canonical: CanonicalUrl,
        depth: u16,
        parent: Option<i64>,
        action_bearing: bool,
        source: Option<RequestSource>,
        candidate: &RecipeCandidateV1,
    ) -> Result<DiscoveryOutcome, StoreError> {
        let mut proposal = crawlx_core::request::RequestEnvelopeV1::get(canonical.clone(), depth, parent);
        proposal.route.clone_from(&candidate.route);
        if candidate.kind == RecipeCandidateKindV1::Sitemap {
            proposal.metadata.insert(
                SITEMAP_DEPTH_KEY.to_owned(),
                serde_json::json!(candidate.sitemap_depth),
            );
        }
        if let Some(language) = &candidate.language_hint {
            proposal
                .metadata
                .insert(LANGUAGE_HINT_KEY.to_owned(), serde_json::json!(language));
        }
        self.discover_with(canonical, depth, parent, action_bearing, source, Some(proposal))
            .await
    }

    /// Select the page's links through the recipe's ordered rules on the shared CPU pool. The
    /// body's admission moves into the blocking job and stays there until it exits.
    pub(super) async fn recipe_html_candidates(
        &self,
        response: &FetchResponse,
        cancel: &CancellationToken,
    ) -> Result<Vec<RecipeCandidateV1>, RecipeExecutionError> {
        let Some(recipe) = self.recipe.clone() else {
            return Ok(Vec::new());
        };
        let input = memory_plane::AdmittedBytes::of(response);
        let page = response.final_url.clone();
        let token = self.event_cancel(cancel);
        self.cpu_pool
            .run(move || {
                let html = String::from_utf8_lossy(input.bytes());
                recipe.html(&html, &page, &token)
            })
            .await
            .map_err(|_| RecipeExecutionError::Recipe(ExtensionRecipeError::Invalid))?
    }

    /// Evaluate a fetched sitemap document through the recipe. A document deeper than the
    /// recipe's maximum is refused before it is parsed.
    pub(super) async fn recipe_sitemap_candidates(
        &self,
        response: &FetchResponse,
        depth: Option<&serde_json::Value>,
        cancel: &CancellationToken,
    ) -> Result<Vec<RecipeCandidateV1>, RecipeExecutionError> {
        let Some(recipe) = self.recipe.clone() else {
            return Ok(Vec::new());
        };
        let looks_like_sitemap = response.body.starts_with(&[0x1f, 0x8b])
            || response
                .content_type
                .as_deref()
                .is_some_and(|c| c.contains("xml"))
            || response.final_url.path().ends_with(".xml")
            || response.final_url.path().ends_with(".xml.gz");
        if !looks_like_sitemap {
            return Ok(Vec::new());
        }
        let depth = match depth {
            None => 0,
            Some(value) => value
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .ok_or(ExtensionRecipeError::Invalid)?,
        };
        let limit = self.fetcher.config().max_body_bytes;
        // gzip output is allocated beyond the wire body: reserve its hard decode cap first.
        let expansion = if response.body.starts_with(&[0x1f, 0x8b]) {
            Some(
                memory_plane::reserve_derived(limit)
                    .map_err(|_| RecipeExecutionError::Recipe(ExtensionRecipeError::Limit))?,
            )
        } else {
            None
        };
        let input = memory_plane::AdmittedBytes::of(response);
        let source = response.final_url.clone();
        let token = self.event_cancel(cancel);
        self.cpu_pool
            .run(move || {
                let _expansion = expansion;
                let decoded = discovery::decode_sitemap(input.bytes(), limit)
                    .map_err(|_| RecipeExecutionError::Recipe(ExtensionRecipeError::Invalid))?;
                recipe.sitemap(&decoded, &source, depth, &token)
            })
            .await
            .map_err(|_| RecipeExecutionError::Recipe(ExtensionRecipeError::Invalid))?
    }

    /// End a row whose recipe evaluation refused its input.
    ///
    /// # Errors
    /// Returns the terminal commit's storage failure.
    pub(super) async fn fail_recipe(
        &self,
        entry: &FrontierEntry,
        error: &RecipeExecutionError,
    ) -> Result<(), WorkerError> {
        if matches!(
            error,
            RecipeExecutionError::Recipe(ExtensionRecipeError::Cancelled)
        ) {
            return self
                .stop_request(entry, lifecycle_plane::LifecycleStop::Cancelled)
                .await;
        }
        self.fail(
            entry,
            "recipe_failed",
            "recipe_failed",
            Attempt::Failed,
            serde_json::json!({"reason":"recipe_failed"}),
        )
        .await
    }

    /// Re-admit every proposal of a page and return the URLs the frontier actually admitted.
    ///
    /// # Errors
    /// Returns the frontier append failure or a lost parent lease.
    pub(super) async fn follow_recipe_candidates(
        &self,
        entry: &FrontierEntry,
        candidates: &[RecipeCandidateV1],
    ) -> Result<Vec<Url>, WorkerError> {
        let mut admitted = Vec::with_capacity(candidates.len());
        let depth = entry.depth.saturating_add(1);
        for candidate in candidates {
            let Some((canonical, bearing)) = self.canonicalize(&candidate.url) else {
                continue;
            };
            let source = RequestSource {
                tag: "recipe",
                attribute: match candidate.kind {
                    RecipeCandidateKindV1::Page => "page",
                    RecipeCandidateKindV1::Sitemap => "sitemap",
                },
                source: entry.url.url.to_string(),
            };
            let url = canonical.url.clone();
            let outcome = self
                .discover_recipe_page(canonical, depth, Some(entry.id), bearing, Some(source), candidate)
                .await?;
            if outcome == DiscoveryOutcome::Admitted {
                admitted.push(url);
            }
        }
        Ok(admitted)
    }

    /// Admit the recipe's start requests as full proposals. Method, route and metadata survive;
    /// URL, depth and parent come from admission.
    ///
    /// # Errors
    /// Returns the recipe's refusal or the frontier append failure.
    pub(super) async fn discover_recipe_start(&self) -> Result<(), WorkerError> {
        let Some(recipe) = self.recipe.clone() else {
            return Ok(());
        };
        let cancel = self.hard_cancel.clone().unwrap_or_default();
        let proposals = recipe
            .start_requests(&cancel)
            .map_err(|error| WorkerError::Config(error.to_string()))?;
        for proposal in proposals {
            let Some((canonical, bearing)) = self.canonicalize(&proposal.url.url) else {
                continue;
            };
            let depth = proposal.depth;
            let source = RequestSource {
                tag: "recipe",
                attribute: "start",
                source: canonical.origin.clone(),
            };
            self.discover_with(canonical, depth, None, bearing, Some(source), Some(proposal))
                .await?;
        }
        Ok(())
    }

    /// Publish the retained page's admitted outlinks as advisory graph evidence, before the
    /// row's terminal commit. Targets re-pass scope, robots and exclusion here; the evidence
    /// grants no navigation authority and its failure never blocks the page, but a lost lease
    /// does. ZDR runs publish nothing.
    ///
    /// # Errors
    /// Returns a lost parent lease or the run lookup failure.
    pub(super) async fn publish_url_graph(
        &self,
        entry: &FrontierEntry,
        urls: &[Url],
        anchors: &BTreeMap<String, String>,
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        let Some((producer, policy)) = &self.url_graph else {
            return Ok(());
        };
        if self.crawl.retention.mode == RetentionMode::Zdr || cancel.is_cancelled() {
            return Ok(());
        }
        let fence = self
            .held
            .lock()
            .get(&entry.id)
            .copied()
            .ok_or(StoreError::LeaseLost)?;
        let tenant = self.deps.runs.get_metadata(self.run).await?.tenant;
        let lease =
            crawlx_core::custody::CustodyLease::for_url(tenant, self.run, entry.id, self.worker, fence);
        let depth = entry.depth.saturating_add(1);
        let mut targets: Vec<(CanonicalUrl, Option<&str>)> = Vec::new();
        let mut seen = BTreeSet::new();
        for url in urls {
            if targets.len() >= MAX_URL_GRAPH_BATCH {
                break;
            }
            let Some((canonical, bearing)) = self.canonicalize(url) else {
                continue;
            };
            if bearing
                || self.prefetch.check(&canonical.url).is_some()
                || !self.scope.decide(&canonical, depth).is_admitted()
                || !seen.insert(canonical.key)
            {
                continue;
            }
            if !self.crawl.cache_only()
                && !matches!(self.robots_decision(&canonical).await, RobotsDecision::Allowed)
            {
                continue;
            }
            let anchor = anchors.get(url.as_str()).map(String::as_str);
            targets.push((canonical, anchor));
        }
        let links: Vec<crate::url_graph::UrlGraphLink<'_>> = targets
            .iter()
            .map(|(target, anchor)| crate::url_graph::UrlGraphLink::new(target, *anchor, 1))
            .collect();
        match producer.record(&lease, policy, &entry.url, &links).await {
            Ok(_) => Ok(()),
            Err(crate::url_graph::UrlGraphProducerError::Store(StoreError::LeaseLost)) => {
                Err(StoreError::LeaseLost.into())
            }
            Err(error) => {
                tracing::warn!(run = %self.run, row = entry.id, error = %error, "url graph evidence not recorded");
                Ok(())
            }
        }
    }
}
