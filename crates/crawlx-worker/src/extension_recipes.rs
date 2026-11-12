//! Compiled immutable native recipes. All returned URLs and actions remain proposals.
//!
//! Callers run CPU work through the shared bounded pool. Every start request,
//! discovered page, nested sitemap and alternate must reenter ordinary authorization,
//! scope, robots, checked egress and acquisition budgets before any network effect.

use crawlx_core::{
    archive_behaviors::RecipeV1,
    extension_recipes::{ExtensionRecipeError, ExtensionRecipePinV1, ExtensionRecipeV1, RecipeSourceV1},
    extensions::{json_size, ExtensionError, ExtensionPipelineV1, HandlerV1},
    extraction::DocumentEnvelopeV1,
    request::RequestEnvelopeV1,
    selectors::SelectorV1,
};
use crawlx_extract::link_options::{LinkFilter, LinkOptions, LinkOptionsError, NofollowPolicy};
use crawlx_url::{extensions::path_extension, ExtensionFilter};
use serde::Serialize;
use std::{borrow::Cow, collections::BTreeSet};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Candidate role; neither role grants permission to acquire it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecipeCandidateKindV1 {
    /// Selected page with an exact pipeline handler.
    Page,
    /// Nested source document, still subject to source-depth and normal scope limits.
    Sitemap,
}

/// One bounded URL proposal, with no browser, request credential or callback handle.
#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RecipeCandidateV1 {
    /// Fragment-free credential-free HTTP(S) URL; canonicalization remains caller-owned.
    pub url: Url,
    /// Exact pipeline label chosen by the first matching rule.
    pub route: String,
    /// Exact registered handler, not an implicit default.
    pub handler: HandlerV1,
    /// Page or nested sitemap proposal.
    pub kind: RecipeCandidateKindV1,
    /// Sitemap depth for nested sources; root document has depth zero.
    pub sitemap_depth: u16,
    /// Publisher language hint, never verified language or admission authority.
    pub language_hint: Option<String>,
    /// Matching immutable rule position; nested traversal has no page-rule match.
    pub rule_index: Option<usize>,
}

impl std::fmt::Debug for RecipeCandidateV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipeCandidateV1")
            .field("route", &self.route)
            .field("handler", &self.handler)
            .field("kind", &self.kind)
            .field("rule_index", &self.rule_index)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct CompiledRule {
    source: RecipeSourceV1,
    route: String,
    filter: LinkFilter,
    deny: LinkFilter,
    extensions: ExtensionFilter,
    denied_extensions: ExtensionFilter,
}

/// An owned immutable configuration snapshot and its exact identity pin.
///
/// There are no mutation methods, user callbacks, browser handles or executable sources.
#[derive(Debug)]
pub struct CompiledExtensionRecipe {
    spec: ExtensionRecipeV1,
    pin: ExtensionRecipePinV1,
    rules: Vec<CompiledRule>,
    actor: RecipeV1,
}

impl CompiledExtensionRecipe {
    /// Compile reviewed native filters and safe actor actions once per run snapshot. A bounded
    /// `actor_script` is already unrolled into the flat action list by the recipe's own
    /// validation, so a refused script (loop over its cap, `EVAL`, unbound variable) never
    /// yields a compiled recipe and the worker only ever sees the same finite steps.
    ///
    /// # Errors
    /// Rejects schema, handlers, invalid selectors/regular expressions, refused scripts and
    /// action bounds.
    pub fn new(spec: ExtensionRecipeV1) -> Result<Self, RecipeExecutionError> {
        let pin = spec.pin()?;
        let actor = spec.compile_actor()?;
        for step in &actor.steps {
            match &step.action {
                crawlx_core::scrape::ScrapeAction::Click { selector, .. }
                | crawlx_core::scrape::ScrapeAction::Fill { selector, .. }
                | crawlx_core::scrape::ScrapeAction::Scroll {
                    selector: Some(selector),
                    ..
                } => {
                    crawlx_extract::xpath::CompiledSelector::compile(&SelectorV1::Css {
                        expression: selector.clone(),
                    })
                    .map_err(LinkOptionsError::from)?;
                }
                crawlx_core::scrape::ScrapeAction::Press { key }
                    if crate::scrape::render::recipe_key_supported(key).is_none() =>
                {
                    return Err(ExtensionRecipeError::Invalid.into());
                }
                _ => {}
            }
        }
        let mut rules = Vec::with_capacity(spec.rules.len());
        for rule in &spec.rules {
            let mut options = LinkOptions::default();
            options.allow.clone_from(&rule.allow);
            options.deny.clone_from(&rule.deny);
            options.allow_domains.clone_from(&rule.allow_domains);
            options.deny_domains.clone_from(&rule.deny_domains);
            options.nofollow = NofollowPolicy::Skip;
            for selector in &rule.selectors {
                match selector {
                    SelectorV1::Css { expression } => options.restrict_css.push(expression.clone()),
                    SelectorV1::Xpath { expression } => options.restrict_xpath.push(expression.clone()),
                    _ => return Err(ExtensionRecipeError::Invalid.into()),
                }
            }
            let filter = LinkFilter::new(&options)?;
            let mut denial = LinkOptions::default();
            denial.deny = options.deny;
            denial.deny_domains = options.deny_domains;
            rules.push(CompiledRule {
                source: rule.source,
                route: rule.route.clone(),
                filter,
                deny: LinkFilter::new(&denial)?,
                extensions: ExtensionFilter::new(&rule.allow_extensions, &[] as &[String], true),
                denied_extensions: ExtensionFilter::new(&[] as &[String], &rule.deny_extensions, true),
            });
        }
        Ok(Self {
            spec,
            pin,
            rules,
            actor,
        })
    }

    /// Exact immutable run configuration identity.
    #[must_use]
    pub fn pin(&self) -> &ExtensionRecipePinV1 {
        &self.pin
    }

    /// Refuse changed contents under an existing run/checkpoint pin.
    ///
    /// # Errors
    /// Returns a pin mismatch for any identifier, revision or digest difference.
    pub fn verify_pin(&self, expected: &ExtensionRecipePinV1) -> Result<(), RecipeExecutionError> {
        if &self.pin == expected {
            Ok(())
        } else {
            Err(ExtensionRecipeError::Pin.into())
        }
    }

    /// Borrow the existing request/parse/item pipeline without copying configuration.
    #[must_use]
    pub fn pipeline(&self) -> &ExtensionPipelineV1 {
        &self.spec.pipeline
    }

    /// Borrow the safe native recipe for the existing governed action runner.
    /// Compilation is not an operator approval and must not bypass registry approval.
    #[must_use]
    pub fn actor(&self) -> &RecipeV1 {
        &self.actor
    }

    /// Apply start middleware without network effects or queue mutation.
    ///
    /// # Errors
    /// Refuses cancellation, hard-denied URLs, unsupported write methods and output bounds.
    /// Replacements remain complete proposals needing fresh native admission.
    pub fn start_requests(
        &self,
        cancel: &CancellationToken,
    ) -> Result<Vec<RequestEnvelopeV1>, RecipeExecutionError> {
        guard(cancel)?;
        let mut output = Vec::with_capacity(self.spec.start_requests.len());
        let mut bytes = 2_usize;
        for request in &self.spec.start_requests {
            guard(cancel)?;
            self.check_request(request)?;
            let mut lifecycle = crate::extensions::RequestLifecycle::new(&self.spec.pipeline)?;
            let prepared = lifecycle.before_acquisition(request, cancel);
            let _ = lifecycle.finalize(matches!(&prepared, Err(ExtensionError::PolicyDenied)));
            let prepared = prepared?;
            if prepared.route == HandlerV1::Skip {
                continue;
            }
            let proposed = prepared.replacement.unwrap_or_else(|| request.clone());
            self.check_request(&proposed)?;
            if self.spec.pipeline.route(&proposed.route)? == HandlerV1::Skip {
                continue;
            }
            self.charge(&proposed, &mut bytes, output.len())?;
            output.push(proposed);
        }
        guard(cancel)?;
        Ok(output)
    }

    fn check_request(&self, request: &RequestEnvelopeV1) -> Result<(), RecipeExecutionError> {
        request.validate().map_err(ExtensionRecipeError::from)?;
        let extension = decoded_extension(&request.url.url);
        if !matches!(request.method.as_str(), "GET" | "HEAD")
            || request.body.is_some()
            || !self.spec.pipeline.routes.contains_key(&request.route)
            || !safe_url(&request.url.url)
            || self.hard_denied(&request.url.url, &extension)
        {
            return Err(ExtensionError::PolicyDenied.into());
        }
        Ok(())
    }

    /// Run existing parse/item built-ins on a privacy-projected document envelope.
    ///
    /// # Errors
    /// Returns existing quality, privacy, cancellation, label and transform failures.
    pub fn item(
        &self,
        route: &str,
        document: &DocumentEnvelopeV1,
        cancel: &CancellationToken,
    ) -> Result<Option<serde_json::Value>, RecipeExecutionError> {
        guard(cancel)?;
        if !self.spec.pipeline.routes.contains_key(route) {
            return Err(ExtensionRecipeError::Handler.into());
        }
        let item = crate::extensions::transform_document(&self.spec.pipeline, route, document, cancel)?;
        if let Some(item) = &item {
            if json_size(item)? > self.spec.max_output_bytes {
                return Err(ExtensionRecipeError::Limit.into());
            }
        }
        Ok(item)
    }

    /// Select links from a stored page, parsing once for all ordered rule filters.
    ///
    /// # Errors
    /// Refuses malformed selectors, parse-memory/node limits, cancellation or batch overflow.
    /// No network, browser evaluation or process execution occurs.
    pub fn html(
        &self,
        html: &str,
        page: &Url,
        cancel: &CancellationToken,
    ) -> Result<Vec<RecipeCandidateV1>, RecipeExecutionError> {
        self.input(html.len(), cancel)?;
        if !safe_url(page) {
            return Err(ExtensionRecipeError::Invalid.into());
        }
        if !self.rules.iter().any(|r| r.source == RecipeSourceV1::Html) {
            return Ok(Vec::new());
        }
        // The shared charge outlives the tree, which the metering sink builds under it.
        let mut charge =
            crawlx_extract::parse_budget::charge(html.len()).map_err(crawlx_extract::ExtractError::from)?;
        let document = crawlx_extract::dom::parse_document(&mut charge, html)
            .map_err(crawlx_extract::ExtractError::from)?;
        crawlx_extract::dom::check_limits(&document, 100_000)?;
        let base = crawlx_extract::metadata::effective_base(&document, page);
        let mut output = Vec::new();
        let mut seen = BTreeSet::new();
        let mut bytes = 2_usize;
        for (index, rule) in self.rules.iter().enumerate() {
            guard(cancel)?;
            if rule.source != RecipeSourceV1::Html {
                continue;
            }
            for link in rule.filter.links_in(&document, page, &base)? {
                guard(cancel)?;
                let extension = decoded_extension(&link.url);
                if !safe_url(&link.url)
                    || self.hard_denied(&link.url, &extension)
                    || !rule.extensions.allows_extension(&extension)
                    || !seen.insert(link.url.clone())
                {
                    continue;
                }
                let candidate = self.page_candidate(link.url, index, None)?;
                // A first-match skip is still claimed, so later rules cannot resurrect it.
                if candidate.handler != HandlerV1::Skip {
                    self.charge(&candidate, &mut bytes, output.len())?;
                    output.push(candidate);
                }
            }
        }
        guard(cancel)?;
        Ok(output)
    }

    /// Select page/alternate handlers and nested references from one stored sitemap.
    ///
    /// The existing discovery traversal supplies each admitted child document separately.
    /// This method never fetches a child or treats an alternate as a scope exemption.
    ///
    /// # Errors
    /// Refuses gzip (caller must use bounded native decoding), malformed/truncated XML,
    /// source-depth overflow, cancellation and candidate/output overflow.
    pub fn sitemap(
        &self,
        bytes: &[u8],
        source: &Url,
        depth: u16,
        cancel: &CancellationToken,
    ) -> Result<Vec<RecipeCandidateV1>, RecipeExecutionError> {
        self.input(bytes.len(), cancel)?;
        let document = crawlx_url::SitemapParser::parse_limited(bytes, self.spec.max_candidates)?;
        self.sitemap_document(document, source, depth, cancel)
    }

    /// Select an already parsed sitemap after the native last-modified filter.
    ///
    /// This shares the byte-entrypoint's exact first-match and denial semantics.
    /// The caller must enforce its byte limit before parsing the native document.
    ///
    /// # Errors
    /// Refuses malformed/truncated documents, excess entries/depth, cancellation and
    /// proposal/output limits. No child document is fetched.
    pub fn sitemap_document(
        &self,
        document: crawlx_url::SitemapDoc,
        source: &Url,
        depth: u16,
        cancel: &CancellationToken,
    ) -> Result<Vec<RecipeCandidateV1>, RecipeExecutionError> {
        guard(cancel)?;
        if depth > self.spec.max_sitemap_depth
            || !safe_url(source)
            || document.urls.len().saturating_add(document.nested.len()) > self.spec.max_candidates
            || document.urls.iter().any(|entry| entry.hreflang.len() > 16)
        {
            return Err(ExtensionRecipeError::Limit.into());
        }
        if document.gzip || document.malformed || document.truncated {
            return Err(ExtensionRecipeError::Invalid.into());
        }
        let mut output = Vec::new();
        let mut seen = BTreeSet::new();
        let mut used = 2_usize;
        for entry in document.urls {
            guard(cancel)?;
            for (location, language) in std::iter::once((entry.loc, None)).chain(
                entry
                    .hreflang
                    .into_iter()
                    .filter(|_| self.spec.sitemap_alternates)
                    .map(|alternate| (alternate.loc, Some(alternate.language))),
            ) {
                guard(cancel)?;
                let Ok(mut url) = source.join(&location) else {
                    continue;
                };
                url.set_fragment(None);
                let extension = decoded_extension(&url);
                if !safe_url(&url) || self.hard_denied(&url, &extension) || !seen.insert(url.clone()) {
                    continue;
                }
                let selected = self.rules.iter().enumerate().find(|(_, rule)| {
                    rule.source == RecipeSourceV1::Sitemap
                        && rule.filter.admits(&url)
                        && rule.extensions.allows_extension(&extension)
                });
                if let Some((index, _)) = selected {
                    let candidate = self.page_candidate(url, index, language)?;
                    if candidate.handler != HandlerV1::Skip {
                        self.charge(&candidate, &mut used, output.len())?;
                        output.push(candidate);
                    }
                }
            }
        }
        if self.spec.follow_sitemaps && depth < self.spec.max_sitemap_depth {
            let next_depth = depth.checked_add(1).ok_or(ExtensionRecipeError::Limit)?;
            let handler = self
                .spec
                .pipeline
                .routes
                .get("default")
                .copied()
                .ok_or(ExtensionRecipeError::Handler)?;
            for nested in document.nested {
                guard(cancel)?;
                let Ok(mut url) = source.join(&nested.loc) else {
                    continue;
                };
                url.set_fragment(None);
                if !safe_url(&url)
                    || url == *source
                    || self.hard_denied(&url, &decoded_extension(&url))
                    || !seen.insert(url.clone())
                    || handler == HandlerV1::Skip
                {
                    continue;
                }
                let candidate = RecipeCandidateV1 {
                    url,
                    route: "default".into(),
                    handler,
                    kind: RecipeCandidateKindV1::Sitemap,
                    sitemap_depth: next_depth,
                    language_hint: None,
                    rule_index: None,
                };
                self.charge(&candidate, &mut used, output.len())?;
                output.push(candidate);
            }
        }
        guard(cancel)?;
        Ok(output)
    }

    fn page_candidate(
        &self,
        url: Url,
        index: usize,
        language_hint: Option<String>,
    ) -> Result<RecipeCandidateV1, RecipeExecutionError> {
        let rule = &self.rules[index];
        let handler = self
            .spec
            .pipeline
            .routes
            .get(&rule.route)
            .copied()
            .ok_or(ExtensionRecipeError::Handler)?;
        Ok(RecipeCandidateV1 {
            url,
            route: rule.route.clone(),
            handler,
            kind: RecipeCandidateKindV1::Page,
            sitemap_depth: 0,
            language_hint,
            rule_index: Some(index),
        })
    }

    fn hard_denied(&self, url: &Url, extension: &str) -> bool {
        self.rules
            .iter()
            .any(|rule| !rule.deny.admits(url) || !rule.denied_extensions.allows_extension(extension))
    }

    fn input(&self, bytes: usize, cancel: &CancellationToken) -> Result<(), RecipeExecutionError> {
        guard(cancel)?;
        if bytes > self.spec.max_input_bytes {
            return Err(ExtensionRecipeError::Limit.into());
        }
        Ok(())
    }

    fn charge(
        &self,
        value: &impl Serialize,
        used: &mut usize,
        count: usize,
    ) -> Result<(), RecipeExecutionError> {
        let size = json_size(value)?;
        let next = used
            .checked_add(size)
            .and_then(|n| n.checked_add(usize::from(count > 0)))
            .ok_or(ExtensionRecipeError::Limit)?;
        if count >= self.spec.max_candidates || next > self.spec.max_output_bytes {
            return Err(ExtensionRecipeError::Limit.into());
        }
        *used = next;
        Ok(())
    }
}

fn guard(cancel: &CancellationToken) -> Result<(), RecipeExecutionError> {
    if cancel.is_cancelled() {
        Err(ExtensionRecipeError::Cancelled.into())
    } else {
        Ok(())
    }
}

fn safe_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.as_str().len() <= 8192
}

fn decoded_extension(url: &Url) -> String {
    let path = url.path();
    let decoded = if path.as_bytes().contains(&b'%') {
        let mut output = Vec::with_capacity(path.len());
        let input = path.as_bytes();
        let mut index = 0_usize;
        while index < input.len() {
            let byte = input[index];
            if byte == b'%' {
                if let Some((high, low)) = input
                    .get(index + 1)
                    .copied()
                    .and_then(hex)
                    .zip(input.get(index + 2).copied().and_then(hex))
                {
                    output.push(high * 16 + low);
                    index += 3;
                    continue;
                }
            }
            output.push(byte);
            index += 1;
        }
        Cow::Owned(String::from_utf8_lossy(&output).into_owned())
    } else {
        Cow::Borrowed(path)
    };
    path_extension(&decoded)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Typed execution errors retain native source chains without embedding raw input values.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecipeExecutionError {
    /// Invalid configuration, pin, cancellation or bound.
    #[error("extension recipe refused")]
    Recipe(#[from] ExtensionRecipeError),
    /// Existing request or item pipeline refused a proposal.
    #[error("extension recipe pipeline refused")]
    Pipeline(#[from] ExtensionError),
    /// Existing static link selector/filter failed.
    #[error("extension recipe link selection failed")]
    Links(#[from] LinkOptionsError),
    /// Existing static parser failed.
    #[error("extension recipe parsing failed")]
    Parse(#[from] crawlx_extract::ExtractError),
    /// Existing bounded sitemap parser failed.
    #[error("extension recipe sitemap failed")]
    Sitemap(#[from] crawlx_url::UrlError),
}
