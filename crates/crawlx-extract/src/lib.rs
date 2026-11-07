//! crawlx-extract: HTML to text/markdown, metadata and link extraction.
//!
//! [`Extractor::extract`] parses a document once with `scraper`/`html5ever`
//! and produces a [`Document`]: title, description, language, canonical URL,
//! Markdown, plain text, cleaned HTML of the selected content, a digest of the
//! raw input, structured [`metadata::Metadata`], absolute deduplicated links
//! and asset URLs.
//!
//! Modules:
//! * [`dom`] converts the parsed tree into a filtered owned tree (scripts,
//!   styles, `noscript`, `template`, `svg` and hidden elements are dropped,
//!   `exclude`/`include` selectors applied);
//! * [`readability`] selects the main content block;
//! * [`markdown`], [`text`] and [`serialize`] render the selected content;
//! * [`tables`] models HTML tables and renders GFM pipe tables;
//! * [`metadata`] and [`links`] read head metadata, links and assets;
//! * [`endpoints`], [`forms`], [`page_type`], [`custom_fields`],
//!   [`technologies`] and [`secrets`] are the katana-derived discovery and
//!   classification extractors (ported with attribution where
//!   noted in the module docs);
//! * [`form_fill`] fills a static form for submission (katana `-aff`/`-fc`),
//!   [`kb`] builds the `knowledgebase` record (endpoint and form classes,
//!   katana `-kb`/`-kb-endpoints`) and [`secret_validation`] plans and
//!   interprets online validation of detected secrets
//!   (`-kb-validate-secrets`); none of them touches the network or the clock.
//! * the Firecrawl scrape formats, all pure functions:
//!   [`firecrawl_meta`] (`metadata` object), [`images`], [`attributes`],
//!   [`base64_images`] (inline base64 image removal), [`branding`]
//!   (`BrandingProfile` heuristics), [`diff`] (`changeTracking` `git-diff` and
//!   `json` modes), [`blocklist`] (`blockAds` CDP URL patterns) and
//!   [`map_rank`] (`/map` `search` ordering).
//!
//! Resource bounds: inputs above `max_input_bytes` (default 16 MiB), documents
//! with more than `max_nodes` nodes and nesting deeper than 512 elements fail
//! with [`ExtractError::TooLarge`]. Extraction never panics on arbitrary
//! input.
//!
//! This is a clean-room implementation of observable behavior; no Firecrawl
//! source is consulted or copied. Katana (MIT) code is ported with
//! attribution in the module docs.

pub mod adaptive_selector;
mod article;
mod article_dates;
mod article_language;
mod article_metadata;
mod article_quality;
mod article_tokens;
pub mod attributes;
pub mod base64_images;
pub mod blocklist;
pub mod branding;
pub mod custom_fields;
pub mod diff;
pub mod document;
pub mod dom;
pub mod endpoints;
pub mod extraction_import;
pub mod firecrawl_meta;
pub mod form_fill;
pub mod forms;
pub mod images;
pub mod item_loader;
pub mod kb;
pub mod links;
pub mod map_rank;
pub mod markdown;
pub mod media;
pub mod metadata;
pub mod page_type;
pub mod parse;
pub mod parse_budget;
pub mod readability;
pub mod secret_validation;
pub mod secrets;
pub mod serialize;
pub mod tables;
pub mod technologies;
pub mod text;
pub mod validation;
pub mod xpath;

use std::collections::HashSet;

use crawlx_core::hash::Digest;
use scraper::{Html, Selector};
use url::Url;

pub use document::{Document, ExtractOptions, ExtractedLink};
pub use endpoints::{DiscoveredEndpoint, DiscoveryInput, DiscoveryOptions};
pub use forms::{StaticForm, StaticInput};
pub use item_loader::validate_content_policy;
pub use links::LinkExtractor;
pub use metadata::{Alternate, Metadata, RobotsMeta};
pub use page_type::PageType;
pub use secrets::{SecretFinding, SecretKind, SecretToken};
pub use technologies::Technology;

use dom::{Elem, Node, Selected};

/// Domain tag of [`Document::raw_html_digest`].
const RAW_HTML_DOMAIN: &str = "crawlx.extract.raw_html.v1";

/// A trusted string projection that may borrow worker-local state.
type StringProjection<'a> = dyn Fn(&str) -> Option<String> + 'a;

/// Errors of the extractor.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    /// The input exceeds a resource limit.
    #[error("input too large: {what} {actual} exceeds limit {limit}")]
    TooLarge {
        /// Which limit was hit (`bytes`, `nodes`, `depth`).
        what: &'static str,
        /// Configured limit.
        limit: usize,
        /// Observed value (a lower bound when the check stopped early).
        actual: usize,
    },
    /// An `include_tags`/`exclude_tags` entry is not a valid CSS selector.
    #[error("invalid selector `{selector}`: {reason}")]
    InvalidSelector {
        /// The offending selector.
        selector: String,
        /// Parser message.
        reason: String,
    },
    /// Native content policy failed validation.
    #[error("invalid content policy: {0}")]
    InvalidContentPolicy(#[from] crawlx_core::CoreError),
    /// Native word-window input, policy or range computation failed closed.
    #[error("word chunk extraction failed: {0}")]
    WordChunks(#[from] crawlx_core::extraction::WordChunkErrorV1),
    /// Bounded static selector or item-loader refused the policy/input.
    #[error("static selector failed: {0}")]
    Selector(#[from] crate::xpath::SelectorError),
    /// A selected JavaScript miner is unavailable in this build.
    #[error("endpoint discovery failed: {0}")]
    Discovery(#[from] endpoints::DiscoveryError),
    /// The process-wide parse-memory budget could not take the parse's charge, so nothing was
    /// parsed. Transient resource pressure: retry once other parses have finished.
    #[error(transparent)]
    ParseMemory(#[from] parse_budget::ParseBudgetExhausted),
}

/// Stateless entry point of the crate.
pub struct Extractor;

fn compile(selectors: &[String]) -> Result<Vec<Selector>, ExtractError> {
    selectors
        .iter()
        .map(|s| {
            Selector::parse(s).map_err(|e| ExtractError::InvalidSelector {
                selector: s.clone(),
                reason: e.to_string(),
            })
        })
        .collect()
}

/// Reject inputs that are too large before parsing. The number of `<` bytes
/// bounds the number of parsed nodes from above (up to implied elements), so
/// pathological inputs are refused before the tree is allocated.
pub(crate) fn precheck(html: &str, opts: &ExtractOptions) -> Result<(), ExtractError> {
    let max_bytes = if opts.content.is_some() {
        opts.max_input_bytes.min(document::DEFAULT_MAX_INPUT_BYTES)
    } else {
        opts.max_input_bytes
    };
    let max_nodes = if opts.content.is_some() {
        opts.max_nodes.min(document::DEFAULT_MAX_NODES)
    } else {
        opts.max_nodes
    };
    if html.len() > max_bytes {
        return Err(ExtractError::TooLarge {
            what: "bytes",
            limit: max_bytes,
            actual: html.len(),
        });
    }
    let lt = html.bytes().filter(|b| *b == b'<').count();
    if lt > max_nodes {
        return Err(ExtractError::TooLarge {
            what: "nodes",
            limit: max_nodes,
            actual: lt,
        });
    }
    Ok(())
}

fn select_ids(doc: &Html, selectors: &[Selector]) -> HashSet<ego_tree::NodeId> {
    selectors
        .iter()
        .flat_map(|s| doc.select(s).map(|e| e.id()))
        .collect()
}

fn find_body(doc: &Html) -> ego_tree::NodeRef<'_, scraper::Node> {
    let mut body = None;
    dom::walk(doc.tree.root(), |el| {
        if body.is_some() {
            return false;
        }
        if el.value().name() == "body" {
            body = Some(*el);
            return false;
        }
        true
    });
    body.unwrap_or_else(|| *doc.root_element())
}

impl Extractor {
    /// Extract a [`Document`] from `html`. `base` is the URL the document was
    /// fetched from; relative references resolve against it unless the
    /// document carries a `<base href>`.
    ///
    /// # Errors
    /// [`ExtractError::TooLarge`] when the input exceeds the byte, node or depth limits;
    /// [`ExtractError::ParseMemory`] when the process-wide parse-memory budget is exhausted;
    /// [`ExtractError::InvalidSelector`] when an include/exclude selector does not parse;
    /// [`ExtractError::Discovery`] when endpoint discovery selects an unavailable miner.
    pub fn extract(html: &str, base: &Url, opts: &ExtractOptions) -> Result<Document, ExtractError> {
        Self::extract_inner(
            html,
            html.as_bytes(),
            Digest::of(RAW_HTML_DOMAIN, html.as_bytes()),
            base,
            opts,
            None,
            None,
        )
    }

    /// Like [`Extractor::extract`] for undecoded bytes. Invalid UTF-8 is
    /// replaced lossy; charset decoding is the fetcher's job. The digest
    /// covers the original bytes.
    ///
    /// # Errors
    /// Same as [`Extractor::extract`].
    pub fn extract_bytes(bytes: &[u8], base: &Url, opts: &ExtractOptions) -> Result<Document, ExtractError> {
        Self::extract_bytes_projected(bytes, base, opts, None)
    }

    /// Extract once and apply a trusted compiled privacy projection before native
    /// metadata/NLP, quality and content digests are finalized.
    ///
    /// `project` returns `None` for an unchanged string, or an owned replacement.
    /// It is a worker-injected pure function, never caller code from configuration.
    /// Legacy extraction ignores this hook unless `opts.content` is selected.
    ///
    /// # Errors
    /// Same as `extract_bytes`; an expanding projection beyond policy limits also fails.
    pub fn extract_bytes_with_projection(
        bytes: &[u8],
        base: &Url,
        opts: &ExtractOptions,
        project: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Document, ExtractError> {
        Self::extract_bytes_projected(bytes, base, opts, Some(project))
    }

    fn extract_bytes_projected(
        bytes: &[u8],
        base: &Url,
        opts: &ExtractOptions,
        project: Option<&StringProjection<'_>>,
    ) -> Result<Document, ExtractError> {
        let max_bytes = if opts.content.is_some() {
            opts.max_input_bytes.min(document::DEFAULT_MAX_INPUT_BYTES)
        } else {
            opts.max_input_bytes
        };
        if bytes.len() > max_bytes {
            return Err(ExtractError::TooLarge {
                what: "bytes",
                limit: max_bytes,
                actual: bytes.len(),
            });
        }
        // The charge covers the lossy copy too: it is taken on the byte length here and topped
        // up to the decoded length in `extract_inner` (replacement characters expand input).
        let charge = parse_budget::charge(bytes.len())?;
        let html = String::from_utf8_lossy(bytes);
        Self::extract_inner(
            &html,
            bytes,
            Digest::of(RAW_HTML_DOMAIN, bytes),
            base,
            opts,
            project,
            Some(charge),
        )
    }

    /// Detect secrets in response `headers` and `body` (`extract.detectSecrets`).
    /// Only kind, location and a hash keyed with `key` are returned; the
    /// value itself never leaves this call.
    #[must_use]
    pub fn detect_secrets(key: &[u8; 32], headers: &[(String, String)], body: &str) -> Vec<SecretFinding> {
        secrets::detect(key, headers, body)
    }

    /// [`detect_secrets`](Self::detect_secrets) plus each finding's matched
    /// value, for online validation (`extract.validateSecrets`). The
    /// [`SecretToken`]s are transient: validate with
    /// [`SecretValidators`](secret_validation::SecretValidators) and drop
    /// them; they must never be stored, serialized or logged (their `Debug`
    /// prints only a length).
    #[must_use]
    pub fn detect_secret_tokens(
        key: &[u8; 32],
        headers: &[(String, String)],
        text: &str,
    ) -> Vec<(SecretFinding, SecretToken)> {
        secrets::detect_tokens(key, headers, text)
    }

    fn extract_inner(
        html: &str,
        raw: &[u8],
        digest: Digest,
        page: &Url,
        opts: &ExtractOptions,
        projection: Option<&StringProjection<'_>>,
        charge: Option<parse_budget::ParseCharge>,
    ) -> Result<Document, ExtractError> {
        precheck(html, opts)?;
        if let Some(policy) = &opts.content {
            policy.validate()?;
            crate::article_dates::validate_timezone(policy)?;
        }
        let include = compile(&opts.include_tags)?;
        let exclude = compile(&opts.exclude_tags)?;

        // Nonwaiting charge for the DOM and everything derived from it. Declared before `doc`,
        // so it is released only after the parsed tree has been dropped.
        let mut charge = match charge {
            Some(charge) => charge,
            None => parse_budget::charge(html.len())?,
        };
        charge.cover(html.len())?;
        let doc = Html::parse_document(html);
        let max_nodes = if opts.content.is_some() {
            opts.max_nodes.min(document::DEFAULT_MAX_NODES)
        } else {
            opts.max_nodes
        };
        dom::check_limits(&doc, max_nodes)?;
        let validation = opts.acquisition_validation.as_ref().map(|context| {
            validation::validate_acquisition(&validation::ValidationInput {
                context,
                content_type: opts.content_type.as_deref(),
                headers: &opts.headers,
                body: raw,
                document: Some(&doc),
            })
        });

        let base = metadata::effective_base(&doc, page);
        let mut head = metadata::extract(&doc, &base);
        let links = links::extract_links(&doc, page, &base);
        let assets = links::extract_assets(&doc, &base);
        let image_urls = opts.image_references.then(|| images::from_document(&doc, &base));
        let attributes = if opts.attribute_selectors.is_empty() {
            None
        } else {
            Some(attributes::from_document(&doc, &opts.attribute_selectors)?)
        };

        let mut selected = Selected {
            exclude: select_ids(&doc, &exclude),
            include: select_ids(&doc, &include),
        };
        let mut item = None;
        let mut read_more = Vec::new();
        let mut has_include = !include.is_empty();
        if let Some(policy) = &opts.content {
            has_include |= !policy.selectors.include.is_empty();
            if !policy.selectors.include.is_empty()
                || !policy.selectors.exclude.is_empty()
                || !policy.selectors.read_more.is_empty()
                || policy.item_loader.is_some()
            {
                let mut indexed = xpath::SelectorDocument::with_operation_limit(&doc, policy.max_operations)?;
                let policy_selection = indexed.select_policy(&policy.selectors)?;
                selected.include.extend(policy_selection.include);
                selected.exclude.extend(policy_selection.exclude);
                read_more = item_loader::select_read_more(&mut indexed, &policy.selectors, &base)?;
                if let Some(spec) = &policy.item_loader {
                    item = Some(item_loader::CompiledItemLoader::compile(spec)?.load(&mut indexed, &base)?);
                }
            }
        }
        let body = dom::convert_node(find_body(&doc), &selected);
        let mut native = None;
        let mut content: Vec<Node> = match body {
            Some(Node::Elem(body)) if opts.content.is_some() => {
                if let Some(policy) = &opts.content {
                    let body = if !has_include {
                        body
                    } else {
                        let mut selection = Elem::new("div");
                        selection.children = dom::collect_matched(vec![Node::Elem(body)]);
                        selection
                    };
                    let mut result = article::select(
                        body,
                        policy,
                        article_metadata::is_forum(&head),
                        !opts.only_main_content || has_include,
                    );
                    if has_include {
                        result.strategy = "explicit_selectors_v1";
                    }
                    let nodes = std::mem::take(&mut result.nodes);
                    native = Some(result);
                    nodes
                } else {
                    Vec::new()
                }
            }
            Some(Node::Elem(body)) => select_content(body, opts, has_include),
            _ => Vec::new(),
        };

        let mut text = text::to_text(&content);
        let mut comments = native
            .as_ref()
            .map(|s| text::to_text(&s.comments))
            .unwrap_or_default();
        let mut blocks = if opts.content.is_some() {
            native
                .as_ref()
                .map(|s| article::source_blocks(&content, &s.main_ids, &text, false))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        if let Some(selection) = &native {
            blocks.extend(article::source_blocks(
                &selection.comments,
                &selection.comment_ids,
                &comments,
                true,
            ));
        }
        let secret_projection = projection.filter(|_| opts.content.is_some());
        let final_projection = |value: &str| {
            let secret = secret_projection.and_then(|project| project(value));
            let source = secret.as_deref().unwrap_or(value);
            if let Some(options) = &opts.content_redaction {
                let redacted = parse::redact::redact(source, options).text;
                if redacted != source {
                    return Some(redacted);
                }
            }
            secret
        };
        let project: Option<&StringProjection<'_>> = (opts.content.is_some()
            && (secret_projection.is_some() || opts.content_redaction.is_some()))
        .then_some(&final_projection);
        let mut source_mapping_redacted = false;
        let mut main_redacted = false;
        if let Some(project) = project {
            main_redacted = article_metadata::project_string(&mut text, project);
            source_mapping_redacted |= main_redacted;
            source_mapping_redacted |= article_metadata::project_string(&mut comments, project);
            for value in [&mut head.title, &mut head.description].into_iter().flatten() {
                article_metadata::project_string(value, project);
            }
            if let (Some(outcome), Some(spec)) = (
                &mut item,
                opts.content
                    .as_ref()
                    .and_then(|policy| policy.item_loader.as_ref()),
            ) {
                item_loader::project_outcome(outcome, spec, project)?;
            }
        }
        if let Some(policy) = &opts.content {
            article::apply_render_policy(&mut content, policy);
        }
        // If normalized inline text changed, discard the old inline markup instead of
        // retaining secret fragments that a browser could concatenate again.
        let mut markdown = if main_redacted {
            markdown::redacted_plain_text(&text)
        } else {
            markdown::to_markdown(&content, &base, opts.keep_data_images)
        };
        let mut html_out = if main_redacted {
            serialize::redacted_text_fragment(&text)
        } else {
            serialize::to_html(&content, &base, opts.keep_data_images)
        };
        if let Some(project) = project {
            article_metadata::project_string(&mut markdown, project);
            article_metadata::project_string(&mut html_out, project);
        }
        if source_mapping_redacted {
            // The output source is now redacted normalized text. Keep stable node IDs,
            // but do not invent an offset mapping back through changed source blocks.
            for block in &mut blocks {
                block.source = None;
            }
        }
        let word_count = if opts.content.is_some() {
            article_metadata::word_count(&text)
        } else {
            text.split_whitespace().count()
        };
        let article = opts
            .content
            .as_ref()
            .map(|policy| {
                for (what, value) in [
                    ("projected main characters", &text),
                    ("projected comment characters", &comments),
                ] {
                    let actual = value.chars().count();
                    if actual > policy.max_output_chars {
                        return Err(ExtractError::TooLarge {
                            what,
                            limit: policy.max_output_chars,
                            actual,
                        });
                    }
                }
                let (metadata, author_excluded) = article_metadata::extract(
                    &doc,
                    &head,
                    page,
                    &text,
                    policy,
                    project,
                    opts.language_detector.as_ref().map(|handle| handle.detector()),
                );
                let operations = native.as_ref().map_or(0, |s| s.operations);
                let quality = article_quality::evaluate(
                    policy,
                    &metadata,
                    &text,
                    blocks.len(),
                    operations,
                    native.as_ref().is_some_and(|s| s.partial) || metadata.nlp_truncated,
                    author_excluded,
                );
                let policy_bytes = serde_json::to_vec(policy)
                    .map_err(|e| crawlx_core::CoreError::Serialization(e.to_string()))?;
                let mut envelope = crawlx_core::extraction::DocumentEnvelopeV1::new(
                    Digest::of("crawlx.extract.policy.v1", &policy_bytes),
                    Digest::of("crawlx.extract.main.unicode_rules_v1", text.as_bytes()),
                    native.as_ref().map_or("explicit_css_v1", |s| s.strategy).into(),
                    native.as_ref().map_or(0, |s| s.fallback_stages),
                    blocks,
                    metadata,
                    quality,
                );
                envelope.chunks = policy
                    .chunks
                    .map(|chunks| crawlx_core::extraction::WordChunkEnvelopeV1::build(&text, chunks))
                    .transpose()?;
                envelope.discovery = article_metadata::discovery(&doc, &base, policy);
                for url in read_more {
                    use crawlx_core::extraction::{DiscoveryIntentV1, DiscoveryPurposeV1};
                    if !envelope.discovery.iter().any(|intent| {
                        intent.url == url && intent.purpose == DiscoveryPurposeV1::ReadMoreReference
                    }) {
                        if envelope.discovery.len() == 32 {
                            return Err(xpath::SelectorError::Budget("discovery intents").into());
                        }
                        envelope
                            .discovery
                            .push(DiscoveryIntentV1::new(url, DiscoveryPurposeV1::ReadMoreReference));
                    }
                }
                if let Some(project) = project {
                    envelope.discovery.retain_mut(|intent| {
                        if let Some(value) = project(intent.url.as_str()) {
                            match Url::parse(&value) {
                                Ok(url) if matches!(url.scheme(), "http" | "https") => intent.url = url,
                                _ => return false,
                            }
                        }
                        true
                    });
                }
                envelope.source_mapping_redacted = source_mapping_redacted;
                envelope.privacy_projection_version = projection.map(|_| 1);
                Ok::<_, ExtractError>(envelope)
            })
            .transpose()?;

        let forms = if opts.forms || opts.page_type {
            forms::extract(&doc, &base)
        } else {
            Vec::new()
        };
        let page_type = opts.page_type.then(|| {
            page_type::classify(&page_type::PageInput {
                doc: &doc,
                title: head.title.as_deref(),
                text: &text,
                forms: &forms,
                status: opts.status,
                headers: &opts.headers,
            })
        });
        let technologies = if opts.technologies {
            technologies::detect(
                &technologies::TechInput {
                    url: Some(page),
                    headers: &opts.headers,
                    html,
                    js_globals: &[],
                },
                &doc,
            )
        } else {
            Vec::new()
        };
        let custom_fields = if opts.custom_fields.is_empty() {
            std::collections::BTreeMap::new()
        } else {
            custom_fields::extract(&opts.custom_fields, &opts.headers, html)
        };
        let discovered_endpoints = if opts.discover_endpoints {
            let input = DiscoveryInput {
                url: page,
                status: opts.status,
                headers: &opts.headers,
                content_type: opts.content_type.as_deref(),
                body: raw,
                depth: opts.depth,
            };
            endpoints::discover_html(
                &doc,
                &base,
                &input,
                &DiscoveryOptions {
                    javascript_mode: opts.javascript_mode,
                    ..DiscoveryOptions::default()
                },
            )?
        } else {
            Vec::new()
        };

        Ok(Document {
            title: head.title,
            description: head.description,
            language: head.language,
            canonical_url: head.canonical_url,
            base_url: base,
            markdown,
            text,
            html: html_out,
            raw_html_digest: digest,
            metadata: head.metadata,
            links,
            assets,
            word_count,
            forms: if opts.forms { forms } else { Vec::new() },
            page_type,
            technologies,
            custom_fields,
            discovered_endpoints,
            article,
            comments,
            validation,
            item,
            image_urls,
            attributes,
        })
    }
}

fn select_content(body: Elem, opts: &ExtractOptions, has_include: bool) -> Vec<Node> {
    if has_include {
        dom::collect_matched(vec![Node::Elem(body)])
    } else if opts.only_main_content {
        vec![Node::Elem(readability::extract_main(body))]
    } else {
        vec![Node::Elem(body)]
    }
}
