//! Opt-in content outputs of [`crate::Extractor`]: HTML and Markdown variants, fit content,
//! citation-style Markdown, normalized tables, link/media scores and the discovery scope.
//!
//! Everything here is derived from the one parse of the acquired document, so one corpus yields
//! several distinct, exactly reproducible renditions:
//!
//! | output | content |
//! |---|---|
//! | `raw_html` | the input exactly as acquired |
//! | `cleaned_html` | the whole page after the element filter (scripts, styles, hidden elements and `excludeTags` removed), before any content selection |
//! | `Document::html` / `markdown` | the selected content (main content, `includeTags` or `targetElements`) |
//! | `fit_html` / `fit_markdown` | the selected content after the [`FitFilter`] |
//! | `markdown_with_citations` | Markdown of the chosen [`CitationSource`] with numbered link markers and a reference list |
//!
//! Nothing is fetched: citations only name URLs the page already contains, and every citation
//! keeps the index of the matching entry of `Document::links` as retained provenance.
//!
//! `targetElements` narrows the selected content only. Links and assets keep the declared
//! [`DiscoveryScope`]: the whole page by default, or only what the selected content references.

use std::collections::BTreeSet;

use scraper::Html;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::document::ExtractedLink;
use crate::dom::{resolve, srcset_urls, Elem, Node};
use crate::fit::{self, FilterError, FitFilter, FitReport};
use crate::link_media::{self, LinkMediaOptions, LinkMediaReport, MAX_PREVIEWS};
use crate::tables::{self, TableExtraction};
use crate::{markdown, serialize};

/// Most `targetElements` selectors accepted.
pub const MAX_TARGET_ELEMENTS: usize = 64;
/// Longest `targetElements` selector, in bytes.
pub const MAX_TARGET_SELECTOR_BYTES: usize = 1_024;

/// Errors of the content outputs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ContentOutputError {
    /// The fit filter refused its parameters or ran out of budget.
    #[error("fit filter failed: {0}")]
    Filter(#[from] FilterError),
    /// An output option is out of range or inconsistent.
    #[error("invalid output option `{name}`: {reason}")]
    InvalidOption {
        /// Option name.
        name: &'static str,
        /// What is wrong.
        reason: &'static str,
    },
}

/// Which links and assets `Document::links` and `Document::assets` list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DiscoveryScope {
    /// Every link and asset of the page, whatever content was selected.
    #[default]
    WholePage,
    /// Only links and assets referenced from the selected content.
    Selected,
}

/// Which content tree the citation-style Markdown is built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CitationSource {
    /// The selected content (the content of `Document::markdown`).
    Selected,
    /// The whole cleaned page.
    Cleaned,
    /// The selected content after the fit filter; needs [`ContentOutputOptions::fit`].
    Fit,
}

/// Which outputs to build. Every output is off by default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
#[non_exhaustive]
pub struct ContentOutputOptions {
    /// CSS selectors of the elements to extract. Narrows text, Markdown and HTML like
    /// `includeTags`; links and assets keep [`Self::discovery_scope`]. Malformed selectors fail
    /// extraction with `InvalidSelector`; at most 64 selectors of 1024 bytes.
    pub target_elements: Vec<String>,
    /// Scope of `Document::links` and `Document::assets`.
    pub discovery_scope: DiscoveryScope,
    /// Return the input as acquired.
    pub raw_html: bool,
    /// Return the cleaned whole page.
    pub cleaned_html: bool,
    /// Build `fit_html` and `fit_markdown` with this filter.
    pub fit: Option<FitFilter>,
    /// Build citation-style Markdown from this source.
    pub citations: Option<CitationSource>,
    /// Analyse the tables of the selected content.
    pub tables: bool,
    /// Score links and media and optionally create preview intents.
    pub link_media: Option<LinkMediaOptions>,
}

impl ContentOutputOptions {
    /// Check the options before any parsing.
    ///
    /// # Errors
    /// [`ContentOutputError`] naming the first bad option.
    pub fn validate(&self) -> Result<(), ContentOutputError> {
        let bad = |name, reason| Err(ContentOutputError::InvalidOption { name, reason });
        if self.target_elements.len() > MAX_TARGET_ELEMENTS {
            return bad("targetElements", "more than 64 selectors");
        }
        if self
            .target_elements
            .iter()
            .any(|s| s.trim().is_empty() || s.len() > MAX_TARGET_SELECTOR_BYTES)
        {
            return bad("targetElements", "empty selector or longer than 1024 bytes");
        }
        if let Some(filter) = &self.fit {
            filter.validate()?;
        }
        if self.citations == Some(CitationSource::Fit) && self.fit.is_none() {
            return bad("citations", "source `fit` needs a fit filter");
        }
        if self
            .link_media
            .as_ref()
            .is_some_and(|o| o.max_previews > MAX_PREVIEWS)
        {
            return bad("linkMedia.maxPreviews", "more than 32 previews");
        }
        Ok(())
    }

    /// The whole cleaned page is needed to build an output.
    pub(crate) fn needs_cleaned(&self) -> bool {
        self.cleaned_html || self.citations == Some(CitationSource::Cleaned)
    }
}

/// One reference of the citation-style Markdown with its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CitationEntry {
    /// One-based marker number (`⟨n⟩`).
    pub index: usize,
    /// Link target as written in the page, resolved against the base URL.
    pub url: Url,
    /// Collapsed link text of the first occurrence.
    pub text: String,
    /// Position of the link in `Document::links` (fragment ignored); `None` for targets that list
    /// does not hold, such as `mailto:` or links outside the discovery scope.
    pub link_index: Option<usize>,
}

/// The requested content outputs of one document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ContentOutputs {
    /// Scope that was applied to `Document::links` and `Document::assets`.
    pub discovery_scope: DiscoveryScope,
    /// The input as acquired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_html: Option<String>,
    /// The cleaned whole page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleaned_html: Option<String>,
    /// HTML of the fit content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fit_html: Option<String>,
    /// Markdown of the fit content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fit_markdown: Option<String>,
    /// Report of the fit filter run (strategy id, counts, operations).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fit: Option<FitReport>,
    /// Citation-style Markdown, reference list included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markdown_with_citations: Option<String>,
    /// Retained references of the citation-style Markdown.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub citations: Vec<CitationEntry>,
    /// Table analysis of the selected content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tables: Option<TableExtraction>,
    /// Link and media scores with preview intents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_media: Option<LinkMediaReport>,
    /// A privacy projection rewrote the main text, so no derived markup variant is returned.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub withheld: bool,
}

impl ContentOutputs {
    /// Apply a trusted privacy projection to every text output.
    pub(crate) fn project(&mut self, project: &dyn Fn(&str) -> Option<String>) {
        let apply = |s: &mut String| {
            if let Some(v) = project(s) {
                *s = v;
            }
        };
        for s in [
            &mut self.raw_html,
            &mut self.cleaned_html,
            &mut self.fit_html,
            &mut self.fit_markdown,
            &mut self.markdown_with_citations,
        ]
        .into_iter()
        .flatten()
        {
            apply(s);
        }
        for c in &mut self.citations {
            apply(&mut c.text);
        }
        if let Some(t) = &mut self.tables {
            for table in &mut t.tables {
                if let Some(c) = &mut table.caption {
                    apply(c);
                }
                for cell in table.header.iter_mut().chain(table.rows.iter_mut().flatten()) {
                    apply(cell);
                }
            }
        }
    }
}

/// Inputs of [`build`].
pub(crate) struct BuildInput<'a> {
    pub options: &'a ContentOutputOptions,
    pub doc: &'a Html,
    pub page: &'a Url,
    pub base: &'a Url,
    pub raw: &'a str,
    pub content: &'a [Node],
    pub cleaned: Option<&'a [Node]>,
    /// Links after the discovery scope was applied.
    pub links: &'a [ExtractedLink],
    pub allowed_media: Option<&'a BTreeSet<String>>,
    pub keep_data_images: bool,
    /// The main text was rewritten by a privacy projection.
    pub withhold: bool,
}

/// Build the requested outputs.
pub(crate) fn build(input: &BuildInput<'_>) -> Result<ContentOutputs, ContentOutputError> {
    let o = input.options;
    let mut out = ContentOutputs {
        discovery_scope: o.discovery_scope,
        ..ContentOutputs::default()
    };
    if let Some(options) = &o.link_media {
        out.link_media = Some(link_media::score(
            input.doc,
            input.page,
            input.base,
            input.links,
            input.allowed_media,
            options,
        ));
    }
    if input.withhold {
        out.withheld = true;
        return Ok(out);
    }
    let html = |nodes: &[Node]| serialize::to_html(nodes, input.base, input.keep_data_images);
    let md = |nodes: &[Node]| markdown::to_markdown(nodes, input.base, input.keep_data_images);
    if o.raw_html {
        out.raw_html = Some(input.raw.to_owned());
    }
    if o.cleaned_html {
        out.cleaned_html = Some(html(input.cleaned.unwrap_or(&[])));
    }
    let fit = o.fit.as_ref().map(|f| fit::apply(input.content, f)).transpose()?;
    if let Some(fit) = &fit {
        out.fit_html = Some(html(&fit.nodes));
        out.fit_markdown = Some(md(&fit.nodes));
        out.fit = Some(fit.report.clone());
    }
    if let Some(source) = o.citations {
        let nodes: &[Node] = match source {
            CitationSource::Selected => input.content,
            CitationSource::Cleaned => input.cleaned.unwrap_or(&[]),
            CitationSource::Fit => fit.as_ref().map(|f| f.nodes.as_slice()).unwrap_or(&[]),
        };
        let (text, citations) =
            markdown::to_markdown_with_citations(nodes, input.base, input.keep_data_images);
        out.markdown_with_citations = Some(text);
        out.citations = citations
            .into_iter()
            .map(|c| {
                let mut key = c.url.clone();
                key.set_fragment(None);
                CitationEntry {
                    link_index: input.links.iter().position(|l| l.url == key),
                    index: c.index,
                    url: c.url,
                    text: c.text,
                }
            })
            .collect();
    }
    if o.tables {
        out.tables = Some(tables::extract_tables(input.content));
    }
    Ok(out)
}

fn collect_urls(e: &Elem, base: &Url, out: &mut BTreeSet<String>) {
    let mut add = |raw: &str| {
        if let Some(mut u) = resolve(base, raw) {
            if matches!(u.scheme(), "http" | "https") {
                u.set_fragment(None);
                out.insert(u.into());
            }
        }
    };
    let attrs: &[&str] = match e.tag.as_str() {
        "a" | "area" => &["href"],
        "img" => &["src", "data-src", "data-original", "data-lazy-src"],
        "source" | "audio" | "track" | "embed" | "script" => &["src"],
        "video" => &["src", "poster"],
        "object" => &["data"],
        _ => &[],
    };
    for name in attrs {
        if let Some(v) = e.attr(name) {
            add(v);
        }
    }
    if matches!(e.tag.as_str(), "img" | "source") {
        for name in ["srcset", "data-srcset"] {
            if let Some(v) = e.attr(name) {
                srcset_urls(v).into_iter().for_each(&mut add);
            }
        }
    }
    for c in e.child_elems() {
        collect_urls(c, base, out);
    }
}

/// URLs (links and assets, fragment removed) referenced from `nodes`.
pub(crate) fn referenced_urls(nodes: &[Node], base: &Url) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for n in nodes {
        if let Node::Elem(e) = n {
            collect_urls(e, base, &mut out);
        }
    }
    out
}
