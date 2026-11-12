//! Link extraction with explicit filter options.
//!
//! [`LinkOptions`] is one declarative struct; [`LinkFilter`] compiles it once (bounded regex
//! engine, CSS/XPath restriction selectors) and extracts from any number of documents.
//!
//! Evaluation order per candidate occurrence, after resolving the reference against the
//! effective base (`<base href>` aware), keeping `http`/`https` only and dropping the fragment:
//!
//! 1. optional canonical form (sorted query pairs);
//! 2. **deny** — any deny regex or deny domain match rejects the link;
//! 3. **allow** — when an allow list is configured the link must match it. Deny always wins:
//!    a link that matches an allow rule and a deny rule is rejected;
//! 4. `rel=nofollow` handling;
//! 5. de-duplication (when `unique`), merging like [`crate::links::extract_links`].
//!
//! Domain rules match the host itself and its subdomains. Regexes run on the absolute URL text
//! through the linear-time engine with bounded program size; a pattern the engine cannot run
//! safely (backreferences, look-around) is refused at compile time.

use crate::document::ExtractedLink;
use crate::links::anchor_text;
use crate::metadata::effective_base;
use crate::xpath::{CompiledSelector, SelectorDocument, SelectorError, XPathValue};
use crate::ExtractError;
use crawlx_core::selectors::SelectorV1;
use ego_tree::NodeId;
use regex::{Regex, RegexBuilder};
use scraper::Html;
use std::collections::{BTreeMap, HashMap, HashSet};
use url::Url;

const MAX_RULES: usize = 64;
const MAX_PATTERN_BYTES: usize = 512;
const REGEX_SIZE_LIMIT: usize = 1 << 20;
const MAX_LINKS: usize = 100_000;

/// What to do with links whose `rel` contains `nofollow`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum NofollowPolicy {
    /// Keep them; [`ExtractedLink::nofollow`] reports the flag.
    #[default]
    Keep,
    /// Drop every such occurrence before de-duplication, so a URL that is also linked without
    /// `nofollow` survives with `nofollow == false`.
    Skip,
}

/// Declarative link extraction options. The default extracts every `a[href]` and `area[href]`
/// link of the whole document and de-duplicates by URL.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkOptions {
    /// Regexes on the absolute URL; when non-empty one must match.
    pub allow: Vec<String>,
    /// Regexes on the absolute URL; any match rejects the link (wins over `allow`).
    pub deny: Vec<String>,
    /// Hosts (and their subdomains) the link must belong to; empty means any.
    pub allow_domains: Vec<String>,
    /// Hosts (and their subdomains) that reject the link (wins over `allow_domains`).
    pub deny_domains: Vec<String>,
    /// Element names scanned for links.
    pub tags: Vec<String>,
    /// Attribute names read from those elements, in order.
    pub attrs: Vec<String>,
    /// CSS selectors; when any restriction is set, only links inside a matching element (or the
    /// element itself) are considered. CSS and XPath restrictions are unioned.
    pub restrict_css: Vec<String>,
    /// XPath 1.0 restriction expressions; see `restrict_css`.
    pub restrict_xpath: Vec<String>,
    /// Rewrite each URL into canonical form (fragment removed, query pairs sorted).
    pub canonicalize: bool,
    /// Collapse duplicate URLs into their first occurrence.
    pub unique: bool,
    /// Handling of `rel=nofollow`.
    pub nofollow: NofollowPolicy,
}

impl Default for LinkOptions {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            tags: vec!["a".to_owned(), "area".to_owned()],
            attrs: vec!["href".to_owned()],
            restrict_css: Vec::new(),
            restrict_xpath: Vec::new(),
            canonicalize: false,
            unique: true,
            nofollow: NofollowPolicy::Keep,
        }
    }
}

/// Invalid link options or a failed extraction.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LinkOptionsError {
    /// A regex or domain rule was refused.
    #[error("invalid link {list} rule {index}: {reason}")]
    Rule {
        /// Option the rule belongs to (`allow`, `deny`, `allow_domains`, `deny_domains`).
        list: &'static str,
        /// Position within that option.
        index: usize,
        /// Why it was refused.
        reason: String,
    },
    /// An option list or name is not acceptable.
    #[error("invalid link option: {0}")]
    Invalid(&'static str),
    /// A restriction selector failed to compile or evaluate.
    #[error("link restriction selector failed")]
    Selector(#[from] SelectorError),
    /// The document was refused before extraction.
    #[error("link extraction input refused")]
    Extract(#[from] ExtractError),
}

fn rule_error(list: &'static str, index: usize, reason: impl Into<String>) -> LinkOptionsError {
    LinkOptionsError::Rule {
        list,
        index,
        reason: reason.into(),
    }
}

fn compile_patterns(list: &'static str, patterns: &[String]) -> Result<Vec<Regex>, LinkOptionsError> {
    if patterns.len() > MAX_RULES {
        return Err(LinkOptionsError::Invalid("too many regex rules"));
    }
    patterns
        .iter()
        .enumerate()
        .map(|(index, pattern)| {
            if pattern.is_empty() || pattern.len() > MAX_PATTERN_BYTES {
                return Err(rule_error(list, index, "pattern is empty or too long"));
            }
            RegexBuilder::new(pattern)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_SIZE_LIMIT)
                .nest_limit(64)
                .build()
                .map_err(|error| rule_error(list, index, error.to_string()))
        })
        .collect()
}

fn compile_domains(list: &'static str, domains: &[String]) -> Result<Vec<String>, LinkOptionsError> {
    if domains.len() > MAX_RULES {
        return Err(LinkOptionsError::Invalid("too many domain rules"));
    }
    domains
        .iter()
        .enumerate()
        .map(|(index, domain)| {
            let trimmed = domain.trim().trim_start_matches('.');
            match url::Host::parse(trimmed) {
                Ok(url::Host::Domain(host)) if !host.is_empty() => Ok(host),
                _ => Err(rule_error(list, index, "not a domain name")),
            }
        })
        .collect()
}

fn compile_names(what: &'static str, names: &[String]) -> Result<Vec<String>, LinkOptionsError> {
    if names.is_empty() || names.len() > MAX_RULES {
        return Err(LinkOptionsError::Invalid(what));
    }
    names
        .iter()
        .map(|name| {
            let name = name.trim().to_ascii_lowercase();
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
            {
                return Err(LinkOptionsError::Invalid(what));
            }
            Ok(name)
        })
        .collect()
}

fn host_matches(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Fragment removed and query pairs sorted; empty pairs dropped.
fn canonical_form(url: &mut Url) {
    url.set_fragment(None);
    let sorted = url.query().map(|query| {
        let mut pairs: Vec<&str> = query.split('&').filter(|pair| !pair.is_empty()).collect();
        pairs.sort_unstable();
        pairs.join("&")
    });
    match sorted {
        Some(joined) if !joined.is_empty() => url.set_query(Some(&joined)),
        Some(_) => url.set_query(None),
        None => {}
    }
}

/// Compiled [`LinkOptions`].
#[derive(Debug)]
pub struct LinkFilter {
    allow: Vec<Regex>,
    deny: Vec<Regex>,
    allow_domains: Vec<String>,
    deny_domains: Vec<String>,
    tags: Vec<String>,
    attrs: Vec<String>,
    restrict: Vec<CompiledSelector>,
    canonicalize: bool,
    unique: bool,
    nofollow: NofollowPolicy,
}

impl LinkFilter {
    /// Compile `options`.
    ///
    /// # Errors
    /// Returns [`LinkOptionsError`] for an unsafe or invalid regex, a malformed domain, an empty
    /// tag or attribute list, or a restriction selector that does not compile.
    pub fn new(options: &LinkOptions) -> Result<Self, LinkOptionsError> {
        let mut restrict = Vec::with_capacity(options.restrict_css.len() + options.restrict_xpath.len());
        if options.restrict_css.len() + options.restrict_xpath.len() > MAX_RULES {
            return Err(LinkOptionsError::Invalid("too many restriction selectors"));
        }
        for expression in &options.restrict_css {
            restrict.push(CompiledSelector::compile(&SelectorV1::Css {
                expression: expression.clone(),
            })?);
        }
        for expression in &options.restrict_xpath {
            restrict.push(CompiledSelector::xpath(expression)?);
        }
        Ok(Self {
            allow: compile_patterns("allow", &options.allow)?,
            deny: compile_patterns("deny", &options.deny)?,
            allow_domains: compile_domains("allow_domains", &options.allow_domains)?,
            deny_domains: compile_domains("deny_domains", &options.deny_domains)?,
            tags: compile_names("tags must be a non-empty list of element names", &options.tags)?,
            attrs: compile_names(
                "attrs must be a non-empty list of attribute names",
                &options.attrs,
            )?,
            restrict,
            canonicalize: options.canonicalize,
            unique: options.unique,
            nofollow: options.nofollow,
        })
    }

    /// Whether `url` passes the deny and allow rules (deny wins).
    #[must_use]
    pub fn admits(&self, url: &Url) -> bool {
        let text = url.as_str();
        let host = url.host_str().unwrap_or("");
        if self.deny.iter().any(|re| re.is_match(text))
            || self.deny_domains.iter().any(|domain| host_matches(host, domain))
        {
            return false;
        }
        (self.allow.is_empty() || self.allow.iter().any(|re| re.is_match(text)))
            && (self.allow_domains.is_empty()
                || self.allow_domains.iter().any(|domain| host_matches(host, domain)))
    }

    /// Parse `html` and extract links under these options, honouring `<base href>`.
    ///
    /// # Errors
    /// [`LinkOptionsError::Extract`] when the input exceeds the size, node or depth limits or
    /// the parse-memory budget; [`LinkOptionsError::Selector`] when a restriction selector fails
    /// to evaluate.
    pub fn links(&self, html: &str, page: &Url) -> Result<Vec<ExtractedLink>, LinkOptionsError> {
        let opts = crate::ExtractOptions::default();
        crate::precheck(html, &opts)?;
        // declared before `doc`: released after the parsed tree is dropped
        let mut charge = crate::parse_budget::charge(html.len()).map_err(ExtractError::from)?;
        let doc = crate::dom::parse_document(&mut charge, html).map_err(ExtractError::from)?;
        crate::dom::check_limits(&doc, opts.max_nodes)?;
        let base = effective_base(&doc, page);
        self.links_in(&doc, page, &base)
    }

    /// Extract links from an already parsed document.
    ///
    /// # Errors
    /// [`LinkOptionsError::Selector`] when a restriction selector fails to evaluate.
    pub fn links_in(
        &self,
        doc: &Html,
        page: &Url,
        base: &Url,
    ) -> Result<Vec<ExtractedLink>, LinkOptionsError> {
        let regions = self.regions(doc)?;
        let mut out: Vec<ExtractedLink> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        let mut stack = vec![(doc.tree.root(), regions.is_none())];
        while let Some((node, inside)) = stack.pop() {
            let mut inside = inside;
            if let Some(el) = scraper::ElementRef::wrap(node) {
                let name = el.value().name();
                if matches!(name, "script" | "style" | "template") {
                    continue;
                }
                inside = inside || regions.as_ref().is_some_and(|set| set.contains(&node.id()));
                if inside && self.tags.iter().any(|tag| tag == name) {
                    for attr in &self.attrs {
                        let Some(value) = el.value().attr(attr) else {
                            continue;
                        };
                        if self.record(el, value, page, base, &mut out, &mut index) && out.len() >= MAX_LINKS
                        {
                            return Ok(out);
                        }
                    }
                }
            }
            stack.extend(node.children().rev().map(|child| (child, inside)));
        }
        Ok(out)
    }

    /// Node ids of every restriction match; `None` when no restriction is configured.
    fn regions(&self, doc: &Html) -> Result<Option<HashSet<NodeId>>, LinkOptionsError> {
        if self.restrict.is_empty() {
            return Ok(None);
        }
        let mut selector_doc = SelectorDocument::new(doc)?;
        let namespaces = BTreeMap::new();
        let mut set = HashSet::new();
        for selector in &self.restrict {
            match selector_doc.evaluate(selector, &namespaces)? {
                XPathValue::Nodes(nodes) => {
                    set.extend(nodes.into_iter().filter_map(|node| selector_doc.native_id(node)));
                }
                _ => return Err(SelectorError::NodeSetRequired.into()),
            }
        }
        Ok(Some(set))
    }

    /// Apply the per-occurrence rules; returns true when a new link was appended.
    fn record(
        &self,
        el: scraper::ElementRef<'_>,
        value: &str,
        page: &Url,
        base: &Url,
        out: &mut Vec<ExtractedLink>,
        index: &mut HashMap<String, usize>,
    ) -> bool {
        let href = value.trim();
        if href.is_empty() || href.starts_with('#') {
            return false;
        }
        let Some(mut url) = crate::dom::resolve(base, href) else {
            return false;
        };
        if !matches!(url.scheme(), "http" | "https") {
            return false;
        }
        url.set_fragment(None);
        if self.canonicalize {
            canonical_form(&mut url);
        }
        if !self.admits(&url) {
            return false;
        }
        let rel: Vec<String> = el
            .value()
            .attr("rel")
            .unwrap_or("")
            .split_whitespace()
            .map(str::to_ascii_lowercase)
            .collect();
        let nofollow = rel.iter().any(|token| token == "nofollow");
        if nofollow && self.nofollow == NofollowPolicy::Skip {
            return false;
        }
        let text = anchor_text(el);
        if self.unique {
            if let Some(&existing) = index.get(url.as_str()) {
                let link = &mut out[existing];
                if link.text.is_empty() {
                    link.text = text;
                }
                for token in rel {
                    if !link.rel.contains(&token) {
                        link.rel.push(token);
                    }
                }
                link.nofollow &= nofollow;
                return false;
            }
            index.insert(url.as_str().to_owned(), out.len());
        }
        let internal = url.host_str().is_some() && url.host_str() == page.host_str();
        out.push(ExtractedLink {
            url,
            text,
            rel,
            nofollow,
            internal,
        });
        true
    }
}
