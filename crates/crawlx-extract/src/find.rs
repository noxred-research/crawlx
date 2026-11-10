//! Bounded element search, traversal, similarity and selector generation on a shared
//! [`SelectorDocument`] index.
//!
//! * [`ElementQuery`] describes elements by tag, attributes and text; [`find_all`],
//!   [`find_first`], [`find_unique`] and [`filter`] evaluate it. A search that must pick one
//!   element ([`find_unique`], [`find_most_similar`]) abstains with a typed outcome when the
//!   answer is ambiguous instead of guessing.
//! * Regex conditions go through the same admission gate as every other pattern
//!   ([`crate::regex_builtins::compile_regex`]): linear-time engine, no backreferences or
//!   look-around, bounded compiled size.
//! * [`ancestors`], [`siblings`], [`children`] and friends traverse the existing tree.
//! * [`find_similar`] ranks same-tag elements by deterministic fixed-point structural similarity
//!   with ties broken by document order.
//! * [`css_path`] and [`xpath_of`] generate selectors that select exactly one element.
//!
//! Every operation charges the document's shared operation budget and returns
//! [`SelectorError::Budget`] on exhaustion; no partial result is returned as a success.

use std::collections::BTreeSet;

use regex::Regex;
use scraper::ElementRef;

use crate::handlers::clean_text;
use crate::regex_builtins::{self, RegexError};
use crate::xpath::{SelectorDocument, SelectorError};

/// How a string (attribute value or element text) is compared.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ValueMatch {
    /// Attribute exists, or the text is non-empty.
    Present,
    /// Exact equality.
    Equals(String),
    /// Substring containment.
    Contains(String),
    /// Prefix match.
    StartsWith(String),
    /// Suffix match.
    EndsWith(String),
    /// Whitespace-separated token equality (the `class` attribute model).
    Word(String),
    /// Admitted linear-time regex search.
    Regex(Regex),
}

impl ValueMatch {
    /// Admit `pattern` as a regex condition.
    ///
    /// # Errors
    /// The [`RegexError`] of the admission gate.
    pub fn regex(pattern: &str) -> Result<Self, RegexError> {
        regex_builtins::compile_regex(pattern).map(Self::Regex)
    }

    /// Admit a built-in pattern (bare or versioned name) as a regex condition.
    ///
    /// # Errors
    /// [`RegexError::UnknownBuiltin`] for an unknown name.
    pub fn builtin(name: &str) -> Result<Self, RegexError> {
        let found = regex_builtins::builtin(name)?;
        regex_builtins::compile_regex(found.pattern).map(Self::Regex)
    }

    fn accepts(&self, value: &str) -> bool {
        match self {
            Self::Present => true,
            Self::Equals(s) => value == s,
            Self::Contains(s) => value.contains(s.as_str()),
            Self::StartsWith(s) => value.starts_with(s.as_str()),
            Self::EndsWith(s) => value.ends_with(s.as_str()),
            Self::Word(s) => value.split_ascii_whitespace().any(|w| w == s),
            Self::Regex(re) => re.is_match(value),
        }
    }
}

/// Conjunction of conditions an element must satisfy.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ElementQuery {
    tag: Option<String>,
    attributes: Vec<(String, ValueMatch)>,
    text: Option<ValueMatch>,
    own_text: bool,
}

impl ElementQuery {
    /// Query matching every element.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Require this tag name (ASCII case-insensitive).
    #[must_use]
    pub fn tag(mut self, tag: &str) -> Self {
        self.tag = Some(tag.to_owned());
        self
    }

    /// Require an attribute condition (name matched ASCII case-insensitively).
    #[must_use]
    pub fn attribute(mut self, name: &str, condition: ValueMatch) -> Self {
        self.attributes.push((name.to_owned(), condition));
        self
    }

    /// Require a class token.
    #[must_use]
    pub fn class(self, class: &str) -> Self {
        self.attribute("class", ValueMatch::Word(class.to_owned()))
    }

    /// Require an exact `id`.
    #[must_use]
    pub fn id(self, id: &str) -> Self {
        self.attribute("id", ValueMatch::Equals(id.to_owned()))
    }

    /// Require the element's whitespace-normalized descendant text to satisfy `condition`.
    #[must_use]
    pub fn text(mut self, condition: ValueMatch) -> Self {
        self.text = Some(condition);
        self.own_text = false;
        self
    }

    /// Require the whitespace-normalized text of the element's own direct text nodes to satisfy
    /// `condition`, ignoring text inside child elements.
    #[must_use]
    pub fn own_text(mut self, condition: ValueMatch) -> Self {
        self.text = Some(condition);
        self.own_text = true;
        self
    }
}

/// Whitespace-normalized text of `node` (descendant text for elements).
///
/// # Errors
/// Shared operation exhaustion.
pub fn text(doc: &mut SelectorDocument<'_>, node: usize) -> Result<String, SelectorError> {
    let raw = doc.string_value(node)?;
    doc.charge(raw.len())?;
    Ok(clean_text(&raw))
}

fn own_text(doc: &mut SelectorDocument<'_>, element: ElementRef<'_>) -> Result<String, SelectorError> {
    let mut raw = String::new();
    for child in element.children() {
        doc.charge(1)?;
        if let Some(t) = child.value().as_text() {
            doc.charge(t.len())?;
            raw.push_str(t);
            raw.push(' ');
        }
    }
    Ok(clean_text(&raw))
}

/// Whether the element at `node` satisfies `query`.
///
/// # Errors
/// Shared operation exhaustion.
pub fn matches(
    doc: &mut SelectorDocument<'_>,
    node: usize,
    query: &ElementQuery,
) -> Result<bool, SelectorError> {
    let Some(element) = doc.element(node) else {
        return Ok(false);
    };
    doc.charge(1)?;
    if let Some(tag) = &query.tag {
        if !element.value().name().eq_ignore_ascii_case(tag) {
            return Ok(false);
        }
    }
    for (name, condition) in &query.attributes {
        doc.charge(element.value().attrs.len().saturating_add(1))?;
        let found = element
            .value()
            .attrs()
            .find(|(attr, _)| attr.eq_ignore_ascii_case(name))
            .map(|(_, value)| value);
        match found {
            Some(value) => {
                doc.charge(value.len())?;
                if !condition.accepts(value) {
                    return Ok(false);
                }
            }
            None => return Ok(false),
        }
    }
    if let Some(condition) = &query.text {
        let value = if query.own_text {
            own_text(doc, element)?
        } else {
            text(doc, node)?
        };
        let accepted = match condition {
            ValueMatch::Present => !value.is_empty(),
            other => other.accepts(&value),
        };
        if !accepted {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Descendant elements of `scope` matching `query`, in document order.
///
/// # Errors
/// Shared operation exhaustion or the selected-node ceiling.
pub fn find_all(
    doc: &mut SelectorDocument<'_>,
    scope: usize,
    query: &ElementQuery,
) -> Result<Vec<usize>, SelectorError> {
    let candidates = doc.descendant_elements(scope)?;
    filter(doc, &candidates, query)
}

/// First descendant element of `scope` matching `query` in document order.
///
/// # Errors
/// Shared operation exhaustion or the selected-node ceiling.
pub fn find_first(
    doc: &mut SelectorDocument<'_>,
    scope: usize,
    query: &ElementQuery,
) -> Result<Option<usize>, SelectorError> {
    for node in doc.descendant_elements(scope)? {
        if matches(doc, node, query)? {
            return Ok(Some(node));
        }
    }
    Ok(None)
}

/// The elements of `nodes` that satisfy `query`, order preserved.
///
/// # Errors
/// Shared operation exhaustion.
pub fn filter(
    doc: &mut SelectorDocument<'_>,
    nodes: &[usize],
    query: &ElementQuery,
) -> Result<Vec<usize>, SelectorError> {
    let mut out = Vec::new();
    for &node in nodes {
        if matches(doc, node, query)? {
            out.push(node);
        }
    }
    Ok(out)
}

/// Result of a search that must identify exactly one element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FindOutcome {
    /// Exactly one element matched.
    Unique(usize),
    /// Nothing matched.
    NotFound,
    /// More than one element matched; the search abstains rather than choosing.
    Ambiguous {
        /// Number of matches found.
        count: usize,
    },
}

/// Find the single descendant of `scope` matching `query`, abstaining when several match.
///
/// # Errors
/// Shared operation exhaustion or the selected-node ceiling.
pub fn find_unique(
    doc: &mut SelectorDocument<'_>,
    scope: usize,
    query: &ElementQuery,
) -> Result<FindOutcome, SelectorError> {
    let found = find_all(doc, scope, query)?;
    Ok(match found.as_slice() {
        [] => FindOutcome::NotFound,
        [one] => FindOutcome::Unique(*one),
        many => FindOutcome::Ambiguous { count: many.len() },
    })
}

/// Element ancestors of `node`, nearest first, excluding the document root.
///
/// # Errors
/// Shared operation exhaustion.
pub fn ancestors(doc: &mut SelectorDocument<'_>, node: usize) -> Result<Vec<usize>, SelectorError> {
    let mut out = Vec::new();
    let mut current = doc.parent_of(node);
    while let Some(parent) = current {
        doc.charge(1)?;
        if doc.element(parent).is_some() {
            out.push(parent);
        }
        current = doc.parent_of(parent);
    }
    Ok(out)
}

/// Nearest ancestor of `node` matching `query`.
///
/// # Errors
/// Shared operation exhaustion.
pub fn find_ancestor(
    doc: &mut SelectorDocument<'_>,
    node: usize,
    query: &ElementQuery,
) -> Result<Option<usize>, SelectorError> {
    for ancestor in ancestors(doc, node)? {
        if matches(doc, ancestor, query)? {
            return Ok(Some(ancestor));
        }
    }
    Ok(None)
}

/// Element children of `node`, document order.
///
/// # Errors
/// Shared operation exhaustion.
pub fn children(doc: &mut SelectorDocument<'_>, node: usize) -> Result<Vec<usize>, SelectorError> {
    doc.element_children(node)
}

/// Element siblings before and after a node, both in document order.
type SiblingSplit = (Vec<usize>, Vec<usize>);

fn sibling_split(doc: &mut SelectorDocument<'_>, node: usize) -> Result<Option<SiblingSplit>, SelectorError> {
    let Some(parent) = doc.parent_of(node) else {
        return Ok(None);
    };
    let all = doc.element_children(parent)?;
    let Some(at) = all.iter().position(|n| *n == node) else {
        return Ok(None);
    };
    Ok(Some((all[..at].to_vec(), all[at + 1..].to_vec())))
}

/// Element siblings of `node` excluding itself, document order.
///
/// # Errors
/// Shared operation exhaustion.
pub fn siblings(doc: &mut SelectorDocument<'_>, node: usize) -> Result<Vec<usize>, SelectorError> {
    Ok(
        sibling_split(doc, node)?.map_or_else(Vec::new, |(mut before, after)| {
            before.extend(after);
            before
        }),
    )
}

/// Following element siblings of `node`, nearest first.
///
/// # Errors
/// Shared operation exhaustion.
pub fn next_siblings(doc: &mut SelectorDocument<'_>, node: usize) -> Result<Vec<usize>, SelectorError> {
    Ok(sibling_split(doc, node)?.map_or_else(Vec::new, |(_, after)| after))
}

/// Preceding element siblings of `node`, nearest first.
///
/// # Errors
/// Shared operation exhaustion.
pub fn previous_siblings(doc: &mut SelectorDocument<'_>, node: usize) -> Result<Vec<usize>, SelectorError> {
    Ok(
        sibling_split(doc, node)?.map_or_else(Vec::new, |(mut before, _)| {
            before.reverse();
            before
        }),
    )
}

/// Nearest following element sibling.
///
/// # Errors
/// Shared operation exhaustion.
pub fn next_sibling(doc: &mut SelectorDocument<'_>, node: usize) -> Result<Option<usize>, SelectorError> {
    Ok(next_siblings(doc, node)?.first().copied())
}

/// Nearest preceding element sibling.
///
/// # Errors
/// Shared operation exhaustion.
pub fn previous_sibling(doc: &mut SelectorDocument<'_>, node: usize) -> Result<Option<usize>, SelectorError> {
    Ok(previous_siblings(doc, node)?.first().copied())
}

/// Tuning of [`find_similar`] and [`find_most_similar`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SimilarOptions {
    /// Minimum score, 0 through 1000.
    pub threshold: u16,
    /// Most matches returned, at most 1000.
    pub max_results: usize,
    /// Score lead over the runner-up that [`find_most_similar`] requires, at least one.
    pub margin: u16,
    /// Also compare attribute values; otherwise only attribute names count.
    pub compare_attribute_values: bool,
}

impl Default for SimilarOptions {
    fn default() -> Self {
        Self {
            threshold: 700,
            max_results: 100,
            margin: 50,
            compare_attribute_values: false,
        }
    }
}

/// An element and its similarity score (0 through 1000, not a probability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SimilarMatch {
    /// Document index of the similar element.
    pub node: usize,
    /// Fixed-point similarity score.
    pub score: u16,
}

/// Decision of [`find_most_similar`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SimilarOutcome {
    /// One candidate passed the threshold with the required lead.
    Match(SimilarMatch),
    /// The best candidate does not lead the runner-up by the required margin.
    Ambiguous {
        /// Best candidate.
        best: SimilarMatch,
        /// Runner-up candidate.
        runner_up: SimilarMatch,
    },
    /// No candidate passed the threshold.
    NotFound,
}

struct Features {
    tag: String,
    depth: usize,
    parent_tag: Option<String>,
    classes: BTreeSet<String>,
    attribute_names: BTreeSet<String>,
    attribute_pairs: BTreeSet<(String, String)>,
    child_tags: BTreeSet<String>,
}

fn features(doc: &mut SelectorDocument<'_>, node: usize) -> Result<Option<Features>, SelectorError> {
    let Some(element) = doc.element(node) else {
        return Ok(None);
    };
    doc.charge(element.value().attrs.len().saturating_add(1))?;
    let mut depth = 0usize;
    let mut parent_tag = None;
    let mut current = doc.parent_of(node);
    while let Some(parent) = current {
        doc.charge(1)?;
        if let Some(parent_element) = doc.element(parent) {
            depth = depth.saturating_add(1);
            if parent_tag.is_none() {
                parent_tag = Some(parent_element.value().name().to_ascii_lowercase());
            }
        }
        current = doc.parent_of(parent);
    }
    let mut classes = BTreeSet::new();
    let mut attribute_names = BTreeSet::new();
    let mut attribute_pairs = BTreeSet::new();
    for (name, value) in element.value().attrs() {
        let name = name.to_ascii_lowercase();
        if name == "class" {
            classes.extend(value.split_ascii_whitespace().map(str::to_owned));
        } else {
            attribute_pairs.insert((name.clone(), value.to_owned()));
            attribute_names.insert(name);
        }
    }
    let child_tags = element
        .children()
        .filter_map(ElementRef::wrap)
        .map(|c| c.value().name().to_ascii_lowercase())
        .collect();
    Ok(Some(Features {
        tag: element.value().name().to_ascii_lowercase(),
        depth,
        parent_tag,
        classes,
        attribute_names,
        attribute_pairs,
        child_tags,
    }))
}

/// `weight * |a ∩ b| / |a ∪ b|`, the full weight when both sets are empty.
fn jaccard<T: Ord>(a: &BTreeSet<T>, b: &BTreeSet<T>, weight: usize) -> usize {
    let union = a.union(b).count();
    weight
        .saturating_mul(a.intersection(b).count())
        .checked_div(union)
        .unwrap_or(weight)
}

fn score(a: &Features, b: &Features, compare_values: bool) -> u16 {
    let (name_weight, value_weight) = if compare_values { (200, 100) } else { (300, 0) };
    let mut total = jaccard(&a.classes, &b.classes, 250)
        + jaccard(&a.attribute_names, &b.attribute_names, name_weight)
        + jaccard(&a.child_tags, &b.child_tags, 150);
    if compare_values {
        total += jaccard(&a.attribute_pairs, &b.attribute_pairs, value_weight);
    }
    if a.depth == b.depth {
        total += 150;
    }
    if a.parent_tag == b.parent_tag {
        total += 150;
    }
    u16::try_from(total.min(1000)).unwrap_or(1000)
}

/// Same-tag elements structurally similar to `node`, best first, ties in document order.
///
/// The reference element itself is excluded. Similarity compares class tokens, attribute names
/// (and optionally values), depth, parent tag and child tag set with fixed-point integer weights.
///
/// # Errors
/// [`SelectorError::NodeSetRequired`] when `node` is not an element, `Budget` on exhaustion or an
/// invalid option, shared operation exhaustion.
pub fn find_similar(
    doc: &mut SelectorDocument<'_>,
    node: usize,
    options: &SimilarOptions,
) -> Result<Vec<SimilarMatch>, SelectorError> {
    if options.threshold > 1000 || options.max_results == 0 || options.max_results > 1000 {
        return Err(SelectorError::Budget("similarity options"));
    }
    let reference = features(doc, node)?.ok_or(SelectorError::NodeSetRequired)?;
    let mut found = Vec::new();
    for candidate in doc.descendant_elements(0)? {
        if candidate == node {
            continue;
        }
        let Some(element) = doc.element(candidate) else {
            continue;
        };
        doc.charge(1)?;
        if !element.value().name().eq_ignore_ascii_case(&reference.tag) {
            continue;
        }
        let Some(other) = features(doc, candidate)? else {
            continue;
        };
        let value = score(&reference, &other, options.compare_attribute_values);
        if value >= options.threshold {
            found.push(SimilarMatch {
                node: candidate,
                score: value,
            });
        }
    }
    found.sort_by(|a, b| b.score.cmp(&a.score).then(a.node.cmp(&b.node)));
    found.truncate(options.max_results);
    Ok(found)
}

/// Choose the single most similar element, abstaining when the lead is below the margin.
///
/// # Errors
/// Same as [`find_similar`]; additionally `Budget` when `margin` is zero.
pub fn find_most_similar(
    doc: &mut SelectorDocument<'_>,
    node: usize,
    options: &SimilarOptions,
) -> Result<SimilarOutcome, SelectorError> {
    if options.margin == 0 {
        return Err(SelectorError::Budget("similarity options"));
    }
    let mut wide = *options;
    wide.max_results = 2;
    let ranked = find_similar(doc, node, &wide)?;
    Ok(match ranked.as_slice() {
        [] => SimilarOutcome::NotFound,
        [only] => SimilarOutcome::Match(*only),
        [best, runner_up, ..] => {
            if best.score.saturating_sub(runner_up.score) >= options.margin {
                SimilarOutcome::Match(*best)
            } else {
                SimilarOutcome::Ambiguous {
                    best: *best,
                    runner_up: *runner_up,
                }
            }
        }
    })
}

const HTML_NS: &str = "http://www.w3.org/1999/xhtml";

fn same_kind_position(
    doc: &mut SelectorDocument<'_>,
    element: ElementRef<'_>,
    node: usize,
    html_only: bool,
) -> Result<usize, SelectorError> {
    let Some(parent) = doc.parent_of(node) else {
        return Ok(1);
    };
    let local = element.value().name();
    let mut position = 1usize;
    for sibling in doc.element_children(parent)? {
        if sibling == node {
            break;
        }
        if let Some(other) = doc.element(sibling) {
            let same_name = other.value().name() == local;
            let same_ns = !html_only || &*other.value().name.ns == HTML_NS;
            if same_name && same_ns {
                position += 1;
            }
        }
    }
    Ok(position)
}

/// Absolute XPath selecting exactly `node`, for example `/html/body/div[2]/p[1]`.
///
/// # Errors
/// [`SelectorError::NodeSetRequired`] when `node` is not an element; shared operation exhaustion.
pub fn xpath_of(doc: &mut SelectorDocument<'_>, node: usize) -> Result<String, SelectorError> {
    let mut chain = vec![node];
    chain.extend(ancestors(doc, node)?);
    chain.reverse();
    let mut out = String::new();
    for current in chain {
        let element = doc.element(current).ok_or(SelectorError::NodeSetRequired)?;
        let html = &*element.value().name.ns == HTML_NS;
        let position = same_kind_position(doc, element, current, html)?;
        let local = element.value().name();
        if html {
            out.push_str(&format!("/{local}[{position}]"));
        } else {
            out.push_str(&format!("/*[local-name()='{local}'][{position}]"));
        }
    }
    Ok(out)
}

/// CSS selector selecting exactly `node`, for example `html > body > div:nth-of-type(2) > p:nth-of-type(1)`.
///
/// # Errors
/// [`SelectorError::NodeSetRequired`] when `node` is not an element;
/// [`SelectorError::Unsupported`] when a tag name on the path cannot be written as a CSS type
/// selector; shared operation exhaustion.
pub fn css_path(doc: &mut SelectorDocument<'_>, node: usize) -> Result<String, SelectorError> {
    let mut chain = vec![node];
    chain.extend(ancestors(doc, node)?);
    chain.reverse();
    let mut parts = Vec::with_capacity(chain.len());
    for current in chain {
        let element = doc.element(current).ok_or(SelectorError::NodeSetRequired)?;
        let name = element.value().name();
        let simple = name.starts_with(|c: char| c.is_ascii_alphabetic())
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !simple || &*element.value().name.ns != HTML_NS {
            return Err(SelectorError::Unsupported(
                "element name not expressible as a CSS type selector",
            ));
        }
        let position = same_kind_position(doc, element, current, true)?;
        parts.push(format!("{}:nth-of-type({position})", name.to_ascii_lowercase()));
    }
    Ok(parts.join(" > "))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use scraper::Html;
    use std::collections::BTreeMap;

    const PAGE: &str = r#"<html><body>
        <ul id="list">
          <li class="item a" data-k="1"><span>Alpha</span> <b>one</b></li>
          <li class="item" data-k="2"><span>Beta</span> <b>two</b></li>
          <li class="item" data-k="3"><span>Gamma</span> <b>three</b></li>
          <li class="other"><em>Delta</em></li>
        </ul>
        <p id="solo">Only <i>one</i> here</p>
        </body></html>"#;

    fn doc(html: &Html) -> SelectorDocument<'_> {
        SelectorDocument::new(html).unwrap()
    }

    #[test]
    fn find_by_tag_attribute_text_and_regex() {
        let html = Html::parse_document(PAGE);
        let mut d = doc(&html);
        let items = find_all(&mut d, 0, &ElementQuery::new().tag("li").class("item")).unwrap();
        assert_eq!(items.len(), 3);
        let by_text = find_all(
            &mut d,
            0,
            &ElementQuery::new()
                .tag("span")
                .text(ValueMatch::Equals("Beta".into())),
        )
        .unwrap();
        assert_eq!(by_text.len(), 1);
        let by_regex = find_all(
            &mut d,
            0,
            &ElementQuery::new()
                .tag("span")
                .text(ValueMatch::regex("^(Alpha|Gamma)$").unwrap()),
        )
        .unwrap();
        assert_eq!(by_regex.len(), 2);
        let attr = find_all(
            &mut d,
            0,
            &ElementQuery::new().attribute("DATA-K", ValueMatch::StartsWith("2".into())),
        )
        .unwrap();
        assert_eq!(attr.len(), 1);
        let own = find_all(
            &mut d,
            0,
            &ElementQuery::new()
                .tag("p")
                .own_text(ValueMatch::Equals("Only here".into())),
        )
        .unwrap();
        assert_eq!(own.len(), 1);
        let nested = find_all(
            &mut d,
            0,
            &ElementQuery::new()
                .tag("p")
                .text(ValueMatch::Equals("Only one here".into())),
        )
        .unwrap();
        assert_eq!(nested, own);
        assert_eq!(
            find_first(&mut d, 0, &ElementQuery::new().tag("li")).unwrap(),
            Some(items[0])
        );
        assert_eq!(text(&mut d, own[0]).unwrap(), "Only one here");
    }

    #[test]
    fn unsupported_regex_is_rejected_at_admission() {
        assert!(matches!(
            ValueMatch::regex(r"(a)\1"),
            Err(RegexError::Backreference)
        ));
        assert!(matches!(ValueMatch::regex("a(?=b)"), Err(RegexError::Lookaround)));
        assert!(matches!(
            ValueMatch::builtin("nope"),
            Err(RegexError::UnknownBuiltin(_))
        ));
        assert!(ValueMatch::builtin("email").is_ok());
    }

    #[test]
    fn ambiguous_unique_search_abstains() {
        let html = Html::parse_document(PAGE);
        let mut d = doc(&html);
        assert!(matches!(
            find_unique(&mut d, 0, &ElementQuery::new().class("item")).unwrap(),
            FindOutcome::Ambiguous { count: 3 }
        ));
        assert_eq!(
            find_unique(&mut d, 0, &ElementQuery::new().class("nothing")).unwrap(),
            FindOutcome::NotFound
        );
        let FindOutcome::Unique(one) = find_unique(&mut d, 0, &ElementQuery::new().id("solo")).unwrap()
        else {
            panic!("expected unique");
        };
        assert_eq!(d.element(one).unwrap().value().name(), "p");
    }

    #[test]
    fn traversal_helpers_return_document_ordered_results() {
        let html = Html::parse_document(PAGE);
        let mut d = doc(&html);
        let items = find_all(&mut d, 0, &ElementQuery::new().tag("li")).unwrap();
        let beta = items[1];
        assert_eq!(siblings(&mut d, beta).unwrap(), [items[0], items[2], items[3]]);
        assert_eq!(next_siblings(&mut d, beta).unwrap(), [items[2], items[3]]);
        assert_eq!(previous_siblings(&mut d, items[2]).unwrap(), [items[1], items[0]]);
        assert_eq!(next_sibling(&mut d, items[3]).unwrap(), None);
        assert_eq!(previous_sibling(&mut d, items[0]).unwrap(), None);
        let span = find_first(&mut d, beta, &ElementQuery::new().tag("span"))
            .unwrap()
            .unwrap();
        let names: Vec<_> = ancestors(&mut d, span)
            .unwrap()
            .into_iter()
            .map(|n| d.element(n).unwrap().value().name().to_owned())
            .collect();
        assert_eq!(names, ["li", "ul", "body", "html"]);
        assert_eq!(
            find_ancestor(&mut d, span, &ElementQuery::new().id("list"))
                .unwrap()
                .map(|n| d.element(n).unwrap().value().name().to_owned()),
            Some("ul".into())
        );
        assert_eq!(children(&mut d, beta).unwrap().len(), 2);
        // `find_all` is scoped: only descendants of the given element.
        assert_eq!(
            find_all(&mut d, beta, &ElementQuery::new().tag("li")).unwrap(),
            Vec::<usize>::new()
        );
        assert_eq!(
            find_all(&mut d, beta, &ElementQuery::new().tag("b"))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn similarity_ranks_deterministically_with_document_order_ties() {
        let html = Html::parse_document(PAGE);
        let mut d = doc(&html);
        let items = find_all(&mut d, 0, &ElementQuery::new().tag("li")).unwrap();
        let ranked = find_similar(&mut d, items[1], &SimilarOptions::default()).unwrap();
        assert_eq!(
            ranked.iter().map(|m| m.node).collect::<Vec<_>>(),
            [items[2], items[0]]
        );
        assert!(ranked[0].score >= ranked[1].score);
        assert!(!ranked.iter().any(|m| m.node == items[3]));
        let again = find_similar(&mut d, items[1], &SimilarOptions::default()).unwrap();
        assert_eq!(ranked, again);
        // items[0] and items[2] differ from items[1] by `class` token / data value only.
        let strict = SimilarOptions {
            compare_attribute_values: true,
            ..SimilarOptions::default()
        };
        assert!(find_similar(&mut d, items[1], &strict).unwrap().len() <= ranked.len());
    }

    #[test]
    fn most_similar_abstains_on_ties_and_matches_with_a_lead() {
        let html = Html::parse_document(
            "<body><div><i class='x'>a</i><i class='x'>b</i><i class='x'>c</i><i class='y z w'>d</i></div></body>",
        );
        let mut d = doc(&html);
        let items = find_all(&mut d, 0, &ElementQuery::new().tag("i")).unwrap();
        let options = SimilarOptions {
            threshold: 500,
            ..SimilarOptions::default()
        };
        // Two equally similar candidates for the first element.
        assert!(matches!(
            find_most_similar(&mut d, items[0], &options).unwrap(),
            SimilarOutcome::Ambiguous { .. }
        ));
        // For the odd one out nothing clears the threshold.
        let strict = SimilarOptions {
            threshold: 800,
            ..SimilarOptions::default()
        };
        assert_eq!(
            find_most_similar(&mut d, items[3], &strict).unwrap(),
            SimilarOutcome::NotFound
        );
        let html = Html::parse_document(
            "<body><div><i class='x'>a</i><i class='x'>b</i><i class='q'>c</i></div></body>",
        );
        let mut d = doc(&html);
        let items = find_all(&mut d, 0, &ElementQuery::new().tag("i")).unwrap();
        let SimilarOutcome::Match(best) = find_most_similar(
            &mut d,
            items[0],
            &SimilarOptions {
                threshold: 500,
                ..SimilarOptions::default()
            },
        )
        .unwrap() else {
            panic!("expected a lead");
        };
        assert_eq!(best.node, items[1]);
        assert!(matches!(
            find_most_similar(
                &mut d,
                items[0],
                &SimilarOptions {
                    margin: 0,
                    ..SimilarOptions::default()
                }
            ),
            Err(SelectorError::Budget(_))
        ));
    }

    #[test]
    fn generated_selectors_select_exactly_the_node() {
        use crate::xpath::{CompiledSelector, XPathValue};
        let html = Html::parse_document(PAGE);
        let mut d = doc(&html);
        for node in d.descendant_elements(0).unwrap() {
            let xpath = xpath_of(&mut d, node).unwrap();
            let css = css_path(&mut d, node).unwrap();
            for compiled in [
                CompiledSelector::xpath(&xpath).unwrap(),
                CompiledSelector::compile(&crawlx_core::selectors::SelectorV1::Css {
                    expression: css.clone(),
                })
                .unwrap(),
            ] {
                let XPathValue::Nodes(found) = d.evaluate(&compiled, &BTreeMap::new()).unwrap() else {
                    panic!("node set expected");
                };
                assert_eq!(found, [node], "{xpath} / {css}");
            }
        }
    }

    #[test]
    fn work_is_bounded_by_the_shared_budget() {
        let html = Html::parse_document(&"<p>x</p>".repeat(200));
        // Smallest limit that still allows the document to be indexed.
        let index_cost = (1..)
            .find(|limit| SelectorDocument::with_operation_limit(&html, *limit).is_ok())
            .unwrap();
        let mut d = SelectorDocument::with_operation_limit(&html, index_cost + 50).unwrap();
        assert!(matches!(
            find_all(&mut d, 0, &ElementQuery::new().tag("p").text(ValueMatch::Present)),
            Err(SelectorError::Budget(_))
        ));
    }
}
