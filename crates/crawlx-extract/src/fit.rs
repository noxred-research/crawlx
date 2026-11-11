//! Deterministic content filters that produce the "fit" content of a page.
//!
//! Two versioned strategies narrow an already selected content tree to the blocks that matter:
//!
//! * [`FitFilter::Pruning`] (`pruning_v1`) scores each block from its text density, link density,
//!   tag weight, class/id hints and text length, all in integer permille, and drops blocks under
//!   the threshold. Boilerplate containers (navigation, footers, sidebars, hinted wrappers) are
//!   vetoed as a whole unless their aggregate score clears the threshold.
//! * [`FitFilter::Bm25`] (`bm25_v1`) keeps the blocks that match a caller query, scored with the
//!   fixed-point BM25 of [`crate::bm25`] against the blocks of the same page.
//!
//! Both walk the tree once in document order, never call a model, never read the clock and use no
//! floating point. A *block* is a leaf block element: an atomic block (`p`, headings, `pre`, lists,
//! data tables, ...) or a container (`div`, `section`, ...) without block descendants. Containers
//! with surviving blocks keep their own inline text; containers whose blocks were all dropped go
//! with them. Work is charged against `max_operations`; exceeding it fails with
//! [`FilterError::Budget`] instead of returning a partial result.

use serde::{Deserialize, Serialize};

use crate::bm25::{self, Corpus, Tokenizer};
use crate::dom::{Elem, Node};

/// Strategy id of the pruning filter.
pub const PRUNING_STRATEGY_ID: &str = "pruning_v1";
/// Strategy id of the BM25 filter.
pub const BM25_STRATEGY_ID: &str = bm25::BM25_VERSION;
/// Default operation budget of one filter run.
pub const DEFAULT_MAX_OPERATIONS: u64 = 2_000_000;
/// Longest accepted BM25 query, in bytes.
pub const MAX_QUERY_BYTES: usize = 4_096;

/// Weight of text density in the pruning score (permille; the five weights sum to 1000).
const W_DENSITY: u64 = 300;
/// Weight of the inverse link density.
const W_LINK: u64 = 250;
/// Weight of the tag prior.
const W_TAG: u64 = 150;
/// Weight of the class/id hint.
const W_CLASS: u64 = 150;
/// Weight of the text-length term.
const W_LENGTH: u64 = 150;
/// Tag overhead in characters of the density denominator.
const TAG_COST: u64 = 25;
/// Characters at which the text-length term saturates.
const LENGTH_SATURATION: u64 = 400;

/// Errors of the content filters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FilterError {
    /// A parameter is out of range.
    #[error("invalid filter parameter `{name}`: {reason}")]
    InvalidParams {
        /// Parameter name.
        name: &'static str,
        /// What is wrong.
        reason: &'static str,
    },
    /// The filter spent its operation budget.
    #[error("filter exceeded its operation budget of {limit}")]
    Budget {
        /// Configured budget.
        limit: u64,
    },
}

/// Parameters of `pruning_v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
#[non_exhaustive]
pub struct PruningParams {
    /// Blocks scoring below this many permille (0..=1000) are dropped.
    pub threshold_permille: u32,
    /// Blocks with fewer whitespace-separated words are dropped; 0 disables the rule.
    pub min_words: u32,
    /// Operation budget.
    pub max_operations: u64,
}

impl Default for PruningParams {
    fn default() -> Self {
        Self {
            threshold_permille: 480,
            min_words: 0,
            max_operations: DEFAULT_MAX_OPERATIONS,
        }
    }
}

impl PruningParams {
    /// Set the score threshold in permille.
    #[must_use]
    pub fn with_threshold_permille(mut self, threshold: u32) -> Self {
        self.threshold_permille = threshold;
        self
    }

    /// Set the minimum word count of a kept block.
    #[must_use]
    pub fn with_min_words(mut self, words: u32) -> Self {
        self.min_words = words;
        self
    }

    /// Set the operation budget.
    #[must_use]
    pub fn with_max_operations(mut self, operations: u64) -> Self {
        self.max_operations = operations;
        self
    }
}

/// Parameters of `bm25_v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct Bm25Params {
    /// Caller query; must contain at least one non-stop-word term.
    pub query: String,
    /// Term-frequency saturation times 1000.
    #[serde(default = "default_k1")]
    pub k1_milli: u32,
    /// Length normalization times 1000 (0..=1000).
    #[serde(default = "default_b")]
    pub b_milli: u32,
    /// Blocks scoring below this (score times 1000) are dropped.
    #[serde(default = "default_bm25_threshold")]
    pub threshold_milli: u32,
    /// Blocks with fewer whitespace-separated words are dropped; 0 disables the rule.
    #[serde(default)]
    pub min_words: u32,
    /// Operation budget.
    #[serde(default = "default_ops")]
    pub max_operations: u64,
}

fn default_k1() -> u32 {
    1_200
}
fn default_b() -> u32 {
    750
}
fn default_bm25_threshold() -> u32 {
    250
}
fn default_ops() -> u64 {
    DEFAULT_MAX_OPERATIONS
}

impl Bm25Params {
    /// Parameters with the `bm25_v1` defaults for `query`.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            k1_milli: default_k1(),
            b_milli: default_b(),
            threshold_milli: default_bm25_threshold(),
            min_words: 0,
            max_operations: DEFAULT_MAX_OPERATIONS,
        }
    }

    /// Set the score threshold (score times 1000).
    #[must_use]
    pub fn with_threshold_milli(mut self, threshold: u32) -> Self {
        self.threshold_milli = threshold;
        self
    }

    /// Set the operation budget.
    #[must_use]
    pub fn with_max_operations(mut self, operations: u64) -> Self {
        self.max_operations = operations;
        self
    }

    /// Set the minimum word count of a kept block.
    #[must_use]
    pub fn with_min_words(mut self, words: u32) -> Self {
        self.min_words = words;
        self
    }
}

/// Selected filter strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum FitFilter {
    /// `pruning_v1`.
    Pruning(PruningParams),
    /// `bm25_v1`.
    Bm25(Bm25Params),
}

impl Default for FitFilter {
    fn default() -> Self {
        Self::Pruning(PruningParams::default())
    }
}

impl FitFilter {
    /// Versioned id of the strategy.
    #[must_use]
    pub fn strategy_id(&self) -> &'static str {
        match self {
            Self::Pruning(_) => PRUNING_STRATEGY_ID,
            Self::Bm25(_) => BM25_STRATEGY_ID,
        }
    }

    /// Check the parameters.
    ///
    /// # Errors
    /// [`FilterError::InvalidParams`] naming the first bad parameter.
    pub fn validate(&self) -> Result<(), FilterError> {
        let bad = |name, reason| Err(FilterError::InvalidParams { name, reason });
        match self {
            Self::Pruning(p) => {
                if p.threshold_permille > 1_000 {
                    return bad("thresholdPermille", "must be at most 1000");
                }
                if p.max_operations == 0 {
                    return bad("maxOperations", "must be positive");
                }
            }
            Self::Bm25(p) => {
                if p.query.len() > MAX_QUERY_BYTES {
                    return bad("query", "exceeds 4096 bytes");
                }
                if p.b_milli > 1_000 {
                    return bad("bMilli", "must be at most 1000");
                }
                if p.k1_milli > 10_000 {
                    return bad("k1Milli", "must be at most 10000");
                }
                if p.max_operations == 0 {
                    return bad("maxOperations", "must be positive");
                }
            }
        }
        Ok(())
    }
}

/// What a filter run did. Counts and the budget spent are deterministic for equal input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct FitReport {
    /// Versioned strategy id (`pruning_v1` or `bm25_v1`).
    pub strategy: String,
    /// Leaf blocks kept.
    pub kept_blocks: usize,
    /// Leaf blocks dropped, plus containers dropped whole by the boilerplate veto.
    pub dropped_blocks: usize,
    /// Operations spent.
    pub operations: u64,
}

/// Filtered content nodes and the run report.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FitOutcome {
    /// Filtered nodes, in document order.
    pub nodes: Vec<Node>,
    /// Run report.
    pub report: FitReport,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Container,
    Atomic,
    Inline,
}

const INLINE_TAGS: &[&str] = &[
    "a", "abbr", "area", "audio", "b", "bdi", "bdo", "big", "br", "button", "canvas", "cite", "code", "data",
    "del", "dfn", "em", "embed", "font", "i", "iframe", "img", "input", "ins", "kbd", "label", "map", "mark",
    "meter", "noscript", "object", "output", "picture", "progress", "q", "rp", "rt", "ruby", "s", "samp",
    "select", "slot", "small", "source", "span", "strike", "strong", "sub", "sup", "svg", "textarea", "time",
    "track", "tt", "u", "var", "video", "wbr",
];

const ATOMIC_TAGS: &[&str] = &[
    "p",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "ul",
    "ol",
    "dl",
    "li",
    "dd",
    "dt",
    "figcaption",
    "hr",
    "summary",
    "caption",
    "legend",
    "menu",
    "dir",
];

/// Tags whose presence inside a table marks it as a layout table.
const LAYOUT_MARKERS: &[&str] = &[
    "table",
    "div",
    "p",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "ul",
    "ol",
    "blockquote",
    "section",
    "article",
    "pre",
];

fn class_of(e: &Elem, budget: &mut Budget) -> Result<Class, FilterError> {
    let tag = e.tag.as_str();
    if INLINE_TAGS.contains(&tag) {
        return Ok(Class::Inline);
    }
    if ATOMIC_TAGS.contains(&tag) {
        return Ok(Class::Atomic);
    }
    if tag == "table" {
        return Ok(if table_is_layout(e, budget)? {
            Class::Container
        } else {
            Class::Atomic
        });
    }
    Ok(Class::Container)
}

fn table_is_layout(table: &Elem, budget: &mut Budget) -> Result<bool, FilterError> {
    for child in table.child_elems() {
        budget.charge(1)?;
        if LAYOUT_MARKERS.contains(&child.tag.as_str()) {
            return Ok(true);
        }
        if table_is_layout(child, budget)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn contains_block(e: &Elem, budget: &mut Budget) -> Result<bool, FilterError> {
    for child in e.child_elems() {
        budget.charge(1)?;
        if class_of(child, budget)? != Class::Inline || contains_block(child, budget)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn wide(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

struct Budget {
    used: u64,
    limit: u64,
}

impl Budget {
    fn charge(&mut self, n: u64) -> Result<(), FilterError> {
        self.used = self.used.saturating_add(n);
        if self.used > self.limit {
            Err(FilterError::Budget { limit: self.limit })
        } else {
            Ok(())
        }
    }
}

/// Integer statistics of a subtree.
#[derive(Default)]
struct Metrics {
    /// Non-whitespace characters.
    text_chars: u64,
    /// Non-whitespace characters inside anchors.
    link_chars: u64,
    /// Structural (non-inline) elements, the root included; inline anchors and emphasis are text.
    tags: u64,
    /// Whitespace-separated words (counted per text node).
    words: u64,
    /// An image, picture, video or audio element occurs.
    media: bool,
}

fn measure(e: &Elem, in_link: bool, m: &mut Metrics, budget: &mut Budget) -> Result<(), FilterError> {
    budget.charge(1)?;
    if !INLINE_TAGS.contains(&e.tag.as_str()) {
        m.tags += 1;
    }
    if matches!(e.tag.as_str(), "img" | "picture" | "video" | "audio") {
        m.media = true;
    }
    let in_link = in_link || e.tag == "a";
    for child in &e.children {
        match child {
            Node::Text(t) => {
                budget.charge(1 + wide(t.len()) / 64)?;
                let chars = wide(t.chars().filter(|c| !c.is_whitespace()).count());
                m.text_chars += chars;
                if in_link {
                    m.link_chars += chars;
                }
                m.words += wide(t.split_whitespace().count());
            }
            Node::Elem(c) => measure(c, in_link, m, budget)?,
        }
    }
    Ok(())
}

fn metrics_of(e: &Elem, budget: &mut Budget) -> Result<Metrics, FilterError> {
    let mut m = Metrics::default();
    measure(e, false, &mut m, budget)?;
    Ok(m)
}

fn leaf_text(e: &Elem, out: &mut String, budget: &mut Budget) -> Result<(), FilterError> {
    budget.charge(1)?;
    let boundary = class_of(e, budget)? != Class::Inline;
    if boundary {
        out.push(' ');
    }
    for child in &e.children {
        match child {
            Node::Text(t) => {
                budget.charge(1 + wide(t.len()) / 64)?;
                out.push_str(t);
            }
            Node::Elem(c) => leaf_text(c, out, budget)?,
        }
    }
    if boundary {
        out.push(' ');
    }
    Ok(())
}

const NEGATIVE_TOKENS: &[&str] = &[
    "nav",
    "navbar",
    "navigation",
    "menu",
    "footer",
    "sidebar",
    "side",
    "aside",
    "ad",
    "ads",
    "advert",
    "advertisement",
    "banner",
    "comment",
    "comments",
    "cookie",
    "cookies",
    "consent",
    "popup",
    "modal",
    "promo",
    "share",
    "sharing",
    "social",
    "related",
    "recommended",
    "widget",
    "breadcrumb",
    "breadcrumbs",
    "newsletter",
    "subscribe",
    "toolbar",
    "masthead",
    "sponsor",
    "sponsored",
];

const POSITIVE_TOKENS: &[&str] = &[
    "content", "article", "post", "entry", "story", "main", "text", "prose", "blog", "page",
];

/// Class/id prior in permille: 0 when a boilerplate token occurs, 1000 for a content token,
/// otherwise neutral. Tokens are whole alphanumeric words, never substrings.
fn class_weight(e: &Elem) -> u64 {
    let mut positive = false;
    for name in ["class", "id"] {
        let Some(value) = e.attr(name) else {
            continue;
        };
        for token in value
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
        {
            let token = token.to_ascii_lowercase();
            if NEGATIVE_TOKENS.contains(&token.as_str()) {
                return 0;
            }
            if POSITIVE_TOKENS.contains(&token.as_str()) {
                positive = true;
            }
        }
    }
    if matches!(
        e.role().as_deref(),
        Some("navigation" | "banner" | "contentinfo" | "complementary" | "search")
    ) {
        return 0;
    }
    if positive {
        1_000
    } else {
        500
    }
}

/// Tag prior in permille.
fn tag_weight(tag: &str) -> u64 {
    match tag {
        "article" | "main" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => 1_000,
        "p" | "pre" | "blockquote" => 800,
        "section" | "figure" | "li" | "dd" => 700,
        "ul" | "ol" | "dl" | "div" | "td" | "th" | "tr" | "tbody" => 500,
        "table" => 400,
        "header" | "aside" | "form" => 100,
        "nav" | "footer" => 0,
        _ => 500,
    }
}

fn pruning_score(e: &Elem, m: &Metrics) -> u64 {
    let text = m.text_chars;
    let density = text * 1_000 / (text + TAG_COST * m.tags.max(1));
    let link_part = 1_000 - (m.link_chars * 1_000 / text.max(1)).min(1_000);
    let length = (text * 1_000 / LENGTH_SATURATION).min(1_000);
    (W_DENSITY * density
        + W_LINK * link_part
        + W_TAG * tag_weight(&e.tag)
        + W_CLASS * class_weight(e)
        + W_LENGTH * length)
        / 1_000
}

trait Judge {
    /// Drop a whole container before descending into it.
    fn veto(&mut self, e: &Elem, budget: &mut Budget) -> Result<bool, FilterError>;
    /// Keep or drop a leaf block.
    fn keep_leaf(&mut self, e: &Elem, budget: &mut Budget) -> Result<bool, FilterError>;
}

struct Pruning<'a> {
    params: &'a PruningParams,
}

impl Judge for Pruning<'_> {
    fn veto(&mut self, e: &Elem, budget: &mut Budget) -> Result<bool, FilterError> {
        let hinted = matches!(e.tag.as_str(), "nav" | "footer" | "aside") || class_weight(e) == 0;
        if !hinted {
            return Ok(false);
        }
        let m = metrics_of(e, budget)?;
        Ok(m.text_chars == 0 || pruning_score(e, &m) < u64::from(self.params.threshold_permille))
    }

    fn keep_leaf(&mut self, e: &Elem, budget: &mut Budget) -> Result<bool, FilterError> {
        let m = metrics_of(e, budget)?;
        if m.words < u64::from(self.params.min_words) {
            return Ok(false);
        }
        if m.text_chars == 0 {
            return Ok(m.media && class_weight(e) > 0 && !matches!(e.tag.as_str(), "nav" | "footer"));
        }
        Ok(pruning_score(e, &m) >= u64::from(self.params.threshold_permille))
    }
}

/// First BM25 pass: keeps every leaf and records its tokens.
struct Bm25Collect<'a> {
    tokenizer: &'a Tokenizer,
    chunks: Vec<Vec<String>>,
    words: Vec<u64>,
}

impl Judge for Bm25Collect<'_> {
    fn veto(&mut self, _: &Elem, _: &mut Budget) -> Result<bool, FilterError> {
        Ok(false)
    }

    fn keep_leaf(&mut self, e: &Elem, budget: &mut Budget) -> Result<bool, FilterError> {
        let mut text = String::new();
        leaf_text(e, &mut text, budget)?;
        let tokens = self.tokenizer.tokens(&text);
        budget.charge(wide(tokens.len()) + wide(text.len()) / 64)?;
        self.words.push(wide(text.split_whitespace().count()));
        self.chunks.push(tokens);
        Ok(true)
    }
}

/// Second BM25 pass: replays the decisions in the same visiting order.
struct Replay {
    decisions: Vec<bool>,
    cursor: usize,
}

impl Judge for Replay {
    fn veto(&mut self, _: &Elem, _: &mut Budget) -> Result<bool, FilterError> {
        Ok(false)
    }

    fn keep_leaf(&mut self, _: &Elem, _: &mut Budget) -> Result<bool, FilterError> {
        let keep = self.decisions.get(self.cursor).copied().unwrap_or(false);
        self.cursor += 1;
        Ok(keep)
    }
}

struct Walker<'j> {
    judge: &'j mut dyn Judge,
    budget: Budget,
    kept: usize,
    dropped: usize,
}

impl Walker<'_> {
    fn node(&mut self, n: &Node) -> Result<Option<Node>, FilterError> {
        match n {
            Node::Text(t) => Ok(Some(Node::Text(t.clone()))),
            Node::Elem(e) => Ok(self.elem(e)?.map(Node::Elem)),
        }
    }

    fn leaf(&mut self, e: &Elem) -> Result<Option<Elem>, FilterError> {
        if self.judge.keep_leaf(e, &mut self.budget)? {
            self.kept += 1;
            Ok(Some(e.clone()))
        } else {
            self.dropped += 1;
            Ok(None)
        }
    }

    fn elem(&mut self, e: &Elem) -> Result<Option<Elem>, FilterError> {
        self.budget.charge(1)?;
        match class_of(e, &mut self.budget)? {
            Class::Inline => Ok(Some(e.clone())),
            Class::Atomic => self.leaf(e),
            Class::Container => {
                if self.judge.veto(e, &mut self.budget)? {
                    self.dropped += 1;
                    return Ok(None);
                }
                let mut has_block = false;
                for child in e.child_elems() {
                    self.budget.charge(1)?;
                    if class_of(child, &mut self.budget)? != Class::Inline
                        || contains_block(child, &mut self.budget)?
                    {
                        has_block = true;
                        break;
                    }
                }
                if !has_block {
                    return self.leaf(e);
                }
                let mut out = Elem::new(&e.tag);
                out.attrs.clone_from(&e.attrs);
                out.stats = e.stats;
                out.has_main = e.has_main;
                out.matched = e.matched;
                let mut survivor = false;
                for child in &e.children {
                    match child {
                        Node::Elem(c) if class_of(c, &mut self.budget)? != Class::Inline => {
                            if let Some(kept) = self.elem(c)? {
                                survivor = true;
                                out.children.push(Node::Elem(kept));
                            }
                        }
                        other => out.children.push(other.clone()),
                    }
                }
                Ok(survivor.then_some(out))
            }
        }
    }

    fn nodes(&mut self, nodes: &[Node]) -> Result<Vec<Node>, FilterError> {
        let mut out = Vec::new();
        for n in nodes {
            if let Some(kept) = self.node(n)? {
                out.push(kept);
            }
        }
        Ok(out)
    }
}

/// Run `filter` over the content `nodes`.
///
/// # Errors
/// [`FilterError::InvalidParams`] for bad parameters (an empty BM25 query included) and
/// [`FilterError::Budget`] when the operation budget is spent.
pub fn apply(nodes: &[Node], filter: &FitFilter) -> Result<FitOutcome, FilterError> {
    filter.validate()?;
    match filter {
        FitFilter::Pruning(params) => {
            let mut judge = Pruning { params };
            let mut walker = Walker {
                judge: &mut judge,
                budget: Budget {
                    used: 0,
                    limit: params.max_operations,
                },
                kept: 0,
                dropped: 0,
            };
            let out = walker.nodes(nodes)?;
            Ok(FitOutcome {
                nodes: out,
                report: FitReport {
                    strategy: PRUNING_STRATEGY_ID.to_owned(),
                    kept_blocks: walker.kept,
                    dropped_blocks: walker.dropped,
                    operations: walker.budget.used,
                },
            })
        }
        FitFilter::Bm25(params) => {
            let tokenizer = Tokenizer::new();
            let terms = tokenizer.query_terms(&params.query);
            if terms.is_empty() {
                return Err(FilterError::InvalidParams {
                    name: "query",
                    reason: "has no scoring terms",
                });
            }
            let mut collect = Bm25Collect {
                tokenizer: &tokenizer,
                chunks: Vec::new(),
                words: Vec::new(),
            };
            let mut first = Walker {
                judge: &mut collect,
                budget: Budget {
                    used: 0,
                    limit: params.max_operations,
                },
                kept: 0,
                dropped: 0,
            };
            first.nodes(nodes)?;
            let budget = first.budget;
            let corpus = Corpus::new(&collect.chunks);
            let scoring = bm25::Params {
                k1_milli: params.k1_milli,
                b_milli: params.b_milli,
            };
            let decisions: Vec<bool> = (0..corpus.len())
                .map(|i| {
                    corpus.score_milli(i, &terms, scoring) >= u64::from(params.threshold_milli)
                        && collect.words[i] >= u64::from(params.min_words)
                })
                .collect();
            let mut replay = Replay { decisions, cursor: 0 };
            let mut second = Walker {
                judge: &mut replay,
                budget,
                kept: 0,
                dropped: 0,
            };
            let out = second.nodes(nodes)?;
            Ok(FitOutcome {
                nodes: out,
                report: FitReport {
                    strategy: BM25_STRATEGY_ID.to_owned(),
                    kept_blocks: second.kept,
                    dropped_blocks: second.dropped,
                    operations: second.budget.used,
                },
            })
        }
    }
}
