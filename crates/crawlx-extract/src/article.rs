//! Native, independently authored article selectors.
//!
//! Paragraph classification, integer parent/grandparent gravity and density share
//! one annotated owned tree. Candidates contain block indices, never DOM copies.
//! These rules do not claim parity with other extractors.

use crate::{
    dom::{Elem, Node},
    readability, text,
};
use crawlx_core::extraction::{
    ArticleAlgorithmV1, CommentPolicyV1, ContentBlockV1, ContentFallbackV1, ContentFocusV1,
    ExtractionPolicyV1, SourceRangeV1,
};
use std::collections::BTreeSet;

struct Block {
    id: usize,
    parent: usize,
    grandparent: usize,
    main: bool,
    comment: bool,
    chrome: bool,
    chars: usize,
    links: usize,
    punctuation: usize,
    stopwords: usize,
    heading: bool,
    fingerprint: crawlx_core::hash::Digest,
    complete: bool,
}
/// Selection owns only winning content; alternatives borrow block indices.
pub(crate) struct ArticleSelection {
    pub nodes: Vec<Node>,
    pub comments: Vec<Node>,
    pub main_ids: Vec<usize>,
    pub comment_ids: Vec<usize>,
    pub strategy: &'static str,
    pub fallback_stages: u8,
    pub operations: usize,
    pub partial: bool,
}
fn hint(e: &Elem, words: &[&str]) -> bool {
    [e.attr("class"), e.attr("id")].into_iter().flatten().any(|s| {
        s.split(|c: char| !c.is_alphanumeric())
            .any(|token| words.iter().any(|word| token.eq_ignore_ascii_case(word)))
    })
}
fn terminal(e: &Elem) -> bool {
    matches!(
        e.tag.as_str(),
        "p" | "pre" | "blockquote" | "table" | "figure" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6"
    ) || (!e.child_elems().any(|c| {
        matches!(
            c.tag.as_str(),
            "div"
                | "section"
                | "article"
                | "main"
                | "p"
                | "pre"
                | "blockquote"
                | "table"
                | "ul"
                | "ol"
                | "li"
                | "h1"
                | "h2"
                | "h3"
                | "h4"
                | "h5"
                | "h6"
        )
    }) && matches!(
        e.tag.as_str(),
        "div" | "section" | "article" | "main" | "li" | "body"
    ))
}
/// Small authored English function-word list, not a downloaded language dictionary.
pub(crate) fn english_stopword(token: &str) -> bool {
    [
        "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "in", "is", "it", "of", "on",
        "or", "that", "the", "their", "this", "to", "was", "were", "will", "with",
    ]
    .iter()
    .any(|word| token.eq_ignore_ascii_case(word))
}
#[derive(Clone, Copy, Default)]
struct Context {
    parent: usize,
    grandparent: usize,
    main: bool,
    comment: bool,
    chrome: bool,
    terminal: bool,
}
struct Scan<'a> {
    blocks: Vec<Block>,
    next: usize,
    operations: usize,
    partial: bool,
    forum: bool,
    policy: &'a ExtractionPolicyV1,
}
impl Scan<'_> {
    fn visit(&mut self, e: &Elem, ctx: Context) {
        if self.operations >= self.policy.max_operations {
            self.partial = true;
            return;
        }
        self.operations = self.operations.saturating_add(1);
        let id = self.next;
        self.next = self.next.saturating_add(1);
        let main = ctx.main
            || matches!(e.tag.as_str(), "main" | "article")
            || e.attr("role") == Some("main")
            || hint(e, &["content", "story", "entry", "post"]);
        let comment = !self.forum && (ctx.comment || hint(e, &["comment", "comments", "replies", "disqus"]));
        let chrome = ctx.chrome
            || matches!(e.tag.as_str(), "nav" | "aside" | "footer" | "dialog")
            || hint(
                e,
                &[
                    "sidebar",
                    "navigation",
                    "advert",
                    "advertisement",
                    "related",
                    "recommended",
                    "cookie",
                    "subscribe",
                    "share",
                ],
            )
            || (e.tag == "header" && !main);
        let is_terminal = terminal(e);
        if !ctx.terminal && is_terminal {
            if self.blocks.len() >= self.policy.max_blocks {
                self.partial = true;
                return;
            }
            let value = text::element_text(e);
            let chars = value.chars().count();
            if self.operations.saturating_add(chars) > self.policy.max_operations {
                self.partial = true;
                return;
            }
            self.operations = self.operations.saturating_add(chars);
            self.blocks.push(Block {
                id,
                parent: ctx.parent,
                grandparent: ctx.grandparent,
                main,
                comment,
                chrome,
                chars,
                links: e.stats.link_len,
                punctuation: value
                    .chars()
                    .filter(|c| matches!(c, '.' | '!' | '?' | '。' | '！' | '？' | ',' | '，'))
                    .count(),
                stopwords: value
                    .split(|c: char| !c.is_alphanumeric())
                    .filter(|t| english_stopword(t))
                    .count(),
                fingerprint: crawlx_core::hash::Digest::of("crawlx.extract.block.v1", value.as_bytes()),
                complete: value
                    .trim_end_matches(['"', '\'', '”', '’', ')', ']'])
                    .ends_with(['.', '!', '?', '。', '！', '？']),
                heading: matches!(e.tag.as_str(), "h1" | "h2" | "h3" | "h4" | "h5" | "h6"),
            });
        }
        for child in e.child_elems() {
            self.visit(
                child,
                Context {
                    parent: id,
                    grandparent: ctx.parent,
                    main,
                    comment,
                    chrome,
                    terminal: ctx.terminal || is_terminal,
                },
            );
        }
    }
}
fn good(b: &Block, focus: ContentFocusV1) -> bool {
    let threshold = if focus == ContentFocusV1::Precision {
        80
    } else if focus == ContentFocusV1::Recall {
        20
    } else {
        40
    };
    !b.chrome
        && !b.comment
        && b.links.saturating_mul(4) <= b.chars.max(1)
        && ((b.main && (b.chars >= 20 || b.heading))
            || (b.chars >= threshold && (b.punctuation > 0 || b.stopwords >= 3)))
}
fn utility(candidate: &[usize], blocks: &[Block]) -> usize {
    let mut seen = BTreeSet::new();
    candidate.iter().fold(0usize, |score, &index| {
        let b = &blocks[index];
        let value = b
            .chars
            .saturating_sub(b.links)
            .min(1000)
            .saturating_add(b.punctuation.saturating_mul(16).min(256))
            .saturating_add(if b.main { 128 } else { 0 })
            .saturating_add(if b.complete { 32 } else { 0 });
        let ambiguity = if b.main || b.heading { 0 } else { 96 };
        let repeated = if seen.insert(b.fingerprint) {
            0
        } else {
            b.chars.saturating_mul(4).saturating_add(256)
        };
        score
            .saturating_add(value)
            .saturating_sub(ambiguity)
            .saturating_sub(repeated)
    })
}
fn candidates(blocks: &[Block], node_count: usize, focus: ContentFocusV1) -> [Vec<usize>; 3] {
    let mut rules: Vec<usize> = blocks
        .iter()
        .enumerate()
        .filter_map(|(i, b)| good(b, focus).then_some(i))
        .collect();
    // Short paragraph between two good paragraphs is retained only outside precision.
    if focus != ContentFocusV1::Precision {
        for i in 1..blocks.len().saturating_sub(1) {
            let b = &blocks[i];
            if !b.chrome
                && !b.comment
                && b.chars > 0
                && b.links == 0
                && good(&blocks[i - 1], focus)
                && good(&blocks[i + 1], focus)
                && blocks[i - 1].parent == b.parent
                && blocks[i + 1].parent == b.parent
            {
                rules.push(i);
            }
        }
        rules.sort_unstable();
        rules.dedup();
    }
    let mut gravity = vec![0usize; node_count];
    for b in blocks.iter().filter(|b| good(b, focus) && !b.heading) {
        let score = b
            .stopwords
            .saturating_mul(16)
            .saturating_add(b.punctuation.saturating_mul(8))
            .saturating_add(b.chars.min(1000) / 10)
            .saturating_add(if b.main { 128 } else { 0 });
        gravity[b.parent] = gravity[b.parent].saturating_add(score.saturating_mul(2));
        gravity[b.grandparent] = gravity[b.grandparent].saturating_add(score);
    }
    // Strict greater preserves preorder ties.
    let mut best = 0usize;
    for i in 1..gravity.len() {
        if gravity[i] > gravity[best] {
            best = i;
        }
    }
    let gravity_blocks = blocks
        .iter()
        .enumerate()
        .filter_map(|(i, b)| {
            (good(b, focus) && (b.parent == best || b.grandparent == best || b.main)).then_some(i)
        })
        .collect();
    // Density reuses annotate's non-anchor character/comma counts, without float decisions.
    let mut density = vec![0usize; node_count];
    for b in blocks.iter().filter(|b| !b.chrome && !b.comment) {
        let score = b.chars.saturating_sub(b.links.saturating_mul(2));
        density[b.parent] = density[b.parent].saturating_add(score);
    }
    let mut dense = 0usize;
    for i in 1..density.len() {
        if density[i] > density[dense] {
            dense = i;
        }
    }
    let density_blocks = blocks
        .iter()
        .enumerate()
        .filter_map(|(i, b)| {
            (!b.chrome
                && !b.comment
                && b.chars > 0
                && b.links.saturating_mul(2) < b.chars
                && (b.parent == dense || b.main))
                .then_some(i)
        })
        .collect();
    [rules, gravity_blocks, density_blocks]
}
fn subtree_elements(e: &Elem) -> usize {
    1usize.saturating_add(
        e.child_elems()
            .map(subtree_elements)
            .fold(0usize, usize::saturating_add),
    )
}
fn take(
    e: Elem,
    next: &mut usize,
    selected: &BTreeSet<usize>,
    comments: &BTreeSet<usize>,
    main: &mut Vec<Node>,
    discussion: &mut Vec<Node>,
) {
    let id = *next;
    *next = next.saturating_add(1);
    if selected.contains(&id) || comments.contains(&id) {
        *next = next.saturating_add(subtree_elements(&e).saturating_sub(1));
        if selected.contains(&id) {
            main.push(Node::Elem(e));
        } else {
            discussion.push(Node::Elem(e));
        }
        return;
    }
    for node in e.children {
        if let Node::Elem(child) = node {
            take(child, next, selected, comments, main, discussion);
        }
    }
}
fn trim_media(e: &mut Elem, policy: &ExtractionPolicyV1) {
    e.children.retain_mut(|node| match node {
        Node::Text(_) => true,
        Node::Elem(child) => {
            if (!policy.tables && child.tag == "table") || (!policy.images && child.tag == "img") {
                false
            } else {
                trim_media(child, policy);
                true
            }
        }
    });
}
fn charge_tree(e: &Elem, operations: &mut usize, limit: usize) -> bool {
    *operations = operations.saturating_add(1);
    if *operations > limit {
        return false;
    }
    e.children.iter().all(|node| match node {
        Node::Text(value) => {
            for _ in value.chars() {
                *operations = operations.saturating_add(1);
                if *operations > limit {
                    return false;
                }
            }
            true
        }
        Node::Elem(child) => charge_tree(child, operations, limit),
    })
}
fn exhausted(operations: usize) -> ArticleSelection {
    ArticleSelection {
        nodes: Vec::new(),
        comments: Vec::new(),
        main_ids: Vec::new(),
        comment_ids: Vec::new(),
        strategy: "resource_limit_v1",
        fallback_stages: 0,
        operations,
        partial: true,
    }
}
struct WholePartition<'a> {
    next: usize,
    comments: Vec<Node>,
    ids: Vec<usize>,
    comment_chars: usize,
    partial: bool,
    forum: bool,
    policy: &'a ExtractionPolicyV1,
}
impl WholePartition<'_> {
    fn visit(&mut self, element: &mut Elem) {
        self.next = self.next.saturating_add(1);
        element.children.retain_mut(|node| {
            let Node::Elem(child) = node else {
                return true;
            };
            if !self.forum && hint(child, &["comment", "comments", "replies", "disqus"]) {
                let id = self.next;
                self.next = self.next.saturating_add(subtree_elements(child));
                if self.policy.comments == CommentPolicyV1::Separate {
                    let chars = text::element_text(child).chars().count().saturating_add(2);
                    if self.comment_chars.saturating_add(chars) <= self.policy.max_output_chars
                        && self.comments.len().saturating_add(1) < self.policy.max_blocks
                    {
                        self.comment_chars = self.comment_chars.saturating_add(chars);
                        self.ids.push(id);
                        self.comments
                            .push(std::mem::replace(node, Node::Text(String::new())));
                    } else {
                        self.partial = true;
                    }
                }
                false
            } else {
                self.visit(child);
                true
            }
        });
    }
}
fn whole_body(
    mut body: Elem,
    policy: &ExtractionPolicyV1,
    forum: bool,
    operations: usize,
) -> ArticleSelection {
    let mut partition = WholePartition {
        next: 0,
        comments: Vec::new(),
        ids: Vec::new(),
        comment_chars: 0,
        partial: false,
        forum,
        policy,
    };
    partition.visit(&mut body);
    let chars = text::element_text(&body).chars().count();
    let fits = chars <= policy.max_output_chars;
    ArticleSelection {
        nodes: if fits { vec![Node::Elem(body)] } else { Vec::new() },
        main_ids: if fits { vec![0] } else { Vec::new() },
        comments: partition.comments,
        comment_ids: partition.ids,
        strategy: "whole_filtered_body_v1",
        fallback_stages: 0,
        operations,
        partial: partition.partial || !fits,
    }
}

/// Select once, then move winning block subtrees into renderers.
pub(crate) fn select(
    mut body: Elem,
    policy: &ExtractionPolicyV1,
    forum: bool,
    whole: bool,
) -> ArticleSelection {
    let mut operations = 0;
    if !charge_tree(&body, &mut operations, policy.max_operations) {
        return exhausted(policy.max_operations);
    }
    trim_media(&mut body, policy);
    if whole {
        return whole_body(body, policy, forum, operations);
    }
    readability::annotate(&mut body);
    let mut scan = Scan {
        blocks: Vec::new(),
        next: 0,
        operations,
        partial: false,
        forum,
        policy,
    };
    scan.visit(&body, Context::default());
    // A stopped scan does not have a complete preorder index. Never attach mismatched
    // source IDs to later siblings or pretend the incomplete block set is accepted.
    if scan.partial {
        return exhausted(scan.operations.min(policy.max_operations));
    }
    let choices = candidates(&scan.blocks, scan.next.max(1), policy.focus);
    let mut choice = if policy.algorithm == ArticleAlgorithmV1::ArticleGravityV1 {
        1
    } else if policy.algorithm == ArticleAlgorithmV1::ArticleDensityV1 {
        2
    } else {
        0
    };
    if policy.algorithm == ArticleAlgorithmV1::ArticleEnsembleV1 {
        let utilities = choices
            .each_ref()
            .map(|candidate| utility(candidate, &scan.blocks));
        for i in 1..choices.len() {
            if utilities[i] > utilities[choice] {
                choice = i;
            }
        }
    }
    let mut chosen = choices[choice].clone(); // Compact block indices, never content/DOM.
    let mut fallback_stages = 0;
    let mut strategy = ["article_rules_v1", "article_gravity_v1", "article_density_v1"][choice];
    if chosen.is_empty() && policy.fallback == ContentFallbackV1::Bounded && !scan.partial {
        fallback_stages = 1;
        strategy = "bounded_block_rescue_v1";
        chosen = scan
            .blocks
            .iter()
            .enumerate()
            .filter_map(|(i, b)| {
                (!b.chrome && !b.comment && b.chars > 0 && b.links.saturating_mul(2) < b.chars).then_some(i)
            })
            .collect();
    }
    let mut partial = scan.partial;
    let mut chars = 0usize;
    chosen.retain(|&i| {
        let b = &scan.blocks[i];
        let count = b.chars.saturating_add(if chars == 0 { 0 } else { 2 });
        if chars.saturating_add(count) > policy.max_output_chars {
            partial = true;
            false
        } else {
            chars = chars.saturating_add(count);
            true
        }
    });
    let main_ids: Vec<usize> = chosen.iter().map(|&i| scan.blocks[i].id).collect();
    let mut comment_chars = 0usize;
    let comment_ids: Vec<usize> = scan
        .blocks
        .iter()
        .filter(|b| b.comment && !b.chrome && policy.comments == CommentPolicyV1::Separate)
        .filter_map(|b| {
            comment_chars = comment_chars.saturating_add(b.chars).saturating_add(2);
            if comment_chars <= policy.max_output_chars {
                Some(b.id)
            } else {
                partial = true;
                None
            }
        })
        .collect();
    let selected = main_ids.iter().copied().collect();
    let comments = comment_ids.iter().copied().collect();
    let mut nodes = Vec::with_capacity(main_ids.len());
    let mut discussion = Vec::with_capacity(comment_ids.len());
    take(body, &mut 0, &selected, &comments, &mut nodes, &mut discussion);
    ArticleSelection {
        nodes,
        comments: discussion,
        main_ids,
        comment_ids,
        strategy,
        fallback_stages,
        operations: scan.operations,
        partial,
    }
}
/// Locate each retained block in its actual normalized rendering, not HTML byte positions.
pub(crate) fn source_blocks(
    nodes: &[Node],
    ids: &[usize],
    rendered: &str,
    comment: bool,
) -> Vec<ContentBlockV1> {
    let mut cursor = 0usize;
    nodes
        .iter()
        .zip(ids)
        .filter_map(|(node, &id)| {
            let block = text::to_text(std::slice::from_ref(node));
            if block.is_empty() {
                return None;
            }
            let relative = rendered.get(cursor..)?.find(&block)?;
            let start = cursor.saturating_add(relative);
            cursor = start.saturating_add(block.len());
            Some(ContentBlockV1::new(
                id,
                SourceRangeV1::new(start, cursor),
                comment,
            ))
        })
        .collect()
}

/// Change only the selected rendering tree, after canonical text and source ranges
/// are fixed. Keep original DOM discovery and article scoring independent of output.
pub(crate) fn apply_render_policy(nodes: &mut [Node], policy: &ExtractionPolicyV1) {
    if policy.links && policy.formatting {
        return;
    }
    for node in nodes {
        let Node::Elem(element) = node else { continue };
        if (!policy.links && element.tag == "a")
            || (!policy.formatting
                && matches!(
                    element.tag.as_str(),
                    "b" | "strong"
                        | "em"
                        | "i"
                        | "u"
                        | "s"
                        | "strike"
                        | "del"
                        | "code"
                        | "kbd"
                        | "samp"
                        | "tt"
                        | "var"
                        | "sub"
                        | "sup"
                        | "mark"
                        | "q"
                        | "cite"
                        | "dfn"
                        | "small"
                        | "big"
                ))
        {
            element.tag.clear();
            element.tag.push_str("span");
            element
                .attrs
                .retain(|(name, _)| matches!(name.as_str(), "lang" | "dir"));
        }
        apply_render_policy(&mut element.children, policy);
    }
}
