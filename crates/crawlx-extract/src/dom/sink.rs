//! Fallible HTML tree construction.
//!
//! `scraper` builds its tree through `html5ever`'s [`TreeSink`], whose methods return handles
//! and so cannot fail. [`parse_document`] and [`parse_fragment`] therefore run the parser over a
//! *metering* sink that wraps `scraper`'s own sink (same tree, same result, no copied parser
//! logic) and charges every allocation it can see against a [`ParseCharge`] **before** it
//! happens:
//!
//! * node storage is reserved in geometric steps with `Tree::try_reserve_exact` (the vendored
//!   `ego-tree` patch), charged for the new capacity including the slack and for the old and new
//!   buffers that coexist while the storage grows, so an allocation failure is a value here;
//! * every element, attribute, text, comment, doctype and processing-instruction payload, every
//!   merge into an existing text node and every recorded parse error is charged first;
//! * the tokenizer and tree-builder state that the sink never sees (token strings, the open
//!   element stack, the input copy) is charged up front and per element from a model that
//!   `tests/parse_memory_ceiling.rs` checks against the measured peak heap.
//!
//! The charge is *prepaid*: the sink spends the bytes `parse_budget::charge` already reserved
//! for the input. Only when the model needs more does it grow the reservation from the same
//! process-wide budget, and that growth, not an abort, is what fails. A failed charge poisons
//! the sink: it stops building (new handles all name one detached sentinel element, every
//! mutation is skipped), the input is no longer fed once the failure is seen, and the partial
//! tree is dropped with the parser. The caller receives [`ParseBudgetExhausted`] and nothing
//! else; the reservation grown during the failed parse is released at once.
//!
//! Input is fed in [`CHUNK_BYTES`] pieces so a failure stops the parse after at most one
//! chunk of further work. Chunking does not change the tree (`html5ever` is a streaming
//! parser); the unit tests compare the result with `Html::parse_document` at chunk sizes down
//! to one byte. A chunk boundary inside a text run can split one entry of `Html::errors` (the
//! parser's diagnostics, which nothing in this crate reads) into several.

use std::borrow::Cow;
use std::cell::{Cell, Ref, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use crawlx_core::parser_memory::BytePermit;
use ego_tree::{NodeId, Tree};
use html5ever::driver::{self, ParseOpts};
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::tree_builder::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::{local_name, ns, Attribute, LocalName, QualName};
use scraper::{Html, HtmlTreeSink};

use crate::parse_budget::{ParseBudget, ParseBudgetExhausted, ParseCharge};

/// Bytes of input handed to the parser per call; a refusal is noticed after the current chunk.
pub const CHUNK_BYTES: usize = 64 * 1024;

/// Bytes of one stored tree node (links plus `scraper::Node`), the unit of storage growth.
const NODE_BYTES: usize = Tree::<scraper::Node>::node_size();
/// Fewest node slots reserved by one growth step.
const MIN_GROW_SLOTS: usize = 32;
/// Smallest growth of the reservation past the prepaid bytes, to avoid one atomic per node.
const GROW_STEP: usize = 16 * 1024;
/// Tendril payloads up to this many bytes live inline and own no heap.
const TENDRIL_INLINE: usize = 8;
/// Heap header and rounding of one out-of-line tendril.
const TENDRIL_OVERHEAD: usize = 32;
/// Interner entry of an atom that is neither static nor short enough to be stored inline.
const ATOM_ENTRY: usize = 48;
/// Copies of one attribute's slot alive at once while it is parsed and stored.
const ATTRIBUTE_COPIES: usize = 3;
/// Longest atom stored inline.
const ATOM_INLINE: usize = 7;
/// Open-element stack and active-formatting list entries one element can occupy, with slack.
const BUILDER_PER_ELEMENT: usize = 4 * std::mem::size_of::<usize>();
/// One recorded parse error: the `Cow` slot with vector slack.
const ERROR_ENTRY: usize = 2 * std::mem::size_of::<Cow<'static, str>>();
/// Fixed per-parse allowance for tokenizer and tree-builder state.
const FIXED_BYTES: usize = 4096;
/// Bytes of tokenizer and input-copy state per input byte: one copy of the input in the chunk
/// buffers that text nodes may keep alive, and up to two token strings (a tag or attribute
/// value being accumulated and its emitted copy).
const INPUT_FACTOR: usize = 3;

/// The result of a refused or failed allocation reservation.
fn exhausted(requested: usize, budget: &ParseBudget) -> ParseBudgetExhausted {
    ParseBudgetExhausted {
        requested,
        available: budget.available(),
        limit: budget.limit(),
    }
}

/// Prepaid allowance, growth permit and failure record of one parse.
struct State {
    budget: Arc<ParseBudget>,
    /// Prepaid bytes not yet spent.
    allowance: usize,
    /// Bytes charged so far (the model's estimate of live parse heap).
    spent: usize,
    /// Highest `spent` plus the buffers that coexisted with it while node storage grew: the
    /// model's estimate of the peak live parse heap.
    peak: usize,
    /// Reservation grown past the prepaid bytes; zero bytes until the model overspends.
    extra: BytePermit,
    failure: Option<ParseBudgetExhausted>,
}

impl State {
    fn fail(&mut self, wanted: usize) {
        self.failure
            .get_or_insert_with(|| exhausted(self.spent.saturating_add(wanted), &self.budget));
    }

    /// Spend `bytes`, which must stay allocatable while a further `transient` bytes coexist.
    fn charge(&mut self, bytes: usize, transient: usize) -> bool {
        if self.failure.is_some() {
            return false;
        }
        let Some(peak) = bytes.checked_add(transient) else {
            self.fail(usize::MAX);
            return false;
        };
        if self.allowance < peak {
            let shortfall = peak - self.allowance;
            if !self.top_up(shortfall) {
                self.fail(peak);
                return false;
            }
        }
        self.allowance -= bytes;
        self.spent = self.spent.saturating_add(bytes);
        self.peak = self.peak.max(self.spent.saturating_add(transient));
        true
    }

    /// Grow the reservation by at least `shortfall` bytes from the shared budget.
    fn top_up(&mut self, shortfall: usize) -> bool {
        let step = shortfall.max(GROW_STEP);
        let grown = if self.extra.grow_by(step).is_ok() {
            step
        } else if self.extra.grow_by(shortfall).is_ok() {
            shortfall
        } else {
            return false;
        };
        self.allowance = self.allowance.saturating_add(grown);
        true
    }
}

/// Shared between the sink and the driver loop; single-threaded, like the parser.
struct Ledger {
    state: RefCell<State>,
}

impl Ledger {
    fn charge(&self, bytes: usize) -> bool {
        self.state.borrow_mut().charge(bytes, 0)
    }

    fn failed(&self) -> bool {
        self.state.borrow().failure.is_some()
    }

    fn take_failure(&self) -> Option<ParseBudgetExhausted> {
        self.state.borrow().failure
    }
}

fn tendril_heap(len: usize) -> usize {
    if len <= TENDRIL_INLINE {
        0
    } else {
        len.saturating_add(TENDRIL_OVERHEAD)
    }
}

fn atom_heap(atom: &LocalName) -> usize {
    if atom.is_static() || atom.len() <= ATOM_INLINE {
        0
    } else {
        ATOM_ENTRY.saturating_add(atom.len())
    }
}

fn attribute_heap(attribute: &Attribute) -> usize {
    // the tokenizer's attribute vector, the element's vector and the clone the tree builder keeps
    // for formatting elements coexist
    ATTRIBUTE_COPIES
        .saturating_mul(std::mem::size_of::<Attribute>())
        .saturating_add(tendril_heap(attribute.value.len()))
        .saturating_add(atom_heap(&attribute.name.local))
}

/// Reserve room for `n` more nodes, charging the growth and its transient peak first.
fn reserve_slots(inner: &HtmlTreeSink, ledger: &Ledger, n: usize) -> bool {
    let mut html = inner.0.borrow_mut();
    let (len, capacity) = (html.tree.len(), html.tree.capacity());
    // one slot stays spare so the sentinel can be created after a failure without allocating
    if len.saturating_add(n).saturating_add(1) <= capacity {
        return true;
    }
    let grow = n.saturating_add(1).max(len).max(MIN_GROW_SLOTS);
    let steady = grow.saturating_mul(NODE_BYTES);
    let transient = capacity.saturating_mul(NODE_BYTES);
    let mut state = ledger.state.borrow_mut();
    if !state.charge(steady, transient) {
        return false;
    }
    if html.tree.try_reserve_exact(grow).is_err() {
        // the allocator refused storage the budget had admitted: no budget share is missing, the
        // process itself cannot hold this tree, so the refusal exceeds every budget
        state.fail(usize::MAX);
        return false;
    }
    true
}

/// A [`TreeSink`] that charges before it allocates and stops building once a charge fails.
struct MeteredSink {
    inner: HtmlTreeSink,
    ledger: Rc<Ledger>,
    /// Detached element every handle created after a failure refers to, so the tree builder
    /// keeps running on valid handles while nothing more is stored. Created on the first
    /// failure in the slot [`reserve_slots`] keeps spare, so it allocates nothing and a parse
    /// that succeeds never contains it.
    sentinel: Cell<Option<NodeId>>,
}

impl MeteredSink {
    fn new(inner: HtmlTreeSink, ledger: Rc<Ledger>) -> Result<Self, ParseBudgetExhausted> {
        if !reserve_slots(&inner, &ledger, 1) {
            return Err(ledger
                .take_failure()
                .unwrap_or_else(|| exhausted(0, &ledger.state.borrow().budget)));
        }
        Ok(Self {
            inner,
            ledger,
            sentinel: Cell::new(None),
        })
    }

    fn sentinel(&self) -> NodeId {
        if let Some(id) = self.sentinel.get() {
            return id;
        }
        let name = QualName::new(None, ns!(html), local_name!("div"));
        let id = self
            .inner
            .create_element(name, Vec::new(), ElementFlags::default());
        self.sentinel.set(Some(id));
        id
    }

    /// Charge `bytes`, then make room for `slots` nodes; `false` once the parse has failed.
    fn admit(&self, bytes: usize, slots: usize) -> bool {
        self.ledger.charge(bytes) && reserve_slots(&self.inner, &self.ledger, slots)
    }

    fn poisoned(&self) -> bool {
        self.ledger.failed()
    }

    /// Charge a text append: new storage when the text starts a node, doubled capacity when it
    /// is merged into the previous one.
    fn admit_text(&self, text: &StrTendril) -> bool {
        let bytes = text.len().saturating_mul(2).saturating_add(TENDRIL_OVERHEAD);
        self.admit(bytes, 1)
    }

    fn admit_child(&self, child: &NodeOrText<NodeId>) -> bool {
        match child {
            NodeOrText::AppendText(text) => self.admit_text(text),
            // once the parse has failed every handle is the sentinel: storing an append would
            // attach it to itself
            NodeOrText::AppendNode(_) => !self.poisoned(),
        }
    }
}

/// Heap bytes of an element and its attributes, with the builder entries it may occupy.
fn element_heap(name: &QualName, attrs: &[Attribute], template: bool) -> usize {
    let attribute_bytes = attrs.iter().fold(0usize, |sum, attribute| {
        sum.saturating_add(attribute_heap(attribute))
    });
    atom_heap(&name.local)
        .saturating_add(attribute_bytes)
        .saturating_add(BUILDER_PER_ELEMENT)
        .saturating_add(if template { NODE_BYTES } else { 0 })
}

impl TreeSink for MeteredSink {
    type Output = Html;
    type Handle = NodeId;
    type ElemName<'a> = Ref<'a, QualName>;

    fn finish(self) -> Html {
        self.inner.finish()
    }

    fn parse_error(&self, msg: Cow<'static, str>) {
        let owned = match &msg {
            Cow::Owned(text) => text.len(),
            Cow::Borrowed(_) => 0,
        };
        if self.ledger.charge(ERROR_ENTRY.saturating_add(owned)) {
            self.inner.parse_error(msg);
        }
    }

    fn set_quirks_mode(&self, mode: QuirksMode) {
        self.inner.set_quirks_mode(mode);
    }

    fn get_document(&self) -> NodeId {
        self.inner.get_document()
    }

    fn same_node(&self, x: &NodeId, y: &NodeId) -> bool {
        self.inner.same_node(x, y)
    }

    fn elem_name<'a>(&'a self, target: &'a NodeId) -> Ref<'a, QualName> {
        self.inner.elem_name(target)
    }

    fn create_element(&self, name: QualName, attrs: Vec<Attribute>, flags: ElementFlags) -> NodeId {
        let template = flags.template;
        let bytes = element_heap(&name, &attrs, template);
        if self.admit(bytes, if template { 2 } else { 1 }) {
            self.inner.create_element(name, attrs, flags)
        } else {
            self.sentinel()
        }
    }

    fn create_comment(&self, text: StrTendril) -> NodeId {
        if self.admit(tendril_heap(text.len()), 1) {
            self.inner.create_comment(text)
        } else {
            self.sentinel()
        }
    }

    fn create_pi(&self, target: StrTendril, data: StrTendril) -> NodeId {
        let bytes = tendril_heap(target.len()).saturating_add(tendril_heap(data.len()));
        if self.admit(bytes, 1) {
            self.inner.create_pi(target, data)
        } else {
            self.sentinel()
        }
    }

    fn append(&self, parent: &NodeId, child: NodeOrText<NodeId>) {
        if self.admit_child(&child) {
            self.inner.append(parent, child);
        }
    }

    fn append_based_on_parent_node(
        &self,
        element: &NodeId,
        prev_element: &NodeId,
        child: NodeOrText<NodeId>,
    ) {
        if self.poisoned() {
            return;
        }
        let has_parent = self
            .inner
            .0
            .borrow()
            .tree
            .get(*element)
            .is_some_and(|node| node.parent().is_some());
        if has_parent {
            self.append_before_sibling(element, child);
        } else {
            self.append(prev_element, child);
        }
    }

    fn append_doctype_to_document(&self, name: StrTendril, public_id: StrTendril, system_id: StrTendril) {
        let bytes = [&name, &public_id, &system_id]
            .into_iter()
            .fold(0usize, |sum, part| sum.saturating_add(tendril_heap(part.len())));
        if self.admit(bytes, 1) {
            self.inner.append_doctype_to_document(name, public_id, system_id);
        }
    }

    fn get_template_contents(&self, target: &NodeId) -> NodeId {
        if self.poisoned() {
            return self.sentinel();
        }
        self.inner.get_template_contents(target)
    }

    fn append_before_sibling(&self, sibling: &NodeId, new_node: NodeOrText<NodeId>) {
        if self.admit_child(&new_node) {
            self.inner.append_before_sibling(sibling, new_node);
        }
    }

    fn add_attrs_if_missing(&self, target: &NodeId, attrs: Vec<Attribute>) {
        // each inserted attribute can reallocate the sorted vector: charge twice its size
        let bytes = attrs
            .iter()
            .fold(0usize, |sum, attribute| {
                sum.saturating_add(attribute_heap(attribute))
            })
            .saturating_mul(2);
        if self.ledger.charge(bytes) {
            self.inner.add_attrs_if_missing(target, attrs);
        }
    }

    fn remove_from_parent(&self, target: &NodeId) {
        if !self.poisoned() {
            self.inner.remove_from_parent(target);
        }
    }

    fn reparent_children(&self, node: &NodeId, new_parent: &NodeId) {
        if !self.poisoned() {
            self.inner.reparent_children(node, new_parent);
        }
    }

    fn mark_script_already_started(&self, node: &NodeId) {
        self.inner.mark_script_already_started(node);
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Document,
    Fragment,
}

/// Parse `html` as a document into a tree whose allocations are charged to `charge`.
///
/// The result is the tree `Html::parse_document` builds. Keep `charge` alive until the tree
/// and everything derived from it are dropped; it holds the reservation the tree lives in.
///
/// # Errors
/// [`ParseBudgetExhausted`] when the parse needs more than the bytes `charge` reserved and the
/// process-wide budget cannot grow the reservation, or when node storage cannot be allocated.
/// No tree is returned and the reservation is back to what it was.
pub fn parse_document(charge: &mut ParseCharge, html: &str) -> Result<Html, ParseBudgetExhausted> {
    run(charge, html, CHUNK_BYTES, Kind::Document)
}

/// Parse `html` as a fragment (context element `body`) like [`parse_document`].
///
/// # Errors
/// As [`parse_document`].
pub fn parse_fragment(charge: &mut ParseCharge, html: &str) -> Result<Html, ParseBudgetExhausted> {
    run(charge, html, CHUNK_BYTES, Kind::Fragment)
}

fn run(charge: &mut ParseCharge, html: &str, chunk: usize, kind: Kind) -> Result<Html, ParseBudgetExhausted> {
    let (extra, allowance, budget) = charge.begin_tree()?;
    let ledger = Rc::new(Ledger {
        state: RefCell::new(State {
            budget,
            allowance,
            spent: 0,
            peak: 0,
            extra,
            failure: None,
        }),
    });
    let outcome = drive(&ledger, html, chunk, kind);
    // the parser and its sink are gone: this is the last handle
    let state = Rc::into_inner(ledger).map(|ledger| ledger.state.into_inner());
    match (outcome, state) {
        (Ok(tree), Some(state)) => {
            charge.end_tree(state.extra, state.peak);
            Ok(tree)
        }
        (Err(failure), _) => Err(failure),
        // unreachable: no clone outlives `drive`; refuse rather than keep an unaccounted tree
        (Ok(_), None) => Err(exhausted(0, charge.budget())),
    }
}

fn drive(ledger: &Rc<Ledger>, html: &str, chunk: usize, kind: Kind) -> Result<Html, ParseBudgetExhausted> {
    let input = html
        .len()
        .saturating_mul(INPUT_FACTOR)
        .saturating_add(FIXED_BYTES);
    if !ledger.charge(input) {
        return Err(ledger
            .take_failure()
            .unwrap_or_else(|| exhausted(input, &ledger.state.borrow().budget)));
    }
    let (document, sink_html) = match kind {
        Kind::Document => (true, Html::new_document()),
        Kind::Fragment => (false, Html::new_fragment()),
    };
    let sink = MeteredSink::new(HtmlTreeSink::new(sink_html), Rc::clone(ledger))?;
    let mut parser = if document {
        driver::parse_document(sink, ParseOpts::default())
    } else {
        driver::parse_fragment(
            sink,
            ParseOpts::default(),
            QualName::new(None, ns!(html), local_name!("body")),
            Vec::new(),
            false,
        )
    };
    if let Some(failure) = ledger.take_failure() {
        return Err(failure);
    }
    let mut rest = html;
    while !rest.is_empty() {
        let mut end = rest.len().min(chunk.max(1));
        while !rest.is_char_boundary(end) {
            end += 1;
        }
        let (piece, tail) = rest.split_at(end);
        parser.process(StrTendril::from_slice(piece));
        if let Some(failure) = ledger.take_failure() {
            return Err(failure);
        }
        rest = tail;
    }
    let tree = parser.finish();
    match ledger.take_failure() {
        Some(failure) => Err(failure),
        None => Ok(tree),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::parse_budget::{charge_bytes, PARSE_BYTES_PER_INPUT_BYTE};

    const FIXTURES: &[&str] = &[
        "",
        "x",
        "<!doctype html><html><head><title>t</title></head><body><p>one<p>two</body></html>",
        "<table><tr><td>a<td>b</table>text<table>pending<b>text</table>",
        "<a><b><i><em><strong><font><u><s><big><small><p>t<p>u<p>v",
        "<p><b>bold<p>misnested</b>after</p><i>x</i>",
        "<template><div>inside</div></template><p>after</p>",
        "<p class=a class=b id=1 ID=2 data-long=\"0123456789abcdef0123456789\">&amp;&lt;&#x41;&bogus;&copy</p>",
        "<!-- a comment --><?pi data?><![CDATA[x]]><!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\">",
        "line one\r\nline two\rline three\n<p>\u{0}nul\u{0}</p>",
        "<p>日本語 😀 text with multi-byte characters</p><span>é</span>",
        "<svg><desc><p>foreign</p></desc></svg><math><mi>x</mi></math><select><option>a<option>b</select>",
        "<form><input><form><button>in</button></form></form><frameset><frame></frameset>",
        "<body><p>unclosed <span><div>deep<div>deeper<div>deepest",
        "<html a=1><html b=2><body c=3><body d=4>merged attributes",
    ];

    fn budget(limit: usize) -> Arc<ParseBudget> {
        Arc::new(ParseBudget::new(limit))
    }

    fn describe(tree: &Html) -> (String, String, usize) {
        (
            tree.html(),
            format!("{:?}", tree.quirks_mode),
            tree.tree.nodes().count(),
        )
    }

    #[test]
    fn tree_equals_scraper_at_every_chunk_size() {
        let budget = budget(usize::MAX / 4);
        for html in FIXTURES {
            for chunk in [1, 2, 3, 5, 7, 64, CHUNK_BYTES] {
                let mut charge = budget.try_charge_input(html.len()).unwrap();
                let metered = run(&mut charge, html, chunk, Kind::Document).unwrap();
                assert_eq!(
                    describe(&metered),
                    describe(&Html::parse_document(html)),
                    "document {html:?} at chunk {chunk}"
                );
                if chunk >= html.len() {
                    assert_eq!(metered.errors, Html::parse_document(html).errors, "{html:?}");
                }
                let metered = run(&mut charge, html, chunk, Kind::Fragment).unwrap();
                assert_eq!(
                    describe(&metered),
                    describe(&Html::parse_fragment(html)),
                    "fragment {html:?} at chunk {chunk}"
                );
            }
        }
    }

    #[test]
    fn model_stays_inside_the_prepaid_factor_for_ordinary_markup() {
        let budget = budget(usize::MAX / 4);
        let page = "<html><head><title>t</title></head><body>".to_owned()
            + &"<div class=\"item\"><a href=\"/x\">link text</a><p>paragraph of ordinary article text</p></div>"
                .repeat(400)
            + "</body></html>";
        let mut charge = budget.try_charge_input(page.len()).unwrap();
        let prepaid = charge.bytes();
        let tree = parse_document(&mut charge, &page).unwrap();
        assert!(
            charge.tree_bytes() > page.len(),
            "the model charges more than the input"
        );
        assert!(
            charge.tree_bytes() < prepaid,
            "{} of {prepaid}",
            charge.tree_bytes()
        );
        assert_eq!(charge.bytes(), prepaid, "no growth past the prepaid reservation");
        assert_eq!(budget.used(), prepaid);
        drop(tree);
        drop(charge);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn refusal_returns_the_typed_error_and_releases_the_growth() {
        let page = "<p>x</p>".repeat(5000);
        // one byte of input is charged: far below what this document needs
        let ceiling = charge_bytes(1).unwrap();
        let budget = budget(ceiling);
        let mut charge = budget.try_charge_input(1).unwrap();
        let refused = parse_document(&mut charge, &page).unwrap_err();
        assert!(refused.requested > ceiling, "{refused}");
        assert_eq!(refused.limit, ceiling);
        assert_eq!(charge.bytes(), ceiling, "the reservation is what it was");
        assert_eq!(charge.tree_bytes(), 0);
        assert_eq!(
            budget.used(),
            ceiling,
            "growth taken during the failed parse is released"
        );
        assert!(parse_fragment(&mut charge, &page).is_err());
        assert_eq!(budget.used(), ceiling);

        // the same input with room parses and grows the reservation past the prepaid bytes
        budget.set_limit(usize::MAX / 4);
        let tree = parse_document(&mut charge, &page).unwrap();
        assert_eq!(describe(&tree), describe(&Html::parse_document(&page)));
        assert!(charge.bytes() > ceiling);
        assert_eq!(budget.used(), charge.bytes());
        drop(tree);
        drop(charge);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn a_failure_part_way_stops_the_parse_and_returns_no_tree() {
        let page = "<div><b>t</b></div>".repeat(40_000);
        let prepaid = charge_bytes(1).unwrap();
        // room for some of the nodes, not all of them
        let budget = budget(prepaid + 256 * 1024);
        let mut charge = budget.try_charge_input(1).unwrap();
        let refused = parse_document(&mut charge, &page).unwrap_err();
        assert!(
            refused.requested > 256 * 1024,
            "the parse got part way: {refused}"
        );
        assert_eq!(budget.used(), prepaid);
        assert_eq!(charge.bytes(), prepaid);
    }

    #[test]
    fn a_failure_inside_a_run_of_nested_elements_never_appends_a_handle_to_itself() {
        // one chunk of nested elements: after the failure every new element is the sentinel and
        // is opened inside the previous one, so a stored append would attach it to itself
        let page = "<div>".repeat(5_000);
        assert!(page.len() < CHUNK_BYTES);
        let prepaid = charge_bytes(1).unwrap();
        let budget = budget(prepaid + 160 * 1024);
        let mut charge = budget.try_charge_input(1).unwrap();
        let refused = parse_document(&mut charge, &page).unwrap_err();
        assert!(
            refused.requested > 160 * 1024,
            "the parse got part way: {refused}"
        );
        assert_eq!(budget.used(), prepaid);
    }

    #[test]
    fn node_storage_that_cannot_be_allocated_is_a_value() {
        let budget = budget(usize::MAX);
        let mut charge = budget.try_charge_input(1).unwrap();
        let (extra, allowance, shared) = charge.begin_tree().unwrap();
        let ledger = Ledger {
            state: RefCell::new(State {
                budget: shared,
                allowance,
                spent: 0,
                peak: 0,
                extra,
                failure: None,
            }),
        };
        let inner = HtmlTreeSink::new(Html::new_document());
        let impossible = usize::try_from(isize::MAX).unwrap() / NODE_BYTES + 1;
        assert!(!reserve_slots(&inner, &ledger, impossible));
        assert!(ledger.failed());
        assert!(
            ledger.take_failure().unwrap().exceeds_budget(),
            "an allocation the process cannot make exceeds every budget"
        );
        assert_eq!(inner.0.borrow().tree.len(), 1, "no node was added");
        // a later request on the poisoned ledger is refused without charging
        let spent = ledger.state.borrow().spent;
        assert!(!ledger.charge(1));
        assert_eq!(ledger.state.borrow().spent, spent);
    }

    #[test]
    fn charges_scale_with_the_factor_the_worker_admits() {
        // the model must fit the admission factor for the shapes it is calibrated on
        let budget = budget(usize::MAX / 4);
        let page = "<a><b><i><em><strong><font><u><s><big><small><p>t".repeat(2000);
        let mut charge = budget.try_charge_input(page.len()).unwrap();
        let tree = parse_document(&mut charge, &page).unwrap();
        assert!(charge.tree_bytes() <= page.len() * PARSE_BYTES_PER_INPUT_BYTE);
        drop(tree);
    }
}
