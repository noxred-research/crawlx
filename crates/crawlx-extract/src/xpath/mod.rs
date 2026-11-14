//! XPath 1.0 on the existing scraper tree. No document resolver, sockets or extension callbacks.
//! Evaluation, string work and DOM indexing share one hard operation counter.
mod css;
mod syntax;
use crawlx_core::selectors::{SelectorPolicyV1, SelectorV1, MAX_OPERATIONS, MAX_SELECTED};
use ego_tree::{NodeId, NodeRef};
use scraper::{ElementRef, Html, Node, Selector};
use std::collections::{BTreeMap, BTreeSet};
use syntax::{Axis, Expr, Step, Test};
const HTML_NS: &str = "http://www.w3.org/1999/xhtml";
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
/// Selector admission/evaluation failure. Budget exhaustion is never an empty match.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SelectorError {
    /// Invalid XPath/CSS syntax.
    #[error("invalid static selector syntax")]
    Syntax,
    /// Unsupported extension or external-document function.
    #[error("unsupported XPath function")]
    UnsupportedFunction,
    /// Prefix lacks caller binding.
    #[error("unbound XPath namespace prefix")]
    Namespace,
    /// Hard resource bound exceeded.
    #[error("selector budget exceeded: {0}")]
    Budget(&'static str),
    /// Operator requires a node set.
    #[error("XPath node set required")]
    NodeSetRequired,
    /// Invalid local item schema or recipe.
    #[error("invalid item loader schema: {0}")]
    Schema(&'static str),
    /// Caller namespace differs from saved descriptor.
    #[error("adaptive selector scope mismatch")]
    ScopeMismatch,
    /// Recognized but unsupported selector syntax, such as a pseudo-element other than
    /// `::text` and `::attr(name)`, or one used where only elements are allowed.
    #[error("unsupported selector syntax: {0}")]
    Unsupported(&'static str),
    /// A regex transform pattern was refused by the shared admission gate.
    #[error(transparent)]
    Regex(#[from] crate::regex_builtins::RegexError),
    /// Structural contract validation.
    #[error(transparent)]
    Policy(#[from] crawlx_core::CoreError),
}
/// XPath result, with stable document-order internal node IDs.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum XPathValue {
    /// Ordered node set.
    Nodes(Vec<usize>),
    /// Unicode string.
    String(String),
    /// IEEE-754 number.
    Number(f64),
    /// Boolean.
    Boolean(bool),
}
/// Compiled static selector, reusable across documents.
#[derive(Debug, Clone)]
pub struct CompiledSelector {
    expression: Compiled,
    /// AST node count charged for evaluations rooted below the document node.
    ast_nodes: usize,
}
#[derive(Debug, Clone)]
enum Compiled {
    XPath(Expr),
    Css(Vec<css::Part>),
}
impl CompiledSelector {
    /// Compile and reject excessive syntax or unknown functions before evaluation.
    /// # Errors
    /// Returns syntax, budget, unsupported-function or policy errors.
    pub fn compile(spec: &SelectorV1) -> Result<Self, SelectorError> {
        if spec.expression().len() > crawlx_core::selectors::MAX_EXPRESSION_BYTES {
            return Err(SelectorError::Budget("expression bytes"));
        }
        match spec {
            SelectorV1::Xpath { expression } => Self::xpath(expression),
            SelectorV1::Css { expression } => Ok(Self {
                expression: Compiled::Css(css::compile(expression)?),
                ast_nodes: 1,
            }),
            _ => Err(SelectorError::Syntax),
        }
    }
    /// Compile XPath directly.
    /// # Errors
    /// Same errors as `compile`.
    pub fn xpath(expression: &str) -> Result<Self, SelectorError> {
        let (expr, ast_nodes) = syntax::compile(expression)?;
        Ok(Self {
            expression: Compiled::XPath(expr),
            ast_nodes,
        })
    }
    /// Validate all static XPath prefix references without parsing or inspecting a document.
    /// # Errors
    /// Returns an unbound namespace error, including prefixes inside predicates or empty paths.
    pub fn validate_namespaces(&self, namespaces: &BTreeMap<String, String>) -> Result<(), SelectorError> {
        if let Compiled::XPath(expression) = &self.expression {
            syntax::validate_namespaces(expression, namespaces)?;
        }
        Ok(())
    }
}

pub(crate) fn compile_css(source: &str) -> Result<Selector, SelectorError> {
    if source.len() > crawlx_core::selectors::MAX_EXPRESSION_BYTES {
        return Err(SelectorError::Budget("expression bytes"));
    }
    if css::has_pseudo_element(source) {
        return Err(SelectorError::Unsupported(
            "pseudo-element in an element selector",
        ));
    }
    Selector::parse(source).map_err(|_| SelectorError::Syntax)
}
#[derive(Debug)]
enum Kind<'a> {
    Root,
    Element(NodeRef<'a, Node>),
    Text(&'a str),
    Comment(&'a str),
    Pi(&'a str, &'a str),
    Attribute(&'a str, &'a str, Option<&'a str>, &'a str),
    Namespace(&'a str, &'a str),
}
#[derive(Debug)]
struct Entry<'a> {
    kind: Kind<'a>,
    parent: Option<usize>,
    children: Vec<usize>,
    attributes: Vec<usize>,
    namespaces: Vec<usize>,
    end: usize,
    native: Option<NodeId>,
}
/// Borrowed static document index. Construct once and reuse for policy and every item field.
#[derive(Debug)]
pub struct SelectorDocument<'a> {
    html: &'a Html,
    entries: Vec<Entry<'a>>,
    ids: BTreeMap<NodeId, usize>,
    operations: usize,
    limit: usize,
}
#[derive(Clone, Copy)]
struct Context {
    node: usize,
    position: usize,
    size: usize,
}
impl<'a> SelectorDocument<'a> {
    /// Index existing DOM without reparsing HTML or copying candidate trees.
    /// # Errors
    /// Returns typed operation exhaustion for oversized trees.
    pub fn new(html: &'a Html) -> Result<Self, SelectorError> {
        Self::with_operation_limit(html, MAX_OPERATIONS)
    }
    /// Index with a stricter caller ceiling applied before visiting or queuing children.
    /// # Errors
    /// Returns typed operation exhaustion; caller limits never raise the hard ceiling.
    pub fn with_operation_limit(html: &'a Html, limit: usize) -> Result<Self, SelectorError> {
        let mut d = Self {
            html,
            entries: Vec::new(),
            ids: BTreeMap::new(),
            operations: 0,
            limit: limit.min(MAX_OPERATIONS),
        };
        let mut stack = vec![(html.tree.root(), None, false)];
        while let Some((node, parent, exit)) = stack.pop() {
            d.charge(1)?;
            if exit {
                if let Some(i) = d.ids.get(&node.id()).copied() {
                    d.entries[i].end = d.entries.len();
                }
                if let Some(sibling) = node.next_sibling() {
                    stack.push((sibling, parent, false));
                }
                continue;
            }
            let kind = match node.value() {
                Node::Document | Node::Fragment => Kind::Root,
                Node::Element(_) => Kind::Element(node),
                Node::Text(t) => Kind::Text(t),
                Node::Comment(c) => Kind::Comment(c),
                Node::ProcessingInstruction(p) => Kind::Pi(&p.target, &p.data),
                Node::Doctype(_) => {
                    if let Some(sibling) = node.next_sibling() {
                        stack.push((sibling, parent, false));
                    }
                    continue;
                }
            };
            let index = d.entries.len();
            d.ids.insert(node.id(), index);
            d.entries.push(Entry {
                kind,
                parent,
                children: Vec::new(),
                attributes: Vec::new(),
                namespaces: Vec::new(),
                end: index + 1,
                native: Some(node.id()),
            });
            if let Some(p) = parent {
                d.entries[p].children.push(index);
            }
            if let Node::Element(el) = node.value() {
                let mut bindings: BTreeMap<&'a str, &'a str> = BTreeMap::new();
                bindings.insert("xml", XML_NS);
                let mut ancestors = Vec::new();
                let mut ancestor = Some(node);
                while let Some(a) = ancestor {
                    d.charge(1)?;
                    ancestors.push(a);
                    ancestor = a.parent();
                }
                for a in ancestors.into_iter().rev() {
                    if let Node::Element(e) = a.value() {
                        if !e.name.ns.is_empty() {
                            bindings.insert(
                                e.name.prefix.as_ref().map_or("", |p| p.as_ref()),
                                e.name.ns.as_ref(),
                            );
                        }
                        for (name, value) in &e.attrs {
                            d.charge(1)?;
                            if name.prefix.as_ref().is_some_and(|p| &**p == "xmlns") {
                                bindings.insert(name.local.as_ref(), value.as_ref());
                            } else if &*name.local == "xmlns" {
                                bindings.insert("", value.as_ref());
                            }
                        }
                    }
                }
                for (name, uri) in bindings {
                    if uri.is_empty() {
                        continue;
                    }
                    let id = d.virtual_entry(Kind::Namespace(name, uri), index);
                    d.entries[index].namespaces.push(id);
                }
                for (name, value) in &el.attrs {
                    d.charge(1)?;
                    if &*name.local == "xmlns" || name.prefix.as_ref().is_some_and(|p| &**p == "xmlns") {
                        continue;
                    }
                    let id = d.virtual_entry(
                        Kind::Attribute(
                            name.local.as_ref(),
                            name.ns.as_ref(),
                            name.prefix.as_ref().map(|p| p.as_ref()),
                            value,
                        ),
                        index,
                    );
                    d.entries[index].attributes.push(id);
                }
            }
            // Queue one child at a time; exit schedules its next sibling. A wide
            // document cannot allocate a child-count-sized work queue before charging.
            stack.push((node, parent, true));
            if let Some(child) = node.first_child() {
                stack.push((child, Some(index), false));
            }
        }
        Ok(d)
    }
    fn virtual_entry(&mut self, kind: Kind<'a>, parent: usize) -> usize {
        let id = self.entries.len();
        self.entries.push(Entry {
            kind,
            parent: Some(parent),
            children: Vec::new(),
            attributes: Vec::new(),
            namespaces: Vec::new(),
            end: id + 1,
            native: None,
        });
        id
    }
    /// Charge shared deterministic work, including schema and transform work.
    /// # Errors
    /// Returns budget exhaustion; it remains exhausted for later calls.
    pub fn charge(&mut self, n: usize) -> Result<(), SelectorError> {
        self.operations = self.operations.saturating_add(n);
        if self.operations > self.limit {
            Err(SelectorError::Budget("operations"))
        } else {
            Ok(())
        }
    }
    /// Restrict remaining work for a stricter caller budget. Never raises the hard ceiling.
    pub fn restrict_operations(&mut self, limit: usize) {
        self.limit = self.limit.min(limit);
    }
    /// Evaluate a compiled selector at the document root.
    /// # Errors
    /// Returns typed evaluation or resource-limit errors.
    pub fn evaluate(
        &mut self,
        selector: &CompiledSelector,
        namespaces: &BTreeMap<String, String>,
    ) -> Result<XPathValue, SelectorError> {
        self.evaluate_in(selector, 0, namespaces)
    }
    /// Evaluate a compiled selector with `context` as the XPath context node and the CSS scope.
    ///
    /// Relative XPath paths start at `context`; absolute paths still start at the document root.
    /// CSS selectors match descendants of `context` (the whole document for node zero).
    /// # Errors
    /// Returns typed evaluation or resource-limit errors, or `NodeSetRequired` for an unknown node.
    pub fn evaluate_in(
        &mut self,
        selector: &CompiledSelector,
        context: usize,
        namespaces: &BTreeMap<String, String>,
    ) -> Result<XPathValue, SelectorError> {
        if context >= self.entries.len() {
            return Err(SelectorError::NodeSetRequired);
        }
        match &selector.expression {
            Compiled::XPath(expr) => {
                self.charge(if context == 0 {
                    crawlx_core::selectors::MAX_AST_NODES
                } else {
                    selector.ast_nodes
                })?;
                syntax::validate_namespaces(expr, namespaces)?;
                self.eval(
                    expr,
                    Context {
                        node: context,
                        position: 1,
                        size: 1,
                    },
                    namespaces,
                )
            }
            Compiled::Css(parts) => self.evaluate_css(parts, context),
        }
    }
    fn evaluate_css(&mut self, parts: &[css::Part], context: usize) -> Result<XPathValue, SelectorError> {
        // CSS matching can walk ancestors for each candidate. Reserve a conservative
        // quadratic bound over the scope and its ancestor chain before invoking the matcher.
        let span = self.entries[context].end.saturating_sub(context);
        let mut depth = 0usize;
        let mut ancestor = self.entries[context].parent;
        while let Some(i) = ancestor {
            depth = depth.saturating_add(1);
            ancestor = self.entries[i].parent;
        }
        self.charge(span.saturating_mul(span.saturating_add(depth)))?;
        let html = self.html;
        let scope = match self.entries[context].kind {
            Kind::Root => None,
            Kind::Element(_) => match self.element(context) {
                Some(element) => Some(element),
                None => return Ok(XPathValue::Nodes(Vec::new())),
            },
            _ => return Ok(XPathValue::Nodes(Vec::new())),
        };
        let mut nodes = Vec::new();
        for part in parts {
            if let Some(root) = scope {
                for element in root.select(&part.selector) {
                    self.css_project(element, &part.projection, &mut nodes)?;
                }
            } else {
                for element in html.select(&part.selector) {
                    self.css_project(element, &part.projection, &mut nodes)?;
                }
            }
        }
        if parts.len() > 1 {
            self.normalize(&mut nodes)?;
        }
        Ok(XPathValue::Nodes(nodes))
    }
    fn css_project(
        &mut self,
        element: ElementRef<'a>,
        projection: &css::Projection,
        nodes: &mut Vec<usize>,
    ) -> Result<(), SelectorError> {
        let Some(&index) = self.ids.get(&element.id()) else {
            return Ok(());
        };
        match projection {
            css::Projection::Elements => nodes.push(index),
            css::Projection::Text => {
                self.charge(self.entries[index].children.len())?;
                for &child in &self.entries[index].children {
                    if matches!(self.entries[child].kind, Kind::Text(_)) {
                        nodes.push(child);
                    }
                }
            }
            css::Projection::Attr(name) => {
                self.charge(self.entries[index].attributes.len())?;
                for &attribute in &self.entries[index].attributes {
                    if let Kind::Attribute(local, _, _, _) = self.entries[attribute].kind {
                        if local.eq_ignore_ascii_case(name) {
                            nodes.push(attribute);
                        }
                    }
                }
            }
        }
        if nodes.len() > MAX_SELECTED {
            return Err(SelectorError::Budget("selected nodes"));
        }
        Ok(())
    }
    /// Select policy elements, rejecting scalar and non-element pruning results.
    /// # Errors
    /// Returns syntax, type or budget failure; no partial selection escapes.
    pub fn select_policy(
        &mut self,
        policy: &SelectorPolicyV1,
    ) -> Result<crate::dom::Selected, SelectorError> {
        policy.validate()?;
        let mut selected = crate::dom::Selected::default();
        for (rules, include) in [(&policy.include, true), (&policy.exclude, false)] {
            for rule in rules {
                let selector = CompiledSelector::compile(rule)?;
                let value = self.evaluate(&selector, &policy.namespaces)?;
                let XPathValue::Nodes(nodes) = value else {
                    return Err(SelectorError::NodeSetRequired);
                };
                for node in nodes {
                    if !matches!(self.entries[node].kind, Kind::Element(_)) {
                        return Err(SelectorError::NodeSetRequired);
                    }
                    if let Some(id) = self.entries[node].native {
                        if include {
                            selected.include.insert(id);
                        } else {
                            selected.exclude.insert(id);
                        }
                    }
                }
            }
        }
        Ok(selected)
    }
    /// Native DOM identity, absent for virtual attributes/namespaces.
    #[must_use]
    pub fn native_id(&self, node: usize) -> Option<NodeId> {
        self.entries.get(node).and_then(|e| e.native)
    }
    /// Index of a native DOM node in this document, absent for nodes outside it.
    #[must_use]
    pub fn index_of(&self, id: NodeId) -> Option<usize> {
        self.ids.get(&id).copied()
    }
    /// Parent of a native node (the document root for top-level nodes), absent for the root
    /// and for virtual attribute/namespace nodes.
    #[must_use]
    pub fn parent_of(&self, node: usize) -> Option<usize> {
        let entry = self.entries.get(node)?;
        entry.native.and(entry.parent)
    }
    /// Element children of `node` in document order.
    /// # Errors
    /// Returns shared operation exhaustion.
    pub fn element_children(&mut self, node: usize) -> Result<Vec<usize>, SelectorError> {
        let entry = self.entries.get(node).ok_or(SelectorError::NodeSetRequired)?;
        let count = entry.children.len();
        self.charge(count.saturating_add(1))?;
        Ok(self.entries[node]
            .children
            .iter()
            .copied()
            .filter(|child| matches!(self.entries[*child].kind, Kind::Element(_)))
            .collect())
    }
    /// Descendant elements of `node` in document order, under the selected-node ceiling.
    /// # Errors
    /// Returns shared operation exhaustion or the selected-node ceiling.
    pub fn descendant_elements(&mut self, node: usize) -> Result<Vec<usize>, SelectorError> {
        let entry = self.entries.get(node).ok_or(SelectorError::NodeSetRequired)?;
        let end = entry.end;
        self.charge(end.saturating_sub(node))?;
        let mut out = Vec::new();
        for (i, entry) in self.entries.iter().enumerate().take(end).skip(node + 1) {
            if matches!(entry.kind, Kind::Element(_)) {
                if out.len() >= MAX_SELECTED {
                    return Err(SelectorError::Budget("selected nodes"));
                }
                out.push(i);
            }
        }
        Ok(out)
    }
    /// Borrow selected element for structural descriptors or attributes.
    #[must_use]
    pub fn element(&self, node: usize) -> Option<ElementRef<'a>> {
        match self.entries.get(node)?.kind {
            Kind::Element(n) => ElementRef::wrap(n),
            _ => None,
        }
    }
    /// Collect all static elements under a caller candidate ceiling.
    /// # Errors
    /// Returns budget exhaustion instead of choosing from an incomplete candidate set.
    pub fn element_candidates(&mut self, max: usize) -> Result<Vec<usize>, SelectorError> {
        let mut out = Vec::new();
        for i in 0..self.entries.len() {
            self.charge(1)?;
            if matches!(self.entries[i].kind, Kind::Element(_)) {
                if out.len() >= max {
                    return Err(SelectorError::Budget("adaptive candidates"));
                }
                out.push(i);
            }
        }
        Ok(out)
    }
    /// String value of selected node according to XPath 1.0.
    /// # Errors
    /// Returns shared operation exhaustion, never partial strings.
    pub fn string_value(&mut self, node: usize) -> Result<String, SelectorError> {
        let entry = self.entries.get(node).ok_or(SelectorError::NodeSetRequired)?;
        let direct = match &entry.kind {
            Kind::Text(t) | Kind::Comment(t) => Some(*t),
            Kind::Pi(_, s) | Kind::Attribute(_, _, _, s) | Kind::Namespace(_, s) => Some(*s),
            _ => None,
        };
        if let Some(s) = direct {
            self.charge(s.len())?;
            return Ok(s.to_owned());
        }
        let end = entry.end;
        let mut out = String::new();
        for i in node + 1..end {
            self.charge(1)?;
            if let Kind::Text(text) = self.entries[i].kind {
                self.charge(text.len())?;
                out.push_str(text);
            }
        }
        Ok(out)
    }
    /// Serialize one selected element only after reserving traversal and escaped output work.
    /// # Errors
    /// Returns type or operation-budget failure before serialization.
    pub fn markup(&mut self, node: usize) -> Result<String, SelectorError> {
        let element = self.element(node).ok_or(SelectorError::NodeSetRequired)?;
        let end = self.entries[node].end;
        for i in node..end {
            let bytes = match &self.entries[i].kind {
                Kind::Element(n) => n
                    .value()
                    .as_element()
                    .map_or(0, |e| e.name.local.len().saturating_mul(2).saturating_add(5)),
                Kind::Text(s) | Kind::Comment(s) => s.len().saturating_add(7),
                Kind::Attribute(name, uri, prefix, value) => name
                    .len()
                    .saturating_add(uri.len())
                    .saturating_add(prefix.map_or(0, str::len))
                    .saturating_add(value.len())
                    .saturating_add(4),
                Kind::Pi(target, data) => target.len().saturating_add(data.len()).saturating_add(5),
                Kind::Root | Kind::Namespace(_, _) => 0,
            };
            self.charge(bytes.saturating_mul(6).saturating_add(1))?;
        }
        Ok(element.html())
    }
    pub(super) fn string(&mut self, value: &XPathValue) -> Result<String, SelectorError> {
        match value {
            XPathValue::String(s) => {
                self.charge(s.len())?;
                Ok(s.clone())
            }
            XPathValue::Number(n) => Ok(number_string(*n)),
            XPathValue::Boolean(b) => Ok(b.to_string()),
            XPathValue::Nodes(n) => n.first().map_or(Ok(String::new()), |n| self.string_value(*n)),
        }
    }
    fn number(&mut self, value: &XPathValue) -> Result<f64, SelectorError> {
        Ok(match value {
            XPathValue::Number(n) => *n,
            XPathValue::Boolean(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            _ => xpath_number(&self.string(value)?),
        })
    }
    fn normalize(&mut self, nodes: &mut Vec<usize>) -> Result<(), SelectorError> {
        let levels = usize::try_from(nodes.len().checked_ilog2().unwrap_or(0))
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        self.charge(nodes.len().saturating_mul(levels))?;
        nodes.sort_unstable();
        nodes.dedup();
        if nodes.len() > MAX_SELECTED {
            Err(SelectorError::Budget("selected nodes"))
        } else {
            Ok(())
        }
    }
    fn eval(
        &mut self,
        e: &Expr,
        c: Context,
        ns: &BTreeMap<String, String>,
    ) -> Result<XPathValue, SelectorError> {
        self.charge(1)?;
        match e {
            Expr::String(s) => {
                self.charge(s.len())?;
                Ok(XPathValue::String(s.clone()))
            }
            Expr::Number(n) => Ok(XPathValue::Number(*n)),
            Expr::Neg(e) => {
                let v = self.eval(e, c, ns)?;
                Ok(XPathValue::Number(-self.number(&v)?))
            }
            Expr::Function(name, args) => self.function(name, args, c, ns),
            Expr::Filter(e, p) => {
                let value = self.eval(e, c, ns)?;
                let XPathValue::Nodes(nodes) = value else {
                    return Err(SelectorError::NodeSetRequired);
                };
                Ok(XPathValue::Nodes(self.filter(nodes, p, ns)?))
            }
            Expr::Path(base, absolute, steps) => {
                let mut nodes = if let Some(base) = base {
                    let XPathValue::Nodes(nodes) = self.eval(base, c, ns)? else {
                        return Err(SelectorError::NodeSetRequired);
                    };
                    nodes
                } else {
                    vec![if *absolute { 0 } else { c.node }]
                };
                for step in steps {
                    let mut next = Vec::new();
                    for node in nodes {
                        let candidates = self.axis(node, step.axis)?;
                        let mut matches = Vec::new();
                        for n in candidates {
                            if self.matches(n, step, ns)? {
                                matches.push(n);
                            }
                        }
                        next.extend(self.filter(matches, &step.predicates, ns)?);
                        if next.len() > MAX_OPERATIONS {
                            return Err(SelectorError::Budget("intermediate nodes"));
                        }
                    }
                    self.normalize(&mut next)?;
                    nodes = next;
                }
                Ok(XPathValue::Nodes(nodes))
            }
            Expr::Binary(op, a, b) => {
                let a = self.eval(a, c, ns)?;
                if *op == "and" && !boolean(&a) {
                    return Ok(XPathValue::Boolean(false));
                }
                if *op == "or" && boolean(&a) {
                    return Ok(XPathValue::Boolean(true));
                }
                let b = self.eval(b, c, ns)?;
                match *op {
                    "and" => Ok(XPathValue::Boolean(boolean(&b))),
                    "or" => Ok(XPathValue::Boolean(boolean(&b))),
                    "|" => {
                        let (XPathValue::Nodes(mut a), XPathValue::Nodes(b)) = (a, b) else {
                            return Err(SelectorError::NodeSetRequired);
                        };
                        a.extend(b);
                        self.normalize(&mut a)?;
                        Ok(XPathValue::Nodes(a))
                    }
                    "=" | "!=" | "<" | ">" | "<=" | ">=" => {
                        Ok(XPathValue::Boolean(self.compare(op, &a, &b)?))
                    }
                    _ => {
                        let a = self.number(&a)?;
                        let b = self.number(&b)?;
                        Ok(XPathValue::Number(match *op {
                            "+" => a + b,
                            "-" => a - b,
                            "*" => a * b,
                            "div" => a / b,
                            "mod" => a % b,
                            _ => return Err(SelectorError::Syntax),
                        }))
                    }
                }
            }
        }
    }
    fn filter(
        &mut self,
        mut nodes: Vec<usize>,
        predicates: &[Expr],
        ns: &BTreeMap<String, String>,
    ) -> Result<Vec<usize>, SelectorError> {
        for p in predicates {
            let size = nodes.len();
            let mut retained = Vec::new();
            for (i, node) in nodes.into_iter().enumerate() {
                let v = self.eval(
                    p,
                    Context {
                        node,
                        position: i + 1,
                        size,
                    },
                    ns,
                )?;
                let keep = match v {
                    XPathValue::Number(n) => n == usize_number(i + 1),
                    _ => boolean(&v),
                };
                if keep {
                    retained.push(node);
                }
            }
            nodes = retained;
        }
        Ok(nodes)
    }
    fn axis(&mut self, node: usize, axis: Axis) -> Result<Vec<usize>, SelectorError> {
        let e = &self.entries[node];
        let work = match axis {
            Axis::Child => e.children.len(),
            Axis::Attribute => e.attributes.len(),
            Axis::Namespace => e.namespaces.len(),
            Axis::Descendant | Axis::DescendantOrSelf => e.end.saturating_sub(node),
            Axis::Following => self.entries.len().saturating_sub(e.end),
            Axis::Preceding => node.saturating_mul(2),
            Axis::Ancestor | Axis::AncestorOrSelf => node.saturating_add(1),
            Axis::FollowingSibling | Axis::PrecedingSibling => {
                e.parent.map_or(0, |p| self.entries[p].children.len())
            }
            Axis::SelfNode | Axis::Parent => 1,
        };
        self.charge(work.saturating_add(1))?;
        let mut out = Vec::new();
        let e = &self.entries[node];
        match axis {
            Axis::SelfNode => out.push(node),
            Axis::Parent => out.extend(e.parent),
            Axis::Child => out.extend(&e.children),
            Axis::Attribute => out.extend(&e.attributes),
            Axis::Namespace => out.extend(&e.namespaces),
            Axis::Ancestor | Axis::AncestorOrSelf => {
                let mut p = if axis == Axis::AncestorOrSelf {
                    Some(node)
                } else {
                    e.parent
                };
                while let Some(i) = p {
                    out.push(i);
                    p = self.entries[i].parent;
                }
            }
            Axis::Descendant | Axis::DescendantOrSelf => {
                if axis == Axis::DescendantOrSelf {
                    out.push(node);
                }
                if matches!(e.kind, Kind::Root | Kind::Element(_)) {
                    for (i, entry) in self.entries.iter().enumerate().take(e.end).skip(node + 1) {
                        if entry.native.is_some() {
                            out.push(i);
                        }
                    }
                }
            }
            Axis::FollowingSibling | Axis::PrecedingSibling => {
                if e.native.is_some() {
                    if let Some(p) = e.parent {
                        for i in &self.entries[p].children {
                            if (axis == Axis::FollowingSibling && *i > node)
                                || (axis == Axis::PrecedingSibling && *i < node)
                            {
                                out.push(*i);
                            }
                        }
                        if axis == Axis::PrecedingSibling {
                            out.reverse();
                        }
                    }
                }
            }
            Axis::Following => {
                for (i, entry) in self.entries.iter().enumerate().skip(e.end) {
                    if entry.native.is_some() {
                        out.push(i);
                    }
                }
            }
            Axis::Preceding => {
                let mut ancestors = BTreeSet::new();
                let mut p = e.parent;
                while let Some(i) = p {
                    ancestors.insert(i);
                    p = self.entries[i].parent;
                }
                for i in (0..node).rev() {
                    if self.entries[i].native.is_some() && !ancestors.contains(&i) {
                        out.push(i);
                    }
                }
            }
        }
        Ok(out)
    }
    fn matches(
        &mut self,
        node: usize,
        step: &Step,
        ns: &BTreeMap<String, String>,
    ) -> Result<bool, SelectorError> {
        self.charge(1)?;
        let kind = &self.entries[node].kind;
        Ok(match &step.test {
            Test::Node => true,
            Test::Text => matches!(kind, Kind::Text(_)),
            Test::Comment => matches!(kind, Kind::Comment(_)),
            Test::Pi(target) => matches!(kind,Kind::Pi(t,_) if target.as_ref().is_none_or(|s|s==t)),
            Test::Name(prefix, name) => {
                let (local, uri) = match (kind, step.axis) {
                    (Kind::Attribute(n, u, _, _), Axis::Attribute) => (*n, *u),
                    (Kind::Namespace(n, _), Axis::Namespace) => (*n, ""),
                    (Kind::Element(n), a) if a != Axis::Attribute && a != Axis::Namespace => {
                        let Node::Element(e) = n.value() else {
                            return Ok(false);
                        };
                        (e.name.local.as_ref(), e.name.ns.as_ref())
                    }
                    _ => return Ok(false),
                };
                let expected = if let Some(p) = prefix {
                    if p == "xml" {
                        XML_NS
                    } else {
                        ns.get(p).map(String::as_str).ok_or(SelectorError::Namespace)?
                    }
                } else if step.axis == Axis::Attribute || step.axis == Axis::Namespace {
                    ""
                } else {
                    HTML_NS
                };
                (name == "*" || name == local) && (prefix.is_none() && name == "*" || uri == expected)
            }
        })
    }
    fn compare(&mut self, op: &str, a: &XPathValue, b: &XPathValue) -> Result<bool, SelectorError> {
        let equality = op == "=" || op == "!=";
        if equality && (matches!(a, XPathValue::Boolean(_)) || matches!(b, XPathValue::Boolean(_))) {
            return Ok(if op == "=" {
                boolean(a) == boolean(b)
            } else {
                boolean(a) != boolean(b)
            });
        }
        if let XPathValue::Nodes(nodes) = a {
            if let XPathValue::Nodes(other) = b {
                for n in nodes {
                    let left = self.string_value(*n)?;
                    for m in other {
                        self.charge(1)?;
                        let right = self.string_value(*m)?;
                        if if equality {
                            if op == "=" {
                                left == right
                            } else {
                                left != right
                            }
                        } else {
                            numeric_compare(op, xpath_number(&left), xpath_number(&right))
                        } {
                            return Ok(true);
                        }
                    }
                }
                return Ok(false);
            }
            for n in nodes {
                let v = XPathValue::String(self.string_value(*n)?);
                if self.compare(op, &v, b)? {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        if matches!(b, XPathValue::Nodes(_)) {
            return self.compare(
                match op {
                    "<" => ">",
                    ">" => "<",
                    "<=" => ">=",
                    ">=" => "<=",
                    s => s,
                },
                b,
                a,
            );
        }
        if equality && !matches!(a, XPathValue::Number(_)) && !matches!(b, XPathValue::Number(_)) {
            let a = self.string(a)?;
            let b = self.string(b)?;
            return Ok(if op == "=" { a == b } else { a != b });
        }
        let a = self.number(a)?;
        let b = self.number(b)?;
        Ok(numeric_compare(op, a, b))
    }
    fn function(
        &mut self,
        name: &str,
        args: &[Expr],
        c: Context,
        ns: &BTreeMap<String, String>,
    ) -> Result<XPathValue, SelectorError> {
        let mut values = Vec::with_capacity(args.len());
        for a in args {
            values.push(self.eval(a, c, ns)?);
        }
        let default = XPathValue::Nodes(vec![c.node]);
        let first = values.first().unwrap_or(&default);
        match name {
            "last" => Ok(XPathValue::Number(usize_number(c.size))),
            "position" => Ok(XPathValue::Number(usize_number(c.position))),
            "true" => Ok(XPathValue::Boolean(true)),
            "false" => Ok(XPathValue::Boolean(false)),
            "count" => {
                let XPathValue::Nodes(n) = first else {
                    return Err(SelectorError::NodeSetRequired);
                };
                Ok(XPathValue::Number(usize_number(n.len())))
            }
            "boolean" => Ok(XPathValue::Boolean(boolean(first))),
            "not" => Ok(XPathValue::Boolean(!boolean(first))),
            "string" => Ok(XPathValue::String(self.string(first)?)),
            "number" => Ok(XPathValue::Number(self.number(first)?)),
            "floor" | "ceiling" | "round" => {
                let n = self.number(first)?;
                Ok(XPathValue::Number(match name {
                    "floor" => n.floor(),
                    "ceiling" => n.ceil(),
                    _ => xpath_round(n),
                }))
            }
            "sum" => {
                let XPathValue::Nodes(nodes) = first else {
                    return Err(SelectorError::NodeSetRequired);
                };
                let mut sum = 0.0;
                for n in nodes {
                    sum += xpath_number(&self.string_value(*n)?);
                }
                Ok(XPathValue::Number(sum))
            }
            "local-name" | "namespace-uri" | "name" => {
                let XPathValue::Nodes(nodes) = first else {
                    return Err(SelectorError::NodeSetRequired);
                };
                let mut result = String::new();
                if let Some(node) = nodes.first() {
                    let (local, uri, prefix) = match &self.entries[*node].kind {
                        Kind::Element(n) => {
                            let Node::Element(e) = n.value() else {
                                return Err(SelectorError::Syntax);
                            };
                            (
                                e.name.local.as_ref(),
                                e.name.ns.as_ref(),
                                e.name.prefix.as_ref().map(|p| p.as_ref()),
                            )
                        }
                        Kind::Attribute(n, u, p, _) => (*n, *u, *p),
                        Kind::Namespace(n, _) => (*n, "", None),
                        Kind::Pi(n, _) => (*n, "", None),
                        _ => ("", "", None),
                    };
                    if name == "namespace-uri" {
                        result.push_str(uri);
                    } else {
                        if name == "name" {
                            if let Some(p) = prefix {
                                result.push_str(p);
                                result.push(':');
                            }
                        }
                        result.push_str(local);
                    }
                }
                self.charge(result.len())?;
                Ok(XPathValue::String(result))
            }
            "id" => {
                let mut ids = BTreeSet::new();
                if let XPathValue::Nodes(nodes) = first {
                    for n in nodes {
                        let s = self.string_value(*n)?;
                        ids.extend(s.split_ascii_whitespace().map(str::to_owned));
                    }
                } else {
                    ids.extend(self.string(first)?.split_ascii_whitespace().map(str::to_owned));
                }
                let mut nodes = Vec::new();
                for i in 0..self.entries.len() {
                    self.charge(1)?;
                    if let Some(el) = self.element(i) {
                        self.charge(el.value().attrs.len())?;
                        if let Some(id) = el.attr("id") {
                            self.charge(id.len())?;
                            if ids.contains(id) {
                                nodes.push(i);
                            }
                        }
                    }
                }
                self.normalize(&mut nodes)?;
                Ok(XPathValue::Nodes(nodes))
            }
            "lang" => {
                let wanted = self.string(first)?.to_ascii_lowercase();
                let mut p = Some(c.node);
                while let Some(i) = p {
                    self.charge(1)?;
                    if let Some(el) = self.element(i) {
                        self.charge(el.value().attrs.len().saturating_mul(2))?;
                        let lang = el
                            .value()
                            .attrs
                            .iter()
                            .find(|(n, _)| &*n.local == "lang" && &*n.ns == XML_NS)
                            .map(|(_, v)| v.as_ref())
                            .or_else(|| el.value().attr("lang"));
                        if let Some(lang) = lang {
                            self.charge(lang.len())?;
                            let lang = lang.to_ascii_lowercase();
                            return Ok(XPathValue::Boolean(
                                lang == wanted
                                    || lang.strip_prefix(&wanted).is_some_and(|s| s.starts_with('-')),
                            ));
                        }
                    }
                    p = self.entries[i].parent;
                }
                Ok(XPathValue::Boolean(false))
            }
            _ => {
                let mut strings = Vec::with_capacity(values.len().max(1));
                for v in &values {
                    strings.push(self.string(v)?);
                }
                if strings.is_empty() {
                    strings.push(self.string(&default)?);
                }
                let s = &strings[0];
                let t = strings.get(1).map_or("", String::as_str);
                let output = match name {
                    "string-length" => return Ok(XPathValue::Number(usize_number(s.chars().count()))),
                    "normalize-space" => s
                        .split([' ', '\t', '\r', '\n'])
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(" "),
                    "concat" => strings.concat(),
                    "starts-with" => return Ok(XPathValue::Boolean(s.starts_with(t))),
                    "contains" => return Ok(XPathValue::Boolean(s.contains(t))),
                    "substring-before" => s.find(t).map_or(String::new(), |i| s[..i].to_owned()),
                    "substring-after" => s.find(t).map_or(String::new(), |i| s[i + t.len()..].to_owned()),
                    "substring" => {
                        let start = xpath_round(self.number(&values[1])?);
                        let end = if values.len() == 3 {
                            start + xpath_round(self.number(&values[2])?)
                        } else {
                            f64::INFINITY
                        };
                        s.chars()
                            .enumerate()
                            .filter(|(i, _)| {
                                let p = usize_number(i + 1);
                                p >= start && p < end
                            })
                            .map(|(_, ch)| ch)
                            .collect()
                    }
                    "translate" => {
                        let from: Vec<_> = t.chars().collect();
                        let to: Vec<_> = strings[2].chars().collect();
                        self.charge(s.len().saturating_mul(from.len().max(1)))?;
                        s.chars()
                            .filter_map(|ch| {
                                from.iter()
                                    .position(|c| *c == ch)
                                    .map_or(Some(ch), |i| to.get(i).copied())
                            })
                            .collect()
                    }
                    _ => return Err(SelectorError::UnsupportedFunction),
                };
                self.charge(output.len())?;
                Ok(XPathValue::String(output))
            }
        }
    }
}
fn boolean(v: &XPathValue) -> bool {
    match v {
        XPathValue::Nodes(n) => !n.is_empty(),
        XPathValue::String(s) => !s.is_empty(),
        XPathValue::Number(n) => *n != 0.0 && !n.is_nan(),
        XPathValue::Boolean(b) => *b,
    }
}
fn numeric_compare(op: &str, a: f64, b: f64) -> bool {
    match op {
        "=" => a == b,
        "!=" => a != b,
        "<" => a < b,
        ">" => a > b,
        "<=" => a <= b,
        ">=" => a >= b,
        _ => false,
    }
}
fn xpath_number(s: &str) -> f64 {
    let trimmed = s.trim_matches([' ', '\t', '\r', '\n']);
    let unsigned = trimmed.strip_prefix('-').unwrap_or(trimmed);
    if unsigned.is_empty() || !unsigned.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return f64::NAN;
    }
    trimmed.parse().unwrap_or(f64::NAN)
}
fn xpath_round(n: f64) -> f64 {
    if n == 0.0 || !n.is_finite() || n.fract() == 0.0 {
        return n;
    }
    if (-0.5..0.0).contains(&n) {
        return -0.0;
    }
    // Adding 0.5 first can round a value just below the tie upward and can
    // change an already-integral large double. Compare its fractional part instead.
    let floor = n.floor();
    if n - floor < 0.5 {
        floor
    } else {
        floor + 1.0
    }
}
fn number_string(n: f64) -> String {
    if n.is_nan() {
        "NaN".into()
    } else if n == f64::INFINITY {
        "Infinity".into()
    } else if n == f64::NEG_INFINITY {
        "-Infinity".into()
    } else if n == 0.0 {
        "0".into()
    } else {
        n.to_string()
    }
}
fn usize_number(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests;
