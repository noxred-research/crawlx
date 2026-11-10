//! JavaScript AST endpoint pass (compatibility flag `-jsl`, feature `js-ast`).
//!
//! The regex pass of [`super::script`] only sees quoted strings of a known
//! shape. This pass parses the script with `oxc` and reads the request
//! sites themselves, the way dedicated JavaScript request-site scanners do (the matcher list
//! follows theirs; the implementation is independent):
//!
//! * `fetch(url, {method, headers, body})`, `new Request(url, opts)`;
//! * `axios(cfg | url)`, `axios.<method>(url, data?, cfg?)`, `axios.request(cfg)`,
//!   and the generic `<obj>.get/post/put/patch/delete(url, …)` client shape
//!   (Angular `HttpClient`, `ky`, `got`) when the URL looks like one;
//! * `xhr.open(method, url)`; `$.ajax({url, type, data, headers})`,
//!   `$.ajax(url, settings)`, `$.get/post/getJSON(url, data)`;
//! * `navigator.sendBeacon(url, data)`; `new URL(path, base?)`;
//! * `location.assign/replace(url)`, `location[.href] = url`; `window.open(url)`;
//!   `history.pushState/replaceState(_, _, url)`; `new WebSocket(url)`,
//!   `new EventSource(url)`;
//! * any other string literal, template or `+` concatenation whose value looks
//!   like a URL or path (`http(s)://`, `//`, `/`, `./`, `../` prefix).
//!
//! Concatenations and template interpolations are folded into a route pattern:
//! a bound identifier that is declared exactly once with a string-like
//! initializer and never reassigned is inlined (`var a = "http://h/"; var b =
//! "x"; a + b` → `http://h/x`); every other expression becomes a `:name`
//! placeholder (`"/users/" + id` → `/users/:id`, `` `/api/${v}/items` `` →
//! `/api/:v/items`). A leading unknown prefix (`base + "/api"`, `"http://" +
//! host + "/x"`) is dropped so the path resolves against the page. Values that
//! are placeholders only are discarded. Each placeholder, and each value that
//! was discarded, is also reported as a typed
//! [`UnresolvedEndpoint`](super::unresolved::UnresolvedEndpoint) (see
//! [`discover_report`]); the script is never evaluated.
//!
//! Method comes from the options object (`method`/`type`) or the call name;
//! header names from the `headers` object literal (names only, lower-cased);
//! body keys from the `body`/`data` object literal, `JSON.stringify({…})` or
//! `new URLSearchParams({…})` (names only, rendered with the fixed form-fill
//! placeholder). Every result has [`Confidence::Structural`]. A script with
//! syntax errors yields nothing. The caller runs regex only in `regex`/`both`
//! mode; `ast` mode never silently falls back.
//!
//! Bounds: scripts above [`MAX_AST_BYTES`] are skipped, and so are scripts that
//! nest brackets, prefix operators or right-associative operators deeper than
//! the lexical guard allows (a hostile `((((…` would overflow the parser's
//! stack); regex still runs in `both` mode. Identifier inlining is
//! depth-limited and cycle-safe, and the visitors stop descending past
//! [`MAX_AST_DEPTH`].

use std::collections::{BTreeMap, BTreeSet};

use http::Method;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, AssignmentExpression, AssignmentTarget, BinaryOperator, BindingIdentifier, BindingPattern,
    CallExpression, Expression, NewExpression, ObjectExpression, ObjectPropertyKind, Statement,
    VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::{GetSpan, SourceType, Span};
use url::Url;

use super::body::{
    fill, JS_AJAX, JS_AXIOS, JS_BEACON, JS_EVENTSOURCE, JS_FETCH, JS_HISTORY, JS_HTTP, JS_LOCATION, JS_OPEN,
    JS_STRING, JS_URL, JS_WEBSOCKET, JS_XHR,
};
use super::unresolved::{
    DiscoveryReport, ScriptOrigin, SourceSpan, UnresolvedEndpoint, UnresolvedKind, UnresolvedLog,
};
use super::{Confidence, DiscoveredEndpoint, EndpointSource};

/// Scripts larger than this are not parsed (arena memory is a small multiple
/// of the source size). Regex fallback is available only in `both` mode.
pub const MAX_AST_BYTES: usize = 4 * 1024 * 1024;

/// Inlining depth for identifier chains (`a = b + "x"; b = c; …`).
const MAX_INLINE_DEPTH: u8 = 8;

/// Global objects whose member calls are read as if they were bare
/// (`window.fetch`, `self.location.href`, `document.location`).
const GLOBAL_OBJECTS: &[&str] = &["window", "globalthis", "self", "top", "parent", "document"];

/// HTTP method names accepted from `xhr.open(method, …)` and options objects.
const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
];

/// Generic HTTP-client method names (`this.http.post(url, body)`).
const CLIENT_METHODS: &[&str] = &["get", "post", "put", "patch", "delete", "head", "options"];

/// An expression the pass could not reduce to text: where it sits and what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Hole {
    span: Span,
    kind: UnresolvedKind,
}

/// One folded string piece.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece<'a> {
    /// Literal text.
    Lit(String),
    /// A reference to a binding, inlined when the binding is a known constant.
    Ref(&'a str, Span),
    /// Anything else, rendered as `:name`.
    Param(String, Hole),
}

/// How string-like a folded expression is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// Not a string expression (object, function, number arithmetic).
    No,
    /// Identifiers, members and calls: stringness depends on their bindings.
    Maybe,
    /// Contains a string literal or template.
    Str,
}

fn param<'a>(out: &mut Vec<Piece<'a>>, name: &str, span: Span, kind: UnresolvedKind) -> Kind {
    out.push(Piece::Param(name.to_owned(), Hole { span, kind }));
    Kind::Maybe
}

/// Deepest expression, statement or pattern nesting the passes recurse into.
/// The oxc visitors and [`fold`] recurse natively, so a hostile script
/// (`a+a+a+…` repeated 100 000 times) would overflow a worker thread's stack;
/// anything deeper is skipped and never reported.
const MAX_AST_DEPTH: u16 = 512;

/// Recursion counter of the visitors.
#[derive(Debug, Default)]
struct Depth(u16);

impl Depth {
    /// Enter one more level; `false` (and no change) at the bound.
    fn enter(&mut self) -> bool {
        if self.0 >= MAX_AST_DEPTH {
            return false;
        }
        self.0 += 1;
        true
    }

    fn leave(&mut self) {
        self.0 = self.0.saturating_sub(1);
    }
}

/// Fold `e` into pieces and report its kind.
fn fold<'a>(e: &Expression<'a>, out: &mut Vec<Piece<'a>>) -> Kind {
    fold_at(e, out, 0)
}

fn fold_at<'a>(e: &Expression<'a>, out: &mut Vec<Piece<'a>>, depth: u16) -> Kind {
    if depth >= MAX_AST_DEPTH {
        return param(out, "param", e.span(), UnresolvedKind::Expression);
    }
    let next = depth.saturating_add(1);
    match e {
        Expression::StringLiteral(s) => match s.value.as_str() {
            Some(v) => {
                out.push(Piece::Lit(v.to_owned()));
                Kind::Str
            }
            None => param(out, "param", s.span, UnresolvedKind::Expression),
        },
        Expression::NumericLiteral(n) => {
            out.push(Piece::Lit(
                n.raw
                    .map_or_else(|| n.value.to_string(), |r| r.as_str().to_owned()),
            ));
            Kind::No
        }
        Expression::TemplateLiteral(t) => {
            for (i, q) in t.quasis.iter().enumerate() {
                let text = q
                    .value
                    .cooked
                    .and_then(|c| c.as_str())
                    .unwrap_or_else(|| q.value.raw.as_str());
                if !text.is_empty() {
                    out.push(Piece::Lit(text.to_owned()));
                }
                if let Some(x) = t.expressions.get(i) {
                    fold_at(x, out, next);
                }
            }
            Kind::Str
        }
        Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
            let l = fold_at(&b.left, out, next);
            let r = fold_at(&b.right, out, next);
            l.max(r)
        }
        Expression::ParenthesizedExpression(p) => fold_at(&p.expression, out, next),
        Expression::AwaitExpression(a) => fold_at(&a.argument, out, next),
        Expression::SequenceExpression(s) => match s.expressions.last() {
            Some(last) => fold_at(last, out, next),
            None => param(out, "param", s.span, UnresolvedKind::Expression),
        },
        Expression::LogicalExpression(l) => fold_at(&l.left, out, next),
        Expression::Identifier(id) => {
            out.push(Piece::Ref(id.name.as_str(), id.span));
            Kind::Maybe
        }
        Expression::StaticMemberExpression(m) => {
            param(out, m.property.name.as_str(), m.span, UnresolvedKind::Member)
        }
        Expression::ComputedMemberExpression(m) => match &m.expression {
            Expression::StringLiteral(s) => param(
                out,
                s.value.as_str().unwrap_or("param"),
                m.span,
                UnresolvedKind::Member,
            ),
            _ => param(out, "param", m.span, UnresolvedKind::Member),
        },
        Expression::CallExpression(c) => fold_call(c, out, next),
        _ => {
            out.push(Piece::Param(
                "param".to_owned(),
                Hole {
                    span: e.span(),
                    kind: UnresolvedKind::Expression,
                },
            ));
            Kind::No
        }
    }
}

/// `encodeURIComponent(x)`, `String(x)`, `x.toString()` and `x.trim()` are
/// transparent; any other call (case conversions change the value) is an
/// unresolved placeholder.
fn fold_call<'a>(c: &CallExpression<'a>, out: &mut Vec<Piece<'a>>, depth: u16) -> Kind {
    let first = c.arguments.first().and_then(Argument::as_expression);
    match c.callee.without_parentheses() {
        Expression::Identifier(id)
            if matches!(
                id.name.as_str(),
                "encodeURIComponent" | "encodeURI" | "String" | "decodeURIComponent"
            ) =>
        {
            if let Some(a) = first {
                return fold_at(a, out, depth).max(Kind::Maybe);
            }
        }
        Expression::StaticMemberExpression(m)
            if c.arguments.is_empty()
                && matches!(m.property.name.as_str(), "toString" | "trim" | "valueOf") =>
        {
            return fold_at(&m.object, out, depth).max(Kind::Maybe);
        }
        _ => {}
    }
    param(out, "param", c.span, UnresolvedKind::Call)
}

/// What pass one learned about a binding name.
#[derive(Debug, Default)]
struct Binding<'a> {
    /// Declarations (declarators, parameters, function names, …).
    declared: u32,
    /// Assigned after declaration.
    assigned: bool,
    /// Folded initializer of the (single) declarator, when string-like.
    init: Option<Vec<Piece<'a>>>,
}

/// Pass one: binding census.
#[derive(Default)]
struct Bindings<'a> {
    names: BTreeMap<&'a str, Binding<'a>>,
    depth: Depth,
}

impl<'a> Visit<'a> for Bindings<'a> {
    fn visit_statement(&mut self, it: &Statement<'a>) {
        if self.depth.enter() {
            walk::walk_statement(self, it);
            self.depth.leave();
        }
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.depth.enter() {
            walk::walk_expression(self, it);
            self.depth.leave();
        }
    }

    fn visit_binding_pattern(&mut self, it: &BindingPattern<'a>) {
        if self.depth.enter() {
            walk::walk_binding_pattern(self, it);
            self.depth.leave();
        }
    }

    fn visit_assignment_target(&mut self, it: &AssignmentTarget<'a>) {
        if self.depth.enter() {
            walk::walk_assignment_target(self, it);
            self.depth.leave();
        }
    }

    fn visit_binding_identifier(&mut self, it: &BindingIdentifier<'a>) {
        self.names.entry(it.name.as_str()).or_default().declared += 1;
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let (BindingPattern::BindingIdentifier(id), Some(init)) = (&it.id, &it.init) {
            let mut pieces = Vec::new();
            if fold(init, &mut pieces) != Kind::No {
                self.names.entry(id.name.as_str()).or_default().init = Some(pieces);
            }
        }
        walk::walk_variable_declarator(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(id) = &it.left {
            self.names.entry(id.name.as_str()).or_default().assigned = true;
        }
        walk::walk_assignment_expression(self, it);
    }
}

/// Constant bindings: declared once, never assigned, string-like initializer.
type Consts<'a> = BTreeMap<&'a str, Vec<Piece<'a>>>;

fn consts<'a>(b: Bindings<'a>) -> Consts<'a> {
    b.names
        .into_iter()
        .filter(|(_, v)| v.declared == 1 && !v.assigned)
        .filter_map(|(k, v)| v.init.map(|init| (k, init)))
        .collect()
}

/// A rendered pattern.
#[derive(Debug, Default)]
struct Rendered {
    text: String,
    /// Some literal text was produced.
    literal: bool,
    /// Some `:name` placeholder was produced.
    placeholder: bool,
    /// Every sub-expression that was rendered as a placeholder, in text order.
    holes: Vec<Hole>,
}

fn render<'a>(
    pieces: &[Piece<'a>],
    consts: &Consts<'a>,
    depth: u8,
    visiting: &mut Vec<&'a str>,
    r: &mut Rendered,
) {
    for p in pieces {
        match p {
            Piece::Lit(s) => {
                r.text.push_str(s);
                r.literal = true;
            }
            Piece::Param(name, hole) => {
                r.text.push(':');
                r.text.push_str(name);
                r.placeholder = true;
                r.holes.push(*hole);
            }
            Piece::Ref(name, span) => match consts.get(name) {
                Some(init) if depth < MAX_INLINE_DEPTH && !visiting.contains(name) => {
                    visiting.push(name);
                    render(init, consts, depth.saturating_add(1), visiting, r);
                    visiting.pop();
                }
                _ => {
                    r.text.push(':');
                    r.text.push_str(name);
                    r.placeholder = true;
                    r.holes.push(Hole {
                        span: *span,
                        kind: UnresolvedKind::Variable,
                    });
                }
            },
        }
    }
}

fn rendered<'a>(pieces: &[Piece<'a>], consts: &Consts<'a>) -> Rendered {
    let mut r = Rendered::default();
    render(pieces, consts, 0, &mut Vec::new(), &mut r);
    r
}

/// Drop an unknown prefix (placeholder, or placeholder authority) so the rest
/// is a path; refuse values without literal text; map `ws(s):` to `http(s):`.
fn normalize(pattern: &str) -> Option<String> {
    let mut p = pattern.trim();
    if p.starts_with(':') {
        p = &p[p.find('/')?..];
    } else {
        let scheme_len = ["https://", "http://", "wss://", "ws://", "//"]
            .iter()
            .find(|s| p.starts_with(**s))
            .map(|s| s.len());
        if let Some(n) = scheme_len {
            if p[n..].starts_with(':') {
                let rel = n + p[n..].find('/')?;
                p = &p[rel..];
            }
        }
    }
    if p.is_empty() || p.chars().any(char::is_whitespace) {
        return None;
    }
    // at least one literal character outside placeholders
    let mut in_placeholder = false;
    let mut has_literal = false;
    for c in p.chars() {
        if c == ':' {
            in_placeholder = true;
        } else if in_placeholder && (c.is_alphanumeric() || c == '_' || c == '$') {
            // placeholder name
        } else {
            in_placeholder = false;
            if c.is_alphanumeric() {
                has_literal = true;
            }
        }
    }
    if !has_literal {
        return None;
    }
    if let Some(rest) = p.strip_prefix("wss://") {
        return Some(format!("https://{rest}"));
    }
    if let Some(rest) = p.strip_prefix("ws://") {
        return Some(format!("http://{rest}"));
    }
    Some(p.to_owned())
}

/// A string value that looks like a URL or path on its own (the reference
/// string-literal matcher, narrowed: no whitespace, no markup or code
/// characters, something after the prefix).
fn url_like(value: &str) -> bool {
    let rest = ["https://", "http://", "wss://", "ws://", "//", "../", "./", "/"]
        .iter()
        .find_map(|p| value.strip_prefix(p));
    let Some(rest) = rest else {
        return false;
    };
    let first = rest.chars().next();
    first.is_some_and(|c| c.is_alphanumeric() || matches!(c, ':' | '_' | '-' | '.'))
        && !value.contains(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '<' | '>' | '"' | '\'' | '`' | '{' | '}' | '(' | ')' | '|' | '^' | '\\' | '*' | ',' | ';'
                )
        })
}

/// Request body shape read from an options object.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BodyKeys {
    Json(BTreeSet<String>),
    Form(BTreeSet<String>),
}

/// What the URL position of a request site resolved to.
#[derive(Debug, Default)]
struct UrlResolution {
    /// Route pattern, `None` when nothing usable was derived.
    pattern: Option<String>,
    /// Every sub-expression that could not be resolved.
    holes: Vec<Hole>,
}

/// What an options object (`fetch` init, axios config, `$.ajax` settings) says.
#[derive(Debug, Default)]
struct Opts {
    url: Option<UrlResolution>,
    method: Option<Method>,
    headers: BTreeSet<String>,
    content_type: Option<String>,
    body: Option<BodyKeys>,
    /// The matcher is only a likely request site (`x.open(…)` without a known
    /// method): resolve it, but do not report what stays unresolved.
    quiet: bool,
}

/// One request site before resolution.
#[derive(Debug)]
struct Site {
    pattern: String,
    method: Method,
    source: EndpointSource,
    headers: BTreeSet<String>,
    content_type: Option<String>,
    body: Option<BodyKeys>,
}

impl Site {
    fn get(pattern: String, source: EndpointSource) -> Self {
        Self {
            pattern,
            method: Method::GET,
            source,
            headers: BTreeSet::new(),
            content_type: None,
            body: None,
        }
    }
}

/// One unresolved sub-expression of a request site.
#[derive(Debug)]
struct Unres {
    source: EndpointSource,
    method: Method,
    hole: Hole,
    /// An endpoint was still emitted for the site.
    partial: bool,
}

/// Pass two: request-site miner.
struct Miner<'a> {
    consts: Consts<'a>,
    /// Span starts of expressions consumed by a matcher; the string catch-all
    /// skips them so `fetch('/x', {method:'POST'})` does not also yield a GET.
    consumed: BTreeSet<u32>,
    /// Inside a folded concatenation: operands are not separate candidates.
    suppress: bool,
    sites: Vec<Site>,
    depth: Depth,
    unresolved: Vec<Unres>,
    /// JavaScript carried in strings (`el.setAttribute('onclick', "fetch('/x')")`),
    /// mined after this script at the next nesting level.
    nested: Vec<String>,
}

/// Object literal behind `{…}` or parentheses.
fn object<'e, 'a>(e: &'e Expression<'a>) -> Option<&'e ObjectExpression<'a>> {
    match e.without_parentheses() {
        Expression::ObjectExpression(o) => Some(o),
        _ => None,
    }
}

fn keys(obj: &ObjectExpression<'_>) -> BTreeSet<String> {
    obj.properties
        .iter()
        .filter_map(|p| match p {
            ObjectPropertyKind::ObjectProperty(p) => {
                p.key.static_name().and_then(|n| n.as_str().map(str::to_owned))
            }
            ObjectPropertyKind::SpreadProperty(_) => None,
        })
        .collect()
}

/// `{…}`, `JSON.stringify({…})`, `new URLSearchParams({…})` → the object's keys.
fn body_keys(e: &Expression<'_>, form_default: bool) -> Option<BodyKeys> {
    match e.without_parentheses() {
        Expression::ObjectExpression(o) => Some(if form_default {
            BodyKeys::Form(keys(o))
        } else {
            BodyKeys::Json(keys(o))
        }),
        Expression::CallExpression(c) if c.callee.is_specific_member_access("JSON", "stringify") => c
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .and_then(object)
            .map(|o| BodyKeys::Json(keys(o))),
        Expression::NewExpression(n) if n.callee.is_specific_id("URLSearchParams") => n
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .and_then(object)
            .map(|o| BodyKeys::Form(keys(o))),
        _ => None,
    }
}

/// `{…}` or `new Headers({…})`.
fn header_object<'e, 'a>(e: &'e Expression<'a>) -> Option<&'e ObjectExpression<'a>> {
    match e.without_parentheses() {
        Expression::ObjectExpression(o) => Some(o),
        Expression::NewExpression(n) if n.callee.is_specific_id("Headers") => n
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .and_then(object),
        _ => None,
    }
}

fn name_method(name: &str) -> Method {
    Method::from_bytes(name.to_ascii_uppercase().as_bytes()).unwrap_or(Method::GET)
}

/// Longest dotted chain read as a callee or assignment target.
const MAX_CHAIN_SEGMENTS: u8 = 32;

/// Dotted member chain (`window.location.href` → `["window", "location", "href"]`);
/// `false` when the chain does not bottom out in an identifier or `this`, or is
/// longer than [`MAX_CHAIN_SEGMENTS`].
fn chain<'a>(e: &Expression<'a>, out: &mut Vec<&'a str>) -> bool {
    chain_at(e, out, 0)
}

fn chain_at<'a>(e: &Expression<'a>, out: &mut Vec<&'a str>, depth: u8) -> bool {
    if depth >= MAX_CHAIN_SEGMENTS {
        return false;
    }
    match e.without_parentheses() {
        Expression::Identifier(id) => {
            out.push(id.name.as_str());
            true
        }
        Expression::ThisExpression(_) => {
            out.push("this");
            true
        }
        Expression::StaticMemberExpression(m) => {
            let ok = chain_at(&m.object, out, depth + 1);
            out.push(m.property.name.as_str());
            ok
        }
        Expression::ComputedMemberExpression(m) => {
            let ok = chain_at(&m.object, out, depth + 1);
            match &m.expression {
                Expression::StringLiteral(s) => {
                    out.push(s.value.as_str().unwrap_or(""));
                    ok
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// Dotted path with the leading global objects stripped
/// (`window.location.assign` → `location.assign`).
fn global_path(segs: &[&str]) -> String {
    let mut i = 0;
    while i + 1 < segs.len() && GLOBAL_OBJECTS.contains(&segs[i].to_ascii_lowercase().as_str()) {
        i += 1;
    }
    segs[i..].join(".")
}

/// A `new URL(path, base)` base that is the page itself (`location`,
/// `location.origin`, `document.baseURI`): resolving against the page is right.
fn is_page_base(e: &Expression<'_>) -> bool {
    let mut segs = Vec::new();
    if !chain(e, &mut segs) {
        return false;
    }
    let path = global_path(&segs);
    path == "location" || path.starts_with("location.") || path == "baseURI"
}

impl<'a> Miner<'a> {
    /// Resolve a URL position: the route pattern (if any) and everything that
    /// stayed unresolved on the way.
    fn resolve_url(&self, e: &Expression<'a>) -> UrlResolution {
        let mut pieces = Vec::new();
        let kind = fold(e, &mut pieces);
        let r = rendered(&pieces, &self.consts);
        let pattern = if kind != Kind::No && r.literal {
            normalize(&r.text)
        } else {
            None
        };
        UrlResolution {
            pattern,
            holes: r.holes,
        }
    }

    /// Remember each unresolved sub-expression of a request site.
    fn record(&mut self, res: &UrlResolution, source: EndpointSource, method: &Method) {
        let partial = res.pattern.is_some();
        for hole in &res.holes {
            self.unresolved.push(Unres {
                source,
                method: method.clone(),
                hole: *hole,
                partial,
            });
        }
    }

    fn pattern_of(&self, pieces: &[Piece<'a>]) -> Option<String> {
        let r = rendered(pieces, &self.consts);
        if !r.literal {
            return None;
        }
        normalize(&r.text)
    }

    /// A fully literal string value (no placeholders): method names, header
    /// values, `new URL` bases.
    fn literal(&self, e: &Expression<'a>) -> Option<String> {
        let mut pieces = Vec::new();
        if fold(e, &mut pieces) == Kind::No {
            return None;
        }
        let r = rendered(&pieces, &self.consts);
        (r.literal && !r.placeholder).then_some(r.text)
    }

    fn method(&self, e: &Expression<'a>) -> Option<Method> {
        let m = self.literal(e)?.trim().to_ascii_uppercase();
        METHODS
            .contains(&m.as_str())
            .then(|| Method::from_bytes(m.as_bytes()).ok())
            .flatten()
    }

    fn options(&mut self, e: Option<&Expression<'a>>, form_default: bool) -> Opts {
        let mut opts = Opts::default();
        let Some(obj) = e.and_then(object) else {
            return opts;
        };
        for p in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(p) = p else {
                continue;
            };
            let Some(name) = p.key.static_name() else {
                continue;
            };
            match name.as_str().unwrap_or("").to_ascii_lowercase().as_str() {
                "url" => {
                    opts.url = Some(self.resolve_url(&p.value));
                    self.consumed.insert(p.value.span().start);
                }
                "method" | "type" => opts.method = self.method(&p.value),
                "headers" => {
                    let Some(h) = header_object(&p.value) else {
                        continue;
                    };
                    for hp in &h.properties {
                        let ObjectPropertyKind::ObjectProperty(hp) = hp else {
                            continue;
                        };
                        let hn = hp
                            .key
                            .static_name()
                            .and_then(|n| n.as_str().map(str::to_ascii_lowercase))
                            .unwrap_or_default();
                        if hn.is_empty() {
                            continue;
                        }
                        if hn == "content-type" {
                            opts.content_type = self.literal(&hp.value);
                        }
                        opts.headers.insert(hn);
                    }
                }
                "body" | "data" => opts.body = body_keys(&p.value, form_default),
                "contenttype" => opts.content_type = self.literal(&p.value),
                _ => {}
            }
        }
        opts
    }

    fn emit(&mut self, url: Option<&Expression<'a>>, source: EndpointSource, method: Method, opts: Opts) {
        let res = match url {
            Some(u) => {
                self.consumed.insert(u.span().start);
                self.resolve_url(u)
            }
            None => opts.url.unwrap_or_default(),
        };
        let method = opts.method.unwrap_or(method);
        if !opts.quiet {
            self.record(&res, source, &method);
        }
        let Some(pattern) = res.pattern else {
            return;
        };
        self.sites.push(Site {
            pattern,
            method,
            source,
            headers: opts.headers,
            content_type: opts.content_type,
            body: opts.body,
        });
    }

    fn emit_get(&mut self, url: Option<&Expression<'a>>, source: EndpointSource) {
        self.emit(url, source, Method::GET, Opts::default());
    }

    fn call(&mut self, c: &CallExpression<'a>) {
        let arg = |i: usize| c.arguments.get(i).and_then(Argument::as_expression);
        let mut segs = Vec::new();
        let dotted = chain(&c.callee, &mut segs);
        let last = segs.last().copied().unwrap_or("");
        let path = if dotted { global_path(&segs) } else { String::new() };
        match path.as_str() {
            "fetch" => {
                if matches!(arg(0), Some(Expression::NewExpression(_))) {
                    return; // `fetch(new Request(…))`: the `new` matcher reads it
                }
                let opts = self.options(arg(1), false);
                self.emit(arg(0), JS_FETCH, Method::GET, opts);
            }
            "axios" | "axios.request" => {
                if arg(0).and_then(object).is_some() {
                    let opts = self.options(arg(0), false);
                    self.emit(None, JS_AXIOS, Method::GET, opts);
                } else {
                    let opts = self.options(arg(1), false);
                    self.emit(arg(0), JS_AXIOS, Method::GET, opts);
                }
            }
            "axios.get" | "axios.delete" | "axios.head" | "axios.options" => {
                let opts = self.options(arg(1), false);
                self.emit(arg(0), JS_AXIOS, name_method(last), opts);
            }
            "axios.post" | "axios.put" | "axios.patch" => {
                let mut opts = self.options(arg(2), false);
                opts.body = arg(1).and_then(|b| body_keys(b, false));
                self.emit(arg(0), JS_AXIOS, name_method(last), opts);
            }
            "$.ajax" | "jQuery.ajax" | "$.getJSON" | "$.getScript" | "jQuery.getJSON" => {
                if arg(0).and_then(object).is_some() {
                    let opts = self.options(arg(0), true);
                    self.emit(None, JS_AJAX, Method::GET, opts);
                } else {
                    let mut opts = self.options(arg(1), true);
                    if opts.body.is_none() {
                        opts.body = arg(1).and_then(|d| body_keys(d, true));
                    }
                    self.emit(arg(0), JS_AJAX, Method::GET, opts);
                }
            }
            "$.get" | "$.post" | "jQuery.get" | "jQuery.post" => {
                let opts = Opts {
                    body: arg(1).and_then(|d| body_keys(d, true)),
                    ..Opts::default()
                };
                self.emit(arg(0), JS_AJAX, name_method(last), opts);
            }
            "navigator.sendBeacon" => {
                let opts = Opts {
                    body: arg(1).and_then(|d| body_keys(d, false)),
                    ..Opts::default()
                };
                self.emit(arg(0), JS_BEACON, Method::POST, opts);
            }
            "location.assign" | "location.replace" => self.emit_get(arg(0), JS_LOCATION),
            "history.pushState" | "history.replaceState" => self.emit_get(arg(2), JS_HISTORY),
            "open" => self.emit_get(arg(0), JS_OPEN),
            _ if segs.len() < 2 => {}
            _ if last == "setAttribute" && c.arguments.len() >= 2 => {
                // `el.setAttribute('onclick', "<js>")`: the string is a handler body
                let is_handler = arg(0)
                    .and_then(|n| self.literal(n))
                    .is_some_and(|n| n.len() > 2 && n.to_ascii_lowercase().starts_with("on"));
                if is_handler {
                    if let Some(code) = arg(1).and_then(|v| self.literal(v)) {
                        self.nested.push(code);
                    }
                }
            }
            _ if last == "open" && c.arguments.len() >= 2 => {
                // `xhr.open(method, url)`; an unknown method stays GET. Other `open`
                // methods exist (`db.open(name, mode)`): unresolved URLs are only
                // reported when the first argument is a known HTTP method.
                let method = arg(0).and_then(|m| self.method(m));
                let opts = Opts {
                    quiet: method.is_none(),
                    method,
                    ..Opts::default()
                };
                self.emit(arg(1), JS_XHR, Method::GET, opts);
            }
            _ if CLIENT_METHODS.contains(&last) => {
                // generic HTTP client (`this.http.post('/api', body)`): only URL-looking targets
                let Some(u) = arg(0) else { return };
                if !self.resolve_url(u).pattern.is_some_and(|p| url_like(&p)) {
                    return;
                }
                let with_body = matches!(last, "post" | "put" | "patch");
                let mut opts = self.options(arg(if with_body { 2 } else { 1 }), false);
                if with_body {
                    opts.body = arg(1).and_then(|b| body_keys(b, false));
                }
                self.emit(Some(u), JS_HTTP, name_method(last), opts);
            }
            _ => {}
        }
    }

    fn new_expression(&mut self, n: &NewExpression<'a>) {
        let arg = |i: usize| n.arguments.get(i).and_then(Argument::as_expression);
        let mut segs = Vec::new();
        if !chain(&n.callee, &mut segs) {
            return;
        }
        match global_path(&segs).as_str() {
            "URL" => {
                let Some(first) = arg(0) else { return };
                self.consumed.insert(first.span().start);
                let res = self.resolve_url(first);
                self.record(&res, JS_URL, &Method::GET);
                let Some(mut pattern) = res.pattern else {
                    return;
                };
                if let Some(b) = arg(1) {
                    self.consumed.insert(b.span().start);
                    let joined = self
                        .literal(b)
                        .and_then(|b| Url::parse(&b).ok())
                        .and_then(|b| b.join(&pattern).ok());
                    if let Some(joined) = joined {
                        pattern = joined.to_string();
                    } else if !is_page_base(b) {
                        // the base is dynamic: the URL stays relative to the page
                        let base = UrlResolution {
                            pattern: Some(pattern.clone()),
                            holes: self.resolve_url(b).holes,
                        };
                        self.record(&base, JS_URL, &Method::GET);
                    }
                }
                self.sites.push(Site::get(pattern, JS_URL));
            }
            "WebSocket" => self.emit_get(arg(0), JS_WEBSOCKET),
            "EventSource" => self.emit_get(arg(0), JS_EVENTSOURCE),
            "Request" => {
                let opts = self.options(arg(1), false);
                self.emit(arg(0), JS_FETCH, Method::GET, opts);
            }
            _ => {}
        }
    }

    /// `location = x`, `location.href = x` (with any global prefix).
    fn assignment(&mut self, a: &AssignmentExpression<'a>) {
        let mut segs = Vec::new();
        let ok = match &a.left {
            AssignmentTarget::AssignmentTargetIdentifier(id) => {
                segs.push(id.name.as_str());
                true
            }
            AssignmentTarget::StaticMemberExpression(m) => {
                let ok = chain(&m.object, &mut segs);
                segs.push(m.property.name.as_str());
                ok
            }
            _ => false,
        };
        if ok && matches!(global_path(&segs).as_str(), "location" | "location.href") {
            self.emit_get(Some(&a.right), JS_LOCATION);
        }
    }

    /// The string catch-all: literals, templates and `+` chains that look like URLs.
    fn candidate(&mut self, e: &Expression<'a>) {
        let mut pieces = Vec::new();
        if fold(e, &mut pieces) == Kind::No {
            return;
        }
        if let Some(p) = self.pattern_of(&pieces).filter(|p| url_like(p)) {
            self.sites.push(Site::get(p, JS_STRING));
        }
    }
}

fn is_stringish(e: &Expression<'_>) -> bool {
    match e.without_parentheses() {
        Expression::StringLiteral(_) | Expression::TemplateLiteral(_) => true,
        Expression::BinaryExpression(b) => b.operator == BinaryOperator::Addition,
        _ => false,
    }
}

impl<'a> Visit<'a> for Miner<'a> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.call(it);
        let prev = self.suppress;
        self.suppress = false;
        walk::walk_call_expression(self, it);
        self.suppress = prev;
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        self.new_expression(it);
        let prev = self.suppress;
        self.suppress = false;
        walk::walk_new_expression(self, it);
        self.suppress = prev;
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        self.assignment(it);
        walk::walk_assignment_expression(self, it);
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        if self.depth.enter() {
            walk::walk_statement(self, it);
            self.depth.leave();
        }
    }

    fn visit_binding_pattern(&mut self, it: &BindingPattern<'a>) {
        if self.depth.enter() {
            walk::walk_binding_pattern(self, it);
            self.depth.leave();
        }
    }

    fn visit_assignment_target(&mut self, it: &AssignmentTarget<'a>) {
        if self.depth.enter() {
            walk::walk_assignment_target(self, it);
            self.depth.leave();
        }
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !self.depth.enter() {
            return;
        }
        if is_stringish(it) {
            if !self.suppress && !self.consumed.contains(&it.span().start) {
                self.candidate(it);
            }
            let prev = self.suppress;
            self.suppress = true;
            walk::walk_expression(self, it);
            self.suppress = prev;
        } else {
            walk::walk_expression(self, it);
        }
        self.depth.leave();
    }
}

/// Body text and content type for the discovered keys: form-encoded when the
/// shape or the declared content type says so, JSON otherwise.
fn render_body(keys: &BodyKeys, content_type: Option<&str>) -> (String, String) {
    let (names, form) = match keys {
        BodyKeys::Json(k) => (
            k,
            content_type.is_some_and(|c| c.contains("x-www-form-urlencoded")),
        ),
        BodyKeys::Form(k) => (k, !content_type.is_some_and(|c| c.contains("json"))),
    };
    if form {
        let body = names
            .iter()
            .map(|k| {
                let key: String = url::form_urlencoded::byte_serialize(k.as_bytes()).collect();
                format!("{key}={}", fill::PLACEHOLDER)
            })
            .collect::<Vec<_>>()
            .join("&");
        (
            body,
            content_type
                .unwrap_or("application/x-www-form-urlencoded")
                .to_owned(),
        )
    } else {
        let obj: serde_json::Map<String, serde_json::Value> = names
            .iter()
            .map(|k| (k.clone(), serde_json::Value::String(fill::PLACEHOLDER.to_owned())))
            .collect();
        (
            serde_json::Value::Object(obj).to_string(),
            content_type.unwrap_or("application/json").to_owned(),
        )
    }
}

/// Nesting levels of handler strings (`setAttribute('onclick', "…")` inside an
/// `onclick` attribute is level 2).
const MAX_NESTING: u8 = 2;

/// What one script yielded before resolution against the page URL.
#[derive(Default)]
struct Found {
    sites: Vec<Site>,
    /// Unresolved sub-expressions with the nesting level of the script text
    /// their span indexes into (0 = the script itself).
    unresolved: Vec<(u8, Unres)>,
}

/// Parse `js` and collect its request sites; handler strings are mined
/// recursively up to [`MAX_NESTING`].
fn sites(js: &str, level: u8, out: &mut Found) {
    if js.len() > MAX_AST_BYTES || super::shape::too_deep(js) {
        return;
    }
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, js, SourceType::unambiguous())
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            ..ParseOptions::default()
        })
        .parse();
    if parsed.diagnostics.has_errors() || parsed.program.body.is_empty() {
        return;
    }
    let mut census = Bindings::default();
    census.visit_program(&parsed.program);
    let mut miner = Miner {
        consts: consts(census),
        consumed: BTreeSet::new(),
        suppress: false,
        sites: Vec::new(),
        unresolved: Vec::new(),
        depth: Depth::default(),
        nested: Vec::new(),
    };
    miner.visit_program(&parsed.program);
    out.sites.append(&mut miner.sites);
    out.unresolved
        .extend(miner.unresolved.drain(..).map(|u| (level, u)));
    if level < MAX_NESTING {
        for code in &miner.nested {
            sites(code, level.saturating_add(1), out);
        }
    }
}

/// Mine `js` for request sites and resolve them against `base`; `depth` is
/// the page's depth. Empty when the script has syntax errors or exceeds
/// [`MAX_AST_BYTES`]. Unresolved expressions are not reported here; see
/// [`discover_report`].
#[must_use]
pub fn discover(js: &str, base: &Url, depth: u32) -> Vec<DiscoveredEndpoint> {
    let mut out = Vec::new();
    discover_into(
        js,
        base,
        depth,
        ScriptOrigin::ScriptFile,
        &mut out,
        &mut UnresolvedLog::new(0),
    );
    out
}

/// [`discover`] plus the unresolved URL expressions of the script: `origin`
/// says what `js` is, `max_unresolved` bounds the listed outcomes (the rest are
/// counted in [`DiscoveryReport::unresolved_dropped`]).
#[must_use]
pub fn discover_report(
    js: &str,
    base: &Url,
    depth: u32,
    origin: ScriptOrigin,
    max_unresolved: usize,
) -> DiscoveryReport {
    let mut out = Vec::new();
    let mut log = UnresolvedLog::new(max_unresolved);
    discover_into(js, base, depth, origin, &mut out, &mut log);
    log.finish(out)
}

/// Mine `js` into `out` and `log`; `origin` names the text `js` is (handler
/// strings found inside it are [`ScriptOrigin::NestedHandler`]).
pub(super) fn discover_into(
    js: &str,
    base: &Url,
    depth: u32,
    origin: ScriptOrigin,
    out: &mut Vec<DiscoveredEndpoint>,
    log: &mut UnresolvedLog,
) {
    let mut found = Found::default();
    sites(js, 0, &mut found);
    let depth = depth.saturating_add(1);
    for site in found.sites {
        let Some(url) = super::resolve(base, &site.pattern) else {
            continue;
        };
        let (body, content_type) = match &site.body {
            Some(keys) => {
                let (b, ct) = render_body(keys, site.content_type.as_deref());
                (Some(b), Some(ct))
            }
            None => (None, None),
        };
        out.push(DiscoveredEndpoint {
            url,
            method: site.method,
            source: site.source,
            body,
            content_type,
            confidence: Confidence::Structural,
            depth,
            headers: site.headers.into_iter().collect(),
        });
    }
    for (level, u) in found.unresolved {
        log.push(UnresolvedEndpoint {
            source: u.source,
            method: u.method,
            kind: u.hole.kind,
            span: SourceSpan {
                start: u.hole.span.start,
                end: u.hole.span.end,
            },
            origin: if level == 0 {
                origin
            } else {
                ScriptOrigin::NestedHandler
            },
            partial: u.partial,
            depth,
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn base() -> Url {
        Url::parse("https://app.example/dir/page.html").unwrap()
    }

    fn run(js: &str) -> Vec<DiscoveredEndpoint> {
        discover(js, &base(), 0)
    }

    fn paths(found: &[DiscoveredEndpoint]) -> Vec<String> {
        found
            .iter()
            .map(|e| format!("{} {}", e.method, &e.url[url::Position::BeforePath..]))
            .collect()
    }

    #[test]
    fn normalize_drops_unknown_prefixes() {
        assert_eq!(normalize(":base/api/x").as_deref(), Some("/api/x"));
        assert_eq!(normalize("http://:host/x").as_deref(), Some("/x"));
        assert_eq!(normalize("/users/:id").as_deref(), Some("/users/:id"));
        assert_eq!(normalize(":a:b"), None);
        assert_eq!(normalize(":a"), None);
        assert_eq!(normalize("/a b"), None);
        assert_eq!(normalize("wss://h/sock").as_deref(), Some("https://h/sock"));
    }

    #[test]
    fn url_like_is_narrow() {
        assert!(url_like("/api/users"));
        assert!(url_like("./x.json"));
        assert!(url_like("//cdn.example/x.js"));
        assert!(url_like("https://h:8080/p"));
        assert!(!url_like("/"));
        assert!(!url_like("/ "));
        assert!(!url_like("/a b"));
        assert!(!url_like("fetch('/x')"));
        assert!(!url_like("/*comment*/"));
        assert!(!url_like("text/plain"));
    }

    #[test]
    fn fetch_with_options() {
        let got = run(
            r"fetch('/api/items', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Token': t},
               body: JSON.stringify({name: n, qty: 1})});",
        );
        assert_eq!(got.len(), 1, "{:?}", paths(&got));
        let e = &got[0];
        assert_eq!(e.method, Method::POST);
        assert_eq!(e.url.path(), "/api/items");
        assert_eq!(e.body.as_deref(), Some(r#"{"name":"crawlx","qty":"crawlx"}"#));
        assert_eq!(e.content_type.as_deref(), Some("application/json"));
        assert_eq!(e.headers, vec!["content-type", "x-token"]);
        assert_eq!(e.source, JS_FETCH);
        assert_eq!(e.confidence, Confidence::Structural);
        assert_eq!(e.depth, 1);
    }

    #[test]
    fn concatenation_and_templates_become_patterns() {
        let got = run(
            "fetch('/users/' + id + '/posts');\nfetch(`/api/${v}/items?q=${encodeURIComponent(q)}`);\nfetch(base + '/rel');\nfetch('http://' + host + '/x');",
        );
        assert_eq!(
            paths(&got),
            vec![
                "GET /users/:id/posts",
                "GET /api/:v/items?q=:q",
                "GET /rel",
                "GET /x"
            ]
        );
    }

    #[test]
    fn constants_are_inlined() {
        let got = run(
            "var mazeDomain = \"http://h.test/\";\nvar mazePath = \"g32/x.found\";\nvar mazeFull = mazeDomain + mazePath;",
        );
        // the origin literal is a URL of its own; the concatenation resolves through both constants
        assert_eq!(paths(&got), vec!["GET /", "GET /g32/x.found"]);
        assert_eq!(got[1].url.host_str(), Some("h.test"));
        assert_eq!(got[1].source, JS_STRING);
        // reassigned or redeclared names stay placeholders
        let got =
            run("var a = '/p/'; a = '/q/'; fetch(a + 'z');\nlet b = '/r/'; { let b = 1; }\nfetch(b + 'z');");
        assert_eq!(paths(&got), vec!["GET /p/", "GET /q/", "GET /r/"]);
        // self-referential chains terminate
        let got = run("var a = b + '/x'; var b = a + '/y'; fetch(a);");
        assert!(paths(&got).iter().all(|p| p.contains("/x")), "{:?}", paths(&got));
    }

    #[test]
    fn matcher_table() {
        let js = r"
            axios.post('/a/1', {k: 1}, {headers: {Authorization: 'x'}});
            axios({url: '/a/2', method: 'put', data: {z: 2}});
            axios.get('/a/3');
            var xhr = new XMLHttpRequest(); xhr.open('DELETE', '/x/1'); xhr.open(m, '/x/2');
            $.ajax({url: '/j/1', type: 'post', data: {a: 1, b: 2}});
            $.ajax('/j/2', {method: 'PATCH'});
            $.post('/j/3', {f: 1}); $.get('/j/4'); jQuery.getJSON('/j/5');
            navigator.sendBeacon('/b/1', payload);
            new URL('/u/1', 'https://other.test/base/'); new URL('u/2');
            location.assign('/l/1'); window.location.replace('/l/2'); location.href = '/l/3';
            document.location = '/l/4'; window.location.href = '/l/5';
            window.open('/o/1'); open('/o/2');
            history.pushState({}, '', '/h/1'); window.history.replaceState(null, '', '/h/2');
            new WebSocket('wss://app.example/ws/1'); new WebSocket('/ws/2');
            new EventSource('/es/1');
            fetch(new Request('/r/1', {method: 'HEAD'}));
            this.http.get('/g/1'); this.http.post('/g/2', {q: 1}); cache.get('key');
        ";
        let got = run(js);
        let p = paths(&got);
        let want = [
            "POST /a/1",
            "PUT /a/2",
            "GET /a/3",
            "DELETE /x/1",
            "GET /x/2",
            "POST /j/1",
            "PATCH /j/2",
            "POST /j/3",
            "GET /j/4",
            "GET /j/5",
            "POST /b/1",
            "GET /u/1",
            "GET /dir/u/2",
            "GET /l/1",
            "GET /l/2",
            "GET /l/3",
            "GET /l/4",
            "GET /l/5",
            "GET /o/1",
            "GET /o/2",
            "GET /h/1",
            "GET /h/2",
            "GET /ws/1",
            "GET /ws/2",
            "GET /es/1",
            "HEAD /r/1",
            "GET /g/1",
            "POST /g/2",
        ];
        assert_eq!(p, want.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        let u1 = got.iter().find(|e| e.url.path() == "/u/1").unwrap();
        assert_eq!(u1.url.host_str(), Some("other.test"));
        let ws = got.iter().find(|e| e.url.path() == "/ws/1").unwrap();
        assert_eq!(ws.url.scheme(), "https");
        let a1 = got.iter().find(|e| e.url.path() == "/a/1").unwrap();
        assert_eq!(a1.body.as_deref(), Some(r#"{"k":"crawlx"}"#));
        assert_eq!(a1.headers, vec!["authorization"]);
        let j1 = got.iter().find(|e| e.url.path() == "/j/1").unwrap();
        assert_eq!(j1.body.as_deref(), Some("a=crawlx&b=crawlx"));
        assert_eq!(
            j1.content_type.as_deref(),
            Some("application/x-www-form-urlencoded")
        );
        let x2 = got.iter().find(|e| e.url.path() == "/x/2").unwrap();
        assert_eq!(x2.source, JS_XHR);
        assert!(got.iter().all(|e| e.source.tag == "js"));
    }

    #[test]
    fn post_sites_do_not_leak_a_get_twin() {
        let got = run("fetch('/only-post', {method: 'POST'});");
        assert_eq!(paths(&got), vec!["POST /only-post"]);
    }

    #[test]
    fn string_catch_all_and_noise() {
        let got = run(
            "var model = { detailUrl: '/detail.found' };\nvar mime = 'text/plain';\nvar slash = '/';\nvar msg = 'see /docs for help';\nvar rx = /\\/api\\//;\nvar tpl = `/t/${a}`;\nvar n = 1 + 2;",
        );
        assert_eq!(paths(&got), vec!["GET /detail.found", "GET /t/:a"]);
    }

    #[test]
    fn parse_failure_and_size_cap_yield_nothing() {
        assert!(run("fetch('/x' {").is_empty());
        assert!(run("").is_empty());
        let big = format!("fetch('/x');{}", " ".repeat(MAX_AST_BYTES));
        assert!(run(&big).is_empty());
    }

    #[test]
    fn event_handler_bodies_parse() {
        let got = run("fetch('/attr.found', {method: 'POST'}); return false;");
        assert_eq!(paths(&got), vec!["POST /attr.found"]);
    }

    #[test]
    fn handler_strings_are_mined_two_levels_deep() {
        let got = run(r#"var b = document.createElement('button');
               b.setAttribute('onclick', "fetch('/nested/one.found')");
               b.setAttribute('onClick', "this.setAttribute('onclick', \"fetch('/nested/two.found')\")");
               b.setAttribute('data-x', "fetch('/not-a-handler.found')");"#);
        assert_eq!(
            paths(&got),
            vec!["GET /nested/one.found", "GET /nested/two.found"]
        );
    }

    #[test]
    fn placeholder_only_values_are_dropped() {
        let got = run("fetch(url); fetch(a + b); fetch(`${x}`); fetch(cfg.endpoint); fetch(1 + 2);");
        assert!(got.is_empty(), "{:?}", paths(&got));
    }
}
