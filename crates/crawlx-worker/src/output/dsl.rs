//! Output condition DSL (the `-mdc/-match-condition` and `-fdc/-filter-condition` compatibility flags).
//!
//! The reference tool evaluates a govaluate-style expression against the flattened
//! JSONL result (`pkg/output/output.go` `evalDslExpr`, `resultToMap`; README.md:1075-1115).
//! This is an own implementation of the subset those expressions use, over the same record
//! the JSONL writer produces:
//!
//! * literals: `"text"` / `'text'` (escapes `\\ \" \' \n \r \t`), numbers (`200`, `-1`,
//!   `0.5`), `true`, `false`;
//! * variables: dotted JSONL paths (`status_code` is the bare form of `response.status_code`,
//!   `request.method`, `response.headers.content-type`, `error`). A bare name resolves in
//!   this order: exact path, `url` (= `request.endpoint`), then the top level, `response.*`,
//!   `request.*`, `response.headers.*` and `response.knowledgebase.*` with names compared in
//!   `snake_case` (`content_type` = `content-type`, `page_type` = `PageType`), so the reference's
//!   flattened names (`endpoint`, `technologies`, `status_code`) keep working. `response`
//!   wins over `request` for names both have (`body`, `raw`), as in the reference;
//! * operators, loosest first: `||`, `&&`, `==` `!=` and infix `contains`, `<` `<=` `>`
//!   `>=`, unary `!`, parentheses. `&&`/`||` short-circuit;
//! * functions: the table in [`functions`]; [`supported_functions`] lists every name with its
//!   argument count and [`UNSUPPORTED_FUNCTIONS`] every function of the pinned reference DSL
//!   this language lacks, with the reason. Names follow the reference (`contains_any`, `to_lower`,
//!   `trim_space`, `regex_all`, `base64_decode`, `sha256`, ...) and the underscore-free spelling the
//!   reference also registers (`containsany`) works too. Arguments are stringified; a list
//!   stringifies as `[a b]` with object elements shown by their `name`, so
//!   `contains(to_lower(technologies), "php")` works. Every function is pure (no clock, environment,
//!   network or random source) and bounded: operands and results over [`MAX_VALUE_LEN`] bytes
//!   and lists over [`MAX_LIST_LEN`] elements evaluate to no value, which makes the condition `false`.
//!   A condition never evaluates its text as code.
//!
//! The function semantics follow the pinned release of the reference DSL's function library
//! (v0.8.21, selected by the reference tool's
//! `35267ac5c8ff1db9694a319d0eb466ed97b0969f` `go.mod`), an MIT-licensed upstream (see
//! THIRD_PARTY_NOTICES.md). The trim family follows its Go string functions: cutsets contain Unicode
//! characters, not substrings; prefix/suffix removal happens only once; `trim_space` uses Unicode
//! whitespace; results never grow. Case mapping is per character like Go's, not the full
//! (multi-character, context-sensitive) mapping. A function name in neither table is a
//! [`DslError::UnknownFunction`] parse error and one in the second table a
//! [`DslError::UnsupportedFunction`], both with the byte position of the name.
//!
//! Evaluation never fails loudly: as in the reference, a reference to an unknown variable, a type
//! mismatch (`!` of a string, `<` between a string and a number) or a non-boolean result
//! makes the whole condition `false` (a match condition does not match, a filter condition
//! does not filter). `==` between different types is `false`, `!=` is `true`.
//!
//! Regexes are the linear-time `regex` crate (no backtracking), at most
//! [`MAX_REGEX_LEN`] bytes with a bounded compiled size; a literal pattern is compiled at
//! parse time so a bad one is a [`DslError::Regex`].

mod functions;

use super::jsonl::Record;
use functions::{apply, unsupported_reason, Func};
pub use functions::{supported_functions, FunctionInfo, MAX_LIST_LEN, MAX_VALUE_LEN, UNSUPPORTED_FUNCTIONS};
use regex::{Regex, RegexBuilder};
use serde_json::Value as Json;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::str::FromStr;
use thiserror::Error;

/// Longest accepted condition source in bytes.
pub const MAX_SOURCE_LEN: usize = 4096;
/// Longest accepted `regex()` pattern in bytes.
pub const MAX_REGEX_LEN: usize = 512;
/// Longest stringified input accepted by the trim family, in bytes.
pub const MAX_TRIM_INPUT_LEN: usize = MAX_VALUE_LEN;
/// Longest stringified trim cutset, prefix or suffix, in bytes.
pub const MAX_TRIM_CUTSET_LEN: usize = 512;
/// Deepest nesting of parentheses, `!` and function calls.
const MAX_DEPTH: usize = 64;
/// Compiled-size bound of a `regex()` pattern.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// A condition that does not parse. `position` is a byte offset into the source.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum DslError {
    /// The source is empty or blank.
    #[error("condition is empty")]
    Empty,
    /// The source is longer than [`MAX_SOURCE_LEN`].
    #[error("condition is {len} bytes, longer than {MAX_SOURCE_LEN}")]
    TooLong {
        /// Source length in bytes.
        len: usize,
    },
    /// A character that starts no token.
    #[error("unexpected character `{ch}` at byte {position}")]
    UnexpectedChar {
        /// Byte offset of the character.
        position: usize,
        /// The character.
        ch: char,
    },
    /// A string literal without its closing quote.
    #[error("unterminated string starting at byte {position}")]
    UnterminatedString {
        /// Byte offset of the opening quote.
        position: usize,
    },
    /// A number literal that is not a finite number.
    #[error("invalid number `{text}` at byte {position}")]
    InvalidNumber {
        /// Byte offset of the literal.
        position: usize,
        /// The literal text.
        text: String,
    },
    /// A token that does not fit the grammar here.
    #[error("expected {expected} at byte {position}, found {found}")]
    Unexpected {
        /// Byte offset of the token.
        position: usize,
        /// What the grammar needed.
        expected: &'static str,
        /// What was there (`end of condition` at the end).
        found: String,
    },
    /// A call of a function the DSL does not have.
    #[error("unknown function `{name}` at byte {position}")]
    UnknownFunction {
        /// Byte offset of the name.
        position: usize,
        /// The name.
        name: String,
    },
    /// A function of the reference DSL that this language does not have.
    #[error("function `{name}` at byte {position} is not supported: {reason}")]
    UnsupportedFunction {
        /// Byte offset of the name.
        position: usize,
        /// The name.
        name: String,
        /// Why the language lacks it.
        reason: &'static str,
    },
    /// A call with the wrong number of arguments.
    #[error("function `{name}` at byte {position} takes {expected} argument(s), got {got}")]
    Arity {
        /// Byte offset of the name.
        position: usize,
        /// The function.
        name: &'static str,
        /// `2`, `2 to 3` or `at least 2`.
        expected: &'static str,
        /// Arguments given.
        got: usize,
    },
    /// A literal `regex()` pattern that is too long or does not compile.
    #[error("invalid regex at byte {position}")]
    Regex {
        /// Byte offset of the `regex` call.
        position: usize,
        /// Why it was rejected.
        #[source]
        source: RegexProblem,
    },
    /// Nesting deeper than the parser accepts.
    #[error("condition nested deeper than {MAX_DEPTH} levels at byte {position}")]
    TooDeep {
        /// Byte offset where the limit was hit.
        position: usize,
    },
}

/// Why a `regex()` pattern was rejected.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum RegexProblem {
    /// Longer than [`MAX_REGEX_LEN`] bytes.
    #[error("pattern is {len} bytes, longer than {MAX_REGEX_LEN}")]
    TooLong {
        /// Pattern length in bytes.
        len: usize,
    },
    /// Does not compile or exceeds the size bound.
    #[error("pattern does not compile")]
    Compile(#[from] regex::Error),
}

impl DslError {
    /// Byte offset the error points at; `None` for errors about the whole source.
    #[must_use]
    pub const fn position(&self) -> Option<usize> {
        match self {
            Self::Empty | Self::TooLong { .. } => None,
            Self::UnexpectedChar { position, .. }
            | Self::UnterminatedString { position }
            | Self::InvalidNumber { position, .. }
            | Self::Unexpected { position, .. }
            | Self::UnknownFunction { position, .. }
            | Self::UnsupportedFunction { position, .. }
            | Self::Arity { position, .. }
            | Self::Regex { position, .. }
            | Self::TooDeep { position } => Some(*position),
        }
    }
}

fn build_regex(pattern: &str) -> Result<Regex, RegexProblem> {
    if pattern.len() > MAX_REGEX_LEN {
        return Err(RegexProblem::TooLong { len: pattern.len() });
    }
    Ok(RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()?)
}

// ---------------------------------------------------------------------------------------
// Lexer

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Num(f64),
    LParen,
    RParen,
    Comma,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    AndAnd,
    OrOr,
    Bang,
    End,
}

impl Tok {
    fn describe(&self) -> String {
        match self {
            Self::Ident(s) => format!("`{s}`"),
            Self::Str(_) => "a string".to_owned(),
            Self::Num(n) => format!("`{n}`"),
            Self::LParen => "`(`".to_owned(),
            Self::RParen => "`)`".to_owned(),
            Self::Comma => "`,`".to_owned(),
            Self::EqEq => "`==`".to_owned(),
            Self::NotEq => "`!=`".to_owned(),
            Self::Lt => "`<`".to_owned(),
            Self::Le => "`<=`".to_owned(),
            Self::Gt => "`>`".to_owned(),
            Self::Ge => "`>=`".to_owned(),
            Self::AndAnd => "`&&`".to_owned(),
            Self::OrOr => "`||`".to_owned(),
            Self::Bang => "`!`".to_owned(),
            Self::End => "end of condition".to_owned(),
        }
    }
}

struct Token {
    tok: Tok,
    pos: usize,
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

fn lex(src: &str) -> Result<Vec<Token>, DslError> {
    let mut out = Vec::new();
    let mut chars = src.char_indices().peekable();
    while let Some(&(pos, c)) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let two = |next: char| src[pos..].chars().nth(1) == Some(next);
        let (tok, width) = match c {
            '(' => (Tok::LParen, 1),
            ')' => (Tok::RParen, 1),
            ',' => (Tok::Comma, 1),
            '=' if two('=') => (Tok::EqEq, 2),
            '!' if two('=') => (Tok::NotEq, 2),
            '!' => (Tok::Bang, 1),
            '<' if two('=') => (Tok::Le, 2),
            '<' => (Tok::Lt, 1),
            '>' if two('=') => (Tok::Ge, 2),
            '>' => (Tok::Gt, 1),
            '&' if two('&') => (Tok::AndAnd, 2),
            '|' if two('|') => (Tok::OrOr, 2),
            '"' | '\'' => {
                chars.next();
                let mut text = String::new();
                let mut closed = false;
                while let Some((_, ch)) = chars.next() {
                    if ch == c {
                        closed = true;
                        break;
                    }
                    if ch == '\\' {
                        match chars.next() {
                            Some((_, 'n')) => text.push('\n'),
                            Some((_, 'r')) => text.push('\r'),
                            Some((_, 't')) => text.push('\t'),
                            Some((_, other)) => text.push(other),
                            None => break,
                        }
                    } else {
                        text.push(ch);
                    }
                }
                if !closed {
                    return Err(DslError::UnterminatedString { position: pos });
                }
                out.push(Token {
                    tok: Tok::Str(text),
                    pos,
                });
                continue;
            }
            d if d.is_ascii_digit()
                || (d == '-' && src[pos + 1..].starts_with(|n: char| n.is_ascii_digit())) =>
            {
                let mut end = pos + 1;
                for (i, ch) in src[pos + 1..].char_indices() {
                    if ch.is_ascii_digit() || ch == '.' {
                        end = pos + 1 + i + ch.len_utf8();
                    } else {
                        break;
                    }
                }
                let text = &src[pos..end];
                let value = f64::from_str(text)
                    .ok()
                    .filter(|v| v.is_finite())
                    .ok_or_else(|| DslError::InvalidNumber {
                        position: pos,
                        text: text.to_owned(),
                    })?;
                for _ in text.chars() {
                    chars.next();
                }
                out.push(Token {
                    tok: Tok::Num(value),
                    pos,
                });
                continue;
            }
            i if is_ident_start(i) => {
                let mut end = pos;
                for (j, ch) in src[pos..].char_indices() {
                    if (j == 0 && is_ident_start(ch)) || (j > 0 && is_ident_continue(ch)) {
                        end = pos + j + ch.len_utf8();
                    } else {
                        break;
                    }
                }
                let text = &src[pos..end];
                for _ in text.chars() {
                    chars.next();
                }
                out.push(Token {
                    tok: Tok::Ident(text.to_owned()),
                    pos,
                });
                continue;
            }
            other => {
                return Err(DslError::UnexpectedChar {
                    position: pos,
                    ch: other,
                })
            }
        };
        for _ in 0..width {
            chars.next();
        }
        out.push(Token { tok, pos });
    }
    out.push(Token {
        tok: Tok::End,
        pos: src.len(),
    });
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// AST

#[derive(Clone, Debug, PartialEq)]
enum Val {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    List(Vec<Val>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
}

#[derive(Clone, Debug)]
enum Expr {
    Lit(Val),
    Var(String),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cmp(CmpOp, Box<Expr>, Box<Expr>),
    Call {
        func: Func,
        args: Vec<Expr>,
        /// A literal regex pattern argument, compiled at parse time.
        compiled: Option<Regex>,
    },
}

// ---------------------------------------------------------------------------------------
// Parser

struct Parser {
    toks: Vec<Token>,
    idx: usize,
    depth: usize,
    vars: BTreeSet<String>,
}

impl Parser {
    fn peek(&self) -> &Token {
        // `lex` always ends the stream with `End`, and `bump` never passes it.
        &self.toks[self.idx.min(self.toks.len().saturating_sub(1))]
    }

    fn bump(&mut self) -> usize {
        let pos = self.peek().pos;
        if self.idx + 1 < self.toks.len() {
            self.idx += 1;
        }
        pos
    }

    fn unexpected(&self, expected: &'static str) -> DslError {
        let t = self.peek();
        DslError::Unexpected {
            position: t.pos,
            expected,
            found: t.tok.describe(),
        }
    }

    fn enter(&mut self) -> Result<(), DslError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(DslError::TooDeep {
                position: self.peek().pos,
            });
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn or(&mut self) -> Result<Expr, DslError> {
        let mut left = self.and()?;
        while self.peek().tok == Tok::OrOr {
            self.bump();
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, DslError> {
        let mut left = self.equality()?;
        while self.peek().tok == Tok::AndAnd {
            self.bump();
            let right = self.equality()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn equality(&mut self) -> Result<Expr, DslError> {
        let mut left = self.relational()?;
        loop {
            let op = match &self.peek().tok {
                Tok::EqEq => CmpOp::Eq,
                Tok::NotEq => CmpOp::Ne,
                Tok::Ident(name) if name == "contains" => CmpOp::Contains,
                _ => return Ok(left),
            };
            self.bump();
            let right = self.relational()?;
            left = Expr::Cmp(op, Box::new(left), Box::new(right));
        }
    }

    fn relational(&mut self) -> Result<Expr, DslError> {
        let mut left = self.unary()?;
        loop {
            let op = match self.peek().tok {
                Tok::Lt => CmpOp::Lt,
                Tok::Le => CmpOp::Le,
                Tok::Gt => CmpOp::Gt,
                Tok::Ge => CmpOp::Ge,
                _ => return Ok(left),
            };
            self.bump();
            let right = self.unary()?;
            left = Expr::Cmp(op, Box::new(left), Box::new(right));
        }
    }

    fn unary(&mut self) -> Result<Expr, DslError> {
        if self.peek().tok == Tok::Bang {
            self.enter()?;
            self.bump();
            let inner = self.unary()?;
            self.leave();
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, DslError> {
        let pos = self.peek().pos;
        match self.peek().tok.clone() {
            Tok::Num(n) => {
                self.bump();
                Ok(Expr::Lit(Val::Num(n)))
            }
            Tok::Str(s) => {
                self.bump();
                Ok(Expr::Lit(Val::Str(s)))
            }
            Tok::LParen => {
                self.enter()?;
                self.bump();
                let inner = self.or()?;
                if self.peek().tok != Tok::RParen {
                    return Err(self.unexpected("`)`"));
                }
                self.bump();
                self.leave();
                Ok(inner)
            }
            Tok::Ident(name) => {
                self.bump();
                if self.peek().tok == Tok::LParen {
                    return self.call(&name, pos);
                }
                match name.as_str() {
                    "true" => Ok(Expr::Lit(Val::Bool(true))),
                    "false" => Ok(Expr::Lit(Val::Bool(false))),
                    _ => {
                        self.vars.insert(name.clone());
                        Ok(Expr::Var(name))
                    }
                }
            }
            _ => Err(self.unexpected("a value, variable, function call or `(`")),
        }
    }

    fn call(&mut self, name: &str, pos: usize) -> Result<Expr, DslError> {
        let Some(func) = Func::lookup(name) else {
            return Err(match unsupported_reason(name) {
                Some(reason) => DslError::UnsupportedFunction {
                    position: pos,
                    name: name.to_owned(),
                    reason,
                },
                None => DslError::UnknownFunction {
                    position: pos,
                    name: name.to_owned(),
                },
            });
        };
        self.enter()?;
        self.bump(); // `(`
        let mut args = Vec::new();
        if self.peek().tok == Tok::RParen {
            self.bump();
        } else {
            loop {
                args.push(self.or()?);
                match self.peek().tok {
                    Tok::Comma => {
                        self.bump();
                    }
                    Tok::RParen => {
                        self.bump();
                        break;
                    }
                    _ => return Err(self.unexpected("`,` or `)`")),
                }
            }
        }
        self.leave();
        let (min, max) = func.arity();
        if args.len() < min || args.len() > max {
            return Err(DslError::Arity {
                position: pos,
                name: func.name(),
                expected: func.arity_text(),
                got: args.len(),
            });
        }
        let compiled = match func.pattern_argument().and_then(|at| args.get(at)) {
            Some(Expr::Lit(Val::Str(pattern))) => {
                Some(build_regex(pattern).map_err(|source| DslError::Regex {
                    position: pos,
                    source,
                })?)
            }
            _ => None,
        };
        Ok(Expr::Call { func, args, compiled })
    }
}

// ---------------------------------------------------------------------------------------
// Evaluation

/// Why one evaluation produced no value; the condition is then `false`.
#[derive(Debug, Error)]
enum EvalError {
    #[error("unknown variable `{0}`")]
    UnknownVariable(String),
    #[error("type mismatch in `{0}`")]
    Type(&'static str),
    #[error("regex pattern rejected")]
    Regex,
    #[error("operand or result exceeds the size limit")]
    Limit,
    #[error("argument the function rejects")]
    Argument,
}

fn snake(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    let mut prev_lower = false;
    for ch in name.chars() {
        if ch == '-' {
            out.push('_');
            prev_lower = false;
        } else if ch.is_ascii_uppercase() {
            if prev_lower {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_lower = false;
        } else {
            out.push(ch);
            prev_lower = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        }
    }
    out
}

fn by_path<'a>(root: &'a Json, name: &str) -> Option<&'a Json> {
    let mut cur = root;
    for seg in name.split('.') {
        cur = cur.get(seg).or_else(|| {
            let lower = seg.to_ascii_lowercase();
            if lower == seg {
                None
            } else {
                cur.get(&lower)
            }
        })?;
    }
    Some(cur)
}

fn in_object<'a>(scope: Option<&'a Json>, wanted: &str) -> Option<&'a Json> {
    scope?
        .as_object()?
        .iter()
        .find(|(k, _)| snake(k) == wanted)
        .map(|(_, v)| v)
}

/// The JSON value `name` refers to in a record (see the module docs for the rules).
fn resolve<'a>(root: &'a Json, name: &str) -> Option<&'a Json> {
    if let Some(v) = by_path(root, name) {
        return Some(v);
    }
    if name == "url" {
        return by_path(root, "request.endpoint");
    }
    if name.contains('.') {
        return None;
    }
    let wanted = snake(name);
    let response = root.get("response");
    in_object(Some(root), &wanted)
        .or_else(|| in_object(response, &wanted))
        .or_else(|| in_object(root.get("request"), &wanted))
        .or_else(|| in_object(response.and_then(|r| r.get("headers")), &wanted))
        .or_else(|| in_object(response.and_then(|r| r.get("knowledgebase")), &wanted))
}

fn val_of(v: &Json) -> Val {
    match v {
        Json::Null => Val::Null,
        Json::Bool(b) => Val::Bool(*b),
        Json::Number(n) => n.as_f64().map_or(Val::Null, Val::Num),
        Json::String(s) => Val::Str(s.clone()),
        Json::Array(items) => Val::List(items.iter().map(element_val).collect()),
        Json::Object(_) => Val::Str(v.to_string()),
    }
}

/// A list element: an object shows its `name` (technologies), anything else as itself.
fn element_val(v: &Json) -> Val {
    match v.get("name").and_then(Json::as_str) {
        Some(name) if v.is_object() => Val::Str(name.to_owned()),
        _ => val_of(v),
    }
}

fn stringify(v: &Val) -> String {
    match v {
        Val::Null => String::new(),
        Val::Bool(b) => b.to_string(),
        Val::Num(n) => n.to_string(),
        Val::Str(s) => s.clone(),
        Val::List(items) => {
            let parts: Vec<String> = items.iter().map(stringify).collect();
            format!("[{}]", parts.join(" "))
        }
    }
}

fn equal(a: &Val, b: &Val) -> bool {
    match (a, b) {
        (Val::Num(x), Val::Num(y)) => x.partial_cmp(y) == Some(Ordering::Equal),
        (Val::List(x), Val::List(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| equal(p, q)),
        _ => a == b,
    }
}

fn order(a: &Val, b: &Val, what: &'static str) -> Result<Ordering, EvalError> {
    match (a, b) {
        (Val::Num(x), Val::Num(y)) => x.partial_cmp(y).ok_or(EvalError::Type(what)),
        (Val::Str(x), Val::Str(y)) => Ok(x.cmp(y)),
        _ => Err(EvalError::Type(what)),
    }
}

fn truth(v: Val, what: &'static str) -> Result<bool, EvalError> {
    match v {
        Val::Bool(b) => Ok(b),
        _ => Err(EvalError::Type(what)),
    }
}

fn eval(expr: &Expr, root: &Json) -> Result<Val, EvalError> {
    match expr {
        Expr::Lit(v) => Ok(v.clone()),
        Expr::Var(name) => resolve(root, name)
            .map(val_of)
            .ok_or_else(|| EvalError::UnknownVariable(name.clone())),
        Expr::Not(inner) => Ok(Val::Bool(!truth(eval(inner, root)?, "!")?)),
        Expr::And(l, r) => {
            if !truth(eval(l, root)?, "&&")? {
                return Ok(Val::Bool(false));
            }
            Ok(Val::Bool(truth(eval(r, root)?, "&&")?))
        }
        Expr::Or(l, r) => {
            if truth(eval(l, root)?, "||")? {
                return Ok(Val::Bool(true));
            }
            Ok(Val::Bool(truth(eval(r, root)?, "||")?))
        }
        Expr::Cmp(op, l, r) => {
            let (a, b) = (eval(l, root)?, eval(r, root)?);
            Ok(Val::Bool(match op {
                CmpOp::Eq => equal(&a, &b),
                CmpOp::Ne => !equal(&a, &b),
                CmpOp::Contains => stringify(&a).contains(&stringify(&b)),
                CmpOp::Lt => order(&a, &b, "<")?.is_lt(),
                CmpOp::Le => order(&a, &b, "<=")?.is_le(),
                CmpOp::Gt => order(&a, &b, ">")?.is_gt(),
                CmpOp::Ge => order(&a, &b, ">=")?.is_ge(),
            }))
        }
        Expr::Call { func, args, compiled } => call(*func, args, compiled.as_ref(), root),
    }
}

fn call(func: Func, args: &[Expr], compiled: Option<&Regex>, root: &Json) -> Result<Val, EvalError> {
    let values = args
        .iter()
        .map(|a| eval(a, root))
        .collect::<Result<Vec<_>, _>>()?;
    apply(func, values, compiled)
}

// ---------------------------------------------------------------------------------------
// Public type

/// A parsed `-mdc` / `-fdc` condition. See the [module docs](self) for the language.
#[derive(Clone, Debug)]
pub struct Dsl {
    source: String,
    root: Expr,
    variables: Vec<String>,
}

impl Dsl {
    /// Parse `source`.
    ///
    /// # Errors
    /// [`DslError`] with the byte position of the problem for a syntax error, an unknown
    /// function, a wrong argument count, or a literal `regex()` pattern that is too long or
    /// does not compile.
    pub fn parse(source: &str) -> Result<Self, DslError> {
        if source.trim().is_empty() {
            return Err(DslError::Empty);
        }
        if source.len() > MAX_SOURCE_LEN {
            return Err(DslError::TooLong { len: source.len() });
        }
        let mut parser = Parser {
            toks: lex(source)?,
            idx: 0,
            depth: 0,
            vars: BTreeSet::new(),
        };
        let root = parser.or()?;
        if parser.peek().tok != Tok::End {
            return Err(parser.unexpected("an operator or end of condition"));
        }
        Ok(Self {
            source: source.to_owned(),
            root,
            variables: parser.vars.into_iter().collect(),
        })
    }

    /// The condition text as given.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The variable names the condition reads, sorted and deduplicated.
    #[must_use]
    pub fn variables(&self) -> &[String] {
        &self.variables
    }

    /// Does the condition read the response body (`body` / `response.body`)? The exporter
    /// loads bodies for a condition that does.
    #[must_use]
    pub fn reads_body(&self) -> bool {
        self.variables
            .iter()
            .any(|v| matches!(v.as_str(), "body" | "response.body"))
    }

    /// Evaluate against `record`; `true` only when the condition evaluates to boolean true.
    /// Unknown variables, type mismatches and non-boolean results are `false`.
    #[must_use]
    pub fn eval(&self, record: &Record) -> bool {
        serde_json::to_value(record).is_ok_and(|json| self.eval_value(&json))
    }

    /// [`Dsl::eval`] over an already serialized record (the JSON the JSONL writer emits).
    #[must_use]
    pub fn eval_value(&self, record: &Json) -> bool {
        match eval(&self.root, record) {
            Ok(Val::Bool(value)) => value,
            Ok(_) => false,
            Err(_) => {
                // Conditions may contain secrets; never log source text or operands.
                tracing::debug!("condition did not evaluate");
                false
            }
        }
    }
}

impl FromStr for Dsl {
    type Err = DslError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    fn record() -> Json {
        json!({
            "timestamp": "2023-11-14T22:13:20Z",
            "request": {
                "method": "GET",
                "endpoint": "https://e.com/admin/default.php?x=1",
                "tag": "a",
                "custom_fields": {"email": ["a@e.com"]}
            },
            "response": {
                "status_code": 200,
                "headers": {"content-type": "text/html; charset=utf-8", "server": "nginx"},
                "body": "<h1>Welcome</h1>",
                "content_length": 16,
                "technologies": [{"name": "PHP", "evidence": "x"}, {"name": "Nginx", "evidence": "y"}],
                "page_type": "login",
                "knowledgebase": {"PageType": "login"}
            }
        })
    }

    fn eval(src: &str) -> bool {
        Dsl::parse(src).unwrap().eval_value(&record())
    }

    #[test]
    fn trim_family_matches_pinned_string_semantics() {
        // the pinned upstream string functions delegate to Go strings.
        let cases = [
            ("trim('abbaHelloaba', 'ab') == 'Hello'", true),
            ("trim_left('abbaHelloaba', 'ab') == 'Helloaba'", true),
            ("trim_right('abbaHelloaba', 'ab') == 'abbaHello'", true),
            ("trim('é🙂Hello🙂é', '🙂é') == 'Hello'", true),
            ("trim('abab', 'ab') == ''", true),
            ("trim('', 'ab') == ''", true),
            ("trim('abc', '') == 'abc'", true),
            ("trim_left('abc', '') == 'abc'", true),
            ("trim_right('abc', '') == 'abc'", true),
            ("trim_prefix('ababHello', 'ab') == 'abHello'", true),
            ("trim_suffix('Helloabab', 'ab') == 'Helloab'", true),
            ("trim_prefix('baHello', 'ab') == 'baHello'", true),
            ("trim_suffix('Helloba', 'ab') == 'Helloba'", true),
            ("trim_prefix('ééHello', 'é') == 'éHello'", true),
            ("trim_suffix('Hello🙂🙂', '🙂') == 'Hello🙂'", true),
            ("trim_prefix('abc', '') == 'abc'", true),
            ("trim_suffix('abc', '') == 'abc'", true),
            ("trim_prefix('', 'abc') == ''", true),
            ("trim_suffix('', 'abc') == ''", true),
            ("trim_space('  a b  ') == 'a b'", true),
            ("trim_space('') == ''", true),
            ("trim_prefix(status_code, 2) == '00'", true),
            ("trim_suffix(true, 'ue') == 'tr'", true),
            ("trim_space(trim(body, '<>h1/')) == 'Welcome'", true),
            ("trim_space(body) == 'Welcome'", false),
            ("trim_space(missing) == ''", false),
            ("trim_space(body)", false),
        ];
        for (source, expected) in cases {
            assert_eq!(eval(source), expected, "{source}");
        }
        let condition = Dsl::parse("trim_space(response.body) == 'Welcome'").unwrap();
        assert!(condition.reads_body());
        assert_eq!(condition.variables(), ["response.body"]);
    }

    #[test]
    fn trim_space_uses_go_unicode_whitespace_not_ascii_control_ranges() {
        let whitespace = "\t\n\u{b}\u{c}\r \u{85}\u{a0}\u{1680}\u{2000}\u{2001}\u{2002}\
            \u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\
            \u{2028}\u{2029}\u{202f}\u{205f}\u{3000}";
        let condition = Dsl::parse("trim_space(body) == 'text'").unwrap();
        let record = json!({"response": {"body": format!("{whitespace}text{whitespace}")}});
        assert!(condition.eval_value(&record));
        for not_whitespace in ['\u{1c}', '\u{200b}', '\u{feff}'] {
            let record = json!({"response": {"body": format!("{not_whitespace}text")}});
            assert!(!condition.eval_value(&record));
        }
    }

    #[test]
    fn trim_family_enforces_exact_arity() {
        for name in ["trim", "trim_left", "trim_right", "trim_prefix", "trim_suffix"] {
            for args in ["", "'a'", "'a', 'b', 'c'"] {
                let error = Dsl::parse(&format!("{name}({args})")).unwrap_err();
                assert!(matches!(
                    error,
                    DslError::Arity {
                        position: 0,
                        expected: "2",
                        ..
                    }
                ));
            }
        }
        for args in ["", "'a', 'b'"] {
            let error = Dsl::parse(&format!("trim_space({args})")).unwrap_err();
            assert!(matches!(
                error,
                DslError::Arity {
                    position: 0,
                    expected: "1",
                    ..
                }
            ));
        }
    }

    #[test]
    fn trim_family_limits_stringified_bytes_and_propagates_failure() {
        for name in [
            "trim",
            "trim_left",
            "trim_right",
            "trim_space",
            "trim_prefix",
            "trim_suffix",
        ] {
            let call = if name == "trim_space" {
                format!("{name}(body)")
            } else {
                format!("{name}(body, '_')")
            };
            let at_limit = json!({"response": {"body": "x".repeat(MAX_TRIM_INPUT_LEN)}});
            let condition = Dsl::parse(&format!("len({call}) == {MAX_TRIM_INPUT_LEN}")).unwrap();
            assert!(condition.eval_value(&at_limit), "{name}");
            let oversized = json!({"response": {"body": "x".repeat(MAX_TRIM_INPUT_LEN + 1)}});
            let condition = Dsl::parse(&format!("!contains({call}, 'never')")).unwrap();
            assert!(!condition.eval_value(&oversized), "{name}");
        }
        for name in ["trim", "trim_left", "trim_right", "trim_prefix", "trim_suffix"] {
            let condition = Dsl::parse(&format!("len({name}(body, server)) >= 0")).unwrap();
            let record = json!({"response": {
                "body": "éxé",
                "headers": {"server": "é".repeat(MAX_TRIM_CUTSET_LEN / 2)}
            }});
            assert!(condition.eval_value(&record), "{name}");
            let oversized = json!({"response": {
                "body": "éxé",
                "headers": {"server": format!("{}x", "é".repeat(MAX_TRIM_CUTSET_LEN / 2))}
            }});
            assert!(!condition.eval_value(&oversized), "{name}");
        }
    }

    #[test]
    fn unlisted_and_unsupported_functions_remain_parse_errors_even_in_dead_branches() {
        for name in ["eval", "exec", "nosuch", "trimspaces", "Repeat"] {
            let source = format!("false && {name}('sensitive-literal')");
            let error = Dsl::parse(&source).unwrap_err();
            assert!(matches!(
                &error,
                DslError::UnknownFunction { name: actual, position: 9 } if actual == name
            ));
            assert!(!error.to_string().contains("sensitive-literal"));
        }
        for (name, reason) in [
            ("rand_char", "random"),
            ("randchar", "random"),
            ("gzip", "compression"),
        ] {
            let source = format!("false && {name}('sensitive-literal')");
            let error = Dsl::parse(&source).unwrap_err();
            assert!(matches!(
                &error,
                DslError::UnsupportedFunction { name: actual, position: 9, reason: why }
                    if actual == name && why.contains(reason)
            ));
            assert!(!error.to_string().contains("sensitive-literal"));
            assert!(error.to_string().contains("byte 9"), "{error}");
        }
    }

    #[test]
    fn evaluation_errors_propagate_before_boolean_projection() {
        let condition = Dsl::parse("trim_space(body) == 'seeded-private-literal'").unwrap();
        let record = json!({"response": {
            "body": format!("seeded-private-record{}", "x".repeat(MAX_TRIM_INPUT_LEN))
        }});
        // Check the actual internal failure, not only a false result that could also
        // come from an ordinary comparison mismatch.
        assert!(matches!(
            super::eval(&condition.root, &record),
            Err(EvalError::Limit)
        ));
        assert!(!condition.eval_value(&record));

        let condition = Dsl::parse("seeded_private_variable == true").unwrap();
        let record = json!({});
        assert!(matches!(
            super::eval(&condition.root, &record),
            Err(EvalError::UnknownVariable(_))
        ));
        assert!(!condition.eval_value(&record));
    }

    #[test]
    fn expression_table() {
        let rows: &[(&str, bool)] = &[
            ("status_code == 200", true),
            ("status_code != 200", false),
            ("status_code == 404", false),
            ("response.status_code == 200", true),
            ("status_code >= 200 && status_code < 300", true),
            ("status_code > 200", false),
            ("request.method == \"GET\"", true),
            ("method == 'GET'", true),
            ("request.method != \"POST\"", true),
            ("url == \"https://e.com/admin/default.php?x=1\"", true),
            ("endpoint == url", true),
            ("contains(endpoint, \"default\") && status_code != 403", true),
            ("contains(endpoint, \"default\") && status_code != 200", false),
            ("endpoint contains \"admin\"", true),
            ("endpoint contains \"nope\"", false),
            ("contains(to_lower(technologies), \"php\")", true),
            ("contains(to_lower(technologies), \"examplecdn\")", false),
            ("contains(technologies, \"Nginx\")", true),
            ("response.headers.content-type contains \"html\"", true),
            ("content_type contains \"html\"", true),
            ("contains(content_type, \"json\")", false),
            ("server == \"nginx\"", true),
            ("page_type == \"login\"", true),
            ("response.knowledgebase.PageType == \"login\"", true),
            ("regex(\"^https://e\\\\.com/admin\", endpoint)", true),
            ("regex(\"^https://other\", endpoint)", false),
            ("regex(\"^[a-z]+$\", request.method)", false),
            ("len(technologies) == 2", true),
            ("len(body) > 10", true),
            ("len(\"abc\") == 3", true),
            ("starts_with(endpoint, \"https://\")", true),
            ("starts_with(endpoint, \"http://\", \"https://\")", true),
            ("ends_with(endpoint, \"x=1\")", true),
            ("contains_any(body, \"zzz\", \"Welcome\")", true),
            ("contains_all(body, \"h1\", \"Welcome\")", true),
            ("contains_all(body, \"h1\", \"nope\")", false),
            ("to_upper(method) == \"GET\"", true),
            ("true", true),
            ("false", false),
            ("!false", true),
            ("!(status_code == 200)", false),
            ("!!(status_code == 200)", true),
            // precedence: && binds tighter than ||
            ("true || false && false", true),
            ("(true || false) && false", false),
            ("false && false || true", true),
            (
                "status_code == 404 || status_code == 200 && method == \"GET\"",
                true,
            ),
            (
                "status_code == 404 || (status_code == 200 && method == \"POST\")",
                false,
            ),
            // comparison binds tighter than &&
            ("1 < 2 == true", true),
            // different types: == is false, != true
            ("status_code == \"200\"", false),
            ("status_code != \"200\"", true),
            ("-1 < 0", true),
            ("0.5 < 1", true),
        ];
        for (src, want) in rows {
            assert_eq!(eval(src), *want, "{src}");
        }
    }

    #[test]
    fn short_circuit_skips_the_unknown_variable() {
        // right side never evaluated
        assert!(eval("status_code == 200 || nosuch == 1"));
        assert!(!eval("status_code == 404 && nosuch == 1"));
        // left side is evaluated first: an unknown variable there makes the whole condition false
        assert!(!eval("nosuch == 1 || status_code == 200"));
        assert!(!eval("nosuch == 1 && status_code == 200"));
        // reached right side with an unknown variable: false, not a panic
        assert!(!eval("status_code == 200 && nosuch == 1"));
    }

    #[test]
    fn errors_make_the_condition_false() {
        assert!(!eval("!\"text\""), "negating a string");
        assert!(!eval("status_code < \"x\""), "ordering mixed types");
        assert!(!eval("status_code"), "non boolean result");
        assert!(!eval("\"a\" && true"), "non boolean operand");
        assert!(
            !eval("regex(method, endpoint)"),
            "runtime pattern `GET` does not match the URL"
        );
        // a runtime pattern that does not compile is false, not an error
        assert!(
            !Dsl::parse("regex(server, endpoint)").unwrap().eval_value(&json!({
                "request": {"endpoint": "x"}, "response": {"headers": {"server": "("}}
            }))
        );
    }

    #[test]
    fn variables_are_collected_and_body_is_detected() {
        let d = Dsl::parse("contains(body, \"x\") && status_code == 200 && status_code != 1").unwrap();
        assert_eq!(d.variables(), ["body", "status_code"]);
        assert!(d.reads_body());
        assert!(Dsl::parse("response.body contains \"x\"").unwrap().reads_body());
        assert!(!Dsl::parse("status_code == 200").unwrap().reads_body());
        assert_eq!(
            d.source(),
            "contains(body, \"x\") && status_code == 200 && status_code != 1"
        );
    }

    #[test]
    fn eval_over_a_record_matches_eval_over_its_json() {
        let r = Record {
            request: Some(crate::output::jsonl::Request {
                endpoint: "https://e.com/".to_owned(),
                method: "GET".to_owned(),
                ..Default::default()
            }),
            response: Some(crate::output::jsonl::Response {
                status_code: 301,
                ..Default::default()
            }),
            error: Some("boom".to_owned()),
            ..Default::default()
        };
        assert!(Dsl::parse("status_code == 301 && error == \"boom\"")
            .unwrap()
            .eval(&r));
        assert!(Dsl::parse("status_code >= 300 && status_code <= 399")
            .unwrap()
            .eval(&r));
        assert!(!Dsl::parse("status_code == 200").unwrap().eval(&r));
    }

    #[test]
    fn parse_errors_carry_positions() {
        type Check = fn(&DslError) -> bool;
        let cases: Vec<(&str, Check)> = vec![
            ("", |e| matches!(e, DslError::Empty)),
            ("   ", |e| matches!(e, DslError::Empty)),
            ("status_code == ", |e| {
                matches!(e, DslError::Unexpected { position: 15, .. })
            }),
            ("status_code = 200", |e| {
                matches!(
                    e,
                    DslError::UnexpectedChar {
                        position: 12,
                        ch: '='
                    }
                )
            }),
            ("status_code == 200 )", |e| {
                matches!(e, DslError::Unexpected { position: 19, .. })
            }),
            ("(status_code == 200", |e| {
                matches!(
                    e,
                    DslError::Unexpected {
                        position: 19,
                        expected: "`)`",
                        ..
                    }
                )
            }),
            ("a == \"abc", |e| {
                matches!(e, DslError::UnterminatedString { position: 5 })
            }),
            ("a & b", |e| {
                matches!(e, DslError::UnexpectedChar { position: 2, ch: '&' })
            }),
            ("a | b", |e| {
                matches!(e, DslError::UnexpectedChar { position: 2, ch: '|' })
            }),
            ("a == 1.2.3", |e| {
                matches!(e, DslError::InvalidNumber { position: 5, .. })
            }),
            ("a == 1 && nofunc(a)", |e| {
                matches!(e, DslError::UnknownFunction { position: 10, .. })
            }),
            ("x && contains(a)", |e| {
                matches!(
                    e,
                    DslError::Arity {
                        position: 5,
                        name: "contains",
                        got: 1,
                        ..
                    }
                )
            }),
            ("len()", |e| {
                matches!(
                    e,
                    DslError::Arity {
                        position: 0,
                        name: "len",
                        got: 0,
                        ..
                    }
                )
            }),
            ("contains(a, b", |e| {
                matches!(e, DslError::Unexpected { position: 13, .. })
            }),
            ("a == 1 2", |e| {
                matches!(e, DslError::Unexpected { position: 7, .. })
            }),
            ("regex(\"(\", a)", |e| {
                matches!(
                    e,
                    DslError::Regex {
                        position: 0,
                        source: RegexProblem::Compile(_)
                    }
                )
            }),
            ("@", |e| {
                matches!(e, DslError::UnexpectedChar { position: 0, ch: '@' })
            }),
        ];
        for (src, check) in cases {
            let err = Dsl::parse(src).unwrap_err();
            assert!(check(&err), "`{src}` -> {err:?}");
        }
        let err = Dsl::parse("a == ").unwrap_err();
        assert_eq!(err.position(), Some(5));
        assert!(err.to_string().contains("byte 5"), "{err}");
        assert_eq!(Dsl::parse("").unwrap_err().position(), None);
    }

    #[test]
    fn limits_bound_source_nesting_and_regex() {
        let long = format!("a == \"{}\"", "x".repeat(MAX_SOURCE_LEN));
        assert!(matches!(Dsl::parse(&long), Err(DslError::TooLong { .. })));
        let deep = format!("{}true{}", "(".repeat(MAX_DEPTH + 2), ")".repeat(MAX_DEPTH + 2));
        assert!(matches!(Dsl::parse(&deep), Err(DslError::TooDeep { .. })));
        let bangs = format!("{}true", "!".repeat(MAX_DEPTH + 2));
        assert!(matches!(Dsl::parse(&bangs), Err(DslError::TooDeep { .. })));
        let long_pattern = format!("regex(\"{}\", a)", "a".repeat(MAX_REGEX_LEN + 1));
        assert!(matches!(
            Dsl::parse(&long_pattern),
            Err(DslError::Regex {
                source: RegexProblem::TooLong { .. },
                ..
            })
        ));
        let big = "regex(\"(?:a{1000}){1000}\", a)";
        assert!(matches!(
            Dsl::parse(big),
            Err(DslError::Regex {
                source: RegexProblem::Compile(_),
                ..
            })
        ));
    }

    #[test]
    fn regex_is_linear_time() {
        // Catastrophic for a backtracking engine; the `regex` crate answers at once.
        let d = Dsl::parse("regex(\"^(a+)+$\", body)").unwrap();
        let body = format!("{}b", "a".repeat(50_000));
        assert!(!d.eval_value(&json!({"response": {"body": body}})));
        let ok = "a".repeat(50_000);
        assert!(d.eval_value(&json!({"response": {"body": ok}})));
    }

    #[test]
    fn strings_support_both_quotes_and_escapes() {
        let r = json!({"response": {"body": "say \"hi\"\n"}});
        assert!(Dsl::parse(r#"contains(body, 'say "hi"')"#)
            .unwrap()
            .eval_value(&r));
        assert!(Dsl::parse(r#"contains(body, "say \"hi\"\n")"#)
            .unwrap()
            .eval_value(&r));
        assert!(Dsl::parse("body == 'say \\\"hi\\\"\\n'").unwrap().eval_value(&r));
    }

    #[test]
    fn from_str_parses() {
        let d: Dsl = "status_code == 200".parse().unwrap();
        assert!(d.eval_value(&record()));
    }
}
