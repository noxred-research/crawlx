//! Bounded XPath 1.0 lexer and recursive-descent expression compiler.
use super::SelectorError;
use crawlx_core::selectors::{MAX_AST_NODES, MAX_EXPRESSION_BYTES};

// Bound recursive parser frames independently of AST size. Parentheses and unary
// prefixes can otherwise exhaust the thread stack before they create any AST nodes.
const MAX_PARSE_DEPTH: usize = 64;
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Token {
    Name(String),
    String(String),
    Number(f64),
    Mark(&'static str),
    End,
}
#[derive(Debug, Clone)]
pub(super) enum Expr {
    String(String),
    Number(f64),
    Neg(Box<Expr>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
    Function(String, Vec<Expr>),
    Path(Option<Box<Expr>>, bool, Vec<Step>),
    Filter(Box<Expr>, Vec<Expr>),
}
#[derive(Debug, Clone)]
pub(super) struct Step {
    pub axis: Axis,
    pub test: Test,
    pub predicates: Vec<Expr>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Axis {
    Child,
    Descendant,
    Parent,
    Ancestor,
    FollowingSibling,
    PrecedingSibling,
    Following,
    Preceding,
    Attribute,
    Namespace,
    SelfNode,
    DescendantOrSelf,
    AncestorOrSelf,
}
#[derive(Debug, Clone)]
pub(super) enum Test {
    Name(Option<String>, String),
    Node,
    Text,
    Comment,
    Pi(Option<String>),
}
fn syntax() -> SelectorError {
    SelectorError::Syntax
}

// XML 1.0 NCNames exclude ':' because the parser handles namespace separators.
fn ncname_start(character: char) -> bool {
    matches!(character,
        'A'..='Z' | '_' | 'a'..='z'
        | '\u{c0}'..='\u{d6}' | '\u{d8}'..='\u{f6}' | '\u{f8}'..='\u{2ff}'
        | '\u{370}'..='\u{37d}' | '\u{37f}'..='\u{1fff}' | '\u{200c}'..='\u{200d}'
        | '\u{2070}'..='\u{218f}' | '\u{2c00}'..='\u{2fef}' | '\u{3001}'..='\u{d7ff}'
        | '\u{f900}'..='\u{fdcf}' | '\u{fdf0}'..='\u{fffd}' | '\u{10000}'..='\u{effff}')
}

fn ncname_character(character: char) -> bool {
    ncname_start(character)
        || matches!(character, '-' | '.' | '0'..='9' | '\u{b7}'
            | '\u{300}'..='\u{36f}' | '\u{203f}'..='\u{2040}')
}
fn lex(input: &str) -> Result<Vec<Token>, SelectorError> {
    if input.len() > MAX_EXPRESSION_BYTES {
        return Err(SelectorError::Budget("expression bytes"));
    }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < input.len() {
        let rest = &input[pos..];
        let c = rest.chars().next().ok_or_else(syntax)?;
        if matches!(c, ' ' | '\t' | '\r' | '\n') {
            pos += c.len_utf8();
            continue;
        }
        if c == '\'' || c == '"' {
            let end = rest[1..].find(c).ok_or_else(syntax)?.saturating_add(1);
            out.push(Token::String(rest[1..end].into()));
            pos += end.saturating_add(1);
            continue;
        }
        if c.is_ascii_digit() || (c == '.' && rest.as_bytes().get(1).is_some_and(u8::is_ascii_digit)) {
            let len = rest
                .bytes()
                .take_while(|b| b.is_ascii_digit() || *b == b'.')
                .count();
            out.push(Token::Number(rest[..len].parse().map_err(|_| syntax())?));
            pos += len;
            continue;
        }
        if ncname_start(c) {
            let mut len = c.len_utf8();
            for ch in rest[c.len_utf8()..].chars() {
                if ncname_character(ch) {
                    len += ch.len_utf8();
                } else {
                    break;
                }
            }
            out.push(Token::Name(rest[..len].into()));
            pos += len;
            continue;
        }
        let mut found = false;
        for mark in [
            "//", "::", "..", "!=", "<=", ">=", "/", ".", "@", "*", "[", "]", "(", ")", ",", "|", "+", "-",
            "=", "<", ">", ":",
        ] {
            if rest.starts_with(mark) {
                out.push(Token::Mark(mark));
                pos += mark.len();
                found = true;
                break;
            }
        }
        if !found {
            return Err(syntax());
        }
    }
    out.push(Token::End);
    Ok(out)
}
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    nodes: usize,
    depth: usize,
}
impl Parser {
    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::End)
    }
    fn mark(&mut self, s: &str) -> bool {
        if matches!(self.peek(),Token::Mark(m) if *m==s) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn require(&mut self, s: &str) -> Result<(), SelectorError> {
        if self.mark(s) {
            Ok(())
        } else {
            Err(syntax())
        }
    }
    fn take(&mut self) -> Token {
        let t = self.peek().clone();
        self.pos += 1;
        t
    }
    fn node(&mut self, e: Expr) -> Result<Expr, SelectorError> {
        self.nodes += 1;
        if self.nodes > MAX_AST_NODES {
            Err(SelectorError::Budget("AST nodes"))
        } else {
            Ok(e)
        }
    }
    fn expr(&mut self, min: u8) -> Result<Expr, SelectorError> {
        if self.depth >= MAX_PARSE_DEPTH {
            return Err(SelectorError::Budget("parser depth"));
        }
        self.depth += 1;
        let mut left = if self.mark("-") {
            let e = self.expr(7)?;
            self.node(Expr::Neg(Box::new(e)))?
        } else {
            self.primary()?
        };
        loop {
            let op = match self.peek() {
                Token::Mark(s) => *s,
                Token::Name(s) => match s.as_str() {
                    "or" => "or",
                    "and" => "and",
                    "div" => "div",
                    "mod" => "mod",
                    _ => "",
                },
                _ => "",
            };
            let precedence = match op {
                "or" => 1,
                "and" => 2,
                "=" | "!=" => 3,
                "<" | ">" | "<=" | ">=" => 4,
                "+" | "-" => 5,
                "*" | "div" | "mod" => 6,
                "|" => 8,
                _ => 0,
            };
            if precedence == 0 || precedence < min {
                break;
            }
            self.pos += 1;
            let right = self.expr(precedence + 1)?;
            left = self.node(Expr::Binary(op, Box::new(left), Box::new(right)))?;
        }
        self.depth -= 1;
        Ok(left)
    }
    fn step_start(&self) -> bool {
        match self.peek() {
            Token::Mark("." | ".." | "@" | "*") => true,
            Token::Name(n) => {
                !matches!(self.tokens.get(self.pos + 1), Some(Token::Mark("(")))
                    || matches!(n.as_str(), "node" | "text" | "comment" | "processing-instruction")
            }
            _ => false,
        }
    }
    fn primary(&mut self) -> Result<Expr, SelectorError> {
        let absolute = self.mark("/");
        let double = if absolute { false } else { self.mark("//") };
        if absolute || double || self.step_start() {
            let mut steps = Vec::new();
            if double {
                self.nodes += 1;
                if self.nodes > MAX_AST_NODES {
                    return Err(SelectorError::Budget("AST nodes"));
                }
                steps.push(descendant());
            }
            if self.step_start() {
                steps.push(self.step()?);
                self.tail(&mut steps)?;
            } else if double {
                return Err(syntax());
            }
            return self.node(Expr::Path(None, absolute || double, steps));
        }
        let mut value = match self.take() {
            Token::String(s) => self.node(Expr::String(s))?,
            Token::Number(n) => self.node(Expr::Number(n))?,
            Token::Mark("(") => {
                let e = self.expr(1)?;
                self.require(")")?;
                e
            }
            Token::Name(name) => {
                self.require("(")?;
                let mut args = Vec::new();
                if !self.mark(")") {
                    loop {
                        args.push(self.expr(1)?);
                        if self.mark(")") {
                            break;
                        }
                        self.require(",")?;
                    }
                }
                validate_function(&name, args.len())?;
                self.node(Expr::Function(name, args))?
            }
            _ => return Err(syntax()),
        };
        let predicates = self.predicates()?;
        if !predicates.is_empty() {
            value = self.node(Expr::Filter(Box::new(value), predicates))?;
        }
        let mut steps = Vec::new();
        self.tail(&mut steps)?;
        if !steps.is_empty() {
            value = self.node(Expr::Path(Some(Box::new(value)), false, steps))?;
        }
        Ok(value)
    }
    fn tail(&mut self, steps: &mut Vec<Step>) -> Result<(), SelectorError> {
        loop {
            if self.mark("//") {
                self.nodes += 1;
                if self.nodes > MAX_AST_NODES {
                    return Err(SelectorError::Budget("AST nodes"));
                }
                steps.push(descendant());
            } else if !self.mark("/") {
                break;
            }
            steps.push(self.step()?);
        }
        Ok(())
    }
    fn predicates(&mut self) -> Result<Vec<Expr>, SelectorError> {
        let mut p = Vec::new();
        while self.mark("[") {
            p.push(self.expr(1)?);
            self.require("]")?;
        }
        Ok(p)
    }
    fn step(&mut self) -> Result<Step, SelectorError> {
        self.nodes += 1;
        if self.nodes > MAX_AST_NODES {
            return Err(SelectorError::Budget("AST nodes"));
        }
        if self.mark(".") {
            return Ok(Step {
                axis: Axis::SelfNode,
                test: Test::Node,
                predicates: Vec::new(),
            });
        }
        if self.mark("..") {
            return Ok(Step {
                axis: Axis::Parent,
                test: Test::Node,
                predicates: Vec::new(),
            });
        }
        let attribute_abbreviation = self.mark("@");
        let mut axis = if attribute_abbreviation {
            Axis::Attribute
        } else {
            Axis::Child
        };
        if let (Some(Token::Name(n)), Some(Token::Mark("::"))) =
            (self.tokens.get(self.pos), self.tokens.get(self.pos + 1))
        {
            if attribute_abbreviation {
                return Err(syntax());
            }
            axis = match n.as_str() {
                "child" => Axis::Child,
                "descendant" => Axis::Descendant,
                "parent" => Axis::Parent,
                "ancestor" => Axis::Ancestor,
                "following-sibling" => Axis::FollowingSibling,
                "preceding-sibling" => Axis::PrecedingSibling,
                "following" => Axis::Following,
                "preceding" => Axis::Preceding,
                "attribute" => Axis::Attribute,
                "namespace" => Axis::Namespace,
                "self" => Axis::SelfNode,
                "descendant-or-self" => Axis::DescendantOrSelf,
                "ancestor-or-self" => Axis::AncestorOrSelf,
                _ => return Err(syntax()),
            };
            self.pos += 2;
        }
        let test = if self.mark("*") {
            Test::Name(None, "*".into())
        } else {
            let Token::Name(n) = self.take() else {
                return Err(syntax());
            };
            if self.mark("(") {
                let t = match n.as_str() {
                    "node" => Test::Node,
                    "text" => Test::Text,
                    "comment" => Test::Comment,
                    "processing-instruction" => {
                        let target = if let Token::String(s) = self.peek() {
                            let s = s.clone();
                            self.pos += 1;
                            Some(s)
                        } else {
                            None
                        };
                        Test::Pi(target)
                    }
                    _ => return Err(syntax()),
                };
                self.require(")")?;
                t
            } else if self.mark(":") {
                let local = if self.mark("*") {
                    "*".into()
                } else {
                    let Token::Name(s) = self.take() else {
                        return Err(syntax());
                    };
                    s
                };
                Test::Name(Some(n), local)
            } else {
                Test::Name(None, n)
            }
        };
        Ok(Step {
            axis,
            test,
            predicates: self.predicates()?,
        })
    }
}
fn descendant() -> Step {
    Step {
        axis: Axis::DescendantOrSelf,
        test: Test::Node,
        predicates: Vec::new(),
    }
}
fn validate_function(name: &str, n: usize) -> Result<(), SelectorError> {
    let valid = match name {
        "last" | "position" | "true" | "false" => n == 0,
        "count" | "id" | "boolean" | "not" | "lang" | "sum" | "floor" | "ceiling" | "round" => n == 1,
        "local-name" | "namespace-uri" | "name" | "string" | "string-length" | "normalize-space"
        | "number" => n <= 1,
        "concat" => n >= 2,
        "starts-with" | "contains" | "substring-before" | "substring-after" => n == 2,
        "substring" => n == 2 || n == 3,
        "translate" => n == 3,
        _ => return Err(SelectorError::UnsupportedFunction),
    };
    if valid {
        Ok(())
    } else {
        Err(syntax())
    }
}
pub(super) fn compile(source: &str) -> Result<Expr, SelectorError> {
    let mut parser = Parser {
        tokens: lex(source)?,
        pos: 0,
        nodes: 0,
        depth: 0,
    };
    let expression = parser.expr(1)?;
    if parser.peek() != &Token::End {
        return Err(syntax());
    }
    // Left-associative operators form deep ASTs without deep parser recursion.
    // Validate before any recursive namespace walk or evaluation can use the tree.
    validate_ast_depth(&expression, 1)?;
    Ok(expression)
}

fn validate_ast_depth(expression: &Expr, depth: usize) -> Result<(), SelectorError> {
    if depth > MAX_PARSE_DEPTH {
        return Err(SelectorError::Budget("AST depth"));
    }
    match expression {
        Expr::String(_) | Expr::Number(_) => {}
        Expr::Neg(child) => validate_ast_depth(child, depth + 1)?,
        Expr::Binary(_, left, right) => {
            validate_ast_depth(left, depth + 1)?;
            validate_ast_depth(right, depth + 1)?;
        }
        Expr::Function(_, arguments) => {
            for argument in arguments {
                validate_ast_depth(argument, depth + 1)?;
            }
        }
        Expr::Filter(base, predicates) => {
            validate_ast_depth(base, depth + 1)?;
            for predicate in predicates {
                validate_ast_depth(predicate, depth + 1)?;
            }
        }
        Expr::Path(base, _, steps) => {
            if let Some(base) = base {
                validate_ast_depth(base, depth + 1)?;
            }
            for step in steps {
                for predicate in &step.predicates {
                    validate_ast_depth(predicate, depth + 1)?;
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_namespaces(
    expr: &Expr,
    ns: &std::collections::BTreeMap<String, String>,
) -> Result<(), SelectorError> {
    match expr {
        Expr::String(_) | Expr::Number(_) => {}
        Expr::Neg(e) => validate_namespaces(e, ns)?,
        Expr::Binary(_, a, b) => {
            validate_namespaces(a, ns)?;
            validate_namespaces(b, ns)?;
        }
        Expr::Function(_, args) => {
            for e in args {
                validate_namespaces(e, ns)?;
            }
        }
        Expr::Filter(e, predicates) => {
            validate_namespaces(e, ns)?;
            for p in predicates {
                validate_namespaces(p, ns)?;
            }
        }
        Expr::Path(base, _, steps) => {
            if let Some(base) = base {
                validate_namespaces(base, ns)?;
            }
            for step in steps {
                if let Test::Name(Some(prefix), _) = &step.test {
                    if prefix != "xml" && !ns.contains_key(prefix) {
                        return Err(SelectorError::Namespace);
                    }
                }
                for p in &step.predicates {
                    validate_namespaces(p, ns)?;
                }
            }
        }
    }
    Ok(())
}
