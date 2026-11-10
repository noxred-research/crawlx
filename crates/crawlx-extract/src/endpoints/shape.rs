//! Lexical bound on the nesting the JavaScript parser would recurse into.
//!
//! The parser recurses once per open bracket, per pending prefix operator and per
//! pending right-associative operator (`a = b = c`, `a ? b : c ? d : e`,
//! `a => b => c`, `a ** b ** c`). A hostile script can nest those a million times
//! and overflow the stack of the worker thread, which aborts the process: stack
//! overflow is not an error Rust can recover from. The AST pass therefore refuses
//! such a script before it is parsed.
//!
//! [`too_deep`] is a linear single-pass scan, not a parser. It understands
//! strings, template literals (with nested `${ … }`), comments and regular
//! expression literals well enough to count brackets that are code, and it
//! counts right-associative operators between statement boundaries (a `;`, or a
//! line break between an operand and the start of the next statement). The bounds
//! are far above anything real code reaches and keep the parser within a default
//! 2 MiB thread stack.

/// Open brackets (`(`, `[`, `{`, `${`) at once.
pub(super) const MAX_BRACKET_DEPTH: usize = 128;
/// Consecutive prefix operators (`!`, `~`, `+`, `-`, `typeof`, `await`, `new`, …).
pub(super) const MAX_PREFIX_RUN: usize = 128;
/// Right-associative operators (`=`, `=>`, `?`, `**`) in one statement.
pub(super) const MAX_RIGHT_ASSOCIATIVE: usize = 128;

/// What the previous significant token was, as far as regex-versus-division and
/// block-versus-object decisions need.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prev {
    /// Start of input.
    Start,
    /// `;`
    Semi,
    /// `{`
    OpenBrace,
    /// `(`, `[`, `,`, `:` and every operator: an operand may start here.
    Op,
    /// `.` / `?.`: the next word is a property name.
    Dot,
    /// `=>`
    Arrow,
    /// Identifier, number, string, template, `)`/`]`/`}` closing an expression.
    Operand,
    /// `)` of `if`/`while`/`for`/`with`, or `}` of a block: a regex may follow.
    CloseStatement,
    /// A keyword after which an operand (or regex) starts: `return`, `typeof`, …
    Keyword,
    /// `else`, `do`, `try`, `finally`: a block follows.
    BlockKeyword,
}

impl Prev {
    fn ends_operand(self) -> bool {
        matches!(self, Self::Operand | Self::CloseStatement)
    }

    fn allows_regex(self) -> bool {
        !matches!(self, Self::Operand)
    }
}

/// One open bracket.
#[derive(Clone, Copy)]
struct Frame {
    /// `(`, `[`, `{`, or `$` for a template substitution.
    open: u8,
    /// The closer ends a statement (a control-flow `(…)`, a block `{…}`).
    statement: bool,
}

const fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_' || c == b'$' || c >= 0x80
}

const fn is_ident_part(c: u8) -> bool {
    is_ident_start(c) || c.is_ascii_digit()
}

/// Skip a quoted string starting at `b[i]` (the quote); returns the index after it.
/// A raw line break ends an unterminated string.
fn skip_string(b: &[u8], mut i: usize) -> usize {
    let quote = b[i];
    i += 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            c if c == quote => return i + 1,
            b'\n' => return i,
            _ => i += 1,
        }
    }
    b.len()
}

/// Skip template text from `b[i]` (after the opening backtick or a closing `}`).
/// Returns the index after the closing backtick, or after `${` with `true`.
fn skip_template(b: &[u8], mut i: usize) -> (usize, bool) {
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'`' => return (i + 1, false),
            b'$' if b.get(i + 1) == Some(&b'{') => return (i + 2, true),
            _ => i += 1,
        }
    }
    (b.len(), false)
}

/// Skip a regular-expression literal starting at `b[i]` (the slash).
fn skip_regex(b: &[u8], mut i: usize) -> usize {
    i += 1;
    let mut class = false;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'[' => {
                class = true;
                i += 1;
            }
            b']' => {
                class = false;
                i += 1;
            }
            b'/' if !class => return i + 1,
            b'\n' => return i,
            _ => i += 1,
        }
    }
    b.len()
}

/// Words that start an operand (a regex may follow) or are prefix operators.
fn word_class(word: &[u8]) -> Option<(Prev, bool)> {
    // (token class, counts as a prefix operator)
    Some(match word {
        b"typeof" | b"void" | b"delete" | b"await" | b"yield" | b"new" => (Prev::Keyword, true),
        b"return" | b"instanceof" | b"in" | b"of" | b"throw" | b"case" => (Prev::Keyword, false),
        b"else" | b"do" | b"try" | b"finally" => (Prev::BlockKeyword, false),
        _ => return None,
    })
}

/// `true` when `js` nests brackets, prefix operators or right-associative
/// operators deeper than the bounds of this module.
pub(super) fn too_deep(js: &str) -> bool {
    let b = js.as_bytes();
    let mut i = 0;
    let mut stack: Vec<Frame> = Vec::new();
    let mut prev = Prev::Start;
    let mut prefix_run = 0usize;
    let mut right = 0usize;
    // a line break followed an operand: the next word/number/string starts a new statement
    let mut line_break_after_operand = false;
    let mut control_word = false;
    while i < b.len() {
        let c = b[i];
        if c == b'\n' {
            line_break_after_operand = prev.ends_operand();
            i += 1;
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let starts_statement =
            line_break_after_operand && (is_ident_start(c) || c.is_ascii_digit() || c == b'\'' || c == b'"');
        line_break_after_operand = false;
        let was_control_word = control_word;
        control_word = false;
        match c {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(b.len());
            }
            b'/' => {
                if prev.allows_regex() {
                    i = skip_regex(b, i);
                    // flags are identifier characters, read below as part of an operand
                    prev = Prev::Operand;
                } else {
                    i += 1;
                    prev = Prev::Op;
                }
                prefix_run = 0;
            }
            b'\'' | b'"' => {
                if starts_statement {
                    right = 0;
                }
                i = skip_string(b, i);
                prev = Prev::Operand;
                prefix_run = 0;
            }
            b'`' => {
                let (next, substitution) = skip_template(b, i + 1);
                i = next;
                prefix_run = 0;
                if substitution {
                    stack.push(Frame {
                        open: b'$',
                        statement: false,
                    });
                    prev = Prev::Op;
                } else {
                    prev = Prev::Operand;
                }
            }
            b'0'..=b'9' => {
                if starts_statement {
                    right = 0;
                }
                while i < b.len() && (is_ident_part(b[i]) || b[i] == b'.') {
                    i += 1;
                }
                prev = Prev::Operand;
                prefix_run = 0;
            }
            c if is_ident_start(c) => {
                let start = i;
                while i < b.len() && is_ident_part(b[i]) {
                    i += 1;
                }
                let word = &b[start..i];
                let property = prev == Prev::Dot;
                let keyword = if property { None } else { word_class(word) };
                if starts_statement && !matches!(word, b"in" | b"instanceof" | b"of") {
                    right = 0;
                }
                match keyword {
                    Some((class, is_prefix)) => {
                        prev = class;
                        if is_prefix {
                            prefix_run += 1;
                        } else {
                            prefix_run = 0;
                        }
                    }
                    None => {
                        control_word = !property && matches!(word, b"if" | b"while" | b"for" | b"with");
                        prev = Prev::Operand;
                        prefix_run = 0;
                    }
                }
                // an operand ends here; a control word still expects its `(`
                if control_word {
                    prev = Prev::Op;
                }
            }
            b'(' | b'[' | b'{' => {
                let statement = match c {
                    b'(' => was_control_word,
                    b'{' => matches!(
                        prev,
                        Prev::Start
                            | Prev::Semi
                            | Prev::OpenBrace
                            | Prev::CloseStatement
                            | Prev::Arrow
                            | Prev::BlockKeyword
                    ),
                    _ => false,
                };
                stack.push(Frame { open: c, statement });
                i += 1;
                prev = if c == b'{' { Prev::OpenBrace } else { Prev::Op };
                prefix_run = 0;
            }
            b')' | b']' => {
                let frame = stack.pop();
                i += 1;
                prev = if frame.is_some_and(|f| f.statement) {
                    Prev::CloseStatement
                } else {
                    Prev::Operand
                };
                prefix_run = 0;
            }
            b'}' => {
                i += 1;
                match stack.pop() {
                    Some(Frame { open: b'$', .. }) => {
                        let (next, substitution) = skip_template(b, i);
                        i = next;
                        if substitution {
                            stack.push(Frame {
                                open: b'$',
                                statement: false,
                            });
                            prev = Prev::Op;
                        } else {
                            prev = Prev::Operand;
                        }
                    }
                    Some(Frame { statement: true, .. }) => prev = Prev::CloseStatement,
                    _ => prev = Prev::Operand,
                }
                prefix_run = 0;
            }
            b';' => {
                right = 0;
                prefix_run = 0;
                prev = Prev::Semi;
                i += 1;
            }
            b'.' => {
                prev = Prev::Dot;
                i += 1;
            }
            b'!' | b'~' => {
                if c == b'!' && b.get(i + 1) == Some(&b'=') {
                    i += if b.get(i + 2) == Some(&b'=') { 3 } else { 2 };
                    prev = Prev::Op;
                    prefix_run = 0;
                } else {
                    prefix_run += 1;
                    prev = Prev::Op;
                    i += 1;
                }
            }
            b'+' | b'-' => {
                if prev.ends_operand() && b.get(i + 1) != Some(&c) {
                    prev = Prev::Op; // binary
                    prefix_run = 0;
                    i += if b.get(i + 1) == Some(&b'=') { 2 } else { 1 };
                } else {
                    prefix_run += 1;
                    i += if b.get(i + 1) == Some(&c) { 2 } else { 1 };
                    prev = Prev::Op;
                }
            }
            b'=' => {
                prefix_run = 0;
                match b.get(i + 1) {
                    Some(b'=') => {
                        i += if b.get(i + 2) == Some(&b'=') { 3 } else { 2 };
                        prev = Prev::Op;
                    }
                    Some(b'>') => {
                        right += 1;
                        i += 2;
                        prev = Prev::Arrow;
                    }
                    _ => {
                        // plain or compound assignment (`<=`/`>=` never reach here)
                        right += 1;
                        i += 1;
                        prev = Prev::Op;
                    }
                }
            }
            b'<' | b'>' => {
                // `<=`, `>=`, `<<=`, `>>=`, `>>>=` consume their `=`
                let mut j = i + 1;
                while j < b.len() && (b[j] == c) {
                    j += 1;
                }
                if b.get(j) == Some(&b'=') {
                    j += 1;
                }
                i = j;
                prev = Prev::Op;
                prefix_run = 0;
            }
            b'*' => {
                if b.get(i + 1) == Some(&b'*') {
                    right += 1;
                    i += 2;
                } else {
                    i += 1;
                }
                prev = Prev::Op;
                prefix_run = 0;
            }
            b'?' => {
                match b.get(i + 1) {
                    Some(b'?') => i += 2, // `??` is left-associative
                    Some(b'.') if !b.get(i + 2).is_some_and(u8::is_ascii_digit) => {
                        i += 2;
                        prev = Prev::Dot;
                        continue;
                    }
                    _ => {
                        right += 1;
                        i += 1;
                    }
                }
                prev = Prev::Op;
                prefix_run = 0;
            }
            _ => {
                prev = Prev::Op;
                prefix_run = 0;
                i += 1;
            }
        }
        if stack.len() > MAX_BRACKET_DEPTH || prefix_run > MAX_PREFIX_RUN || right > MAX_RIGHT_ASSOCIATIVE {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn nested(open: &str, close: &str, n: usize) -> String {
        format!("{}x{}", open.repeat(n), close.repeat(n))
    }

    #[test]
    fn bracket_depth_is_bounded() {
        for (open, close) in [("(", ")"), ("[", "]"), ("{", "}"), ("f(", ")"), ("`${", "}`")] {
            assert!(!too_deep(&nested(open, close, MAX_BRACKET_DEPTH)), "{open}");
            assert!(too_deep(&nested(open, close, MAX_BRACKET_DEPTH + 1)), "{open}");
        }
    }

    #[test]
    fn prefix_runs_are_bounded() {
        assert!(!too_deep(&format!("{}x", "!".repeat(MAX_PREFIX_RUN))));
        assert!(too_deep(&format!("{}x", "!".repeat(MAX_PREFIX_RUN + 1))));
        assert!(too_deep(&format!("{}x", "- ".repeat(MAX_PREFIX_RUN + 1))));
        assert!(too_deep(&format!("{}x", "typeof ".repeat(MAX_PREFIX_RUN + 1))));
        assert!(too_deep(&format!("{}x", "new ".repeat(MAX_PREFIX_RUN + 1))));
        // binary operators between operands are not prefix operators
        assert!(!too_deep(&format!("x{}", " - x".repeat(10_000))));
        assert!(!too_deep(&format!("x{}", " + x".repeat(10_000))));
    }

    #[test]
    fn right_associative_chains_are_bounded() {
        let n = MAX_RIGHT_ASSOCIATIVE + 1;
        assert!(too_deep(&format!("{}x", "x=".repeat(n))));
        assert!(too_deep(&format!("x{}", "?x:x".repeat(n))));
        assert!(too_deep(&format!("{}x", "x=>".repeat(n))));
        assert!(too_deep(&format!("x{}", "**x".repeat(n))));
        // across lines too, while the statement continues
        assert!(too_deep(&format!("{}x", "x=\n".repeat(n))));
        // the same number of statements is fine, with or without semicolons
        assert!(!too_deep(&"x=1;".repeat(10_000)));
        assert!(!too_deep(&"x=1\n".repeat(10_000)));
        assert!(!too_deep(&"var a = b ? c : d\n".repeat(10_000)));
    }

    #[test]
    fn long_left_associative_chains_are_not_the_parsers_problem() {
        assert!(!too_deep(&format!("x{}", " + y".repeat(100_000))));
        assert!(!too_deep(&format!("x{}", ".y".repeat(100_000))));
        assert!(!too_deep(&format!("x{}", "()".repeat(100_000))));
        assert!(!too_deep(&format!("x{}", "&&y".repeat(100_000))));
    }

    #[test]
    fn strings_comments_and_regexes_hide_their_brackets() {
        let n = MAX_BRACKET_DEPTH * 4;
        assert!(!too_deep(&format!("var a = \"{}\";", "(".repeat(n))));
        assert!(!too_deep(&format!("var a = '{}';", "[".repeat(n))));
        assert!(!too_deep(&format!("var a = `{}`;", "{".repeat(n))));
        assert!(!too_deep(&format!("// {}\nx", "(".repeat(n))));
        assert!(!too_deep(&format!("/* {} */ x", "(".repeat(n))));
        assert!(!too_deep(&format!("var r = /{}/;", "\\(".repeat(n))));
        assert!(!too_deep(&format!("var r = /[{}]/;", "(".repeat(n))));
        // a regex holding a quote must not open a string that swallows real code
        assert!(too_deep(&format!(
            "if (1) /'/.test(x);{}x;{}'",
            "(".repeat(n),
            ")".repeat(n)
        )));
        assert!(too_deep(&format!(
            "x = /'/; {}x{} // '",
            "(".repeat(n),
            ")".repeat(n)
        )));
        // division is not a regex
        assert!(!too_deep(&format!(
            "x = a / b / '; {}x{} '",
            "(".repeat(n),
            ")".repeat(n)
        )));
    }

    #[test]
    fn template_substitutions_nest_like_brackets() {
        let inner = "`a${`b${(".repeat(80);
        assert!(too_deep(&format!("{inner}1{}", ")}`}`".repeat(80))));
        assert!(!too_deep("`a${b}c${d}e`"));
        assert!(!too_deep(&format!("x = `{}`", "${a}".repeat(10_000))));
    }

    #[test]
    fn ordinary_code_is_within_bounds() {
        let js =
            "(function(){ var a = {b: [1,2,{c: (d ? e : f)}]}; if (a) { for (;;) { x = y = z; } } })();\n\
                  const f = (a) => (b) => a + b;\nlet r = a /2/ 3; let s = a ? b : c ? d : e;";
        assert!(!too_deep(js));
    }
}
