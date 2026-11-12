//! Bounded actor script: a small line-oriented grammar that compiles into the closed
//! [`ActorActionV1`] vocabulary.
//!
//! The grammar adds convenience, never authority. Variables are compile-time string
//! constants, `REPEAT` is unrolled, and `IF` compares two compile-time strings, so the
//! output is the same finite, ordered action list a hand-written recipe holds. That list
//! still has to pass the native recipe allowlist, the operator registry approval, and the
//! safety kernel and action journal when it runs; a denied step stops every later step.
//!
//! ```text
//! # comment
//! LET user = "reader"               variable (constant string)
//! WAIT 500                          milliseconds
//! CLICK `a.next`                    CSS selector in backticks
//! FILL `input[name=q]` "${user}"    "${name}" inserts a variable
//! TYPE "text"                       native typing into the focused element
//! PRESS Enter
//! SCROLL down [`#feed`]
//! REPEAT 3 AS page                  1 to 20 iterations; $page is "1", "2", "3"
//!   CLICK `li:nth-child(${page})`
//! END
//! IF $user == "reader"              == or !=, over variables and quoted strings
//!   WAIT 100
//! ELSE
//!   WAIT 200
//! END
//! ```
//!
//! Everything else is refused before a run starts. `EVAL` and its synonyms never compile,
//! a direct value assignment (`SET`) is a non-native interaction and is refused, and
//! conditions over page state (`IF EXISTS ...`) need a runtime branch the finite action
//! list does not have.

use super::ActorActionV1;
use crate::scrape::{ScrollDirection, MAX_WAIT_MS};
use std::collections::{BTreeMap, BTreeSet};

/// Largest script source, bytes.
pub const MAX_SCRIPT_BYTES: usize = 16 * 1024;
/// Most iterations of one `REPEAT`.
pub const MAX_SCRIPT_REPEAT: u32 = 20;
/// Deepest nesting of `REPEAT` and `IF` blocks.
pub const MAX_SCRIPT_DEPTH: usize = 3;
/// Most distinct variable names, loop variables included.
pub const MAX_SCRIPT_VARIABLES: usize = 16;
/// Most statement evaluations while unrolling, empty iterations included.
pub const MAX_SCRIPT_EVALUATIONS: usize = 2048;
/// Longest variable value or interpolated string, bytes.
pub const MAX_SCRIPT_VALUE: usize = 4096;
const MAX_NAME: usize = 32;

/// Why a script did not compile. Messages carry a line number, never script text, because a
/// script may hold input values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScriptError {
    /// The source is empty or above [`MAX_SCRIPT_BYTES`].
    #[error("actor script is empty or above the byte cap")]
    Size,
    /// The line is not valid grammar.
    #[error("actor script syntax error at line {line}")]
    Syntax {
        /// One-based source line.
        line: u32,
    },
    /// The command is not part of the grammar.
    #[error("actor script command not supported at line {line}")]
    UnknownCommand {
        /// One-based source line.
        line: u32,
    },
    /// `EVAL` or a synonym: script evaluation is never permitted.
    #[error("actor script evaluation is not permitted at line {line}")]
    Eval {
        /// One-based source line.
        line: u32,
    },
    /// `SET`: assigning a page value directly bypasses native input.
    #[error("actor script direct value assignment is a non-native interaction at line {line}")]
    NonNativeInteraction {
        /// One-based source line.
        line: u32,
    },
    /// A condition over page state needs a runtime branch.
    #[error("actor script runtime condition is not supported at line {line}")]
    RuntimeCondition {
        /// One-based source line.
        line: u32,
    },
    /// A repeat count is outside `1..=`[`MAX_SCRIPT_REPEAT`].
    #[error("actor script repeat count is outside the allowed range at line {line}")]
    RepeatRange {
        /// One-based source line.
        line: u32,
    },
    /// Blocks nest deeper than [`MAX_SCRIPT_DEPTH`].
    #[error("actor script nesting is too deep at line {line}")]
    Depth {
        /// One-based source line.
        line: u32,
    },
    /// A `${name}` or `$name` names no variable bound before it.
    #[error("actor script variable is not defined at line {line}")]
    UnknownVariable {
        /// One-based source line.
        line: u32,
    },
    /// More than [`MAX_SCRIPT_VARIABLES`] distinct names.
    #[error("actor script defines too many variables at line {line}")]
    TooManyVariables {
        /// One-based source line.
        line: u32,
    },
    /// The unrolled script exceeds the action, evaluation or value cap.
    #[error("actor script expands beyond its limits")]
    Limit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Str(String),
    Sel(String),
    Assign,
    Equal,
    NotEqual,
}

#[derive(Debug)]
enum Operand {
    Var(String),
    Lit(String),
}

#[derive(Debug)]
enum Cmd {
    Wait(u32),
    Click(String),
    Fill(String, String),
    Type(String),
    Press(String),
    Scroll(ScrollDirection, Option<String>),
}

#[derive(Debug)]
enum Stmt {
    Let {
        line: u32,
        name: String,
        value: String,
    },
    Do {
        line: u32,
        cmd: Cmd,
    },
    Repeat {
        line: u32,
        count: u32,
        var: Option<String>,
        body: Vec<Stmt>,
    },
    If {
        line: u32,
        left: Operand,
        equal: bool,
        right: Operand,
        then: Vec<Stmt>,
        otherwise: Vec<Stmt>,
    },
}

/// Compile `source` into the ordered action list it denotes.
///
/// # Errors
/// [`ScriptError`] for every construct outside the bounded grammar, an exceeded cap or an
/// unbound variable. Nothing executes and nothing is partially returned.
pub fn compile_script(source: &str) -> Result<Vec<ActorActionV1>, ScriptError> {
    if source.trim().is_empty() || source.len() > MAX_SCRIPT_BYTES {
        return Err(ScriptError::Size);
    }
    let mut lines = Vec::new();
    for (index, text) in source.lines().enumerate() {
        let number = u32::try_from(index + 1).map_err(|_| ScriptError::Size)?;
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        lines.push((number, tokenize(text, number)?));
    }
    let mut parser = Parser {
        lines: &lines,
        next: 0,
        declared: BTreeSet::new(),
    };
    let (program, end) = parser.block(0)?;
    if end != End::Eof {
        let line = lines.get(parser.next.saturating_sub(1)).map_or(1, |(n, _)| *n);
        return Err(ScriptError::Syntax { line });
    }
    let mut run = Run {
        out: Vec::new(),
        vars: BTreeMap::new(),
        budget: MAX_SCRIPT_EVALUATIONS,
    };
    run.block(&program)?;
    if run.out.is_empty() {
        return Err(ScriptError::Size);
    }
    Ok(run.out)
}

fn tokenize(text: &str, line: u32) -> Result<Vec<Tok>, ScriptError> {
    let syntax = ScriptError::Syntax { line };
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '"' => {
                chars.next();
                let mut value = String::new();
                loop {
                    match chars.next().ok_or(syntax)? {
                        '"' => break,
                        '\\' => match chars.next().ok_or(syntax)? {
                            '"' => value.push('"'),
                            '\\' => value.push('\\'),
                            _ => return Err(syntax),
                        },
                        other => value.push(other),
                    }
                    if value.len() > MAX_SCRIPT_VALUE {
                        return Err(ScriptError::Limit);
                    }
                }
                out.push(Tok::Str(value));
            }
            '`' => {
                chars.next();
                let mut value = String::new();
                loop {
                    match chars.next().ok_or(syntax)? {
                        '`' => break,
                        other => value.push(other),
                    }
                    if value.len() > MAX_SCRIPT_VALUE {
                        return Err(ScriptError::Limit);
                    }
                }
                out.push(Tok::Sel(value));
            }
            '=' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    out.push(Tok::Equal);
                } else {
                    out.push(Tok::Assign);
                }
            }
            '!' => {
                chars.next();
                if chars.next() != Some('=') {
                    return Err(syntax);
                }
                out.push(Tok::NotEqual);
            }
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || matches!(c, '"' | '`' | '=' | '!') {
                        break;
                    }
                    word.push(c);
                    chars.next();
                    if word.len() > MAX_SCRIPT_VALUE {
                        return Err(ScriptError::Limit);
                    }
                }
                out.push(Tok::Word(word));
            }
        }
    }
    Ok(out)
}

fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name.len() <= MAX_NAME
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    Eof,
    Close,
    Else,
}

struct Parser<'a> {
    lines: &'a [(u32, Vec<Tok>)],
    next: usize,
    declared: BTreeSet<String>,
}

impl Parser<'_> {
    fn declare(&mut self, name: &str, line: u32) -> Result<(), ScriptError> {
        if !valid_name(name) {
            return Err(ScriptError::Syntax { line });
        }
        self.declared.insert(name.to_owned());
        if self.declared.len() > MAX_SCRIPT_VARIABLES {
            return Err(ScriptError::TooManyVariables { line });
        }
        Ok(())
    }

    /// Reject malformed or unbound `${name}` references before anything runs.
    fn check_template(&self, raw: &str, line: u32) -> Result<(), ScriptError> {
        let mut rest = raw;
        while let Some(pos) = rest.find("${") {
            let after = &rest[pos + 2..];
            let end = after.find('}').ok_or(ScriptError::Syntax { line })?;
            let name = &after[..end];
            if !valid_name(name) {
                return Err(ScriptError::Syntax { line });
            }
            if !self.declared.contains(name) {
                return Err(ScriptError::UnknownVariable { line });
            }
            rest = &after[end + 1..];
        }
        Ok(())
    }

    fn block(&mut self, depth: usize) -> Result<(Vec<Stmt>, End), ScriptError> {
        let mut out = Vec::new();
        while let Some((line, tokens)) = self.lines.get(self.next) {
            let line = *line;
            self.next += 1;
            let Some(Tok::Word(head)) = tokens.first() else {
                return Err(ScriptError::Syntax { line });
            };
            let rest = &tokens[1..];
            let command = head.to_ascii_uppercase();
            match command.as_str() {
                "END" if rest.is_empty() => return Ok((out, End::Close)),
                "ELSE" if rest.is_empty() => return Ok((out, End::Else)),
                "LET" => out.push(self.let_stmt(rest, line)?),
                "REPEAT" => out.push(self.repeat_stmt(rest, line, depth)?),
                "IF" => out.push(self.if_stmt(rest, line, depth)?),
                "EVAL" | "EXEC" | "EXECUTE" | "JS" | "JAVASCRIPT" | "SCRIPT" => {
                    return Err(ScriptError::Eval { line })
                }
                "SET" => return Err(ScriptError::NonNativeInteraction { line }),
                "WAIT" | "CLICK" | "FILL" | "TYPE" | "PRESS" | "SCROLL" => {
                    let cmd = self.command(&command, rest, line)?;
                    out.push(Stmt::Do { line, cmd });
                }
                _ => return Err(ScriptError::UnknownCommand { line }),
            }
        }
        Ok((out, End::Eof))
    }

    fn let_stmt(&mut self, rest: &[Tok], line: u32) -> Result<Stmt, ScriptError> {
        let [Tok::Word(name), Tok::Assign, Tok::Str(value)] = rest else {
            return Err(ScriptError::Syntax { line });
        };
        self.check_template(value, line)?;
        self.declare(name, line)?;
        Ok(Stmt::Let {
            line,
            name: name.clone(),
            value: value.clone(),
        })
    }

    fn repeat_stmt(&mut self, rest: &[Tok], line: u32, depth: usize) -> Result<Stmt, ScriptError> {
        if depth >= MAX_SCRIPT_DEPTH {
            return Err(ScriptError::Depth { line });
        }
        let (count, var) = match rest {
            [Tok::Word(n)] => (n, None),
            [Tok::Word(n), Tok::Word(kw), Tok::Word(name)] if kw.eq_ignore_ascii_case("as") => {
                (n, Some(name.clone()))
            }
            _ => return Err(ScriptError::Syntax { line }),
        };
        let count: u32 = count.parse().map_err(|_| ScriptError::Syntax { line })?;
        if !(1..=MAX_SCRIPT_REPEAT).contains(&count) {
            return Err(ScriptError::RepeatRange { line });
        }
        if let Some(name) = &var {
            self.declare(name, line)?;
        }
        let (body, end) = self.block(depth + 1)?;
        if end != End::Close {
            return Err(ScriptError::Syntax { line });
        }
        Ok(Stmt::Repeat {
            line,
            count,
            var,
            body,
        })
    }

    fn operand(&self, token: &Tok, line: u32) -> Result<Operand, ScriptError> {
        match token {
            Tok::Str(value) => {
                self.check_template(value, line)?;
                Ok(Operand::Lit(value.clone()))
            }
            Tok::Word(word) => {
                let name = word.strip_prefix('$').ok_or(ScriptError::Syntax { line })?;
                if !valid_name(name) {
                    return Err(ScriptError::Syntax { line });
                }
                if !self.declared.contains(name) {
                    return Err(ScriptError::UnknownVariable { line });
                }
                Ok(Operand::Var(name.to_owned()))
            }
            _ => Err(ScriptError::Syntax { line }),
        }
    }

    fn if_stmt(&mut self, rest: &[Tok], line: u32, depth: usize) -> Result<Stmt, ScriptError> {
        if depth >= MAX_SCRIPT_DEPTH {
            return Err(ScriptError::Depth { line });
        }
        let runtime = rest.iter().any(|t| matches!(t, Tok::Sel(_)))
            || matches!(rest.first(), Some(Tok::Word(w)) if w.eq_ignore_ascii_case("exists")
                || w.eq_ignore_ascii_case("visible"));
        if runtime {
            return Err(ScriptError::RuntimeCondition { line });
        }
        let [left, op, right] = rest else {
            return Err(ScriptError::Syntax { line });
        };
        let equal = match op {
            Tok::Equal => true,
            Tok::NotEqual => false,
            _ => return Err(ScriptError::Syntax { line }),
        };
        let left = self.operand(left, line)?;
        let right = self.operand(right, line)?;
        let (then, end) = self.block(depth + 1)?;
        let otherwise = match end {
            End::Close => Vec::new(),
            End::Else => {
                let (otherwise, end) = self.block(depth + 1)?;
                if end != End::Close {
                    return Err(ScriptError::Syntax { line });
                }
                otherwise
            }
            End::Eof => return Err(ScriptError::Syntax { line }),
        };
        Ok(Stmt::If {
            line,
            left,
            equal,
            right,
            then,
            otherwise,
        })
    }

    fn command(&self, command: &str, rest: &[Tok], line: u32) -> Result<Cmd, ScriptError> {
        let syntax = ScriptError::Syntax { line };
        match (command, rest) {
            ("WAIT", [Tok::Word(ms)]) => {
                let ms: u32 = ms.parse().map_err(|_| syntax)?;
                if ms == 0 || ms > MAX_WAIT_MS {
                    return Err(syntax);
                }
                Ok(Cmd::Wait(ms))
            }
            ("CLICK", [Tok::Sel(selector)]) => {
                self.check_template(selector, line)?;
                Ok(Cmd::Click(selector.clone()))
            }
            ("FILL", [Tok::Sel(selector), Tok::Str(text)]) => {
                self.check_template(selector, line)?;
                self.check_template(text, line)?;
                Ok(Cmd::Fill(selector.clone(), text.clone()))
            }
            ("TYPE", [Tok::Str(text)]) => {
                self.check_template(text, line)?;
                Ok(Cmd::Type(text.clone()))
            }
            ("PRESS", [Tok::Word(key) | Tok::Str(key)]) => Ok(Cmd::Press(key.clone())),
            ("SCROLL", [Tok::Word(direction)]) => Ok(Cmd::Scroll(direction_of(direction, line)?, None)),
            ("SCROLL", [Tok::Word(direction), Tok::Sel(selector)]) => {
                self.check_template(selector, line)?;
                Ok(Cmd::Scroll(
                    direction_of(direction, line)?,
                    Some(selector.clone()),
                ))
            }
            _ => Err(syntax),
        }
    }
}

fn direction_of(word: &str, line: u32) -> Result<ScrollDirection, ScriptError> {
    if word.eq_ignore_ascii_case("up") {
        Ok(ScrollDirection::Up)
    } else if word.eq_ignore_ascii_case("down") {
        Ok(ScrollDirection::Down)
    } else {
        Err(ScriptError::Syntax { line })
    }
}

struct Run {
    out: Vec<ActorActionV1>,
    vars: BTreeMap<String, String>,
    budget: usize,
}

impl Run {
    fn charge(&mut self) -> Result<(), ScriptError> {
        self.budget = self.budget.checked_sub(1).ok_or(ScriptError::Limit)?;
        Ok(())
    }

    fn emit(&mut self, action: ActorActionV1) -> Result<(), ScriptError> {
        if self.out.len() >= crate::archive_behaviors::MAX_RECIPE_STEPS {
            return Err(ScriptError::Limit);
        }
        self.out.push(action);
        Ok(())
    }

    fn expand(&self, raw: &str, line: u32) -> Result<String, ScriptError> {
        let mut out = String::new();
        let mut rest = raw;
        while let Some(pos) = rest.find("${") {
            out.push_str(&rest[..pos]);
            let after = &rest[pos + 2..];
            let end = after.find('}').ok_or(ScriptError::Syntax { line })?;
            let value = self
                .vars
                .get(&after[..end])
                .ok_or(ScriptError::UnknownVariable { line })?;
            out.push_str(value);
            if out.len() > MAX_SCRIPT_VALUE {
                return Err(ScriptError::Limit);
            }
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        if out.len() > MAX_SCRIPT_VALUE {
            return Err(ScriptError::Limit);
        }
        Ok(out)
    }

    fn bind(&mut self, name: &str, value: String, line: u32) -> Result<(), ScriptError> {
        if !self.vars.contains_key(name) && self.vars.len() >= MAX_SCRIPT_VARIABLES {
            return Err(ScriptError::TooManyVariables { line });
        }
        self.vars.insert(name.to_owned(), value);
        Ok(())
    }

    fn operand(&self, operand: &Operand, line: u32) -> Result<String, ScriptError> {
        match operand {
            Operand::Lit(raw) => self.expand(raw, line),
            Operand::Var(name) => self
                .vars
                .get(name)
                .cloned()
                .ok_or(ScriptError::UnknownVariable { line }),
        }
    }

    fn block(&mut self, stmts: &[Stmt]) -> Result<(), ScriptError> {
        for stmt in stmts {
            self.charge()?;
            match stmt {
                Stmt::Let { line, name, value } => {
                    let value = self.expand(value, *line)?;
                    self.bind(name, value, *line)?;
                }
                Stmt::Do { line, cmd } => {
                    let action = self.action(cmd, *line)?;
                    self.emit(action)?;
                }
                Stmt::Repeat {
                    line,
                    count,
                    var,
                    body,
                } => {
                    let prior = var.as_ref().and_then(|name| self.vars.get(name).cloned());
                    for iteration in 1..=*count {
                        if let Some(name) = var {
                            self.bind(name, iteration.to_string(), *line)?;
                        }
                        self.block(body)?;
                    }
                    if let Some(name) = var {
                        match prior {
                            Some(value) => {
                                self.vars.insert(name.clone(), value);
                            }
                            None => {
                                self.vars.remove(name);
                            }
                        }
                    }
                }
                Stmt::If {
                    line,
                    left,
                    equal,
                    right,
                    then,
                    otherwise,
                } => {
                    let same = self.operand(left, *line)? == self.operand(right, *line)?;
                    self.block(if same == *equal { then } else { otherwise })?;
                }
            }
        }
        Ok(())
    }

    fn action(&self, cmd: &Cmd, line: u32) -> Result<ActorActionV1, ScriptError> {
        Ok(match cmd {
            Cmd::Wait(milliseconds) => ActorActionV1::Wait {
                milliseconds: *milliseconds,
            },
            Cmd::Click(selector) => ActorActionV1::Click {
                selector: self.expand(selector, line)?,
            },
            Cmd::Fill(selector, text) => ActorActionV1::Fill {
                selector: self.expand(selector, line)?,
                text: self.expand(text, line)?,
            },
            Cmd::Type(text) => ActorActionV1::Write {
                text: self.expand(text, line)?,
            },
            Cmd::Press(key) => ActorActionV1::Press { key: key.clone() },
            Cmd::Scroll(direction, selector) => ActorActionV1::Scroll {
                direction: *direction,
                selector: selector.as_deref().map(|s| self.expand(s, line)).transpose()?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn click(selector: &str) -> ActorActionV1 {
        ActorActionV1::Click {
            selector: selector.into(),
        }
    }

    #[test]
    fn variables_repeat_and_if_unroll_into_the_flat_vocabulary() {
        let source = r#"
            # sign in then page through results
            LET user = "reader"
            FILL `input[name=user]` "${user}"
            TYPE "x\"y"
            PRESS Enter
            REPEAT 3 AS page
              CLICK `li:nth-child(${page})`
              IF $page == "2"
                WAIT 250
              ELSE
                SCROLL down
              END
            END
            IF $user != "reader"
              CLICK `never`
            END
            SCROLL up `#feed`
            WAIT 10
        "#;
        let actions = compile_script(source).unwrap();
        assert_eq!(
            actions,
            vec![
                ActorActionV1::Fill {
                    selector: "input[name=user]".into(),
                    text: "reader".into()
                },
                ActorActionV1::Write { text: "x\"y".into() },
                ActorActionV1::Press { key: "Enter".into() },
                click("li:nth-child(1)"),
                ActorActionV1::Scroll {
                    direction: ScrollDirection::Down,
                    selector: None
                },
                click("li:nth-child(2)"),
                ActorActionV1::Wait { milliseconds: 250 },
                click("li:nth-child(3)"),
                ActorActionV1::Scroll {
                    direction: ScrollDirection::Down,
                    selector: None
                },
                ActorActionV1::Scroll {
                    direction: ScrollDirection::Up,
                    selector: Some("#feed".into())
                },
                ActorActionV1::Wait { milliseconds: 10 },
            ]
        );
        assert_eq!(
            compile_script(source).unwrap(),
            actions,
            "compilation is deterministic"
        );
    }

    #[test]
    fn loops_over_the_cap_and_oversized_expansions_are_refused() {
        assert_eq!(
            compile_script("REPEAT 21\nCLICK `a`\nEND"),
            Err(ScriptError::RepeatRange { line: 1 })
        );
        assert_eq!(
            compile_script("REPEAT 0\nCLICK `a`\nEND"),
            Err(ScriptError::RepeatRange { line: 1 })
        );
        assert_eq!(compile_script("REPEAT 20\nCLICK `a`\nEND").unwrap().len(), 20);
        // 20 x 3 = 60 actions: above the finite recipe step cap
        assert_eq!(
            compile_script("REPEAT 20\nREPEAT 3\nCLICK `a`\nEND\nEND"),
            Err(ScriptError::Limit)
        );
        // empty iterations are charged too, so nesting cannot spin
        assert_eq!(
            compile_script("REPEAT 20\nREPEAT 20\nREPEAT 20\nLET a = \"x\"\nEND\nEND\nEND\nCLICK `a`"),
            Err(ScriptError::Limit)
        );
        let deep =
            "REPEAT 1\n".repeat(MAX_SCRIPT_DEPTH + 1) + "CLICK `a`\n" + &"END\n".repeat(MAX_SCRIPT_DEPTH + 1);
        assert!(matches!(compile_script(&deep), Err(ScriptError::Depth { .. })));
        assert_eq!(
            compile_script(&"CLICK `a`\n".repeat(MAX_SCRIPT_BYTES)),
            Err(ScriptError::Size)
        );
        assert_eq!(compile_script(" \n# only a comment"), Err(ScriptError::Size));
    }

    #[test]
    fn eval_direct_set_and_runtime_conditions_never_compile() {
        for source in [
            "EVAL `window.location = 'x'`",
            "eval \"1\"",
            "REPEAT 2\nEvAl `x`\nEND",
            "IF $a == \"b\"\nEXECUTE `x`\nEND",
            "JAVASCRIPT `x`",
        ] {
            let error = compile_script(&format!("LET a = \"b\"\n{source}")).unwrap_err();
            assert!(matches!(error, ScriptError::Eval { .. }), "{source}: {error}");
        }
        assert!(matches!(
            compile_script("SET `input` \"value\""),
            Err(ScriptError::NonNativeInteraction { line: 1 })
        ));
        assert!(matches!(
            compile_script("IF EXISTS `#login`\nCLICK `#login`\nEND"),
            Err(ScriptError::RuntimeCondition { line: 1 })
        ));
        // refused even when the branch can never run
        assert!(matches!(
            compile_script("LET a = \"b\"\nIF $a == \"c\"\nEVAL `x`\nEND"),
            Err(ScriptError::Eval { line: 3 })
        ));
        for source in ["GO \"https://example.test/\"", "RELOAD", "CLICK_XY 1 2"] {
            assert!(matches!(
                compile_script(source),
                Err(ScriptError::UnknownCommand { .. })
            ));
        }
    }

    #[test]
    fn variables_are_bound_before_use_bounded_and_scoped() {
        assert!(matches!(
            compile_script("CLICK `${missing}`"),
            Err(ScriptError::UnknownVariable { line: 1 })
        ));
        assert!(matches!(
            compile_script("IF $missing == \"a\"\nWAIT 1\nEND"),
            Err(ScriptError::UnknownVariable { line: 1 })
        ));
        assert!(matches!(
            compile_script("REPEAT 2 AS i\nWAIT 1\nEND\nCLICK `${i}`"),
            Err(ScriptError::UnknownVariable { .. })
        ));
        let many: String = (0..=MAX_SCRIPT_VARIABLES)
            .map(|i| format!("LET v{i} = \"x\"\n"))
            .collect();
        assert!(matches!(
            compile_script(&(many + "WAIT 1")),
            Err(ScriptError::TooManyVariables { .. })
        ));
        let long = "x".repeat(MAX_SCRIPT_VALUE);
        assert_eq!(
            compile_script(&format!("LET a = \"{long}\"\nTYPE \"${{a}}${{a}}\"")),
            Err(ScriptError::Limit)
        );
        for bad in [
            "LET 1x = \"a\"",
            "LET a = b",
            "WAIT 0",
            "WAIT 60001",
            "WAIT soon",
            "CLICK \"a\"",
            "SCROLL sideways",
            "TYPE \"unterminated",
            "END",
            "ELSE",
            "REPEAT 2\nWAIT 1",
            "IF \"a\" == \"a\"\nWAIT 1",
            "FILL `a`",
            "TYPE \"${a\"",
        ] {
            assert!(compile_script(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn errors_never_echo_script_text() {
        let secret = "private-input-marker";
        for source in [
            format!("FILL `input` \"{secret}\"\nEVAL `{secret}`"),
            format!("SET `input` \"{secret}\""),
            format!("TYPE \"{secret}\" extra"),
            format!("LET a = \"{secret}\"\nCLICK `${{b}}`"),
        ] {
            let message = compile_script(&source).unwrap_err().to_string();
            assert!(!message.contains(secret), "{message}");
        }
    }
}
