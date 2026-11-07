//! Output filters (katana `-mr`, `-fr`, `-em`, `-ef`).
//!
//! Semantics from katana `pkg/output/output.go` (`Write`, `matchOutput`, `filterOutput`) at
//! commit `9662cd7b60ba1bc3a88232433ddefc4f48a65bfe` (MIT): the extension filter is checked
//! on the URL path first; then the result is kept only when any match regex matches (when
//! match regexes are given) and dropped when any filter regex matches. Katana tests its
//! regexes against the request URL; here they are tested against the URL and against the
//! rendered line, so a filter can also select on a field or template value.
//!
//! A `-mdc` / `-fdc` condition ([`super::Dsl`]) joins the regexes exactly as in katana: a
//! result matches when any match regex hits **or** the match condition holds (when neither
//! is configured everything matches), and is filtered when any filter regex hits **or** the
//! filter condition holds. [`OutputFilters::accept_with`] takes the evaluated conditions.
//!
//! `-mr`/`-fr` values are lists ([`expand_patterns`]): an existing file name stands for its
//! lines, otherwise the value is split on commas outside quotes.

use crawlx_url::ExtensionFilter;
use regex::Regex;
use std::path::Path;
use thiserror::Error;
use url::Url;

/// Maximum length of one match/filter regex.
pub const MAX_PATTERN_LEN: usize = 512;

/// A rejected filter configuration.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FilterError {
    /// A regex longer than [`MAX_PATTERN_LEN`] bytes.
    #[error("output regex is {len} bytes, longer than {MAX_PATTERN_LEN}")]
    PatternTooLong {
        /// Length of the rejected pattern in bytes.
        len: usize,
    },
    /// A regex that does not compile.
    #[error("invalid output regex")]
    InvalidPattern(#[from] regex::Error),
    /// A quote in a pattern list that is never closed.
    #[error("unclosed quote in pattern list `{list}`")]
    UnclosedQuote {
        /// The list as given.
        list: String,
    },
    /// A pattern file that cannot be read.
    #[error("reading pattern file {path}")]
    PatternFile {
        /// The file.
        path: String,
        /// Why it could not be read.
        #[source]
        source: std::io::Error,
    },
}

/// Compiled match/filter regexes and extension allow/deny lists.
#[derive(Clone, Debug, Default)]
pub struct OutputFilters {
    match_regex: Vec<Regex>,
    filter_regex: Vec<Regex>,
    extensions: ExtensionFilter,
}

fn compile(patterns: &[String]) -> Result<Vec<Regex>, FilterError> {
    patterns
        .iter()
        .map(|p| {
            if p.len() > MAX_PATTERN_LEN {
                return Err(FilterError::PatternTooLong { len: p.len() });
            }
            Ok(Regex::new(p)?)
        })
        .collect()
}

/// Split one list value on commas outside single or double quotes; a quoted part is taken
/// verbatim without its quotes. Blank parts are dropped.
fn split_list(value: &str) -> Result<Vec<String>, FilterError> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in value.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => current.push(c),
            (None, '\'' | '"') => quote = Some(ch),
            (None, ',') => parts.push(std::mem::take(&mut current)),
            (None, c) => current.push(c),
        }
    }
    if quote.is_some() {
        return Err(FilterError::UnclosedQuote {
            list: value.to_owned(),
        });
    }
    parts.push(current);
    Ok(parts
        .into_iter()
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect())
}

/// Expand `-mr` / `-fr` arguments the way katana's `goflags` file-or-list slice does: a
/// value naming an existing file stands for the file's lines (blank lines and `#` comment
/// lines are skipped), any other value is split on commas outside quotes. A pattern that
/// needs a literal comma is quoted (`'a{1,3}'`) or put in a file.
///
/// # Errors
/// [`FilterError::PatternFile`] when a pattern file cannot be read,
/// [`FilterError::UnclosedQuote`] for a list with an unclosed quote.
pub fn expand_patterns(values: &[String]) -> Result<Vec<String>, FilterError> {
    let mut out = Vec::new();
    for value in values {
        if !value.is_empty() && Path::new(value).is_file() {
            let text = std::fs::read_to_string(value).map_err(|source| FilterError::PatternFile {
                path: value.clone(),
                source,
            })?;
            out.extend(
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_owned),
            );
        } else {
            out.extend(split_list(value)?);
        }
    }
    Ok(out)
}

impl OutputFilters {
    /// Compile the filters. Extension entries are normalized (lowercase, leading dot
    /// stripped, `none` = no extension); no default deny list applies.
    ///
    /// # Errors
    /// [`FilterError`] for a regex that is too long or invalid.
    pub fn new(
        match_regex: &[String],
        filter_regex: &[String],
        extension_match: &[String],
        extension_filter: &[String],
    ) -> Result<Self, FilterError> {
        Ok(Self {
            match_regex: compile(match_regex)?,
            filter_regex: compile(filter_regex)?,
            extensions: ExtensionFilter::new(extension_match, extension_filter, true),
        })
    }

    /// Does the configuration accept everything?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.match_regex.is_empty() && self.filter_regex.is_empty() && self.extensions.is_permissive()
    }

    /// Should the `line` rendered for `url` be emitted? Regexes and extensions only; see
    /// [`OutputFilters::accept_with`] for conditions.
    #[must_use]
    pub fn accept(&self, url: &Url, line: &str) -> bool {
        self.accept_with(url, line, None, None)
    }

    /// [`OutputFilters::accept`] with the results of the `-mdc` / `-fdc` conditions
    /// (`None` = not configured). With a match condition the result is kept when a match
    /// regex hits or the condition holds; a filter condition that holds drops the result like
    /// a filter regex does.
    #[must_use]
    pub fn accept_with(
        &self,
        url: &Url,
        line: &str,
        match_condition: Option<bool>,
        filter_condition: Option<bool>,
    ) -> bool {
        if !self.extensions.allows(url) {
            return false;
        }
        let url_str = url.as_str();
        let hits = |r: &Regex| r.is_match(url_str) || r.is_match(line);
        let constrained = !self.match_regex.is_empty() || match_condition.is_some();
        if constrained && !(self.match_regex.iter().any(hits) || match_condition == Some(true)) {
            return false;
        }
        !(self.filter_regex.iter().any(hits) || filter_condition == Some(true))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    fn url(u: &str) -> Url {
        Url::parse(u).unwrap()
    }

    #[test]
    fn empty_filters_accept_everything() {
        let f = OutputFilters::default();
        assert!(f.is_empty());
        assert!(f.accept(&url("https://e.com/a.png"), "anything"));
    }

    #[test]
    fn match_wins_only_when_a_match_regex_hits() {
        let f = OutputFilters::new(&s(&["/api/", "admin"]), &[], &[], &[]).unwrap();
        assert!(f.accept(&url("https://e.com/api/v1"), "x"));
        assert!(f.accept(&url("https://e.com/x"), "admin=1"), "line match counts");
        assert!(!f.accept(&url("https://e.com/x"), "y"));
    }

    #[test]
    fn filter_rejects_when_any_filter_regex_hits() {
        let f = OutputFilters::new(&s(&["api"]), &s(&["logout"]), &[], &[]).unwrap();
        assert!(f.accept(&url("https://e.com/api/a"), "x"));
        assert!(!f.accept(&url("https://e.com/api/logout"), "x"));
        assert!(!f.accept(&url("https://e.com/api/a"), "logout"));
    }

    #[test]
    fn extensions_compare_on_the_url_path() {
        let f = OutputFilters::new(&[], &[], &s(&[".JS", "php"]), &[]).unwrap();
        assert!(f.accept(&url("https://e.com/app.js?x=.png"), "x"));
        assert!(f.accept(&url("https://e.com/a/b.PHP"), "x"));
        assert!(!f.accept(&url("https://e.com/a/b.png"), "x"));
        assert!(!f.accept(&url("https://e.com/a/"), "x"));
        let f = OutputFilters::new(&[], &[], &[], &s(&["png", "none"])).unwrap();
        assert!(f.accept(&url("https://e.com/a.js"), "x"));
        assert!(!f.accept(&url("https://e.com/a.png"), "x"));
        assert!(!f.accept(&url("https://e.com/a"), "x"));
        assert!(!f.is_empty());
    }

    #[test]
    fn retained_export_dotfile_filters_have_no_implicit_default_deny_list() {
        let dotfile = url("https://e.com/.PNG?name=.html");
        let trailing_dot = url("https://e.com/file.");
        let extensionless = url("https://e.com/page");
        let unfiltered = OutputFilters::new(&[], &[], &[], &[]).unwrap();
        assert!(unfiltered.accept(&dotfile, "x"));
        assert!(unfiltered.accept(&trailing_dot, "x"));
        let deny_png = OutputFilters::new(&[], &[], &[], &s(&["png"])).unwrap();
        assert!(!deny_png.accept_with(&dotfile, "x", Some(true), None));
        let select_png = OutputFilters::new(&[], &[], &s(&["png"]), &[]).unwrap();
        assert!(select_png.accept(&dotfile, "x"));
        assert!(!select_png.accept(&trailing_dot, "x"));
        let select_none = OutputFilters::new(&[], &[], &s(&["none"]), &[]).unwrap();
        assert!(select_none.accept(&extensionless, "x"));
        assert!(!select_none.accept(&dotfile, "x"));
        assert!(!select_none.accept(&trailing_dot, "x"));
        let select_dot = OutputFilters::new(&[], &[], &s(&["."]), &[]).unwrap();
        assert!(select_dot.accept(&trailing_dot, "x"));
        assert!(!select_dot.accept(&extensionless, "x"));
        assert!(!select_dot.accept(&dotfile, "x"));
    }

    #[test]
    fn bad_patterns_are_rejected() {
        assert!(matches!(
            OutputFilters::new(&s(&["("]), &[], &[], &[]),
            Err(FilterError::InvalidPattern(_))
        ));
        assert!(matches!(
            OutputFilters::new(&[], &[String::from("a").repeat(513)], &[], &[]),
            Err(FilterError::PatternTooLong { len: 513 })
        ));
    }

    #[test]
    fn conditions_join_the_regexes_like_katana() {
        let u = url("https://e.com/a");
        // a match condition alone decides
        let f = OutputFilters::default();
        assert!(f.accept_with(&u, "x", Some(true), None));
        assert!(!f.accept_with(&u, "x", Some(false), None));
        // regex OR condition
        let f = OutputFilters::new(&s(&["/a$"]), &[], &[], &[]).unwrap();
        assert!(
            f.accept_with(&u, "x", Some(false), None),
            "regex hit keeps the result"
        );
        let f = OutputFilters::new(&s(&["nope"]), &[], &[], &[]).unwrap();
        assert!(
            f.accept_with(&u, "x", Some(true), None),
            "condition keeps the result"
        );
        assert!(!f.accept_with(&u, "x", Some(false), None));
        assert!(!f.accept_with(&u, "x", None, None));
        // a filter condition that holds drops the result, one that does not hold keeps it
        let f = OutputFilters::default();
        assert!(!f.accept_with(&u, "x", None, Some(true)));
        assert!(f.accept_with(&u, "x", None, Some(false)));
        // filter beats match
        assert!(!f.accept_with(&u, "x", Some(true), Some(true)));
        // extensions still apply first
        let f = OutputFilters::new(&[], &[], &[], &s(&["png"])).unwrap();
        assert!(!f.accept_with(&url("https://e.com/a.png"), "x", Some(true), None));
    }

    #[test]
    fn pattern_lists_split_on_commas_outside_quotes() {
        assert_eq!(
            expand_patterns(&s(&["a,b", " c ,, d"])).unwrap(),
            ["a", "b", "c", "d"]
        );
        assert_eq!(expand_patterns(&s(&["'a{1,3}',b"])).unwrap(), ["a{1,3}", "b"]);
        assert_eq!(expand_patterns(&s(&["\"x,y\""])).unwrap(), ["x,y"]);
        assert!(expand_patterns(&[]).unwrap().is_empty());
        assert!(matches!(
            expand_patterns(&s(&["'oops,b"])),
            Err(FilterError::UnclosedQuote { .. })
        ));
    }

    #[test]
    fn pattern_files_stand_for_their_lines() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("patterns.txt");
        std::fs::write(&file, "# comment\n/api/\n\n  admin  \na,b\n").unwrap();
        let got = expand_patterns(&[file.to_string_lossy().into_owned(), "x,y".to_owned()]).unwrap();
        assert_eq!(
            got,
            ["/api/", "admin", "a,b", "x", "y"],
            "file lines are not comma split"
        );
        let f = OutputFilters::new(&got, &[], &[], &[]).unwrap();
        assert!(f.accept(&url("https://e.com/api/v1"), "z"));
        assert!(!f.accept(&url("https://e.com/other"), "z"));
    }
}
