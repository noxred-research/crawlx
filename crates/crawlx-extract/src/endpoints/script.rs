//! Regex-based endpoint mining of script text, script/stylesheet files and
//! textual page bodies (compatibility flag `-jc`).
//!
//! Ported from an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md;
//! the patterns are verbatim except one deviation: the absolute
//! alternative of `pageBodyRegex` accepts an explicit `:port`, the same
//! `(?:\:\d{1,5})?` group the reference `relativeEndpointsRegex` already has (an
//! upstream `http://host:8080/x` in page text was otherwise missed). Both regexes
//! compile once with explicit size limits so a pattern change can never blow up
//! compilation memory, and a failed compile degrades to "no matches" instead of
//! panicking.

use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};

/// Compiled-program size limit for the ported patterns.
const REGEX_SIZE_LIMIT: usize = 4 << 20;

/// `pageBodyRegex`: endpoints in arbitrary page bodies (relative `./x`,
/// absolute `http(s)://…/x`, and paths with a known dynamic/static extension).
const PAGE_BODY: &str = concat!(
    r"(?:",
    r"(",
    r"(?:[\.]{1,2}/[A-Za-z0-9\-_/\\?&@\.?=%]+)",
    r"|(https?://[A-Za-z0-9_\-\.]+(?:\:\d{1,5})?([\.]{0,2})?\/[A-Za-z0-9\-_/\\?&@\.?=%]+)",
    r"|(/[A-Za-z0-9\-_/\\?&@\.%]+\.(aspx?|action|cfm|cgi|do|pl|css|x?html?|js(p|on)?|pdf|php5?|py|rss))",
    r"|([A-Za-z0-9\-_?&@\.%]+/[A-Za-z0-9/\\\-_?&@\.%]+\.(aspx?|action|cfm|cgi|do|pl|css|x?html?|js(p|on)?|pdf|php5?|py|rss))",
    r")",
    r")",
);

/// `relativeEndpointsRegex`: endpoints quoted inside JavaScript/CSS text.
const RELATIVE_ENDPOINTS: &str = concat!(
    r#"(?:"|'|\s)"#,
    r"(",
    r#"((https?://[A-Za-z0-9_\-.]+(?:\:\d{1,5})?)+([\.]{1,2})?/[A-Za-z0-9/\-_\\.%]+(?:[\?|#][^"']+)?)"#,
    r#"|((\.{1,2}/)?[a-zA-Z0-9\-_/\\%]+\.(aspx?|js(?:on|p)?|html|php5?|action|do)(?:[\?|#][^"']+)?)"#,
    r#"|((\.{0,2}/)[a-zA-Z0-9\-_/\\%]+(?:/|\\)[a-zA-Z0-9\-_]{3,}(?:[\?|#][^"']+)?)"#,
    r"|((\.{0,2})[a-zA-Z0-9\-_/\\%]{3,}/)",
    r")",
    r#"(?:"|'|\s)"#,
);

fn compile(pattern: &str) -> Option<Regex> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .ok()
}

static PAGE_BODY_RE: LazyLock<Option<Regex>> = LazyLock::new(|| compile(PAGE_BODY));
static RELATIVE_RE: LazyLock<Option<Regex>> = LazyLock::new(|| compile(RELATIVE_ENDPOINTS));

/// Both ported patterns compiled (asserted by tests; a broken pattern would
/// otherwise silently disable mining).
#[must_use]
pub fn patterns_compiled() -> bool {
    PAGE_BODY_RE.is_some() && RELATIVE_RE.is_some()
}

fn unique_group1<'a>(re: &Regex, data: &'a str) -> Vec<&'a str> {
    let mut out: Vec<&'a str> = Vec::new();
    for caps in re.captures_iter(data) {
        if let Some(m) = caps.get(1) {
            let s = m.as_str();
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

/// `ExtractBodyEndpoints`: unique endpoint strings of a textual page body, in order.
#[must_use]
pub fn extract_body_endpoints(data: &str) -> Vec<&str> {
    PAGE_BODY_RE
        .as_ref()
        .map_or_else(Vec::new, |re| unique_group1(re, data))
}

/// `ExtractRelativeEndpoints`: unique endpoint strings quoted in script text, in order.
#[must_use]
pub fn extract_relative_endpoints(data: &str) -> Vec<&str> {
    RELATIVE_RE
        .as_ref()
        .map_or_else(Vec::new, |re| unique_group1(re, data))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn patterns_compile() {
        assert!(patterns_compiled());
    }

    #[test]
    fn relative_endpoints_from_js() {
        let js = r#"fetch("/api/v1/users.json"); const u = './assets/app.js'; var x = "https://cdn.example.com/lib/x.js";"#;
        let got = extract_relative_endpoints(js);
        assert!(got.contains(&"/api/v1/users.json"), "{got:?}");
        assert!(got.contains(&"./assets/app.js"), "{got:?}");
        assert!(got.contains(&"https://cdn.example.com/lib/x.js"), "{got:?}");
    }

    #[test]
    fn body_endpoints_dedupe() {
        let got = extract_body_endpoints("see ./a/b.html and ./a/b.html and /x/y.php");
        assert_eq!(got, vec!["./a/b.html", "/x/y.php"]);
    }
}
