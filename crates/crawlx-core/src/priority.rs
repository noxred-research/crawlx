//! The native `priority` frontier strategy, derived from newer-main Katana
//! `pkg/engine/common/priority.go` (MIT), not Katana v1.8.0: every
//! URL gets a *surface score* and is ordered by `depth - score`, so one score point is worth
//! one level of depth and a promising link a level deeper still goes ahead of a plain one.
//!
//! Pure and deterministic: the score depends only on the URL and the request method.

use url::Url;

/// Path segments that usually lead to more attack surface than an average page.
const SURFACE_WORDS: [&str; 35] = [
    "admin",
    "administrator",
    "api",
    "graphql",
    "rest",
    "upload",
    "uploads",
    "file",
    "files",
    "download",
    "import",
    "export",
    "backup",
    "auth",
    "login",
    "signin",
    "signup",
    "register",
    "oauth",
    "sso",
    "token",
    "password",
    "reset",
    "account",
    "user",
    "users",
    "profile",
    "dashboard",
    "manage",
    "console",
    "config",
    "settings",
    "debug",
    "internal",
    "swagger",
];

/// Highest score [`surface_score`] returns (word 2, query 1, non-GET 1).
pub const MAX_SCORE: u32 = 4;

/// Surface score of a request: 2 for the first attack-surface word in the path, 1 for a
/// query string, 1 for a method other than `GET`.
#[must_use]
pub fn surface_score(url: &Url, is_get: bool) -> u32 {
    let mut score = 0;
    if url
        .path()
        .split(|c: char| !c.is_alphanumeric())
        .any(|w| SURFACE_WORDS.iter().any(|s| s.eq_ignore_ascii_case(w)))
    {
        score += 2;
    }
    if url.query().is_some_and(|q| !q.is_empty()) {
        score += 1;
    }
    if !is_get {
        score += 1;
    }
    score
}

/// Queue key of a URL at `depth` under the priority strategy: `depth - score` shifted by
/// [`MAX_SCORE`] so it stays unsigned. Lower is visited first.
#[must_use]
pub fn priority_depth(url: &Url, depth: u32, is_get: bool) -> u32 {
    depth
        .saturating_add(MAX_SCORE)
        .saturating_sub(surface_score(url, is_get))
}

/// Deterministic strategy key within one explicit request-priority tier.
///
/// Breadth-first uses depth and discovery order. Depth-first uses descending depth
/// and reverse discovery order. Priority uses the surface-adjusted depth, then
/// breadth-first tie-breaks. Callers must compare explicit request priorities first.
#[must_use]
pub fn strategy_order(
    strategy: crate::config::CrawlStrategy,
    depth: u16,
    scored_depth: u32,
    id: i64,
) -> (i64, i64, i64) {
    match strategy {
        crate::config::CrawlStrategy::BreadthFirst => (i64::from(depth), 0, id),
        crate::config::CrawlStrategy::DepthFirst => (-i64::from(depth), 0, !id),
        crate::config::CrawlStrategy::Priority => (i64::from(scored_depth), i64::from(depth), id),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn words_query_and_method_add_up() {
        assert_eq!(surface_score(&u("https://a.test/blog/post"), true), 0);
        assert_eq!(surface_score(&u("https://a.test/admin/panel"), true), 2);
        assert_eq!(surface_score(&u("https://a.test/blog?id=1"), true), 1);
        assert_eq!(surface_score(&u("https://a.test/blog"), false), 1);
        assert_eq!(
            surface_score(&u("https://a.test/api/v1/users?x=1"), false),
            MAX_SCORE
        );
    }

    #[test]
    fn only_whole_words_count_and_only_once() {
        assert_eq!(surface_score(&u("https://a.test/administrators-guide"), true), 0);
        assert_eq!(surface_score(&u("https://a.test/Admin/API/login"), true), 2);
        assert_eq!(surface_score(&u("https://a.test/user-profile"), true), 2);
    }

    #[test]
    fn a_surface_link_one_level_deeper_beats_a_plain_one() {
        let plain = priority_depth(&u("https://a.test/blog/a"), 1, true);
        let surface = priority_depth(&u("https://a.test/admin/a"), 2, true);
        assert!(surface < plain, "{surface} < {plain}");
        assert_eq!(priority_depth(&u("https://a.test/api/x?q=1"), 0, true), 1);
    }
}
