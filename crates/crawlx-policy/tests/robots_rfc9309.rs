//! RFC 9309 conformance corpus for `crawlx_policy::robots`.
//!
//! Every row is one vector: a `robots.txt` body, a crawler user agent, a request path and the
//! verdict the RFC (or its worked example) gives. The rows go through the public parser and
//! cache only, so a change that moves a verdict fails here before it reaches a crawl. The
//! section numbers are those of RFC 9309 (Robots Exclusion Protocol, September 2022).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::time::{Clock, ManualClock, Timestamp};
use crawlx_policy::robots::{
    product_token, DisallowedBy, FetchStatus, Match, RobotsCache, RobotsConfig, RobotsTxt, RobotsVerdict,
    MAX_ROBOTS_BYTES,
};
use std::sync::Arc;
use std::time::Duration;

const UA: &str = "crawlx/1.0 (+https://example.test/bot)";

/// One path-matching vector.
struct Vector {
    id: &'static str,
    section: &'static str,
    file: &'static str,
    agent: &'static str,
    path: &'static str,
    allowed: bool,
}

const fn row(
    id: &'static str,
    section: &'static str,
    file: &'static str,
    agent: &'static str,
    path: &'static str,
    allowed: bool,
) -> Vector {
    Vector {
        id,
        section,
        file,
        agent,
        path,
        allowed,
    }
}

fn verdict(file: &str, agent: &str, path: &str) -> bool {
    matches!(
        RobotsTxt::parse(file.as_bytes()).evaluate(agent, path),
        Match::Allowed
    )
}

fn check(vectors: &[Vector]) {
    let mut failures = Vec::new();
    for v in vectors {
        let got = verdict(v.file, v.agent, v.path);
        if got != v.allowed {
            failures.push(format!(
                "{} (RFC 9309 {}): {:?} as {:?} on {:?}: expected {}, got {}",
                v.id,
                v.section,
                v.path,
                v.agent,
                v.file,
                verdict_name(v.allowed),
                verdict_name(got)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} vector(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

const fn verdict_name(allowed: bool) -> &'static str {
    if allowed {
        "allowed"
    } else {
        "disallowed"
    }
}

/// RFC 9309 section 2.2.2, the table of path patterns: `Disallow: <pattern>` matches exactly
/// the listed paths and none of the others.
const PATTERN_TABLE: &[(&str, &[&str], &[&str])] = &[
    (
        "/fish",
        &[
            "/fish",
            "/fish.html",
            "/fish/salmon.html",
            "/fishheads",
            "/fishheads/yummy.html",
            "/fish.php?id=anything",
        ],
        &["/Fish.asp", "/catfish", "/?id=fish", "/desert/fish"],
    ),
    (
        "/fish*",
        &[
            "/fish",
            "/fish.html",
            "/fish/salmon.html",
            "/fishheads",
            "/fishheads/yummy.html",
            "/fish.php?id=anything",
        ],
        &["/Fish.asp", "/catfish", "/?id=fish"],
    ),
    (
        "/fish/",
        &["/fish/", "/fish/?id=anything", "/fish/salmon.htm"],
        &["/fish", "/fish.html", "/Fish/Salmon.asp"],
    ),
    (
        "/*.php",
        &[
            "/filename.php",
            "/folder/filename.php",
            "/folder/filename.php?parameters",
            "/folder/any.php.file.html",
            "/filename.php/",
        ],
        &["/", "/windows.PHP"],
    ),
    (
        "/*.php$",
        &["/filename.php", "/folder/filename.php"],
        &[
            "/filename.php?parameters",
            "/filename.php/",
            "/filename.php5",
            "/windows.PHP",
        ],
    ),
    (
        "/fish*.php",
        &["/fish.php", "/fishheads/catfish.php?parameters"],
        &["/Fish.PHP"],
    ),
];

#[test]
fn s2_2_2_path_pattern_table() {
    let mut failures = Vec::new();
    for (pattern, matching, other) in PATTERN_TABLE {
        let file = format!("User-agent: *\nDisallow: {pattern}\n");
        for path in *matching {
            if verdict(&file, UA, path) {
                failures.push(format!("Disallow: {pattern} must match {path}"));
            }
        }
        for path in *other {
            if !verdict(&file, UA, path) {
                failures.push(format!("Disallow: {pattern} must not match {path}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Section 2.2.2: octets outside ASCII and escapes are compared after normalization.
#[test]
fn s2_2_2_percent_encoding_table() {
    // (rule path in robots.txt, request path that it matches)
    let table = [
        ("/foo/bar?baz=quz", "/foo/bar?baz=quz"),
        ("/foo/bar/\u{30C4}", "/foo/bar/%E3%83%84"),
        ("/foo/bar/%E3%83%84", "/foo/bar/%E3%83%84"),
        ("/foo/bar/%62%61%7A", "/foo/bar/baz"),
        // hex digits of an escape are case-insensitive
        ("/foo/%e3%83%84", "/foo/%E3%83%84"),
    ];
    for (rule, path) in table {
        let file = format!("User-agent: *\nDisallow: {rule}\n");
        assert!(!verdict(&file, UA, path), "Disallow: {rule} must match {path}");
    }
    // an escaped reserved character is not the character itself
    let file = "User-agent: *\nDisallow: /a%2Fb\n";
    assert!(verdict(file, UA, "/a/b"), "%2F is not a path separator");
    assert!(!verdict(file, UA, "/a%2Fb"));
}

#[test]
fn s2_2_2_most_specific_match_wins_and_allow_wins_a_tie() {
    check(&[
        row(
            "allow-p-over-disallow-root",
            "2.2.2",
            "User-agent: *\nAllow: /p\nDisallow: /\n",
            UA,
            "/page",
            true,
        ),
        row(
            "order-does-not-matter",
            "2.2.2",
            "User-agent: *\nDisallow: /\nAllow: /p\n",
            UA,
            "/page",
            true,
        ),
        row(
            "outside-the-allow-prefix",
            "2.2.2",
            "User-agent: *\nAllow: /p\nDisallow: /\n",
            UA,
            "/folder/page",
            false,
        ),
        row(
            "tie-goes-to-allow",
            "2.2.2",
            "User-agent: *\nAllow: /folder\nDisallow: /folder\n",
            UA,
            "/folder/page",
            true,
        ),
        row(
            "tie-goes-to-allow-reversed",
            "2.2.2",
            "User-agent: *\nDisallow: /folder\nAllow: /folder\n",
            UA,
            "/folder/page",
            true,
        ),
        row(
            "root-anchor-allows-only-root",
            "2.2.2",
            "User-agent: *\nAllow: /$\nDisallow: /\n",
            UA,
            "/",
            true,
        ),
        row(
            "root-anchor-denies-the-rest",
            "2.2.2",
            "User-agent: *\nAllow: /$\nDisallow: /\n",
            UA,
            "/page.htm",
            false,
        ),
        row(
            "longer-disallow-beats-shorter-allow",
            "2.2.2",
            "User-agent: *\nAllow: /a\nDisallow: /a/b\n",
            UA,
            "/a/b/c",
            false,
        ),
        row(
            "longer-allow-beats-shorter-disallow",
            "2.2.2",
            "User-agent: *\nDisallow: /a\nAllow: /a/b\n",
            UA,
            "/a/b/c",
            true,
        ),
        row(
            "wildcard-counts-in-the-length",
            "2.2.2",
            "User-agent: *\nAllow: /x\nDisallow: /*.pdf\n",
            UA,
            "/x/f.pdf",
            false,
        ),
        row(
            "end-anchor-counts-in-the-length",
            "2.2.2",
            "User-agent: *\nAllow: /docs/\nDisallow: /docs/*.pdf$\n",
            UA,
            "/docs/a.pdf",
            false,
        ),
        row(
            "end-anchor-leaves-other-files",
            "2.2.2",
            "User-agent: *\nAllow: /docs/\nDisallow: /docs/*.pdf$\n",
            UA,
            "/docs/a.pdf.html",
            true,
        ),
    ]);
}

#[test]
fn s2_2_2_an_empty_path_is_the_root() {
    assert!(!verdict("User-agent: *\nDisallow: /\n", UA, ""));
    assert!(verdict("User-agent: *\nDisallow: /a\n", UA, ""));
}

#[test]
fn s2_2_2_matching_is_case_sensitive_on_the_path() {
    check(&[
        row(
            "lowercase-rule-uppercase-path",
            "2.2.2",
            "User-agent: *\nDisallow: /private\n",
            UA,
            "/Private",
            true,
        ),
        row(
            "uppercase-rule-lowercase-path",
            "2.2.2",
            "User-agent: *\nDisallow: /Private\n",
            UA,
            "/private",
            true,
        ),
        row(
            "same-case",
            "2.2.2",
            "User-agent: *\nDisallow: /Private\n",
            UA,
            "/Private/x",
            false,
        ),
    ]);
}

#[test]
fn s2_2_2_the_query_is_part_of_the_matched_path() {
    check(&[
        row(
            "rule-on-a-query",
            "2.2.2",
            "User-agent: *\nDisallow: /*?session=\n",
            UA,
            "/p?session=1",
            false,
        ),
        row(
            "same-path-without-the-query",
            "2.2.2",
            "User-agent: *\nDisallow: /*?session=\n",
            UA,
            "/p",
            true,
        ),
        row(
            "query-after-another-parameter",
            "2.2.2",
            "User-agent: *\nDisallow: /*?session=\n",
            UA,
            "/p?a=1&session=1",
            true,
        ),
        row(
            "anchored-query",
            "2.2.2",
            "User-agent: *\nDisallow: /search$\n",
            UA,
            "/search?q=1",
            true,
        ),
        row(
            "anchored-no-query",
            "2.2.2",
            "User-agent: *\nDisallow: /search$\n",
            UA,
            "/search",
            false,
        ),
    ]);
}

/// The sample file of section 5.1.
const SECTION_5_1: &str = "User-Agent: *\n\
Disallow: *.gif$\n\
Disallow: /example/\n\
Allow: /publications/\n\
\n\
User-Agent: foobot\n\
Disallow:/\n\
Allow:/example/page.html\n\
Allow:/example/allowed.gif\n\
\n\
User-Agent: barbot\n\
User-Agent: bazbot\n\
Disallow: /example/page.html\n\
\n\
User-Agent: quxbot\n\
\n";

#[test]
fn s5_1_the_sample_file() {
    check(&[
        // the `*` group: a gif anywhere, and the /example/ tree, are closed
        row("star-gif", "5.1", SECTION_5_1, "otherbot", "/images/a.gif", false),
        row(
            "star-example",
            "5.1",
            SECTION_5_1,
            "otherbot",
            "/example/index.html",
            false,
        ),
        row(
            "star-publications",
            "5.1",
            SECTION_5_1,
            "otherbot",
            "/publications/a.html",
            true,
        ),
        row("star-root", "5.1", SECTION_5_1, "otherbot", "/", true),
        // foobot has its own group and never falls back to `*`
        row("foobot-root-closed", "5.1", SECTION_5_1, "foobot", "/", false),
        row(
            "foobot-page-open",
            "5.1",
            SECTION_5_1,
            "foobot",
            "/example/page.html",
            true,
        ),
        row(
            "foobot-gif-open",
            "5.1",
            SECTION_5_1,
            "foobot",
            "/example/allowed.gif",
            true,
        ),
        row(
            "foobot-other-gif-closed",
            "5.1",
            SECTION_5_1,
            "foobot",
            "/example/other.gif",
            false,
        ),
        // barbot and bazbot share one group
        row(
            "barbot-page-closed",
            "5.1",
            SECTION_5_1,
            "barbot",
            "/example/page.html",
            false,
        ),
        row(
            "bazbot-page-closed",
            "5.1",
            SECTION_5_1,
            "bazbot",
            "/example/page.html",
            false,
        ),
        row(
            "barbot-gif-open",
            "5.1",
            SECTION_5_1,
            "barbot",
            "/images/a.gif",
            true,
        ),
        row(
            "bazbot-example-open",
            "5.1",
            SECTION_5_1,
            "bazbot",
            "/example/other.html",
            true,
        ),
        // quxbot names an empty group: nothing is closed, and `*` does not apply
        row(
            "quxbot-open",
            "5.1",
            SECTION_5_1,
            "quxbot",
            "/example/page.html",
            true,
        ),
        row(
            "quxbot-gif-open",
            "5.1",
            SECTION_5_1,
            "quxbot",
            "/images/a.gif",
            true,
        ),
    ]);
}

#[test]
fn s2_2_1_user_agent_selection() {
    check(&[
        row(
            "token-is-case-insensitive",
            "2.2.1",
            "User-agent: CRAWLX\nDisallow: /a\n",
            UA,
            "/a",
            false,
        ),
        row(
            "rule-agent-lowercase",
            "2.2.1",
            "user-agent: crawlx\nDisallow: /a\n",
            "CrawlX/9",
            "/a",
            false,
        ),
        row(
            "version-and-comment-are-not-the-token",
            "2.2.1",
            "User-agent: crawlx\nDisallow: /a\n",
            "crawlx/2.3 (+https://x.test)",
            "/a",
            false,
        ),
        row(
            "other-token-does-not-apply",
            "2.2.1",
            "User-agent: otherbot\nDisallow: /a\n",
            UA,
            "/a",
            true,
        ),
        row(
            "star-applies-without-a-specific-group",
            "2.2.1",
            "User-agent: *\nDisallow: /a\n",
            UA,
            "/a",
            false,
        ),
        row(
            "specific-group-excludes-star",
            "2.2.1",
            "User-agent: crawlx\nDisallow: /b\n\nUser-agent: *\nDisallow: /a\n",
            UA,
            "/a",
            true,
        ),
        row(
            "specific-group-rule-applies",
            "2.2.1",
            "User-agent: crawlx\nDisallow: /b\n\nUser-agent: *\nDisallow: /a\n",
            UA,
            "/b",
            false,
        ),
        row(
            "star-then-specific-order",
            "2.2.1",
            "User-agent: *\nDisallow: /a\n\nUser-agent: crawlx\nDisallow: /b\n",
            UA,
            "/a",
            true,
        ),
        row(
            "agent-lines-split-by-a-blank-line-share-a-group",
            "2.2.1",
            "User-agent: crawlx\n\nUser-agent: *\nDisallow: /\n",
            UA,
            "/a",
            false,
        ),
        row(
            "a-prefix-of-the-token-is-not-the-token",
            "2.2.1",
            "User-agent: crawl\nDisallow: /a\n",
            UA,
            "/a",
            true,
        ),
        row(
            "a-longer-token-is-not-the-token",
            "2.2.1",
            "User-agent: crawlxbot\nDisallow: /a\n",
            UA,
            "/a",
            true,
        ),
        row(
            "no-group-at-all-allows",
            "2.2.1",
            "Sitemap: https://example.test/s.xml\n",
            UA,
            "/a",
            true,
        ),
        row("empty-file-allows", "2.2.1", "", UA, "/a", true),
    ]);
}

#[test]
fn s2_2_1_groups_with_several_agents_and_split_groups() {
    check(&[
        row("consecutive-agents-share-a-group-first", "2.2.1", "User-agent: crawlx\nUser-agent: otherbot\nDisallow: /a\n", UA, "/a", false),
        row("consecutive-agents-share-a-group-second", "2.2.1", "User-agent: otherbot\nUser-agent: crawlx\nDisallow: /a\n", UA, "/a", false),
        row("agents-split-by-a-rule-are-two-groups", "2.2.1", "User-agent: otherbot\nDisallow: /b\nUser-agent: crawlx\nDisallow: /a\n", UA, "/b", true),
        row("blank-line-does-not-split-a-group", "2.2.1", "User-agent: crawlx\n\nUser-agent: otherbot\nDisallow: /a\n", UA, "/a", false),
        // matching groups are combined into one (section 2.2.1)
        row("two-groups-of-one-agent-first", "2.2.1", "User-agent: crawlx\nDisallow: /a\n\nUser-agent: x\nDisallow: /z\n\nUser-agent: crawlx\nDisallow: /b\n", UA, "/a", false),
        row("two-groups-of-one-agent-second", "2.2.1", "User-agent: crawlx\nDisallow: /a\n\nUser-agent: x\nDisallow: /z\n\nUser-agent: crawlx\nDisallow: /b\n", UA, "/b", false),
        row("two-groups-of-one-agent-other-group", "2.2.1", "User-agent: crawlx\nDisallow: /a\n\nUser-agent: x\nDisallow: /z\n\nUser-agent: crawlx\nDisallow: /b\n", UA, "/z", true),
        row("merged-groups-use-the-longest-match", "2.2.1", "User-agent: crawlx\nDisallow: /a\n\nUser-agent: crawlx\nAllow: /a/b\n", UA, "/a/b/c", true),
        row("two-star-groups-merge", "2.2.1", "User-agent: *\nDisallow: /a\n\nUser-agent: *\nDisallow: /b\n", UA, "/b", false),
    ]);
}

#[test]
fn s2_2_other_lines_do_not_change_the_rules() {
    check(&[
        row(
            "rules-before-any-agent-are-ignored",
            "2.2",
            "Disallow: /a\nUser-agent: *\nDisallow: /b\n",
            UA,
            "/a",
            true,
        ),
        row(
            "unknown-directive-is-ignored",
            "2.2",
            "User-agent: *\nNoindex: /a\nDisallow: /b\n",
            UA,
            "/a",
            true,
        ),
        row(
            "a-line-without-a-colon-is-ignored",
            "2.2",
            "User-agent: *\nthis is nothing\nDisallow: /b\n",
            UA,
            "/b",
            false,
        ),
        row(
            "sitemap-does-not-end-a-group",
            "2.2.3",
            "User-agent: *\nSitemap: https://example.test/s.xml\nDisallow: /a\n",
            UA,
            "/a",
            false,
        ),
        row(
            "comment-after-a-rule",
            "2.2",
            "User-agent: *\nDisallow: /a # not /b\n",
            UA,
            "/a",
            false,
        ),
        row(
            "comment-is-not-part-of-the-pattern",
            "2.2",
            "User-agent: *\nDisallow: /a # not /b\n",
            UA,
            "/a#",
            false,
        ),
        row(
            "whole-line-comment",
            "2.2",
            "# Disallow: /a\nUser-agent: *\nDisallow: /b\n",
            UA,
            "/a",
            true,
        ),
        row(
            "empty-disallow-allows-everything",
            "2.2.2",
            "User-agent: *\nDisallow:\n",
            UA,
            "/a",
            true,
        ),
        row(
            "empty-allow-is-no-rule",
            "2.2.2",
            "User-agent: *\nAllow:\nDisallow: /a\n",
            UA,
            "/a",
            false,
        ),
        row(
            "crlf-line-ends",
            "2.2",
            "User-agent: *\r\nDisallow: /a\r\n",
            UA,
            "/a",
            false,
        ),
        row(
            "cr-only-line-ends",
            "2.2",
            "User-agent: *\rDisallow: /a\r",
            UA,
            "/a",
            false,
        ),
        row(
            "no-final-newline",
            "2.2",
            "User-agent: *\nDisallow: /a",
            UA,
            "/a",
            false,
        ),
        row(
            "utf8-bom",
            "2.2",
            "\u{feff}User-agent: *\nDisallow: /a\n",
            UA,
            "/a",
            false,
        ),
        row(
            "spaces-around-the-colon",
            "2.2",
            "User-agent :  *\nDisallow  :   /a\n",
            UA,
            "/a",
            false,
        ),
        row(
            "directive-names-are-case-insensitive",
            "2.2",
            "USER-AGENT: *\nDISALLOW: /a\n",
            UA,
            "/a",
            false,
        ),
        row(
            "tabs-around-the-value",
            "2.2",
            "User-agent:\t*\nDisallow:\t/a\t\n",
            UA,
            "/a",
            false,
        ),
    ]);
}

#[test]
fn s2_2_2_wildcards() {
    check(&[
        row(
            "star-in-the-middle",
            "2.2.2",
            "User-agent: *\nDisallow: /a*c\n",
            UA,
            "/abc",
            false,
        ),
        row(
            "star-matches-nothing",
            "2.2.2",
            "User-agent: *\nDisallow: /a*c\n",
            UA,
            "/ac",
            false,
        ),
        row(
            "star-matches-slashes",
            "2.2.2",
            "User-agent: *\nDisallow: /a*c\n",
            UA,
            "/a/b/c",
            false,
        ),
        row(
            "star-needs-the-suffix",
            "2.2.2",
            "User-agent: *\nDisallow: /a*c\n",
            UA,
            "/a/b/d",
            true,
        ),
        row(
            "leading-star",
            "2.2.2",
            "User-agent: *\nDisallow: *.gif$\n",
            UA,
            "/x/y.gif",
            false,
        ),
        row(
            "two-stars",
            "2.2.2",
            "User-agent: *\nDisallow: /a*b*c\n",
            UA,
            "/a-b-c",
            false,
        ),
        row(
            "two-stars-in-the-wrong-order",
            "2.2.2",
            "User-agent: *\nDisallow: /a*b*c\n",
            UA,
            "/a-c-b",
            true,
        ),
        row(
            "trailing-star-is-a-prefix",
            "2.2.2",
            "User-agent: *\nDisallow: /a*\n",
            UA,
            "/abc",
            false,
        ),
        row(
            "dollar-only-at-the-end-is-an-anchor",
            "2.2.2",
            "User-agent: *\nDisallow: /a$\n",
            UA,
            "/a",
            false,
        ),
        row(
            "dollar-anchor-excludes-longer-paths",
            "2.2.2",
            "User-agent: *\nDisallow: /a$\n",
            UA,
            "/ab",
            true,
        ),
        row(
            "star-dollar",
            "2.2.2",
            "User-agent: *\nDisallow: /*$\n",
            UA,
            "/anything",
            false,
        ),
        row(
            "anchor-after-a-star-needs-a-suffix-match",
            "2.2.2",
            "User-agent: *\nDisallow: /a*b$\n",
            UA,
            "/abab",
            false,
        ),
        row(
            "anchor-after-a-star-rejects-a-longer-tail",
            "2.2.2",
            "User-agent: *\nDisallow: /a*b$\n",
            UA,
            "/abc",
            true,
        ),
    ]);
}

/// Section 2.5: a crawler parses at least 500 KiB; the parser here stops at exactly that, and a
/// line cut by the limit is dropped, not applied as a shorter rule.
#[test]
fn s2_5_size_limit() {
    let mut early = String::from("User-agent: *\nDisallow: /early\n");
    while early.len() < MAX_ROBOTS_BYTES - 64 {
        early.push_str("# padding padding padding padding padding padding padding\n");
    }
    let tail = "Disallow: /late\n";
    let robots = RobotsTxt::parse(format!("{early}{tail}").as_bytes());
    assert!(robots.truncated() || early.len() + tail.len() <= MAX_ROBOTS_BYTES);
    assert!(matches!(robots.evaluate(UA, "/early"), Match::Disallowed(_)));

    // a rule that starts after the limit is never read
    let mut body = String::from("User-agent: *\nDisallow: /early\n");
    while body.len() <= MAX_ROBOTS_BYTES {
        body.push_str("# padding padding padding padding padding padding padding\n");
    }
    body.push_str("Disallow: /beyond\n");
    let robots = RobotsTxt::parse(body.as_bytes());
    assert!(robots.truncated());
    assert!(matches!(robots.evaluate(UA, "/early"), Match::Disallowed(_)));
    assert_eq!(robots.evaluate(UA, "/beyond"), Match::Allowed);

    // a line cut in the middle is dropped: `Disallow: /priv` must not become a rule
    let mut body = String::from("User-agent: *\n");
    while body.len() < MAX_ROBOTS_BYTES - 8 {
        body.push_str("# padding padding padding padding padding padding padding\n");
    }
    let keep = body.len();
    body.truncate(keep);
    body.push_str("Disallow: /private-area\n");
    let robots = RobotsTxt::parse(body.as_bytes());
    assert_eq!(robots.evaluate(UA, "/private-area"), Match::Allowed);
    assert_eq!(robots.evaluate(UA, "/priv"), Match::Allowed);
}

#[test]
fn s2_5_invalid_utf8_does_not_stop_the_parse() {
    let mut body = b"User-agent: *\n# \xff\xfe garbage\n".to_vec();
    body.extend_from_slice(b"Disallow: /a\n");
    assert!(matches!(
        RobotsTxt::parse(&body).evaluate(UA, "/a"),
        Match::Disallowed(_)
    ));
}

#[test]
fn s2_2_1_product_token_extraction() {
    for (agent, token) in [
        ("crawlx/1.0 (+https://example.test/bot)", "crawlx"),
        ("CrawlX", "crawlx"),
        ("  crawlx/2  ", "crawlx"),
        ("Mozilla/5.0 (compatible; crawlx)", "mozilla"), // wire-compat: browser-style User-Agent shape
        ("crawlx (+https://example.test)", "crawlx"),
        ("", ""),
    ] {
        assert_eq!(product_token(agent), token, "{agent:?}");
    }
}

// ---- section 2.3: what a failed or unusual fetch of /robots.txt means -----------------------

const ORIGIN: &str = "https://example.test";

fn cache() -> (RobotsCache, ManualClock) {
    let clock = ManualClock::new(Timestamp::from_ymd_hms(2026, 11, 21, 12, 0, 0).unwrap());
    (
        RobotsCache::with_config(
            Arc::new(clock.clone()),
            RobotsConfig {
                user_agent: UA.to_owned(),
                ..RobotsConfig::default()
            },
        ),
        clock,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// Every path may be fetched.
    AllowAll,
    /// Every path is closed until the file can be read.
    DisallowAll,
}

fn behaves(cache: &RobotsCache) -> Vec<(&'static str, bool)> {
    ["/", "/a", "/a/b?x=1", "/robots.txt", "/sitemap.xml"]
        .into_iter()
        .map(|path| {
            (
                path,
                matches!(cache.evaluate(ORIGIN, path), RobotsVerdict::Allowed),
            )
        })
        .collect()
}

/// Sections 2.3.1.1 to 2.3.1.4: what each outcome of the `/robots.txt` fetch means for every
/// path of the origin, a sitemap included.
#[test]
fn s2_3_1_fetch_outcomes() {
    let table: [(&str, FetchStatus, Expect, &str); 6] = [
        (
            "2xx with a body that closes nothing",
            FetchStatus::Ok(b"User-agent: *\nDisallow:\n".to_vec()),
            Expect::AllowAll,
            "2.3.1.1",
        ),
        (
            "more than five redirects: unavailable",
            FetchStatus::TooManyRedirects,
            Expect::AllowAll,
            "2.3.1.2",
        ),
        (
            "4xx (400, 401, 403, 404, 410, 429...): unavailable",
            FetchStatus::Status4xx,
            Expect::AllowAll,
            "2.3.1.3",
        ),
        (
            "5xx: unreachable, complete disallow",
            FetchStatus::Status5xx,
            Expect::DisallowAll,
            "2.3.1.4",
        ),
        (
            "network error or timeout: unreachable, complete disallow",
            FetchStatus::Unreachable,
            Expect::DisallowAll,
            "2.3.1.4",
        ),
        (
            "2xx with Disallow: /",
            FetchStatus::Ok(b"User-agent: *\nDisallow: /\n".to_vec()),
            Expect::DisallowAll,
            "2.3.1.1",
        ),
    ];
    for (name, status, expect, section) in table {
        let (mut cache, _) = cache();
        assert_eq!(
            cache.evaluate(ORIGIN, "/"),
            RobotsVerdict::Unknown,
            "{name}: nothing is known before the fetch"
        );
        cache.record_fetch(ORIGIN, status);
        for (path, allowed) in behaves(&cache) {
            assert_eq!(
                allowed,
                expect == Expect::AllowAll,
                "{name} (RFC 9309 {section}): {path} must be {expect:?}"
            );
        }
    }
}

#[test]
fn s2_3_1_4_an_unreachable_file_is_never_read_as_permission() {
    let (mut cache, clock) = cache();
    cache.record_fetch(ORIGIN, FetchStatus::Status5xx);
    // an outage past the give-up horizon changes the label of the denial, not the verdict
    for _ in 0..40 {
        clock.advance_ms(3_600_000);
        cache.record_fetch(ORIGIN, FetchStatus::Status5xx);
        assert!(
            matches!(
                cache.evaluate(ORIGIN, "/"),
                RobotsVerdict::Disallowed(DisallowedBy::Unreachable { .. })
            ),
            "an outage of {:?} must still close the origin",
            clock.now()
        );
    }
    assert!(matches!(
        cache.evaluate(ORIGIN, "/a"),
        RobotsVerdict::Disallowed(DisallowedBy::Unreachable { give_up: true, .. })
    ));
}

#[test]
fn s2_3_1_4_the_fetch_is_retried_after_a_backoff_and_a_good_answer_ends_the_outage() {
    let (mut cache, clock) = cache();
    cache.record_fetch(ORIGIN, FetchStatus::Status5xx);
    assert!(!cache.needs_refetch(ORIGIN, clock.now()));
    clock.advance_ms(Duration::from_secs(3600).as_millis().try_into().unwrap());
    assert!(cache.needs_refetch(ORIGIN, clock.now()));
    cache.record_fetch(
        ORIGIN,
        FetchStatus::Ok(b"User-agent: *\nDisallow: /private\n".to_vec()),
    );
    assert_eq!(cache.evaluate(ORIGIN, "/open"), RobotsVerdict::Allowed);
    assert!(matches!(
        cache.evaluate(ORIGIN, "/private"),
        RobotsVerdict::Disallowed(DisallowedBy::Rule(_))
    ));
}

/// Section 2.4: a crawler does not use a cached file for more than 24 hours.
#[test]
fn s2_4_a_cached_file_expires_within_a_day() {
    for status in [
        FetchStatus::Ok(b"User-agent: *\nDisallow: /a\n".to_vec()),
        FetchStatus::Status4xx,
        FetchStatus::TooManyRedirects,
    ] {
        let (mut cache, clock) = cache();
        cache.record_fetch(ORIGIN, status.clone());
        clock.advance_ms(24 * 3_600_000 - 1);
        assert_ne!(
            cache.evaluate(ORIGIN, "/a"),
            RobotsVerdict::Unknown,
            "{status:?}: still fresh"
        );
        clock.advance_ms(1);
        assert_eq!(
            cache.evaluate(ORIGIN, "/a"),
            RobotsVerdict::Unknown,
            "{status:?}: 24 h old must be fetched again"
        );
        assert!(cache.needs_refetch(ORIGIN, clock.now()), "{status:?}");
    }
}

#[test]
fn s2_4_a_longer_max_age_is_capped_at_a_day() {
    let (mut cache, clock) = cache();
    cache.record_fetch_with(
        ORIGIN,
        FetchStatus::Ok(b"User-agent: *\nDisallow: /a\n".to_vec()),
        Some(Duration::from_secs(30 * 24 * 3600)),
    );
    clock.advance_ms(24 * 3_600_000);
    assert_eq!(cache.evaluate(ORIGIN, "/a"), RobotsVerdict::Unknown);
}

/// The answer belongs to one origin (scheme, host and port): another origin knows nothing.
#[test]
fn s2_3_the_file_applies_to_its_own_origin_only() {
    let (mut cache, _) = cache();
    cache.record_fetch(ORIGIN, FetchStatus::Ok(b"User-agent: *\nDisallow: /\n".to_vec()));
    for other in [
        "http://example.test",
        "https://example.test:8443",
        "https://www.example.test",
        "https://example.org",
    ] {
        assert_eq!(cache.evaluate(other, "/"), RobotsVerdict::Unknown, "{other}");
    }
    assert!(matches!(
        cache.evaluate(ORIGIN, "/"),
        RobotsVerdict::Disallowed(DisallowedBy::Rule(_))
    ));
}

#[test]
fn s2_2_3_sitemap_lines_are_global_and_keep_their_order() {
    let robots = RobotsTxt::parse(
        b"Sitemap: https://example.test/a.xml\nUser-agent: other\nDisallow: /x\nSitemap: https://example.test/b.xml\n\
User-agent: *\nSitemap: https://example.test/a.xml\nDisallow:\n",
    );
    assert_eq!(
        robots.sitemaps(),
        ["https://example.test/a.xml", "https://example.test/b.xml"]
    );
}

#[test]
fn a_cache_answers_for_the_configured_agent_and_its_aliases() {
    let clock = ManualClock::new(Timestamp::from_ymd_hms(2026, 11, 21, 12, 0, 0).unwrap());
    let body = b"User-agent: legacybot\nDisallow: /legacy\n\nUser-agent: crawlx\nDisallow: /own\n\nUser-agent: *\nDisallow: /star\n".to_vec();
    let mut plain = RobotsCache::with_config(
        Arc::new(clock.clone()),
        RobotsConfig {
            user_agent: UA.to_owned(),
            ..RobotsConfig::default()
        },
    );
    plain.record_fetch(ORIGIN, FetchStatus::Ok(body.clone()));
    assert_eq!(plain.evaluate(ORIGIN, "/legacy"), RobotsVerdict::Allowed);
    assert!(matches!(
        plain.evaluate(ORIGIN, "/own"),
        RobotsVerdict::Disallowed(_)
    ));
    assert_eq!(
        plain.evaluate(ORIGIN, "/star"),
        RobotsVerdict::Allowed,
        "a named group excludes `*`"
    );

    let mut aliased = RobotsCache::with_config(
        Arc::new(clock),
        RobotsConfig {
            user_agent: UA.to_owned(),
            aliases: vec!["legacybot".to_owned()],
            ..RobotsConfig::default()
        },
    );
    aliased.record_fetch(ORIGIN, FetchStatus::Ok(body));
    assert!(matches!(
        aliased.evaluate(ORIGIN, "/legacy"),
        RobotsVerdict::Disallowed(_)
    ));
    assert!(matches!(
        aliased.evaluate(ORIGIN, "/own"),
        RobotsVerdict::Disallowed(_)
    ));
}
