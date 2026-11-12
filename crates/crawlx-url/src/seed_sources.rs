//! Candidate URLs from recorded seed sources.
//!
//! Each [`SeedFixtureV1`] is a document somebody already fetched: a capture-index listing, a
//! certificate-transparency search result, a sitemap, a `robots.txt`, a feed or a home page. This
//! module turns the documents into one ordered, deduplicated list of candidate URLs. It performs
//! no I/O of any kind, reads no clock and draws no randomness, so the same fixtures always give
//! the same candidates in the same order.
//!
//! A candidate is a proposal only. Nothing here decides scope, robots or authorization: the
//! worker admits each candidate exactly like a discovered link, so a source can never widen what
//! the crawl is allowed to touch.

use crate::feed::{parse_feed, FeedError};
use crate::links::{extract_links, LinkKind};
use crate::sitemap::SitemapParser;
use crate::UrlError;
use crawlx_core::discovery::{SeedFixtureV1, SeedSourceKindV1, SourceDiscoveryPolicyV1};
use std::collections::BTreeSet;
use url::Url;

/// Longest candidate URL kept, in bytes.
const MAX_CANDIDATE_BYTES: usize = 4096;
/// Candidates read from one fixture before it is cut off.
const MAX_PER_FIXTURE: usize = 100_000;

/// A fixture that cannot be read as the kind it claims to be.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SeedSourceError {
    /// A JSON fixture is not valid JSON.
    #[error("{kind} fixture is not valid JSON")]
    Json {
        /// The fixture's declared kind.
        kind: &'static str,
        /// The parser's error.
        #[source]
        source: serde_json::Error,
    },
    /// The sitemap fixture is not a usable sitemap.
    #[error("sitemap fixture is not usable")]
    Sitemap(#[source] UrlError),
    /// The sitemap fixture is gzip data; decompress it before recording it.
    #[error("sitemap fixture is compressed; record the decompressed document")]
    Compressed,
    /// The feed fixture is not a usable feed.
    #[error("feed fixture is not usable")]
    Feed(#[source] FeedError),
    /// A JSON fixture does not have the shape its kind requires.
    #[error("{kind} fixture has no recognizable records")]
    Shape {
        /// The fixture's declared kind.
        kind: &'static str,
    },
}

/// One candidate and the kind of fixture that named it first.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SeedCandidate {
    /// Absolute, credential-free `http(s)` URL without a fragment.
    pub url: Url,
    /// The fixture kind that named it first.
    pub source: SeedSourceKindV1,
}

/// The deduplicated candidates of all fixtures.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SeedSet {
    /// Candidates in fixture order, then document order within a fixture; the first sighting of
    /// a URL wins.
    pub candidates: Vec<SeedCandidate>,
    /// Sightings dropped as duplicates of an earlier candidate.
    pub duplicates: usize,
    /// Entries that were not a usable URL (relative with no base, other scheme, credentials,
    /// control characters, too long, not parseable).
    pub rejected: usize,
    /// More distinct candidates existed than `max_urls`; the later ones were dropped.
    pub truncated: bool,
}

/// Tally of one fixture before deduplication.
#[derive(Default)]
struct Found {
    urls: Vec<Url>,
    rejected: usize,
}

impl Found {
    /// Accept `raw` (absolute, or relative to `base`) as a candidate, or count it as rejected.
    fn push(&mut self, base: &Url, raw: &str) {
        let raw = raw.trim();
        if raw.is_empty() || raw.len() > MAX_CANDIDATE_BYTES || raw.chars().any(char::is_control) {
            self.rejected += 1;
            return;
        }
        match base.join(raw) {
            Ok(mut url)
                if matches!(url.scheme(), "http" | "https")
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none() =>
            {
                url.set_fragment(None);
                if self.urls.len() < MAX_PER_FIXTURE {
                    self.urls.push(url);
                }
            }
            _ => self.rejected += 1,
        }
    }
}

/// Read every fixture and merge the candidates.
///
/// `base` resolves relative references and supplies the origin of a `robots.txt`; it is the
/// crawl's seed URL. Candidates are kept in fixture order, deduplicated on the URL's normalized
/// text, and cut at `max_urls`.
///
/// # Errors
/// The first fixture that cannot be read as its declared kind.
pub fn collect(fixtures: &[SeedFixtureV1], base: &Url, max_urls: usize) -> Result<SeedSet, SeedSourceError> {
    let mut set = SeedSet::default();
    let mut seen = BTreeSet::<String>::new();
    for fixture in fixtures {
        let found = parse_fixture(fixture, base)?;
        set.rejected += found.rejected;
        for url in found.urls {
            if !seen.insert(url.as_str().to_owned()) {
                set.duplicates += 1;
            } else if set.candidates.len() >= max_urls {
                set.truncated = true;
            } else {
                set.candidates.push(SeedCandidate {
                    url,
                    source: fixture.kind,
                });
            }
        }
    }
    Ok(set)
}

fn parse_fixture(fixture: &SeedFixtureV1, base: &Url) -> Result<Found, SeedSourceError> {
    match fixture.kind {
        SeedSourceKindV1::ArchiveIndex => archive_index(&fixture.content, base),
        SeedSourceKindV1::CertificateTransparency => certificate_transparency(&fixture.content),
        SeedSourceKindV1::Sitemap => sitemap(&fixture.content, base),
        SeedSourceKindV1::Robots => Ok(robots(&fixture.content, base)),
        SeedSourceKindV1::Feed => feed(&fixture.content, base),
        SeedSourceKindV1::Homepage => Ok(homepage(&fixture.content, base)),
        // a kind added later is refused rather than read as something else
        _ => Err(SeedSourceError::Shape { kind: "unknown" }),
    }
}

/// `true` for a recorded HTTP status that means the capture was not a live page.
fn dead_status(status: &str) -> bool {
    status.parse::<u16>().is_ok_and(|code| code >= 400)
}

/// Capture-index listings: CDX text lines, JSON lines, or a JSON table or array.
fn archive_index(text: &str, base: &Url) -> Result<Found, SeedSourceError> {
    let mut found = Found::default();
    let trimmed = text.trim_start();
    if trimmed.starts_with('[') {
        let root: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|source| SeedSourceError::Json {
                kind: "archive_index",
                source,
            })?;
        let rows = root.as_array().ok_or(SeedSourceError::Shape {
            kind: "archive_index",
        })?;
        // a table's first row names its columns; an array of objects has none
        let header: Option<Vec<&str>> = rows
            .first()
            .and_then(serde_json::Value::as_array)
            .map(|cells| cells.iter().filter_map(serde_json::Value::as_str).collect());
        let column = |names: &[&str]| {
            header
                .as_ref()
                .and_then(|cells| cells.iter().position(|cell| names.contains(cell)))
        };
        let original = column(&["original", "url"]);
        let status = column(&["statuscode", "status"]);
        let mut recognized = false;
        for row in rows.iter().skip(usize::from(header.is_some())) {
            if let Some(cells) = row.as_array() {
                let Some(url) = original
                    .and_then(|i| cells.get(i))
                    .and_then(serde_json::Value::as_str)
                else {
                    found.rejected += 1;
                    continue;
                };
                recognized = true;
                if status
                    .and_then(|i| cells.get(i))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(dead_status)
                {
                    continue;
                }
                found.push(base, url);
            } else if let Some(object) = row.as_object() {
                let Some(url) = ["original", "url"]
                    .iter()
                    .find_map(|key| object.get(*key).and_then(serde_json::Value::as_str))
                else {
                    found.rejected += 1;
                    continue;
                };
                recognized = true;
                if object
                    .get("statuscode")
                    .or_else(|| object.get("status"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(dead_status)
                {
                    continue;
                }
                found.push(base, url);
            } else {
                found.rejected += 1;
            }
        }
        if !recognized && !rows.is_empty() {
            return Err(SeedSourceError::Shape {
                kind: "archive_index",
            });
        }
        return Ok(found);
    }
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line.starts_with('{') {
            let object: serde_json::Value =
                serde_json::from_str(line).map_err(|source| SeedSourceError::Json {
                    kind: "archive_index",
                    source,
                })?;
            let url = ["original", "url"]
                .iter()
                .find_map(|key| object.get(*key).and_then(serde_json::Value::as_str));
            match url {
                Some(url)
                    if !object
                        .get("statuscode")
                        .or_else(|| object.get("status"))
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(dead_status) =>
                {
                    found.push(base, url);
                }
                Some(_) => {}
                None => found.rejected += 1,
            }
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // `urlkey timestamp original mimetype statuscode digest length`
        let is_cdx =
            fields.len() >= 3 && fields[1].len() == 14 && fields[1].bytes().all(|b| b.is_ascii_digit());
        if is_cdx {
            if fields.get(4).is_some_and(|status| dead_status(status)) {
                continue;
            }
            found.push(base, fields[2]);
        } else if fields.len() == 1 {
            found.push(base, fields[0]);
        } else {
            found.rejected += 1;
        }
    }
    Ok(found)
}

/// Host names of a certificate-transparency search result: a JSON array of entries with
/// `name_value` (newline separated), `common_name` or `dns_names`, or of plain strings. A leading
/// `*.` is dropped. Hosts are sorted so the log's own ordering cannot change the candidates.
fn certificate_transparency(text: &str) -> Result<Found, SeedSourceError> {
    let root: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|source| SeedSourceError::Json {
            kind: "certificate_transparency",
            source,
        })?;
    let entries = root.as_array().ok_or(SeedSourceError::Shape {
        kind: "certificate_transparency",
    })?;
    let mut names = Vec::<&str>::new();
    for entry in entries {
        match entry {
            serde_json::Value::String(name) => names.push(name),
            serde_json::Value::Object(object) => {
                for key in ["name_value", "common_name"] {
                    if let Some(value) = object.get(key).and_then(serde_json::Value::as_str) {
                        names.extend(value.lines());
                    }
                }
                if let Some(list) = object.get("dns_names").and_then(serde_json::Value::as_array) {
                    names.extend(list.iter().filter_map(serde_json::Value::as_str));
                }
            }
            _ => {}
        }
    }
    let mut hosts = BTreeSet::new();
    let mut rejected = 0;
    for name in names {
        let host = name.trim().trim_start_matches("*.").to_ascii_lowercase();
        let valid = host.contains('.')
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        if valid {
            hosts.insert(host);
        } else {
            rejected += 1;
        }
    }
    let mut found = Found {
        urls: Vec::new(),
        rejected,
    };
    for host in hosts {
        if let Ok(url) = Url::parse(&format!("https://{host}/")) {
            found.urls.push(url);
        } else {
            found.rejected += 1;
        }
    }
    Ok(found)
}

/// A sitemap's page URLs. Nested sitemaps of an index are not candidates: they are documents,
/// not pages, and a fixture run reads no further document.
fn sitemap(text: &str, base: &Url) -> Result<Found, SeedSourceError> {
    let doc =
        SitemapParser::parse_limited(text.as_bytes(), MAX_PER_FIXTURE).map_err(SeedSourceError::Sitemap)?;
    if doc.gzip {
        return Err(SeedSourceError::Compressed);
    }
    let mut found = Found::default();
    for entry in &doc.urls {
        found.push(base, &entry.loc);
    }
    Ok(found)
}

/// A `robots.txt`: each `Sitemap:` line, and each literal `Allow:`/`Disallow:` path (one with no
/// wildcard) resolved against the seed's origin. Disallowed paths are listed on purpose: the
/// worker's robots gate refuses them, which is what the crawl records for them.
fn robots(text: &str, base: &Url) -> Found {
    let mut found = Found::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match field.trim().to_ascii_lowercase().as_str() {
            "sitemap" => found.push(base, value),
            "allow" | "disallow" if value.starts_with('/') && !value.contains(['*', '$']) => {
                found.push(base, value);
            }
            _ => {}
        }
    }
    found
}

/// A feed's entry links (RSS, RDF, Atom or JSON Feed).
fn feed(text: &str, base: &Url) -> Result<Found, SeedSourceError> {
    let policy = SourceDiscoveryPolicyV1::default();
    let document = parse_feed(text.as_bytes(), base, &policy).map_err(SeedSourceError::Feed)?;
    let mut found = Found::default();
    for entry in document.entries {
        found.push(base, entry.url.as_str());
    }
    Ok(found)
}

/// A home page's followable anchors and image-map areas.
fn homepage(html: &str, base: &Url) -> Found {
    let mut found = Found::default();
    for link in extract_links(html, base) {
        if matches!(link.kind, LinkKind::Anchor | LinkKind::Area) && !link.nofollow {
            found.push(base, link.url.as_str());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn base() -> Url {
        Url::parse("https://site.test/").unwrap()
    }

    fn urls(set: &SeedSet) -> Vec<&str> {
        set.candidates.iter().map(|c| c.url.as_str()).collect()
    }

    fn one(kind: SeedSourceKindV1, content: &str) -> Result<SeedSet, SeedSourceError> {
        collect(&[SeedFixtureV1::new(kind, content)], &base(), 1000)
    }

    #[test]
    fn cdx_text_lines_json_lines_and_tables_all_yield_original_urls() {
        let cdx = "\
com,site)/ 20240101000000 https://site.test/ text/html 200 AAA 100
com,site)/a 20240102000000 https://site.test/a text/html 200 BBB 100
com,site)/a 20240301000000 https://site.test/a text/html 200 CCC 100
com,site)/gone 20240102000000 https://site.test/gone text/html 404 DDD 100
com,site)/moved 20240102000000 https://site.test/moved warc/revisit - EEE 100
";
        let set = one(SeedSourceKindV1::ArchiveIndex, cdx).unwrap();
        assert_eq!(
            urls(&set),
            [
                "https://site.test/",
                "https://site.test/a",
                "https://site.test/moved"
            ]
        );
        assert_eq!(set.duplicates, 1, "the same original at two capture times");

        let lines = "{\"original\":\"https://site.test/x\",\"statuscode\":\"200\"}\n{\"url\":\"https://site.test/y\"}\n{\"original\":\"https://site.test/z\",\"statuscode\":\"500\"}\n";
        assert_eq!(
            urls(&one(SeedSourceKindV1::ArchiveIndex, lines).unwrap()),
            ["https://site.test/x", "https://site.test/y"]
        );

        let table = r#"[["urlkey","timestamp","original","statuscode"],["k","20240101000000","https://site.test/t1","200"],["k","20240101000000","https://site.test/t2","404"]]"#;
        assert_eq!(
            urls(&one(SeedSourceKindV1::ArchiveIndex, table).unwrap()),
            ["https://site.test/t1"]
        );

        assert!(one(SeedSourceKindV1::ArchiveIndex, "[1,2]").is_err());
        assert!(one(SeedSourceKindV1::ArchiveIndex, "[not json").is_err());
    }

    #[test]
    fn certificate_transparency_names_become_sorted_unique_https_origins() {
        let log = r#"[
            {"name_value":"b.site.test\n*.site.test","common_name":"b.site.test"},
            {"name_value":"A.site.test"},
            {"dns_names":["c.other.test","not a host"]},
            "d.third.test"
        ]"#;
        let set = one(SeedSourceKindV1::CertificateTransparency, log).unwrap();
        assert_eq!(
            urls(&set),
            [
                "https://a.site.test/",
                "https://b.site.test/",
                "https://c.other.test/",
                "https://d.third.test/",
                "https://site.test/",
            ]
        );
        assert_eq!(set.rejected, 1);
        assert!(one(SeedSourceKindV1::CertificateTransparency, "{}").is_err());
    }

    #[test]
    fn sitemap_robots_feed_and_homepage_fixtures_resolve_against_the_seed() {
        let sitemap = r#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://site.test/s1</loc></url><url><loc>/s2</loc></url><url><loc>ftp://site.test/no</loc></url></urlset>"#;
        let set = one(SeedSourceKindV1::Sitemap, sitemap).unwrap();
        assert_eq!(
            urls(&set),
            ["https://site.test/s1"],
            "only absolute loc entries the parser admits"
        );
        assert!(one(SeedSourceKindV1::Sitemap, "<urlset").is_err());

        let robots = "User-agent: *\nDisallow: /private/\nDisallow: /*.pdf$\nAllow: /public/ # note\nSitemap: https://site.test/sitemap.xml\nCrawl-delay: 1\n";
        assert_eq!(
            urls(&one(SeedSourceKindV1::Robots, robots).unwrap()),
            [
                "https://site.test/private/",
                "https://site.test/public/",
                "https://site.test/sitemap.xml"
            ]
        );

        let rss = r#"<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
            <item><title>one</title><link>https://site.test/post-1</link></item>
            <item><title>two</title><link>https://site.test/post-2</link></item></channel></rss>"#;
        assert_eq!(
            urls(&one(SeedSourceKindV1::Feed, rss).unwrap()),
            ["https://site.test/post-1", "https://site.test/post-2"]
        );
        assert!(one(SeedSourceKindV1::Feed, "plain text").is_err());

        let html = r##"<html><body><a href="/about">About</a><a href="https://other.test/x">x</a>
            <a href="/skip" rel="nofollow">skip</a><a href="#top">top</a><a href="mailto:a@b.test">m</a></body></html>"##;
        assert_eq!(
            urls(&one(SeedSourceKindV1::Homepage, html).unwrap()),
            ["https://site.test/about", "https://other.test/x"]
        );
    }

    #[test]
    fn merging_keeps_fixture_order_first_sighting_and_the_cap() {
        let fixtures = [
            SeedFixtureV1::new(SeedSourceKindV1::Robots, "Allow: /a\nAllow: /b\n"),
            SeedFixtureV1::new(
                SeedSourceKindV1::ArchiveIndex,
                "https://site.test/b\nhttps://site.test/c\nhttps://site.test/d\nftp://site.test/e\n",
            ),
        ];
        let set = collect(&fixtures, &base(), 1000).unwrap();
        assert_eq!(
            urls(&set),
            [
                "https://site.test/a",
                "https://site.test/b",
                "https://site.test/c",
                "https://site.test/d"
            ]
        );
        assert_eq!(
            set.candidates[1].source,
            SeedSourceKindV1::Robots,
            "first sighting wins"
        );
        assert_eq!((set.duplicates, set.rejected, set.truncated), (1, 1, false));
        // the same inputs always give the same output
        assert_eq!(collect(&fixtures, &base(), 1000).unwrap(), set);
        let capped = collect(&fixtures, &base(), 3).unwrap();
        assert_eq!(
            urls(&capped),
            [
                "https://site.test/a",
                "https://site.test/b",
                "https://site.test/c"
            ]
        );
        assert!(capped.truncated);
    }

    #[test]
    fn credentials_controls_and_oversized_entries_are_rejected() {
        let long = format!("https://site.test/{}", "x".repeat(5000));
        let content = format!("https://user:pw@site.test/a\nhttps://site.test/ok\n{long}\n");
        let set = one(SeedSourceKindV1::ArchiveIndex, &content).unwrap();
        assert_eq!(urls(&set), ["https://site.test/ok"]);
        assert_eq!(set.rejected, 2);
    }
}
