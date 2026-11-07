//! Normalization shared by both sides of a comparison and the similarity
//! measures of the scorecard.
//!
//! Nothing here knows which side produced the text: Firecrawl and crawlx output go through
//! the same functions, so a systematic formatting choice on either side cancels out and only
//! content differences remain.

use std::collections::BTreeSet;
use unicode_normalization::UnicodeNormalization;
use url::Url;

/// Placeholder that replaces the crawl origin in URL keys and link targets, so two runs of
/// the same fixture on different hosts/ports compare equal.
pub const ORIGIN: &str = "{origin}";

/// Placeholder that replaces the port of another host of the same fixture server (a subdomain
/// or alias the gym answers for) in URL keys: the two runs listen on different ports.
pub const PORT: &str = "{port}";

/// Query parameters stripped from link targets on both sides (strip tracking
/// parameters): the usual campaign and click identifiers.
const TRACKING: &[&str] = &[
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "fbclid",
    "gclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
    "ref",
];

/// `scheme://host[:port]` of `url`, without a path.
#[must_use]
pub fn origin_of(url: &Url) -> String {
    let mut s = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
    if let Some(p) = url.port() {
        s.push(':');
        s.push_str(&p.to_string());
    }
    s
}

fn same_origin(url: &Url, origin: &Url) -> bool {
    url.scheme() == origin.scheme()
        && url.host_str() == origin.host_str()
        && url.port_or_known_default() == origin.port_or_known_default()
}

/// Canonical comparison key of a URL (C1): the fragment is dropped, a trailing
/// slash is removed (both systems treat `/a` and `/a/` as one page in the fixtures, and the
/// gym serves both), the query is kept with its pairs sorted by name when `keep_query`
/// (crawlx canonicalizes parameter order; Firecrawl keeps document order) or additionally
/// stripped of tracking parameters otherwise, and the crawl origin is replaced by [`ORIGIN`].
/// Other origins keep their full form. Unparseable input is returned trimmed, so it still
/// diffs visibly.
#[must_use]
pub fn url_key(raw: &str, origin: &Url, keep_query: bool) -> String {
    let Ok(mut url) = Url::parse(raw.trim()) else {
        return raw.trim().to_owned();
    };
    url.set_fragment(None);
    canonical_query(&mut url, keep_query);
    let path = url.path().trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    let mut key = if same_origin(&url, origin) {
        format!("{ORIGIN}{path}")
    } else if origin.port().is_some()
        && url.scheme() == origin.scheme()
        && url.port_or_known_default() == origin.port_or_known_default()
    {
        // another host name of the same server: the port is the server's own
        format!(
            "{}://{}:{PORT}{path}",
            url.scheme(),
            url.host_str().unwrap_or_default()
        )
    } else {
        format!("{}{path}", origin_of(&url))
    };
    if let Some(q) = url.query().filter(|q| !q.is_empty()) {
        key.push('?');
        key.push_str(q);
    }
    key
}

/// Sort query pairs by name (stable, so repeated names keep their order) and drop tracking
/// parameters unless `keep_tracking`.
fn canonical_query(url: &mut Url, keep_tracking: bool) {
    if url.query().is_none_or(str::is_empty) {
        url.set_query(None);
        return;
    }
    let mut kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| keep_tracking || !TRACKING.contains(&k.as_ref()))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    kept.sort_by(|a, b| a.0.cmp(&b.0));
    if kept.is_empty() {
        url.set_query(None);
    } else {
        let mut q = url.query_pairs_mut();
        q.clear();
        for (k, v) in &kept {
            q.append_pair(k, v);
        }
    }
}

/// Decode the HTML entities both markdown converters may leave behind.
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    s.replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Rewrite one link target: resolve against `page`, strip tracking parameters, rebase the
/// origin, drop the fragment.
fn normalize_target(target: &str, page: &Url, origin: &Url) -> String {
    let t = target.trim().trim_matches(|c| c == '<' || c == '>');
    let t = t.split_whitespace().next().unwrap_or_default();
    if t.starts_with('#') {
        return String::new();
    }
    match page.join(t) {
        Ok(abs) => url_key(abs.as_str(), origin, false),
        Err(_) => t.to_owned(),
    }
}

/// Normalize `[text](target)` and `![alt](target)` link targets in one line, and turn
/// `<http://…>` autolinks into the inline form.
fn normalize_links(line: &str, page: &Url, origin: &Url) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find("](") {
        let (head, tail) = rest.split_at(start + 2);
        out.push_str(head);
        let Some(end) = tail.find(')') else {
            out.push_str(tail);
            return out;
        };
        out.push_str(&normalize_target(&tail[..end], page, origin));
        out.push(')');
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    autolinks(&out, page, origin)
}

fn autolinks(line: &str, page: &Url, origin: &Url) -> String {
    if !line.contains("<http") {
        return line.to_owned();
    }
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find("<http") {
        let (head, tail) = rest.split_at(start);
        out.push_str(head);
        let Some(end) = tail.find('>') else {
            out.push_str(tail);
            return out;
        };
        let target = &tail[1..end];
        let key = normalize_target(target, page, origin);
        out.push_str(&format!("[{key}]({key})"));
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

fn is_setext_underline(line: &str, ch: char) -> bool {
    let t = line.trim();
    t.len() >= 2 && t.chars().all(|c| c == ch)
}

/// Unify a list marker: `*`, `+` and `-` become `-`; `1)` becomes `1.`.
fn normalize_list_marker(line: &str) -> String {
    let indent_len = line.len() - line.trim_start().len();
    let (indent, body) = line.split_at(indent_len);
    let mut chars = body.chars();
    match chars.next() {
        Some('*' | '+') if chars.clone().next() == Some(' ') => format!("{indent}-{}", chars.as_str()),
        Some(c) if c.is_ascii_digit() => {
            let digits: String = body.chars().take_while(char::is_ascii_digit).collect();
            let after = &body[digits.len()..];
            if let Some(rest) = after.strip_prefix(") ") {
                format!("{indent}{digits}. {rest}")
            } else {
                line.to_owned()
            }
        }
        _ => line.to_owned(),
    }
}

/// Canonical table row: cells trimmed and separated by ` | `, separator rows reduced to `---`.
fn normalize_table_row(line: &str) -> String {
    let t = line.trim();
    if !t.starts_with('|') {
        return line.to_owned();
    }
    let inner = t.trim_matches('|');
    let cells: Vec<String> = inner
        .split('|')
        .map(|c| {
            let c = c.trim();
            if !c.is_empty() && c.chars().all(|ch| matches!(ch, '-' | ':')) {
                "---".to_owned()
            } else {
                c.to_owned()
            }
        })
        .collect();
    format!("| {} |", cells.join(" | "))
}

/// Normalize a markdown document: NFC, line endings, trailing whitespace,
/// entity decoding, setext → ATX headings, list and emphasis markers, link targets
/// (resolved against `page`, tracking stripped, origin rebased), table rows, blank-line runs.
#[must_use]
pub fn normalize_markdown(markdown: &str, page: &Url, origin: &Url) -> String {
    let text: String = markdown.nfc().collect();
    let text = decode_entities(&text.replace("\r\n", "\n").replace('\r', "\n"));
    let raw: Vec<&str> = text.lines().collect();
    let mut lines: Vec<String> = Vec::with_capacity(raw.len());
    let mut in_code = false;
    let mut i = 0;
    while i < raw.len() {
        let line = raw[i].trim_end();
        if line.trim_start().starts_with("```") || line.trim_start().starts_with("~~~") {
            in_code = !in_code;
            lines.push(line.trim_start().to_owned());
            i += 1;
            continue;
        }
        if in_code {
            lines.push(line.to_owned());
            i += 1;
            continue;
        }
        // setext heading: text line followed by === or ---
        if !line.trim().is_empty() && i + 1 < raw.len() {
            let next = raw[i + 1];
            let level = if is_setext_underline(next, '=') {
                Some("# ")
            } else if is_setext_underline(next, '-') && !line.trim_start().starts_with('|') {
                Some("## ")
            } else {
                None
            };
            if let Some(prefix) = level {
                lines.push(format!("{prefix}{}", line.trim()));
                i += 2;
                continue;
            }
        }
        let mut l = line.to_owned();
        if l.trim_start().starts_with('#') {
            // ATX: single space after the marker, no closing hashes
            let t = l.trim_start();
            let hashes = t.chars().take_while(|c| *c == '#').count();
            let body = t[hashes..].trim().trim_end_matches('#').trim();
            l = format!("{} {body}", "#".repeat(hashes));
        } else {
            l = normalize_list_marker(&l);
            l = normalize_table_row(&l);
        }
        l = l.replace("__", "**");
        l = normalize_links(&l, page, origin);
        // collapse internal runs of spaces/tabs outside code
        let collapsed: Vec<&str> = l.split_whitespace().collect();
        let indent_len = l.len() - l.trim_start().len();
        let indent = &l[..indent_len.min(l.len())];
        l = format!("{indent}{}", collapsed.join(" "));
        lines.push(l);
        i += 1;
    }
    // collapse blank runs, trim leading/trailing blanks
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for l in lines {
        if l.trim().is_empty() {
            if out.last().is_some_and(|p| p.is_empty()) || out.is_empty() {
                continue;
            }
            out.push(String::new());
        } else {
            out.push(l);
        }
    }
    while out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out.join("\n")
}

/// Jaccard similarity of the whitespace-separated token sets of two normalized texts;
/// two empty texts are identical (`1.0`).
#[must_use]
pub fn token_jaccard(a: &str, b: &str) -> f64 {
    let ta: BTreeSet<&str> = a.split_whitespace().collect();
    let tb: BTreeSet<&str> = b.split_whitespace().collect();
    set_jaccard(&ta, &tb)
}

/// Split normalized markdown into blocks: one block per heading, list item,
/// table row, fenced code span and paragraph; whitespace inside a block is collapsed.
#[must_use]
pub fn markdown_blocks(normalized: &str) -> Vec<String> {
    fn flush(paragraph: &mut Vec<&str>, blocks: &mut Vec<String>) {
        if !paragraph.is_empty() {
            blocks.push(paragraph.join(" "));
            paragraph.clear();
        }
    }
    let mut blocks = Vec::new();
    let mut paragraph: Vec<&str> = Vec::new();
    let mut code: Option<Vec<&str>> = None;
    for line in normalized.lines() {
        let t = line.trim();
        let fence = t.starts_with("```") || t.starts_with("~~~");
        if let Some(body) = code.as_mut() {
            if fence {
                blocks.push(format!("```{}", body.join("\n")));
                code = None;
            } else {
                body.push(line);
            }
            continue;
        }
        if fence {
            flush(&mut paragraph, &mut blocks);
            code = Some(Vec::new());
            continue;
        }
        let digits = t.chars().take_while(char::is_ascii_digit).count();
        let item = t.starts_with("- ") || (digits > 0 && t[digits..].starts_with(". "));
        if t.is_empty() {
            flush(&mut paragraph, &mut blocks);
        } else if t.starts_with('#') || t.starts_with('|') || item {
            flush(&mut paragraph, &mut blocks);
            blocks.push(t.split_whitespace().collect::<Vec<_>>().join(" "));
        } else {
            paragraph.push(t);
        }
    }
    if let Some(body) = code {
        blocks.push(format!("```{}", body.join("\n")));
    }
    flush(&mut paragraph, &mut blocks);
    blocks
}

/// Block-level F1 of two block lists: multiset precision and recall of exactly equal blocks
/// (the first list is the reference). Both empty is `1.0`.
#[must_use]
pub fn block_f1(reference: &[String], candidate: &[String]) -> f64 {
    if reference.is_empty() && candidate.is_empty() {
        return 1.0;
    }
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for b in reference {
        *counts.entry(b.as_str()).or_default() += 1;
    }
    let mut matched = 0usize;
    for b in candidate {
        if let Some(n) = counts.get_mut(b.as_str()) {
            if *n > 0 {
                *n -= 1;
                matched += 1;
            }
        }
    }
    if matched == 0 {
        return 0.0;
    }
    // block counts of one page; exact in f64
    #[allow(clippy::cast_precision_loss)]
    {
        let precision = matched as f64 / candidate.len() as f64;
        let recall = matched as f64 / reference.len() as f64;
        2.0 * precision * recall / (precision + recall)
    }
}

/// Ordered-subsequence ratio of two block lists: `2 * LCS / (|a| + |b|)`, `1.0` only when both
/// lists are equal, lower when blocks are missing, extra or reordered. Both empty is `1.0`.
/// Lists whose length product exceeds the LCS cell budget return `None` (the quadratic
/// alignment is skipped).
#[must_use]
pub fn ordered_subsequence_ratio(a: &[String], b: &[String]) -> Option<f64> {
    if a.is_empty() && b.is_empty() {
        return Some(1.0);
    }
    if a.len().saturating_mul(b.len()) > LCS_CELLS {
        return None;
    }
    let w = b.len() + 1;
    let mut dp = vec![0u32; (a.len() + 1) * w];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            dp[i * w + j] = if a[i] == b[j] {
                dp[(i + 1) * w + j + 1] + 1
            } else {
                dp[(i + 1) * w + j].max(dp[i * w + j + 1])
            };
        }
    }
    // block counts of one page; exact in f64
    #[allow(clippy::cast_precision_loss)]
    {
        Some(2.0 * f64::from(dp[0]) / (a.len() + b.len()) as f64)
    }
}

/// Jaccard similarity of two sets; both empty is `1.0`.
#[must_use]
pub fn set_jaccard<T: Ord>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> f64 {
    let inter = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        1.0
    } else {
        // both counts are small (page tokens); the f64 conversion is exact far beyond them
        #[allow(clippy::cast_precision_loss)]
        {
            inter as f64 / union as f64
        }
    }
}

/// Lines only on one side of a comparison, from a longest-common-subsequence alignment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LineDiff {
    /// Lines present in the first text only.
    pub removed: Vec<String>,
    /// Lines present in the second text only.
    pub added: Vec<String>,
}

impl LineDiff {
    /// `true` when the two texts align line for line.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.added.is_empty()
    }
}

/// Largest `lines(a) * lines(b)` the quadratic LCS is run on; beyond it the diff degrades to a
/// set difference of lines (still correct about *which* lines differ, not about order).
const LCS_CELLS: usize = 4_000_000;

/// Line diff of two texts (first → second).
#[must_use]
pub fn line_diff(a: &str, b: &str) -> LineDiff {
    let la: Vec<&str> = a.lines().collect();
    let lb: Vec<&str> = b.lines().collect();
    if la.len().saturating_mul(lb.len()) > LCS_CELLS {
        let sa: BTreeSet<&str> = la.iter().copied().collect();
        let sb: BTreeSet<&str> = lb.iter().copied().collect();
        return LineDiff {
            removed: sa.difference(&sb).map(|s| (*s).to_owned()).collect(),
            added: sb.difference(&sa).map(|s| (*s).to_owned()).collect(),
        };
    }
    // dp[i][j] = LCS length of la[i..] and lb[j..]
    let w = lb.len() + 1;
    let mut dp = vec![0u32; (la.len() + 1) * w];
    for i in (0..la.len()).rev() {
        for j in (0..lb.len()).rev() {
            dp[i * w + j] = if la[i] == lb[j] {
                dp[(i + 1) * w + j + 1] + 1
            } else {
                dp[(i + 1) * w + j].max(dp[i * w + j + 1])
            };
        }
    }
    let mut out = LineDiff::default();
    let (mut i, mut j) = (0, 0);
    while i < la.len() && j < lb.len() {
        if la[i] == lb[j] {
            i += 1;
            j += 1;
        } else if dp[(i + 1) * w + j] >= dp[i * w + j + 1] {
            out.removed.push(la[i].to_owned());
            i += 1;
        } else {
            out.added.push(lb[j].to_owned());
            j += 1;
        }
    }
    out.removed.extend(la[i..].iter().map(|s| (*s).to_owned()));
    out.added.extend(lb[j..].iter().map(|s| (*s).to_owned()));
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn origin() -> Url {
        Url::parse("http://gym.test").unwrap()
    }

    #[test]
    fn url_keys_rebase_origin_and_drop_noise() {
        let o = origin();
        assert_eq!(
            url_key("http://gym.test/s1/about/#team", &o, true),
            "{origin}/s1/about"
        );
        assert_eq!(url_key("http://gym.test/", &o, true), "{origin}/");
        assert_eq!(
            url_key("http://gym.test/s1/about?utm_source=x", &o, true),
            "{origin}/s1/about?utm_source=x"
        );
        assert_eq!(
            url_key("http://gym.test/s1/about?utm_source=x", &o, false),
            "{origin}/s1/about"
        );
        assert_eq!(
            url_key("http://gym.test/s1/p?id=3&utm_source=x", &o, false),
            "{origin}/s1/p?id=3"
        );
        assert_eq!(
            url_key("https://external.example/partner/", &o, true),
            "https://external.example/partner"
        );
        let other = Url::parse("http://127.0.0.1:4100").unwrap();
        assert_eq!(url_key("http://127.0.0.1:4100/s1/", &other, true), "{origin}/s1");
    }

    #[test]
    fn markdown_normalization_is_side_neutral() {
        let page = Url::parse("http://gym.test/s1/").unwrap();
        let o = origin();
        let firecrawl = "Title\n=====\r\n\r\n* [About](/s1/about/?utm_source=a)  \n* __bold__ &amp; <http://gym.test/s1/x>\n\n\n| a |b|\n|--|:-:|\n";
        let crawlx = "# Title\n\n- [About](http://gym.test/s1/about/)\n- **bold** & [{origin}/s1/x](http://gym.test/s1/x/#frag)\n\n| a | b |\n| --- | --- |";
        let a = normalize_markdown(firecrawl, &page, &o);
        let b = normalize_markdown(crawlx, &page, &o);
        assert_eq!(a, b, "\n{a}\n---\n{b}");
        assert!((token_jaccard(&a, &b) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn line_diff_reports_each_side() {
        let d = line_diff("a\nb\nc", "a\nc\nd");
        assert_eq!(d.removed, vec!["b"]);
        assert_eq!(d.added, vec!["d"]);
        assert!(line_diff("x", "x").is_empty());
    }

    #[test]
    fn jaccard_handles_empty_sets() {
        assert!((token_jaccard("", "") - 1.0).abs() < f64::EPSILON);
        assert!(token_jaccard("a b", "") < f64::EPSILON);
        assert!((token_jaccard("a b", "b c") - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn markdown_splits_into_blocks() {
        let md = "# Title\n\nfirst line\nsecond line\n\n- one\n- two\n1. three\n\n| a | b |\n| --- | --- |\n\n```\ncode  x\n\nmore\n```\n\nlast";
        assert_eq!(
            markdown_blocks(md),
            vec![
                "# Title",
                "first line second line",
                "- one",
                "- two",
                "1. three",
                "| a | b |",
                "| --- | --- |",
                "```code  x\n\nmore",
                "last"
            ]
        );
        assert!(markdown_blocks("").is_empty());
    }

    #[test]
    fn block_f1_and_the_ordered_ratio_see_what_token_similarity_misses() {
        let blocks = |s: &str| markdown_blocks(s);
        let a = blocks("# T\n\none two\n\nthree four");
        let merged = blocks("# T\n\none two three four");
        // the same tokens, different blocks
        assert!(
            (token_jaccard("# T one two three four", "# T one two three four") - 1.0).abs() < f64::EPSILON
        );
        assert!(
            (block_f1(&a, &merged) - 0.4).abs() < 1e-9,
            "{}",
            block_f1(&a, &merged)
        );
        assert!((block_f1(&a, &a) - 1.0).abs() < f64::EPSILON);
        assert!(block_f1(&a, &[]) < f64::EPSILON);
        assert!((block_f1(&[], &[]) - 1.0).abs() < f64::EPSILON);
        // a repeated block counts once per occurrence
        let twice = blocks("x\n\nx");
        assert!((block_f1(&twice, &blocks("x")) - 2.0 / 3.0).abs() < 1e-9);
        // reordered blocks: F1 is 1, the ordered ratio is not
        let ab = blocks("a\n\nb\n\nc");
        let cb = blocks("c\n\nb\n\na");
        assert!((block_f1(&ab, &cb) - 1.0).abs() < f64::EPSILON);
        let ratio = ordered_subsequence_ratio(&ab, &cb).unwrap();
        assert!((ratio - 2.0 / 6.0).abs() < 1e-9, "{ratio}");
        assert!((ordered_subsequence_ratio(&ab, &ab).unwrap() - 1.0).abs() < f64::EPSILON);
        assert_eq!(ordered_subsequence_ratio(&[], &[]), Some(1.0));
    }

    #[test]
    fn other_hosts_of_the_gym_port_are_rebased_to_a_port_placeholder() {
        let o = Url::parse("http://gym.test:4101").unwrap();
        assert_eq!(
            url_key("http://app.gym.test:4101/d2/scope/sub/", &o, true),
            "http://app.gym.test:{port}/d2/scope/sub"
        );
        // another port, another scheme or no port at all stay as they are
        assert_eq!(
            url_key("http://app.gym.test:9/x", &o, true),
            "http://app.gym.test:9/x"
        );
        assert_eq!(
            url_key("https://app.gym.test:4101/x", &o, true),
            "https://app.gym.test:4101/x"
        );
        let moved = Url::parse("http://gym.test:41233").unwrap();
        assert_eq!(
            url_key("http://app.gym.test:41233/d2/scope/sub", &moved, true),
            "http://app.gym.test:{port}/d2/scope/sub"
        );
        let plain = Url::parse("http://gym.test").unwrap();
        assert_eq!(
            url_key("http://other.test/x", &plain, true),
            "http://other.test/x"
        );
    }
}
