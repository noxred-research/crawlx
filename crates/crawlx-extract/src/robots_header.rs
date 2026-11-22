//! `X-Robots-Tag` response header directives, merged with the `<meta name=robots>` ones.
//!
//! The header carries the same indexing directives as the robots meta element (`noindex`,
//! `nofollow`, `none`, `noarchive`, `nosnippet`, `noimageindex`), optionally scoped to one
//! crawler: `X-Robots-Tag: crawlx: noindex`. This module only *reads* them into a
//! [`RobotsMeta`]; nothing here decides what is crawled, and the caller records the result as a
//! fact about the response.
//!
//! Rules, each bounded and deterministic:
//! * every header line is combined (a response may repeat the header), directive names are
//!   case-insensitive and separated by commas; unknown directives (`unavailable_after: <date>`,
//!   `max-snippet: 20`, `notranslate`, ...) are ignored without error;
//! * a line that starts with `<token>:` is scoped: its directives apply only when `<token>` is
//!   `*` or equals the crawler's own product token (compared case-insensitively). The prefix
//!   is a scope only when it is a single token that is not itself a directive name, so
//!   `unavailable_after: 25 Jun 2030 15:00:00 PST` is a directive with a value, not a scope;
//! * at most [`MAX_HEADER_BYTES`] bytes are read across all lines; a directive cut by the cap
//!   is dropped, never read as a shorter one;
//! * header bytes that are not UTF-8 are replaced by U+FFFD before parsing, so a stray byte
//!   cannot hide the directives around it.

use crate::metadata::RobotsMeta;

/// Bytes read across all `X-Robots-Tag` lines of one response (8 KiB).
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Directive names that carry a value after a colon. Their prefix is never a crawler scope.
const VALUED_DIRECTIVES: [&str; 4] = [
    "unavailable_after",
    "max-snippet",
    "max-image-preview",
    "max-video-preview",
];

/// Directive names without a value that this module reads or that must not be taken for a scope.
const PLAIN_DIRECTIVES: [&str; 11] = [
    "all",
    "none",
    "noindex",
    "index",
    "nofollow",
    "follow",
    "noarchive",
    "nosnippet",
    "noimageindex",
    "notranslate",
    "indexifembedded",
];

impl RobotsMeta {
    /// The directives set in `self` or in `other`.
    #[must_use]
    pub fn union(self, other: Self) -> Self {
        Self {
            noindex: self.noindex || other.noindex,
            nofollow: self.nofollow || other.nofollow,
            noarchive: self.noarchive || other.noarchive,
            nosnippet: self.nosnippet || other.nosnippet,
            noimageindex: self.noimageindex || other.noimageindex,
        }
    }

    /// Set the flag a lower-cased directive name stands for; any other name is ignored.
    pub(crate) fn apply(&mut self, directive: &str) {
        match directive {
            "none" => {
                self.noindex = true;
                self.nofollow = true;
            }
            "noindex" => self.noindex = true,
            "nofollow" => self.nofollow = true,
            "noarchive" => self.noarchive = true,
            "nosnippet" => self.nosnippet = true,
            "noimageindex" => self.noimageindex = true,
            _ => {}
        }
    }
}

/// The directives the `X-Robots-Tag` header lines in `lines` set for the crawler whose product
/// token is `token` (`crawlx/1.0` gives `crawlx`; see `crawlx_policy::robots::product_token`).
///
/// `lines` are the raw values of every `X-Robots-Tag` header of the response, in order. Reads at
/// most [`MAX_HEADER_BYTES`] bytes in total. No line, or none that applies, gives the default
/// (all `false`).
#[must_use]
pub fn parse_x_robots_tag<'a, I>(lines: I, token: &str) -> RobotsMeta
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let token = token.trim().to_ascii_lowercase();
    let mut budget = MAX_HEADER_BYTES;
    let mut out = RobotsMeta::default();
    for raw in lines {
        if budget == 0 {
            break;
        }
        let capped = raw.len() > budget;
        let raw = &raw[..raw.len().min(budget)];
        budget -= raw.len();
        let line = String::from_utf8_lossy(raw);
        parse_line(&line, capped, &token, &mut out);
    }
    out
}

/// Fold one header line into `out`. `capped` says the line was cut by the byte cap, so its last
/// piece may be incomplete.
fn parse_line(line: &str, capped: bool, token: &str, out: &mut RobotsMeta) {
    let (scope, rest) = split_scope(line);
    if scope.is_some_and(|scope| scope != "*" && scope != token) {
        return;
    }
    let mut pieces = rest.split(',').peekable();
    while let Some(piece) = pieces.next() {
        if capped && pieces.peek().is_none() {
            // the cap may have cut this directive short
            break;
        }
        let name = piece.trim().to_ascii_lowercase();
        out.apply(&name);
    }
}

/// Split `<token>: rest` into the lower-cased scope token and the rest; no scope gives the
/// whole line.
fn split_scope(line: &str) -> (Option<String>, &str) {
    let Some((head, rest)) = line.split_once(':') else {
        return (None, line);
    };
    let head = head.trim().to_ascii_lowercase();
    let is_token = !head.is_empty()
        && head
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'*'));
    let is_directive =
        VALUED_DIRECTIVES.contains(&head.as_str()) || PLAIN_DIRECTIVES.contains(&head.as_str());
    if is_token && !is_directive {
        (Some(head), rest)
    } else {
        (None, line)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn parse(lines: &[&str], token: &str) -> RobotsMeta {
        parse_x_robots_tag(lines.iter().map(|line| line.as_bytes()), token)
    }

    fn flags(meta: RobotsMeta) -> [bool; 5] {
        [
            meta.noindex,
            meta.nofollow,
            meta.noarchive,
            meta.nosnippet,
            meta.noimageindex,
        ]
    }

    #[test]
    fn table() {
        // (lines, token, noindex, nofollow, noarchive, nosnippet, noimageindex)
        let cases: &[(&[&str], &str, [bool; 5])] = &[
            (&[], "crawlx", [false; 5]),
            (&["noindex"], "crawlx", [true, false, false, false, false]),
            (&["none"], "crawlx", [true, true, false, false, false]),
            (
                &["NoFollow, NoArchive"],
                "crawlx",
                [false, true, true, false, false],
            ),
            (
                &["nosnippet,noimageindex"],
                "crawlx",
                [false, false, false, true, true],
            ),
            (&["index, follow, all"], "crawlx", [false; 5]),
            (&["noindex,"], "crawlx", [true, false, false, false, false]),
            (&[" , ,noindex , "], "crawlx", [true, false, false, false, false]),
            (&["crawlx: noindex"], "crawlx", [true, false, false, false, false]),
            (&["CrawlX: NoIndex"], "crawlx", [true, false, false, false, false]),
            (&["crawlx: noindex"], "other", [false; 5]),
            (&["googlebot: noindex"], "crawlx", [false; 5]),
            (&["*: nofollow"], "crawlx", [false, true, false, false, false]),
            (
                &["googlebot: noindex", "nofollow"],
                "crawlx",
                [false, true, false, false, false],
            ),
            (
                &["noindex", "nofollow, noarchive"],
                "crawlx",
                [true, true, true, false, false],
            ),
            (
                &["googlebot: noindex", "crawlx: none"],
                "crawlx",
                [true, true, false, false, false],
            ),
            (
                &["unavailable_after: 25 Jun 2030 15:00:00 PST"],
                "crawlx",
                [false; 5],
            ),
            (
                &["noindex, unavailable_after: 25 Jun 2030 15:00:00 PST"],
                "crawlx",
                [true, false, false, false, false],
            ),
            (
                &["unavailable_after: Tue, 25 Jun 2030 15:00:00 PST, nofollow"],
                "crawlx",
                [false, true, false, false, false],
            ),
            (
                &["max-snippet: 20, noarchive"],
                "crawlx",
                [false, false, true, false, false],
            ),
            (
                &["crawlx: unavailable_after: 25 Jun 2030, noindex"],
                "crawlx",
                [true, false, false, false, false],
            ),
            (&["noindexx, nofollowed, none-ish"], "crawlx", [false; 5]),
            (&[""], "crawlx", [false; 5]),
            (&["crawlx:"], "crawlx", [false; 5]),
        ];
        for (lines, token, expected) in cases {
            assert_eq!(flags(parse(lines, token)), *expected, "{lines:?} for {token}");
        }
    }

    #[test]
    fn non_utf8_bytes_do_not_hide_neighbouring_directives() {
        let line: &[u8] = b"noindex, \xff\xfe, nofollow";
        let meta = parse_x_robots_tag([line], "crawlx");
        assert!(meta.noindex && meta.nofollow);
        let only_garbage: &[u8] = b"\xff\xfe\xfd";
        assert_eq!(
            parse_x_robots_tag([only_garbage], "crawlx"),
            RobotsMeta::default()
        );
        let scoped: &[u8] = b"crawlx\xff: noindex";
        assert_eq!(parse_x_robots_tag([scoped], "crawlx"), RobotsMeta::default());
    }

    #[test]
    fn the_byte_cap_bounds_the_read_and_drops_a_cut_directive() {
        // padding of unknown directives up to the cap, then a directive past it
        let mut line = "x,".repeat(MAX_HEADER_BYTES / 2);
        line.push_str("noindex");
        assert_eq!(parse(&[line.as_str()], "crawlx"), RobotsMeta::default());
        // a directive that ends exactly at the cap is read
        let mut exact = "x,".repeat((MAX_HEADER_BYTES - "noindex".len()) / 2);
        exact.push_str(&",".repeat((MAX_HEADER_BYTES - "noindex".len()) % 2));
        exact.push_str("noindex");
        assert_eq!(exact.len(), MAX_HEADER_BYTES);
        assert!(parse(&[exact.as_str()], "crawlx").noindex);
        // a directive cut by the cap is dropped, not read as a shorter one
        let mut cut = "x,".repeat((MAX_HEADER_BYTES - 4) / 2);
        cut.push_str("nonexistent");
        assert!(cut.len() > MAX_HEADER_BYTES);
        assert_eq!(parse(&[cut.as_str()], "crawlx"), RobotsMeta::default());
        // the cap spans lines: a second line past it is not read
        let filler = "x,".repeat(MAX_HEADER_BYTES / 2);
        assert_eq!(
            parse(&[filler.as_str(), "noindex"], "crawlx"),
            RobotsMeta::default()
        );
        // and a first line short of it leaves room for the second
        assert!(parse(&["x", "noindex"], "crawlx").noindex);
    }

    #[test]
    fn union_merges_flags() {
        let meta = RobotsMeta {
            noindex: true,
            ..RobotsMeta::default()
        };
        let header = RobotsMeta {
            nofollow: true,
            nosnippet: true,
            ..RobotsMeta::default()
        };
        assert_eq!(flags(meta.union(header)), [true, true, false, true, false]);
        assert_eq!(meta.union(RobotsMeta::default()), meta);
    }
}
