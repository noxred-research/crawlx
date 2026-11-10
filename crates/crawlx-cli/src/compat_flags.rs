//! Compatibility flags: `crawlx crawl -mdc 'status_code == 200' -field-scope rdn -jsonl`.
//!
//! clap has no multi-letter short flags, but the compatibility spellings are single-dash words:
//! its short names (`-mdc`, `-ct`, `-hc`, ...) and, through the Go flag-parsing convention, every long name with one
//! dash (`-field-scope`, `-jsonl`). [`normalize_args`] rewrites those words, after the `crawl`
//! subcommand, to the `--long` flags this crate defines, so a compatibility command line works
//! unchanged. Single-letter shorts (`-u`, `-p`, `-d`, `-s`, `-c`, `-f`, `-o`, `-j`, `-v`, `-e`,
//! `-r`, `-H`) are real clap shorts and are not touched.

use clap::Args as _;
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};

/// The compatibility multi-letter short names and the `crawl` flag each stands for.
const COMPAT_SHORT: &[(&str, &str)] = &[
    ("aff", "automatic-form-fill"),
    ("cdd", "chrome-data-dir"),
    ("cos", "crawl-out-scope"),
    ("cs", "crawl-scope"),
    ("csk", "captcha-solver-key"),
    ("csp", "captcha-solver-provider"),
    ("ct", "crawl-duration"),
    ("cwu", "chrome-ws-url"),
    ("do", "display-out-scope"),
    ("dr", "no-redirects"),
    ("duc", "disable-update-check"),
    ("duf", "disable-unique-filter"),
    ("dwt", "dom-wait-time"),
    ("ed", "enable-diagnostics"),
    ("ef", "extension-filter"),
    ("elog", "error-log"),
    ("em", "extension-match"),
    ("eof", "exclude-output-fields"),
    ("fc", "form-config"),
    ("fdc", "filter-condition"),
    ("flc", "custom-field-config"),
    ("fpt", "filter-page-type"),
    ("fr", "filter-regex"),
    ("fs", "field-scope"),
    ("fsu", "filter-similar"),
    ("fst", "filter-similar-threshold"),
    ("fx", "form-extraction"),
    ("hc", "health-check"),
    ("ho", "headless-options"),
    ("hh", "hybrid"),
    ("hl", "headless"),
    ("hrl", "host-rate-limit"),
    ("hrlm", "host-rate-limit-minute"),
    ("iqp", "ignore-query-params"),
    ("jc", "js-crawl"),
    ("jsl", "jsluice"),
    ("kb", "knowledge-base"),
    ("kf", "known-files"),
    ("lof", "list-output-fields"),
    ("mdc", "match-condition"),
    ("mdp", "max-pages-per-host"),
    ("mfc", "max-failure-count"),
    ("mr", "match-regex"),
    ("mrs", "max-response-size"),
    ("nc", "no-color"),
    ("ncb", "no-clobber"),
    ("ndef", "no-default-ext-filter"),
    ("noi", "no-incognito"),
    ("nos", "no-sandbox"),
    ("ns", "no-scope"),
    ("ob", "omit-body"),
    ("or", "omit-raw"),
    ("ot", "output-template"),
    ("pc", "path-climb"),
    ("pcs", "page-content-similar"),
    ("pcsd", "content-similar-distance"),
    ("pcsm", "page-content-similar-mode"),
    ("pcsn", "content-similar-budget"),
    ("pcst", "content-similar-threshold"),
    ("pls", "page-load-strategy"),
    ("rd", "delay"),
    ("rf", "recorded-flow"),
    ("rl", "rate-limit"),
    ("rlm", "rate-limit-minute"),
    ("sb", "show-browser"),
    ("sc", "system-chrome"),
    ("scp", "system-chrome-path"),
    ("sdd", "similarity-deduplication"),
    ("sf", "store-field"),
    ("sfd", "store-fields"),
    ("sr", "store-response"),
    ("srd", "store-response-dir"),
    ("td", "tech-detect"),
    ("tlsi", "tls-impersonate"),
    ("up", "update"),
    ("xhr", "xhr-extraction"),
];

/// Every long flag name and alias of `crawl`.
fn crawl_long_names() -> BTreeSet<String> {
    let command = crate::crawl::CrawlArgs::augment_args(clap::Command::new("crawl"));
    let mut names = BTreeSet::new();
    for arg in command.get_arguments() {
        names.extend(arg.get_long().map(str::to_owned));
        names.extend(arg.get_all_aliases().into_iter().flatten().map(str::to_owned));
    }
    names
}

/// Rewrite compatibility single-dash words after the `crawl` subcommand to `--long` flags (see the
/// module documentation). Arguments before `crawl`, after a bare `--`, and everything that is
/// not exactly a compatibility name (optionally `=value`) pass through unchanged.
#[must_use]
pub fn normalize_args<I, T>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let Some(subcommand) = args.iter().skip(1).position(|a| a == "crawl").map(|p| p + 1) else {
        return args;
    };
    let longs = crawl_long_names();
    let mut out = Vec::with_capacity(args.len());
    let mut literal = false;
    for (i, arg) in args.into_iter().enumerate() {
        if i <= subcommand || literal {
            out.push(arg);
        } else if arg == "--" {
            literal = true;
            out.push(arg);
        } else {
            out.push(rewrite(&arg, &longs).unwrap_or(arg));
        }
    }
    out
}

fn rewrite(arg: &OsStr, longs: &BTreeSet<String>) -> Option<OsString> {
    let rest = arg.to_str()?.strip_prefix('-')?;
    if rest.starts_with('-') || rest.len() < 2 {
        return None;
    }
    let (name, value) = match rest.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (rest, None),
    };
    let long = COMPAT_SHORT
        .iter()
        .find(|(short, _)| *short == name)
        .map(|(_, long)| *long)
        .or_else(|| longs.contains(name).then_some(name))?;
    Some(
        match value {
            Some(v) => format!("--{long}={v}"),
            None => format!("--{long}"),
        }
        .into(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn norm(args: &[&str]) -> Vec<String> {
        normalize_args(args.iter().copied())
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect()
    }

    #[test]
    fn compat_similarity_switches_keep_boolean_values_and_backend_separate() {
        assert_eq!(
            norm(&["crawlx", "crawl", "-pcs=false", "-sdd", "-pcsm=tfidf"]),
            [
                "crawlx",
                "crawl",
                "--page-content-similar=false",
                "--similarity-deduplication",
                "--page-content-similar-mode=tfidf",
            ]
        );
        assert_eq!(
            norm(&[
                "crawlx",
                "crawl",
                "-page-content-similar",
                "-similarity-deduplication=false",
                "-page-content-similar-mode",
                "simhash",
            ]),
            [
                "crawlx",
                "crawl",
                "--page-content-similar",
                "--similarity-deduplication=false",
                "--page-content-similar-mode",
                "simhash",
            ]
        );
    }

    #[test]
    fn compat_shorts_and_single_dash_long_names_become_long_flags() {
        assert_eq!(
            norm(&[
                "crawlx",
                "crawl",
                "-u",
                "https://a.test/",
                "-mdc",
                "status_code == 200",
                "-ct=5m",
                "-jsonl",
                "-field-scope",
                "rdn"
            ]),
            [
                "crawlx",
                "crawl",
                "-u",
                "https://a.test/",
                "--match-condition",
                "status_code == 200",
                "--crawl-duration=5m",
                "--jsonl",
                "--field-scope",
                "rdn"
            ]
        );
        // aliases and flags crawlx spells differently from the compatibility flags
        assert_eq!(
            norm(&[
                "crawlx",
                "crawl",
                "-retry",
                "2",
                "-dr",
                "-kb-secrets",
                "-exclude",
                "cdn"
            ]),
            [
                "crawlx",
                "crawl",
                "--retry",
                "2",
                "--no-redirects",
                "--kb-secrets",
                "--exclude",
                "cdn"
            ]
        );
    }

    #[test]
    fn single_letter_shorts_unknown_words_values_and_other_commands_are_left_alone() {
        let same = [
            "crawlx",
            "crawl",
            "-p",
            "5",
            "-H",
            "X-A: b",
            "-fr",
            "x",
            "-nonsense",
            "-10",
            "--field-scope",
            "rdn",
            "plain",
        ];
        let got = norm(&same);
        assert_eq!(&got[..6], &["crawlx", "crawl", "-p", "5", "-H", "X-A: b"]);
        assert_eq!(got[6], "--filter-regex");
        assert_eq!(
            &got[7..],
            &["x", "-nonsense", "-10", "--field-scope", "rdn", "plain"]
        );
        // before `crawl`, in other subcommands and after `--` nothing changes
        assert_eq!(norm(&["crawlx", "-mdc", "crawl"]), ["crawlx", "-mdc", "crawl"]);
        assert_eq!(norm(&["crawlx", "export", "-mdc"]), ["crawlx", "export", "-mdc"]);
        assert_eq!(
            norm(&["crawlx", "crawl", "--", "-mdc", "-silent"]),
            ["crawlx", "crawl", "--", "-mdc", "-silent"]
        );
    }

    #[test]
    fn compat_browser_attach_and_hybrid_spellings_map_to_crawl_flags() {
        assert_eq!(
            norm(&[
                "crawlx",
                "crawl",
                "-cwu",
                "ws://127.0.0.1:9222/devtools/browser/x",
                "-noi",
                "-hh"
            ]),
            [
                "crawlx",
                "crawl",
                "--chrome-ws-url",
                "ws://127.0.0.1:9222/devtools/browser/x",
                "--no-incognito",
                "--hybrid"
            ]
        );
        assert_eq!(
            norm(&["crawlx", "crawl", "-chrome-ws-url=ws://h/x"]),
            ["crawlx", "crawl", "--chrome-ws-url=ws://h/x"]
        );
    }
}
