//! Seed input of `crawlx crawl` (compatibility `-u`, `-list`, stdin, `-parallelism`, `-resume`,
//! `-config`).

use crate::merge::fill_fields;
use anyhow::{anyhow, bail, Context as _};
use clap::Args;
use std::path::PathBuf;
use url::Url;

/// Where seeds, parallelism, resume state and the configuration file come from.
#[derive(Args, Debug, Clone, Default)]
pub struct InputArgs {
    /// Seed URLs (optional when `-u`, `--list` or `--request` supplies them); `-` reads one
    /// URL per line from standard input.
    #[arg(value_name = "URL")]
    pub targets: Vec<String>,
    /// Seed URL; comma separated lists are accepted and the flag may repeat. Every seed is a
    /// separate run with its own frontier.
    #[arg(
        short = 'u',
        long = "url",
        value_name = "URL",
        value_delimiter = ',',
        help_heading = "Input"
    )]
    pub url: Vec<String>,
    /// File of seed URLs, one per line (`#` starts a comment). Repeatable.
    #[arg(long, value_name = "FILE", help_heading = "Input")]
    pub list: Vec<PathBuf>,
    /// Seeds crawled at the same time (default 10); outputs are still printed in seed order.
    #[arg(
        short = 'p',
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u16).range(1..=1024),
        help_heading = "Input"
    )]
    pub parallelism: Option<u16>,
    /// Resume file of an in-memory run: read when it exists, written when the run stops with
    /// URLs left (Ctrl-C, `--limit-urls`, `--crawl-duration`), removed when every frontier
    /// ran dry.
    #[arg(long, value_name = "FILE", help_heading = "Input")]
    pub resume: Option<PathBuf>,
    /// Configuration file: compatibility-style YAML with long-flag keys, or a `CreateCrawl` body as
    /// JSON (`.json`) or TOML (`.toml`, table `[crawl]`). Flags override the file; the file
    /// overrides defaults; an unknown key is an error.
    #[arg(long, value_name = "FILE", help_heading = "Input")]
    pub config: Option<PathBuf>,
}

impl InputArgs {
    /// Fill unset fields from `lower`.
    pub(crate) fn fill_from(&mut self, lower: Self) {
        fill_fields!(
            self,
            lower,
            InputArgs {
                targets,
                url,
                list,
                parallelism,
                resume,
                config
            }
        );
    }

    /// Seeds named by flags and list files, without standard input. Positional `-` is skipped.
    ///
    /// # Errors
    /// An unreadable list file or an invalid URL, naming the source.
    pub(crate) fn flag_seeds(&self) -> anyhow::Result<Vec<Url>> {
        let mut seeds = Vec::new();
        for raw in self.targets.iter().filter(|t| t.as_str() != "-") {
            seeds.push(parse_seed(raw, "seed URL")?);
        }
        for raw in &self.url {
            seeds.push(parse_seed(raw, "--url")?);
        }
        for path in &self.list {
            let text =
                std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            seeds.extend(parse_lines(&text, &format!("--list {}", path.display()))?);
        }
        Ok(dedupe(seeds))
    }

    /// `true` when a positional `-` asks for standard input.
    pub(crate) fn wants_stdin(&self) -> bool {
        self.targets.iter().any(|t| t == "-")
    }
}

fn parse_seed(raw: &str, what: &str) -> anyhow::Result<Url> {
    let raw = raw.trim();
    let url = Url::parse(raw).with_context(|| format!("{what}: invalid URL {raw:?}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("{what}: {raw:?} is not an http or https URL");
    }
    Ok(url)
}

/// One URL per non-blank, non-comment line.
///
/// # Errors
/// The first invalid line, with its number.
pub(crate) fn parse_lines(text: &str, source: &str) -> anyhow::Result<Vec<Url>> {
    text.lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(n, line)| parse_seed(line, &format!("{source} line {n}")))
        .collect()
}

/// Drop repeated seeds, keeping the first occurrence.
pub(crate) fn dedupe(seeds: Vec<Url>) -> Vec<Url> {
    let mut seen = std::collections::BTreeSet::new();
    seeds
        .into_iter()
        .filter(|u| seen.insert(u.as_str().to_owned()))
        .collect()
}

/// The seeds of a run: flag seeds, then standard input when `-` was given, else the request's
/// own `seedUrl`.
///
/// # Errors
/// No seed anywhere, or a bad URL.
pub(crate) fn resolve_seeds(
    input: &InputArgs,
    request_seed: Option<&Url>,
    stdin: impl FnOnce() -> anyhow::Result<String>,
) -> anyhow::Result<Vec<Url>> {
    let mut seeds = input.flag_seeds()?;
    if input.wants_stdin() {
        seeds.extend(parse_lines(&stdin()?, "standard input")?);
        seeds = dedupe(seeds);
    }
    if seeds.is_empty() {
        match request_seed {
            Some(url) if !input.wants_stdin() => seeds.push(url.clone()),
            _ if input.wants_stdin() => bail!("standard input held no URL"),
            _ => {
                return Err(anyhow!(
                    "a seed URL (positional, -u, --list, or `-` for stdin) or --request is required"
                ))
            }
        }
    }
    Ok(seeds)
}

/// Read all of standard input.
///
/// # Errors
/// An I/O error while reading.
pub(crate) fn read_stdin() -> anyhow::Result<String> {
    use std::io::Read as _;
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .context("reading standard input")?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn lines_skip_blanks_and_comments_and_name_the_bad_line() {
        let seeds = parse_lines("# seeds\n\nhttps://a.test/\n  http://b.test/x  \n", "list").unwrap();
        assert_eq!(seeds.len(), 2);
        let err = parse_lines("https://a.test/\nnot a url\n", "list")
            .unwrap_err()
            .to_string();
        assert!(err.contains("list line 2"), "{err}");
        let err = parse_lines("ftp://a.test/\n", "list").unwrap_err().to_string();
        assert!(err.contains("not an http or https URL"), "{err}");
    }

    #[test]
    fn seeds_come_from_every_source_without_repeats() {
        let input = InputArgs {
            targets: vec!["https://a.test/".into(), "-".into()],
            url: vec!["https://b.test/".into(), "https://a.test/".into()],
            ..InputArgs::default()
        };
        let seeds = resolve_seeds(&input, None, || {
            Ok("https://c.test/\nhttps://b.test/\n".to_owned())
        })
        .unwrap();
        let seeds: Vec<&str> = seeds.iter().map(Url::as_str).collect();
        assert_eq!(seeds, ["https://a.test/", "https://b.test/", "https://c.test/"]);
    }

    #[test]
    fn no_seed_anywhere_is_an_error_and_the_request_seed_is_the_fallback() {
        let input = InputArgs::default();
        assert!(resolve_seeds(&input, None, || Ok(String::new())).is_err());
        let fallback = Url::parse("https://r.test/").unwrap();
        let seeds = resolve_seeds(&input, Some(&fallback), || Ok(String::new())).unwrap();
        assert_eq!(seeds, [fallback]);
        let stdin_only = InputArgs {
            targets: vec!["-".into()],
            ..InputArgs::default()
        };
        assert!(resolve_seeds(&stdin_only, None, || Ok("\n".to_owned())).is_err());
    }
}
