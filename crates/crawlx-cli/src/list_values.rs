//! List-valued flags that accept inline values or a file of them: `--resolvers`.
//!
//! A value is either the list itself (`1.1.1.1,9.9.9.9:5353`, split by clap at the commas) or
//! the path of a file. A file holds one or more entries per line separated by commas or white
//! space; blank lines and `#` comments (whole-line or trailing) are ignored. Entries keep their
//! first-seen order and a repeated entry counts once, so the same server named inline and in a
//! file is queried once and does not use up the cap twice.

use anyhow::{bail, Context as _};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

/// The most resolvers a request may carry (the request validation enforces the same cap).
pub(crate) const MAX_RESOLVERS: usize = 8;

/// Split one line or inline value into entries.
fn entries(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(|line| line.split_once('#').map_or(line, |(before, _)| before))
        .flat_map(|line| line.split(|c: char| c == ',' || c.is_whitespace()))
        .filter(|entry| !entry.is_empty())
}

/// Expand `values` (inline entries and/or file paths) to the ordered, de-duplicated entries.
///
/// # Errors
/// An unreadable file (named, with the flag), or a file that is not valid UTF-8.
pub(crate) fn expand(flag: &str, values: &[String]) -> anyhow::Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for value in values {
        let from_file = !value.is_empty() && Path::new(value).is_file();
        let text = if from_file {
            std::fs::read_to_string(value).with_context(|| format!("{flag}: reading {value}"))?
        } else {
            value.clone()
        };
        for entry in entries(&text) {
            if seen.insert(entry.to_owned()) {
                out.push(entry.to_owned());
            }
        }
    }
    Ok(out)
}

/// `--resolvers`: `ip` (port 53) or `ip:port` / `[ipv6]:port`, at most [`MAX_RESOLVERS`].
///
/// The list only chooses *which DNS servers answer*; the egress checks still judge every
/// address those servers return, so a resolver cannot steer a crawl to a private target.
///
/// # Errors
/// An unreadable file, an entry that is neither an IP address nor a socket address, or more
/// than [`MAX_RESOLVERS`] distinct entries.
pub(crate) fn resolvers(values: &[String]) -> anyhow::Result<Vec<String>> {
    let list = expand("--resolvers", values)?;
    if let Some(bad) = list
        .iter()
        .find(|e| e.parse::<IpAddr>().is_err() && e.parse::<SocketAddr>().is_err())
    {
        bail!("--resolvers: {bad:?} is not an IP address, `ip:port` or `[ipv6]:port`");
    }
    if list.len() > MAX_RESOLVERS {
        bail!(
            "--resolvers: {} distinct resolvers given, at most {MAX_RESOLVERS} are allowed",
            list.len()
        );
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn inline_entries_keep_order_and_drop_repeats() {
        assert_eq!(
            resolvers(&strings(&["9.9.9.9", "1.1.1.1:5353", "9.9.9.9"])).unwrap(),
            ["9.9.9.9", "1.1.1.1:5353"]
        );
    }

    #[test]
    fn a_file_may_hold_commas_spaces_comments_and_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolvers.txt");
        std::fs::write(
            &path,
            "# trusted resolvers\n1.1.1.1, 9.9.9.9:5353   # primary pair\n\n[2606:4700:4700::1111]:53\n9.9.9.9:5353\n",
        )
        .unwrap();
        let list = resolvers(&strings(&["8.8.8.8", path.to_str().unwrap(), "1.1.1.1"])).unwrap();
        assert_eq!(
            list,
            ["8.8.8.8", "1.1.1.1", "9.9.9.9:5353", "[2606:4700:4700::1111]:53"]
        );
    }

    #[test]
    fn bad_entries_and_the_cap_are_named_with_the_flag() {
        let error = resolvers(&strings(&["1.1.1.1", "dns.example"]))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("--resolvers") && error.contains("dns.example"),
            "{error}"
        );
        let nine: Vec<String> = (1..=9).map(|n| format!("10.0.0.{n}")).collect();
        let error = resolvers(&nine).unwrap_err().to_string();
        assert!(error.contains("9 distinct resolvers"), "{error}");
        // the same server twice is one resolver, so nine names for eight servers fit
        let mut eight = nine[..8].to_vec();
        eight.push("10.0.0.1".to_owned());
        assert_eq!(resolvers(&eight).unwrap().len(), 8);
    }

    #[test]
    fn a_directory_is_not_a_list_file() {
        let dir = tempfile::tempdir().unwrap();
        // a directory is not a regular file, so it is read as an inline value and rejected as one
        let error = resolvers(&strings(&[dir.path().to_str().unwrap()]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("--resolvers"), "{error}");
    }
}
