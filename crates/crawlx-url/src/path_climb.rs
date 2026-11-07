//! Parent directory URLs of a URL (katana `-pc` / `utils.ExtractParentPaths`, MIT): the
//! candidates the worker offers to the frontier when `scope.pathClimb` is on.
//!
//! Pure and deterministic: the result depends only on the URL.

use url::Url;

/// Parent directory URLs of `url`, nearest first.
///
/// `https://h/a/b/c.html?q=1#f` yields `https://h/a/b/`, `https://h/a/` and `https://h/`.
/// Every parent keeps the scheme, credentials, host and port of `url`, has no query and no
/// fragment, ends in `/`, and is never `url` itself (a URL whose path is `/` has no
/// parents). Empty path segments are skipped. URLs without a host (`mailto:`, `data:`)
/// have no parents.
#[must_use]
pub fn parent_paths(url: &Url) -> Vec<Url> {
    if url.cannot_be_a_base() || url.host().is_none() {
        return Vec::new();
    }
    let segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();
    let mut base = url.clone();
    base.set_query(None);
    base.set_fragment(None);
    let mut parents = Vec::with_capacity(segments.len());
    for keep in (0..segments.len()).rev() {
        let mut path = String::with_capacity(1 + segments[..keep].iter().map(|s| s.len() + 1).sum::<usize>());
        path.push('/');
        for segment in &segments[..keep] {
            path.push_str(segment);
            path.push('/');
        }
        let mut parent = base.clone();
        parent.set_path(&path);
        parents.push(parent);
    }
    parents
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn parents(s: &str) -> Vec<String> {
        parent_paths(&Url::parse(s).unwrap())
            .iter()
            .map(Url::to_string)
            .collect()
    }

    #[test]
    fn nearest_first_down_to_the_root() {
        assert_eq!(
            parents("https://example.com/test/path/to/file.html"),
            [
                "https://example.com/test/path/to/",
                "https://example.com/test/path/",
                "https://example.com/test/",
                "https://example.com/",
            ]
        );
    }

    #[test]
    fn query_fragment_are_dropped_and_origin_is_kept() {
        assert_eq!(
            parents("http://u:p@Example.com:8080/a/b?x=1&y=2#frag"),
            ["http://u:p@example.com:8080/a/", "http://u:p@example.com:8080/"]
        );
    }

    #[test]
    fn never_the_url_itself() {
        assert!(parents("https://example.com/").is_empty());
        assert!(parents("https://example.com").is_empty());
        assert!(parents("https://example.com/?q=1").is_empty());
        assert_eq!(parents("https://example.com/a/"), ["https://example.com/"]);
        assert_eq!(
            parents("https://example.com/a/b/"),
            ["https://example.com/a/", "https://example.com/"]
        );
    }

    #[test]
    fn empty_segments_and_encoded_paths_survive() {
        assert_eq!(
            parents("https://example.com//a//b%20c/d"),
            [
                "https://example.com/a/b%20c/",
                "https://example.com/a/",
                "https://example.com/",
            ]
        );
    }

    #[test]
    fn urls_without_a_host_have_no_parents() {
        assert!(parents("mailto:someone@example.com").is_empty());
        assert!(parents("data:text/plain,hello").is_empty());
    }
}
