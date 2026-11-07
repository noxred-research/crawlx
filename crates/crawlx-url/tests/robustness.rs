#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Parser robustness: arbitrary input never panics (fuzz targets, as property tests).

use crawlx_url::{extract_links, PathFilter, RouteTemplater, SitemapParser};
use proptest::prelude::*;
use url::Url;

proptest! {
    #[test]
    fn sitemap_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = SitemapParser::parse(&bytes);
    }

    #[test]
    fn sitemap_parser_never_panics_on_xmlish(s in "(<(urlset|url|loc|sitemap|sitemapindex|lastmod|x:loc)>|</(urlset|url|loc|sitemap|sitemapindex)>|https?://[a-z.]{1,8}/?|&[a-z#0-9]{0,4};?|<!\\[CDATA\\[|\\]\\]>| ){0,40}") {
        let _ = SitemapParser::parse(s.as_bytes());
    }

    #[test]
    fn link_scanner_never_panics(s in "(<a |<A |href=|\"|'|>|</a>|<!--|-->|<script>|</script>|<base |<link rel=alternate |/|é|&amp;|&#x41;|&#9999999999;| |x|<){0,60}") {
        let base = Url::parse("https://example.com/a/").unwrap();
        let _ = extract_links(&s, &base);
    }

    #[test]
    fn templating_and_patterns_never_panic(path in ".{0,80}", pat in ".{0,40}") {
        let _ = RouteTemplater::new().template(&path);
        let _ = PathFilter::new(std::slice::from_ref(&pat), std::slice::from_ref(&pat));
    }
}
