#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Property tests (`fuzz_html_extract` contract): extraction of
//! arbitrary input never panics, output stays bounded and links are a subset
//! of the document's anchors.

use std::collections::HashSet;

use crawlx_extract::{ExtractOptions, Extractor};
use proptest::prelude::*;
use url::Url;

fn page() -> Url {
    Url::parse("https://example.com/dir/page").unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        for only_main in [true, false] {
            let o = ExtractOptions { only_main_content: only_main, ..ExtractOptions::default() };
            let _ = Extractor::extract_bytes(&bytes, &page(), &o);
        }
    }

    #[test]
    fn tag_soup_never_panics_and_output_is_bounded(
        parts in proptest::collection::vec(
            prop_oneof![
                Just("<div>".to_owned()), Just("</div>".to_owned()), Just("<p>".to_owned()),
                Just("<a href=\"/x?y=1\">".to_owned()), Just("</a>".to_owned()), Just("<ul><li>".to_owned()),
                Just("<table><tr><td colspan=3>".to_owned()), Just("</table>".to_owned()),
                Just("<pre><code class=\"language-c\">".to_owned()), Just("</pre>".to_owned()),
                Just("<b>".to_owned()), Just("<i>".to_owned()), Just("</b>".to_owned()),
                Just("<img src=a.png alt=\"[x]\">".to_owned()), Just("<br>".to_owned()),
                Just("<script>".to_owned()), Just("<!--".to_owned()), Just("&amp;".to_owned()),
                "[ -~]{0,12}",
            ],
            0..120,
        )
    ) {
        let html: String = parts.concat();
        let d = Extractor::extract(&html, &page(), &ExtractOptions::default()).unwrap();
        // Output size <= 4x input (plus slack for tiny inputs).
        prop_assert!(d.markdown.len() <= 4 * html.len() + 64, "markdown too large");
        prop_assert!(d.html.len() <= 4 * html.len() + 64, "html too large");
        // Max two consecutive newlines outside code blocks is checked on fence-free output.
        if !d.markdown.contains("```") {
            prop_assert!(!d.markdown.contains("\n\n\n"));
        }
    }

    #[test]
    fn links_are_a_subset_of_anchors(hrefs in proptest::collection::vec("[a-z0-9/._?=#-]{0,16}", 0..20)) {
        let mut html = String::new();
        for h in &hrefs {
            html.push_str(&format!("<a href=\"{h}\">t</a>"));
        }
        let d = Extractor::extract(&html, &page(), &ExtractOptions::default()).unwrap();
        let resolved: HashSet<String> = hrefs
            .iter()
            .filter_map(|h| page().join(h).ok())
            .map(|mut u| { u.set_fragment(None); u.to_string() })
            .collect();
        for l in &d.links {
            prop_assert!(resolved.contains(l.url.as_str()));
        }
        let unique: HashSet<&str> = d.links.iter().map(|l| l.url.as_str()).collect();
        prop_assert_eq!(unique.len(), d.links.len());
    }
}
