//! Link/media scoring, internal/external classes, preview intents and head projection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::extraction::{check_preview_target, PreviewIntentV1, PreviewPurposeV1, PreviewRefusalV1};
use crawlx_extract::content_outputs::{ContentOutputOptions, DiscoveryScope};
use crawlx_extract::link_media::{
    project_head, LinkClass, LinkMediaOptions, LinkMediaReport, MediaScoreKind, LINK_MEDIA_SCHEMA,
};
use crawlx_extract::{Document, ExtractOptions, Extractor};
use url::Url;

const PAGE: &str = r#"<!doctype html>
<html lang="en"><head><title>Hub</title></head><body>
<header><nav><a href="/home">Home</a><a href="/products">Products</a></nav></header>
<main><article>
<h2><a href="/guides/start-here">Start here with the complete guide</a></h2>
<p>See the <a href="https://other.test/research/paper?utm_source=feed&amp;utm_medium=x">full research paper</a> and a <a href="https://other.test/ads" rel="nofollow sponsored">click here</a> offer.</p>
<p><a href="http://127.0.0.1:8080/admin">local panel</a> <a href="https://intranet/wiki">team wiki</a> <a href="https://sub.fixture.test/docs">docs site</a></p>
<figure><img src="/img/hero.jpg" width="800" height="400" alt="Hero image"><figcaption>Caption</figcaption></figure>
<img src="/img/pixel.gif" width="1" height="1">
<video src="/media/clip.mp4" width="640" height="360" title="Clip" controls></video>
</article></main>
<aside><img src="/img/ad.png" alt=""></aside>
<footer><a href="/privacy">Privacy policy</a></footer>
</body></html>"#;

fn page() -> Url {
    Url::parse("https://fixture.test/p").unwrap()
}

fn run(html: &str, page: &Url, configure: impl FnOnce(&mut ContentOutputOptions)) -> Document {
    let mut outputs = ContentOutputOptions::default();
    configure(&mut outputs);
    Extractor::extract(
        html,
        page,
        &ExtractOptions {
            outputs: Some(outputs),
            ..ExtractOptions::default()
        },
    )
    .unwrap()
}

fn report(doc: &Document) -> &LinkMediaReport {
    doc.outputs.as_ref().unwrap().link_media.as_ref().unwrap()
}

fn scored<'a>(r: &'a LinkMediaReport, url: &str) -> &'a crawlx_extract::link_media::ScoredLink {
    r.links
        .iter()
        .find(|l| l.url.as_str() == url)
        .unwrap_or_else(|| panic!("{url} not scored"))
}

#[test]
fn links_carry_separate_intrinsic_and_contextual_components() {
    let doc = run(PAGE, &page(), |o| {
        o.link_media = Some(LinkMediaOptions::default())
    });
    let r = report(&doc);
    assert_eq!(r.schema, LINK_MEDIA_SCHEMA);
    assert!(!r.truncated && r.previews.is_empty());
    for l in &r.links {
        assert_eq!(
            doc.links[l.link_index].url, l.url,
            "link_index points into Document::links"
        );
    }
    let home = scored(r, "https://fixture.test/home");
    let guide = scored(r, "https://fixture.test/guides/start-here");
    // Same well-formed target quality, very different placement.
    assert_eq!(home.intrinsic.url, 1000);
    assert_eq!(home.intrinsic.text, 600, "one-word anchor");
    assert_eq!(guide.intrinsic.text, 1000);
    assert_eq!(guide.intrinsic.total, 1000);
    assert_eq!(home.contextual.region, 150, "inside nav");
    assert_eq!(guide.contextual.region, 1000, "inside article");
    assert_eq!(guide.contextual.heading, 1000);
    assert!(
        home.intrinsic.total >= 800 && home.contextual.total < 400,
        "{home:?}"
    );
    assert!(guide.contextual.total > home.contextual.total);
    assert_eq!(
        guide.combined,
        (guide.intrinsic.total + guide.contextual.total) / 2
    );
    // URL shape and rel hints are intrinsic.
    let tracked = scored(
        r,
        "https://other.test/research/paper?utm_source=feed&utm_medium=x",
    );
    assert_eq!(tracked.intrinsic.url, 600);
    let sponsored = scored(r, "https://other.test/ads");
    assert_eq!((sponsored.intrinsic.rel, sponsored.intrinsic.text), (200, 200));
    // Container link density: a link-only list scores lower than a link inside prose.
    assert!(sponsored.contextual.container_density > home.contextual.container_density);
    // Footer links sit low.
    assert_eq!(scored(r, "https://fixture.test/privacy").contextual.region, 100);
}

#[test]
fn links_are_classified_against_the_page_host() {
    let doc = run(PAGE, &page(), |o| {
        o.link_media = Some(LinkMediaOptions::default())
    });
    let r = report(&doc);
    assert_eq!(scored(r, "https://fixture.test/home").class, LinkClass::Internal);
    assert_eq!(
        scored(r, "https://sub.fixture.test/docs").class,
        LinkClass::Subdomain
    );
    assert_eq!(scored(r, "https://other.test/ads").class, LinkClass::External);
    let www = Url::parse("https://www.fixture.test/p").unwrap();
    let doc = run(
        r#"<body><a href="https://fixture.test/a">a b</a><a href="https://evilfixture.test/">x y</a></body>"#,
        &www,
        |o| o.link_media = Some(LinkMediaOptions::default()),
    );
    let r = report(&doc);
    assert_eq!(scored(r, "https://fixture.test/a").class, LinkClass::Internal);
    assert_eq!(scored(r, "https://evilfixture.test/").class, LinkClass::External);
}

#[test]
fn media_scores_keep_components_apart() {
    let doc = run(PAGE, &page(), |o| {
        o.link_media = Some(LinkMediaOptions::default())
    });
    let r = report(&doc);
    let urls: Vec<&str> = r.images.iter().map(|m| m.url.as_str()).collect();
    assert_eq!(
        urls,
        [
            "https://fixture.test/img/hero.jpg",
            "https://fixture.test/img/pixel.gif",
            "https://fixture.test/img/ad.png"
        ]
    );
    let (hero, pixel, ad) = (&r.images[0], &r.images[1], &r.images[2]);
    assert!(r.images.iter().all(|m| m.kind == MediaScoreKind::Image));
    assert_eq!(
        (
            hero.intrinsic.description,
            hero.intrinsic.dimensions,
            hero.intrinsic.format
        ),
        (1000, 1000, 1000)
    );
    assert_eq!(hero.contextual.figure, 1000, "figure with caption");
    assert_eq!(hero.contextual.region, 1000);
    assert!(hero.combined > pixel.combined && hero.combined > ad.combined);
    assert_eq!(pixel.intrinsic.dimensions, 0, "tracking pixel");
    assert_eq!(pixel.intrinsic.description, 0, "missing alt");
    assert_eq!(ad.intrinsic.description, 300, "explicit empty alt is decorative");
    assert_eq!(ad.contextual.region, 250, "inside aside");
    let [clip] = r.media.as_slice() else {
        panic!("{:?}", r.media)
    };
    assert_eq!(clip.kind, MediaScoreKind::Video);
    assert_eq!(clip.url.as_str(), "https://fixture.test/media/clip.mp4");
    assert_eq!(
        (
            clip.intrinsic.description,
            clip.intrinsic.dimensions,
            clip.intrinsic.format
        ),
        (1000, 1000, 1000)
    );
}

#[test]
fn private_and_local_targets_never_become_preview_intents() {
    let doc = run(PAGE, &page(), |o| {
        let mut options = LinkMediaOptions::with_previews(32);
        options.min_preview_score = 0;
        o.link_media = Some(options);
    });
    let r = report(&doc);
    assert!(!r.previews.is_empty());
    for intent in &r.previews {
        assert_eq!(intent.purpose, PreviewPurposeV1::HeadMetadata);
        check_preview_target(&intent.url).unwrap();
        assert!(intent.url.host_str() != Some("127.0.0.1") && intent.url.host_str() != Some("intranet"));
    }
    let refused: Vec<(&str, PreviewRefusalV1)> = r
        .refused_previews
        .iter()
        .map(|x| (x.url.as_str(), x.reason))
        .collect();
    assert!(
        refused.contains(&("http://127.0.0.1:8080/admin", PreviewRefusalV1::PrivateAddress)),
        "{refused:?}"
    );
    assert!(
        refused.contains(&("https://intranet/wiki", PreviewRefusalV1::LocalName)),
        "{refused:?}"
    );
    // The page itself is never previewed, and the best links come first.
    assert!(r.previews.iter().all(|i| i.url != page()));
    let best = r.links.iter().map(|l| l.combined).max().unwrap();
    let first = r.previews.first().unwrap();
    assert_eq!(scored(r, first.url.as_str()).combined, best);
}

#[test]
fn previews_are_off_by_default_and_capped() {
    let doc = run(PAGE, &page(), |o| {
        o.link_media = Some(LinkMediaOptions::default())
    });
    assert!(report(&doc).previews.is_empty() && report(&doc).refused_previews.is_empty());
    let doc = run(PAGE, &page(), |o| {
        let mut options = LinkMediaOptions::with_previews(2);
        options.min_preview_score = 0;
        o.link_media = Some(options);
    });
    assert_eq!(report(&doc).previews.len(), 2);
    let err = Extractor::extract(
        PAGE,
        &page(),
        &ExtractOptions {
            outputs: Some({
                let mut o = ContentOutputOptions::default();
                o.link_media = Some(LinkMediaOptions::with_previews(33));
                o
            }),
            ..ExtractOptions::default()
        },
    );
    assert!(err.is_err());
}

#[test]
fn scoring_follows_the_declared_discovery_scope() {
    let whole = run(PAGE, &page(), |o| {
        o.target_elements = vec!["h2".into()];
        o.link_media = Some(LinkMediaOptions::default());
    });
    assert!(report(&whole).links.len() >= 8, "whole page scored");
    assert!(report(&whole).images.len() == 3);
    let selected = run(PAGE, &page(), |o| {
        o.target_elements = vec!["h2".into()];
        o.discovery_scope = DiscoveryScope::Selected;
        o.link_media = Some(LinkMediaOptions::default());
    });
    let urls: Vec<&str> = report(&selected).links.iter().map(|l| l.url.as_str()).collect();
    assert_eq!(urls, ["https://fixture.test/guides/start-here"]);
    assert!(report(&selected).images.is_empty() && report(&selected).media.is_empty());
}

#[test]
fn report_is_deterministic_and_round_trips() {
    let a = run(PAGE, &page(), |o| {
        o.link_media = Some(LinkMediaOptions::with_previews(4))
    });
    let b = run(PAGE, &page(), |o| {
        o.link_media = Some(LinkMediaOptions::with_previews(4))
    });
    assert_eq!(report(&a), report(&b));
    let json = serde_json::to_string(report(&a)).unwrap();
    assert!(json.contains("\"intrinsic\"") && json.contains("\"contextual\""));
    let back: LinkMediaReport = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, report(&a));
}

fn intent(url: &str, bytes: u32) -> PreviewIntentV1 {
    PreviewIntentV1::with_budget(Url::parse(url).unwrap(), PreviewPurposeV1::HeadMetadata, bytes).unwrap()
}

#[test]
fn head_projection_reads_only_the_head() {
    let bytes = br#"<html lang="en"><head><title>Doc title</title>
<meta name="description" content="About this page">
<meta property="og:image" content="/pic.png"><meta property="og:site_name" content="Example">
<meta name="robots" content="noindex">
<link rel="canonical" href="/canon"></head><body><h1>BODYTEXT</h1><meta property="og:title" content="late"></body></html>"#;
    let head = project_head(&intent("https://x.test/a/b", 65_536), bytes).unwrap();
    assert_eq!(head.url.as_str(), "https://x.test/a/b");
    assert_eq!(head.title.as_deref(), Some("Doc title"));
    assert_eq!(head.description.as_deref(), Some("About this page"));
    assert_eq!(head.language.as_deref(), Some("en"));
    assert_eq!(
        head.canonical_url.as_ref().map(Url::as_str),
        Some("https://x.test/canon")
    );
    assert_eq!(
        head.image_url.as_ref().map(Url::as_str),
        Some("https://x.test/pic.png")
    );
    assert_eq!(head.site_name.as_deref(), Some("Example"));
    assert!(head.noindex && !head.nofollow && !head.truncated);
    assert!(!serde_json::to_string(&head).unwrap().contains("BODYTEXT"));
    assert!(
        !head.open_graph.contains_key("og:title"),
        "body markup is cut off"
    );
}

#[test]
fn head_projection_honours_the_byte_budget() {
    let mut bytes = b"<html><head><title>T</title></head><body>".to_vec();
    bytes.extend(std::iter::repeat_n(b'x', 5_000));
    let head = project_head(&intent("https://x.test/", 1_024), &bytes).unwrap();
    assert!(head.truncated);
    assert_eq!(head.title.as_deref(), Some("T"));
}
