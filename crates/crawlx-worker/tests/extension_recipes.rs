//! Finite recipe compilation and proposal-only discovery acceptance tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::{
    extension_recipes::{ActorActionV1, DiscoveryRuleV1, ExtensionRecipeV1, RecipeSourceV1},
    extensions::{ExtensionConfigV1, ExtensionSpecV1, HandlerV1},
    extraction::{ArticleMetadataV1, DocumentEnvelopeV1, QualityOutcomeV1, QualityStatusV1},
    hash::Digest,
    request::RequestEnvelopeV1,
    selectors::SelectorV1,
};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use crawlx_worker::extension_recipes::{CompiledExtensionRecipe, RecipeCandidateKindV1};
use tokio_util::sync::CancellationToken;
use url::Url;

fn url(path: &str) -> Url {
    Url::parse("https://example.test/").unwrap().join(path).unwrap()
}

fn recipe_spec() -> ExtensionRecipeV1 {
    let mut spec = ExtensionRecipeV1::new("fixture".into(), 1);
    spec.pipeline
        .routes
        .insert("article".into(), HandlerV1::DocumentItem);
    spec.pipeline
        .routes
        .insert("fallback".into(), HandlerV1::DocumentItem);
    spec.pipeline.routes.insert("skip".into(), HandlerV1::Skip);
    spec
}

fn request(path: &str) -> RequestEnvelopeV1 {
    let canonical = Canonicalizer::canonicalize_url(&url(path), &CanonicalizeOptions::default()).unwrap();
    let mut request = RequestEnvelopeV1::get(canonical, 0, None);
    request.route = "article".into();
    request
}

fn document(title: &str) -> DocumentEnvelopeV1 {
    let mut metadata = ArticleMetadataV1::default();
    metadata.title.value = Some(title.into());
    let mut document = DocumentEnvelopeV1::new(
        Digest([0; 32]),
        Digest([0; 32]),
        "fixture".into(),
        0,
        Vec::new(),
        metadata,
        QualityOutcomeV1::new(QualityStatusV1::Accepted, Vec::new(), 1000, 1, 1),
    );
    document.privacy_projection_version = Some(1);
    document
}

#[test]
fn html_rule_order_selectors_and_exact_handlers_are_deterministic() {
    let mut spec = recipe_spec();
    let mut first = DiscoveryRuleV1::new(RecipeSourceV1::Html, "article".into());
    first.selectors.push(SelectorV1::Css {
        expression: "main".into(),
    });
    first.allow.push("/story".into());
    first.allow_domains.push("example.test".into());
    first.allow_extensions.push("html".into());
    let mut second = DiscoveryRuleV1::new(RecipeSourceV1::Html, "fallback".into());
    second.selectors.push(SelectorV1::Xpath {
        expression: "//nav".into(),
    });
    spec.rules = vec![first, second];
    let compiled = CompiledExtensionRecipe::new(spec).unwrap();
    let html = r#"<base href="/news/"><main><a href="story.html#part">story</a><a href="ignored.txt">wrong extension</a></main><nav><a href="story.html">duplicate</a><a href="index">index</a></nav><footer><a href="outside">outside</a></footer>"#;
    let selected = compiled
        .html(html, &url("/root"), &CancellationToken::new())
        .unwrap();
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].url, url("/news/story.html"));
    assert_eq!(selected[0].route, "article");
    assert_eq!(selected[0].handler, HandlerV1::DocumentItem);
    assert_eq!(selected[0].rule_index, Some(0));
    assert_eq!(selected[1].url, url("/news/index"));
    assert_eq!(selected[1].route, "fallback");
    assert_eq!(selected[1].rule_index, Some(1));
    assert_eq!(
        selected,
        compiled
            .html(html, &url("/root"), &CancellationToken::new())
            .unwrap()
    );
}

#[test]
fn later_hard_denies_beat_earlier_allow_and_cannot_be_resurrected() {
    let mut spec = recipe_spec();
    let first = DiscoveryRuleV1::new(RecipeSourceV1::Html, "article".into());
    let mut denial = DiscoveryRuleV1::new(RecipeSourceV1::Html, "fallback".into());
    denial.allow.push("never-matches".into());
    denial.deny.push("/private".into());
    denial.deny_domains.push("denied.test".into());
    denial.deny_extensions.push("pdf".into());
    spec.rules = vec![first, denial];
    let compiled = CompiledExtensionRecipe::new(spec).unwrap();
    let selected = compiled.html(
        r#"<a href="/private">deny</a><a href="https://sub.denied.test/x">host</a><a href="/report.PDF?view=html">extension</a><a href="/report%2e%50DF">encoded</a><a href="/safe">safe</a><a href="https://user:password@example.test/secret">credential</a><a href="javascript:alert(1)">code</a>"#,
        &url("/"),
        &CancellationToken::new(),
    ).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].url, url("/safe"));
}

#[test]
fn first_match_skip_blocks_later_handler() {
    let mut spec = recipe_spec();
    spec.rules = vec![
        DiscoveryRuleV1::new(RecipeSourceV1::Html, "skip".into()),
        DiscoveryRuleV1::new(RecipeSourceV1::Html, "article".into()),
    ];
    let compiled = CompiledExtensionRecipe::new(spec).unwrap();
    assert!(compiled
        .html("<a href='/story'>story</a>", &url("/"), &CancellationToken::new())
        .unwrap()
        .is_empty());
}

#[test]
fn sitemap_nested_sources_alternates_and_first_match_handlers_are_proposals() {
    let mut spec = recipe_spec();
    spec.follow_sitemaps = true;
    spec.sitemap_alternates = true;
    let mut french = DiscoveryRuleV1::new(RecipeSourceV1::Sitemap, "article".into());
    french.allow.push("/fr/".into());
    let fallback = DiscoveryRuleV1::new(RecipeSourceV1::Sitemap, "fallback".into());
    let mut deny = DiscoveryRuleV1::new(RecipeSourceV1::Sitemap, "skip".into());
    deny.allow.push("no-page".into());
    deny.deny_domains.push("denied.test".into());
    spec.rules = vec![french, fallback, deny];
    let compiled = CompiledExtensionRecipe::new(spec).unwrap();
    let cancel = CancellationToken::new();
    let nested = compiled.sitemap(
        br#"<sitemapindex><sitemap><loc>https://example.test/child.xml</loc></sitemap><sitemap><loc>https://denied.test/private.xml</loc></sitemap><sitemap><loc>https://example.test/root.xml</loc></sitemap></sitemapindex>"#,
        &url("/root.xml"), 0, &cancel,
    ).unwrap();
    assert_eq!(nested.len(), 1);
    assert_eq!(nested[0].kind, RecipeCandidateKindV1::Sitemap);
    assert_eq!(nested[0].sitemap_depth, 1);
    assert_eq!(nested[0].url, url("/child.xml"));
    assert_eq!(nested[0].route, "default");
    let pages = compiled.sitemap(
        br#"<urlset xmlns:h="http://www.w3.org/1999/xhtml" xmlns:e="urn:untrusted"><url><loc>https://example.test/en/story</loc><h:link rel="alternate" hreflang="fr" href="https://example.test/fr/story"/><h:link rel="alternate" hreflang="xx" href="https://denied.test/story"/><e:link rel="alternate" hreflang="bad" href="https://example.test/injected"/></url></urlset>"#,
        &nested[0].url, nested[0].sitemap_depth, &cancel,
    ).unwrap();
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].route, "fallback");
    assert_eq!(pages[0].rule_index, Some(1));
    assert_eq!(pages[1].route, "article");
    assert_eq!(pages[1].rule_index, Some(0));
    assert_eq!(pages[1].language_hint.as_deref(), Some("fr"));
    assert!(pages.iter().all(|p| p.kind == RecipeCandidateKindV1::Page));
}

#[test]
fn sitemap_limits_and_alternate_opt_in_fail_closed() {
    let mut spec = recipe_spec();
    spec.follow_sitemaps = true;
    spec.max_sitemap_depth = 0;
    spec.rules
        .push(DiscoveryRuleV1::new(RecipeSourceV1::Sitemap, "article".into()));
    let compiled = CompiledExtensionRecipe::new(spec).unwrap();
    let cancel = CancellationToken::new();
    assert!(compiled
        .sitemap(
            br#"<sitemapindex><sitemap><loc>https://example.test/child.xml</loc></sitemap></sitemapindex>"#,
            &url("/root.xml"),
            0,
            &cancel
        )
        .unwrap()
        .is_empty());
    assert!(compiled
        .sitemap(b"https://example.test/page", &url("/root.xml"), 1, &cancel)
        .is_err());
    let pages = compiled.sitemap(br#"<urlset xmlns:h="http://www.w3.org/1999/xhtml"><url><loc>https://example.test/en</loc><h:link rel="alternate" hreflang="fr" href="https://example.test/fr"/></url></urlset>"#, &url("/root.xml"), 0, &cancel).unwrap();
    assert_eq!(pages.len(), 1);
    assert!(compiled
        .sitemap(b"\x1f\x8bcompressed", &url("/root.xml"), 0, &cancel)
        .is_err());
    assert!(compiled
        .sitemap(
            b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///secret'>]><urlset/>",
            &url("/root.xml"),
            0,
            &cancel
        )
        .is_err());
}

#[test]
fn start_request_and_item_stages_use_existing_reviewed_pipeline() {
    let mut spec = recipe_spec();
    spec.start_requests.push(request("/start"));
    spec.pipeline.extensions = vec![
        ExtensionSpecV1::new(ExtensionConfigV1::ReadOnly {}, 0),
        ExtensionSpecV1::new(ExtensionConfigV1::TrimTitle {}, 0),
        ExtensionSpecV1::new(ExtensionConfigV1::RequireTitle {}, 1),
    ];
    let compiled = CompiledExtensionRecipe::new(spec).unwrap();
    let cancel = CancellationToken::new();
    let starts = compiled.start_requests(&cancel).unwrap();
    assert_eq!(starts.len(), 1);
    assert_eq!(starts[0].url.url, url("/start"));
    assert_eq!(starts[0].route, "article");
    let item = compiled
        .item("article", &document("  Title  "), &cancel)
        .unwrap()
        .unwrap();
    assert_eq!(item["title"], "Title");
    assert!(compiled.item("missing", &document("Title"), &cancel).is_err());
    assert!(compiled.item("article", &document("  "), &cancel).is_err());
    let mut private = document("Title");
    private.privacy_projection_version = None;
    assert!(compiled.item("article", &private, &cancel).is_err());
}

#[test]
fn replacements_do_not_inherit_authority_or_override_hard_denial() {
    let mut spec = recipe_spec();
    spec.start_requests.push(request("/start"));
    let mut blocked = DiscoveryRuleV1::new(RecipeSourceV1::Html, "article".into());
    blocked.deny.push("/blocked".into());
    spec.rules.push(blocked);
    spec.pipeline.extensions.push(ExtensionSpecV1::new(
        ExtensionConfigV1::ReplaceRequest {
            request: Box::new(request("/blocked")),
        },
        0,
    ));
    let compiled = CompiledExtensionRecipe::new(spec).unwrap();
    assert!(compiled.start_requests(&CancellationToken::new()).is_err());
    let mut spec = recipe_spec();
    let mut write = request("/write");
    write.method = "POST".into();
    spec.start_requests.push(write);
    assert!(CompiledExtensionRecipe::new(spec).is_err());
}

#[test]
fn immutable_pin_cancellation_and_candidate_limits_are_enforced() {
    let mut spec = recipe_spec();
    spec.max_candidates = 1;
    spec.rules
        .push(DiscoveryRuleV1::new(RecipeSourceV1::Html, "article".into()));
    let pin = spec.pin().unwrap();
    let compiled = CompiledExtensionRecipe::new(spec.clone()).unwrap();
    compiled.verify_pin(&pin).unwrap();
    spec.rules[0].allow.push("different".into());
    assert!(compiled.verify_pin(&spec.pin().unwrap()).is_err());
    assert!(compiled
        .html(
            "<a href='/a'>a</a><a href='/b'>b</a>",
            &url("/"),
            &CancellationToken::new()
        )
        .is_err());
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(compiled.html("<a href='/a'>a</a>", &url("/"), &cancel).is_err());
    assert!(compiled
        .sitemap(b"https://example.test/page", &url("/root.xml"), 0, &cancel)
        .is_err());
    assert!(compiled.start_requests(&cancel).is_err());
    assert!(compiled.item("article", &document("Title"), &cancel).is_err());
}

#[test]
fn invalid_selectors_keys_and_executable_input_are_rejected_before_actions() {
    let mut bad = recipe_spec();
    bad.actor_actions
        .push(ActorActionV1::Click { selector: "[".into() });
    assert!(CompiledExtensionRecipe::new(bad).is_err());
    let mut bad = recipe_spec();
    bad.actor_actions.push(ActorActionV1::Press {
        key: "not-a-native-key".into(),
    });
    assert!(CompiledExtensionRecipe::new(bad).is_err());
    let mut bad = recipe_spec();
    let mut rule = DiscoveryRuleV1::new(RecipeSourceV1::Html, "article".into());
    rule.allow.push("(?<=unsafe)lookbehind".into());
    bad.rules.push(rule);
    assert!(CompiledExtensionRecipe::new(bad).is_err());
    for action in [
        serde_json::json!({"type":"executeJavascript","script":"return window"}),
        serde_json::json!({"type":"click","selector":"a","callback":"code"}),
        serde_json::json!({"type":"fill","selector":"input","text":"x","handle":"raw"}),
    ] {
        assert!(serde_json::from_value::<ActorActionV1>(action).is_err());
    }
}

#[test]
fn hard_denials_apply_across_sources_and_output_bytes_reject_whole_batch() {
    let mut spec = recipe_spec();
    let html = DiscoveryRuleV1::new(RecipeSourceV1::Html, "article".into());
    let mut sitemap = DiscoveryRuleV1::new(RecipeSourceV1::Sitemap, "fallback".into());
    sitemap.deny.push("/private".into());
    spec.rules = vec![html, sitemap];
    let compiled = CompiledExtensionRecipe::new(spec.clone()).unwrap();
    assert!(compiled
        .html(
            "<a href='/private'>private</a>",
            &url("/"),
            &CancellationToken::new(),
        )
        .unwrap()
        .is_empty());
    spec.max_output_bytes = 2;
    let compiled = CompiledExtensionRecipe::new(spec).unwrap();
    assert!(compiled
        .html(
            "<a href='/public'>public</a>",
            &url("/"),
            &CancellationToken::new(),
        )
        .is_err());
}
