//! Native extraction import validation and authored, MIT-licensed local corpus.
//!
//! Conversion compiles static selectors before the caller can perform acquisition.
//! The embedded corpus is new project-authored text, not copied upstream articles.
//! Golden spans are labels, not measured extraction quality or benchmark results.
//!
//! `authored_fixture_manifests()` exports original article/news/feed licenses,
//! checksums, frozen dates and exact source gold spans. `pinned_profile_fixture_manifests()`
//! exports one deterministic declarative manifest per advertised source option/alias,
//! including authored rejected/external-required/decision-needed expectations.

use crawlx_core::{
    extraction_import::{
        inspect_manifest, parse_manifest, ExtractionDispositionV1, ExtractionImportError,
        ExtractionImportReportV1,
    },
    hash::Digest,
    CreateCrawl,
};
use serde::Serialize;

/// Inspect bounded declarative JSON and compile every mapped static selector.
///
/// Returned native requests use the existing `CreateCrawl` API. No filesystem,
/// model, external provider, Python runtime, or network is accessed.
///
/// # Errors
/// Returns typed strict JSON, source pin, manifest bounds, or lifecycle validation errors.
/// Invalid selectors remain typed rejected report entries and prevent conversion.
pub fn inspect(
    bytes: &[u8],
) -> Result<(ExtractionImportReportV1, Option<CreateCrawl>), ExtractionImportError> {
    let manifest = parse_manifest(bytes)?;
    let (mut report, mut request) = inspect_manifest(&manifest)?;
    if let Some(policy) = request
        .as_ref()
        .and_then(|request| request.extract.content.as_ref())
    {
        for (name, selectors) in [
            ("selectors.include", &policy.selectors.include),
            ("selectors.exclude", &policy.selectors.exclude),
            ("selectors.readMore", &policy.selectors.read_more),
        ] {
            for selector in selectors {
                if crate::xpath::CompiledSelector::compile(selector).is_err() {
                    report.dispositions.push(ExtractionDispositionV1::rejected(
                        name.to_owned(), "extract.content.selectors",
                        "static selector syntax, function, or budget is unsupported; conversion stops before acquisition",
                    ));
                    report.convertible = false;
                    report.options_digest = None;
                }
            }
        }
    }
    if !report.convertible {
        request = None;
    }
    Ok((report, request))
}
/// Convert only when every supplied setting has an executable native mapping.
///
/// # Errors
/// Returns strict parsing/validation errors or `Unavailable` for any unresolved request.
pub fn convert(bytes: &[u8]) -> Result<CreateCrawl, ExtractionImportError> {
    inspect(bytes)?.1.ok_or(ExtractionImportError::Unavailable)
}

/// Original article fixture, authored for crawlx under MIT; no third-party content.
pub const AUTHORED_ARTICLE_HTML: &str = "<!doctype html><html lang='en'><head><title>Library lantern project</title><meta name='author' content='Alex Example'><meta property='article:published_time' content='2026-11-01'></head><body><nav>Home | Notices</nav><article><h1>Library lantern project</h1><p>The neighborhood library opened its lantern workshop on Monday. Volunteers built twelve paper lanterns and placed them beside the reading room.</p><p>Visitors may join the next workshop without a ticket. The library will provide paper, string, and a quiet table for every participant.</p></article><section id='comments'><p>A reader asked whether the next workshop will include blue paper.</p></section><aside>Unrelated shop promotion</aside></body></html>";
/// Original news fixture, authored for crawlx under MIT; no third-party content.
pub const AUTHORED_NEWS_HTML: &str = "<!doctype html><html lang='en'><head><title>Footbridge inspection notice</title><meta property='article:published_time' content='2026-11-02'><meta name='author' content='Sam Example'><link rel='alternate' type='application/feed+json' href='/news/feed.json'></head><body><article><h1>Footbridge inspection notice</h1><p>The park footbridge will close for a routine inspection on Tuesday morning. Walkers can use the marked riverside path while the inspection team works.</p><p>The team expects to reopen the bridge before lunch. A notice at each entrance will show the current access route and the inspection contact.</p></article><aside>Subscribe for unrelated offers</aside></body></html>";
/// Original JSON Feed, authored for crawlx under MIT, resolving only reserved test URLs.
pub const AUTHORED_NEWS_FEED: &str = r#"{"version":"https://jsonfeed.org/version/1.1","title":"Authored fixture news","home_page_url":"https://fixture.test/news/","feed_url":"https://fixture.test/news/feed.json","items":[{"id":"inspection-notice","url":"https://fixture.test/news/bridge","title":"Footbridge inspection notice","date_published":"2026-11-02T09:00:00Z","content_text":"The park footbridge will close for a routine inspection on Tuesday morning."}]}"#;
/// Full license for original embedded corpus, not for upstream software or webpages.
pub const AUTHORED_FIXTURE_LICENSE: &str = "MIT License\n\nCopyright (c) 2026 crawlx contributors\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the Software), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n";
/// One authored labeled span. A label is not a measured successful extraction.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AuthoredGoldenSpanV1 {
    /// Main, comment, or excluded content role.
    pub role: &'static str,
    /// Verbatim original text expected in this content group.
    pub text: &'static str,
    /// Inclusive UTF-8 source offset in the authored HTML fixture.
    pub source_start: usize,
    /// Exclusive UTF-8 source offset, not normalized output coordinates.
    pub source_end: usize,
}
/// Reproducible licensed fixture metadata; no third-party content, model, or metric.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AuthoredFixtureManifestV1 {
    /// Manifest schema.
    pub version: u16,
    /// Stable authored corpus ID.
    pub id: &'static str,
    /// Deterministic reserved fixture URL; never downloaded by this module.
    pub source_url: &'static str,
    /// Original content provenance, not an upstream webpage claim.
    pub provenance: &'static str,
    /// Corpus redistribution license.
    pub license: &'static str,
    /// Full required MIT grant and notice.
    pub license_text: &'static str,
    /// Explicit frozen calendar reference; never current time.
    pub reference_date: &'static str,
    /// Domain-separated exact fixture byte checksum.
    pub content_digest: Digest,
    /// Exact UTF-8 fixture byte count.
    pub content_bytes: usize,
    /// Deterministic original gold source spans.
    pub gold_spans: Vec<AuthoredGoldenSpanV1>,
    /// No measurement has been performed; JSON null is deliberate.
    pub measured_f1: Option<f64>,
}
/// Enumerate original licensed article/news corpus and exact gold span metadata.
///
/// # Errors
/// Returns a typed manifest error if an authored gold label is absent or overflows.
pub fn authored_fixture_manifests() -> Result<Vec<AuthoredFixtureManifestV1>, ExtractionImportError> {
    type FixtureCase<'a> = (&'a str, &'a str, &'a str, &'a [(&'a str, &'a str)]);
    let cases: &[FixtureCase<'_>] = &[
        (
            "authored-library-article-v1",
            "https://fixture.test/article",
            AUTHORED_ARTICLE_HTML,
            &[
                (
                    "main",
                    "The neighborhood library opened its lantern workshop on Monday. Volunteers built twelve paper lanterns and placed them beside the reading room.",
                ),
                (
                    "main",
                    "Visitors may join the next workshop without a ticket. The library will provide paper, string, and a quiet table for every participant.",
                ),
                (
                    "comment",
                    "A reader asked whether the next workshop will include blue paper.",
                ),
                ("excluded", "Unrelated shop promotion"),
            ],
        ),
        (
            "authored-bridge-news-v1",
            "https://fixture.test/news/bridge",
            AUTHORED_NEWS_HTML,
            &[
                (
                    "main",
                    "The park footbridge will close for a routine inspection on Tuesday morning. Walkers can use the marked riverside path while the inspection team works.",
                ),
                (
                    "main",
                    "The team expects to reopen the bridge before lunch. A notice at each entrance will show the current access route and the inspection contact.",
                ),
                ("excluded", "Subscribe for unrelated offers"),
            ],
        ),
        (
            "authored-news-feed-v1",
            "https://fixture.test/news/feed.json",
            AUTHORED_NEWS_FEED,
            &[
                (
                    "main",
                    "The park footbridge will close for a routine inspection on Tuesday morning.",
                ),
                ("discovery", "https://fixture.test/news/bridge"),
                ("title", "Footbridge inspection notice"),
            ],
        ),
    ];
    cases
        .iter()
        .map(|&(id, source_url, html, labels)| {
            let gold_spans = labels
                .iter()
                .map(|&(role, text)| {
                    let start = html.find(text).ok_or(ExtractionImportError::Manifest(
                        "authored gold span absent from original source",
                    ))?;
                    let end = start
                        .checked_add(text.len())
                        .ok_or(ExtractionImportError::Manifest(
                            "authored gold span offset overflow",
                        ))?;
                    Ok(AuthoredGoldenSpanV1 {
                        role,
                        text,
                        source_start: start,
                        source_end: end,
                    })
                })
                .collect::<Result<Vec<_>, ExtractionImportError>>()?;
            Ok(AuthoredFixtureManifestV1 {
                version: 1,
                id,
                source_url,
                provenance: "original crawlx-authored synthetic text; no third-party article content",
                license: "MIT",
                license_text: AUTHORED_FIXTURE_LICENSE,
                reference_date: "2026-11-04",
                content_digest: Digest::of("crawlx.authored-extraction-fixture.v1", html.as_bytes()),
                content_bytes: html.len(),
                gold_spans,
                measured_f1: None,
            })
        })
        .collect()
}
/// One original, licensed source-profile fixture with an authored expected disposition.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PinnedProfileFixtureV1 {
    /// Exact option/alias exercised in this fixture.
    pub option: &'static str,
    /// Exact release, never latest.
    pub source_release: &'static str,
    /// License of the original declarative fixture itself.
    pub fixture_license: &'static str,
    /// Complete grant for the authored fixture.
    pub fixture_license_text: &'static str,
    /// Source package license, independent of the authored fixture.
    pub source_license: &'static str,
    /// Executable JSON manifest input for the actual source-import dispatcher.
    pub manifest: serde_json::Value,
    /// Authored expected state of the supplied option; not a measured result.
    pub expected_option_state: crawlx_core::extraction_import::ImportStateV1,
}
/// Enumerate deterministic manifests exercising every advertised pinned option and alias.
///
/// These fixtures contain only original data and reserved `.test` URLs. Unavailable
/// modes deliberately expect typed rejection/external-required/decision-needed,
/// rather than asserting upstream feature equivalence.
#[must_use]
pub fn pinned_profile_fixture_manifests() -> Vec<PinnedProfileFixtureV1> {
    use crawlx_core::extraction_import::{
        option_catalog, ExtractionDialectV1 as Dialect, ExtractionSourceV1 as Source, ImportStateV1 as State,
    };
    use serde_json::json;
    let mut fixtures = Vec::new();
    for source in [Source::PrecisionText, Source::NewsArticle, Source::SurfaceFlags] {
        for dialect in [Dialect::Library, Dialect::Cli, Dialect::Settings] {
            if source == Source::SurfaceFlags && dialect != Dialect::Cli {
                continue;
            }
            for &(option, category) in option_catalog(source, dialect) {
                let value = match category {
                    "url" => json!("https://fixture.test/article"),
                    "timeout" => json!(7),
                    "delay" => json!(2),
                    "max_file_size" => json!(20_000_000),
                    "depth" | "threads" | "max_domain_pages" => json!(2),
                    "retry" => json!(1),
                    "global_rps" | "global_rpm" | "host_rps" | "host_rpm" => json!(10),
                    "max_text" => json!(100_000),
                    "max_summary" => json!(5000),
                    "max_summary_sent" => json!(5),
                    "max_keywords" => json!(10),
                    "language" => json!("en"),
                    "user_agent" => json!("crawlx-authored-fixture/1"),
                    "prune_xpath" => json!("//aside"),
                    "read_more_link" => json!("//a[@rel='next']"),
                    "author_blacklist" => json!(["Alex Example"]),
                    "strategy" => json!("breadth-first"),
                    "output_format" => json!(if source == Source::NewsArticle {
                        "json"
                    } else {
                        "markdown"
                    }),
                    "fetch_images" | "private_hosts" | "insecure_ssl" | "external_urls" => json!(false),
                    "proxy" | "credentials" | "recorded_flow" => json!("env://AUTHORED_FIXTURE_REFERENCE"),
                    "headers" | "cookies" => json!({"authored_fixture": "never_echo_this_value"}),
                    "requests_params" => json!({"timeout": 7}),
                    "top_image_settings" => {
                        json!({"min_width":300,"min_height":200,"min_area":10_000,"max_retries":2})
                    }
                    "date_params" => json!({"max_date":"2026-11-04"}),
                    _ => json!(true),
                };
                let state = match category {
                    "proxy" | "cookies" | "headers" | "credentials" | "recorded_flow" => State::Rejected,
                    "solver" | "news_search" | "trends" | "archived" | "sentence_tokenizer" => {
                        State::ExternalRequired
                    }
                    "unavailable" | "requests_params" | "top_image_settings" | "date_params" => {
                        State::DecisionNeeded
                    }
                    "source_mode" if source != Source::PrecisionText => State::Rejected,
                    "output_format" if source == Source::NewsArticle => State::Rejected,
                    _ => State::Translated,
                };
                let seed_key = match (source, dialect) {
                    (Source::PrecisionText, Dialect::Cli) => "URL",
                    (Source::SurfaceFlags, Dialect::Cli) => "u",
                    _ => "url",
                };
                let mut options = serde_json::Map::new();
                if category != "url" {
                    options.insert(seed_key.into(), json!("https://fixture.test/article"));
                }
                options.insert(option.into(), value);
                fixtures.push(PinnedProfileFixtureV1 { option, source_release: source.release(),
                    fixture_license: "MIT", fixture_license_text: AUTHORED_FIXTURE_LICENSE, source_license: source.license(),
                    manifest: json!({"version":1,"source":source,"sourceVersion":source.release(),"dialect":dialect,"options":options}),
                    expected_option_state: state });
            }
        }
    }
    fixtures
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::extraction_import::{ExtractionDialectV1, ExtractionSourceV1, ImportStateV1};
    use serde_json::json;

    fn profile(source: ExtractionSourceV1, dialect: ExtractionDialectV1, options: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"version":1,"source":source,"sourceVersion":source.release(),"dialect":dialect,"options":options})).unwrap()
    }
    use serde_json::Value;
    #[test]
    fn converted_request_reaches_real_shared_native_extractor_on_authored_fixture() {
        let bytes = profile(
            ExtractionSourceV1::PrecisionText,
            ExtractionDialectV1::Library,
            json!({"url":"https://fixture.test/article","include_comments":true,"include_tables":false,"include_images":false,"fast":true,"prune_xpath":"//aside","author_blacklist":["alex example"]}),
        );
        let request = convert(&bytes).unwrap();
        let policy = request.extract.content.as_ref().unwrap();
        let document = crate::Extractor::extract(
            AUTHORED_ARTICLE_HTML,
            &request.seed_url,
            &crate::ExtractOptions {
                content: Some(policy.clone()),
                ..crate::ExtractOptions::default()
            },
        )
        .unwrap();
        assert!(document
            .text
            .contains("The neighborhood library opened its lantern workshop"));
        assert!(!document.text.contains("Unrelated shop promotion"));
        assert!(!document.text.contains("A reader asked"));
        assert!(document.comments.contains("A reader asked"));
        let article = document.article.as_ref().unwrap();
        assert_eq!(
            article.quality.status,
            crawlx_core::extraction::QualityStatusV1::Rejected
        );
        assert_eq!(
            article.quality.reasons,
            vec![crawlx_core::extraction::QualityReasonV1::AuthorExcluded]
        );
        assert_eq!(
            article.metadata.authors.value.as_ref().unwrap(),
            &["Alex Example"]
        );
    }
    #[test]
    fn malformed_and_external_xpath_fails_before_any_input_or_provider_io() {
        for expression in [
            "//article[",
            "document('file:///etc/passwd')",
            "//article[matches(., 'x')]",
        ] {
            let bytes = profile(
                ExtractionSourceV1::PrecisionText,
                ExtractionDialectV1::Library,
                json!({"url":"https://fixture.test/article","prune_xpath":expression}),
            );
            let (report, request) = inspect(&bytes).unwrap();
            assert!(!report.convertible);
            assert!(request.is_none());
            assert!(
                report
                    .dispositions
                    .iter()
                    .any(|d| d.target == Some("extract.content.selectors")
                        && d.state == ImportStateV1::Rejected)
            );
        }
    }
    #[test]
    fn authored_manifest_spans_checksums_and_rights_are_exact_without_measured_f1() {
        let manifests = authored_fixture_manifests().unwrap();
        assert_eq!(manifests.len(), 3);
        for (manifest, html) in
            manifests
                .iter()
                .zip([AUTHORED_ARTICLE_HTML, AUTHORED_NEWS_HTML, AUTHORED_NEWS_FEED])
        {
            assert_eq!(manifest.content_bytes, html.len());
            assert_eq!(
                manifest.content_digest,
                Digest::of("crawlx.authored-extraction-fixture.v1", html.as_bytes())
            );
            assert!(manifest.measured_f1.is_none());
            assert_eq!(manifest.license, "MIT");
            assert!(manifest.license_text.contains("Permission is hereby granted"));
            assert!(manifest.gold_spans.len() >= 3);
            for span in &manifest.gold_spans {
                assert_eq!(&html[span.source_start..span.source_end], span.text);
            }
        }
        let feed: Value = serde_json::from_str(AUTHORED_NEWS_FEED).unwrap();
        assert_eq!(feed["items"][0]["url"], "https://fixture.test/news/bridge");
    }
    #[test]
    fn every_pinned_catalog_option_and_mode_has_a_local_manifest_case() {
        let fixtures = pinned_profile_fixture_manifests();
        assert!(fixtures.len() > 300);
        for fixture in fixtures {
            let (report, request) = inspect(&serde_json::to_vec(&fixture.manifest).unwrap()).unwrap();
            assert_eq!(report.source_version, fixture.source_release);
            assert_eq!(fixture.fixture_license, "MIT");
            let option = report
                .dispositions
                .iter()
                .find(|d| d.id == fixture.option && d.requested)
                .unwrap();
            assert_eq!(option.state, fixture.expected_option_state, "{}", fixture.option);
            assert_eq!(request.is_some(), report.convertible);
        }
    }
    #[test]
    fn output_formats_never_fall_back_silently_or_expand_into_filesystem_sinks() {
        for format in ["json", "text", "csv", "xml", "xmltei", "pickle"] {
            let bytes = profile(
                ExtractionSourceV1::PrecisionText,
                ExtractionDialectV1::Library,
                json!({"url":"https://fixture.test/article","output_format":format}),
            );
            assert!(matches!(convert(&bytes), Err(ExtractionImportError::Unavailable)));
        }
        let bytes = profile(
            ExtractionSourceV1::PrecisionText,
            ExtractionDialectV1::Library,
            json!({"url":"https://fixture.test/article","output_format":"html"}),
        );
        assert_eq!(
            convert(&bytes).unwrap().output.formats,
            vec![crawlx_core::config::OutputFormat::Html]
        );
    }
}
