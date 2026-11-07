//! Authored MIT gold corpus. No upstream pages, algorithms, models or sockets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::extraction::*;
use crawlx_extract::{
    serialize::{write_article, ArticleFormat},
    Document, ExtractOptions, Extractor,
};
use serde_json::Value;
use url::Url;

const GOLD: &str = include_str!("../../crawlx-bench/fixtures/ext-article/gold.json");
fn fixture(name: &str) -> &'static str {
    match name {
        "main" => include_str!("../../crawlx-bench/fixtures/ext-article/main.html"),
        "chrome" => include_str!("../../crawlx-bench/fixtures/ext-article/chrome.html"),
        "siblings" => include_str!("../../crawlx-bench/fixtures/ext-article/siblings.html"),
        "malformed" => include_str!("../../crawlx-bench/fixtures/ext-article/malformed.html"),
        "forum" => include_str!("../../crawlx-bench/fixtures/ext-article/forum.html"),
        "comments" => include_str!("../../crawlx-bench/fixtures/ext-article/comments.html"),
        "metadata" => include_str!("../../crawlx-bench/fixtures/ext-article/metadata.html"),
        "unicode" => include_str!("../../crawlx-bench/fixtures/ext-article/unicode.html"),
        _ => panic!("unknown authored fixture"),
    }
}
fn extract(source: &str, policy: ExtractionPolicyV1) -> Document {
    Extractor::extract(
        source,
        &Url::parse("https://fixture.test/2026/11/01/story").unwrap(),
        &ExtractOptions {
            content: Some(policy),
            ..ExtractOptions::default()
        },
    )
    .unwrap()
}
fn policy() -> ExtractionPolicyV1 {
    let mut policy = ExtractionPolicyV1::default();
    policy.comments = CommentPolicyV1::Separate;
    policy.reference_date = Some("2026-11-04".parse().unwrap());
    policy
}
#[test]
fn authored_gold_spans_main_chrome_siblings_malformed_and_comments_are_exact() {
    let gold: Value = serde_json::from_str(GOLD).unwrap();
    assert_eq!(gold["license"], "MIT");
    for entry in gold["fixtures"].as_array().unwrap() {
        let id = entry["id"].as_str().unwrap();
        let html = fixture(id);
        // Verify gold annotations name real source characters, not expected-output echoes.
        let source: Vec<char> = html.chars().collect();
        for key in ["mainSourceScalarSpans", "commentSourceScalarSpans"] {
            for span in entry[key].as_array().unwrap() {
                let start = usize::try_from(span["start"].as_u64().unwrap()).unwrap();
                let end = usize::try_from(span["end"].as_u64().unwrap()).unwrap();
                assert_eq!(
                    source[start..end].iter().collect::<String>(),
                    span["text"].as_str().unwrap(),
                    "{id}"
                );
            }
        }
        let doc = extract(html, policy());
        assert_eq!(doc.text, entry["goldMain"].as_str().unwrap(), "main {id}");
        assert_eq!(
            doc.comments,
            entry["goldComments"].as_str().unwrap(),
            "comments {id}"
        );
        let envelope = doc.article.as_ref().unwrap();
        let mut main_end = 0;
        let mut comment_end = 0;
        for block in &envelope.blocks {
            let (text, previous) = if block.comment {
                (&doc.comments, &mut comment_end)
            } else {
                (&doc.text, &mut main_end)
            };
            let range = block.source.as_ref().unwrap();
            assert!(range.start >= *previous);
            assert!(text.get(range.start..range.end).is_some());
            *previous = range.end;
        }
        assert_eq!(envelope.quality.status, QualityStatusV1::Accepted, "{id}");
    }
}
#[test]
fn article_objects_win_without_website_author_and_preserve_date_conflicts() {
    let doc = extract(fixture("metadata"), policy());
    let metadata = &doc.article.unwrap().metadata;
    assert_eq!(metadata.title.value.as_deref(), Some("Harbor opens"));
    assert_eq!(metadata.authors.value.as_ref().unwrap(), &["Ada Vale", "M. Chen"]);
    assert!(metadata.authors.evidence.iter().any(|e| e.raw == "Other Writer"));
    assert!(!metadata.authors.evidence.iter().any(|e| e.raw == "Website Owner"));
    assert_eq!(
        metadata.published.value.as_ref().unwrap().date.to_string(),
        "2026-11-02"
    );
    assert_eq!(
        metadata.modified.value.as_ref().unwrap().date.to_string(),
        "2026-11-03"
    );
    assert!(metadata.published.uncertain);
    assert!(metadata.published.evidence.iter().any(|e| e.raw == "03/04/2026"));
    assert_eq!(metadata.language.value.as_deref(), Some("en-gb"));
    assert_eq!(metadata.declared_keywords, ["harbor", "local"]);
}
#[test]
fn ambiguous_numeric_dates_need_locale_and_future_dates_use_only_pinned_reference() {
    let html = "<main><p>The council has approved the bridge repairs, and work can begin after the survey.</p><time datetime='03/04/2026'>03/04/2026</time></main>";
    let base = Url::parse("https://fixture.test/story").unwrap();
    let run = |p: ExtractionPolicyV1| {
        Extractor::extract(
            html,
            &base,
            &ExtractOptions {
                content: Some(p),
                ..ExtractOptions::default()
            },
        )
        .unwrap()
        .article
        .unwrap()
    };
    assert!(run(policy()).metadata.published.value.is_none());
    let mut us = policy();
    us.locale = Some("en-US".into());
    assert_eq!(
        run(us).metadata.published.value.unwrap().date.to_string(),
        "2026-03-04"
    );
    let mut gb = policy();
    gb.locale = Some("en-GB".into());
    assert_eq!(
        run(gb).metadata.published.value.unwrap().date.to_string(),
        "2026-04-03"
    );
    let future = extract(
        "<meta property='article:published_time' content='2027-01-01'><main><p>The report describes a future event, but its publication time must remain unknown today.</p></main>",
        policy(),
    );
    // URL calendar hints may remain; the rejected future source is retained as uncertainty.
    let date = &future.article.as_ref().unwrap().metadata.published;
    assert!(date.evidence.iter().any(|e| e.raw == "2027-01-01"));
    assert!(date
        .value
        .as_ref()
        .is_none_or(|d| d.date.to_string() != "2027-01-01"));
    assert!(date.uncertain);
}
#[test]
fn unicode_summary_uses_exact_source_slices_and_keyword_ties_use_first_occurrence() {
    let doc = extract(fixture("unicode"), policy());
    let envelope = doc.article.as_ref().unwrap();
    assert!(
        envelope.metadata.language.value.is_none(),
        "unknown must not become English"
    );
    assert!(!envelope.metadata.summary.is_empty());
    let mut end = 0;
    for range in &envelope.metadata.summary {
        assert!(range.start >= end);
        assert!(doc
            .text
            .get(range.start..range.end)
            .is_some_and(|s| !s.is_empty()));
        end = range.end;
    }
    assert_eq!(envelope.metadata.keywords[0].token, "éclair");
    assert_eq!(envelope.metadata.keywords[1].token, "zebra");
    assert_eq!(envelope.metadata.keywords[0].score, 2);
    assert_eq!(envelope.metadata.keywords[1].score, 2);
    let repeated = extract(fixture("unicode"), policy());
    assert_eq!(
        serde_json::to_vec(&doc).unwrap(),
        serde_json::to_vec(&repeated).unwrap()
    );
}
#[test]
fn precision_recall_and_literal_fallback_change_real_selected_text() {
    let source = "<body><div>Short tail with facts.</div><p>The field team has finished a careful survey of the wetland, and the report explains every important change in the nesting grounds.</p></body>";
    let mut precision = policy();
    precision.algorithm = ArticleAlgorithmV1::ArticleRulesV1;
    precision.focus = ContentFocusV1::Precision;
    precision.fallback = ContentFallbackV1::None;
    let mut recall = precision.clone();
    recall.focus = ContentFocusV1::Recall;
    assert!(!extract(source, precision).text.contains("Short tail"));
    assert!(extract(source, recall).text.contains("Short tail"));
    let mut none = policy();
    none.algorithm = ArticleAlgorithmV1::ArticleRulesV1;
    none.fallback = ContentFallbackV1::None;
    let no = extract("<div>Brief note</div>", none.clone());
    assert!(no.text.is_empty());
    assert_eq!(no.article.unwrap().fallback_stages, 0);
    none.fallback = ContentFallbackV1::Bounded;
    let rescued = extract("<div>Brief note</div>", none);
    assert_eq!(rescued.text, "Brief note");
    assert_eq!(rescued.article.unwrap().fallback_stages, 1);
}
#[test]
fn quality_rejection_partial_and_missing_model_are_not_transport_failures() {
    let mut strict = policy();
    strict.min_main_chars = 10_000;
    strict.required_metadata = vec![RequiredMetadataV1::PublishedDate];
    let doc = extract(
        "<main><p>A short authored notice is still a real acquired document, not a transport failure.</p></main>",
        strict,
    );
    let quality = &doc.article.unwrap().quality;
    assert_eq!(quality.status, QualityStatusV1::Rejected);
    assert!(quality.reasons.contains(&QualityReasonV1::TooShort));
    // The explicit fixture URL supplies a calendar hint. Use a no-date URL for required-date rejection.
    let mut required = policy();
    required.required_metadata = vec![RequiredMetadataV1::PublishedDate];
    let doc = Extractor::extract("<main><p>A short notice has no publication evidence, so a required date must be reported missing.</p></main>",
        &Url::parse("https://fixture.test/no-date").unwrap(), &ExtractOptions { content: Some(required), ..ExtractOptions::default() }).unwrap();
    assert!(doc
        .article
        .unwrap()
        .quality
        .reasons
        .contains(&QualityReasonV1::MissingRequiredMetadata));
    let mut capped = policy();
    capped.max_operations = 1;
    let partial = extract(fixture("main"), capped);
    assert_eq!(partial.article.unwrap().quality.status, QualityStatusV1::Partial);
    let mut model = policy();
    model.nlp = NlpCapabilityV1::PunktModel;
    let unavailable = extract(fixture("main"), model);
    let article = unavailable.article.unwrap();
    assert_eq!(article.quality.status, QualityStatusV1::Unavailable);
    assert!(article.metadata.summary.is_empty());
    assert!(article
        .quality
        .reasons
        .contains(&QualityReasonV1::ModelUnavailable));
}
#[test]
fn author_exclusion_rejects_coauthors_and_conflicts_without_erasing_acquired_content() {
    let source = r#"<html><head><meta name="author" content="Other Writer">
      <script type="application/ld+json">{"@type":"NewsArticle","author":[{"name":"Émilie Durand"},{"name":"Alex Example"}]}</script>
      </head><body><article><p>Original reporting explains the verified findings and preserves source evidence for independent audit.</p></article></body></html>"#;
    let baseline = extract(source, policy());
    for name in ["  ÉMILIE\u{2003}DURAND ", "alex example", "other writer"] {
        let mut excluded = policy();
        excluded.excluded_authors = vec![name.into()];
        let blocked = extract(source, excluded);
        let article = blocked.article.as_ref().unwrap();
        assert_eq!(article.quality.status, QualityStatusV1::Rejected);
        assert_eq!(article.quality.reasons, vec![QualityReasonV1::AuthorExcluded]);
        assert_eq!(blocked.text, baseline.text);
        assert_eq!(
            article.metadata.authors,
            baseline.article.as_ref().unwrap().metadata.authors
        );
    }
    for name in ["Émilie", "Alex Examples", "ÉmilieDurand"] {
        let mut allowed = policy();
        allowed.excluded_authors = vec![name.into()];
        assert_eq!(
            extract(source, allowed).article.unwrap().quality.status,
            QualityStatusV1::Accepted
        );
    }
}

#[test]
fn structural_link_and_formatting_controls_preserve_canonical_text_and_discovery() {
    let source = r#"<article><p>Careful reporting preserves every original word while controlling how the selected article is rendered:
      <a href="/target"><strong>bold link</strong></a>, <em>emphasis</em>,
      <code>inline_code</code>, <s>old text</s>, <q>quoted text</q>, and x<sup>2</sup>.</p>
      <table><tr><td>Cell one</td><td>Cell two</td></tr></table><img src="/photo" alt="Photo">
      <pre>block_code</pre></article>"#;
    let render = |links, formatting| {
        let mut selected = policy();
        selected.links = links;
        selected.formatting = formatting;
        Extractor::extract(
            source,
            &Url::parse("https://fixture.test/story").unwrap(),
            &ExtractOptions {
                content: Some(selected),
                only_main_content: false,
                ..ExtractOptions::default()
            },
        )
        .unwrap()
    };
    let baseline = render(true, true);
    for (links, formatting) in [(true, true), (true, false), (false, true), (false, false)] {
        let output = render(links, formatting);
        assert_eq!(output.text, baseline.text);
        assert_eq!(output.links, baseline.links);
        let article = output.article.as_ref().unwrap();
        assert_eq!(
            article.main_digest,
            baseline.article.as_ref().unwrap().main_digest
        );
        assert_eq!(article.blocks, baseline.article.as_ref().unwrap().blocks);
        assert_eq!(output.html.contains("<a href="), links);
        assert_eq!(output.markdown.contains("](https://fixture.test/target)"), links);
        assert_eq!(output.html.contains("<strong>"), formatting);
        assert_eq!(output.html.contains("<code>"), formatting);
        assert_eq!(output.markdown.contains("**bold link**"), formatting);
        assert_eq!(output.markdown.contains("`inline_code`"), formatting);
        assert!(output.html.contains("<table>"));
        assert!(output.html.contains("<img src="));
        assert!(output.html.contains("<pre>block_code</pre>"));
    }
}

#[test]
fn media_readmore_are_unresolved_bounded_intents_and_legacy_remains_opt_out() {
    let html = "<html><head><meta property='og:image' content='http://127.0.0.1/private'></head><body><main><p>The article describes a local service, but the parser must never contact that service itself.</p><img src='http://169.254.169.254/secret'><a rel='next' href='/more'>Read more</a></main></body></html>";
    let doc = extract(html, policy());
    let intents = &doc.article.as_ref().unwrap().discovery;
    assert_eq!(intents.len(), 3);
    assert!(intents
        .iter()
        .any(|i| i.purpose == DiscoveryPurposeV1::ReadMoreReference));
    assert!(
        doc.validation.is_none(),
        "HTML cannot invent a successful target response"
    );
    let legacy = Extractor::extract(
        html,
        &Url::parse("https://fixture.test/").unwrap(),
        &ExtractOptions::default(),
    )
    .unwrap();
    assert!(legacy.article.is_none() && legacy.comments.is_empty());
}
#[test]
fn serializers_escape_xml_and_neutralize_csv_formulas_without_rewriting_source_text() {
    let doc = extract(
        "<title>=SUM(1,2)</title><main><p>The source contains &lt;tag&gt; &amp; quoted data, and every output must preserve its meaning.</p></main>",
        policy(),
    );
    let mut csv = Vec::new();
    write_article(&mut csv, &doc, ArticleFormat::Csv).unwrap();
    assert!(String::from_utf8(csv).unwrap().contains("\"'=SUM(1,2)\""));
    let mut xml = Vec::new();
    write_article(&mut xml, &doc, ArticleFormat::Tei).unwrap();
    let xml = String::from_utf8(xml).unwrap();
    assert!(xml.contains("&lt;tag&gt; &amp;"));
    assert!(!xml.contains("<!DOCTYPE"));
    assert!(xml.contains("xmlns=\"http://www.tei-c.org/ns/1.0\""));
    assert!(doc.text.contains("<tag> &"));
}

#[test]
fn whole_filtered_body_keeps_direct_text_and_chrome_while_native_comments_stay_separate() {
    let source = "<body>Direct introduction<nav>Navigation text</nav><article><p>The report has enough detail to explain the bridge repairs and the new crossing schedule.</p></article>Direct ending<section id='comments'><p>The reader asks whether the bridge will remain open during the next inspection.</p></section></body>";
    let doc = Extractor::extract(
        source,
        &Url::parse("https://fixture.test/story").unwrap(),
        &ExtractOptions {
            only_main_content: false,
            content: Some(policy()),
            ..ExtractOptions::default()
        },
    )
    .unwrap();
    assert!(doc.text.contains("Direct introduction") && doc.text.contains("Navigation text"));
    assert!(doc.text.contains("Direct ending"));
    assert!(!doc.text.contains("The reader asks"));
    assert!(doc.comments.contains("The reader asks"));
    assert_eq!(doc.article.unwrap().fallback_stages, 0);
}

#[test]
fn compiled_projection_finalizes_nlp_quality_digest_and_unknown_block_mapping() {
    let secret = "article_secret_Q7v9N4x2";
    let source = "<main><p>The report contains <span>article_secret_</span><span>Q7v9N4x2</span>, and the bridge remains open for the town today.</p></main>";
    let mut content = policy();
    let mut chunks = WordChunkPolicyV1::default();
    chunks.strategy = WordChunkStrategyV1::Sliding { window: 5, step: 3 };
    content.chunks = Some(chunks);
    let options = ExtractOptions {
        content: Some(content),
        ..ExtractOptions::default()
    };
    let doc = Extractor::extract_bytes_with_projection(
        source.as_bytes(),
        &Url::parse("https://fixture.test/story").unwrap(),
        &options,
        &|value| {
            value
                .contains(secret)
                .then(|| value.replace(secret, "[REDACTED]"))
        },
    )
    .unwrap();
    let envelope = doc.article.as_ref().unwrap();
    let chunks = envelope.chunks.as_ref().unwrap();
    chunks.validate(&doc.text, &chunks.policy).unwrap();
    assert!(chunks.ranges.len() > 1);
    assert!(!doc.text.contains(secret));
    assert!(!doc.html.contains("article_secret_"));
    assert_eq!(
        envelope.main_digest,
        crawlx_core::hash::Digest::of("crawlx.extract.main.unicode_rules_v1", doc.text.as_bytes())
    );
    assert_eq!(envelope.quality.main_chars, doc.text.chars().count());
    assert!(envelope.source_mapping_redacted);
    assert!(envelope.blocks.iter().all(|block| block.source.is_none()));
    assert!(envelope
        .metadata
        .summary
        .iter()
        .all(|range| doc.text.get(range.start..range.end).is_some()));
    for format in [ArticleFormat::Json, ArticleFormat::Jsonl] {
        let mut output = Vec::new();
        write_article(&mut output, &doc, format).unwrap();
        let value: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["article"]["chunks"], serde_json::to_value(chunks).unwrap());
        assert!(!String::from_utf8(output).unwrap().contains(secret));
    }
}

#[test]
fn authored_locale_dates_and_dictionary_tokens_reach_actual_article_nlp() {
    let fixtures: Value = serde_json::from_str(include_str!("fixtures/article_locales.json")).unwrap();
    assert_eq!(fixtures["license"], "MIT");
    for case in fixtures["dates"].as_array().unwrap() {
        let html = format!(
            "<meta property='article:published_time' content='{}'><main><p>The orchard report records a careful count of each new tree planted beside the village river.</p></main>",
            case["raw"].as_str().unwrap()
        );
        let mut p = policy();
        p.locale = Some(case["locale"].as_str().unwrap().into());
        let doc = extract(&html, p);
        let article = doc.article.unwrap();
        assert_eq!(
            article.metadata.published.value.unwrap().date.to_string(),
            case["gold"].as_str().unwrap()
        );
    }
    for case in fixtures["tokens"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let html = format!("<main><p>{text}</p></main>");
        let mut p = policy();
        p.min_main_chars = 1;
        p.tokenizer = ArticleTokenizerV1::IcuDictionaryUax29V17V1;
        let first = extract(&html, p.clone());
        let second = extract(&html, p);
        assert_eq!(first.article, second.article);
        let article = first.article.unwrap();
        assert_eq!(
            article.metadata.tokenizer_version.as_deref(),
            Some("icu_dictionary_uax29_v17_v1")
        );
        let expected = case["gold"].as_array().unwrap();
        assert_eq!(article.metadata.keywords.len(), expected.len());
        for (keyword, gold) in article.metadata.keywords.iter().zip(expected) {
            assert_eq!(keyword.token, gold["token"].as_str().unwrap());
            assert_eq!(
                keyword.source.start,
                usize::try_from(gold["start"].as_u64().unwrap()).unwrap()
            );
            assert_eq!(
                keyword.source.end,
                usize::try_from(gold["end"].as_u64().unwrap()).unwrap()
            );
            assert_eq!(
                first.text[keyword.source.start..keyword.source.end].to_lowercase(),
                keyword.token
            );
        }
        for range in article.metadata.summary {
            assert!(first.text.get(range.start..range.end).is_some());
        }
    }
}

#[test]
fn prior_article_metadata_json_remains_readable_without_detector_fields() {
    let mut legacy = serde_json::to_value(ArticleMetadataV1::default()).unwrap();
    for key in [
        "declaredLanguage",
        "detectedLanguage",
        "languageModelDigest",
        "languageModelUnavailable",
        "tokenizerVersion",
        "tokenizerUnavailable",
    ] {
        legacy.as_object_mut().unwrap().remove(key);
    }
    let decoded: ArticleMetadataV1 = serde_json::from_value(legacy).unwrap();
    assert!(!decoded.language_model_unavailable);
    assert!(decoded.detected_language.value.is_none());
    assert!(!decoded.tokenizer_unavailable);
}

#[test]
fn unicode_sentence_marks_keep_exact_final_source_slices() {
    let text = "गाँव की नदी के पास बच्चे पुस्तक पढ़ते हैं। هل قرأ الأطفال الكتب عن الطيور؟ 川の近くで子どもたちは本を読みました。";
    let mut p = policy();
    p.tokenizer = ArticleTokenizerV1::IcuDictionaryUax29V17V1;
    p.summary_sentences = 8;
    p.summary_max_chars = 4096;
    let doc = extract(&format!("<main><p>{text}</p></main>"), p);
    let article = doc.article.unwrap();
    let slices: Vec<_> = article
        .metadata
        .summary
        .iter()
        .map(|range| &doc.text[range.start..range.end])
        .collect();
    assert_eq!(
        slices,
        [
            "गाँव की नदी के पास बच्चे पुस्तक पढ़ते हैं।",
            "هل قرأ الأطفال الكتب عن الطيور؟",
            "川の近くで子どもたちは本を読みました。",
        ]
    );
}

#[test]
fn native_word_chunks_preformatted_renditions_keep_internal_whitespace_and_refuse_stale_text() {
    let mut content = policy();
    let mut chunks = WordChunkPolicyV1::default();
    chunks.strategy = WordChunkStrategyV1::Fixed { window: 2 };
    content.chunks = Some(chunks);
    let mut doc = extract("<main><pre>α\tbeta\n   中🙂 delta\n tail</pre></main>", content);
    assert!(doc.text.contains("α\tbeta\n   中🙂 delta\n tail"));
    let ranges = &doc.article.as_ref().unwrap().chunks.as_ref().unwrap().ranges;
    let parts: Vec<_> = ranges
        .iter()
        .map(|range| &doc.text[range.start..range.end])
        .collect();
    assert_eq!(parts, ["α\tbeta", "中🙂 delta", "tail"]);
    for format in [
        ArticleFormat::Text,
        ArticleFormat::Markdown,
        ArticleFormat::Html,
        ArticleFormat::Csv,
        ArticleFormat::Xml,
        ArticleFormat::Tei,
    ] {
        let mut output = Vec::new();
        write_article(&mut output, &doc, format).unwrap();
        assert!(!String::from_utf8(output).unwrap().contains("finalTextDigest"));
    }
    doc.text.truncate("α".len());
    for format in [ArticleFormat::Json, ArticleFormat::Jsonl, ArticleFormat::Text] {
        let mut output = Vec::new();
        assert!(matches!(
            write_article(&mut output, &doc, format),
            Err(crawlx_extract::serialize::ArticleWriteError::WordChunks(_))
        ));
        assert!(output.is_empty());
    }
}

#[test]
fn native_word_chunks_actual_extractor_refuses_one_over_result_limit() {
    let mut content = policy();
    let mut chunks = WordChunkPolicyV1::default();
    chunks.strategy = WordChunkStrategyV1::Fixed { window: 1 };
    chunks.max_ranges = 1;
    content.chunks = Some(chunks);
    assert!(matches!(
        Extractor::extract(
            "<main><p>first second</p></main>",
            &Url::parse("https://fixture.test/").unwrap(),
            &ExtractOptions {
                content: Some(content),
                ..Default::default()
            },
        ),
        Err(crawlx_extract::ExtractError::WordChunks(WordChunkErrorV1::Limit(
            "result ranges"
        )))
    ));
}
