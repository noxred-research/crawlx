#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `ParserPipeline`: one entry point for markup and documents, ordered stages, limit refusal.

use crawlx_core::extraction::{
    ExtractionPolicyV1, ParserPipelineV1, PipelineRouteV1, PipelineStageV1, StageStatusV1, PIPELINE_FORMATS,
};
use crawlx_core::hash::Digest;
use crawlx_extract::decode::{DecodeOptions, EncodingSource};
use crawlx_extract::parse::{supported_formats, FormatKind, ParseFormat};
use crawlx_extract::pipeline::{
    ParserPipeline, PipelineContent, PipelineError, PipelineInput, PipelineOutput,
};
use crawlx_extract::ExtractOptions;
use url::Url;

const PAGE: &str = "<!doctype html><html lang='en'><head><title>Harbor lantern notice</title></head><body>\
<nav><a href='/home'>Home</a></nav><article><h1>Harbor lantern notice</h1>\
<p>The harbor office will light the stone lanterns every evening this week, and volunteers will place the glass covers at dusk.</p>\
<p>Visitors can read the schedule at the gate and ask the lantern keepers about the route along the quay.</p>\
<a href='/schedule'>Schedule</a></article></body></html>";

fn url() -> Url {
    Url::parse("https://fixture.test/news/harbor").unwrap()
}

fn pipeline() -> ParserPipeline {
    ParserPipeline::new(ParserPipelineV1::default()).unwrap()
}

fn stage_order(output: &PipelineOutput) -> Vec<PipelineStageV1> {
    output.stages.iter().map(|record| record.stage).collect()
}

fn pdf() -> Vec<u8> {
    use lopdf::content::{Content, Operation};
    use lopdf::{dictionary, Document, Object, Stream};
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let font_id = doc.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica", "Encoding" => "WinAnsiEncoding",
    });
    let resources_id = doc.add_object(dictionary! { "Font" => dictionary! { "F1" => font_id } });
    let ops = vec![
        Operation::new("BT", vec![]),
        Operation::new("Tf", vec!["F1".into(), 12.into()]),
        Operation::new("Td", vec![72.into(), 700.into()]),
        Operation::new("Tj", vec![Object::string_literal("Lantern ledger page")]),
        Operation::new("ET", vec![]),
    ];
    let content_id = doc.add_object(Stream::new(
        dictionary! {},
        Content { operations: ops }.encode().unwrap(),
    ));
    let page_id =
        doc.add_object(dictionary! { "Type" => "Page", "Parent" => pages_id, "Contents" => content_id });
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Count" => 1, "Kids" => vec![page_id.into()],
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        }),
    );
    let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog_id);
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

#[test]
fn html_and_documents_use_one_entry_and_one_result_type() {
    let pipeline = pipeline();
    let page_url = url();
    let html = pipeline
        .run(
            PipelineInput::new(PAGE.as_bytes())
                .with_content_type("text/html; charset=utf-8")
                .with_page_url(&page_url),
        )
        .unwrap();
    assert_eq!(html.format, ParseFormat::Html);
    assert_eq!(html.route, PipelineRouteV1::Html);
    assert!(matches!(html.content, PipelineContent::Page(_)));
    assert_eq!(html.title(), Some("Harbor lantern notice"));
    assert!(html.text().contains("stone lanterns"));
    assert!(html.link_urls().contains(&"https://fixture.test/schedule"));

    let text = pipeline
        .run(
            PipelineInput::new(b"Lantern keepers meet at the quay.\n\nBring a cover.")
                .with_filename("notes.txt"),
        )
        .unwrap();
    assert_eq!(text.format, ParseFormat::Txt);
    assert_eq!(text.route, PipelineRouteV1::Document);
    assert!(matches!(text.content, PipelineContent::Document(_)));
    assert!(text.text().contains("Lantern keepers meet at the quay."));

    let csv = pipeline
        .run(PipelineInput::new(b"name,qty\nlantern,4\ncover,9\n").with_filename("stock.csv"))
        .unwrap();
    assert_eq!(csv.format, ParseFormat::Csv);
    assert!(csv.markdown().contains("lantern"));

    let pdf = pipeline
        .run(PipelineInput::new(&pdf()).with_filename("ledger.pdf"))
        .unwrap();
    assert_eq!(pdf.format, ParseFormat::Pdf);
    assert!(pdf.text().contains("Lantern ledger page"));

    for output in [&html, &text, &csv, &pdf] {
        assert_eq!(output.record_version, pipeline.record_version());
        assert_eq!(output.pipeline_digest, *pipeline.digest());
    }
}

#[test]
fn every_run_reports_the_stages_in_contract_order() {
    let pipeline = pipeline();
    let page_url = url();
    let html = pipeline
        .run(PipelineInput::new(PAGE.as_bytes()).with_page_url(&page_url))
        .unwrap();
    let text = pipeline
        .run(PipelineInput::new(b"plain text body").with_filename("a.txt"))
        .unwrap();
    for output in [&html, &text] {
        assert_eq!(stage_order(output), PipelineStageV1::ALL);
    }
    assert_eq!(
        html.stage(PipelineStageV1::Quality).unwrap().status,
        StageStatusV1::NotApplicable
    );
    assert_eq!(
        html.stage(PipelineStageV1::Transform).unwrap().status,
        StageStatusV1::PassThrough
    );
    assert_eq!(
        html.stage(PipelineStageV1::Detect).unwrap().input,
        u64::try_from(PAGE.len()).unwrap()
    );
    assert_eq!(
        text.stage(PipelineStageV1::Select).unwrap().status,
        StageStatusV1::PassThrough
    );

    // A native content policy turns the quality stage on and reports the charged operations.
    let options = ExtractOptions {
        content: Some(ExtractionPolicyV1::default()),
        ..ExtractOptions::default()
    };
    let gated = pipeline
        .run(
            PipelineInput::new(PAGE.as_bytes())
                .with_page_url(&page_url)
                .with_page_options(&options),
        )
        .unwrap();
    let quality = gated.stage(PipelineStageV1::Quality).unwrap();
    assert_eq!(quality.status, StageStatusV1::Completed);
    assert!(quality.output > 0);
}

#[test]
fn upload_pipeline_routes_html_to_the_document_parser_without_a_page_url() {
    let uploads = ParserPipeline::new(ParserPipelineV1::for_uploads()).unwrap();
    let output = uploads
        .run(PipelineInput::new(PAGE.as_bytes()).with_filename("page.html"))
        .unwrap();
    assert_eq!(output.route, PipelineRouteV1::Document);
    assert!(output.text().contains("stone lanterns"));
    assert_ne!(uploads.record_version(), pipeline().record_version());

    // The default pipeline sends HTML to the page extractor, which needs the page URL.
    let error = pipeline()
        .run(PipelineInput::new(PAGE.as_bytes()).with_filename("page.html"))
        .unwrap_err();
    assert!(matches!(error, PipelineError::MissingPageUrl));
}

#[test]
fn unrouted_formats_are_refused_not_parsed() {
    let mut spec = ParserPipelineV1::default();
    spec.routes.remove("pdf");
    let pipeline = ParserPipeline::new(spec).unwrap();
    let error = pipeline
        .run(PipelineInput::new(&pdf()).with_filename("ledger.pdf"))
        .unwrap_err();
    assert!(
        matches!(error, PipelineError::Unrouted { format: "pdf" }),
        "{error:?}"
    );
}

fn limited(edit: impl FnOnce(&mut ParserPipelineV1)) -> ParserPipeline {
    let mut spec = ParserPipelineV1::default();
    edit(&mut spec);
    ParserPipeline::new(spec).unwrap()
}

fn assert_limit(error: PipelineError, expected: &str) {
    match error {
        PipelineError::Limit { what, limit, actual } => {
            assert_eq!(what, expected);
            assert!(actual > limit, "{what}: {actual} must exceed {limit}");
        }
        other => panic!("expected a {expected} limit refusal, got {other:?}"),
    }
}

#[test]
fn input_node_depth_operation_child_and_output_limits_refuse() {
    let page_url = url();

    let input = limited(|s| s.limits.max_input_bytes = 64);
    assert_limit(
        input
            .run(PipelineInput::new(PAGE.as_bytes()).with_page_url(&page_url))
            .unwrap_err(),
        "input bytes",
    );

    let nodes = limited(|s| s.limits.max_nodes = 8);
    assert_limit(
        nodes
            .run(PipelineInput::new(PAGE.as_bytes()).with_page_url(&page_url))
            .unwrap_err(),
        "nodes",
    );

    let nested = format!(
        "<html><body>{}x{}</body></html>",
        "<div>".repeat(30),
        "</div>".repeat(30)
    );
    let depth = limited(|s| s.limits.max_depth = 10);
    assert_limit(
        depth
            .run(PipelineInput::new(nested.as_bytes()).with_page_url(&page_url))
            .unwrap_err(),
        "depth",
    );
    // The same markup passes under the default depth limit.
    pipeline()
        .run(PipelineInput::new(nested.as_bytes()).with_page_url(&page_url))
        .unwrap();

    let operations = limited(|s| s.limits.max_operations = 100);
    let options = ExtractOptions {
        content: Some(ExtractionPolicyV1::default()),
        ..ExtractOptions::default()
    };
    assert_limit(
        operations
            .run(
                PipelineInput::new(PAGE.as_bytes())
                    .with_page_url(&page_url)
                    .with_page_options(&options),
            )
            .unwrap_err(),
        "operations",
    );

    let children = limited(|s| s.limits.max_children = 1);
    assert_limit(
        children
            .run(PipelineInput::new(PAGE.as_bytes()).with_page_url(&page_url))
            .unwrap_err(),
        "children",
    );

    let output = limited(|s| s.limits.max_output_bytes = 16);
    assert_limit(
        output
            .run(PipelineInput::new(PAGE.as_bytes()).with_page_url(&page_url))
            .unwrap_err(),
        "output bytes",
    );
    assert_limit(
        output
            .run(
                PipelineInput::new(b"a line of text that is longer than sixteen bytes")
                    .with_filename("a.txt"),
            )
            .unwrap_err(),
        "output bytes",
    );
}

#[test]
fn the_input_limit_applies_to_documents_before_detection() {
    let tiny = limited(|s| s.limits.max_input_bytes = 8);
    assert_limit(
        tiny.run(PipelineInput::new(b"too long for this pipeline").with_filename("a.txt"))
            .unwrap_err(),
        "input bytes",
    );
}

#[test]
fn invalid_pipelines_never_run() {
    let mut spec = ParserPipelineV1::default();
    spec.stages.reverse();
    assert!(matches!(
        ParserPipeline::new(spec),
        Err(PipelineError::Invalid(_))
    ));
    let mut spec = ParserPipelineV1::default();
    spec.limits.max_nodes = 0;
    assert!(matches!(
        ParserPipeline::new(spec),
        Err(PipelineError::Invalid(_))
    ));
}

#[test]
fn projection_reaches_both_routes() {
    let pipeline = pipeline();
    let page_url = url();
    let redact = |value: &str| value.contains("lantern").then(|| value.replace("lantern", "[x]"));
    let options = ExtractOptions {
        content: Some(ExtractionPolicyV1::default()),
        ..ExtractOptions::default()
    };
    // Without a content policy the page extractor would ignore the projection: refused.
    let refused = pipeline
        .run(
            PipelineInput::new(PAGE.as_bytes())
                .with_page_url(&page_url)
                .with_projection(&redact),
        )
        .unwrap_err();
    assert!(matches!(refused, PipelineError::ProjectionNeedsContentPolicy));
    let html = pipeline
        .run(
            PipelineInput::new(PAGE.as_bytes())
                .with_page_url(&page_url)
                .with_page_options(&options)
                .with_projection(&redact),
        )
        .unwrap();
    assert!(!html.text().contains("lantern"));
    assert_eq!(
        html.stage(PipelineStageV1::Transform).unwrap().status,
        StageStatusV1::Completed
    );
    let text = pipeline
        .run(
            PipelineInput::new(b"the lantern keeper")
                .with_filename("a.txt")
                .with_projection(&redact),
        )
        .unwrap();
    assert_eq!(text.text().trim(), "the [x] keeper");
    let PipelineContent::Document(parsed) = &text.content else {
        panic!("document route expected");
    };
    assert!(!parsed.raw_html.contains("lantern"));
}

#[test]
fn utf16_markup_is_decoded_and_invalid_utf8_is_reported() {
    let pipeline = pipeline();
    let page_url = url();
    let mut utf16 = vec![0xFF, 0xFE];
    for unit in PAGE.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let output = pipeline
        .run(
            PipelineInput::new(&utf16)
                .with_content_type("text/html")
                .with_page_url(&page_url),
        )
        .unwrap();
    assert!(output.text().contains("stone lanterns"));
    assert_eq!(
        output.stage(PipelineStageV1::DecodeInput).unwrap().status,
        StageStatusV1::Completed
    );
    let PipelineContent::Page(document) = &output.content else {
        panic!("page route expected");
    };
    assert!(document.decode.is_none());
    assert_eq!(
        document.raw_html_digest,
        Digest::of("crawlx.extract.raw_html.v1", &utf16)
    );

    let mut lossy = PAGE.as_bytes().to_vec();
    lossy.splice(lossy.len() - 20..lossy.len() - 20, [0xFF, 0xFE, 0xFD]);
    let output = pipeline
        .run(
            PipelineInput::new(&lossy)
                .with_content_type("text/html")
                .with_page_url(&page_url),
        )
        .unwrap();
    assert!(output.warnings.iter().any(|w| w.contains("replaced")));
}

#[test]
fn declared_page_charset_preserves_text_report_and_original_digest() {
    let source = b"<html><head><title>Caf\xe9 notice</title></head><body>\
        <p>The caf\xe9 opens daily for neighbors, serving warm drinks beside the harbor.</p>\
        </body></html>";
    let page_url = url();
    for options in [
        ExtractOptions {
            decode: Some(DecodeOptions::with_charset("windows-1252")),
            ..ExtractOptions::default()
        },
        ExtractOptions {
            decode: Some(DecodeOptions::default()),
            content_type: Some("text/html; charset=ISO-8859-1".to_owned()),
            ..ExtractOptions::default()
        },
    ] {
        let output = pipeline()
            .run(
                PipelineInput::new(source)
                    .with_content_type("text/html")
                    .with_page_url(&page_url)
                    .with_page_options(&options),
            )
            .unwrap();
        assert_eq!(output.title(), Some("Café notice"));
        assert!(output.text().contains("café opens daily"), "{}", output.text());
        assert!(output.warnings.is_empty());
        assert_eq!(
            output.stage(PipelineStageV1::DecodeInput).unwrap().status,
            StageStatusV1::Completed
        );
        let PipelineContent::Page(document) = output.content else {
            panic!("page route expected");
        };
        let report = document.decode.as_ref().unwrap();
        assert_eq!(report.encoding, "windows-1252");
        assert_eq!(report.source, EncodingSource::Declared);
        assert_eq!(report.bom_len, 0);
        assert_eq!(report.issue_count, 0);
        assert_eq!(
            document.raw_html_digest,
            Digest::of("crawlx.extract.raw_html.v1", source)
        );
    }
}

#[test]
fn page_bom_survives_decoding_and_wins_over_declared_charset() {
    let source = "<html><head><title>Café notice</title></head><body>\
        <p>The café opens daily for neighbors, serving warm drinks beside the harbor.</p>\
        </body></html>";
    let mut utf8 = vec![0xEF, 0xBB, 0xBF];
    utf8.extend_from_slice(source.as_bytes());
    let mut utf16 = vec![0xFF, 0xFE];
    for unit in source.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let options = ExtractOptions {
        decode: Some(DecodeOptions::with_charset("windows-1252")),
        content: Some(ExtractionPolicyV1::default()),
        ..ExtractOptions::default()
    };
    let project = |value: &str| value.contains("café").then(|| value.replace("café", "tea room"));
    let page_url = url();
    for (bytes, encoding, bom_len) in [(utf8, "UTF-8", 3), (utf16, "UTF-16LE", 2)] {
        let output = pipeline()
            .run(
                PipelineInput::new(&bytes)
                    .with_content_type("text/html")
                    .with_page_url(&page_url)
                    .with_page_options(&options)
                    .with_projection(&project),
            )
            .unwrap();
        assert!(
            output.text().contains("tea room opens daily"),
            "{}",
            output.text()
        );
        assert!(output.warnings.is_empty());
        let PipelineContent::Page(document) = output.content else {
            panic!("page route expected");
        };
        let report = document.decode.as_ref().unwrap();
        assert_eq!(report.encoding, encoding);
        assert_eq!(report.source, EncodingSource::Bom);
        assert_eq!(report.bom_len, bom_len);
        assert_eq!(report.issue_count, 0);
        assert!(report.declaration_conflict);
        assert_eq!(
            document.raw_html_digest,
            Digest::of("crawlx.extract.raw_html.v1", &bytes)
        );
        assert_ne!(
            document.raw_html_digest,
            Digest::of("crawlx.extract.raw_html.v1", source.as_bytes())
        );
    }
}

#[test]
fn declared_charset_applies_before_pipeline_depth_check() {
    let source = format!(
        "<html><body>{}deep content{}</body></html>",
        "<div>".repeat(30),
        "</div>".repeat(30)
    );
    let bytes: Vec<u8> = source.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let options = ExtractOptions {
        decode: Some(DecodeOptions::with_charset("UTF-16LE")),
        ..ExtractOptions::default()
    };
    let page_url = url();
    let input = PipelineInput::new(&bytes)
        .with_content_type("text/html")
        .with_page_url(&page_url)
        .with_page_options(&options);
    assert_limit(
        limited(|spec| spec.limits.max_depth = 10).run(input).unwrap_err(),
        "depth",
    );
    let output = pipeline().run(input).unwrap();
    assert!(output.text().contains("deep content"));
}

#[test]
fn malformed_page_bytes_keep_original_diagnostic_offsets() {
    let prefix = b"<html><body><p>Visible text before ";
    let mut bytes = prefix.to_vec();
    bytes.push(0xFF);
    bytes.extend_from_slice(b" and after one malformed byte in the original source.</p></body></html>");
    let options = ExtractOptions {
        decode: Some(DecodeOptions::default()),
        ..ExtractOptions::default()
    };
    let page_url = url();
    let output = pipeline()
        .run(
            PipelineInput::new(&bytes)
                .with_content_type("text/html")
                .with_page_url(&page_url)
                .with_page_options(&options),
        )
        .unwrap();
    assert!(output.text().contains("before \u{FFFD} and after"));
    assert_eq!(output.warnings.len(), 1);
    let PipelineContent::Page(document) = output.content else {
        panic!("page route expected");
    };
    let report = document.decode.as_ref().unwrap();
    assert_eq!(report.encoding, "UTF-8");
    assert_eq!(report.source, EncodingSource::Default);
    assert_eq!(report.bom_len, 0);
    assert_eq!(report.issue_count, 1);
    assert_eq!(report.issues[0].offset, prefix.len());
    assert_eq!(report.issues[0].length, 1);
    assert_eq!(
        document.raw_html_digest,
        Digest::of("crawlx.extract.raw_html.v1", &bytes)
    );
}

#[test]
fn record_version_embeds_the_pipeline_digest() {
    let a = pipeline();
    let b = limited(|s| s.limits.max_output_bytes = 1024);
    assert_ne!(a.record_version(), b.record_version());
    assert_eq!(
        a.record_version(),
        ParserPipelineV1::default().record_version().unwrap()
    );
    assert!(a.record_version().starts_with("parser_pipeline_v1/"));
}

#[test]
fn contract_format_names_match_the_document_parser() {
    let mut parser: Vec<&str> = supported_formats().iter().map(|f| f.format).collect();
    parser.sort_unstable();
    let mut contract = PIPELINE_FORMATS.to_vec();
    contract.sort_unstable();
    assert_eq!(parser, contract);
    // Default routes cover exactly the text-bearing formats.
    let defaults = ParserPipelineV1::default();
    for info in supported_formats() {
        assert_eq!(
            defaults.route(info.format).is_some(),
            info.kind == FormatKind::Document,
            "{}",
            info.format
        );
    }
}
