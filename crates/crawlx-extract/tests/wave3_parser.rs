#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Native parser policy/traversal fixtures, not external-equivalence receipts.

use std::{
    cell::Cell,
    io::{Cursor, Write},
};

use crawlx_core::{extraction::ParserPipelineV1, hash::Digest};
use crawlx_extract::{
    parse::traversal::{feed_with_freshness, traverse, ChildContent, TraversalError, TraversalLimits},
    parser_policy::{InputPolicy, ModelPolicy},
    pipeline::{ParserPipeline, PipelineContent, PipelineInput},
    source_policy::SourceFreshness,
};

fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn pipeline() -> ParserPipeline {
    ParserPipeline::new(ParserPipelineV1::for_uploads()).unwrap()
}

#[test]
fn text_only_never_calls_dom_even_for_invalid_tree_depth_and_truncates_utf8_safely() {
    let mut spec = ParserPipelineV1::default();
    spec.limits.max_depth = 1;
    spec.limits.max_nodes = 1;
    let pipeline = ParserPipeline::new(spec).unwrap();
    let source = "<html><body><div><p>éé</p></div></body></html>";
    let output = pipeline
        .run(
            PipelineInput::new(source.as_bytes())
                .with_content_type("text/html")
                .with_input_policy(InputPolicy::new(ModelPolicy::TextOnly, Some(22))),
        )
        .unwrap();
    assert!(output.provenance.truncated);
    assert!(matches!(output.content, PipelineContent::Document(_)));
    assert!(output.html().is_empty());
    assert!(output.markdown().is_empty());
    assert!(output.text().len() <= 22);
    assert_eq!(output.provenance.model, ModelPolicy::TextOnly);
}

#[test]
fn nested_archive_ids_keep_parent_ordinal_and_unsupported_children_explicit() {
    let inner = archive(&[("child.txt", b"inside")]);
    let bytes = archive(&[("nested.zip", &inner), ("unsupported.bin", b"unrecognized")]);
    let root = Digest::of("fixture", b"root");
    let records = traverse(
        &pipeline(),
        &bytes,
        None,
        root,
        TraversalLimits::default(),
        &|| false,
    )
    .unwrap();
    assert_eq!(records.len(), 4);
    assert_eq!(records[1].parent, Some(root));
    assert_eq!(records[2].parent, Some(records[1].id));
    assert_eq!(records[3].ordinal, 1);
    assert!(matches!(records[3].content, ChildContent::Unsupported));
    let again = traverse(
        &pipeline(),
        &bytes,
        None,
        root,
        TraversalLimits::default(),
        &|| false,
    )
    .unwrap();
    assert_eq!(
        records.iter().map(|record| record.id).collect::<Vec<_>>(),
        again.iter().map(|record| record.id).collect::<Vec<_>>()
    );
}

#[test]
fn archive_ratio_aggregate_bytes_depth_and_midflight_cancel_refuse() {
    let repeated = vec![b'x'; 64 * 1024];
    let bomb = archive(&[("large.txt", &repeated)]);
    let root = Digest::of("fixture", b"root");
    let mut limits = TraversalLimits::default();
    limits.max_ratio = 2;
    assert!(traverse(&pipeline(), &bomb, None, root, limits, &|| false).is_err());
    limits.max_ratio = 10_000;
    limits.max_expanded_bytes = 100;
    assert!(traverse(&pipeline(), &bomb, None, root, limits, &|| false).is_err());
    let inner = archive(&[("child.txt", b"inside")]);
    let nested = archive(&[("inner.zip", &inner)]);
    limits = TraversalLimits::default();
    limits.max_depth = 1;
    assert!(traverse(&pipeline(), &nested, None, root, limits, &|| false).is_err());
    limits = TraversalLimits::default();
    limits.max_ratio = 10_000;
    let ticks = Cell::new(0_u32);
    let deadline = || {
        let next = ticks.get() + 1;
        ticks.set(next);
        next > 4
    };
    assert!(matches!(
        traverse(&pipeline(), &bomb, None, root, limits, &deadline),
        Err(TraversalError::Cancelled)
    ));
}

#[test]
fn complete_feed_freshness_and_soft_output_truncation_are_distinct() {
    let bytes = b"<feed><updated>2026-01-02T00:00:00Z</updated><entry><title>one</title></entry><entry><title>two</title></entry></feed>";
    let root = Digest::of("fixture", b"feed");
    let full = feed_with_freshness(
        &pipeline(),
        bytes,
        "application/atom+xml",
        root,
        TraversalLimits::default(),
        10,
        Some(0),
        &|| false,
    )
    .unwrap();
    assert_eq!(full.freshness, SourceFreshness::Modified);
    assert_eq!(full.omitted_entries, 0);
    let truncated = feed_with_freshness(
        &pipeline(),
        bytes,
        "application/atom+xml",
        root,
        TraversalLimits::default(),
        1,
        Some(0),
        &|| false,
    )
    .unwrap();
    assert_eq!(truncated.freshness, SourceFreshness::Truncated);
    assert_eq!(truncated.omitted_entries, 1);
    assert_eq!(truncated.records.len(), 2);
}
