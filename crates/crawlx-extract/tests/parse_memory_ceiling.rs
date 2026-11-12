//! Measured peak-heap ceiling of the HTML parse path.
//!
//! Every adversarial case is sized at the extraction input cap
//! ([`DEFAULT_MAX_INPUT_BYTES`], 16 MiB) or, for node-dense inputs, at the `<` count cap
//! ([`DEFAULT_MAX_NODES`]) that `Extractor` enforces before parsing. For each case the test
//! measures the peak live heap of
//!
//! 1. `scraper::Html::parse_document` and the fallible tree sink `dom::parse_document`,
//! 2. parse plus `dom::check_limits` (via the public `Extractor` limits),
//! 3. `Extractor::extract_bytes` with legacy options,
//! 4. `Extractor::extract_bytes` with the default article content policy, and
//! 5. the same with include/exclude/read-more selectors (builds the selector index),
//!
//! and fails when any phase exceeds `input_len * PARSE_BYTES_PER_INPUT_BYTE`, the factor the
//! worker charges against its process-wide parse-memory budget
//! ([`crawlx_extract::parse_budget`]).
//!
//! The sink charges every allocation it sees (plus a model of the parser state it does not) to
//! the reservation before it happens, so the test also checks that model: for every case the
//! bytes the sink charged are at least its measured peak heap and at most the bytes admitted
//! for the input, i.e. the sink never refuses a corpus shape and never undercounts one.
//!
//! The counting allocator wraps the system allocator and counts requested bytes, not allocator
//! metadata or fragmentation; production uses mimalloc, whose size-class rounding is covered by
//! the margin documented next to the factor. The test is a single `#[test]` so no sibling test
//! thread allocates while a phase is being measured.
//!
//! Ignored by default (about 90 s in release, far slower in debug). Run:
//! `cargo test --release -p crawlx-extract --test parse_memory_ceiling -- --ignored --nocapture`
//! Write the per-case report: set `CRAWLX_PARSE_CEILING_REPORT=/path/report.json`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::vec_init_then_push
)]

use crawlx_extract::document::{DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_NODES};
use crawlx_extract::dom;
use crawlx_extract::parse_budget::{charge_bytes, global, PARSE_BYTES_PER_INPUT_BYTE};
use crawlx_extract::{ExtractError, ExtractOptions, Extractor};
use peak_alloc::PeakAlloc;
use scraper::Html;
use serde_json::json;
use url::Url;

#[global_allocator]
static PEAK: PeakAlloc = PeakAlloc;

const MAX_BYTES: usize = DEFAULT_MAX_INPUT_BYTES;
const MAX_LT: usize = DEFAULT_MAX_NODES;

/// Append `piece(i)` until the next piece would exceed `max_bytes` or `max_lt` `<` bytes.
fn build(max_bytes: usize, max_lt: usize, mut piece: impl FnMut(usize, &mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::with_capacity(max_bytes);
    let mut lt = 0usize;
    let mut scratch = Vec::new();
    for i in 0.. {
        scratch.clear();
        piece(i, &mut scratch);
        let piece_lt = scratch.iter().filter(|b| **b == b'<').count();
        if out.len() + scratch.len() > max_bytes || lt + piece_lt > max_lt {
            break;
        }
        lt += piece_lt;
        out.extend_from_slice(&scratch);
    }
    out
}

fn repeat(unit: &str, max_lt: usize) -> Vec<u8> {
    build(MAX_BYTES, max_lt, |_, out| out.extend_from_slice(unit.as_bytes()))
}

/// `prefix`, then filler up to the cap minus `suffix`, then `suffix`.
fn wrapped(prefix: &str, fill: &str, suffix: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_BYTES);
    out.extend_from_slice(prefix.as_bytes());
    let room = MAX_BYTES - prefix.len() - suffix.len();
    while out.len() - prefix.len() + fill.len() <= room {
        out.extend_from_slice(fill.as_bytes());
    }
    out.extend_from_slice(suffix.as_bytes());
    out
}

fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut cases: Vec<(&'static str, Vec<u8>)> = Vec::new();
    // many tiny nodes, at the `<` cap and below it (so the extraction phases run fully)
    cases.push(("tiny_void_nodes_at_node_cap", repeat("<br>", MAX_LT)));
    cases.push(("tiny_elements_at_node_cap", repeat("<p>a</p>", MAX_LT)));
    cases.push(("tiny_unclosed_inline_at_node_cap", repeat("<i>a", MAX_LT)));
    cases.push(("tiny_elements_extractable", repeat("<p>a</p>", 300_000)));
    // deep nesting up to the depth limit, and far past it (parse completes, depth check refuses)
    let block = format!("{}x{}", "<div>".repeat(510), "</div>".repeat(510));
    cases.push(("nesting_at_depth_limit", repeat(&block, MAX_LT)));
    // html5ever scans the open-element stack per start tag, so unbounded depth is quadratic in
    // time (not memory): well past the limit, but in blocks that keep the run bounded.
    let deep = format!("{}x{}", "<div>".repeat(1500), "</div>".repeat(1500));
    cases.push(("nesting_beyond_limit_1500", repeat(&deep, 300_000)));
    // one huge token
    cases.push((
        "huge_attribute_value",
        wrapped("<a href=\"", "xxxxxxxxxxxxxxxx", "\">t</a>"),
    ));
    cases.push(("huge_comment", wrapped("<!--", "xxxxxxxxxxxxxxxx", "-->")));
    cases.push(("huge_tag_name", wrapped("<", "aaaaaaaaaaaaaaaa", ">t")));
    cases.push(("huge_attribute_name", wrapped("<p ", "aaaaaaaaaaaaaaaa", "=1>t")));
    cases.push((
        "huge_doctype_public_id",
        wrapped("<!DOCTYPE html PUBLIC \"", "xxxxxxxxxxxxxxxx", "\"><p>t"),
    ));
    cases.push(("huge_text", wrapped("<p>", "lorem ipsum dolor ", "</p>")));
    cases.push((
        "huge_script_rawtext",
        wrapped("<script>", "var a = 1; ", "</script>"),
    ));
    cases.push((
        "huge_textarea_rcdata",
        wrapped("<textarea>", "lorem &amp; ipsum ", "</textarea>"),
    ));
    // atom interning: every tag, attribute and class name unique
    cases.push((
        "unique_tag_names",
        build(MAX_BYTES, MAX_LT, |i, out| {
            out.extend_from_slice(format!("<t{i}>").as_bytes());
        }),
    ));
    cases.push((
        "unique_attr_and_class_names",
        build(MAX_BYTES, MAX_LT, |i, out| {
            out.extend_from_slice(format!("<p a{i}=\"1\" class=\"c{i} d{i}\">x</p>").as_bytes());
        }),
    ));
    cases.push((
        "unique_long_names",
        build(MAX_BYTES, MAX_LT, |i, out| {
            let pad = "n".repeat(56);
            out.extend_from_slice(format!("<{pad}{i} {pad}a{i}=\"1\" class=\"{pad}{i}\">").as_bytes());
        }),
    ));
    cases.push((
        "many_attributes_per_element",
        build(MAX_BYTES, MAX_LT, |i, out| {
            out.extend_from_slice(b"<p");
            for j in 0..300 {
                out.extend_from_slice(format!(" a{j}=1").as_bytes());
            }
            let _ = i;
            out.extend_from_slice(b">x</p>");
        }),
    ));
    // malformed tables with pending character tokens, foster parenting
    cases.push((
        "malformed_tables_pending_text",
        repeat("<table>abc<tr>def<td>ghi<b>jkl<i>mno", MAX_LT),
    ));
    cases.push((
        "table_pending_text_run",
        wrapped("<table>", "lorem ipsum dolor ", "<td>x"),
    ));
    // formatting-element reconstruction and the adoption agency algorithm
    cases.push((
        "formatting_reconstruction",
        repeat("<a><b><i><em><strong><font><u><s><big><small><p>t", MAX_LT),
    ));
    cases.push((
        "adoption_agency_misnested",
        repeat("<b>1<p>2</b>3<p>4</i>5</b>", MAX_LT),
    ));
    cases.push(("nobr_repeated", repeat("<nobr>x", MAX_LT)));
    cases.push(("anchor_nested_adoption", repeat("<a href=x>y", MAX_LT)));
    // Noah's Ark compares each new formatting element with the whole active list, so one long
    // run of distinct elements is quadratic in time (not memory): blocks of 300 keep it bounded.
    cases.push((
        "formatting_distinct_attributes",
        build(MAX_BYTES, MAX_LT, |i, out| {
            for j in 0..300 {
                out.extend_from_slice(format!("<b x={i}-{j}>").as_bytes());
            }
            out.extend_from_slice(b"<p>t");
            out.extend_from_slice("</b>".repeat(300).as_bytes());
        }),
    ));
    cases.push((
        "formatting_all_kinds_misnested",
        repeat(
            "<a><b><big><code><em><font><i><nobr><s><small><strike><strong><tt><u><p>t</a></b></u></i>",
            MAX_LT,
        ),
    ));
    // misnesting that leaves blocks open: closed after every 200 units, as html5ever's per-tag
    // open-element scans are quadratic in depth (time, not memory)
    let block = format!("{}{}", "<b><i><div>x</b>y</i>z".repeat(200), "</div>".repeat(200));
    cases.push(("misnested_blocks_adoption", repeat(&block, MAX_LT)));
    let block = format!(
        "{}{}",
        "<table><b><i><tr>x".repeat(200),
        "</table></div>".repeat(200)
    );
    cases.push(("table_foster_formatting", repeat(&block, MAX_LT)));
    cases.push((
        "formatting_pop_cycle",
        repeat("<div><b x=1><i y=1><u z=1></div><p>t", MAX_LT),
    ));
    // templates
    cases.push((
        "templates_flat",
        repeat("<template><div>x</div></template>", MAX_LT),
    ));
    let nested_templates = format!("{}{}", "<template>".repeat(1500), "</template>".repeat(1500));
    cases.push(("templates_nested_1500", repeat(&nested_templates, 300_000)));
    // adjacent text merges: ignored tokens split one text node into many appends
    cases.push(("adjacent_text_merges", repeat("abcdefghij</q>", MAX_LT)));
    cases.push((
        "adjacent_text_merges_pi",
        repeat("abcdefghij<?pi>", MAX_LT / 2), // bogus comments: separate nodes
    ));
    // character references
    cases.push((
        "character_references",
        wrapped("<p>", "&amp;&lt;&#65;&#x1F600;&notin;&nbsp;", "</p>"),
    ));
    cases.push((
        "character_references_attr",
        wrapped("<p title=\"", "&amp;&#x1F600;&notin;", "\">t</p>"),
    ));
    // invalid UTF-8: `extract_bytes` allocates a lossy copy
    let mut invalid = wrapped("<p>", "lorem ipsum dolor ", "</p>");
    invalid.insert(10, 0xFF);
    cases.push(("invalid_utf8_text", invalid));
    let mut dense = b"<p>".to_vec();
    dense.resize(5 * 1024 * 1024, 0xFF); // every byte becomes a 3-byte U+FFFD: 15 MiB of text
    cases.push(("invalid_utf8_dense_replacement", dense));
    // realistic article-like markup for the baseline ratio
    cases.push((
        "article_like_markup",
        build(MAX_BYTES, MAX_LT, |i, out| {
            out.extend_from_slice(
                format!(
                    "<div class=\"post\"><h2>Heading {i}</h2><p>Lorem ipsum dolor sit amet, consectetur \
                     adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
                     <a href=\"/p/{i}\">more</a> <img src=\"/i/{i}.png\" alt=\"i\"> <em>ut enim</em> ad minim \
                     veniam, quis nostrud exercitation.</p></div>\n"
                )
                .as_bytes(),
            );
        }),
    ));
    cases
}

/// Peak live heap bytes above the allocation level at entry; `f`'s result is dropped inside.
fn measure<T>(f: impl FnOnce() -> T) -> (usize, isize) {
    let before = PEAK.current_usage();
    PEAK.reset_peak_usage();
    drop(f());
    let peak = PEAK.peak_usage();
    let after = PEAK.current_usage();
    (
        peak.saturating_sub(before),
        isize::try_from(after).unwrap() - isize::try_from(before).unwrap(),
    )
}

fn article_policy(selectors: bool) -> crawlx_core::extraction::ExtractionPolicyV1 {
    let value = if selectors {
        json!({"selectors": {
            "include": [{"kind": "css", "expression": "article, main, .post"}],
            "exclude": [{"kind": "css", "expression": "nav, footer"}],
            "readMore": [{"kind": "css", "expression": "a"}],
        }})
    } else {
        json!({})
    };
    serde_json::from_value(value).unwrap()
}

#[test]
#[ignore = "about 90 s in release, far slower in debug: cargo test --release -p crawlx-extract --test parse_memory_ceiling -- --ignored --nocapture"]
fn parse_and_extract_stay_under_the_charged_ceiling() {
    // the production budget would refuse the largest inputs here; this test measures the parser
    global().set_limit(usize::MAX);
    let base = Url::parse("https://example.test/page").unwrap();
    // warm lazily initialised statics (atom tables, regexes, policies) outside any measurement
    let warm =
        b"<html><head><title>t</title></head><body><article><p>warm up text</p></article></body></html>";
    for options in [
        ExtractOptions::default(),
        ExtractOptions {
            content: Some(article_policy(false)),
            ..ExtractOptions::default()
        },
        ExtractOptions {
            content: Some(article_policy(true)),
            ..ExtractOptions::default()
        },
    ] {
        drop(Extractor::extract_bytes(warm, &base, &options));
    }
    drop(Html::parse_document(std::str::from_utf8(warm).unwrap()));

    let legacy = ExtractOptions::default();
    let content = ExtractOptions {
        content: Some(article_policy(false)),
        ..ExtractOptions::default()
    };
    let selectors = ExtractOptions {
        content: Some(article_policy(true)),
        ..ExtractOptions::default()
    };

    let mut rows = Vec::new();
    let mut worst = ("", "", 0.0f64);
    let mut least_coverage = f64::INFINITY;
    let mut failures = Vec::new();
    for (name, input) in corpus() {
        let len = input.len();
        eprintln!("measuring {name}");
        assert!(
            len > 0 && len <= MAX_BYTES,
            "{name}: generator produced {len} bytes"
        );
        assert!(
            input.iter().filter(|b| **b == b'<').count() <= MAX_LT,
            "{name}: exceeds the `<` precheck"
        );
        let ceiling = charge_bytes(len).expect("charge fits usize");
        let text = || String::from_utf8_lossy(&input);

        let (parse, parse_net) = measure(|| Html::parse_document(&text()));
        // the fallible sink: its peak heap and what its model charged for the same input
        let mut sink_charge = global().try_charge_input(len).expect("unlimited budget");
        let (sink_peak, _) =
            measure(|| dom::parse_document(&mut sink_charge, &text()).expect("unlimited budget"));
        let model = sink_charge.tree_bytes();
        drop(sink_charge);
        let (parse_check, _) = measure(|| {
            let html = text();
            let doc = Html::parse_document(&html);
            let checked = crawlx_extract::dom::check_limits(&doc, MAX_LT);
            (doc, checked.is_ok())
        });
        let mut outcome = String::new();
        let mut phase = |label: &'static str, options: &ExtractOptions| {
            let (peak, net) = measure(|| {
                let result = Extractor::extract_bytes(&input, &base, options);
                outcome = match &result {
                    Ok(_) => "ok".to_owned(),
                    Err(ExtractError::TooLarge { what, .. }) => format!("too_large:{what}"),
                    Err(other) => format!("error:{other}"),
                };
                result
            });
            (label, peak, net)
        };
        let phases = [
            ("parse_document", parse, parse_net),
            ("fallible_parse_document", sink_peak, 0),
            ("parse_and_check_limits", parse_check, 0),
            phase("extract_legacy", &legacy),
            phase("extract_content_policy", &content),
            phase("extract_content_selectors", &selectors),
        ];
        let mut cells = serde_json::Map::new();
        for (label, peak, net) in phases {
            let ratio = peak as f64 / len as f64;
            if ratio > worst.2 {
                worst = (name, label, ratio);
            }
            if peak > ceiling {
                failures.push(format!(
                    "{name}/{label}: peak {peak} B = {ratio:.2}/B exceeds ceiling {ceiling} B ({PARSE_BYTES_PER_INPUT_BYTE}/B)"
                ));
            }
            assert!(
                net.unsigned_abs() < len / 8 + 1_048_576,
                "{name}/{label}: retained {net} B after drop"
            );
            cells.insert(
                label.to_owned(),
                json!({"peak_bytes": peak, "bytes_per_input_byte": ratio, "net_retained_bytes": net}),
            );
        }
        let coverage = model as f64 / sink_peak as f64;
        least_coverage = least_coverage.min(coverage);
        if model < sink_peak {
            failures.push(format!(
                "{name}: the sink charged {model} B but its peak heap was {sink_peak} B ({coverage:.2}x): the model understates"
            ));
        }
        if model > ceiling {
            failures.push(format!(
                "{name}: the sink charged {model} B, above the {ceiling} B admitted for the input"
            ));
        }
        eprintln!(
            "{name:<34} sink peak={:.2} model={:.2} model/peak={coverage:.2}",
            sink_peak as f64 / len as f64,
            model as f64 / len as f64,
        );
        cells.insert(
            "fallible_parse_model".to_owned(),
            json!({"model_bytes": model, "model_bytes_per_input_byte": model as f64 / len as f64, "model_over_peak": coverage}),
        );
        eprintln!(
            "{name:<34} len={len:>9} parse={:.2} check={:.2} legacy={:.2} content={:.2} selectors={:.2} [{outcome}]",
            parse as f64 / len as f64,
            parse_check as f64 / len as f64,
            cells["extract_legacy"]["bytes_per_input_byte"].as_f64().unwrap(),
            cells["extract_content_policy"]["bytes_per_input_byte"].as_f64().unwrap(),
            cells["extract_content_selectors"]["bytes_per_input_byte"].as_f64().unwrap(),
        );
        rows.push(
            json!({"case": name, "input_bytes": len, "last_extract_outcome": outcome, "phases": cells}),
        );
    }
    eprintln!(
        "worst: {} / {} = {:.2} bytes per input byte; charged factor {PARSE_BYTES_PER_INPUT_BYTE}; \
         least sink model / peak = {least_coverage:.2}",
        worst.0, worst.1, worst.2
    );
    if let Ok(path) = std::env::var("CRAWLX_PARSE_CEILING_REPORT") {
        let report = json!({
            "allocator": "peak_alloc over the system allocator (requested live bytes; no allocator metadata)",
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "max_input_bytes": MAX_BYTES,
            "max_nodes": MAX_LT,
            "worst_case": {"case": worst.0, "phase": worst.1, "bytes_per_input_byte": worst.2},
            "charged_factor": PARSE_BYTES_PER_INPUT_BYTE,
            "least_sink_model_over_peak": least_coverage,
            "margin_over_worst_case": PARSE_BYTES_PER_INPUT_BYTE as f64 / worst.2 - 1.0,
            "cases": rows,
        });
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    assert!(
        failures.is_empty(),
        "parse memory ceiling exceeded:\n{}",
        failures.join("\n")
    );
    assert!(
        PARSE_BYTES_PER_INPUT_BYTE as f64 >= worst.2 * 1.25,
        "the charged factor {PARSE_BYTES_PER_INPUT_BYTE} must keep a 25% margin over the measured worst case {:.2}",
        worst.2
    );
}
