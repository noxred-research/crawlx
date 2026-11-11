//! Table scoring and normalized row output.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_extract::content_outputs::ContentOutputOptions;
use crawlx_extract::tables::{ExtractedTable, TableExtraction, TableKind, TABLE_RULES_VERSION};
use crawlx_extract::{ExtractOptions, Extractor};
use url::Url;

fn tables(body: &str) -> TableExtraction {
    let html = format!("<!doctype html><html><body>{body}</body></html>");
    let mut outputs = ContentOutputOptions::default();
    outputs.tables = true;
    let doc = Extractor::extract(
        &html,
        &Url::parse("https://fixture.test/").unwrap(),
        &ExtractOptions {
            only_main_content: false,
            outputs: Some(outputs),
            ..ExtractOptions::default()
        },
    )
    .unwrap();
    doc.outputs.unwrap().tables.unwrap()
}

fn rows(t: &ExtractedTable) -> Vec<Vec<&str>> {
    t.rows
        .iter()
        .map(|r| r.iter().map(String::as_str).collect())
        .collect()
}

fn header(t: &ExtractedTable) -> Vec<&str> {
    t.header.iter().map(String::as_str).collect()
}

#[test]
fn simple_data_table_yields_exact_rows() {
    let out = tables(
        "<table><caption>Sales</caption><thead><tr><th>Region</th><th>Q1</th><th>Q2</th></tr></thead>\
         <tbody><tr><td>North</td><td>10</td><td>12</td></tr><tr><td>South</td><td>7</td><td>9</td></tr></tbody></table>",
    );
    assert_eq!(out.rules, TABLE_RULES_VERSION);
    assert!(!out.truncated);
    let [t] = out.tables.as_slice() else {
        panic!("{out:?}")
    };
    assert_eq!(t.kind, TableKind::Data);
    assert_eq!((t.index, t.depth, t.parent), (0, 0, None));
    assert_eq!(t.caption.as_deref(), Some("Sales"));
    assert_eq!(header(t), ["Region", "Q1", "Q2"]);
    assert_eq!(rows(t), [["North", "10", "12"], ["South", "7", "9"]]);
    assert_eq!((t.score.rows, t.score.columns, t.score.header_rows), (3, 3, 1));
    assert_eq!(t.score.total, 1000);
}

#[test]
fn merged_headers_and_spans_normalize_by_repetition() {
    let out = tables(
        "<table><thead>\
         <tr><th rowspan=\"2\">Item</th><th colspan=\"2\">2023</th><th colspan=\"2\">2024</th></tr>\
         <tr><th>H1</th><th>H2</th><th>H1</th><th>H2</th></tr></thead><tbody>\
         <tr><td>Apples</td><td>1</td><td>2</td><td>3</td><td>4</td></tr>\
         <tr><td rowspan=\"2\">Pears</td><td>5</td><td>6</td><td>7</td><td>8</td></tr>\
         <tr><td>9</td><td>10</td><td>11</td><td>12</td></tr></tbody></table>",
    );
    let t = &out.tables[0];
    assert_eq!(t.kind, TableKind::Data);
    assert_eq!(t.score.header_rows, 2);
    assert_eq!(
        header(t),
        ["Item", "2023 / H1", "2023 / H2", "2024 / H1", "2024 / H2"]
    );
    assert_eq!(
        rows(t),
        [
            ["Apples", "1", "2", "3", "4"],
            ["Pears", "5", "6", "7", "8"],
            ["Pears", "9", "10", "11", "12"],
        ]
    );
}

#[test]
fn data_table_inside_a_layout_table_is_reported_separately() {
    let out = tables(
        "<table width=\"100%\"><tr>\
         <td><div><p>Navigation text and some prose that sits in a layout cell of the page.</p></div></td>\
         <td><table><tr><th>Key</th><th>Value</th></tr><tr><td>a</td><td>1</td></tr><tr><td>b</td><td>2</td></tr></table></td>\
         </tr></table>",
    );
    let [outer, inner] = out.tables.as_slice() else {
        panic!("{out:?}")
    };
    assert_eq!(outer.kind, TableKind::Layout);
    assert!(outer.rows.is_empty() && outer.header.is_empty());
    assert_eq!(outer.score.nested_tables, 1);
    assert_eq!((inner.index, inner.depth, inner.parent), (1, 1, Some(0)));
    assert_eq!(inner.kind, TableKind::Data);
    assert_eq!(header(inner), ["Key", "Value"]);
    assert_eq!(rows(inner), [["a", "1"], ["b", "2"]]);
}

#[test]
fn layout_wrappers_and_link_bars_are_layout() {
    let out = tables(
        "<table><tr><td><p>Only cell</p></td></tr></table>\
         <table><tr><td><a href=\"/a\">Alpha</a></td><td><a href=\"/b\">Beta</a></td><td><a href=\"/c\">Gamma</a></td></tr></table>\
         <table></table>",
    );
    assert_eq!(out.tables.len(), 3);
    assert!(out.tables.iter().all(|t| t.kind == TableKind::Layout), "{out:?}");
    assert!(out.tables.iter().all(|t| t.rows.is_empty()));
    assert!(out.tables[1].score.link_density >= 700);
}

#[test]
fn weak_evidence_is_explicitly_ambiguous() {
    let out = tables(
        // One row, no header.
        "<table><tr><td>a</td><td>b</td><td>c</td></tr></table>\
         <table><tr><td>a</td><td>b</td><td>c</td></tr><tr><td>d</td></tr><tr><td>e</td><td>f</td></tr></table>\
         <table><thead><tr><th>Only</th><th>Header</th></tr></thead></table>",
    );
    assert_eq!(out.tables.len(), 3);
    for t in &out.tables {
        assert_eq!(t.kind, TableKind::Ambiguous, "{t:?}");
        assert!(
            t.rows.is_empty() && t.header.is_empty(),
            "no rows are guessed: {t:?}"
        );
    }
    // The ragged table's inconsistency is visible in its components.
    assert!(out.tables[1].score.consistency < 700);
}

#[test]
fn prose_grid_is_not_data() {
    let prose = "Sentence about the harbor and the weather over the long winter months. ".repeat(4);
    let out = tables(&format!(
        "<table><tr><td><p>{prose}</p></td><td><p>{prose}</p></td></tr><tr><td><p>{prose}</p></td><td><p>{prose}</p></td></tr></table>"
    ));
    assert_ne!(out.tables[0].kind, TableKind::Data, "{:?}", out.tables[0]);
    assert!(out.tables[0].rows.is_empty());
}

#[test]
fn output_is_deterministic_and_serializable() {
    let body = "<table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>";
    let a = tables(body);
    let b = tables(body);
    assert_eq!(a, b);
    let json = serde_json::to_string(&a).unwrap();
    let back: TableExtraction = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
    assert!(json.contains("\"kind\":\"data\""));
}

#[test]
fn table_count_is_capped_and_flagged() {
    let many = "<table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>".repeat(300);
    let out = tables(&many);
    assert_eq!(out.tables.len(), 256);
    assert!(out.truncated);
}
