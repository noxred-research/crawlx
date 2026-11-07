#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Shared golden for the ranker's candidate row text (`role text region | tried n`).
//!
//! `tests/fixtures/row-render.json` is read by the Python trainer's tests, so both sides prove
//! they render the same bytes. The file is generated through the real path
//! ([`render_question`], the rendering the engine and the dataset recorder share). After an
//! intended change to the rendering, rewrite it with `CRAWLX_UPDATE_GOLDEN=1 cargo test -p
//! crawlx-model --test row_render`.

use crawlx_model::onnx_ranker::{render_question, ROW_SIGNALS, ROW_TRIED_CAP};
use crawlx_model::provenance::{Instruction, Provenance, ProvenanceTagged};
use crawlx_model::typed::{CandidateView, StateView};
use crawlx_model::{CandidateRef, TypedDecisionRequest, TypedQuestion};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/row-render.json");

/// `(role, text, region, tried)`. Every field is stable under the P2 sanitizer, so the golden
/// inputs are exactly what the renderer sees (the Python side need not sanitize).
const CASES: [(&str, &str, Option<&str>, u32); 18] = [
    ("button", "menu", None, 0),
    ("button", "menu", None, 2),
    ("button", "menu", None, 3),
    ("button", "menu", None, 7),
    ("link", "settings", Some("navigation:main"), 0),
    ("link", "settings", Some("navigation:main"), 1),
    ("link", "settings", Some("navigation:main"), 2),
    ("link", "settings", Some("navigation:main"), 3),
    ("link", "settings", Some("navigation:main"), 9),
    ("link", "settings", Some("navigation:main"), u32::MAX),
    // empty text and region: every empty field leaves its separating space
    ("button", "", None, 0),
    ("", "", None, 1),
    // an empty region renders exactly like a missing one
    ("textbox", "Search", Some(""), 1),
    ("textbox", "Search", None, 1),
    // non-ASCII text and region
    ("button", "Спасибо 日本語 ✓", Some("main"), 2),
    ("link", "café ☕ menu", Some("navigación:principal"), 3),
    // the bar and a digit inside the text are plain text
    ("combobox", "sort | newest 2", Some("toolbar"), 0),
    (
        "checkbox",
        "Remember me on this device for thirty days then ask again",
        Some("form:login"),
        5,
    ),
];

#[derive(Serialize, Deserialize)]
struct Case {
    role: String,
    text: String,
    region: Option<String>,
    tried: u32,
    row: String,
}

/// The candidate row of one case, taken from the shared question rendering.
fn rendered_row(role: &str, text: &str, region: Option<&str>, tried: u32) -> String {
    let cand = CandidateView::new(role, text, region).with_tried(tried);
    assert_eq!(
        (cand.role.as_str(), cand.text.as_str(), cand.region.as_deref()),
        (role, text, region),
        "golden inputs must survive sanitization"
    );
    let req = TypedDecisionRequest {
        goal: Instruction::from_static("Pick the next control."),
        state: ProvenanceTagged::new(
            Provenance::PageText,
            StateView {
                route_template: "/app".to_owned(),
                regions: Vec::new(),
                candidates: vec![cand],
            },
        ),
        questions: Vec::new(),
    };
    let question = TypedQuestion::Choice {
        id: "next_action".into(),
        options: vec![CandidateRef(0)],
    };
    let mut rows = render_question(&req, &question).rows;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], "none of these", "the none row is unchanged");
    rows.remove(1)
}

fn generated() -> String {
    let cases: Vec<Case> = CASES
        .iter()
        .map(|&(role, text, region, tried)| Case {
            role: role.to_owned(),
            text: text.to_owned(),
            region: region.map(str::to_owned),
            tried,
            row: rendered_row(role, text, region, tried),
        })
        .collect();
    let mut json = serde_json::to_string_pretty(&cases).unwrap();
    json.push('\n');
    json
}

/// The golden file's text. With `CRAWLX_UPDATE_GOLDEN=1` it is rewritten first, once, before any
/// test reads it (the tests run in parallel).
static COMMITTED: LazyLock<String> = LazyLock::new(|| {
    if std::env::var("CRAWLX_UPDATE_GOLDEN").is_ok_and(|v| v == "1") {
        std::fs::write(GOLDEN, generated()).unwrap();
    }
    std::fs::read_to_string(GOLDEN).unwrap()
});

#[test]
fn row_render_golden_matches_the_current_rendering() {
    assert_eq!(
        *COMMITTED,
        generated(),
        "tests/fixtures/row-render.json is stale; rewrite it with CRAWLX_UPDATE_GOLDEN=1"
    );
}

/// The committed rows follow the written contract, computed here without the renderer, so the
/// golden cannot drift together with a faulty renderer.
#[test]
fn committed_rows_follow_the_written_contract() {
    assert_eq!((ROW_SIGNALS, ROW_TRIED_CAP), (["tried"], 3));
    let cases: Vec<Case> = serde_json::from_str(&COMMITTED).unwrap();
    assert!(cases.len() >= 12, "{} cases", cases.len());
    for c in &cases {
        let region = c.region.as_deref().unwrap_or("");
        let n = c.tried.min(3);
        assert_eq!(
            c.row,
            format!("{} {} {} | tried {n}", c.role, c.text, region),
            "{} {}",
            c.role,
            c.text
        );
    }
    for tried in [0, 1, 2, 3, 9] {
        assert!(
            cases.iter().any(|c| c.tried == tried),
            "no case with tried {tried}"
        );
    }
    assert!(cases.iter().any(|c| c.region.is_none()));
    assert!(cases.iter().any(|c| c.region.as_deref() == Some("")));
    assert!(cases.iter().any(|c| !c.text.is_ascii()));
    assert!(cases.iter().any(|c| c.row == "button menu  | tried 0"));
}
