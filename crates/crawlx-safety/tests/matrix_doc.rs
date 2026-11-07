//! Exhaustive matrix test: the `(RiskClass, profile)` table in
//! `docs/design/safety-matrix.md` is the kernel's own rendering
//! (`risk_matrix_markdown()`), so docs and code cannot drift. `CRAWLX_BLESS=1` rewrites
//! the documented section from the kernel.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::config::SafetyProfile;
use crawlx_core::safety::{RiskClass, SafetyDecision};
use crawlx_safety::{risk_matrix_cell, risk_matrix_markdown, MATRIX_CLASSES, MATRIX_PROFILES};
use std::path::PathBuf;

const BEGIN: &str = "<!-- risk-matrix:begin";
const END: &str = "<!-- risk-matrix:end -->";

fn doc_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/design/safety-matrix.md")
}

/// `(before, table, after)` around the generated section; `before` ends with the begin
/// marker line and `after` starts with the end marker.
fn split(doc: &str) -> (&str, &str, &str) {
    let begin = doc.find(BEGIN).expect("begin marker");
    let begin_eol = begin + doc[begin..].find('\n').expect("begin marker line") + 1;
    let end = doc.find(END).expect("end marker");
    assert!(begin_eol <= end, "markers out of order");
    (&doc[..begin_eol], &doc[begin_eol..end], &doc[end..])
}

#[test]
fn documented_matrix_equals_the_kernel_rendering() {
    let path = doc_path();
    let doc = std::fs::read_to_string(&path).unwrap();
    let (before, documented, after) = split(&doc);
    let generated = risk_matrix_markdown();
    if std::env::var_os("CRAWLX_BLESS").is_some() && documented != generated {
        std::fs::write(&path, format!("{before}{generated}{after}")).unwrap();
        return;
    }
    assert_eq!(
        documented, generated,
        "docs/design/safety-matrix.md matrix differs from risk_matrix_markdown(); run with CRAWLX_BLESS=1 to rewrite"
    );
}

#[test]
fn every_class_and_profile_has_exactly_one_row_and_column() {
    let table = risk_matrix_markdown();
    let rows: Vec<&str> = table.lines().collect();
    assert_eq!(rows.len(), 2 + MATRIX_CLASSES.len());
    assert!(rows[0].starts_with("| Class |"));
    for (row, class) in rows[2..].iter().zip(MATRIX_CLASSES) {
        let cells: Vec<&str> = row.trim_matches('|').split('|').map(str::trim).collect();
        assert_eq!(cells.len(), 1 + MATRIX_PROFILES.len(), "{row}");
        assert_eq!(cells[0], format!("`{}`", class.as_str()));
    }
    let mut seen = std::collections::BTreeSet::new();
    for class in MATRIX_CLASSES {
        assert!(seen.insert(class), "{class:?} listed twice");
    }
    assert_eq!(
        seen.len(),
        11,
        "every RiskClass variant must appear once; add new variants to MATRIX_CLASSES"
    );
}

#[test]
fn cells_carry_the_decision_word_of_the_default_table() {
    for class in MATRIX_CLASSES {
        for profile in MATRIX_PROFILES {
            let cell = risk_matrix_cell(class, profile);
            let word = cell.split(' ').next().unwrap();
            let expected = match class.default_decision(profile, true) {
                SafetyDecision::Allow => "allow",
                SafetyDecision::Deny => "deny",
                SafetyDecision::ApprovalRequired => "approval",
            };
            assert_eq!(word, expected, "{class:?} under {profile:?}: {cell}");
        }
    }
    assert_eq!(
        risk_matrix_cell(RiskClass::ExternalCommunication, SafetyProfile::ReadOnly),
        "deny"
    );
    assert_eq!(
        risk_matrix_cell(RiskClass::ExternalCommunication, SafetyProfile::TestEnvironment),
        "allow (configured test sinks only)"
    );
    assert_eq!(
        risk_matrix_cell(RiskClass::FileUpload, SafetyProfile::AuthorizedSecurityTest),
        "allow (fixture files only)"
    );
    assert_eq!(
        risk_matrix_cell(
            RiskClass::PersistentWriteOtherPrincipal,
            SafetyProfile::AuthorizedSecurityTest
        ),
        "allow (recorded as cross-principal probe)"
    );
    assert_eq!(
        risk_matrix_cell(RiskClass::OutOfScope, SafetyProfile::AuthorizedSecurityTest),
        "deny"
    );
}
