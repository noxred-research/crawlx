//! Grounded run and finding summaries.
//!
//! A deterministic accumulator turns the facts a run retained (counters, coverage, retained
//! pages, surface triage, operator-reviewed findings) into numbered facts with evidence ids.
//! The report's tables and sections are produced from those facts alone, so a summary exists
//! without any model. A model may add prose claims; each is checked against the accumulator
//! and dropped unless every cited id exists, every number it states appears in a cited fact,
//! its status is allowed (only an operator-reviewed finding can be `confirmed`), and it makes
//! no assertion the evidence cannot carry (CVSS scores, exploitability, completeness).

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Prompt label of the narrative call.
pub const PROMPT_VERSION: &str = "run-summary.prompt.v1";
/// Schema label of the narrative reply.
pub const SCHEMA_VERSION: &str = "run-narrative.v1";
/// Most facts offered to a model.
pub const MAX_MODEL_FACTS: usize = 120;

/// Section ids in report order.
pub const SECTIONS: [(&str, &str); 8] = [
    ("scope", "Scope"),
    ("work_performed", "Work performed"),
    ("observed_surfaces", "Observed surfaces"),
    ("reviewed_findings", "Reviewed findings"),
    ("hypotheses", "Hypotheses (unverified)"),
    ("blocked_paths", "Blocked paths"),
    ("recommended_manual_checks", "Recommended manual checks"),
    ("limitations", "Limitations"),
];

/// Operator-reviewed finding as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// Operator-chosen id.
    pub id: String,
    /// Short title.
    pub title: String,
    /// `confirmed`, `dismissed` or `needs_review`.
    pub status: String,
    /// `info`, `low`, `medium`, `high` or `critical` (an operator label, never a score).
    pub severity: String,
    /// Evidence ids the operator linked.
    pub evidence: Vec<String>,
}

/// One retained page as summary input.
#[derive(Clone, Debug)]
pub struct PageRef {
    /// Evidence id (`artifact:<id>` or `page:<id>`).
    pub reference: String,
    /// Host of the page.
    pub host: String,
    /// HTTP status.
    pub status: u16,
}

/// Everything a summary is computed from.
#[derive(Clone, Debug)]
pub struct SummaryInput {
    /// Run status label.
    pub status: String,
    /// Terminal reason label.
    pub terminal_reason: Option<String>,
    /// `urls` counters as JSON.
    pub urls: Value,
    /// Coverage summary as JSON.
    pub coverage: Value,
    /// Retained pages (possibly capped).
    pub pages: Vec<PageRef>,
    /// Retained pages before the cap.
    pub pages_total: usize,
    /// Surfaces of the latest stored triage.
    pub surfaces: Vec<Value>,
    /// Whether a triage was stored at all.
    pub triage_present: bool,
    /// Operator-reviewed findings.
    pub findings: Vec<Finding>,
    /// Whether the run is zero-data-retention (nothing derived is stored).
    pub zdr: bool,
}

/// One numbered fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    /// Fact id.
    pub id: String,
    /// Section the fact belongs to.
    pub section: &'static str,
    /// The statement.
    pub text: String,
    /// Status of the statement.
    pub status: &'static str,
    /// Evidence ids behind it (artifact, traffic, surface ids).
    pub evidence: Vec<String>,
}

/// The deterministic accumulator.
#[derive(Clone, Debug, Default)]
pub struct Accumulator {
    /// Facts by id, in insertion order of [`Accumulator::order`].
    pub facts: BTreeMap<String, Fact>,
    /// Fact ids in report order.
    pub order: Vec<String>,
    /// Confirmed finding ids (operator-reviewed).
    pub confirmed: BTreeSet<String>,
}

impl Accumulator {
    fn add(
        &mut self,
        id: &str,
        section: &'static str,
        status: &'static str,
        text: String,
        evidence: Vec<String>,
    ) {
        if self.facts.contains_key(id) {
            return;
        }
        self.order.push(id.to_owned());
        self.facts.insert(
            id.to_owned(),
            Fact {
                id: id.to_owned(),
                section,
                text,
                status,
                evidence,
            },
        );
    }

    /// Every id a claim may cite: fact ids and the evidence ids facts carry.
    #[must_use]
    pub fn citable(&self) -> BTreeSet<String> {
        let mut ids: BTreeSet<String> = self.facts.keys().cloned().collect();
        for fact in self.facts.values() {
            ids.extend(fact.evidence.iter().cloned());
        }
        ids
    }
}

fn n(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// Build the accumulator.
#[must_use]
pub fn accumulate(input: &SummaryInput) -> Accumulator {
    let mut acc = Accumulator::default();
    let reason = input.terminal_reason.as_deref().unwrap_or("none yet");
    acc.add(
        "run:status",
        "scope",
        "observed",
        format!("The run status is {} (terminal reason: {reason}).", input.status),
        Vec::new(),
    );
    let hosts: BTreeSet<&str> = input.pages.iter().map(|p| p.host.as_str()).collect();
    acc.add(
        "scope:hosts",
        "scope",
        "observed",
        format!(
            "{} host(s) have retained pages: {}.",
            hosts.len(),
            hosts.iter().copied().collect::<Vec<_>>().join(", ")
        ),
        input.pages.iter().take(8).map(|p| p.reference.clone()).collect(),
    );
    let u = &input.urls;
    acc.add(
        "work:urls",
        "work_performed",
        "observed",
        format!(
            "URLs: {} discovered, {} admitted, {} attempted, {} succeeded, {} failed, {} unreachable, {} with unknown outcome.",
            n(u, "discovered"), n(u, "admitted"), n(u, "attempted"), n(u, "succeeded"), n(u, "failed"),
            n(u, "unreachable"), n(u, "unknownOutcome")
        ),
        Vec::new(),
    );
    acc.add(
        "work:pages",
        "work_performed",
        "observed",
        format!(
            "{} page(s) are retained{}.",
            input.pages_total,
            if input.pages_total > input.pages.len() {
                format!("; {} were read for this summary", input.pages.len())
            } else {
                String::new()
            }
        ),
        input.pages.iter().take(8).map(|p| p.reference.clone()).collect(),
    );
    acc.add(
        "work:coverage",
        "work_performed",
        "observed",
        format!(
            "Coverage unit {}: {} discovered, {} exercised in the trusted lane.",
            input
                .coverage
                .get("unit")
                .and_then(Value::as_str)
                .unwrap_or("ActionContextKey"),
            n(&input.coverage, "discovered"),
            n(&input.coverage, "exercisedTrusted")
        ),
        Vec::new(),
    );
    let refused: Vec<&PageRef> = input
        .pages
        .iter()
        .filter(|p| matches!(p.status, 401 | 403))
        .collect();
    if !refused.is_empty() {
        acc.add(
            "blocked:refused_pages",
            "blocked_paths",
            "observed",
            format!("{} retained page(s) were refused with 401 or 403.", refused.len()),
            refused.iter().take(8).map(|p| p.reference.clone()).collect(),
        );
    }
    acc.add(
        "blocked:policy",
        "blocked_paths",
        "observed",
        format!(
            "{} discovered URL(s) were blocked by policy and {} by robots rules.",
            n(u, "policyBlocked"),
            n(u, "robotsBlocked")
        ),
        Vec::new(),
    );
    for surface in &input.surfaces {
        let id = surface["surfaceId"].as_str().unwrap_or_default();
        let fact_id = format!("surface:{id}");
        let route = format!(
            "{} {}",
            surface["method"].as_str().unwrap_or_default(),
            surface["route"].as_str().unwrap_or_default()
        );
        let evidence: Vec<String> = surface["evidenceRefs"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        let facts: Vec<&str> = surface["observedFacts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| f["fact"].as_str())
            .collect();
        if !facts.is_empty() {
            acc.add(
                &fact_id,
                "observed_surfaces",
                "observed",
                format!("{route}: {}.", facts.join("; ")),
                evidence.clone(),
            );
        }
        for (i, hypothesis) in surface["hypotheses"].as_array().into_iter().flatten().enumerate() {
            acc.add(
                &format!("hypothesis:{id}:{i}"),
                "hypotheses",
                "hypothesis",
                format!(
                    "{route}: {}",
                    hypothesis["statement"].as_str().unwrap_or_default()
                ),
                evidence.clone(),
            );
        }
        let checks: Vec<&str> = surface["labels"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter_map(check_for)
            .collect();
        if !checks.is_empty() {
            acc.add(
                &format!("check:{id}"),
                "recommended_manual_checks",
                "observed",
                format!("{route}: {}.", checks.join("; ")),
                evidence,
            );
        }
    }
    for finding in &input.findings {
        let fact_id = format!("finding:{}", finding.id);
        if finding.status == "confirmed" {
            acc.confirmed.insert(fact_id.clone());
        }
        let status = if finding.status == "confirmed" {
            "confirmed"
        } else {
            "observed"
        };
        acc.add(
            &fact_id,
            "reviewed_findings",
            status,
            format!(
                "Operator review of {:?}: status {}, severity label {}.",
                finding.title, finding.status, finding.severity
            ),
            finding.evidence.clone(),
        );
    }
    acc.add(
        "limits:retained_only",
        "limitations",
        "limitation",
        "This summary reads retained evidence only; nothing was fetched or tested to write it.".to_owned(),
        Vec::new(),
    );
    if n(u, "unknownOutcome") > 0 {
        acc.add(
            "limits:unknown_outcome",
            "limitations",
            "limitation",
            format!(
                "{} attempt(s) have an unknown outcome; coverage may be understated.",
                n(u, "unknownOutcome")
            ),
            Vec::new(),
        );
    }
    if input.pages_total > input.pages.len() {
        acc.add(
            "limits:pages_capped",
            "limitations",
            "limitation",
            format!(
                "Only the first {} of {} retained pages were read; the rest are not reflected here.",
                input.pages.len(),
                input.pages_total
            ),
            Vec::new(),
        );
    }
    if input.pages_total == 0 {
        acc.add(
            "limits:no_pages",
            "limitations",
            "limitation",
            "No page content is retained for this run (not recorded, expired or withheld), so no page-level observation can be reported.".to_owned(),
            Vec::new(),
        );
    }
    if !input.triage_present {
        acc.add(
            "limits:no_triage",
            "limitations",
            "limitation",
            "No surface triage is stored for this run; observed surfaces and hypotheses are not reported."
                .to_owned(),
            Vec::new(),
        );
    }
    if input.zdr {
        acc.add(
            "limits:zdr",
            "limitations",
            "limitation",
            "The run is zero-data-retention: derived summaries are returned but not stored.".to_owned(),
            Vec::new(),
        );
    }
    acc
}

fn check_for(label: &str) -> Option<&'static str> {
    Some(match label {
        "auth" => "review the authentication flow manually",
        "role_boundary" => "compare responses across roles manually",
        "upload" => "review upload handling manually",
        "admin" => "review access control of the administrative route manually",
        "search_input" | "object_reference" => "review input and object-reference handling manually",
        "export" => "review the scope of the exported data manually",
        "state_change" => "review protection of the state-changing request manually",
        _ => return None,
    })
}

/// A rendered claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// The statement.
    pub text: String,
    /// Evidence ids it cites.
    pub cites: Vec<String>,
    /// `observed`, `hypothesis`, `confirmed` or `limitation`.
    pub status: String,
    /// `crawlx` (deterministic) or `model`.
    pub origin: &'static str,
}

impl Claim {
    /// As JSON.
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({"text": self.text, "cites": self.cites, "status": self.status, "origin": self.origin})
    }
}

/// A section of claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// Section id.
    pub id: &'static str,
    /// Title.
    pub title: &'static str,
    /// Claims.
    pub claims: Vec<Claim>,
}

/// Which section ids a summary kind reports.
#[must_use]
pub fn kind_sections(kind: &str) -> Vec<&'static str> {
    if kind == "findings" {
        vec![
            "reviewed_findings",
            "hypotheses",
            "recommended_manual_checks",
            "limitations",
        ]
    } else {
        SECTIONS.iter().map(|(id, _)| *id).collect()
    }
}

/// The deterministic sections for `kind` (`run` or `findings`).
#[must_use]
pub fn sections(acc: &Accumulator, kind: &str) -> Vec<Section> {
    let wanted = kind_sections(kind);
    SECTIONS
        .iter()
        .filter(|(id, _)| wanted.contains(id))
        .map(|(id, title)| Section {
            id,
            title,
            claims: acc
                .order
                .iter()
                .filter_map(|fid| acc.facts.get(fid))
                .filter(|f| f.section == *id)
                .map(|f| {
                    let mut cites = vec![f.id.clone()];
                    cites.extend(f.evidence.iter().take(6).cloned());
                    Claim {
                        text: f.text.clone(),
                        cites,
                        status: f.status.to_owned(),
                        origin: "crawlx",
                    }
                })
                .collect(),
        })
        .collect()
}

/// `(record id, text)` pairs offered to a model: the facts of the wanted sections.
#[must_use]
pub fn model_records(acc: &Accumulator, kind: &str) -> Vec<(String, String)> {
    let wanted = kind_sections(kind);
    acc.order
        .iter()
        .filter_map(|id| acc.facts.get(id))
        .filter(|f| wanted.contains(&f.section))
        .take(MAX_MODEL_FACTS)
        .map(|f| {
            (
                f.id.clone(),
                format!(
                    "section: {}\nstatus: {}\nstatement: {}\nevidence: {}",
                    f.section,
                    f.status,
                    f.text,
                    f.evidence.join(", ")
                ),
            )
        })
        .collect()
}

/// The JSON Schema of the narrative reply.
#[must_use]
pub fn narrative_schema() -> Value {
    let ids: Vec<&str> = SECTIONS.iter().map(|(id, _)| *id).collect();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["sections"],
        "properties": {"sections": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "claims"],
                "properties": {
                    "id": {"type": "string", "enum": ids},
                    "claims": {"type": "array", "maxItems": 20, "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["text", "cites", "status"],
                        "properties": {
                            "text": {"type": "string", "maxLength": 500},
                            "cites": {"type": "array", "minItems": 1, "maxItems": 12, "items": {"type": "string", "maxLength": 160}},
                            "status": {"type": "string", "enum": ["observed", "hypothesis", "confirmed", "limitation"]},
                        },
                    }},
                },
            },
        }},
    })
}

const FORBIDDEN: [&str; 9] = [
    "cvss",
    "exploitab",
    "exploited",
    "weaponiz",
    "fully tested",
    "complete coverage",
    "100% coverage",
    "legally authorized",
    "has permission",
];
const CONFIRM_WORDS: [&str; 4] = ["confirmed", "verified vulnerab", "proven", "vulnerable"];

fn numbers_in(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut token = String::new();
    for c in text.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_digit() || (!token.is_empty() && matches!(c, '.' | ',')) {
            token.push(c);
        } else if !token.is_empty() {
            let plain: String = std::mem::take(&mut token)
                .trim_end_matches(['.', ','])
                .chars()
                .filter(|ch| *ch != ',')
                .collect();
            if !plain.is_empty() {
                out.insert(plain);
            }
        }
    }
    out
}

/// Validate the model's narrative against the accumulator. Returns the claims that passed,
/// grouped by section, and one rejection record per dropped claim.
#[must_use]
pub fn validate_narrative(
    acc: &Accumulator,
    kind: &str,
    reply: &Value,
) -> (BTreeMap<String, Vec<Claim>>, Vec<Value>) {
    let wanted = kind_sections(kind);
    let citable = acc.citable();
    let mut kept: BTreeMap<String, Vec<Claim>> = BTreeMap::new();
    let mut rejected = Vec::new();
    let empty = Vec::new();
    for section in reply.get("sections").and_then(Value::as_array).unwrap_or(&empty) {
        let id = section.get("id").and_then(Value::as_str).unwrap_or_default();
        for claim in section.get("claims").and_then(Value::as_array).unwrap_or(&empty) {
            let text = crawlx_model::provenance::sanitize_untrusted(
                claim.get("text").and_then(Value::as_str).unwrap_or_default(),
                500,
            );
            let status = claim
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let cites: Vec<String> = claim
                .get("cites")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
            let reject = |reason: &str| json!({"section": id, "text": text, "reason": reason});
            if !wanted.contains(&id) {
                rejected.push(reject("section_not_in_summary"));
                continue;
            }
            if text.is_empty() || cites.is_empty() {
                rejected.push(reject("missing_text_or_citation"));
                continue;
            }
            if let Some(bad) = cites.iter().find(|c| !citable.contains(*c)) {
                rejected.push(
                    json!({"section": id, "text": text, "reason": "unknown_citation", "citation": bad}),
                );
                continue;
            }
            let lower = text.to_lowercase();
            if FORBIDDEN.iter().any(|w| lower.contains(w)) {
                rejected.push(reject("unsupported_assertion"));
                continue;
            }
            let cited_facts: Vec<&Fact> = cites.iter().filter_map(|c| acc.facts.get(c)).collect();
            let is_confirmed = status == "confirmed";
            if is_confirmed && !cites.iter().any(|c| acc.confirmed.contains(c)) {
                rejected.push(reject("unreviewed_confirmation"));
                continue;
            }
            if !is_confirmed && CONFIRM_WORDS.iter().any(|w| lower.contains(w)) {
                rejected.push(reject("unsupported_assertion"));
                continue;
            }
            if status == "hypothesis" && cited_facts.iter().any(|f| f.status == "confirmed") {
                rejected.push(reject("status_mismatch"));
                continue;
            }
            // every number must appear in a cited fact (or in its evidence ids)
            let mut allowed: BTreeSet<String> = BTreeSet::new();
            for cite in &cites {
                allowed.extend(numbers_in(cite));
                if let Some(fact) = acc.facts.get(cite) {
                    allowed.extend(numbers_in(&fact.text));
                }
            }
            if let Some(number) = numbers_in(&text).into_iter().find(|v| !allowed.contains(v)) {
                rejected.push(json!({"section": id, "text": text, "reason": "number_not_in_cited_fact", "number": number}));
                continue;
            }
            if !matches!(
                status.as_str(),
                "observed" | "hypothesis" | "confirmed" | "limitation"
            ) {
                rejected.push(reject("status_not_allowed"));
                continue;
            }
            kept.entry(id.to_owned()).or_default().push(Claim {
                text,
                cites,
                status,
                origin: "model",
            });
        }
    }
    (kept, rejected)
}

/// Markdown for the sections, deterministic claims first and model claims marked as generated.
#[must_use]
pub fn render_markdown(kind: &str, sections: &[Section], model: &BTreeMap<String, Vec<Claim>>) -> String {
    let mut out = String::new();
    out.push_str(if kind == "findings" {
        "# Findings summary\n\n"
    } else {
        "# Run summary\n\n"
    });
    for section in sections {
        out.push_str(&format!("## {}\n\n", section.title));
        let generated = model.get(section.id);
        if section.claims.is_empty() && generated.is_none() {
            out.push_str("_Nothing to report._\n\n");
            continue;
        }
        for claim in &section.claims {
            out.push_str(&format!(
                "- {} _[{}; evidence: {}]_\n",
                claim.text,
                claim.status,
                claim.cites.join(", ")
            ));
        }
        for claim in generated.into_iter().flatten() {
            out.push_str(&format!(
                "- {} _[model-generated, checked against evidence; {}; evidence: {}]_\n",
                claim.text,
                claim.status,
                claim.cites.join(", ")
            ));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn input() -> SummaryInput {
        SummaryInput {
            status: "completed".to_owned(),
            terminal_reason: Some("frontier_exhausted".to_owned()),
            urls: json!({"discovered": 120, "admitted": 100, "attempted": 90, "succeeded": 80, "failed": 5, "unreachable": 3, "unknownOutcome": 2, "policyBlocked": 7, "robotsBlocked": 1}),
            coverage: json!({"unit": "ActionContextKey", "discovered": 40, "exercisedTrusted": 25}),
            pages: vec![
                PageRef {
                    reference: "artifact:a1".to_owned(),
                    host: "app.test".to_owned(),
                    status: 200,
                },
                PageRef {
                    reference: "artifact:a2".to_owned(),
                    host: "app.test".to_owned(),
                    status: 403,
                },
            ],
            pages_total: 2,
            surfaces: vec![json!({
                "surfaceId": "s1", "method": "POST", "route": "/upload",
                "labels": ["upload"], "observedFacts": [{"label": "upload", "fact": "a multipart request was observed", "evidence": ["traffic:1"]}],
                "hypotheses": [{"label": "admin", "statement": "the route name suggests an admin surface"}],
                "evidenceRefs": ["traffic:1"],
            })],
            triage_present: true,
            findings: vec![
                Finding {
                    id: "f1".to_owned(),
                    title: "Upload accepts any type".to_owned(),
                    status: "confirmed".to_owned(),
                    severity: "medium".to_owned(),
                    evidence: vec!["traffic:1".to_owned()],
                },
                Finding {
                    id: "f2".to_owned(),
                    title: "Maybe IDOR".to_owned(),
                    status: "needs_review".to_owned(),
                    severity: "low".to_owned(),
                    evidence: Vec::new(),
                },
            ],
            zdr: false,
        }
    }

    #[test]
    fn the_deterministic_report_needs_no_model_and_cites_everything() {
        let acc = accumulate(&input());
        let sections = sections(&acc, "run");
        assert_eq!(sections.len(), 8);
        for section in &sections {
            for claim in &section.claims {
                assert!(!claim.cites.is_empty());
                assert!(claim.cites.iter().all(|c| acc.citable().contains(c)));
            }
        }
        let md = render_markdown("run", &sections, &BTreeMap::new());
        assert!(md.contains("120 discovered"));
        assert!(md.contains("2 attempt(s) have an unknown outcome"));
        assert_eq!(
            md,
            render_markdown(
                "run",
                &super::sections(&accumulate(&input()), "run"),
                &BTreeMap::new()
            ),
            "deterministic"
        );
    }

    #[test]
    fn empty_and_partial_runs_state_their_limits() {
        let mut empty = input();
        empty.pages.clear();
        empty.pages_total = 0;
        empty.surfaces.clear();
        empty.triage_present = false;
        empty.findings.clear();
        let acc = accumulate(&empty);
        for id in ["limits:no_pages", "limits:no_triage", "limits:retained_only"] {
            assert!(acc.facts.contains_key(id), "{id}");
        }
        let mut capped = input();
        capped.pages_total = 500;
        assert!(accumulate(&capped).facts.contains_key("limits:pages_capped"));
    }

    #[test]
    fn model_claims_must_cite_real_evidence_and_real_numbers() {
        let acc = accumulate(&input());
        let reply = json!({"sections": [{"id": "work_performed", "claims": [
            {"text": "120 URLs were discovered and 80 succeeded.", "cites": ["work:urls"], "status": "observed"},
            {"text": "999 URLs were discovered.", "cites": ["work:urls"], "status": "observed"},
            {"text": "The crawl reached everything.", "cites": ["fact:invented"], "status": "observed"},
            {"text": "No citation.", "cites": [], "status": "observed"},
            {"text": "Coverage was complete coverage of the app.", "cites": ["work:coverage"], "status": "observed"},
        ]}]});
        let (kept, rejected) = validate_narrative(&acc, "run", &reply);
        assert_eq!(kept["work_performed"].len(), 1);
        let reasons: Vec<&str> = rejected.iter().map(|r| r["reason"].as_str().unwrap()).collect();
        assert_eq!(
            reasons,
            vec![
                "number_not_in_cited_fact",
                "unknown_citation",
                "missing_text_or_citation",
                "unsupported_assertion"
            ]
        );
    }

    #[test]
    fn a_model_cannot_promote_a_hypothesis_or_invent_a_confirmation() {
        let acc = accumulate(&input());
        let hypothesis = acc
            .order
            .iter()
            .find(|id| id.starts_with("hypothesis:"))
            .unwrap()
            .clone();
        let reply = json!({"sections": [
            {"id": "hypotheses", "claims": [
                {"text": "The admin surface is confirmed vulnerable.", "cites": [hypothesis.clone()], "status": "confirmed"},
                {"text": "The admin surface is vulnerable.", "cites": [hypothesis.clone()], "status": "hypothesis"},
                {"text": "The route name suggests an admin surface.", "cites": [hypothesis], "status": "hypothesis"},
            ]},
            {"id": "reviewed_findings", "claims": [
                {"text": "Upload accepts any type (operator reviewed).", "cites": ["finding:f1"], "status": "confirmed"},
                {"text": "Maybe IDOR is confirmed.", "cites": ["finding:f2"], "status": "confirmed"},
                {"text": "The exploit chain has a CVSS of 9.8.", "cites": ["finding:f1"], "status": "observed"},
            ]},
        ]});
        let (kept, rejected) = validate_narrative(&acc, "run", &reply);
        assert_eq!(kept["hypotheses"].len(), 1);
        assert_eq!(kept["reviewed_findings"].len(), 1);
        let reasons: Vec<&str> = rejected.iter().map(|r| r["reason"].as_str().unwrap()).collect();
        assert_eq!(
            reasons,
            vec![
                "unreviewed_confirmation",
                "unsupported_assertion",
                "unreviewed_confirmation",
                "unsupported_assertion"
            ]
        );
    }

    #[test]
    fn findings_summaries_report_only_review_material() {
        let acc = accumulate(&input());
        let ids: Vec<&str> = sections(&acc, "findings").iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            vec![
                "reviewed_findings",
                "hypotheses",
                "recommended_manual_checks",
                "limitations"
            ]
        );
        let reply = json!({"sections": [{"id": "work_performed", "claims": [{"text": "x", "cites": ["work:urls"], "status": "observed"}]}]});
        let (kept, rejected) = validate_narrative(&acc, "findings", &reply);
        assert!(kept.is_empty());
        assert_eq!(rejected[0]["reason"], "section_not_in_summary");
    }
}
