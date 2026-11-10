//! Observations derived from wire captures and their comparison under the divergence ledger
//! (request decision, terminal status, cancel behavior, event stream).
//!
//! Each scenario of a capture is reduced to named [`Observation`]s by [`observe`]; the same
//! function runs on both sides, so a systematic formatting difference cancels out. A *hard*
//! observation is a behavior (accept or reject, terminal status, whether a cancelled crawl goes
//! quiet, the webhook event sequence): an undocumented difference blocks. A soft one is
//! explanatory (HTTP code, error code, counters, envelope keys): an undocumented difference
//! warns. The ledger entry kind is `behavior`, matched on `<scenario>/<observation>`.

use super::{ScenarioCapture, WireCapture};
use crate::differential::ledger::{DivergenceKind, Ledger};
use crate::differential::normalize::url_key;
use crate::differential::{Finding, Severity, Verdict};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use url::Url;

/// A stale-lease SLO: a killed worker's job must be re-leased within two minutes.
const LEASE_SLO_MS: u64 = 120_000;

/// One named fact about a scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Observation {
    /// The value, rendered as text.
    pub value: String,
    /// A hard observation blocks when it differs without a ledger entry; a soft one warns.
    pub hard: bool,
}

fn hard(v: impl Into<String>) -> Observation {
    Observation {
        value: v.into(),
        hard: true,
    }
}

fn soft(v: impl Into<String>) -> Observation {
    Observation {
        value: v.into(),
        hard: false,
    }
}

/// `accept` (2xx), `reject` (4xx), `error` (5xx) or `unreachable` (no response).
#[must_use]
pub const fn decision(status: u16) -> &'static str {
    match status {
        200..=299 => "accept",
        400..=499 => "reject",
        0 => "unreachable",
        _ => "error",
    }
}

fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

/// First path segment of every `details[]` entry of a rejection body, sorted, joined with `,`.
fn blamed_fields(body: &Value) -> String {
    let mut out: BTreeSet<String> = BTreeSet::new();
    if let Some(Value::Array(details)) = body.get("details") {
        for d in details {
            match d.get("path") {
                // zod style: ["webhook", "url"]
                Some(Value::Array(path)) => {
                    if let Some(first) = path.first() {
                        out.insert(text(Some(first)));
                    }
                }
                // JSON-pointer style: "/webhook/url"
                Some(Value::String(p)) => {
                    if let Some(first) = p.split('/').find(|s| !s.is_empty()) {
                        out.insert(first.to_owned());
                    }
                }
                _ => {}
            }
            if let Some(Value::Array(keys)) = d.get("keys") {
                out.extend(keys.iter().map(|k| text(Some(k))));
            }
        }
    }
    out.into_iter().collect::<Vec<_>>().join(",")
}

fn has_warning(body: &Value) -> bool {
    ["warning", "warnings"].iter().any(|k| {
        body.get(*k).is_some_and(|w| match w {
            Value::Null => false,
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            _ => true,
        })
    })
}

/// `crawl.started, crawl.page*3, crawl.completed`: consecutive equal types folded.
fn fold_sequence(types: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < types.len() {
        let n = types[i..].iter().take_while(|t| **t == types[i]).count();
        out.push(if n > 1 {
            format!("{}*{n}", types[i])
        } else {
            types[i].clone()
        });
        i += n;
    }
    out.join(",")
}

fn webhook_observations(events: &[Value], request: Option<&Value>, out: &mut BTreeMap<String, Observation>) {
    let bodies: Vec<&Value> = events
        .iter()
        .map(|e| e.get("body").unwrap_or(&Value::Null))
        .collect();
    let types: Vec<String> = bodies.iter().map(|b| text(b.get("type"))).collect();
    out.insert("webhook.types".to_owned(), hard(fold_sequence(&types)));
    let terminal = types
        .iter()
        .filter(|t| matches!(t.as_str(), "crawl.completed" | "crawl.failed"))
        .count();
    out.insert("webhook.terminal_events".to_owned(), hard(terminal.to_string()));
    out.insert("webhook.deliveries".to_owned(), soft(events.len().to_string()));
    let mut envelope: BTreeMap<&str, String> = BTreeMap::new();
    for (t, b) in types.iter().zip(&bodies) {
        envelope.entry(t.as_str()).or_insert_with(|| {
            b.as_object()
                .map(|m| m.keys().cloned().collect::<Vec<_>>().join(","))
                .unwrap_or_default()
        });
    }
    for (t, keys) in envelope {
        out.insert(format!("webhook.envelope.{t}"), soft(keys));
    }
    let hook = request.and_then(|r| r.get("webhook"));
    if let Some(meta) = hook.and_then(|h| h.get("metadata")) {
        let echoed = !bodies.is_empty() && bodies.iter().all(|b| b.get("metadata") == Some(meta));
        out.insert(
            "webhook.metadata_echo".to_owned(),
            hard(if echoed { "echoed" } else { "missing" }),
        );
    }
    if let Some(Value::Object(want)) = hook.and_then(|h| h.get("headers")) {
        let echoed = !events.is_empty()
            && events.iter().all(|e| {
                want.iter().all(|(k, v)| {
                    e.get("headers")
                        .and_then(|h| h.get(k.to_ascii_lowercase()))
                        .and_then(Value::as_str)
                        == v.as_str()
                })
            });
        out.insert(
            "webhook.headers_echo".to_owned(),
            hard(if echoed { "echoed" } else { "missing" }),
        );
    }
    out.insert(
        "webhook.success_flag".to_owned(),
        soft(
            if !bodies.is_empty()
                && bodies
                    .iter()
                    .all(|b| b.get("success") == Some(&Value::Bool(true)))
            {
                "all true"
            } else {
                "not all true"
            },
        ),
    );
    let page_data: BTreeSet<String> = types
        .iter()
        .zip(&bodies)
        .filter(|(t, _)| t.as_str() == "crawl.page")
        .map(|(_, b)| match b.get("data") {
            Some(Value::Array(a)) => format!("array({})", a.len()),
            Some(Value::Null) | None => "none".to_owned(),
            Some(_) => "other".to_owned(),
        })
        .collect();
    if !page_data.is_empty() {
        out.insert(
            "webhook.page_data".to_owned(),
            soft(page_data.into_iter().collect::<Vec<_>>().join(",")),
        );
    }
    let signatures: BTreeSet<String> = events
        .iter()
        .filter_map(|e| e.get("headers").and_then(Value::as_object))
        .flat_map(|h| h.keys().filter(|k| k.contains("signature")).cloned())
        .collect();
    out.insert(
        "webhook.signature_headers".to_owned(),
        soft(signatures.into_iter().collect::<Vec<_>>().join(",")),
    );
    let content_type = events
        .first()
        .and_then(|e| e.get("headers"))
        .and_then(|h| h.get("content-type"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    out.insert(
        "webhook.content_type".to_owned(),
        soft(content_type.split(';').next().unwrap_or_default().trim()),
    );
    let failed: Vec<&Value> = events
        .iter()
        .filter(|e| e.get("replied").and_then(Value::as_u64).is_some_and(|s| s >= 400))
        .map(|e| e.get("body").unwrap_or(&Value::Null))
        .collect();
    if !failed.is_empty() {
        let retried = failed.iter().all(|f| {
            events
                .iter()
                .filter(|e| e.get("replied").and_then(Value::as_u64).is_some_and(|s| s < 400))
                .any(|e| e.get("body") == Some(*f))
        });
        out.insert(
            "webhook.redelivered_after_failure".to_owned(),
            hard(if retried { "retried" } else { "dropped" }),
        );
    }
}

/// Derive the observations of one scenario. `origin` is the origin the system reached the gym
/// on: document URLs are rebased against it, so two systems on different hosts compare equal.
#[must_use]
pub fn observe(origin: &Url, s: &ScenarioCapture) -> BTreeMap<String, Observation> {
    let mut out: BTreeMap<String, Observation> = BTreeMap::new();
    for ex in &s.exchanges {
        let step = match ex.step.as_str() {
            "request" | "settle" => ex.step.clone(),
            other if other.starts_with("after:") => other.to_owned(),
            _ => continue,
        };
        out.insert(format!("{step}.decision"), hard(decision(ex.status)));
        out.insert(format!("{step}.http"), soft(ex.status.to_string()));
        out.insert(format!("{step}.code"), soft(text(ex.response.get("code"))));
        out.insert(format!("{step}.fields"), soft(blamed_fields(&ex.response)));
        out.insert(
            format!("{step}.warning"),
            soft(has_warning(&ex.response).to_string()),
        );
        if let Some(status) = ex.response.get("status") {
            out.insert(format!("{step}.status"), soft(text(Some(status))));
        }
    }
    if let Some(fin) = s.exchange("final") {
        let b = &fin.response;
        out.insert("final.status".to_owned(), hard(text(b.get("status"))));
        out.insert("final.total".to_owned(), soft(text(b.get("total"))));
        out.insert("final.completed".to_owned(), soft(text(b.get("completed"))));
        let mut urls: BTreeSet<String> = BTreeSet::new();
        if let Some(Value::Array(docs)) = b.get("data") {
            for d in docs {
                if let Some(u) = d.get("sourceURL").and_then(Value::as_str) {
                    urls.insert(url_key(u, origin, true));
                }
            }
        }
        out.insert(
            "final.urls".to_owned(),
            hard(urls.into_iter().collect::<Vec<_>>().join(" ")),
        );
    }
    if let Some(Value::Number(n)) = s.notes.get("quiet_requests") {
        let n = n.as_u64().unwrap_or(0);
        out.insert("quiet".to_owned(), hard(if n == 0 { "quiet" } else { "active" }));
        out.insert("quiet.requests".to_owned(), soft(n.to_string()));
    }
    if let Some(hook) = s.notes.get("hook") {
        out.insert(
            "hook.ok".to_owned(),
            hard(
                hook.get("ok")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    .to_string(),
            ),
        );
        if let Some(ms) = s.notes.get("hook_to_final_ms").and_then(Value::as_u64) {
            out.insert(
                "resumed_within_slo".to_owned(),
                hard((ms <= LEASE_SLO_MS).to_string()),
            );
        }
    }
    if let Some(Value::Array(events)) = s.notes.get("sink_events") {
        webhook_observations(
            events,
            s.exchange("request").and_then(|e| e.request.as_ref()),
            &mut out,
        );
    }
    out
}

/// One compared observation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObservationRow {
    /// Scenario id.
    pub scenario: String,
    /// Observation name.
    pub name: String,
    /// Upstream value; empty when the observation exists on the crawlx side only.
    pub upstream: Option<String>,
    /// crawlx value.
    pub crawlx: Option<String>,
    /// Hard or soft.
    pub hard: bool,
    /// Ledger id when the difference is documented.
    pub documented: Option<String>,
}

impl ObservationRow {
    /// Both sides observed the same value.
    #[must_use]
    pub fn equal(&self) -> bool {
        self.upstream == self.crawlx
    }
}

/// The comparison of two captures of one family.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct WireReport {
    /// Family id.
    pub label: String,
    /// Scenarios compared.
    pub scenarios: Vec<String>,
    /// Every observation of every scenario.
    pub rows: Vec<ObservationRow>,
    /// Differences, blocking first.
    pub findings: Vec<Finding>,
    /// Ledger entries no finding matched.
    pub unused_entries: Vec<String>,
}

impl WireReport {
    /// The verdict.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        match self.findings.iter().map(|f| f.severity).max() {
            Some(Severity::Blocking) => Verdict::Block,
            Some(Severity::Warning) => Verdict::Warn,
            _ => Verdict::Pass,
        }
    }

    /// Process exit code: `0` pass (or warn unless `fail_on_warning`), `1` block, `3` warn
    /// with `fail_on_warning`.
    #[must_use]
    pub fn exit_code(&self, fail_on_warning: bool) -> u8 {
        match self.verdict() {
            Verdict::Pass => 0,
            Verdict::Warn if fail_on_warning => 3,
            Verdict::Warn => 0,
            _ => 1,
        }
    }

    /// The markdown scorecard.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let count = |s: Severity| self.findings.iter().filter(|f| f.severity == s).count();
        let mut out = String::new();
        let _ = writeln!(out, "# Differential scorecard (wire): {}\n", self.label);
        let _ = writeln!(
            out,
            "Verdict: **{:?}** ({} blocking, {} warnings, {} documented)\n",
            self.verdict(),
            count(Severity::Blocking),
            count(Severity::Warning),
            count(Severity::Documented)
        );
        let total = self.rows.len();
        let equal = self.rows.iter().filter(|r| r.equal()).count();
        let _ = writeln!(
            out,
            "| Metric | Value |\n|---|---:|\n| scenarios compared | {} |\n| observations | {total} |\n| observations equal | {equal} |\n",
            self.scenarios.len()
        );
        let _ = writeln!(out, "## Scenarios\n");
        let _ = writeln!(out, "| Scenario | Upstream | crawlx | Agree |\n|---|---|---|---|");
        for id in &self.scenarios {
            let rows: Vec<&ObservationRow> = self.rows.iter().filter(|r| &r.scenario == id).collect();
            let headline = |side: fn(&ObservationRow) -> &Option<String>| -> String {
                [
                    "request.decision",
                    "final.status",
                    "settle.decision",
                    "webhook.types",
                ]
                .iter()
                .filter_map(|n| rows.iter().find(|r| r.name == *n).and_then(|r| side(r).clone()))
                .collect::<Vec<_>>()
                .join(" / ")
            };
            let all_equal = rows.iter().all(|r| r.equal());
            let _ = writeln!(
                out,
                "| `{id}` | {} | {} | {} |",
                headline(|r| &r.upstream),
                headline(|r| &r.crawlx),
                if all_equal { "yes" } else { "**no**" }
            );
        }
        let _ = writeln!(out, "\n## Differences\n");
        let different: Vec<&ObservationRow> = self.rows.iter().filter(|r| !r.equal()).collect();
        if different.is_empty() {
            let _ = writeln!(out, "None: every observation is equal.");
        } else {
            let _ = writeln!(
                out,
                "| Scenario | Observation | Upstream | crawlx | Kind | Ledger |\n|---|---|---|---|---|---|"
            );
            for r in different {
                let _ = writeln!(
                    out,
                    "| `{}` | `{}` | `{}` | `{}` | {} | {} |",
                    r.scenario,
                    r.name,
                    r.upstream.as_deref().unwrap_or("(absent)"),
                    r.crawlx.as_deref().unwrap_or("(absent)"),
                    if r.hard { "hard" } else { "soft" },
                    r.documented.as_deref().unwrap_or("**undocumented**")
                );
            }
        }
        let _ = writeln!(out, "\n## Findings\n");
        if self.findings.is_empty() {
            let _ = writeln!(out, "None.");
        }
        for f in &self.findings {
            let _ = writeln!(
                out,
                "- {:?} `{}`: {}{}",
                f.severity,
                f.subject,
                f.detail,
                f.documented
                    .as_deref()
                    .map_or(String::new(), |d| format!(" [{d}]"))
            );
        }
        if !self.unused_entries.is_empty() {
            let _ = writeln!(
                out,
                "\nLedger entries not exercised: {}",
                self.unused_entries.join(", ")
            );
        }
        out
    }
}

/// Compare two captures of the family `label` under `ledger` (entries without a `families`
/// list, and those naming `label`).
///
/// # Errors
/// A message when an origin of a capture is not a URL.
pub fn compare(
    label: &str,
    upstream: &WireCapture,
    crawlx: &WireCapture,
    ledger: &Ledger,
) -> Result<WireReport, String> {
    let ledger = ledger.for_family(label);
    let origin = |c: &WireCapture| {
        Url::parse(&c.wire_sample.origin).map_err(|e| format!("origin `{}`: {e}", c.wire_sample.origin))
    };
    let (fo, co) = (origin(upstream)?, origin(crawlx)?);
    let mut rows = Vec::new();
    let mut findings = Vec::new();
    let mut used: BTreeSet<String> = BTreeSet::new();
    let mut scenarios = Vec::new();
    let ids: BTreeSet<&str> = upstream
        .scenarios
        .iter()
        .chain(&crawlx.scenarios)
        .map(|s| s.id.as_str())
        .collect();
    for id in ids {
        let (Some(f), Some(c)) = (upstream.scenario(id), crawlx.scenario(id)) else {
            findings.push(Finding {
                severity: Severity::Blocking,
                kind: DivergenceKind::Behavior,
                subject: id.to_owned(),
                detail: "scenario captured on one side only".to_owned(),
                documented: None,
            });
            continue;
        };
        scenarios.push(id.to_owned());
        let (fo_obs, co_obs) = (observe(&fo, f), observe(&co, c));
        let names: BTreeSet<&String> = fo_obs.keys().chain(co_obs.keys()).collect();
        for name in names {
            let (a, b) = (fo_obs.get(name), co_obs.get(name));
            let is_hard = a.is_some_and(|o| o.hard) || b.is_some_and(|o| o.hard);
            let mut row = ObservationRow {
                scenario: id.to_owned(),
                name: name.clone(),
                upstream: a.map(|o| o.value.clone()),
                crawlx: b.map(|o| o.value.clone()),
                hard: is_hard,
                documented: None,
            };
            if !row.equal() {
                let subject = format!("{id}/{name}");
                row.documented = ledger.behavior(&subject).map(|d| d.id.clone());
                if let Some(d) = &row.documented {
                    used.insert(d.clone());
                }
                findings.push(Finding {
                    severity: match (&row.documented, is_hard) {
                        (Some(_), _) => Severity::Documented,
                        (None, true) => Severity::Blocking,
                        (None, false) => Severity::Warning,
                    },
                    kind: DivergenceKind::Behavior,
                    detail: format!(
                        "upstream `{}` vs crawlx `{}`",
                        row.upstream.as_deref().unwrap_or("(absent)"),
                        row.crawlx.as_deref().unwrap_or("(absent)")
                    ),
                    subject,
                    documented: row.documented.clone(),
                });
            }
            rows.push(row);
        }
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.subject.cmp(&b.subject))
    });
    let unused_entries = ledger
        .entries
        .iter()
        .filter(|e| !used.contains(&e.id))
        .map(|e| e.id.clone())
        .collect();
    Ok(WireReport {
        label: label.to_owned(),
        scenarios,
        rows,
        findings,
        unused_entries,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::differential::wire::{Exchange, WireProvenance};
    use serde_json::json;

    fn ex(step: &str, status: u16, response: Value) -> Exchange {
        Exchange {
            step: step.to_owned(),
            method: "POST".to_owned(),
            path: "/v2/crawl".to_owned(),
            request: None,
            status,
            response,
            elapsed_ms: 1,
        }
    }

    fn capture(origin: &str, scenarios: Vec<ScenarioCapture>) -> WireCapture {
        WireCapture {
            wire_sample: WireProvenance {
                provenance: "test".to_owned(),
                system: "x".to_owned(),
                api_root: "http://api".to_owned(),
                origin: origin.to_owned(),
                ..WireProvenance::default()
            },
            family: "f".to_owned(),
            scenarios,
            access_log: None,
        }
    }

    fn scenario(id: &str, exchanges: Vec<Exchange>) -> ScenarioCapture {
        ScenarioCapture {
            id: id.to_owned(),
            exchanges,
            ..ScenarioCapture::default()
        }
    }

    #[test]
    fn decisions_and_blamed_fields_are_extracted() {
        assert_eq!(decision(200), "accept");
        assert_eq!(decision(400), "reject");
        assert_eq!(decision(403), "reject");
        assert_eq!(decision(500), "error");
        assert_eq!(decision(0), "unreachable");
        let body = json!({"details": [
            {"path": ["limit"], "code": "invalid_type"},
            {"path": [], "keys": ["bogus"]},
            {"path": ["webhook", "url"]}
        ]});
        assert_eq!(blamed_fields(&body), "bogus,limit,webhook");
    }

    #[test]
    fn equal_decisions_pass_and_a_different_decision_blocks_until_documented() {
        let fc = capture(
            "http://gym.test:4101",
            vec![
                scenario(
                    "a",
                    vec![ex(
                        "request",
                        400,
                        json!({"code": "BAD_REQUEST", "details": [{"path": ["limit"]}]}),
                    )],
                ),
                scenario(
                    "b",
                    vec![
                        ex("request", 200, json!({"id": "x"})),
                        ex("settle", 200, json!({"status": "cancelled"})),
                    ],
                ),
            ],
        );
        let cx = capture(
            "http://site.example.test:9",
            vec![
                scenario(
                    "a",
                    vec![ex(
                        "request",
                        400,
                        json!({"code": "VALIDATION", "details": [{"path": ["limit"]}]}),
                    )],
                ),
                scenario(
                    "b",
                    vec![
                        ex("request", 400, json!({"error": "no"})),
                        ex("settle", 200, json!({"status": "cancelled"})),
                    ],
                ),
            ],
        );
        let r = compare("f", &fc, &cx, &Ledger::default()).unwrap();
        assert_eq!(r.verdict(), Verdict::Block, "{}", r.to_markdown());
        let subjects: Vec<&str> = r.findings.iter().map(|f| f.subject.as_str()).collect();
        assert!(subjects.contains(&"b/request.decision"), "{subjects:?}");
        assert!(subjects.contains(&"a/request.code"), "{subjects:?}");
        let ledger = Ledger::parse(
            r#"
[[divergence]]
id = "VAL-900"
family = "VAL"
level = "C0"
kind = "behavior"
match = "b/*"
class = "intentional_correctness"
source = "test"
rationale = "r"
user_visible = "u"
[[divergence]]
id = "VAL-901"
family = "VAL"
level = "C0"
kind = "behavior"
match = "a/request.code"
class = "unsupported_feature"
source = "test"
rationale = "r"
"#,
        )
        .unwrap();
        let r = compare("f", &fc, &cx, &ledger).unwrap();
        assert_eq!(r.verdict(), Verdict::Pass, "{}", r.to_markdown());
        assert!(r.unused_entries.is_empty());
        assert!(r.to_markdown().contains("VAL-900"));
    }

    #[test]
    fn final_urls_are_rebased_and_cancel_quiet_is_a_hard_observation() {
        let mk = |origin: &str, quiet: u64| {
            let mut s = scenario(
                "c",
                vec![
                    ex("request", 200, json!({"id": "1"})),
                    ex(
                        "final",
                        200,
                        json!({"status": "cancelled", "total": 9, "completed": 3, "data": [
                            {"sourceURL": format!("{origin}/d2/slow/"), "statusCode": 200},
                            {"sourceURL": format!("{origin}/d2/slow/p/1"), "statusCode": 200}
                        ]}),
                    ),
                ],
            );
            s.notes.insert("quiet_requests".to_owned(), json!(quiet));
            capture(origin, vec![s])
        };
        let a = observe(
            &Url::parse("http://gym.test:4101").unwrap(),
            &mk("http://gym.test:4101", 0).scenarios[0],
        );
        let b = observe(
            &Url::parse("http://h.test:7").unwrap(),
            &mk("http://h.test:7", 4).scenarios[0],
        );
        assert_eq!(a["final.urls"], b["final.urls"]);
        assert_eq!(a["final.urls"].value, "{origin}/d2/slow {origin}/d2/slow/p/1");
        assert_eq!(a["quiet"].value, "quiet");
        assert_eq!(b["quiet"].value, "active");
        assert!(a["quiet"].hard && !a["quiet.requests"].hard);
    }

    #[test]
    fn webhook_events_reduce_to_a_sequence_envelope_and_echo() {
        let req = json!({"webhook": {"url": "u", "headers": {"X-Diff": "1"}, "metadata": {"run": "wh"}}});
        let event = |t: &str, replied: u64, data: Value| {
            json!({
                "label": "wh", "seq": 1, "replied": replied,
                "headers": {"x-diff": "1", "content-type": "application/json; charset=utf-8", "x-firecrawl-signature": "sha256=x"}, // wire-compat: webhook signature header
                "body": {"success": true, "type": t, "id": "j", "data": data, "metadata": {"run": "wh"}}
            })
        };
        let events = vec![
            event("crawl.started", 200, json!([])),
            event("crawl.page", 500, json!([{"markdown": "x"}])),
            event("crawl.page", 200, json!([{"markdown": "x"}])),
            event("crawl.page", 200, json!([{"markdown": "y"}])),
            event("crawl.completed", 200, json!([])),
        ];
        let mut out = BTreeMap::new();
        webhook_observations(&events, Some(&req), &mut out);
        assert_eq!(
            out["webhook.types"].value,
            "crawl.started,crawl.page*3,crawl.completed"
        );
        assert_eq!(out["webhook.terminal_events"].value, "1");
        assert_eq!(out["webhook.metadata_echo"].value, "echoed");
        assert_eq!(out["webhook.headers_echo"].value, "echoed");
        assert_eq!(out["webhook.signature_headers"].value, "x-firecrawl-signature"); // wire-compat: webhook signature header
        assert_eq!(out["webhook.page_data"].value, "array(1)");
        assert_eq!(
            out["webhook.envelope.crawl.page"].value,
            "data,id,metadata,success,type"
        );
        assert_eq!(out["webhook.redelivered_after_failure"].value, "retried");
        assert_eq!(out["webhook.content_type"].value, "application/json");
    }

    #[test]
    fn a_scenario_on_one_side_only_blocks() {
        let fc = capture(
            "http://a:1",
            vec![scenario("only", vec![ex("request", 200, json!({"id": "1"}))])],
        );
        let cx = capture("http://b:1", vec![]);
        let r = compare("f", &fc, &cx, &Ledger::default()).unwrap();
        assert_eq!(r.verdict(), Verdict::Block);
    }
}
