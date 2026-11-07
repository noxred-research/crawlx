//! Golden per-`(strategy, version)` proposal snapshots.
//!
//! One fixed `DecisionContext` (about fifty candidates: links in and out of scope, visited
//! and unvisited; buttons, some with risk classes; form controls; hidden items reachable
//! through a known menu) is fed to every deterministic production strategy in three
//! phases. The proposals land in
//! `fixtures/golden/strategies/<strategy>-v<version>.json`. The test fails when:
//!
//! * the file for `(name(), version())` is missing — bless it;
//! * the proposals differ from the file — bump `VERSION` in the strategy module and bless;
//! * a file's embedded version differs from its name, or a file names a strategy that is
//!   not registered.
//!
//! `CRAWLX_BLESS=1 cargo test -p crawlx-strategies golden` rewrites the files.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::context::DecisionContext;
use crate::registry::{self, Gates};
use crate::switching::Phase;
use crate::testutil::{Fixture, Spec};
use crate::url_plane::{UrlPlane, UrlPlaneConfig};
use crate::utility::micros;
use crate::Strategy;
use crawlx_core::action::BrowserAction;
use crawlx_core::config::StrategyName;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::gates::GateStatus;
use crawlx_core::ids::ModelDecisionId;
use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
use crawlx_core::safety::RiskClass;
use crawlx_core::{ActionContextKey, ActionKind, TrustLane};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Directory of the blessed files.
const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/golden/strategies");
/// Set to rewrite the files instead of comparing.
const BLESS_ENV: &str = "CRAWLX_BLESS";
/// Phases every strategy is snapshotted under; `as_str()` names them in the file.
const PHASES: [Phase; 3] = [Phase::Greedy, Phase::StateRecovery, Phase::EnablementRecovery];

/// One proposal as recorded.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
struct ProposalRecord {
    /// Hex `ActionContextId` of `key`.
    key_id: String,
    /// Position in the strategy's emitted list (ranking is part of the contract).
    rank: usize,
    key: ActionContextKey,
    action_kind: ActionKind,
    /// CDP backend node of the action's target, when it has one.
    target_backend_node: Option<i64>,
    /// Destination of a `Navigate`.
    navigate_url: Option<String>,
    epoch: ObservationEpoch,
    strategy: String,
    strategy_version: u32,
    /// `confidence` × 10⁶, rounded (float formatting never matters).
    confidence_micros: i64,
    expected: ExpectedEffect,
    hinted_risk: Option<RiskClass>,
    model_decision: Option<ModelDecisionId>,
    summary: String,
}

impl ProposalRecord {
    fn from_proposal(rank: usize, p: &ActionProposal) -> Self {
        let navigate_url = match &p.action {
            BrowserAction::Navigate { url } => Some(url.to_string()),
            _ => None,
        };
        Self {
            key_id: p.key.id().to_string(),
            rank,
            key: p.key.clone(),
            action_kind: p.action.kind(),
            target_backend_node: p.action.target().map(|t| t.backend_node_id.0),
            navigate_url,
            epoch: p.epoch,
            strategy: p.strategy.to_owned(),
            strategy_version: p.strategy_version,
            confidence_micros: micros(p.confidence),
            expected: p.expected.clone(),
            hinted_risk: p.hinted_risk,
            model_decision: p.model_decision,
            summary: p.summary.clone(),
        }
    }
}

/// The proposals of one phase, sorted by `(key_id, action_kind, navigate_url, rank)`.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
struct RoundRecord {
    phase: String,
    proposals: Vec<ProposalRecord>,
}

/// Shape of the fixed context, so a drift in the fixture itself is visible in the diff.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
struct ContextDigest {
    candidates: usize,
    keyed_actions: usize,
    hidden_targets: usize,
    seed: u64,
}

/// One `<strategy>-v<version>.json` file.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
struct Snapshot {
    strategy: String,
    version: u32,
    context: ContextDigest,
    rounds: Vec<RoundRecord>,
}

impl Snapshot {
    fn file_name(&self) -> String {
        format!("{}-v{}.json", self.strategy, self.version)
    }

    fn path(&self) -> PathBuf {
        Path::new(DIR).join(self.file_name())
    }

    fn to_json(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).unwrap();
        s.push('\n');
        s
    }
}

/// The fixed page: ~50 candidates covering links (in/out of scope, visited, templated),
/// buttons (plain, risky, blocked, exercised), form controls and hidden-but-known items.
fn fixture() -> Fixture {
    // 1. A menu page: opening "Menu" reveals "Item A"/"Item B"; the menu closes again, so the
    //    items are known hidden targets with a recorded enablement path.
    let mut f = Fixture::new(&[Spec::button("Menu"), Spec::button("Other")]);
    let menu = f.key("Menu", ActionKind::Click);
    let revealed = f.reveal_items(&["Item A", "Item B"]);
    f.exec(&menu, f.open_cluster(), &revealed, TrustLane::TrustedUi);
    f.mark_risk(&menu, RiskClass::NavigationReveal);

    // 2. The full page on the same route and cluster.
    let mut specs = vec![
        Spec::button("Menu"),
        Spec::button("Other"),
        Spec::link("Docs", "/docs"),
        Spec::link("Pricing", "/pricing/plans"),
        Spec::link("About", "/about"),
        Spec::link("Home", "/app"),
        Spec::link("Settings", "/settings"),
        Spec::link("FAQ", "/help#faq"),
        Spec::link("Help", "/help"),
        Spec::link("API", "https://api.example/x"),
        Spec::link("CDN", "https://cdn.test/x"),
        Spec::link("Mail", "mailto:ops@example"),
        Spec::button("Help"),
        Spec::button("Profile"),
        Spec::button("Save"),
        Spec::button("Submit"),
        Spec::button("Delete"),
        Spec::button("Archive"),
        Spec::button("Pay now"),
        Spec::button("Send invite"),
        Spec::button("Change password"),
        Spec::button("Next"),
        Spec::button("Previous"),
        Spec::button("Open"),
        Spec::button("Close"),
        Spec::textbox("Search", &[("type", "search")]),
        Spec::textbox("Email", &[("type", "email")]),
        Spec::textbox("Name", &[("type", "text")]),
        Spec::textbox("Password", &[("type", "password")]),
        Spec::textbox("Amount", &[("type", "number")]),
        Spec::checkbox("Remember"),
        Spec::checkbox("Agree"),
        Spec::checkbox("Notify"),
        Spec::button("Hidden A").hidden(),
        Spec::button("Hidden B").hidden(),
        Spec::link("Hidden link", "/hidden").hidden(),
    ];
    for i in 1..=4u8 {
        let item = format!("Item {i}");
        specs.push(Spec::link("Open item", &format!("/items/{i}")).in_container(&item));
        specs.push(Spec::button("Edit").in_container(&item));
        specs.push(Spec::button("Remove").in_container(&item));
    }
    // Controls the previous observation did not show (`event_driven` input).
    let late = [
        Spec::button("Sort"),
        Spec::button("Filter"),
        Spec::button("Export"),
    ];
    let mut full = specs.clone();
    full.extend(late);
    f.observe(&full);

    // 3. History: visited destinations, exercised keys, risk classes, one blocked key.
    f.mark_url_visited("https://app.example/app");
    f.mark_url_visited("https://app.example/docs");
    let next = f.key("Next", ActionKind::Click);
    f.exercise(&next, TrustLane::TrustedUi);
    let open = f.key("Open", ActionKind::Click);
    f.exercise(&open, TrustLane::TrustedUi);
    f.exercise(&open, TrustLane::TrustedUi);
    let search = f.key("Search", ActionKind::Type);
    f.exercise(&search, TrustLane::Diagnostic);
    for (name, risk) in [
        ("Delete", RiskClass::Destructive),
        ("Pay now", RiskClass::FinancialTransaction),
        ("Send invite", RiskClass::ExternalCommunication),
        ("Change password", RiskClass::SecurityChange),
        ("Save", RiskClass::PersistentWriteOwn),
        ("Archive", RiskClass::PersistentWriteOwn),
    ] {
        let key = f.key(name, ActionKind::Click);
        f.mark_risk(&key, risk);
    }
    let close = f.key("Close", ActionKind::Click);
    f.block(&close);

    // 4. The session's previous observation lacked `late`; the final one shows them.
    f.observe(&specs);
    f.observe(&full);
    f
}

/// Every deterministic production strategy at its current version. `system1` and
/// `llm_planner` are model-backed (not pure functions of the context) and are
/// covered by recorded-engine tests instead.
fn production_strategies() -> Vec<Arc<dyn Strategy>> {
    let gates = Gates::from_status(GateStatus::ALL);
    let mut out: Vec<Arc<dyn Strategy>> = [
        StrategyName::InteractionBfs,
        StrategyName::StateNovelty,
        StrategyName::Enablement,
        StrategyName::EventDriven,
    ]
    .into_iter()
    .map(|name| registry::build(name, &gates).unwrap())
    .collect();
    out.push(Arc::new(UrlPlane::new(UrlPlaneConfig::default())));
    out.sort_by_key(|s| s.name());
    out
}

async fn snapshot(strategy: &dyn Strategy, f: &Fixture) -> Snapshot {
    let mut rounds = Vec::with_capacity(PHASES.len());
    let mut digest = None;
    for phase in PHASES {
        let ctx: DecisionContext<'_> = f.ctx_with_phase(phase);
        digest.get_or_insert_with(|| ContextDigest {
            candidates: ctx.candidates.len(),
            keyed_actions: ctx.keyed_actions().len(),
            hidden_targets: ctx.hidden_targets.len(),
            seed: ctx.seed.0,
        });
        let proposals = strategy.propose(&ctx).await.unwrap();
        for p in &proposals {
            assert_eq!(p.strategy, strategy.name());
            assert_eq!(p.strategy_version, strategy.version());
        }
        let mut records: Vec<ProposalRecord> = proposals
            .iter()
            .enumerate()
            .map(|(rank, p)| ProposalRecord::from_proposal(rank, p))
            .collect();
        records.sort_by(|a, b| {
            a.key_id
                .cmp(&b.key_id)
                .then(a.action_kind.cmp(&b.action_kind))
                .then(a.navigate_url.cmp(&b.navigate_url))
                .then(a.rank.cmp(&b.rank))
        });
        rounds.push(RoundRecord {
            phase: phase.as_str().to_owned(),
            proposals: records,
        });
    }
    Snapshot {
        strategy: strategy.name().to_owned(),
        version: strategy.version(),
        context: digest.unwrap(),
        rounds,
    }
}

/// Compare `current` with the blessed `on_disk` file; the error names the fix.
fn check(current: &Snapshot, on_disk: Option<&str>) -> Result<(), String> {
    let file = current.file_name();
    let Some(text) = on_disk else {
        return Err(format!(
            "no golden file {file} for strategy {} v{}: run `{BLESS_ENV}=1 cargo test -p crawlx-strategies golden` \
             and commit fixtures/golden/strategies/{file}",
            current.strategy, current.version
        ));
    };
    let blessed: Snapshot =
        serde_json::from_str(text).map_err(|e| format!("golden file {file} is not a valid snapshot: {e}"))?;
    if blessed.strategy != current.strategy || blessed.version != current.version {
        return Err(format!(
            "golden file {file} records {} v{} but its name says {} v{}: fix the file name or re-bless",
            blessed.strategy, blessed.version, current.strategy, current.version
        ));
    }
    if blessed.context != current.context {
        return Err(format!(
            "golden fixture context changed for {file} ({:?} → {:?}): the shared fixture drifted; \
             re-bless every strategy with `{BLESS_ENV}=1`",
            blessed.context, current.context
        ));
    }
    if blessed.rounds != current.rounds {
        let mut detail = String::new();
        for (b, c) in blessed.rounds.iter().zip(&current.rounds) {
            if b != c {
                detail.push_str(&format!(
                    "\n  phase {}: {} blessed vs {} current proposals",
                    b.phase,
                    b.proposals.len(),
                    c.proposals.len()
                ));
                let bk: BTreeSet<&str> = b.proposals.iter().map(|p| p.key_id.as_str()).collect();
                let ck: BTreeSet<&str> = c.proposals.iter().map(|p| p.key_id.as_str()).collect();
                for k in bk.difference(&ck) {
                    detail.push_str(&format!("\n    - {k}"));
                }
                for k in ck.difference(&bk) {
                    detail.push_str(&format!("\n    + {k}"));
                }
            }
        }
        return Err(format!(
            "proposals of strategy {} changed but version() is still {}: bump `VERSION` in its module, \
             then run `{BLESS_ENV}=1 cargo test -p crawlx-strategies golden` to bless {}-v{}.json \
             (strategy versioning rule){detail}",
            current.strategy,
            current.version,
            current.strategy,
            current.version + 1
        ));
    }
    Ok(())
}

/// `(strategy, version)` parsed from `<strategy>-v<version>.json`.
fn parse_file_name(name: &str) -> Option<(String, u32)> {
    let stem = name.strip_suffix(".json")?;
    let (strategy, version) = stem.rsplit_once("-v")?;
    Some((strategy.to_owned(), version.parse().ok()?))
}

#[tokio::test]
async fn golden_proposals_match_per_strategy_version() {
    let bless = std::env::var_os(BLESS_ENV).is_some_and(|v| !v.is_empty() && v != "0");
    let f = fixture();
    assert!(
        (45..=60).contains(&f.candidates.len()),
        "fixture has {} candidates",
        f.candidates.len()
    );
    let strategies = production_strategies();
    let mut expected_files = BTreeSet::new();
    let mut failures = Vec::new();
    for strategy in &strategies {
        let current = snapshot(strategy.as_ref(), &f).await;
        let path = current.path();
        expected_files.insert(current.file_name());
        if bless {
            std::fs::create_dir_all(DIR).unwrap();
            std::fs::write(&path, current.to_json()).unwrap();
            continue;
        }
        let on_disk = std::fs::read_to_string(&path).ok();
        if let Err(msg) = check(&current, on_disk.as_deref()) {
            failures.push(msg);
        }
    }
    // Every file in the directory belongs to a registered strategy at its current version:
    // a stale `<strategy>-v<old>.json` after a bump, or a file for a removed strategy, fails.
    let names: BTreeSet<String> = std::fs::read_dir(DIR)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".json"))
                .collect()
        })
        .unwrap_or_default();
    for name in names.difference(&expected_files) {
        let what = match parse_file_name(name) {
            Some((strategy, version)) => format!("{strategy} v{version}"),
            None => "an unparseable name".to_owned(),
        };
        failures.push(format!(
            "stale golden file {name} ({what}): no registered strategy has that (name, version); delete it"
        ));
    }
    if bless {
        for name in names.difference(&expected_files) {
            std::fs::remove_file(Path::new(DIR).join(name)).unwrap();
        }
        return;
    }
    assert!(
        failures.is_empty(),
        "golden snapshot failures:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn golden_snapshots_are_stable_across_runs_and_cover_every_strategy() {
    let f = fixture();
    let strategies = production_strategies();
    let names: Vec<&str> = strategies.iter().map(|s| s.name()).collect();
    assert_eq!(
        names,
        [
            "enablement",
            "event_driven",
            "interaction_bfs",
            "state_novelty",
            "url_plane"
        ]
    );
    for strategy in &strategies {
        let a = snapshot(strategy.as_ref(), &f).await;
        let b = snapshot(strategy.as_ref(), &fixture()).await;
        assert_eq!(a, b, "{} is not a pure function of the context", strategy.name());
        assert!(
            a.rounds.iter().any(|r| !r.proposals.is_empty()),
            "{} proposes nothing in any phase; the fixture does not exercise it",
            strategy.name()
        );
        assert_eq!(
            a.to_json(),
            serde_json::from_str::<Snapshot>(&a.to_json()).unwrap().to_json()
        );
    }
}

#[tokio::test]
async fn a_changed_proposal_set_without_a_version_bump_names_the_fix() {
    let f = fixture();
    let bfs = registry::build(StrategyName::InteractionBfs, &Gates::from_status(GateStatus::ALL)).unwrap();
    let current = snapshot(bfs.as_ref(), &f).await;
    assert!(check(&current, Some(&current.to_json())).is_ok());

    // missing file
    let err = check(&current, None).unwrap_err();
    assert!(err.contains("no golden file interaction_bfs-v1.json"), "{err}");
    assert!(err.contains(BLESS_ENV), "{err}");

    // same version, different proposals
    let mut drifted = current.clone();
    drifted.rounds[0].proposals.pop();
    let err = check(&drifted, Some(&current.to_json())).unwrap_err();
    assert!(
        err.contains("changed but version() is still 1: bump `VERSION`"),
        "{err}"
    );
    assert!(err.contains("bless interaction_bfs-v2.json"), "{err}");
    assert!(err.contains("phase greedy"), "{err}");

    // confidence change alone is a proposal change
    let mut recal = current.clone();
    recal.rounds[0].proposals[0].confidence_micros += 1;
    assert!(check(&recal, Some(&current.to_json())).is_err());

    // file name and embedded version disagree
    let mut renamed = current.clone();
    renamed.version = 2;
    let err = check(&renamed, Some(&current.to_json())).unwrap_err();
    assert!(
        err.contains("records interaction_bfs v1 but its name says interaction_bfs v2"),
        "{err}"
    );

    // fixture drift is reported as such, not as a strategy change
    let mut ctx = current.clone();
    ctx.context.candidates += 1;
    let err = check(&ctx, Some(&current.to_json())).unwrap_err();
    assert!(err.contains("fixture context changed"), "{err}");

    assert_eq!(
        parse_file_name("state_novelty-v12.json"),
        Some(("state_novelty".to_owned(), 12))
    );
    assert_eq!(parse_file_name("state_novelty.json"), None);
}
