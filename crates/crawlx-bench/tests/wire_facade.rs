//! The wire families (VAL, PREC, CLAMP, PERSIST, CANCEL, RESUME/LEASE, WH, ZDR)
//! replayed against the crawlx compat facade: the committed black-box captures of the real
//! Firecrawl (`bench/differential/captures/<family>.json`, pinned commit) are compared with a
//! live run of the same scenarios (`bench/differential/wire-scenarios.json`) against an
//! in-process facade, worker, gym and webhook sink (`support/facade_rig.rs`), under the ledger
//! `bench/differential/divergences.toml`. Every family must reach its `expect`ed verdict.
//!
//! No Firecrawl, no Chromium, no network beyond loopback. The rig runs on the in-memory store;
//! `wire-resume` also runs on PostgreSQL (`CRAWLX_TEST_DATABASE_URL`, skipped without it).
//! Environment:
//!
//! * `CRAWLX_WIRE_FIRECRAWL=FILE`: compare with this Firecrawl capture instead of the committed one;
//! * `CRAWLX_WIRE_RECORD=DIR`: also write the facade's capture to `DIR/<family>.crawlx.json`
//!   (`.crawlx.postgres.json` on PostgreSQL; and do not fail when the family has no Firecrawl
//!   capture yet);
//! * `CRAWLX_WIRE_SCORECARDS=DIR`: also write the scorecard to `DIR/<family>.scorecard.md`
//!   (`.postgres.scorecard.md` on PostgreSQL).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/facade_rig.rs"]
mod facade_rig;

use crawlx_bench::differential::wire::{compare, run_family, WireCapture, WireSpec};
use crawlx_bench::differential::{Ledger, Severity, Verdict};
use facade_rig::FacadeRig;
use std::path::{Path, PathBuf};

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
}

/// The store the facade rig runs on.
#[derive(Clone, Copy)]
enum Store {
    Memory,
    Postgres,
}

async fn replay(id: &str, store: Store) {
    let spec = WireSpec::load(&repo_path("bench/differential/wire-scenarios.json")).unwrap();
    let family = spec.family(id).unwrap_or_else(|| panic!("no family `{id}`"));
    let capture_path = std::env::var("CRAWLX_WIRE_FIRECRAWL").map_or_else(
        |_| repo_path(&format!("bench/differential/captures/{id}.json")),
        PathBuf::from,
    );
    // without a Firecrawl capture the facade can still be recorded (a first look at a new family)
    let firecrawl = match (
        WireCapture::load(&capture_path),
        std::env::var("CRAWLX_WIRE_RECORD"),
    ) {
        (Ok(c), _) => Some(c),
        (Err(_), Ok(_)) => None,
        (Err(e), Err(_)) => panic!("{id}: {}: {e}", capture_path.display()),
    };
    if let Some(firecrawl) = &firecrawl {
        assert_eq!(firecrawl.wire_sample.provenance, "black_box_run", "{id}");
        assert_eq!(
            firecrawl.wire_sample.upstream_commit.as_deref(),
            Some("c31e88c07afe941bfd8aebde61684eeba042abb5"),
            "{id}"
        );
        assert_eq!(firecrawl.family, id);
        assert_eq!(
            firecrawl
                .scenarios
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>(),
            family.scenarios.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            "{id}: the committed capture and the scenario file disagree; re-capture the family"
        );
    }

    let (rig, tag) = match store {
        Store::Memory => (FacadeRig::start().await, ""),
        Store::Postgres => {
            let Some(rig) = FacadeRig::start_postgres().await else {
                eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
                return;
            };
            (rig, ".postgres")
        }
    };
    let crawlx = run_family(&rig.target(), family).await.unwrap();
    rig.stop().await;

    if let Ok(dir) = std::env::var("CRAWLX_WIRE_RECORD") {
        crawlx
            .save(&Path::new(&dir).join(format!("{id}.crawlx{tag}.json")))
            .unwrap();
    }
    let Some(firecrawl) = firecrawl else {
        eprintln!(
            "{id}: no Firecrawl capture at {}; recorded the facade only",
            capture_path.display()
        );
        return;
    };
    let ledger = Ledger::load(&repo_path("bench/differential/divergences.toml")).unwrap();
    let report = compare::compare(id, &firecrawl, &crawlx, &ledger).unwrap();
    let md = report.to_markdown();
    if let Ok(dir) = std::env::var("CRAWLX_WIRE_SCORECARDS") {
        std::fs::write(Path::new(&dir).join(format!("{id}{tag}.scorecard.md")), &md).unwrap();
    }
    let expected = match family.expect.as_deref().unwrap_or("pass") {
        "pass" => Verdict::Pass,
        "warn" => Verdict::Warn,
        "block" => Verdict::Block,
        other => panic!("{id}: unknown expect {other}"),
    };
    assert_eq!(report.verdict(), expected, "{id}:\n{md}");
    assert_eq!(
        family.open.is_some(),
        expected == Verdict::Block,
        "{id}: a block is allowed only as a recorded residual (`open`)"
    );
    if expected == Verdict::Pass {
        assert!(
            report.findings.iter().all(|f| f.severity == Severity::Documented),
            "{id}: a pass has only documented findings\n{md}"
        );
    }
}

macro_rules! family_test {
    ($name:ident, $id:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $name() {
            replay($id, Store::Memory).await;
        }
    };
}

family_test!(wire_val_matches_the_captured_firecrawl, "wire-val");
family_test!(wire_prec_matches_the_captured_firecrawl, "wire-prec");
family_test!(wire_clamp_matches_the_captured_firecrawl, "wire-clamp");
family_test!(wire_persist_matches_the_captured_firecrawl, "wire-persist");
family_test!(wire_cancel_matches_the_captured_firecrawl, "wire-cancel");
family_test!(wire_resume_matches_the_captured_firecrawl, "wire-resume");
family_test!(wire_webhook_matches_the_captured_firecrawl, "wire-webhook");
family_test!(wire_zdr_matches_the_captured_firecrawl, "wire-zdr");

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_resume_matches_the_captured_firecrawl_on_postgres() {
    replay("wire-resume", Store::Postgres).await;
}
