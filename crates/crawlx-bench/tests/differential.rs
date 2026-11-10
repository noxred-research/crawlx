//! Differential runner against the committed exports and in-process crawlx runs of
//! the same fixtures. `captures/s1.authored.json` is the authored sample of 2026-10-20 (kept for
//! diffing); `captures/<family>.json` are black-box exports of the pinned upstream. No
//! upstream, no Chromium, no network.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::differential::{
    CrawlxRun, DifferentialRunner, DivergenceKind, FixtureRun, Ledger, Report, Severity, Side,
    UpstreamExport, Verdict,
};
use crawlx_bench::gym::fixtures::{self, FileDef};
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_core::config::QueryPolicy;
use crawlx_core::hash::Digest;
use crawlx_url::TrailingSlash;
use std::path::{Path, PathBuf};
use url::Url;

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
}

fn sample() -> UpstreamExport {
    UpstreamExport::load(&repo_path("bench/differential/captures/s1.authored.json")).unwrap()
}

fn ledger() -> Ledger {
    Ledger::load(&repo_path("bench/differential/divergences.toml")).unwrap()
}

async fn gym() -> GymHandle {
    GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap()
}

// Authored entry source from 300ba24, the version served to the 2026-10-28 upstream run.
// This is fixture input, not a newly measured upstream capture.
const G12_CAPTURE_INDEX: &str =
    include_str!("../../../bench/differential/fixtures/2026-10-28/g12/index.html");

async fn capture_gym(fixture: &str) -> GymHandle {
    if fixture != "g12" {
        return gym().await;
    }
    let current = fixtures::find("g12").unwrap().file("").unwrap();
    for (version, source, expected) in [
        (
            "current privacy fixture",
            current.body,
            "f612587c73c3cc75beb305e4a84c0ce894533fd99e1868af206c340a221ff667",
        ),
        (
            "2026-10-28 capture fixture",
            G12_CAPTURE_INDEX,
            "3f38c50ca2e80e8b24bf106e690e7324dcf05f9632f78c4d33839abfe5c0f570",
        ),
    ] {
        assert_eq!(
            Digest::of("crawlx/bench/differential/fixture-source/v1", source.as_bytes()).to_hex(),
            expected,
            "{version}: review authored source changes before replaying historical evidence"
        );
    }
    assert_eq!(
        current.body.replace("g12_session_canary_7d91e8c4", "abc123"),
        G12_CAPTURE_INDEX,
        "the capture fixture must differ only in the historical session token"
    );
    GymServer::start_with_fixture_file(
        "127.0.0.1:0".parse().unwrap(),
        "g12",
        FileDef {
            body: G12_CAPTURE_INDEX,
            ..*current
        },
    )
    .await
    .unwrap()
}

async fn crawl(policy: QueryPolicy) -> (CrawlxRun, Url) {
    let gym = gym().await;
    let dir = tempfile::tempdir().unwrap();
    let mut opts = FixtureRun::new("s1");
    opts.query_policy = policy;
    let run = CrawlxRun::crawl_fixture(&opts, &gym, dir.path()).await.unwrap();
    let origin = Url::parse(&gym.base_url).unwrap();
    gym.shutdown().await;
    (run, origin)
}

#[test]
fn sample_export_loads_with_the_s1_semantics() {
    let e = sample();
    assert_eq!(e.status, "completed");
    assert_eq!(e.data.len(), 32, "28 pages + 4 tracking variants");
    assert_eq!(e.errors.errors.len(), 2);
    assert_eq!(e.errors.robots_blocked.len(), 2);
    assert_eq!(e.origin().unwrap().as_str(), "http://gym.test/");
    assert!(e.data.iter().all(|d| d.markdown.is_some() && !d.links.is_empty()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_all_run_matches_the_sample_on_every_level() {
    let (run, origin) = crawl(QueryPolicy::KeepAll).await;
    assert_eq!(run.pages.len(), 32, "{:?}", run.counters);
    let report = DifferentialRunner::new(ledger())
        .with_label("s1 keep_all")
        .compare(&sample(), &Url::parse("http://gym.test").unwrap(), &run, &origin);
    let md = report.to_markdown();
    eprintln!("{md}");
    assert_eq!(report.verdict(), Verdict::Pass, "{md}");
    assert_eq!(report.exit_code(true), 0);
    assert!(report.set_diffs.is_empty());
    assert_eq!(report.common_pages, 32);
    assert_eq!(report.attempted, (34, 34));
    assert!(report.corpus_mean.unwrap() >= 0.98, "{md}");
    assert!(report.pages.iter().all(|p| p.metadata.is_empty()), "{md}");
    assert!(report.counters.is_empty(), "{md}");
    assert_eq!(
        report.unused_entries,
        vec!["QRY-001"],
        "ledger entry for classify runs stays idle"
    );
    assert!(md.contains("# Differential scorecard: s1 keep_all"));
    assert!(md.contains("Verdict: **Pass**"));

    // round trip through the JSON the nightly job writes
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("crawlx.json");
    run.save(&p).unwrap();
    assert_eq!(CrawlxRun::load(&p).unwrap(), run);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classify_run_diverges_on_tracking_variants_and_only_the_ledger_makes_it_pass() {
    let (run, origin) = crawl(QueryPolicy::Classify).await;
    assert_eq!(run.pages.len(), 28, "{:?}", run.counters);
    let fc_origin = Url::parse("http://gym.test").unwrap();

    // undocumented: blocking, exit 1
    let report = DifferentialRunner::new(Ledger::default()).compare(&sample(), &fc_origin, &run, &origin);
    assert_eq!(report.verdict(), Verdict::Block, "{}", report.to_markdown());
    assert_eq!(report.exit_code(false), 1);
    let blocking: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Blocking)
        .map(|f| f.subject.as_str())
        .collect();
    assert_eq!(
        blocking,
        vec![
            "{origin}/s1/about?utm_source=newsletter",
            "{origin}/s1/docs/guide?utm_source=api",
            "{origin}/s1/docs?utm_campaign=spring&utm_medium=email",
            "{origin}/s1/products/beta?utm_source=cross",
        ]
    );
    assert!(report
        .set_diffs
        .iter()
        .all(|d| d.kind == DivergenceKind::Admission && d.side == Side::UpstreamOnly));

    // documented by QRY-001: pass, exit 0, findings informational
    let report = DifferentialRunner::new(ledger()).compare(&sample(), &fc_origin, &run, &origin);
    let md = report.to_markdown();
    assert_eq!(report.verdict(), Verdict::Pass, "{md}");
    assert_eq!(report.exit_code(true), 0);
    assert_eq!(
        report.findings.len(),
        6,
        "4 admission + total/completed explained by them:\n{md}"
    );
    assert_eq!(report.counters.len(), 2);
    assert!(report
        .findings
        .iter()
        .all(|f| f.documented.as_deref() == Some("QRY-001")));
    assert!(report.unused_entries.is_empty());
    assert!(md.contains("| admission | upstream | `{origin}/s1/about?utm_source=newsletter` | QRY-001 |"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cli_output_directory_is_a_valid_crawlx_side() {
    let (run, origin) = crawl(QueryPolicy::KeepAll).await;
    // write what `crawlx crawl --out DIR` writes, from the run
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("pages")).unwrap();
    let mut metadata = Vec::new();
    let mut links = serde_json::Map::new();
    for (i, p) in run.pages.iter().enumerate() {
        let rel = format!("pages/p{i}.md");
        std::fs::write(dir.path().join(&rel), p.markdown.as_deref().unwrap()).unwrap();
        metadata.push(serde_json::json!({
            "url": p.url, "status": p.status, "contentType": p.content_type, "title": p.title,
            "file": rel, "metadata": {"description": p.description, "language": p.language},
        }));
        links.insert(p.url.clone(), serde_json::json!(p.links));
    }
    std::fs::write(
        dir.path().join("metadata.json"),
        serde_json::to_vec(&metadata).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.path().join("links.json"), serde_json::to_vec(&links).unwrap()).unwrap();
    std::fs::write(
        dir.path().join("report.json"),
        serde_json::to_vec(&serde_json::json!({"status": "completed", "counters": {"urls": run.counters}}))
            .unwrap(),
    )
    .unwrap();
    let loaded = CrawlxRun::from_cli_dir(dir.path()).unwrap();
    assert_eq!(loaded.pages, run.pages);
    assert!(loaded.frontier.is_empty());
    // without the frontier the failed and robots-blocked URLs are unknown on the crawlx side,
    // which the scorecard reports as upstream-only admission and robots entries
    let report = DifferentialRunner::new(ledger()).compare(
        &sample(),
        &Url::parse("http://gym.test").unwrap(),
        &loaded,
        &origin,
    );
    let keys: Vec<&str> = report.set_diffs.iter().map(|d| d.key.as_str()).collect();
    assert_eq!(
        keys,
        vec![
            "{origin}/s1/error",
            "{origin}/s1/missing",
            "{origin}/s1/private",
            "{origin}/s1/private/secret"
        ]
    );
    assert_eq!(report.common_pages, 32);
}

/// What `families.json` says about one family, as the in-process crawlx run needs it.
fn family_run(doc: &serde_json::Value, f: &serde_json::Value, request: serde_json::Value) -> FixtureRun {
    let fixture = f["fixture"].as_str().unwrap();
    let mut opts = FixtureRun::new(fixture);
    opts.request = request;
    opts.trailing_slash = Some(TrailingSlash::Keep);
    opts.claim_origin = f["claim_origin"] == true;
    if opts.claim_origin || f.get("host").is_some() {
        opts.host = Some(f["host"].as_str().unwrap_or("gym.test").to_owned());
        opts.seed_path = f["seed_path"].as_str().map(str::to_owned);
        let names = f.get("aliases").unwrap_or(&doc["fixture_hosts"][fixture]);
        opts.aliases = names
            .as_array()
            .map(|a| a.iter().filter_map(|n| n.as_str().map(str::to_owned)).collect())
            .unwrap_or_default();
    }
    opts
}

/// Replay family `f` of `doc` (`families.json`): its committed capture against an in-process
/// crawlx run of the same request under the ledger.
async fn replay_family(doc: &serde_json::Value, f: &serde_json::Value) -> (Report, UpstreamExport) {
    let id = f["id"].as_str().unwrap();
    let path = repo_path(&format!("bench/differential/captures/{id}.json"));
    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let sample = &raw["crawlxSample"];
    assert_eq!(sample["provenance"], "black_box_run", "{id}");
    assert_eq!(
        sample["upstreamCommit"], "c31e88c07afe941bfd8aebde61684eeba042abb5",
        "{id}"
    );
    assert_eq!(sample["family"], id);
    let capture = UpstreamExport::load(&path).unwrap();

    let gym = capture_gym(f["fixture"].as_str().unwrap()).await;
    let dir = tempfile::tempdir().unwrap();
    let opts = family_run(doc, f, sample["request"].clone());
    let run = CrawlxRun::crawl_fixture(&opts, &gym, dir.path()).await.unwrap();
    let origin = Url::parse(&opts.crawl_origin(&gym)).unwrap();
    gym.shutdown().await;

    let report = DifferentialRunner::new(ledger())
        .with_label(id)
        .with_cardinality_only(f["compare"] == "cardinality")
        .compare(&capture, &capture.origin().unwrap(), &run, &origin);
    (report, capture)
}

fn families_doc() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(repo_path("bench/differential/families.json")).unwrap()).unwrap()
}

/// The families of `bench/differential/families.json`, replayed offline: every committed capture
/// (a real run of upstream `c31e88c07afe941bfd8aebde61684eeba042abb5`) is compared with an
/// in-process crawlx run of the same request under the ledger and must reach its `expect`ed
/// verdict. A family with `open` set is a recorded residual: it must stay `block`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_committed_capture_reaches_its_expected_verdict() {
    let doc = families_doc();
    let families = doc["families"].as_array().unwrap();
    assert!(families.len() >= 26, "families.json lost rows");
    for f in families {
        let id = f["id"].as_str().unwrap();
        let (report, _) = replay_family(&doc, f).await;
        let expected = match f["expect"].as_str().unwrap() {
            "pass" => Verdict::Pass,
            "warn" => Verdict::Warn,
            "block" => Verdict::Block,
            other => panic!("{id}: unknown expect {other}"),
        };
        let md = report.to_markdown();
        assert_eq!(report.verdict(), expected, "{id}:\n{md}");
        assert_eq!(
            f.get("open").is_some(),
            expected == Verdict::Block,
            "{id}: a block is allowed only as a recorded residual (`open`)"
        );
        if expected == Verdict::Pass {
            assert!(
                report.findings.iter().all(|x| x.severity == Severity::Documented),
                "{id}: a pass has only documented findings\n{md}"
            );
        }
    }
}

/// The requested set: every committed capture of a `d2` family carries the gym's
/// access log, both sides' logs are compared, and a page the system asked for is in it. The
/// scorecard of a family states the number of page requests each side made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d2_captures_carry_the_access_log_and_it_is_compared() {
    let doc = families_doc();
    let mut seen = 0;
    for f in doc["families"].as_array().unwrap() {
        if f["fixture"] != "d2" {
            continue;
        }
        let id = f["id"].as_str().unwrap();
        let (report, capture) = replay_family(&doc, f).await;
        let log = capture
            .access_log
            .as_ref()
            .unwrap_or_else(|| panic!("{id}: no accessLog in the capture"));
        assert!(
            log.entries.iter().any(|e| e.path.starts_with("/d2/")),
            "{id}: the access log holds no d2 request"
        );
        let (fc, cx) = report
            .requested
            .unwrap_or_else(|| panic!("{id}: the requested sets were not compared"));
        // crawlx reads a robots.txt that answers 5xx as a complete disallow: no page request
        assert!(fc > 0 && (cx > 0 || id == "d2-robots-503"), "{id}: {fc} / {cx}");
        assert!(report.to_markdown().contains("## C1 requested set"), "{id}");
        seen += 1;
    }
    assert!(seen >= 13, "only {seen} d2 families");
}
