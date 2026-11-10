//! `crawl-bench` (equivalent of a reference crawl-bench tool): the pure parts
//! (profiles, targets, percentiles, medians, aggregation, baseline comparison, table and JSON
//! shapes), the recording proxy, a real crawl of gym fixtures through the URL plane, and the
//! binary's exit status. Wall-clock numbers are measured, never asserted exactly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::crawl_bench::recorder::{Hit, Recorder};
use crawlx_bench::crawl_bench::{
    combine, compare, delta_label, discovered_endpoints, endpoint_key, known_endpoints, percentile, run,
    summarize, BenchConfig, Metric, Metrics, Profile, Report, Row, Sample, Target, AGGREGATE_LABEL, SCHEMA,
};
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::worker_exec::crawl_request_for_url;
use crawlx_bench::BenchError;
use crawlx_core::config::{
    CrawlMode, CrawlStrategy, CreateCrawl, HostScope, QueryPolicy, SafetyProfile, SitemapMode,
};
use crawlx_core::hash::Digest;
use crawlx_core::repo::PageRecord;
use crawlx_core::traffic::TrustLane;
use crawlx_core::CrawlRunId;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Duration;
use url::Url;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn metrics(doc: Value) -> Metrics {
    serde_json::from_value(doc).unwrap()
}

/// A baseline-shaped metrics document; `patch` overrides fields.
fn doc(patch: Value) -> Value {
    let mut base = json!({
        "pages": 28, "endpoints": 30, "known": 28, "found": 28, "recall": 1.0,
        "requests": 40, "errors": 0, "seconds": 2.0, "rps": 20.0, "p50_ms": 1.0, "p95_ms": 2.0
    });
    for (k, v) in patch.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

/// A report parsed from `(target, profile, metrics)` cells plus aggregate cells.
fn report(cells: &[(&str, &str, Value)], aggregate: &[(&str, Value)]) -> Report {
    let mut results = json!({});
    for (target, profile, m) in cells {
        results[*target][*profile] = m.clone();
    }
    let mut agg = json!({});
    for (profile, m) in aggregate {
        agg[*profile] = m.clone();
    }
    Report::from_json(
        &json!({"schema": SCHEMA, "repeat": 1, "seed": 1, "results": results, "aggregate": agg, "endpoints": {}})
            .to_string(),
    )
    .unwrap()
}

/// The request the harness applies a profile to: a gym-style `crawl_request_for_url` request.
fn request(profile: Profile) -> CreateCrawl {
    let mut req = crawl_request_for_url(
        Url::parse("http://127.0.0.1:9/").unwrap(),
        1,
        SafetyProfile::ReadOnly,
    );
    profile.apply(&mut req);
    req
}

/// Every test lives under this module so `cargo test -p crawlx-bench crawl_bench` selects them.
mod crawl_bench {
    use super::*;

    // ---- profiles and targets -----------------------------------------------------------------

    #[test]
    fn every_profile_crawls_the_url_plane_and_compat_flag_defaults_set_the_preset_values() {
        for profile in Profile::ALL {
            let req = request(profile);
            assert_eq!(req.mode, CrawlMode::Static, "{profile}");
            assert!(!req.dynamic.enabled, "{profile}");
        }

        let k = request(Profile::CompatFlagDefaults);
        assert_eq!(k.scope.host_scope, HostScope::Rdn);
        assert_eq!(k.scope.max_discovery_depth, 3);
        assert_eq!(k.scope.strategy, CrawlStrategy::DepthFirst);
        assert!(!k.scope.js_endpoints);
        assert!(k.scope.known_files.is_empty());
        assert_eq!(k.scope.sitemap, SitemapMode::Skip);
        assert_eq!(k.scope.query_policy, QueryPolicy::KeepAll);
        assert!(!k.safety.respect_robots_txt);
        assert_eq!(k.fetch.max_response_bytes, 4 * 1024 * 1024);
        assert_eq!(k.politeness.global_rps, Some(150));
        assert_eq!(k.politeness.max_concurrency, 10);

        // crawlx defaults stay crawlx defaults (production pacing, breadth-first, depth 10, js on) ...
        let c = request(Profile::CrawlxDefaults);
        assert_eq!(c.politeness.delay_ms, 250);
        assert_eq!(c.scope.max_discovery_depth, 10);
        assert_eq!(c.scope.strategy, CrawlStrategy::BreadthFirst);
        assert!(c.scope.js_endpoints);
        assert!(c.safety.respect_robots_txt);
        // ... and the static profile keeps the gym's faster pace.
        let s = request(Profile::Static);
        assert_eq!(
            s.politeness.delay_ms, 10,
            "normalize() later lifts it to the 50 ms floor"
        );
        assert_eq!(s.scope.max_discovery_depth, 10);
    }

    #[test]
    fn profile_and_metric_names_round_trip_and_unknown_names_list_the_valid_ones() {
        for p in Profile::ALL {
            assert_eq!(Profile::parse(p.name()).unwrap(), p);
            assert_eq!(p.to_string(), p.name());
        }
        let err = Profile::parse("turbo").unwrap_err().to_string();
        assert!(
            err.contains("turbo") && err.contains("compat-flag-defaults") && err.contains("static"),
            "{err}"
        );

        for m in Metric::ALL {
            assert_eq!(Metric::parse(m.name()).unwrap(), m);
        }
        let err = Metric::parse("vibes").unwrap_err().to_string();
        assert!(err.contains("vibes") && err.contains("p95_ms"), "{err}");
    }

    #[test]
    fn targets_parse_gym_fixtures_and_http_urls_only() {
        assert_eq!(Target::parse("gym:s1").unwrap(), Target::Gym("s1".to_owned()));
        assert_eq!(Target::parse("gym:s1").unwrap().name(), "gym:s1");
        let url = Target::parse("http://127.0.0.1:4280/login.php?x=1").unwrap();
        assert_eq!(url.name(), "http://127.0.0.1:4280/login.php?x=1");
        assert!(matches!(url, Target::Url(_)));

        assert!(matches!(
            Target::parse("gym:no-such-fixture"),
            Err(BenchError::UnknownFixture(_))
        ));
        for bad in ["ftp://example.test/", "example.test", "file:///etc/passwd", "gym"] {
            let err = Target::parse(bad).unwrap_err().to_string();
            assert!(err.contains(bad) && err.contains("gym:<fixture>"), "{bad}: {err}");
        }
    }

    #[test]
    fn config_validation_rejects_empty_and_duplicate_inputs() {
        let s1 = || Target::parse("gym:s1").unwrap();
        assert!(BenchConfig::new(vec![s1()]).validate().is_ok());
        let cases: Vec<(BenchConfig, &str)> = vec![
            (BenchConfig::new(vec![]), "target"),
            (BenchConfig::new(vec![s1(), s1()]), "twice"),
            (
                {
                    let mut c = BenchConfig::new(vec![s1()]);
                    c.profiles = vec![];
                    c
                },
                "profile",
            ),
            (
                {
                    let mut c = BenchConfig::new(vec![s1()]);
                    c.profiles = vec![Profile::Static, Profile::Static];
                    c
                },
                "twice",
            ),
            (
                {
                    let mut c = BenchConfig::new(vec![s1()]);
                    c.repeat = 0;
                    c
                },
                "--repeat",
            ),
            (
                {
                    let mut c = BenchConfig::new(vec![s1()]);
                    c.duration_seconds = 0;
                    c
                },
                "--duration-seconds",
            ),
            (
                {
                    let mut c = BenchConfig::new(vec![s1()]);
                    c.max_pages = 0;
                    c
                },
                "--max-pages",
            ),
        ];
        for (cfg, needle) in cases {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(needle), "{needle}: {err}");
        }
    }

    // ---- endpoint sets ------------------------------------------------------------------------

    #[test]
    fn endpoint_keys_resolve_references_and_drop_foreign_origins() {
        let origin = Url::parse("http://127.0.0.1:7000/s1/").unwrap();
        assert_eq!(endpoint_key("/s1/about/", &origin).as_deref(), Some("/s1/about"));
        assert_eq!(
            endpoint_key("about/?utm=1#frag", &origin).as_deref(),
            Some("/s1/about")
        );
        assert_eq!(
            endpoint_key("http://127.0.0.1:7000/", &origin).as_deref(),
            Some("/")
        );
        assert_eq!(
            endpoint_key("/s1/a/b.html", &origin).as_deref(),
            Some("/s1/a/b.html")
        );
        for foreign in [
            "https://external.example/partner",
            "http://127.0.0.1:7001/s1/",
            "https://127.0.0.1:7000/s1/",
            "mailto:hello@gym.test",
        ] {
            assert_eq!(endpoint_key(foreign, &origin), None, "{foreign}");
        }
    }

    #[test]
    fn discovered_endpoints_merge_pages_links_and_mined_endpoints() {
        let origin = Url::parse("http://127.0.0.1:7000/").unwrap();
        let page = page(
            "http://127.0.0.1:7000/s1/",
            &["/s1/about/", "https://external.example/x", "/s1/about/?utm=1"],
            json!({"discovered_endpoints": [
                {"url": "http://127.0.0.1:7000/api/items", "method": "POST"},
                {"url": "https://elsewhere.example/api"}
            ]}),
        );
        let found = discovered_endpoints(&[page], &origin);
        assert_eq!(found, set(&["/s1", "/s1/about", "/api/items"]));
    }

    fn page(url: &str, links: &[&str], metadata: Value) -> PageRecord {
        let canonical =
            Canonicalizer::canonicalize_url(&Url::parse(url).unwrap(), &CanonicalizeOptions::default())
                .unwrap();
        PageRecord {
            run: CrawlRunId::new(),
            frontier_id: 0,
            url: canonical,
            status: 200,
            content_type: Some("text/html".to_owned()),
            content_digest: Digest::of("crawl-bench/test", url.as_bytes()),
            title: None,
            markdown: None,
            html: None,
            metadata,
            links: links.iter().map(|l| (*l).to_owned()).collect(),
            fetched_at: chrono::Utc::now(),
            lane: TrustLane::Diagnostic,
        }
    }

    #[test]
    fn known_endpoint_lists_come_from_the_fixture_ground_truth() {
        // s1: the 28 pages robots.txt allows (private/ and private/secret are blocked).
        let s1 = known_endpoints(&FixtureManifest::embedded("s1").unwrap()).unwrap();
        assert_eq!(s1.len(), 28, "{s1:?}");
        assert!(s1.contains("/s1") && s1.contains("/s1/archive/y1") && s1.contains("/s1/blog/post-6"));
        assert!(!s1.iter().any(|p| p.starts_with("/s1/private")), "{s1:?}");

        // g32: the targets the URL plane is expected to request.
        let maze = FixtureManifest::embedded("g32").unwrap();
        let static_targets = maze
            .expected
            .crawl_maze
            .iter()
            .filter(|t| t.plane == crawlx_bench::gym::manifest::MazePlane::Static)
            .count();
        let g32 = known_endpoints(&maze).unwrap();
        assert_eq!(g32.len(), static_targets);
        assert!(g32.contains("/g32/test/html/body/a/href.found"), "{g32:?}");
        assert!(g32.iter().all(|p| p.starts_with("/g32/test/")));

        // hybrid-mix: the URL-addressable pages under the fixture path.
        let hm = known_endpoints(&FixtureManifest::embedded("hybrid-mix").unwrap()).unwrap();
        assert_eq!(
            hm,
            set(&[
                "/hybrid-mix",
                "/hybrid-mix/docs-index.html",
                "/hybrid-mix/docs-install.html",
                "/hybrid-mix/docs-configure.html",
                "/hybrid-mix/docs-faq.html",
                "/hybrid-mix/pricing.html",
                "/hybrid-mix/app.html",
            ])
        );

        // a fixture without an endpoint list has no recall
        assert_eq!(known_endpoints(&FixtureManifest::embedded("g01").unwrap()), None);
    }

    // ---- statistics ---------------------------------------------------------------------------

    #[test]
    fn percentiles_use_the_nearest_rank() {
        let v: Vec<f64> = (1..=10).map(f64::from).collect();
        assert!((percentile(&v, 50) - 5.0).abs() < f64::EPSILON);
        assert!((percentile(&v, 95) - 10.0).abs() < f64::EPSILON);
        assert!((percentile(&v, 100) - 10.0).abs() < f64::EPSILON);
        assert!((percentile(&v, 0) - 1.0).abs() < f64::EPSILON);
        assert!((percentile(&[7.0], 95) - 7.0).abs() < f64::EPSILON);
        assert!(percentile(&[], 50).abs() < f64::EPSILON);
        let hundred: Vec<f64> = (1..=100).map(f64::from).collect();
        assert!((percentile(&hundred, 95) - 95.0).abs() < f64::EPSILON);
        assert!((percentile(&hundred, 50) - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn summarize_derives_every_metric_from_the_recorded_hits() {
        let hits = vec![
            Hit::new("GET", "/robots.txt", 200, ms(10)),
            Hit::new("GET", "/s1/", 200, ms(20)),
            Hit::new("GET", "/s1/about", 200, ms(30)),
            Hit::new("GET", "/s1/missing", 404, ms(500)),
            Hit::new("GET", "/s1/error", 500, ms(600)),
            Hit::new("POST", "/s1/form", 200, ms(700)),
            Hit::new("GET", "/s1/dead", 502, ms(800)),
        ];
        let known = set(&["/s1", "/s1/about", "/s1/team", "/s1/blog"]);
        let found = set(&["/s1", "/s1/about", "/s1/other"]);
        let s = summarize(3, found, Some(&known), &hits, 2.0);
        let m = &s.metrics;
        assert_eq!((m.pages, m.requests, m.errors, m.endpoints), (3, 7, 2, 3));
        assert_eq!((m.known, m.found), (Some(4), Some(2)));
        assert_eq!(m.recall, Some(0.5));
        assert!((m.seconds - 2.0).abs() < f64::EPSILON && (m.rps - 3.5).abs() < f64::EPSILON);
        // only the three 2xx GETs count as page latency: 10, 20, 30 ms
        assert_eq!(s.latencies_ms.len(), 3);
        assert!(
            (m.p50_ms - 20.0).abs() < 1e-9 && (m.p95_ms - 30.0).abs() < 1e-9,
            "{m:?}"
        );

        let no_truth = summarize(0, BTreeSet::new(), None, &[], 0.0);
        assert_eq!(
            (
                no_truth.metrics.known,
                no_truth.metrics.found,
                no_truth.metrics.recall
            ),
            (None, None, None)
        );
        assert!(no_truth.metrics.rps.abs() < f64::EPSILON && no_truth.metrics.p95_ms.abs() < f64::EPSILON);
    }

    fn synth(pages: u64, requests: u64, seconds: f64, found: u64, known: u64, latencies: &[f64]) -> Sample {
        Sample::new(
            metrics(json!({
                "pages": pages, "endpoints": found, "known": known, "found": found,
                "recall": found as f64 / known as f64,
                "requests": requests, "errors": 0, "seconds": seconds,
            })),
            latencies.to_vec(),
            BTreeSet::new(),
        )
    }

    #[test]
    fn combine_takes_the_per_field_median_and_pools_latency_across_repeats() {
        let samples = vec![
            synth(10, 12, 3.0, 9, 10, &[5.0, 1.0]),
            synth(30, 14, 1.0, 10, 10, &[3.0]),
            synth(20, 13, 2.0, 8, 10, &[4.0, 2.0]),
        ];
        let m = combine(&samples);
        assert_eq!((m.pages, m.requests), (20, 13));
        assert!((m.seconds - 2.0).abs() < f64::EPSILON);
        assert_eq!((m.known, m.found), (Some(10), Some(9)));
        assert_eq!(m.recall, Some(0.9));
        assert!((m.rps - 6.5).abs() < 1e-9, "{}", m.rps);
        // pooled and sorted: 1 2 3 4 5 -> p50 = 3, p95 = 5
        assert!((m.p50_ms - 3.0).abs() < f64::EPSILON && (m.p95_ms - 5.0).abs() < f64::EPSILON);

        assert_eq!(combine(&[]), Metrics::default());
    }

    #[test]
    fn assemble_sums_counts_into_an_aggregate_per_profile() {
        let rows = vec![
            Row::new(
                "gym:a",
                Profile::Static,
                vec![synth(10, 20, 2.0, 5, 10, &[1.0, 2.0])],
            ),
            Row::new(
                "gym:b",
                Profile::Static,
                vec![synth(30, 40, 3.0, 15, 20, &[3.0, 4.0])],
            ),
            Row::new(
                "gym:a",
                Profile::CompatFlagDefaults,
                vec![synth(1, 2, 1.0, 1, 10, &[9.0])],
            ),
        ];
        let report = Report::assemble(3, 77, &rows);
        assert_eq!((report.schema, report.repeat, report.seed), (SCHEMA, 3, 77));
        assert_eq!(
            report.results.keys().map(String::as_str).collect::<Vec<_>>(),
            ["gym:a", "gym:b"]
        );
        assert_eq!(
            report.results["gym:a"]
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["compat-flag-defaults", "static"]
        );

        let agg = &report.aggregate["static"];
        assert_eq!((agg.pages, agg.requests, agg.endpoints), (40, 60, 20));
        assert_eq!((agg.known, agg.found), (Some(30), Some(20)));
        assert!((agg.recall.unwrap() - 20.0 / 30.0).abs() < 1e-12);
        assert!((agg.seconds - 5.0).abs() < f64::EPSILON && (agg.rps - 12.0).abs() < 1e-9);
        assert!((agg.p50_ms - 2.0).abs() < f64::EPSILON && (agg.p95_ms - 4.0).abs() < f64::EPSILON);
        assert_eq!(report.aggregate["compat-flag-defaults"].pages, 1);
    }

    // ---- baseline comparison ------------------------------------------------------------------

    #[test]
    fn delta_labels_follow_the_reference_report() {
        assert_eq!(delta_label(0.0, 0.0), "=");
        assert_eq!(delta_label(0.0, 3.0), "new");
        assert_eq!(delta_label(100.0, 110.0), "+10%");
        assert_eq!(delta_label(100.0, 50.0), "-50%");
        assert_eq!(delta_label(100.0, 99.8), "=");
        assert_eq!(delta_label(28.0, 20.0), "-29%");
    }

    #[test]
    fn a_run_worse_than_the_baseline_flags_every_worse_gated_metric() {
        let current = report(
            &[(
                "gym:s1",
                "static",
                doc(json!({"pages": 20, "recall": 0.8, "seconds": 3.0})),
            )],
            &[],
        );
        let baseline = report(&[("gym:s1", "static", doc(json!({})))], &[]);

        let regressions = compare(&current, &baseline, 10.0, &Metric::gated()).unwrap();
        // pages 28 -> 20 is 28.6 % worse, recall 1.0 -> 0.8 is 20 % worse, seconds 2 -> 3 is 50 % worse
        let metrics: Vec<Metric> = regressions.iter().map(|r| r.metric).collect();
        assert_eq!(
            metrics,
            [Metric::Pages, Metric::Recall, Metric::Seconds],
            "{regressions:?}"
        );
        for (r, expected) in regressions.iter().zip([200.0 / 7.0, 20.0, 50.0]) {
            assert!((r.worse_pct - expected).abs() < 1e-9, "{r}");
            assert!(r.target == "gym:s1" && r.profile == "static");
        }
        let text = regressions[0].to_string();
        assert!(
            text.contains("gym:s1/static")
                && text.contains("pages")
                && text.contains("28")
                && text.contains("20"),
            "{text}"
        );

        // the allowance is a threshold: 30 % tolerates pages and recall, 60 % tolerates everything
        let at_30: Vec<_> = compare(&current, &baseline, 30.0, &Metric::gated())
            .unwrap()
            .iter()
            .map(|r| r.metric)
            .collect();
        assert_eq!(at_30, [Metric::Seconds]);
        assert!(compare(&current, &baseline, 60.0, &Metric::gated())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_run_better_than_or_equal_to_the_baseline_flags_nothing_even_at_zero_allowance() {
        let current = report(
            &[("gym:s1", "static", doc(json!({})))],
            &[("static", doc(json!({})))],
        );
        let worse_baseline = report(
            &[(
                "gym:s1",
                "static",
                doc(json!({"pages": 10, "recall": 0.5, "seconds": 9.0, "p95_ms": 50.0, "rps": 1.0})),
            )],
            &[("static", doc(json!({"pages": 10})))],
        );
        assert!(compare(&current, &worse_baseline, 0.0, &Metric::gated())
            .unwrap()
            .is_empty());
        assert!(compare(&current, &current, 0.0, &Metric::gated())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn lower_is_better_metrics_leaving_zero_always_regress_and_higher_is_better_ones_never_do() {
        let clean = report(&[("t", "static", doc(json!({"errors": 0})))], &[]);
        let broken = report(&[("t", "static", doc(json!({"errors": 3})))], &[]);
        let r = compare(&broken, &clean, 1_000_000.0, &[Metric::Errors]).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[0].worse_pct.is_infinite());
        assert!(r[0].to_string().contains("from zero"), "{}", r[0]);
        // the other way round is an improvement
        assert!(compare(&clean, &broken, 0.0, &[Metric::Errors])
            .unwrap()
            .is_empty());
        // a higher-is-better metric at zero in the baseline cannot get worse
        let zero = report(&[("t", "static", doc(json!({"pages": 0})))], &[]);
        assert!(compare(&zero, &zero, 0.0, &[Metric::Pages]).unwrap().is_empty());
    }

    #[test]
    fn the_gate_selects_the_metrics_and_cells_absent_from_either_side_are_skipped() {
        let current = report(
            &[
                ("t", "static", doc(json!({"seconds": 4.0, "pages": 1}))),
                ("t", "compat-flag-defaults", doc(json!({"pages": 1}))),
                ("new-target", "static", doc(json!({"pages": 1}))),
                (
                    "nogt",
                    "static",
                    doc(json!({"recall": null, "known": null, "found": null})),
                ),
            ],
            &[],
        );
        let baseline = report(
            &[
                ("t", "static", doc(json!({}))),
                ("nogt", "static", doc(json!({}))),
                ("gone", "static", doc(json!({}))),
            ],
            &[],
        );
        // only the seconds cell is gated; the pages regression of t/static is ignored
        let seconds = compare(&current, &baseline, 10.0, &[Metric::Seconds]).unwrap();
        assert_eq!(seconds.len(), 1);
        assert_eq!(
            (seconds[0].target.as_str(), seconds[0].metric),
            ("t", Metric::Seconds)
        );

        // t/compat-flag-defaults and new-target/static have no baseline cell, `gone` has no current
        // cell, nogt has no recall in the current run: only t/static compares, on pages and seconds
        let all = compare(&current, &baseline, 10.0, &Metric::gated()).unwrap();
        let cells: Vec<(&str, &str, Metric)> = all
            .iter()
            .map(|r| (r.target.as_str(), r.profile.as_str(), r.metric))
            .collect();
        assert_eq!(
            cells,
            [("t", "static", Metric::Pages), ("t", "static", Metric::Seconds)],
            "{all:?}"
        );
    }

    #[test]
    fn aggregate_rows_are_compared_under_the_aggregate_label() {
        let current = report(&[], &[("static", doc(json!({"pages": 10})))]);
        let baseline = report(&[], &[("static", doc(json!({"pages": 28})))]);
        let r = compare(&current, &baseline, 10.0, &[Metric::Pages]).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].target.as_str(), r[0].profile.as_str()),
            (AGGREGATE_LABEL, "static")
        );
    }

    #[test]
    fn the_aggregate_of_a_subset_is_not_compared_with_the_aggregate_of_the_whole() {
        let cell = |pages: u64| doc(json!({ "pages": pages }));
        let whole = report(
            &[("a", "static", cell(10)), ("b", "static", cell(18))],
            &[("static", cell(28))],
        );
        let subset = report(&[("a", "static", cell(10))], &[("static", cell(10))]);
        assert!(!subset.covers_same_targets(&whole) && whole.covers_same_targets(&whole));
        // 10 against 28 would be a 64 % regression, but the two aggregates cover different targets
        assert!(compare(&subset, &whole, 0.0, &[Metric::Pages])
            .unwrap()
            .is_empty());
        let table = subset.table(Some(&whole));
        let aggregate = table.lines().find(|l| l.starts_with(AGGREGATE_LABEL)).unwrap();
        assert!(
            !aggregate
                .split_whitespace()
                .skip(2)
                .any(|cell| cell.contains('(')),
            "{aggregate}"
        );
        // the cell both reports share is still compared
        let shared = table
            .lines()
            .find(|l| l.split_whitespace().next() == Some("a"))
            .unwrap();
        assert!(shared.contains("10 (=)"), "{shared}");
    }

    #[test]
    fn compare_rejects_unusable_allowances_and_ungateable_metrics() {
        let r = report(&[("t", "static", doc(json!({})))], &[]);
        for bad in [-1.0, f64::NAN, f64::INFINITY] {
            let err = compare(&r, &r, bad, &Metric::gated()).unwrap_err().to_string();
            assert!(err.contains("--max-regress"), "{bad}: {err}");
        }
        let err = compare(&r, &r, 5.0, &[Metric::Pages, Metric::Requests])
            .unwrap_err()
            .to_string();
        assert!(err.contains("requests") && err.contains("gated"), "{err}");
        assert!(!Metric::gated().contains(&Metric::Requests));
    }

    // ---- output shapes ------------------------------------------------------------------------

    #[test]
    fn the_table_has_a_header_one_row_per_cell_and_the_aggregate_rows() {
        let rep = report(
            &[
                ("gym:s1", "static", doc(json!({}))),
                (
                    "gym:s1",
                    "compat-flag-defaults",
                    doc(json!({"recall": 0.82, "pages": 23})),
                ),
                (
                    "gym:x",
                    "static",
                    doc(json!({"recall": null, "known": null, "found": null})),
                ),
            ],
            &[
                ("static", doc(json!({}))),
                ("compat-flag-defaults", doc(json!({}))),
            ],
        );
        let table = rep.table(None);
        let lines: Vec<Vec<&str>> = table.lines().map(|l| l.split_whitespace().collect()).collect();
        assert_eq!(
            lines[0],
            [
                "target",
                "profile",
                "pages",
                "endpoints",
                "recall",
                "requests",
                "errors",
                "seconds",
                "rps",
                "p50_ms",
                "p95_ms"
            ]
        );
        // header + 3 cells + 2 aggregates; targets sorted, then profiles sorted
        assert_eq!(lines.len(), 6, "{table}");
        assert_eq!(&lines[1][..2], ["gym:s1", "compat-flag-defaults"]);
        assert_eq!(&lines[2][..2], ["gym:s1", "static"]);
        assert_eq!(&lines[3][..2], ["gym:x", "static"]);
        assert_eq!(&lines[4][..2], [AGGREGATE_LABEL, "compat-flag-defaults"]);
        assert_eq!(&lines[5][..2], [AGGREGATE_LABEL, "static"]);
        // values: ints plain, recall as a percentage, `-` without ground truth, 2 decimals for time
        assert_eq!(
            lines[1][2..],
            ["23", "30", "82.0%", "40", "0", "2.00", "20.0", "1.00", "2.00"]
        );
        assert_eq!(lines[3][4], "-");
        // columns are aligned: every line has its first cell at column 0 and no trailing spaces
        assert!(table.lines().all(|l| !l.ends_with(' ')));
        let profile_col: Vec<usize> = table
            .lines()
            .map(|l| {
                l.find("static")
                    .or_else(|| l.find("compat-flag-defaults"))
                    .or_else(|| l.find("profile"))
                    .unwrap()
            })
            .collect();
        assert!(profile_col.windows(2).all(|w| w[0] == w[1]), "{table}");
    }

    #[test]
    fn a_baseline_annotates_every_comparable_cell_with_its_change() {
        let current = report(
            &[
                (
                    "t",
                    "static",
                    doc(json!({"pages": 20, "errors": 2, "requests": 44})),
                ),
                ("t", "other", doc(json!({}))),
            ],
            &[],
        );
        let baseline = report(&[("t", "static", doc(json!({"errors": 0})))], &[]);
        let table = current.table(Some(&baseline));
        let row = table
            .lines()
            .find(|l| l.split_whitespace().take(2).eq(["t", "static"]))
            .unwrap();
        assert!(row.contains("20 (-29%)"), "{row}");
        assert!(row.contains("2 (new)"), "{row}");
        assert!(row.contains("44 (+10%)"), "{row}");
        assert!(row.contains("100.0% (=)"), "{row}");
        // a cell without a baseline counterpart stays bare
        let other = table.lines().find(|l| l.contains("other")).unwrap();
        assert!(!other.contains('('), "{other}");
    }

    #[test]
    fn the_json_report_has_a_stable_shape_and_round_trips() {
        let rows = vec![Row::new(
            "gym:s1",
            Profile::Static,
            vec![Sample::new(
                metrics(json!({"pages": 2, "endpoints": 2, "requests": 3, "seconds": 1.5})),
                vec![2.0, 1.0],
                set(&["/s1", "/s1/about"]),
            )],
        )];
        let rep = Report::assemble(1, 5, &rows);
        let json = rep.to_json().unwrap();
        assert!(json.ends_with("}\n"));
        let v: Value = serde_json::from_str(&json).unwrap();

        let keys = |v: &Value| -> Vec<String> { v.as_object().unwrap().keys().cloned().collect() };
        assert_eq!(
            keys(&v),
            ["aggregate", "endpoints", "repeat", "results", "schema", "seed"]
        );
        assert_eq!(
            (v["schema"].as_u64(), v["repeat"].as_u64(), v["seed"].as_u64()),
            (Some(1), Some(1), Some(5))
        );
        assert_eq!(
            keys(&v["results"]["gym:s1"]["static"]),
            [
                "endpoints",
                "errors",
                "found",
                "known",
                "p50_ms",
                "p95_ms",
                "pages",
                "recall",
                "requests",
                "rps",
                "seconds"
            ]
        );
        assert_eq!(keys(&v["aggregate"]), ["static"]);
        assert_eq!(v["endpoints"]["gym:s1"]["static"], json!(["/s1", "/s1/about"]));
        assert!(v["results"]["gym:s1"]["static"]["recall"].is_null());

        assert_eq!(Report::from_json(&json).unwrap(), rep);

        let mut other = v.clone();
        other["schema"] = json!(SCHEMA + 1);
        let err = Report::from_json(&other.to_string()).unwrap_err().to_string();
        assert!(err.contains("schema"), "{err}");
        assert!(matches!(Report::from_json("{"), Err(BenchError::Json(_))));
    }

    // ---- the recorder -------------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_recorder_forwards_the_proxy_host_and_records_status_and_latency() {
        let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let recorder = Recorder::start(&Url::parse(&gym.base_url).unwrap())
            .await
            .unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let base = recorder.base_url();

        let robots = client.get(format!("{base}/robots.txt")).send().await.unwrap();
        assert_eq!(robots.status().as_u16(), 200);
        let body = robots.text().await.unwrap();
        // the gym builds the sitemap URL from the Host it receives: the proxy's, not its own
        let proxy_host = base.trim_start_matches("http://");
        assert!(
            body.contains(&format!("Sitemap: http://{proxy_host}/s1/sitemap.xml")),
            "{body}"
        );

        assert_eq!(
            client
                .get(format!("{base}/s1/missing"))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            404
        );
        assert_eq!(
            client
                .get(format!("{base}/s1/error?x=1"))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            500
        );
        let page = client.get(format!("{base}/s1/about/")).send().await.unwrap();
        assert_eq!(page.status().as_u16(), 200);
        assert!(page.text().await.unwrap().contains("<html"));

        let hits = recorder.hits();
        let seen: Vec<(&str, &str, u16)> = hits
            .iter()
            .map(|h| (h.method.as_str(), h.path.as_str(), h.status))
            .collect();
        assert_eq!(
            seen,
            [
                ("GET", "/robots.txt", 200),
                ("GET", "/s1/missing", 404),
                ("GET", "/s1/error", 500),
                ("GET", "/s1/about/", 200),
            ]
        );
        assert!(hits.iter().all(|h| h.latency > Duration::ZERO));
        assert_eq!(hits.iter().filter(|h| h.is_error()).count(), 1);
        assert_eq!(hits.iter().filter(|h| h.is_page()).count(), 2);
        // the gym saw exactly the forwarded requests
        assert_eq!(gym.ledger().ops("s1").len(), 3);

        recorder.shutdown().await;
        gym.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_recorder_answers_502_when_the_upstream_is_gone_and_refuses_non_http_upstreams() {
        // a port nothing listens on
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = format!("http://{}", free.local_addr().unwrap());
        drop(free);
        let recorder = Recorder::start(&Url::parse(&dead).unwrap()).await.unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let status = client
            .get(format!("{}/x", recorder.base_url()))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 502);
        let hits = recorder.hits();
        assert_eq!((hits.len(), hits[0].status, hits[0].is_error()), (1, 502, true));
        recorder.shutdown().await;

        let err = Recorder::start(&Url::parse("ftp://example.test/").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, BenchError::CrawlBench(_)), "{err}");
    }

    // ---- real crawls --------------------------------------------------------------------------

    fn bench(targets: &[&str], profiles: &[Profile]) -> BenchConfig {
        let mut cfg = BenchConfig::new(targets.iter().map(|t| Target::parse(t).unwrap()).collect());
        cfg.profiles = profiles.to_vec();
        cfg.repeat = 1;
        cfg.duration_seconds = 60;
        cfg
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_static_profile_reaches_every_known_endpoint_of_s1_and_reports_server_side_metrics() {
        let cfg = bench(&["gym:s1"], &[Profile::Static]);
        let mut progress = Vec::new();
        let report = run(&cfg, |p| {
            progress.push((p.target.to_owned(), p.profile, p.run, p.of))
        })
        .await
        .unwrap();
        assert_eq!(progress, [("gym:s1".to_owned(), Profile::Static, 1, 1)]);

        let m = &report.results["gym:s1"]["static"];
        // the 28 pages robots.txt allows are fetched and all 28 known endpoints are discovered
        assert_eq!(m.pages, 28, "{m:?}");
        assert_eq!(
            (m.known, m.found, m.recall),
            (Some(28), Some(28), Some(1.0)),
            "{m:?}"
        );
        assert!(m.endpoints >= 28, "{m:?}");
        // the target saw the pages plus robots.txt, the sitemap and the failing urls
        assert!(m.requests >= 28 + 2 + 2, "{m:?}");
        assert!(m.errors >= 1, "the 500 page is a server error: {m:?}");
        assert!(m.seconds > 0.0 && m.rps > 0.0, "{m:?}");
        assert!(m.p50_ms > 0.0 && m.p95_ms >= m.p50_ms, "{m:?}");

        let found = &report.endpoints["gym:s1"]["static"];
        assert!(found.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
        assert!(
            found.iter().any(|p| p == "/s1/archive/y1"),
            "reached through the sitemap: {found:?}"
        );
        assert!(
            !found
                .iter()
                .any(|p| p.contains("example.org") || p.contains("external")),
            "{found:?}"
        );
        // the aggregate of a single row is the row
        let agg = &report.aggregate["static"];
        assert_eq!(
            (agg.pages, agg.requests, agg.recall),
            (m.pages, m.requests, m.recall)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_discovered_endpoint_set_is_identical_across_runs() {
        let mut cfg = bench(&["gym:s1", "gym:hybrid-mix"], &[Profile::Static]);
        cfg.repeat = 2;
        let first = run(&cfg, |_| {}).await.unwrap();
        let second = run(&cfg, |_| {}).await.unwrap();
        assert_eq!(first.endpoints, second.endpoints);
        for target in ["gym:s1", "gym:hybrid-mix"] {
            let (a, b) = (
                &first.results[target]["static"],
                &second.results[target]["static"],
            );
            assert_eq!(
                (a.pages, a.endpoints, a.known, a.found, a.recall),
                (b.pages, b.endpoints, b.known, b.found, b.recall),
                "{target}"
            );
            assert!(a.pages > 0 && a.recall.is_some());
        }
        // hybrid-mix: the static plane reaches exactly the URL-addressable pages
        assert_eq!(first.results["gym:hybrid-mix"]["static"].recall, Some(1.0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_compat_flag_defaults_profile_crawls_differently_from_the_static_profile() {
        let cfg = bench(&["gym:s1"], &[Profile::Static, Profile::CompatFlagDefaults]);
        let report = run(&cfg, |_| {}).await.unwrap();
        let s = &report.results["gym:s1"]["static"];
        let k = &report.results["gym:s1"]["compat-flag-defaults"];
        // the compat flag defaults do not read the sitemap, so the five archive pages nothing links to are missed
        assert_eq!(s.recall, Some(1.0), "{s:?}");
        assert!(k.recall.unwrap() < s.recall.unwrap(), "{k:?}");
        assert!(k.found.unwrap() <= 28 - 5, "{k:?}");
        let (static_set, compat_set) = (
            &report.endpoints["gym:s1"]["static"],
            &report.endpoints["gym:s1"]["compat-flag-defaults"],
        );
        assert!(static_set.iter().any(|p| p == "/s1/archive/y1"));
        assert!(
            !compat_set.iter().any(|p| p.starts_with("/s1/archive")),
            "{compat_set:?}"
        );
        // both profiles still crawled the linked site
        assert!(k.pages >= 20, "{k:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_target_without_ground_truth_reports_no_recall_and_the_crawl_maze_has_a_list() {
        let cfg = bench(&["gym:g01", "gym:g32"], &[Profile::Static]);
        let report = run(&cfg, |_| {}).await.unwrap();
        let g01 = &report.results["gym:g01"]["static"];
        assert_eq!((g01.known, g01.found, g01.recall), (None, None, None));
        assert!(g01.pages >= 1);
        let maze = &report.results["gym:g32"]["static"];
        assert!(maze.known.unwrap() > 20, "{maze:?}");
        assert!(maze.found.unwrap() > 0 && maze.recall.unwrap() > 0.0, "{maze:?}");
        // the aggregate recall covers the targets that have a list only
        let agg = &report.aggregate["static"];
        assert_eq!((agg.known, agg.found), (maze.known, maze.found));
        assert_eq!(agg.pages, g01.pages + maze.pages);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_committed_baseline_still_holds_for_the_coverage_metrics() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/baselines/crawl-bench.json");
        let baseline = Report::from_json(&std::fs::read_to_string(&path).unwrap()).unwrap();
        // the recording is not vacuous: the compat flag defaults cover less of the crawl maze than ours
        assert_eq!(baseline.results["gym:s1"]["static"].recall, Some(1.0));
        let maze = &baseline.results["gym:g32"];
        assert!(maze["compat-flag-defaults"].recall.unwrap() < maze["static"].recall.unwrap());

        let cfg = bench(
            &["gym:s1", "gym:hybrid-mix"],
            &[Profile::Static, Profile::CompatFlagDefaults],
        );
        let report = run(&cfg, |_| {}).await.unwrap();
        let gate = [Metric::Pages, Metric::Endpoints, Metric::Recall];
        let regressions = compare(&report, &baseline, 0.0, &gate).unwrap();
        assert!(
            regressions.is_empty(),
            "coverage fell below bench/baselines/crawl-bench.json: {regressions:?}"
        );
        // those four cells exist on both sides, so the comparison was not vacuous
        for (target, profile) in [
            ("gym:s1", "static"),
            ("gym:s1", "compat-flag-defaults"),
            ("gym:hybrid-mix", "static"),
            ("gym:hybrid-mix", "compat-flag-defaults"),
        ] {
            assert!(
                baseline.results[target].contains_key(profile)
                    && report.results[target].contains_key(profile)
            );
        }
    }

    // ---- the binary ---------------------------------------------------------------------------

    const BIN: &str = env!("CARGO_BIN_EXE_crawl-bench");

    fn run_bin(args: &[&str]) -> std::process::Output {
        std::process::Command::new(BIN).args(args).output().unwrap()
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn the_help_documents_targets_profiles_baselines_and_exit_status() {
        let out = run_bin(&["--help"]);
        assert!(out.status.success());
        let help = text(&out.stdout);
        for needle in [
            "TARGETS",
            "gym:<fixture>",
            "http(s)://",
            "PROFILES",
            "static",
            "compat-flag-defaults",
            "crawlx-defaults",
            "BASELINES",
            "--baseline",
            "--max-regress",
            "--gate-metrics",
            "EXIT STATUS",
            "--json",
            "--repeat",
            "--target",
            "--profile",
            "recall",
            "p95",
        ] {
            assert!(help.contains(needle), "--help lacks `{needle}`:\n{help}");
        }
    }

    #[test]
    fn the_binary_exits_1_on_a_regression_and_0_otherwise_and_2_on_usage_errors() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.json");
        let out_s = out.to_str().unwrap();
        let base = ["--target", "gym:s1", "--profile", "static", "--repeat", "1"];
        let with = |extra: &[&str]| -> Vec<String> {
            base.iter().chain(extra.iter()).map(|s| (*s).to_owned()).collect()
        };
        let run = |args: &[String]| run_bin(&args.iter().map(String::as_str).collect::<Vec<_>>());

        // 1. a plain run prints the table and writes the report
        let first = run(&with(&["--json", out_s]));
        assert!(first.status.success(), "{}", text(&first.stderr));
        let table = text(&first.stdout);
        assert!(
            table.contains("gym:s1") && table.contains(AGGREGATE_LABEL),
            "{table}"
        );
        let progress = text(&first.stderr);
        assert!(progress.contains("gym:s1/static #1/1: pages=28"), "{progress}");
        let written = Report::from_json(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(written.results["gym:s1"]["static"].pages, 28);

        // 2. the deterministic metrics equal the baseline written by run 1: pass at zero allowance
        let same = run(&with(&[
            "--baseline",
            out_s,
            "--max-regress",
            "0",
            "--gate-metrics",
            "pages,endpoints,recall",
        ]));
        assert_eq!(same.status.code(), Some(0), "{}", text(&same.stderr));
        assert!(text(&same.stdout).contains("(=)"));

        // 3. a baseline that crawled more pages than this run is a regression
        let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        doc["results"]["gym:s1"]["static"]["pages"] = json!(1000);
        let better = dir.path().join("better.json");
        std::fs::write(&better, doc.to_string()).unwrap();
        let regressed = run(&with(&[
            "--baseline",
            better.to_str().unwrap(),
            "--max-regress",
            "10",
            "--gate-metrics",
            "pages",
        ]));
        assert_eq!(regressed.status.code(), Some(1));
        let stderr = text(&regressed.stderr);
        assert!(
            stderr.contains("regression") && stderr.contains("gym:s1/static") && stderr.contains("pages"),
            "{stderr}"
        );
        assert!(
            text(&regressed.stdout).contains("(-97%)"),
            "the table still shows the change"
        );

        // 4. a baseline that crawled fewer pages is an improvement
        doc["results"]["gym:s1"]["static"]["pages"] = json!(3);
        let weaker = dir.path().join("weaker.json");
        std::fs::write(&weaker, doc.to_string()).unwrap();
        let improved = run(&with(&[
            "--baseline",
            weaker.to_str().unwrap(),
            "--max-regress",
            "0",
            "--gate-metrics",
            "pages",
        ]));
        assert_eq!(improved.status.code(), Some(0), "{}", text(&improved.stderr));

        // 5. a baseline without --max-regress only annotates
        let annotated = run(&with(&["--baseline", better.to_str().unwrap()]));
        assert_eq!(annotated.status.code(), Some(0));
        assert!(text(&annotated.stdout).contains("(-97%)"));
    }

    #[test]
    fn the_binary_rejects_bad_usage_before_crawling() {
        let cases: [(&[&str], &str); 6] = [
            (&["--target", "gym:no-such-fixture"], "no-such-fixture"),
            (&["--target", "ftp://example.test/"], "gym:<fixture>"),
            (&["--target", "gym:s1", "--profile", "turbo"], "turbo"),
            (&["--target", "gym:s1", "--max-regress", "5"], "--baseline"),
            (&["--target", "gym:s1", "--repeat", "0"], "--repeat"),
            (
                &["--target", "gym:s1", "--baseline", "/nonexistent/baseline.json"],
                "baseline.json",
            ),
        ];
        for (args, needle) in cases {
            let out = run_bin(args);
            assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out.stderr));
            let stderr = text(&out.stderr);
            assert!(stderr.contains(needle), "{args:?}: {stderr}");
        }
        let none = run_bin(&[]);
        assert_eq!(none.status.code(), Some(2));
        assert!(text(&none.stderr).contains("--target"));
    }
}
