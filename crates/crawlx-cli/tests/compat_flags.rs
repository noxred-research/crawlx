//! The compatibility flags of `crawlx crawl`, each asserted by what it changes — the
//! request it builds, the requests a local site receives, or the files and text it produces.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/surface_site.rs"]
mod surface_site;

use clap::Parser as _;
use crawlx_core::config::{CrawlStrategy, HostScope, KnownFile, PageType};
use crawlx_core::{Clock, CreateCrawl, SystemClock, TenantId};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;
use crawlx_worker::surface::resume::ResumeState;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use surface_site::{Gauge, Page, Site};

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

fn record_for(origins: &[&str]) -> AuthorizationRecord {
    let now = SystemClock.now();
    AuthorizationRecord {
        // `localhost` may resolve to `::1` as well as `127.0.0.1` (dual-stack hosts): egress
        // checks every resolved address, so both loopbacks are authorized for the fixtures.
        authorized_networks: vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()],
        ..sample_record(TenantId::new(), now, origins)
    }
}

/// A scratch directory with an authorization record for `origins`.
struct Ctx {
    dir: tempfile::TempDir,
    authz: PathBuf,
}

impl Ctx {
    fn new(origins: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let authz = dir.path().join("authz.local.json");
        std::fs::write(&authz, serde_json::to_vec_pretty(&record_for(origins)).unwrap()).unwrap();
        Self { dir, authz }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn out(&self) -> PathBuf {
        self.path("out")
    }

    /// Static-mode flags that make a local crawl admissible and deterministic.
    fn base(&self) -> Vec<String> {
        [
            "--mode",
            "static",
            "--authorization-record",
            self.authz.to_str().unwrap(),
            "--allow-private-networks",
            "--seed",
            "20261027",
            "--delay-ms",
            "0",
            "--output",
            self.out().to_str().unwrap(),
        ]
        .map(str::to_owned)
        .to_vec()
    }
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| (*a).to_owned()).collect()
}

fn env_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// Run `crawlx crawl <args>` in this process with `env` as its environment.
async fn crawl_env(args: &[String], env: &[(&str, &str)]) -> (String, anyhow::Result<ExitCode>) {
    let mut argv = vec!["crawlx".to_owned(), "crawl".to_owned()];
    argv.extend_from_slice(args);
    let cli = crawlx_cli::Cli::try_parse_from(crawlx_cli::normalize_args(argv)).unwrap();
    let env = env_of(env);
    let mut out = Vec::new();
    let code = crawlx_cli::execute_with_env(cli, &mut out, &|k| env.get(k).cloned()).await;
    (String::from_utf8(out).unwrap(), code)
}

async fn crawl(args: &[String]) -> (String, anyhow::Result<ExitCode>) {
    crawl_env(args, &[]).await
}

#[tokio::test]
async fn native_strategies_schedule_new_children_against_pending_siblings() {
    for strategy in ["breadth-first", "depth-first", "priority"] {
        let site = Site::start(|_| {
            vec![
                (
                    "/",
                    Page::doc("Root", r#"<a href="/left">left</a><a href="/right">right</a>"#),
                ),
                ("/left", Page::doc("Left", r#"<a href="/admin/left">child</a>"#)),
                (
                    "/right",
                    Page::doc("Right", r#"<a href="/admin/right">child</a>"#),
                ),
                ("/admin/left", Page::doc("Left child", "<p>left leaf</p>")),
                ("/admin/right", Page::doc("Right child", "<p>right leaf</p>")),
            ]
        })
        .await;
        let ctx = Ctx::new(&[&site.base]);
        let mut args = vec![format!("{}/", site.base)];
        args.extend(ctx.base());
        args.extend(strings(&[
            "--concurrency",
            "1",
            "--strategy",
            strategy,
            "--depth",
            "3",
        ]));
        let (out, result) = crawl(&args).await;
        assert_eq!(result.unwrap(), ExitCode::SUCCESS, "{strategy}: {out}");
        let hits: Vec<_> = site
            .pages_hit()
            .into_iter()
            .filter(|path| {
                matches!(
                    path.as_str(),
                    "/" | "/left" | "/right" | "/admin/left" | "/admin/right"
                )
            })
            .collect();
        let mut all = hits.clone();
        all.sort();
        assert_eq!(
            all,
            ["/", "/admin/left", "/admin/right", "/left", "/right"],
            "{strategy}: {hits:?}"
        );
        assert_eq!(hits[0], "/");
        assert!(matches!(hits[1].as_str(), "/left" | "/right"));
        let first_child = format!("/admin{}", hits[1]);
        if strategy == "breadth-first" {
            assert!(matches!(hits[2].as_str(), "/left" | "/right"), "{hits:?}");
        } else {
            assert_eq!(
                hits[2], first_child,
                "{strategy}: new child must beat pending sibling: {hits:?}"
            );
        }
    }
}

#[tokio::test]
async fn scope_regex_files_filter_actual_requests_and_output() {
    let site = Site::start(|_| {
        vec![
            ("/", Page::doc("Root", r#"<a href="/allowed">allowed</a><a href="/blocked">blocked</a><a href="/outside">outside</a><a href="/inline">inline</a>"#)),
            ("/allowed", Page::doc("Allowed", "<p>allowed page</p>")),
            ("/blocked", Page::doc("Blocked", "<p>excluded page</p>")),
            ("/outside", Page::doc("Outside", "<p>outside include patterns</p>")),
            ("/inline", Page::doc("Inline", "<p>inline pattern page</p>")),
        ]
    })
    .await;
    let ctx = Ctx::new(&[&site.base]);
    let include = ctx.path("include.txt");
    let exclude = ctx.path("exclude.txt");
    std::fs::write(
        &include,
        format!(
            "# explicit scope source\n\n^{}/$\n/allowed$\n/blocked$\n",
            site.base
        ),
    )
    .unwrap();
    std::fs::write(&exclude, "# excluded even when included\n\n/blocked$\n").unwrap();
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .arg("crawl")
        .arg(format!("{}/", site.base))
        .args(ctx.base())
        .args(["-cs", include.to_str().unwrap(), "-cs", "/inline$"])
        .args(["-cos", exclude.to_str().unwrap(), "--silent", "-f", "url"])
        .env_clear()
        .env("TMPDIR", ctx.dir.path())
        .env("XDG_CACHE_HOME", ctx.path("cache"))
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut fetched = site.pages_hit();
    fetched.sort();
    assert_eq!(fetched, ["/", "/allowed", "/inline"]);
    let emitted = String::from_utf8(output.stdout).unwrap();
    let mut emitted: Vec<_> = emitted.lines().collect();
    emitted.sort_unstable();
    let mut expected = vec![
        format!("{}/", site.base),
        format!("{}/allowed", site.base),
        format!("{}/inline", site.base),
    ];
    expected.sort();
    assert_eq!(emitted, expected);

    // An unreadable text source fails before any new target request.
    std::fs::write(&include, [0xff]).unwrap();
    let mut args = vec![format!("{}/", site.base)];
    args.extend(ctx.base());
    args.extend(strings(&["--crawl-scope", include.to_str().unwrap()]));
    let (_, result) = crawl(&args).await;
    assert!(result.is_err());
    let mut after = site.pages_hit();
    after.sort();
    assert_eq!(after, fetched);
}

fn parse_crawl(args: &[&str]) -> crawlx_cli::CrawlArgs {
    let mut argv = vec!["crawlx", "crawl", "https://example.test/"];
    argv.extend_from_slice(args);
    let cli = crawlx_cli::Cli::try_parse_from(crawlx_cli::normalize_args(argv)).unwrap();
    let crawlx_cli::Command::Crawl(args) = cli.command else {
        panic!("crawl command");
    };
    *args
}

fn request_of(args: &[&str]) -> CreateCrawl {
    crawlx_cli::crawl::build_request(&parse_crawl(args)).unwrap()
}

#[test]
fn crawl_order_defaults_to_breadth_first_without_flags() {
    assert_eq!(request_of(&[]).scope.strategy, CrawlStrategy::BreadthFirst);
}

#[test]
fn crawl_order_aliases_select_the_same_strategy() {
    for (aliases, expected) in [
        (
            ["bfs", "breadth_first", "breadth-first"],
            CrawlStrategy::BreadthFirst,
        ),
        (["dfs", "depth_first", "depth-first"], CrawlStrategy::DepthFirst),
    ] {
        for alias in aliases {
            assert_eq!(
                request_of(&["--strategy", alias]).scope.strategy,
                expected,
                "{alias}"
            );
        }
    }
}

#[test]
fn crawl_order_defaults_to_breadth_first_in_config_files() {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in [
        ("crawl.json", r#"{"limits":{"urls":8}}"#),
        ("crawl.toml", "[crawl.limits]\nurls = 8\n"),
        ("crawl.yaml", "limit-urls: 8\n"),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        assert_eq!(
            request_of(&["--config", path.to_str().unwrap()]).scope.strategy,
            CrawlStrategy::BreadthFirst,
            "{name}"
        );
    }
}

#[test]
fn crawl_order_defaults_to_breadth_first_in_request_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("request.json");
    std::fs::write(&path, r#"{"seedUrl":"https://example.test/","scope":{}}"#).unwrap();
    assert_eq!(
        request_of(&["--request", path.to_str().unwrap()]).scope.strategy,
        CrawlStrategy::BreadthFirst
    );
}

#[test]
fn config_json_body_supplies_the_seed_when_no_seed_is_given() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crawl.json");
    std::fs::write(
        &path,
        r#"{"seedUrl":"https://config.test/start","limits":{"urls":8}}"#,
    )
    .unwrap();
    let argv = ["crawlx", "crawl", "--config", path.to_str().unwrap()];
    let cli = crawlx_cli::Cli::try_parse_from(crawlx_cli::normalize_args(argv)).unwrap();
    let crawlx_cli::Command::Crawl(args) = cli.command else {
        panic!("crawl command");
    };
    let request = crawlx_cli::crawl::build_request(&args).unwrap();
    assert_eq!(request.seed_url.as_str(), "https://config.test/start");
    assert_eq!(request.limits.urls, 8);
}

#[test]
fn compat_similarity_enables_and_backend_are_independent_in_every_order() {
    use crawlx_core::config::SimilarityMode;
    use crawlx_url::content_similarity::{Config, Index};

    let body = b"<html><body><main>alpha beta gamma delta epsilon zeta eta theta</main></body></html>";
    for (flags, mode) in [
        (vec![], SimilarityMode::Off),
        (vec!["-pcsm=tfidf"], SimilarityMode::Off),
        (vec!["-pcs"], SimilarityMode::Simhash),
        (vec!["-sdd"], SimilarityMode::Simhash),
        (vec!["-page-content-similar"], SimilarityMode::Simhash),
        (vec!["--similarity-deduplication"], SimilarityMode::Simhash),
        (vec!["-pcs=false", "-sdd=false"], SimilarityMode::Off),
        (vec!["-pcs=true", "-sdd=false"], SimilarityMode::Simhash),
        (vec!["-pcs=false", "-sdd=true"], SimilarityMode::Simhash),
        (vec!["-pcs=true", "-sdd=true"], SimilarityMode::Simhash),
    ] {
        let mut reversed = flags.clone();
        reversed.reverse();
        for flags in [flags, reversed] {
            let request = request_of(&flags);
            assert_eq!(request.scope.content_similarity.mode, mode, "{flags:?}");
            let mut index = Index::new(Config::from_request(&request.scope.content_similarity));
            assert!(!index.accept(body).filtered, "{flags:?}");
            assert_eq!(
                index.accept(body).filtered,
                mode != SimilarityMode::Off,
                "{flags:?}"
            );
            assert!(!request.scope.disable_unique_filter, "{flags:?}");
        }
    }
    for enable in [
        "-pcs",
        "-sdd",
        "-page-content-similar",
        "-similarity-deduplication",
    ] {
        for (backend, mode) in [
            ("simhash", SimilarityMode::Simhash),
            ("tfidf", SimilarityMode::Tfidf),
            ("bm25", SimilarityMode::Bm25),
            ("off", SimilarityMode::Off),
        ] {
            for flags in [
                vec![enable, "-pcsm", backend],
                vec!["-pcsm", backend, enable],
                vec![enable, "-page-content-similar-mode", backend],
            ] {
                let request = request_of(&flags);
                assert_eq!(request.scope.content_similarity.mode, mode, "{flags:?}");
                let mut index = Index::new(Config::from_request(&request.scope.content_similarity));
                assert!(!index.accept(body).filtered, "{flags:?}");
                assert_eq!(
                    index.accept(body).filtered,
                    mode != SimilarityMode::Off,
                    "{flags:?}"
                );
            }
        }
    }
    let request = request_of(&["-pcs", "-pcsd", "5", "-pcst", "0.9", "-pcsn", "2", "-duf"]);
    assert_eq!(request.scope.content_similarity.distance, 5);
    assert!((request.scope.content_similarity.threshold - 0.9).abs() < f64::EPSILON);
    assert_eq!(request.scope.content_similarity.budget, 2);
    assert!(request.scope.disable_unique_filter);
    let mut index = Index::new(Config::from_request(&request.scope.content_similarity));
    assert!(!index.accept(body).filtered);
    assert!(!index.accept(body).filtered);
    assert!(index.accept(body).filtered);
}

#[test]
fn compat_similarity_config_and_request_precedence_preserves_explicit_false() {
    use crawlx_core::config::SimilarityMode;

    let dir = tempfile::tempdir().unwrap();
    let yaml = dir.path().join("flags.yaml");
    let json = dir.path().join("request.json");
    std::fs::write(
        &json,
        r#"{"scope":{"contentSimilarity":{"mode":"bm25"},"urlExclude":["/denied"]}}"#,
    )
    .unwrap();
    for (config, flags, mode) in [
        (
            "page-content-similar: true\npage-content-similar-mode: tfidf\n",
            vec![],
            SimilarityMode::Tfidf,
        ),
        (
            "similarity-deduplication: true\n",
            vec!["-pcs=false"],
            SimilarityMode::Off,
        ),
        (
            "page-content-similar: true\n",
            vec!["-sdd=false"],
            SimilarityMode::Off,
        ),
        (
            "page-content-similar: false\n",
            vec!["-sdd"],
            SimilarityMode::Simhash,
        ),
        (
            "page-content-similar: true\npage-content-similar-mode: tfidf\n",
            vec!["-pcsm", "bm25"],
            SimilarityMode::Bm25,
        ),
        (
            "page-content-similar: false\npage-content-similar-mode: tfidf\n",
            vec!["-pcs"],
            SimilarityMode::Tfidf,
        ),
        (
            "page-content-similar: true\n",
            vec!["--content-similar", "off"],
            SimilarityMode::Off,
        ),
        ("content-similar: tfidf\n", vec!["-pcs"], SimilarityMode::Simhash),
        (
            "content-similar: tfidf\n",
            vec!["-pcsm", "bm25"],
            SimilarityMode::Off,
        ),
    ] {
        std::fs::write(&yaml, config).unwrap();
        let mut args = vec!["--config", yaml.to_str().unwrap()];
        args.extend(flags);
        assert_eq!(
            request_of(&args).scope.content_similarity.mode,
            mode,
            "{config} {args:?}"
        );
    }
    for config in [
        "page-content-similar: false\n",
        "similarity-deduplication: false\n",
        "page-content-similar: false\nsimilarity-deduplication: false\n",
    ] {
        std::fs::write(&yaml, config).unwrap();
        let before = request_of(&["--request", json.to_str().unwrap()]);
        let after = request_of(&[
            "--request",
            json.to_str().unwrap(),
            "--config",
            yaml.to_str().unwrap(),
        ]);
        assert_eq!(after.scope.content_similarity.mode, SimilarityMode::Off);
        assert_eq!(after.scope.url_exclude, before.scope.url_exclude);
        assert_eq!(
            serde_json::to_value(after.safety).unwrap(),
            serde_json::to_value(before.safety).unwrap()
        );
    }
    assert_eq!(
        request_of(&["--request", json.to_str().unwrap(), "-pcsm", "tfidf"])
            .scope
            .content_similarity
            .mode,
        SimilarityMode::Tfidf
    );
    for backend in ["simhash", "tfidf", "bm25"] {
        assert_eq!(
            request_of(&[
                "--request",
                json.to_str().unwrap(),
                "-pcs=false",
                "-pcsm",
                backend
            ])
            .scope
            .content_similarity
            .mode,
            SimilarityMode::Off
        );
    }
    for config in [
        "page-content-similar: maybe\n",
        "similarity-deduplication: 1\n",
        "page-content-similar-mode: unknown\n",
        "content-similar: tfidf\npage-content-similar: true\n",
    ] {
        std::fs::write(&yaml, config).unwrap();
        assert!(
            crawlx_cli::crawl::build_request(&parse_crawl(&["--config", yaml.to_str().unwrap(),])).is_err(),
            "{config}"
        );
    }
    for flags in [
        vec!["-pcs=maybe"],
        vec!["-sdd=1"],
        vec!["-pcsm", "unknown"],
        vec!["--content-similar", "tfidf", "-pcs"],
        vec!["-sdd", "--content-similar", "off"],
        vec!["-pcsm", "bm25", "--content-similar", "simhash"],
    ] {
        let mut argv = vec!["crawlx", "crawl", "https://example.test/"];
        argv.extend(flags);
        assert!(crawlx_cli::Cli::try_parse_from(crawlx_cli::normalize_args(argv)).is_err());
    }
    let mut args = parse_crawl(&["-pcs"]);
    args.url.content_similar = Some(crawlx_cli::crawl::SimilarityArg::Tfidf);
    assert!(crawlx_cli::crawl::build_request(&args)
        .unwrap_err()
        .to_string()
        .contains("conflicts"));
}

#[tokio::test]
async fn compat_similarity_runtime_smoke_filters_expansion_without_disabling_url_dedupe() {
    let site = Site::start(|_| {
        let similar = |link| Page::html(format!(
            "<html><body><main>alpha beta gamma delta epsilon zeta eta theta</main><nav><a href=\"/{link}\">next</a></nav></body></html>"
        ));
        vec![
            ("/", Page::doc("Root", r#"<a href="/a">a</a><a href="/a">again</a><a href="/b">b</a>"#)),
            ("/a", similar("a-child")),
            ("/b", similar("b-child")),
            ("/a-child", Page::doc("First", "<p>one</p>")),
            ("/b-child", Page::doc("Second", "<p>two</p>")),
        ]
    }).await;
    for (flags, filtered) in [
        (vec![], false),
        (vec!["-pcsm", "tfidf"], false),
        (vec!["-pcs"], true),
        (vec!["-sdd"], true),
        (vec!["-pcs", "-pcsm", "off"], false),
        (vec!["-pcs", "-duf"], true),
        (vec!["-sdd", "-pcsn", "2"], false),
    ] {
        let ctx = Ctx::new(&[&site.base]);
        let before_a = site.count("/a");
        let before_b = site.count("/b");
        let before_children = site.count("/a-child") + site.count("/b-child");
        let mut args = ctx.base();
        args.extend(strings(&["--concurrency", "1"]));
        args.extend(strings(&flags));
        args.push(format!("{}/", site.base));
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_crawlx"))
            .arg("crawl")
            .args(&args)
            .env_clear()
            .env("TMPDIR", ctx.dir.path())
            .env("XDG_CACHE_HOME", ctx.path("cache"))
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{flags:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(site.count("/a") - before_a, 1, "{flags:?}");
        assert_eq!(site.count("/b") - before_b, 1, "{flags:?}");
        assert_eq!(
            site.count("/a-child") + site.count("/b-child") - before_children,
            if filtered { 1 } else { 2 },
            "{flags:?}"
        );
        let metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ctx.out().join("metadata.json")).unwrap()).unwrap();
        assert_eq!(
            metadata
                .as_array()
                .unwrap()
                .iter()
                .filter(|page| page["metadata"]["dedupe"]["reason"] == "content_similar")
                .count(),
            usize::from(filtered),
            "{flags:?}"
        );
    }
}

#[test]
fn headless_no_scope_and_seconds_delay_reach_native_request_fields() {
    use crawlx_core::config::CrawlMode;

    for flags in [
        vec!["-hl", "-ns", "-rd", "2"],
        vec!["-headless", "-no-scope", "-delay=2"],
        vec!["--headless", "--no-scope", "--delay", "2"],
    ] {
        let request = request_of(&flags);
        assert_eq!(request.mode, CrawlMode::Dynamic, "{flags:?}");
        assert_eq!(request.scope.host_scope, HostScope::None, "{flags:?}");
        assert_eq!(request.politeness.delay_ms, 2000, "{flags:?}");
        assert!(!request.safety.allow_private_networks, "{flags:?}");
        assert!(request.safety.respect_robots_txt, "{flags:?}");
    }
    assert_eq!(request_of(&["-hh"]).mode, CrawlMode::Hybrid);
    assert_eq!(request_of(&["-rd=0"]).politeness.delay_ms, 0);
    assert_eq!(request_of(&["-rd", "4294967"]).politeness.delay_ms, 4_294_967_000);
    for value in ["4294968", "4294967295"] {
        let error = crawlx_cli::crawl::build_request(&parse_crawl(&["-rd", value])).unwrap_err();
        assert!(
            error.to_string().contains("overflows the millisecond field"),
            "{error:#}"
        );
    }
}

#[test]
fn compat_mode_scope_and_delay_conflicts_fail_in_both_orders() {
    for pair in [
        (vec!["-hl"], vec!["-hh"]),
        (vec!["-hl"], vec!["--mode", "static"]),
        (vec!["-hh"], vec!["--mode", "dynamic"]),
        (vec!["-ns"], vec!["-fs", "fqdn"]),
        (vec!["-rd", "1"], vec!["--delay-ms", "1000"]),
    ] {
        for reverse in [false, true] {
            let mut argv = vec!["crawlx", "crawl", "https://example.test/"];
            let (first, second) = if reverse {
                (&pair.1, &pair.0)
            } else {
                (&pair.0, &pair.1)
            };
            argv.extend(first);
            argv.extend(second);
            let error = crawlx_cli::Cli::try_parse_from(crawlx_cli::normalize_args(argv)).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        }
    }
    for flags in [
        vec!["-rd", "-1"],
        vec!["-rd", "1.5"],
        vec!["-rd", "4294967296"],
        vec!["-hl=false"],
    ] {
        let mut argv = vec!["crawlx", "crawl", "https://example.test/"];
        argv.extend(flags);
        assert!(crawlx_cli::Cli::try_parse_from(crawlx_cli::normalize_args(argv)).is_err());
    }

    // Public request construction must not rely only on clap's conflict checks.
    let mut flags = parse_crawl(&["-hl"]);
    flags.hybrid = true;
    assert!(crawlx_cli::crawl::build_request(&flags)
        .unwrap_err()
        .to_string()
        .contains("mutually exclusive"));
    let mut flags = parse_crawl(&["-ns"]);
    flags.url.field_scope = parse_crawl(&["-fs", "none"]).url.field_scope;
    assert!(crawlx_cli::crawl::build_request(&flags)
        .unwrap_err()
        .to_string()
        .contains("--field-scope"));
    let mut flags = parse_crawl(&["-rd", "1"]);
    flags.delay_ms = Some(1000);
    assert!(crawlx_cli::crawl::build_request(&flags)
        .unwrap_err()
        .to_string()
        .contains("--delay-ms"));
}

#[test]
fn compat_adapters_override_request_fields_without_changing_safety_or_url_filters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("request.json");
    std::fs::write(
        &path,
        r#"{"mode":"static","scope":{"hostScope":"fqdn","hostScopePattern":"^old.test$","urlInclude":["/allowed"],"urlExclude":["/denied"],"excludeHosts":["blocked.test"]},"politeness":{"delayMs":500}}"#,
    ).unwrap();
    let before = request_of(&["--request", path.to_str().unwrap()]);
    let after = request_of(&["--request", path.to_str().unwrap(), "-hl", "-ns", "-rd", "2"]);
    assert_eq!(after.mode, crawlx_core::config::CrawlMode::Dynamic);
    assert_eq!(after.scope.host_scope, HostScope::None);
    assert!(after.scope.host_scope_pattern.is_none());
    assert_eq!(after.scope.url_include, before.scope.url_include);
    assert_eq!(after.scope.url_exclude, before.scope.url_exclude);
    assert_eq!(after.scope.exclude_hosts, before.scope.exclude_hosts);
    assert_eq!(after.politeness.delay_ms, 2000);
    assert_eq!(
        serde_json::to_value(&after.safety).unwrap(),
        serde_json::to_value(&before.safety).unwrap()
    );
}

#[test]
fn compat_adapters_load_from_yaml_and_reject_cross_layer_conflicts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flags.yaml");
    std::fs::write(&path, "headless: true\nno-scope: true\ndelay: 2\n").unwrap();
    let config = path.to_str().unwrap();
    let request = request_of(&["--config", config]);
    assert_eq!(request.mode, crawlx_core::config::CrawlMode::Dynamic);
    assert_eq!(request.scope.host_scope, HostScope::None);
    assert_eq!(request.politeness.delay_ms, 2000);
    for flags in [
        vec!["--config", config, "--mode", "static"],
        vec!["--config", config, "--field-scope", "fqdn"],
        vec!["--config", config, "--delay-ms", "1000"],
    ] {
        assert!(
            crawlx_cli::crawl::build_request(&parse_crawl(&flags)).is_err(),
            "{flags:?}"
        );
    }
}

#[tokio::test]
async fn no_scope_changes_native_traversal_but_preserves_explicit_exclusions() {
    for (flags, follows_other) in [
        (vec![], false),
        (vec!["-ns"], true),
        (vec!["-ns", "-cos", "/other$"], false),
        (vec!["-ns", "-e", "localhost"], false),
    ] {
        let site = Site::start(|base| {
            let port = base.rsplit(':').next().unwrap();
            vec![
                (
                    "/",
                    Page::doc(
                        "Root",
                        &format!(r#"<a href="http://localhost:{port}/other">other</a>"#),
                    ),
                ),
                ("/other", Page::doc("Other", "<p>other host</p>")),
            ]
        })
        .await;
        let port = site.base.rsplit(':').next().unwrap();
        let localhost = format!("http://localhost:{port}");
        let ctx = Ctx::new(&[&site.base, &localhost]);
        let mut args = ctx.base();
        // Exercise the seconds adapter through the same execution path, without a timed assertion.
        let at = args.iter().position(|a| a == "--delay-ms").unwrap();
        args.splice(at..=at + 1, strings(&["-rd", "0"]));
        args.extend(flags.iter().map(|flag| (*flag).to_owned()));
        args.push(format!("{}/", site.base));
        let (stdout, code) = crawl(&args).await;
        assert_eq!(code.unwrap(), ExitCode::SUCCESS, "{flags:?}: {stdout}");
        assert_eq!(
            site.pages_hit().contains(&"/other".to_owned()),
            follows_other,
            "{flags:?}"
        );
    }
}

#[tokio::test]
async fn no_scope_never_authorizes_private_egress_and_delay_overflow_never_fetches() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let mut args = ctx.base();
    let at = args.iter().position(|a| a == "--allow-private-networks").unwrap();
    args.remove(at);
    args.extend(strings(&["-ns", &format!("{}/", site.base)]));
    let (_, code) = crawl(&args).await;
    assert!(code.is_err());
    assert!(
        site.hits().is_empty(),
        "no-scope cannot bypass private-network admission"
    );

    let mut args = ctx.base();
    let at = args.iter().position(|a| a == "--delay-ms").unwrap();
    args.splice(at..=at + 1, strings(&["-rd", "4294968"]));
    args.push(format!("{}/", site.base));
    let (_, code) = crawl(&args).await;
    let error = code.unwrap_err();
    assert!(
        format!("{error:#}").contains("overflows the millisecond field"),
        "{error:#}"
    );
    assert!(site.hits().is_empty(), "overflow must fail before any request");
}

#[tokio::test]
async fn headless_adapter_reaches_native_browser_health_gate() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let missing = ctx.path("missing-chromium");
    let mut args = ctx.base();
    let at = args.iter().position(|a| a == "--mode").unwrap();
    args.splice(at..=at + 1, strings(&["-hl"]));
    args.extend(strings(&[
        "--health-check",
        "--system-chrome-path",
        missing.to_str().unwrap(),
        &format!("{}/", site.base),
    ]));
    let (stdout, code) = crawl(&args).await;
    assert_eq!(code.unwrap(), ExitCode::from(1), "{stdout}");
    assert!(
        stdout.contains("launch options") && stdout.contains("FAIL"),
        "{stdout}"
    );
    assert!(site.hits().is_empty());
}

fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn endpoint(record: &serde_json::Value) -> &str {
    record["request"]["endpoint"].as_str().unwrap()
}

#[tokio::test]
async fn cli_extension_matching_preserves_dotfile_and_trailing_dot_admission_and_output() {
    for (seed, flags, expected) in [
        ("/index.html", vec![], vec!["/file.", "/index.html", "/plain"]),
        (
            "/index.html",
            vec!["-em", "html,png"],
            vec!["/.png", "/image.png", "/index.html"],
        ),
        (
            "/index.html",
            vec!["-em", "html,none"],
            vec!["/index.html", "/plain"],
        ),
        (
            "/index.html",
            vec!["-em", "html,."],
            vec!["/file.", "/index.html"],
        ),
        ("/seed.png", vec![], vec![]),
        ("/seed.png", vec!["-ndef"], vec!["/leaf.html", "/seed.png"]),
        ("/seed.png", vec!["-ndef", "-ef", "png"], vec![]),
        ("/seed.html", vec!["-ef", "html"], vec![]),
        ("/seed.png", vec!["-em", "png", "-ef", "png"], vec!["/seed.png"]),
        (
            "/seed.html",
            vec!["-em", "html", "-ef", "html"],
            vec!["/leaf.html", "/seed.html"],
        ),
    ] {
        let site = Site::start(|_| {
            vec![
                (
                    "/index.html",
                    Page::doc(
                        "Extension fixture",
                        r#"<a href="/.png">dotfile</a><a href="/image.png">image suffix</a><a href="/file.">trailing dot</a><a href="/plain">no extension</a>"#,
                    ),
                ),
                ("/.png", Page::doc("Dotfile", "<p>dotfile response</p>")),
                ("/image.png", Page::doc("Image suffix", "<p>image suffix response</p>")),
                ("/file.", Page::doc("Trailing dot", "<p>trailing dot response</p>")),
                ("/plain", Page::doc("No extension", "<p>extensionless response</p>")),
                (
                    "/seed.png",
                    Page::doc("PNG seed", r#"<a href="/leaf.html">leaf</a>"#),
                ),
                (
                    "/seed.html",
                    Page::doc("HTML seed", r#"<a href="/leaf.html">leaf</a>"#),
                ),
                ("/leaf.html", Page::doc("Leaf", "<p>reachable child</p>")),
            ]
        }).await;
        let ctx = Ctx::new(&[&site.base]);
        let request = ctx.path("request.json");
        std::fs::write(&request, r#"{"scope":{"crawlEntireDomain":true}}"#).unwrap();
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_crawlx"))
            .arg("crawl")
            .arg(format!("{}{seed}", site.base))
            .args(ctx.base())
            .args(["--request", request.to_str().unwrap()])
            .args(&flags)
            .args(["--silent", "-f", "url"])
            .env_clear()
            .env("TMPDIR", ctx.dir.path())
            .env("XDG_CACHE_HOME", ctx.path("cache"))
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{seed} {flags:?}: stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(small_pages(&site), expected, "{seed} {flags:?}: traversal");
        let mut urls: Vec<String> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        urls.sort();
        let expected_urls: Vec<String> = expected
            .iter()
            .map(|path| format!("{}{path}", site.base))
            .collect();
        assert_eq!(urls, expected_urls, "{seed} {flags:?}: native CLI output");
    }
}

#[tokio::test]
async fn retained_extension_export_does_not_reopen_filtered_traversal_or_change_the_report() {
    let site = Site::start(|_| {
        vec![
            (
                "/start.html",
                Page::doc(
                    "Start",
                    r#"<a href="/bridge.php">bridge</a><a href="/kept.html">kept</a>"#,
                ),
            ),
            (
                "/bridge.php",
                Page::doc("Bridge", r#"<a href="/hidden.html">hidden child</a>"#),
            ),
            ("/kept.html", Page::doc("Kept", "<p>direct child</p>")),
            (
                "/hidden.html",
                Page::doc("Hidden", "<p>filtered branch child</p>"),
            ),
        ]
    })
    .await;
    let ctx = Ctx::new(&[&site.base]);
    let request = ctx.path("request.json");
    std::fs::write(&request, r#"{"scope":{"crawlEntireDomain":true}}"#).unwrap();
    let mut args = ctx.base();
    args.extend(strings(&[
        "--request",
        request.to_str().unwrap(),
        "--extension-match",
        "html",
        &format!("{}/start.html", site.base),
    ]));
    let (stdout, result) = crawl(&args).await;
    assert_eq!(result.unwrap(), ExitCode::SUCCESS, "{stdout}");
    assert_eq!(small_pages(&site), ["/kept.html", "/start.html"]);
    let expected = [
        format!("{}/kept.html", site.base),
        format!("{}/start.html", site.base),
    ];
    drop(site);

    let report = ctx.out().join("report.json");
    let original = std::fs::read(&report).unwrap();
    for (flag, expected) in [
        ("--extension-filter", Vec::new()),
        ("--extension-match", expected.to_vec()),
    ] {
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_crawlx"))
            .arg("export")
            .arg(&report)
            .args(["--format", "text", "--field", "url", flag, "html"])
            .env_clear()
            .env("TMPDIR", ctx.dir.path())
            .env("XDG_CACHE_HOME", ctx.path("cache"))
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{flag}: {}",
            String::from_utf8_lossy(&output.stderr),
        );
        let mut emitted: Vec<_> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        emitted.sort();
        assert_eq!(emitted, expected, "{flag}: retained export");
        assert_eq!(std::fs::read(&report).unwrap(), original);
    }
}

/// `/`, `/a` and `/b` linking to each other and to a 404.
async fn small_site() -> Site {
    Site::start(|_| {
        vec![
            (
                "/",
                Page::doc(
                    "Home",
                    r#"<p>Home page text.</p><a href="/a">A</a> <a href="/b">B</a> <a href="/missing">gone</a>"#,
                ),
            ),
            ("/a", Page::doc("A", r#"<p>Page A text.</p><a href="/">home</a>"#)),
            ("/b", Page::doc("B", r#"<p>Page B text.</p><a href="/a">A</a>"#)),
        ]
    })
    .await
}

fn small_pages(site: &Site) -> Vec<String> {
    let mut hit = site.pages_hit();
    hit.sort();
    hit
}

// ---------------------------------------------------------------------------------------------
// input: -u, --list, stdin, -p, --resume
// ---------------------------------------------------------------------------------------------

async fn tiny_site(gauge: Arc<Gauge>, delay: Duration) -> Site {
    Site::start_with_gauge(
        |_| {
            vec![
                ("/", Page::doc("Root", r#"<a href="/p">p</a>"#).slow(delay)),
                ("/p", Page::doc("P", "<p>leaf</p>")),
            ]
        },
        gauge,
    )
    .await
}

#[tokio::test]
async fn comma_lists_list_files_and_flags_are_separate_runs_printed_in_seed_order() {
    let gauge = Arc::new(Gauge::default());
    let (a, b, c) = (
        tiny_site(Arc::clone(&gauge), Duration::ZERO).await,
        tiny_site(Arc::clone(&gauge), Duration::ZERO).await,
        tiny_site(Arc::clone(&gauge), Duration::ZERO).await,
    );
    let ctx = Ctx::new(&[&a.base, &b.base, &c.base]);
    let list = ctx.path("seeds.txt");
    std::fs::write(&list, format!("# third seed\n{}/\n\n", c.base)).unwrap();
    let mut args = ctx.base();
    args.extend(strings(&["-u", &format!("{}/,{}/", a.base, b.base), "--list"]));
    args.push(list.to_str().unwrap().to_owned());
    args.extend(strings(&["-f", "url"]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();

    // text lines: seed A's pages, then B's, then C's, each in URL order
    let lines: Vec<&str> = stdout.lines().take_while(|l| !l.starts_with("seed ")).collect();
    let want: Vec<String> = [&a, &b, &c]
        .iter()
        .flat_map(|s| [format!("{}/", s.base), format!("{}/p", s.base)])
        .collect();
    assert_eq!(lines, want, "{stdout}");
    // one run (own frontier) per seed: each site saw `/` and `/p` exactly once
    for site in [&a, &b, &c] {
        assert_eq!(small_pages(site), ["/", "/p"]);
    }
    // one report directory per seed, one counter block per seed
    let dirs: Vec<_> = std::fs::read_dir(ctx.out())
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.path().join("report.json").is_file())
        .collect();
    assert_eq!(dirs.len(), 3);
    assert_eq!(
        stdout.matches("terminal_reason=frontier_exhausted").count(),
        3,
        "{stdout}"
    );
}

#[tokio::test]
async fn parallelism_bounds_how_many_seeds_run_at_once() {
    for (parallelism, check) in [("1", 1usize), ("3", 0)] {
        let gauge = Arc::new(Gauge::default());
        let delay = Duration::from_millis(500);
        let sites = [
            tiny_site(Arc::clone(&gauge), delay).await,
            tiny_site(Arc::clone(&gauge), delay).await,
            tiny_site(Arc::clone(&gauge), delay).await,
        ];
        let bases: Vec<&str> = sites.iter().map(|s| s.base.as_str()).collect();
        let ctx = Ctx::new(&bases);
        let mut args = ctx.base();
        args.extend(strings(&["--parallelism", parallelism, "-u"]));
        args.push(
            bases
                .iter()
                .map(|b| format!("{b}/"))
                .collect::<Vec<_>>()
                .join(","),
        );
        let (_, code) = crawl(&args).await;
        code.unwrap();
        for site in &sites {
            assert_eq!(site.count("/"), 1, "-p {parallelism}");
        }
        if check == 1 {
            assert_eq!(gauge.max(), 1, "-p 1 must never overlap two seeds");
        } else {
            assert!(gauge.max() >= 2, "-p 3 should overlap seeds, saw {}", gauge.max());
        }
    }
}

#[tokio::test]
async fn standard_input_dash_reads_one_seed_per_line() {
    use tokio::io::AsyncWriteExt as _;
    let (a, b) = (small_site().await, small_site().await);
    let ctx = Ctx::new(&[&a.base, &b.base]);
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .arg("crawl")
        .arg("-")
        .args(ctx.base())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(format!("{}/\n\n{}/\n", a.base, b.base).as_bytes())
        .await
        .unwrap();
    drop(stdin);
    let output = child.wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout.matches("terminal_reason=frontier_exhausted").count(),
        2,
        "{stdout}"
    );
    assert_eq!(small_pages(&a), ["/", "/a", "/b", "/missing"]);
    assert_eq!(small_pages(&b), ["/", "/a", "/b", "/missing"]);
}

#[tokio::test]
async fn a_dash_with_an_empty_standard_input_is_an_error() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .arg("crawl")
        .arg("-")
        .args(ctx.base())
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("standard input held no URL"));
}

fn chain_site_pages(base: &str) -> Vec<(&'static str, Page)> {
    let _ = base;
    vec![
        (
            "/",
            Page::doc(
                "Root",
                r#"<a href="/p1">1</a> <a href="/p2">2</a> <a href="/p3">3</a> <a href="/p4">4</a>"#,
            ),
        ),
        ("/p1", Page::doc("P1", "<p>one</p>")),
        ("/p2", Page::doc("P2", "<p>two</p>")),
        ("/p3", Page::doc("P3", "<p>three</p>")),
        ("/p4", Page::doc("P4", "<p>four</p>")),
    ]
}

#[tokio::test]
async fn resume_continues_a_stopped_run_and_removes_the_file_when_the_frontier_runs_dry() {
    let site = Site::start(chain_site_pages).await;
    let ctx = Ctx::new(&[&site.base]);
    let resume = ctx.path("resume.json");
    let seed = format!("{}/", site.base);

    let mut args = ctx.base();
    args.extend(strings(&[
        "--limit-urls",
        "2",
        "--resume",
        resume.to_str().unwrap(),
        &seed,
    ]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    assert!(stdout.contains("resume state written to"), "{stdout}");
    let state = ResumeState::from_json(&std::fs::read_to_string(&resume).unwrap()).unwrap();
    assert!(!state.pending.is_empty(), "{state:?}");
    assert!(state.visited.len() >= 2, "{state:?}");
    let after_first = small_pages(&site);
    assert_eq!(after_first.len(), 2, "{after_first:?}");

    // the second invocation fetches only what the first one left
    let mut args = ctx.base();
    args.extend(strings(&[
        "--limit-urls",
        "100",
        "--resume",
        resume.to_str().unwrap(),
        &seed,
    ]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    assert!(stdout.contains("terminal_reason=frontier_exhausted"), "{stdout}");
    assert!(!resume.exists(), "an exhausted frontier deletes the resume file");
    assert_eq!(small_pages(&site), ["/", "/p1", "/p2", "/p3", "/p4"]);
    for target in ["/", "/p1", "/p2", "/p3", "/p4"] {
        assert_eq!(site.count(target), 1, "{target} fetched twice");
    }
}

#[tokio::test]
async fn resume_with_several_seeds_keeps_one_state_per_seed() {
    let (a, b) = (
        Site::start(chain_site_pages).await,
        Site::start(chain_site_pages).await,
    );
    let ctx = Ctx::new(&[&a.base, &b.base]);
    let resume = ctx.path("resume.json");
    let seeds = format!("{}/,{}/", a.base, b.base);

    let mut args = ctx.base();
    args.extend(strings(&[
        "--limit-urls",
        "2",
        "--resume",
        resume.to_str().unwrap(),
        "-u",
        &seeds,
    ]));
    crawl(&args).await.1.unwrap();
    let envelope: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&resume).unwrap()).unwrap();
    assert_eq!(envelope["runs"].as_object().unwrap().len(), 2, "{envelope}");

    let mut args = ctx.base();
    args.extend(strings(&[
        "--limit-urls",
        "100",
        "--resume",
        resume.to_str().unwrap(),
        "-u",
        &seeds,
    ]));
    crawl(&args).await.1.unwrap();
    assert!(!resume.exists());
    for site in [&a, &b] {
        assert_eq!(small_pages(site), ["/", "/p1", "/p2", "/p3", "/p4"]);
        assert_eq!(site.count("/"), 1);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn ctrl_c_writes_the_resume_state_and_a_second_run_finishes_the_crawl() {
    let delay = Duration::from_millis(400);
    let site = Site::start(|_| {
        let mut pages = vec![(
            "/",
            Page::doc(
                "Root",
                r#"<a href="/p1">1</a> <a href="/p2">2</a> <a href="/p3">3</a> <a href="/p4">4</a> <a href="/p5">5</a> <a href="/p6">6</a>"#,
            ),
        )];
        for p in ["/p1", "/p2", "/p3", "/p4", "/p5", "/p6"] {
            pages.push((p, Page::doc("P", "<p>x</p>").slow(delay)));
        }
        pages
    })
    .await;
    let ctx = Ctx::new(&[&site.base]);
    let resume = ctx.path("resume.json");
    let seed = format!("{}/", site.base);
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .arg("crawl")
        .arg(&seed)
        .args(ctx.base())
        .args(["--resume", resume.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // interrupt once the crawl is inside the slow pages
    for _ in 0..200 {
        if site.pages_hit().len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        site.pages_hit().len() >= 3,
        "the crawl never got going: {:?}",
        site.pages_hit()
    );
    let pid = child.id().unwrap().to_string();
    let status = std::process::Command::new("kill")
        .args(["-INT", &pid])
        .status()
        .unwrap();
    assert!(status.success());
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("the interrupted crawl must drain and exit")
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        resume.is_file(),
        "no resume file after Ctrl-C\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = ResumeState::from_json(&std::fs::read_to_string(&resume).unwrap()).unwrap();
    assert!(!state.pending.is_empty(), "{state:?}");

    let mut args = ctx.base();
    args.extend(strings(&["--resume", resume.to_str().unwrap(), &seed]));
    let (_, code) = crawl(&args).await;
    code.unwrap();
    assert!(!resume.exists());
    for target in ["/p1", "/p2", "/p3", "/p4", "/p5", "/p6"] {
        assert_eq!(
            site.count(target),
            1,
            "{target} was fetched {} times",
            site.count(target)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// -config: compatibility YAML, CreateCrawl JSON and TOML; flag > config file > defaults
// ---------------------------------------------------------------------------------------------

#[test]
fn a_yaml_config_fills_what_the_flags_leave_unset() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("compat.yaml");
    std::fs::write(
        &cfg,
        "timeout: 20\nrate-limit: 50\ndepth: 2\nno-redirects: true\ncrawl-scope:\n  - ^https://example\\.test/a/\n  - ^https://example\\.test/b/\nstrategy: priority\nfield-scope: dn\n",
    )
    .unwrap();
    let cfg = cfg.to_str().unwrap();

    // only the file: its values apply
    let crawl = request_of(&["--config", cfg]);
    assert_eq!(crawl.fetch.timeout_ms, 20_000);
    assert_eq!(crawl.politeness.global_rps, Some(50));
    assert_eq!(crawl.scope.max_discovery_depth, 2);
    assert!(!crawl.fetch.follow_redirects);
    assert_eq!(crawl.scope.url_include.len(), 2);
    assert_eq!(crawl.scope.strategy, CrawlStrategy::Priority);
    assert_eq!(crawl.scope.host_scope, HostScope::Dn);

    // flags win over the file; untouched keys still come from the file; absent keys are defaults
    let crawl = request_of(&[
        "--config",
        cfg,
        "--timeout",
        "5",
        "--rate-limit",
        "70",
        "--crawl-scope",
        "only-this",
        "--field-scope",
        "rdn",
    ]);
    assert_eq!(crawl.fetch.timeout_ms, 5_000);
    assert_eq!(crawl.politeness.global_rps, Some(70));
    assert_eq!(crawl.scope.url_include, ["only-this"]);
    assert_eq!(crawl.scope.host_scope, HostScope::Rdn);
    assert_eq!(crawl.scope.max_discovery_depth, 2, "from the file");
    assert_eq!(crawl.fetch.retries, 1, "the default");
}

#[test]
fn an_unknown_config_key_is_an_error_naming_it() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("bad.yaml");
    std::fs::write(&cfg, "timeout: 20\nrate-limitt: 5\n").unwrap();
    let err = crawlx_cli::crawl::build_request(&parse_crawl(&["--config", cfg.to_str().unwrap()]))
        .unwrap_err()
        .to_string();
    assert!(err.contains("unknown key `rate-limitt`"), "{err}");
    for (name, body) in [
        ("bad.json", r#"{"scope":{"strategyy":"depth_first"}}"#),
        ("bad.toml", "[crawl.scope]\nstrategyy = \"depth_first\"\n"),
    ] {
        let cfg = dir.path().join(name);
        std::fs::write(&cfg, body).unwrap();
        let err = crawlx_cli::crawl::build_request(&parse_crawl(&["--config", cfg.to_str().unwrap()]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("scope.strategyy"), "{name}: {err}");
    }
}

#[test]
fn json_and_toml_configs_are_request_bodies_under_the_request_file_and_the_flags() {
    let dir = tempfile::tempdir().unwrap();
    let json = dir.path().join("c.json");
    std::fs::write(
        &json,
        r#"{"scope":{"strategy":"depth_first","maxDiscoveryDepth":4},"limits":{"urls":77},"fetch":{"timeoutMs":3000}}"#,
    )
    .unwrap();
    let toml = dir.path().join("c.toml");
    std::fs::write(
        &toml,
        "[crawl.scope]\nstrategy = \"priority\"\n[crawl.limits]\nurls = 55\n",
    )
    .unwrap();
    let request = dir.path().join("request.json");
    std::fs::write(
        &request,
        r#"{"seedUrl":"https://example.test/","limits":{"urls":9}}"#,
    )
    .unwrap();

    let crawl = request_of(&["--config", json.to_str().unwrap()]);
    assert_eq!(crawl.scope.strategy, CrawlStrategy::DepthFirst);
    assert_eq!(crawl.scope.max_discovery_depth, 4);
    assert_eq!(crawl.limits.urls, 77);
    assert_eq!(crawl.fetch.timeout_ms, 3000);
    assert_eq!(
        crawl.limits.interactions, 5_000,
        "absent keys keep their defaults"
    );

    let crawl = request_of(&["--config", toml.to_str().unwrap()]);
    assert_eq!(crawl.scope.strategy, CrawlStrategy::Priority);
    assert_eq!(crawl.limits.urls, 55);

    // the request file overrides the config body; flags override both
    let crawl = request_of(&[
        "--config",
        json.to_str().unwrap(),
        "--request",
        request.to_str().unwrap(),
    ]);
    assert_eq!(crawl.limits.urls, 9);
    assert_eq!(
        crawl.scope.strategy,
        CrawlStrategy::DepthFirst,
        "the body still fills the rest"
    );
    let crawl = request_of(&[
        "--config",
        json.to_str().unwrap(),
        "--request",
        request.to_str().unwrap(),
        "--limit-urls",
        "3",
        "--strategy",
        "breadth-first",
    ]);
    assert_eq!(crawl.limits.urls, 3);
    assert_eq!(crawl.scope.strategy, CrawlStrategy::BreadthFirst);
}

#[tokio::test]
async fn a_yaml_config_can_drive_a_whole_crawl() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let cfg = ctx.path("compat.yaml");
    let out = ctx.path("urls.txt");
    std::fs::write(&cfg, format!("output-file: {}\nfield: path\n", out.display())).unwrap();
    let mut args = ctx.base();
    args.extend(strings(&[
        "--config",
        cfg.to_str().unwrap(),
        &format!("{}/", site.base),
    ]));
    crawl(&args).await.1.unwrap();
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "/\n/a\n/b\n");
}

// ---------------------------------------------------------------------------------------------
// --compat-defaults
// ---------------------------------------------------------------------------------------------

#[test]
fn compat_defaults_set_the_preset_values_and_explicit_flags_override_them() {
    let plain = request_of(&[]);
    assert_eq!(plain.scope.host_scope, HostScope::Fqdn, "crawlx's own default");

    let k = request_of(&["--compat-defaults"]);
    assert_eq!(k.scope.host_scope, HostScope::Rdn);
    assert_eq!(k.scope.max_discovery_depth, 3);
    assert_eq!(k.scope.strategy, CrawlStrategy::DepthFirst);
    assert!(!k.scope.js_endpoints);
    assert!(k.scope.known_files.is_empty());
    assert!(!k.extract.forms);
    assert_eq!(k.politeness.global_rps, Some(150));
    assert_eq!(
        k.politeness.delay_ms, 50,
        "the compatibility 0 sits on the politeness floor"
    );
    assert_eq!(k.fetch.max_response_bytes, 4 * 1024 * 1024);
    // everything the preset does not name keeps crawlx's value
    assert_eq!(k.fetch.timeout_ms, plain.fetch.timeout_ms);
    assert_eq!(k.limits.urls, plain.limits.urls);

    let o = request_of(&[
        "--compat-defaults",
        "--field-scope",
        "fqdn",
        "--depth",
        "7",
        "--strategy",
        "breadth-first",
        "--js-crawl",
        "--known-files",
        "sitemap",
        "--form-extraction",
        "--rate-limit",
        "20",
        "--delay-ms",
        "300",
        "--max-response-size",
        "1048576",
    ]);
    assert_eq!(o.scope.host_scope, HostScope::Fqdn);
    assert_eq!(o.scope.max_discovery_depth, 7);
    assert_eq!(o.scope.strategy, CrawlStrategy::BreadthFirst);
    assert!(o.scope.js_endpoints);
    assert_eq!(o.scope.known_files, [KnownFile::Sitemap]);
    assert!(o.extract.forms);
    assert_eq!(o.politeness.global_rps, Some(20));
    assert_eq!(o.politeness.delay_ms, 300);
    assert_eq!(o.fetch.max_response_bytes, 1_048_576);

    // a request file sits above the preset too
    let dir = tempfile::tempdir().unwrap();
    let request = dir.path().join("r.json");
    std::fs::write(
        &request,
        r#"{"seedUrl":"https://example.test/","scope":{"strategy":"priority"}}"#,
    )
    .unwrap();
    let r = request_of(&["--compat-defaults", "--request", request.to_str().unwrap()]);
    assert_eq!(r.scope.strategy, CrawlStrategy::Priority);
    assert_eq!(r.scope.max_discovery_depth, 3, "the preset fills the rest");
}

#[tokio::test]
async fn compat_defaults_leave_technologies_out_of_jsonl_unless_tech_detect_is_given() {
    let site = Site::start(|_| {
        vec![(
            "/",
            Page::doc("Home", "<p>hello</p>").header("x-powered-by", "PHP/8.2.1"),
        )]
    })
    .await;
    let seed = format!("{}/", site.base);
    let technologies = |extra: &[&str]| {
        let ctx = Ctx::new(&[&site.base]);
        let file = ctx.path("r.jsonl");
        let mut args = ctx.base();
        args.extend(strings(&["--jsonl", "-o", file.to_str().unwrap(), &seed]));
        args.extend(strings(extra));
        async move {
            let _ctx = ctx;
            crawl(&args).await.1.unwrap();
            let records = read_jsonl(&file);
            assert_eq!(records.len(), 1);
            records[0]["response"]["technologies"].clone()
        }
    };
    assert!(
        technologies(&[]).await.is_array(),
        "crawlx lists technologies by default"
    );
    assert!(technologies(&["--compat-defaults"]).await.is_null());
    assert!(technologies(&["--compat-defaults", "--tech-detect"])
        .await
        .is_array());
}

// KR-G2: authored fixtures distinguish AST folding from regex-only comments.
#[tokio::test]
async fn javascript_modes_control_inline_and_standalone_crawl_requests() {
    for (flags, ast, regex) in [
        (vec![], true, true),
        (vec!["--javascript-mode", "off"], false, false),
        (vec!["--javascript-mode", "regex"], false, true),
        (vec!["--javascript-mode", "ast"], true, false),
        (vec!["--javascript-mode", "both"], true, true),
        (vec!["--js-crawl"], false, true),
        (vec!["--jsluice"], true, false),
        (vec!["--js-crawl", "--jsluice"], true, true),
    ] {
        let site = Site::start(|_| {
            let script = |section: &str| {
                format!(
                "const part = '{section}'; fetch('/' + part + '/ast-only'); // '/{section}/regex-only.js'\n"
            )
            };
            let mut bundle = Page::html(script("standalone"));
            bundle.content_type = "text/javascript";
            vec![
                (
                    "/",
                    Page::doc(
                        "Root",
                        &format!(
                    "<a href='/structural'>link</a><script src='/bundle.js'></script><script>{}</script>",
                    script("inline")
                ),
                    ),
                ),
                ("/bundle.js", bundle),
                ("/structural", Page::doc("Structural", "<p>leaf</p>")),
            ]
        })
        .await;
        let ctx = Ctx::new(&[&site.base]);
        let mut args = ctx.base();
        args.push(format!("{}/", site.base));
        args.extend(strings(&flags));
        crawl(&args).await.1.unwrap();
        let hits = site.pages_hit();
        assert!(
            hits.iter().any(|path| path == "/structural"),
            "{flags:?}: {hits:?}"
        );
        assert!(
            hits.iter().any(|path| path == "/bundle.js"),
            "{flags:?}: {hits:?}"
        );
        for section in ["inline", "standalone"] {
            assert_eq!(
                hits.contains(&format!("/{section}/ast-only")),
                ast,
                "{flags:?}: {hits:?}"
            );
            assert_eq!(
                hits.contains(&format!("/{section}/regex-only.js")),
                regex,
                "{flags:?}: {hits:?}"
            );
        }
    }
}

#[tokio::test]
async fn javascript_cli_selection_overrides_yaml_and_request_config_on_the_wire() {
    for yaml in [true, false] {
        let site = Site::start(|_| vec![("/", Page::html(
            "<a href='/structural'>link</a><script>const section = 'selected'; fetch('/' + section + '/ast-only'); // '/regex-only.js'\n</script>"
        ))]).await;
        let ctx = Ctx::new(&[&site.base]);
        let config = ctx.path(if yaml { "miners.yaml" } else { "miners.json" });
        std::fs::write(
            &config,
            if yaml {
                "javascript-mode: off\n"
            } else {
                r#"{"extract":{"javascript":{"mode":"off"}}}"#
            },
        )
        .unwrap();
        let mut args = ctx.base();
        args.extend(strings(&["--config", config.to_str().unwrap(), "--jsluice"]));
        args.push(format!("{}/", site.base));
        crawl(&args).await.1.unwrap();
        let hits = site.pages_hit();
        assert!(hits.iter().any(|path| path == "/structural"), "{hits:?}");
        assert!(hits.iter().any(|path| path == "/selected/ast-only"), "{hits:?}");
        assert!(!hits.iter().any(|path| path == "/regex-only.js"), "{hits:?}");
    }
}

#[test]
fn javascript_explicit_mode_rejects_compatibility_switch_conflicts() {
    for compatibility in ["--js-crawl", "--jsluice", "--no-js-endpoints"] {
        let error = crawlx_cli::Cli::try_parse_from([
            "crawlx",
            "crawl",
            "https://fixture.test/",
            "--javascript-mode",
            "ast",
            compatibility,
        ])
        .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
    let error = crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "crawl",
        "https://fixture.test/",
        "--javascript-mode",
        "unsupported",
    ])
    .unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
}

// ---------------------------------------------------------------------------------------------
// scope and request flags that change what is fetched
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn depth_limits_the_link_hops() {
    let site = Site::start(|_| {
        vec![
            ("/", Page::doc("Root", r#"<a href="/one">1</a>"#)),
            ("/one", Page::doc("One", r#"<a href="/two">2</a>"#)),
            ("/two", Page::doc("Two", r#"<a href="/three">3</a>"#)),
            ("/three", Page::doc("Three", "<p>end</p>")),
        ]
    })
    .await;
    for (depth, want) in [
        ("1", vec!["/", "/one"]),
        ("3", vec!["/", "/one", "/three", "/two"]),
    ] {
        let ctx = Ctx::new(&[&site.base]);
        let before = site.hits().len();
        let mut args = ctx.base();
        args.extend(strings(&["-d", depth, &format!("{}/", site.base)]));
        crawl(&args).await.1.unwrap();
        let mut got: Vec<String> = site
            .hits()
            .into_iter()
            .skip(before)
            .map(|h| h.target)
            .filter(|t| t != "/robots.txt" && t != "/sitemap.xml")
            .collect();
        got.sort();
        assert_eq!(got, want, "--depth {depth}");
    }
}

#[tokio::test]
async fn path_climb_crawls_the_parent_directories_of_discovered_urls() {
    let pages = |_: &str| {
        let page = |t: &str, links: &str| Page::doc(t, &format!("<p>x</p>{links}"));
        vec![
            ("/", page("Root", r#"<a href="/docs/guide/page">deep</a>"#)),
            ("/docs/guide/page", page("Page", "")),
            ("/docs/guide/", page("Guide", "")),
            ("/docs/", page("Docs", "")),
        ]
    };
    let climbing = Site::start(pages).await;
    let ctx = Ctx::new(&[&climbing.base]);
    let mut args = ctx.base();
    args.extend(strings(&["--path-climb", &format!("{}/", climbing.base)]));
    crawl(&args).await.1.unwrap();
    assert_eq!(
        small_pages(&climbing),
        ["/", "/docs/", "/docs/guide/", "/docs/guide/page"]
    );

    // without the flag only the linked page is fetched
    let plain = Site::start(pages).await;
    let ctx = Ctx::new(&[&plain.base]);
    let mut args = ctx.base();
    args.push(format!("{}/", plain.base));
    crawl(&args).await.1.unwrap();
    assert_eq!(small_pages(&plain), ["/", "/docs/guide/page"]);
}

#[tokio::test]
async fn ignore_query_params_fetches_urls_that_differ_only_in_values_once() {
    let site = Site::start(|_| {
        vec![
            (
                "/",
                Page::doc(
                    "Root",
                    r#"<a href="/item?id=1">1</a> <a href="/item?id=2">2</a> <a href="/item?id=3">3</a>"#,
                ),
            ),
            ("/item", Page::doc("Item", "<p>item</p>")),
        ]
    })
    .await;
    let run = |extra: &'static [&'static str]| {
        let ctx = Ctx::new(&[&site.base]);
        let mut args = ctx.base();
        args.extend(strings(extra));
        args.push(format!("{}/", site.base));
        async move {
            let _ctx = ctx;
            crawl(&args).await.1.unwrap();
        }
    };
    run(&[]).await;
    let without = site.pages_hit().iter().filter(|t| t.starts_with("/item")).count();
    let before = site.hits().len();
    run(&["--ignore-query-params"]).await;
    let with = site
        .hits()
        .into_iter()
        .skip(before)
        .filter(|h| h.target.starts_with("/item"))
        .count();
    assert!(
        without >= 2,
        "the default crawl follows the distinct ids ({without})"
    );
    assert_eq!(with, 1, "--ignore-query-params collapses them");
}

#[tokio::test]
async fn disable_unique_filter_keeps_pages_with_identical_bodies() {
    let same = || {
        Page::html("<html><head><title>Same</title></head><body><main><p>identical body text</p></main></body></html>")
    };
    let site = Site::start(move |_| {
        vec![
            ("/", Page::doc("Root", r#"<a href="/x">x</a> <a href="/y">y</a>"#)),
            ("/x", same()),
            ("/y", same()),
        ]
    })
    .await;
    // pages the crawl recorded as exact-content duplicates of an earlier page
    let duplicates = |extra: &[&str]| {
        let ctx = Ctx::new(&[&site.base]);
        let mut args = ctx.base();
        args.extend(strings(extra));
        args.push(format!("{}/", site.base));
        async move {
            crawl(&args).await.1.unwrap();
            let metadata: serde_json::Value =
                serde_json::from_slice(&std::fs::read(ctx.out().join("metadata.json")).unwrap()).unwrap();
            metadata
                .as_array()
                .unwrap()
                .iter()
                .filter(|p| p["metadata"]["dedupe"]["reason"] == "content_exact")
                .count()
        }
    };
    assert_eq!(
        duplicates(&[]).await,
        1,
        "the second identical body is a content_exact duplicate"
    );
    assert_eq!(duplicates(&["--disable-unique-filter"]).await, 0);
}

#[tokio::test]
async fn a_regex_field_scope_admits_hosts_it_matches() {
    // the same server answers as `127.0.0.1` and `localhost`: two host names
    let site = Site::start(|base| {
        let port = base.rsplit(':').next().unwrap().to_owned();
        vec![
            (
                "/",
                Page::doc(
                    "Root",
                    &format!(r#"<a href="http://localhost:{port}/other">other</a>"#),
                ),
            ),
            ("/other", Page::doc("Other", "<p>other host</p>")),
        ]
    })
    .await;
    let port = site.base.rsplit(':').next().unwrap().to_owned();
    let localhost = format!("http://localhost:{port}");
    let run = |scope: Option<&'static str>| {
        let ctx = Ctx::new(&[&site.base, &localhost]);
        let mut args = ctx.base();
        if let Some(s) = scope {
            args.extend(strings(&["--field-scope", s]));
        }
        args.extend(strings(&["-f", "url", &format!("{}/", site.base)]));
        async move {
            let _ctx = ctx;
            let (stdout, code) = crawl(&args).await;
            code.unwrap();
            stdout
                .lines()
                .take_while(|l| !l.starts_with("crawl "))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        }
    };
    let default = run(None).await;
    assert_eq!(default, [format!("{}/", site.base)]);
    let regex = run(Some("^localhost$")).await;
    assert!(regex.contains(&format!("{localhost}/other")), "{regex:?}");
    assert!(
        regex.contains(&format!("{}/", site.base)),
        "the seed host stays in scope: {regex:?}"
    );
}

#[test]
fn flags_map_onto_scope_fetch_extract_and_limit_fields() {
    let dir = tempfile::tempdir().unwrap();
    let forms = dir.path().join("forms.yaml");
    std::fs::write(
        &forms,
        "email: bot@example.test\nphone: '5550100'\nplaceholder: filler\n",
    )
    .unwrap();
    let c = request_of(&[
        "--exclude",
        "cdn,private-ips",
        "--ignore-query-params",
        "--path-climb",
        "--disable-unique-filter",
        "--field-scope",
        "(company-staging.io|company.com)",
        "--depth",
        "5",
        "--resolvers",
        "1.1.1.1,9.9.9.9:5353",
        "--crawl-duration",
        "5m",
        "--no-expand-page-type",
        "login,captcha",
        "--automatic-form-fill",
        "--form-config",
        forms.to_str().unwrap(),
        "--xhr-extraction",
        "--knowledge-base",
        "--kb-endpoints",
        "--kb-validate-secrets",
        "--capture-raw",
        "--max-scroll-steps",
        "7",
        "--block-consent-banners",
        "--interaction-depth",
        "3",
        "--interaction-selector",
        "a.nav, button.go",
        "--interaction-exclude",
        ".logout",
        "--interaction-max-states",
        "40",
        "--interaction-max-actions",
        "0",
        "--interaction-settle",
        "1500ms",
        "--interaction-duration",
        "2m",
        "--max-failure-count",
        "12",
        "--enable-diagnostics",
        "--time-stable",
        "2",
        "--retry",
        "4",
        "--disable-redirects",
        "--user-agent",
        "crawlx-test/1",
        "--robots-user-agent",
        "robots-test",
        "--skip-tls-verification",
    ]);
    let s = &c.scope;
    assert_eq!(s.exclude_hosts, ["cdn", "private-ips"]);
    assert!(s.ignore_query_params && s.path_climb && s.disable_unique_filter);
    assert_eq!(
        s.host_scope_pattern.as_deref(),
        Some("(company-staging.io|company.com)")
    );
    assert_eq!(
        s.host_scope,
        HostScope::Fqdn,
        "a regex leaves the preset scope alone"
    );
    assert_eq!(s.max_discovery_depth, 5);
    assert_eq!(s.filter_page_types, [PageType::Login, PageType::Captcha]);
    assert_eq!(c.fetch.resolvers, ["1.1.1.1", "9.9.9.9:5353"]);
    assert_eq!(c.limits.duration_seconds, 300);
    let f = &c.extract.form_fill;
    assert!(f.enabled);
    assert_eq!(f.email.as_deref(), Some("bot@example.test"));
    assert_eq!(f.phone.as_deref(), Some("5550100"));
    assert_eq!(f.placeholder.as_deref(), Some("filler"));
    assert!(c.extract.xhr && c.extract.knowledge_base && c.extract.kb_endpoints);
    assert!(
        c.extract.validate_secrets && c.extract.detect_secrets,
        "validation implies detection"
    );
    assert!(c.output.capture_raw);
    let d = &c.dynamic;
    assert_eq!(d.max_scroll_steps, 7);
    assert!(d.block_consent_banners && d.enable_diagnostics);
    assert_eq!(d.interaction_depth, 3);
    assert_eq!(d.interaction_selector, ["a.nav, button.go"]);
    assert_eq!(d.interaction_exclude, [".logout"]);
    assert_eq!(d.interaction_settle_ms, 1500);
    assert_eq!(d.interaction_duration_seconds, 120);
    assert_eq!(d.max_failure_count, 12);
    assert_eq!(d.time_stable_ms, 2000);
    assert_eq!(c.limits.states, 40);
    assert_eq!(c.limits.interactions, 100_000, "the compatibility 0 is unlimited");
    assert_eq!(c.fetch.retries, 4);
    assert!(!c.fetch.follow_redirects);
    assert_eq!(c.fetch.user_agent.as_deref(), Some("crawlx-test/1"));
    assert_eq!(c.fetch.robots_user_agent.as_deref(), Some("robots-test"));
    assert!(c.fetch.skip_tls_verification);
}

#[test]
fn crawl_duration_takes_units_has_no_ten_second_floor_and_rejects_less_than_a_second() {
    assert_eq!(
        request_of(&["--crawl-duration", "30s"]).limits.duration_seconds,
        30
    );
    assert_eq!(
        request_of(&["--crawl-duration", "5m"]).limits.duration_seconds,
        300
    );
    assert_eq!(
        request_of(&["--crawl-duration", "1h"]).limits.duration_seconds,
        3600
    );
    assert_eq!(
        request_of(&["--crawl-duration", "90"]).limits.duration_seconds,
        90
    );
    assert_eq!(request_of(&["--crawl-duration", "2s"]).limits.duration_seconds, 2);
    for bad in ["500ms", "8d", "0"] {
        let err = crawlx_cli::crawl::build_request(&parse_crawl(&["--crawl-duration", bad]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--crawl-duration"), "{bad}: {err}");
    }
    assert!(crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "crawl",
        "https://example.test/",
        "--crawl-duration",
        "soon"
    ])
    .is_err());
}

#[test]
fn recorded_flow_selects_the_recorded_login_plan_of_the_roles() {
    let dir = tempfile::tempdir().unwrap();
    let flow = dir.path().join("flow.json");
    std::fs::write(
        &flow,
        r#"{"title":"login","steps":[{"type":"navigate","url":"https://example.test/login"}]}"#,
    )
    .unwrap();
    let c = request_of(&[
        "--role",
        "admin=env://ADMIN",
        "--recorded-flow",
        flow.to_str().unwrap(),
    ]);
    let plan = c.roles[0].login_plan.as_deref().unwrap();
    assert!(plan.starts_with("recorded:file:///"), "{plan}");
    assert!(plan.ends_with("flow.json"), "{plan}");
    assert_eq!(
        request_of(&["--role", "admin=env://ADMIN"]).roles[0].login_plan,
        None
    );
    // a flow needs a role to fill it, and must be JSON
    assert!(crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "crawl",
        "https://example.test/",
        "--recorded-flow",
        flow.to_str().unwrap()
    ])
    .is_err());
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, "not json").unwrap();
    let err = crawlx_cli::crawl::build_request(&parse_crawl(&[
        "--role",
        "admin=env://ADMIN",
        "--recorded-flow",
        bad.to_str().unwrap(),
    ]))
    .unwrap_err()
    .to_string();
    assert!(err.contains("not JSON"), "{err}");
}

// ---------------------------------------------------------------------------------------------
// request controls: -H, --cookie, --user-agent, -r
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn headers_cookies_and_user_agent_reach_the_site_and_never_reach_the_reports() {
    const SECRET: &str = "s3cr3t-literal-value-31337";
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let mut args = ctx.base();
    args.extend(strings(&[
        "-H",
        &format!("X-Api-Key: {SECRET}"),
        "-H",
        "X-Plain: shown",
        "--cookie",
        &format!("sid={SECRET}"),
        "--user-agent",
        "compat-flags-test/9",
        "--jsonl",
        &format!("{}/", site.base),
    ]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    let hits = site.hits();
    assert!(!hits.is_empty());
    for hit in hits.iter().filter(|h| h.target == "/a") {
        assert_eq!(hit.headers.get("x-api-key").map(String::as_str), Some(SECRET));
        assert_eq!(hit.headers.get("x-plain").map(String::as_str), Some("shown"));
        assert!(hit
            .headers
            .get("cookie")
            .is_some_and(|c| c.contains(&format!("sid={SECRET}"))));
        assert_eq!(
            hit.headers.get("user-agent").map(String::as_str),
            Some("compat-flags-test/9")
        );
    }
    // no file the crawl wrote, and nothing it printed, holds the literal secret
    let mut files = vec![
        ctx.out().join("report.json"),
        ctx.out().join("metadata.json"),
        ctx.out().join("results.jsonl"),
    ];
    files.extend(
        std::fs::read_dir(ctx.out().join("pages"))
            .unwrap()
            .map(|e| e.unwrap().path()),
    );
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            !text.contains(SECRET),
            "{} leaks the header value",
            file.display()
        );
    }
    assert!(!stdout.contains(SECRET));
    let report = std::fs::read_to_string(ctx.out().join("report.json")).unwrap();
    assert!(
        report.contains("[redacted]"),
        "the request in report.json shows redacted values"
    );
}

#[test]
fn malformed_headers_and_cookies_are_refused() {
    for args in [
        &["-H", "no colon here"][..],
        &["--cookie", "novalue"],
        &["--cookie", "a=b;secure"],
    ] {
        let err = crawlx_cli::crawl::build_request(&parse_crawl(args))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("--headers") || err.contains("--cookie"),
            "{args:?}: {err}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("headers.txt");
    std::fs::write(&file, "# comment\nX-One: 1\n\nX-Two: 2\n").unwrap();
    let c = request_of(&["-H", file.to_str().unwrap(), "-H", "X-Three: 3"]);
    let names: Vec<&str> = c.fetch.extra_headers.iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["x-one", "x-three", "x-two"]);
}

/// A DNS server on loopback answering every `A` query with `ip` and every other type with an
/// empty answer.
async fn fake_dns(ip: [u8; 4]) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            if n < 12 {
                continue;
            }
            // end of the question: name labels, then type and class
            let mut i = 12;
            while i < n && buf[i] != 0 {
                i += usize::from(buf[i]) + 1;
            }
            let qend = i + 5;
            if qend > n {
                continue;
            }
            let qtype = u16::from_be_bytes([buf[i + 1], buf[i + 2]]);
            let mut reply = buf[..qend].to_vec();
            reply[2] = 0x81;
            reply[3] = 0x80;
            reply[6..12].copy_from_slice(&[0, u8::from(qtype == 1), 0, 0, 0, 0]);
            if qtype == 1 {
                reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                reply.extend_from_slice(&ip);
            }
            let _ = socket.send_to(&reply, peer).await;
        }
    });
    (addr, task)
}

#[tokio::test]
async fn resolvers_decide_how_the_seed_host_resolves() {
    let site = small_site().await;
    let port = site.base.rsplit(':').next().unwrap().to_owned();
    let seed = format!("http://fake-host.test:{port}/");
    let (dns, _task) = fake_dns([127, 0, 0, 1]).await;
    let ctx = Ctx::new(&[&format!("http://fake-host.test:{port}")]);

    // the custom resolver maps fake-host.test to the local site
    let mut args = ctx.base();
    args.extend(strings(&["--resolvers", &dns.to_string(), &seed]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    assert!(stdout.contains("urls.succeeded"), "{stdout}");
    assert!(
        small_pages(&site).contains(&"/a".to_owned()),
        "{:?}",
        small_pages(&site)
    );
    let before = site.hits().len();

    // without it the name does not resolve and nothing reaches the site
    let ctx = Ctx::new(&[&format!("http://fake-host.test:{port}")]);
    let mut args = ctx.base();
    args.push(seed);
    let _ = crawl(&args).await;
    assert_eq!(
        site.hits().len(),
        before,
        "an unresolvable host must not reach the site"
    );
}

#[tokio::test]
async fn a_resolver_list_file_steers_resolution_but_never_widens_authorization() {
    let site = small_site().await;
    let port = site.base.rsplit(':').next().unwrap().to_owned();
    let (dns, _task) = fake_dns([127, 0, 0, 1]).await;
    // the file form: comments, blank lines, a repeated entry and a trailing comment
    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("resolvers.txt");
    std::fs::write(
        &list,
        format!("# local test resolver\n\n{dns} # primary\n{dns}\n"),
    )
    .unwrap();
    let list = list.to_str().unwrap().to_owned();

    // an authorized origin resolved through the file's server is crawled
    let ctx = Ctx::new(&[&format!("http://fake-host.test:{port}")]);
    let mut args = ctx.base();
    args.extend(strings(&[
        "--resolvers",
        &list,
        &format!("http://fake-host.test:{port}/"),
    ]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    assert!(stdout.contains("urls.succeeded"), "{stdout}");
    let before = site.hits().len();
    assert!(before > 0);

    // the same resolver answering a private address for a host the record does not cover
    // reaches nothing: resolution never grants authorization
    let ctx = Ctx::new(&[&format!("http://fake-host.test:{port}")]);
    let mut args = ctx.base();
    args.extend(strings(&[
        "--resolvers",
        &list,
        &format!("http://uncovered-host.test:{port}/"),
    ]));
    let _ = crawl(&args).await;
    assert_eq!(
        site.hits().len(),
        before,
        "an uncovered host must not reach the site"
    );
}

// ---------------------------------------------------------------------------------------------
// forms: -aff, -fc
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn automatic_form_fill_follows_get_forms_with_the_configured_values() {
    let site = Site::start(|_| {
        vec![
            (
                "/",
                Page::doc(
                    "Home",
                    r#"<form action="/search" method="get"><input type="email" name="mail"><input type="text" name="topic"><input type="submit" value="go"></form>"#,
                ),
            ),
            ("/search", Page::doc("Results", "<p>results</p>")),
        ]
    })
    .await;
    let seed = format!("{}/", site.base);
    let ctx = Ctx::new(&[&site.base]);
    let mut args = ctx.base();
    args.push(seed.clone());
    crawl(&args).await.1.unwrap();
    let before = site.pages_hit();
    assert!(
        before.iter().all(|t| !t.contains("filled%40")),
        "the configured values are not used without --form-config: {before:?}"
    );

    let ctx = Ctx::new(&[&site.base]);
    let values = ctx.path("forms.yaml");
    std::fs::write(&values, "email: filled@example.test\nplaceholder: lorem\n").unwrap();
    let mut args = ctx.base();
    args.extend(strings(&["--form-config", values.to_str().unwrap(), &seed]));
    crawl(&args).await.1.unwrap();
    let filled: Vec<String> = site
        .pages_hit()
        .into_iter()
        .filter(|t| t.starts_with("/search") && t.contains("filled%40"))
        .collect();
    assert_eq!(filled.len(), 1, "{filled:?}");
    assert!(filled[0].contains("mail=filled%40example.test"), "{}", filled[0]);
    assert!(filled[0].contains("topic=lorem"), "{}", filled[0]);
}

// ---------------------------------------------------------------------------------------------
// output: -o, -ncb, -sr/-srd, -mr/-fr, -mdc/-fdc, -fpt, -lof, -elog, -f, -or/-ob/-eof, -j
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn output_file_receives_the_urls_and_no_clobber_numbers_the_next_file() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let file = ctx.path("urls.txt");
    let mut args = ctx.base();
    args.extend(strings(&[
        "-o",
        file.to_str().unwrap(),
        &format!("{}/", site.base),
    ]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    let expected = format!("{b}/\n{b}/a\n{b}/b\n", b = site.base);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), expected);
    assert!(
        stdout.starts_with("crawl "),
        "results go to the file, the counters stay on stdout:\n{stdout}"
    );

    // -ncb leaves the existing file alone
    let mut args = ctx.base();
    args.extend(strings(&[
        "-o",
        file.to_str().unwrap(),
        "--no-clobber",
        &format!("{}/", site.base),
    ]));
    crawl(&args).await.1.unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), expected);
    assert_eq!(std::fs::read_to_string(ctx.path("urls1.txt")).unwrap(), expected);

    // without -ncb the file is replaced
    std::fs::write(&file, "stale").unwrap();
    let mut args = ctx.base();
    args.extend(strings(&[
        "-o",
        file.to_str().unwrap(),
        &format!("{}/", site.base),
    ]));
    crawl(&args).await.1.unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), expected);
}

#[tokio::test]
async fn store_response_writes_raw_exchanges_and_an_index() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let dir = ctx.path("responses");
    let mut args = ctx.base();
    args.extend(strings(&[
        "-srd",
        dir.to_str().unwrap(),
        &format!("{}/", site.base),
    ]));
    crawl(&args).await.1.unwrap();
    let index = std::fs::read_to_string(dir.join("index.txt")).unwrap();
    let lines: Vec<&str> = index.lines().collect();
    assert_eq!(lines.len(), 3, "{index}");
    for line in &lines {
        assert!(line.ends_with("(200 OK)"), "{line}");
        let file = line.split(' ').next().unwrap();
        let text = std::fs::read_to_string(file).unwrap();
        assert!(text.starts_with(&site.base), "{text}");
        assert!(
            text.contains("GET / HTTP/1.1")
                || text.contains("GET /a HTTP/1.1")
                || text.contains("GET /b HTTP/1.1"),
            "{text}"
        );
        assert!(text.contains("HTTP/1.1 200"), "{text}");
        assert!(
            text.contains("<html"),
            "the raw response carries the body: {text}"
        );
    }
    // -ncb: a non-empty directory is kept, the next numbered one is used
    let mut args = ctx.base();
    args.extend(strings(&[
        "-sr",
        "-srd",
        dir.to_str().unwrap(),
        "-ncb",
        &format!("{}/", site.base),
    ]));
    crawl(&args).await.1.unwrap();
    assert_eq!(std::fs::read_to_string(dir.join("index.txt")).unwrap(), index);
    assert_eq!(
        std::fs::read_to_string(ctx.path("responses1").join("index.txt"))
            .unwrap()
            .lines()
            .count(),
        3
    );
    // -sr alone stores under the output directory
    let mut args = ctx.base();
    args.extend(strings(&["--store-response", &format!("{}/", site.base)]));
    crawl(&args).await.1.unwrap();
    assert!(ctx.out().join("crawlx_response").join("index.txt").is_file());
}

#[tokio::test]
async fn match_and_filter_regexes_select_output_lines() {
    let site = small_site().await;
    let seed = format!("{}/", site.base);
    let lines = |extra: &[&str]| {
        let ctx = Ctx::new(&[&site.base]);
        let mut args = ctx.base();
        args.extend(strings(extra));
        args.extend(strings(&["-f", "path", &seed]));
        async move {
            let _ctx = ctx;
            let (stdout, code) = crawl(&args).await;
            code.unwrap();
            stdout
                .lines()
                .take_while(|l| !l.starts_with("crawl "))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(lines(&["-mr", "^/[ab]$"]).await, ["/a", "/b"]);
    assert_eq!(lines(&["-fr", "^/[ab]$"]).await, ["/"]);
    assert_eq!(
        lines(&["--match-regex", "^/a$,^/b$", "--filter-regex", "b"]).await,
        ["/a"]
    );
    // a file of patterns, one per line
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("patterns.txt");
    std::fs::write(&file, "# keep these\n^/a$\n^/$\n").unwrap();
    assert_eq!(
        lines(&["--match-regex", file.to_str().unwrap()]).await,
        ["/", "/a"]
    );
}

#[tokio::test]
async fn several_fields_print_one_line_per_value_in_field_order() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let mut args = ctx.base();
    args.extend(strings(&[
        "-f",
        "path,fqdn",
        "--filter-regex",
        "^/b",
        &format!("{}/", site.base),
    ]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    let host = site.authority();
    let lines: Vec<&str> = stdout.lines().take_while(|l| !l.starts_with("crawl ")).collect();
    let fqdn = host.split(':').next().unwrap();
    assert_eq!(lines, ["/", fqdn, "/a", fqdn, fqdn], "{stdout}");
    // a bad field fails before anything runs
    let (_, code) = crawl(&{
        let mut a = ctx.base();
        a.extend(strings(&["-f", "path,no such field", &format!("{}/", site.base)]));
        a
    })
    .await;
    assert!(code.unwrap_err().to_string().contains("--field"));
}

#[tokio::test]
async fn match_and_filter_conditions_select_jsonl_records() {
    let site = small_site().await;
    let seed = format!("{}/", site.base);
    let urls = |extra: &[&str]| {
        let ctx = Ctx::new(&[&site.base]);
        let file = ctx.path("r.jsonl");
        let mut args = ctx.base();
        args.extend(strings(&["--jsonl", "-o", file.to_str().unwrap()]));
        args.extend(strings(extra));
        args.push(seed.clone());
        async move {
            let _ctx = ctx;
            crawl(&args).await.1.unwrap();
            let mut urls: Vec<String> = read_jsonl(&file).iter().map(|r| endpoint(r).to_owned()).collect();
            urls.sort();
            urls
        }
    };
    let base = &site.base;
    assert_eq!(urls(&[]).await.len(), 3);
    assert_eq!(
        urls(&["-mdc", r#"ends_with(url, "/a")"#]).await,
        [format!("{base}/a")]
    );
    assert_eq!(
        urls(&[
            "--filter-condition",
            r#"ends_with(url, "/a") || ends_with(url, "/b")"#
        ])
        .await,
        [format!("{base}/")]
    );
    assert_eq!(urls(&["-mdc", "status_code == 404"]).await.len(), 0);
    // a malformed condition fails before the crawl and names the problem
    let ctx = Ctx::new(&[&site.base]);
    let mut args = ctx.base();
    args.extend(strings(&["-mdc", "status_code ==", &seed]));
    let err = crawl(&args).await.1.unwrap_err().to_string();
    assert!(err.contains("--match-condition"), "{err}");
}

#[tokio::test]
async fn filter_page_type_filters_the_output_and_no_expand_page_type_stops_following() {
    let site = Site::start(|_| {
        vec![
            ("/", Page::doc("Home", r#"<a href="/login">sign in</a> <a href="/b">b</a>"#)),
            (
                "/login",
                Page::doc(
                    "Sign in",
                    r#"<form method="post" action="/session"><input name="user"><input type="password" name="pw"></form><a href="/hidden">hidden</a>"#,
                ),
            ),
            ("/b", Page::doc("B", "<p>b</p>")),
            ("/hidden", Page::doc("Hidden", "<p>only reachable through the login page</p>")),
        ]
    })
    .await;
    let seed = format!("{}/", site.base);
    let site = &site;
    let run = |extra: &[&str]| {
        let ctx = Ctx::new(&[&site.base]);
        let file = ctx.path("r.jsonl");
        let mut args = ctx.base();
        args.extend(strings(&["--jsonl", "-o", file.to_str().unwrap()]));
        args.extend(strings(extra));
        args.push(seed.clone());
        let before = site.hits().len();
        async move {
            let _ctx = ctx;
            let (stdout, code) = crawl(&args).await;
            code.unwrap();
            let mut urls: Vec<String> = read_jsonl(&file)
                .iter()
                .map(|r| endpoint(r).rsplit('/').next().unwrap().to_owned())
                .collect();
            urls.sort();
            let fetched: Vec<String> = site
                .hits()
                .into_iter()
                .skip(before)
                .map(|h| h.target)
                .filter(|t| t != "/robots.txt" && t != "/sitemap.xml")
                .collect();
            (urls, fetched, stdout)
        }
    };
    let (urls, fetched, _) = run(&[]).await;
    assert_eq!(urls, ["", "b", "hidden", "login"]);
    assert!(fetched.contains(&"/hidden".to_owned()));

    // -fpt: the login page is crawled and its links followed, but it is not in the output
    let (urls, fetched, stdout) = run(&["--filter-page-type", "login"]).await;
    assert_eq!(urls, ["", "b", "hidden"]);
    assert!(
        fetched.contains(&"/login".to_owned()) && fetched.contains(&"/hidden".to_owned()),
        "{fetched:?}"
    );
    assert!(stdout.contains("urls.succeeded"), "{stdout}");

    // --no-expand-page-type: the page is recorded, its links are not followed
    let (urls, fetched, _) = run(&["--no-expand-page-type", "login"]).await;
    assert_eq!(urls, ["", "b", "login"]);
    assert!(!fetched.contains(&"/hidden".to_owned()), "{fetched:?}");
}

#[tokio::test]
async fn jsonl_carries_body_and_raw_unless_omitted_and_exclude_output_fields_drops_names() {
    let site = small_site().await;
    let seed = format!("{}/", site.base);
    let records = |extra: &[&str]| {
        let ctx = Ctx::new(&[&site.base]);
        let file = ctx.path("r.jsonl");
        let mut args = ctx.base();
        args.extend(strings(&["--jsonl", "-o", file.to_str().unwrap()]));
        args.extend(strings(extra));
        args.push(seed.clone());
        async move {
            let _ctx = ctx;
            crawl(&args).await.1.unwrap();
            read_jsonl(&file)
        }
    };
    let full = records(&[]).await;
    let home = full.iter().find(|r| endpoint(r) == seed).unwrap();
    assert!(home["response"]["body"]
        .as_str()
        .unwrap()
        .contains("Home page text."));
    let raw = home["response"]["raw"].as_str().unwrap();
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    assert!(home["request"]["raw"]
        .as_str()
        .unwrap()
        .starts_with("GET / HTTP/1.1"));

    let slim = records(&["-ob", "-or"]).await;
    let home = slim.iter().find(|r| endpoint(r) == seed).unwrap();
    assert!(home["response"].get("body").is_none());
    assert!(home["response"].get("raw").is_none());
    assert!(home["request"].get("raw").is_none());

    let trimmed = records(&["-eof", "timestamp,body"]).await;
    let home = trimmed.iter().find(|r| endpoint(r) == seed).unwrap();
    assert!(home.get("timestamp").is_none());
    assert!(home["response"].get("body").is_none());
    assert!(home["response"].get("status_code").is_some());

    // a name that is not a JSONL field is refused before the crawl
    let ctx = Ctx::new(&[&site.base]);
    let mut args = ctx.base();
    args.extend(strings(&["-eof", "nonsense", &seed]));
    let err = crawl(&args).await.1.unwrap_err().to_string();
    assert!(
        err.contains("nonsense") && err.contains("--list-output-fields"),
        "{err}"
    );
}

#[tokio::test]
async fn list_output_fields_prints_the_jsonl_field_names_and_exits() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (stdout, code) = crawl(&strings(&["-lof", "--output", out.to_str().unwrap()])).await;
    code.unwrap();
    let names: Vec<&str> = stdout.lines().collect();
    assert!(names.contains(&"status_code"), "{stdout}");
    assert!(names.contains(&"endpoint"), "{stdout}");
    assert!(names.contains(&"technologies"), "{stdout}");
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(names, sorted, "sorted and unique");
    assert!(!out.exists(), "nothing was crawled");
}

#[tokio::test]
async fn the_error_log_lists_failed_urls() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let log = ctx.path("errors.log");
    let mut args = ctx.base();
    args.extend(strings(&[
        "-elog",
        log.to_str().unwrap(),
        &format!("{}/", site.base),
    ]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    let lines = read_jsonl(&log);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["endpoint"], format!("{}/missing", site.base));
    assert_eq!(lines[0]["status_code"], 404);
    assert_eq!(lines[0]["error"], "http_404");
    assert!(stdout.contains("error log: 1 failure(s)"), "{stdout}");
    // an existing log is kept under -ncb
    let mut args = ctx.base();
    args.extend(strings(&[
        "--error-log",
        log.to_str().unwrap(),
        "-ncb",
        &format!("{}/", site.base),
    ]));
    crawl(&args).await.1.unwrap();
    assert_eq!(read_jsonl(&log).len(), 1);
    assert_eq!(read_jsonl(&ctx.path("errors1.log")).len(), 1);
}

#[tokio::test]
async fn silent_prints_results_only_and_no_color_controls_ansi() {
    let site = small_site().await;
    let seed = format!("{}/", site.base);
    let ctx = Ctx::new(&[&site.base]);
    let mut args = ctx.base();
    args.extend(strings(&["--silent", "-f", "path", &seed]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    assert_eq!(stdout, "/\n/a\n/b\n");

    let mut args = ctx.base();
    args.push(seed.clone());
    let (plain, _) = crawl(&args).await;
    assert!(!plain.contains('\x1b'));
    let (forced, _) = crawl_env(&args, &[("CLICOLOR_FORCE", "1")]).await;
    assert!(forced.contains("\x1b[32mfrontier_exhausted\x1b[0m"), "{forced}");
    let mut off = args.clone();
    off.push("--no-color".to_owned());
    let (off, _) = crawl_env(&off, &[("CLICOLOR_FORCE", "1")]).await;
    assert!(!off.contains('\x1b'), "{off}");
    let (no_color_env, _) = crawl_env(&args, &[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "1")]).await;
    assert!(!no_color_env.contains('\x1b'));
}

// ---------------------------------------------------------------------------------------------
// knowledge base, secrets, technologies
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn knowledge_base_adds_the_object_to_jsonl_and_kb_endpoints_classifies_endpoints() {
    let site = Site::start(|_| {
        vec![(
            "/",
            Page::html(
                r#"<html><head><title>Sign in</title></head><body><form method="post" action="/session"><input name="user"><input type="password" name="pw"></form>
                <script>fetch("/api/v1/users"); fetch("/graphql", {method: "POST"});</script></body></html>"#,
            ),
        )]
    })
    .await;
    let seed = format!("{}/", site.base);
    let ctx = Ctx::new(&[&site.base]);
    let file = ctx.path("r.jsonl");
    let mut args = ctx.base();
    args.extend(strings(&[
        "--jsonl",
        "-o",
        file.to_str().unwrap(),
        "--knowledge-base",
        "--kb-endpoints",
        &seed,
    ]));
    crawl(&args).await.1.unwrap();
    let records = read_jsonl(&file);
    let kb = &records[0]["response"]["knowledgebase"];
    assert!(kb.is_object(), "{}", records[0]);
    assert_eq!(kb["PageType"], "login", "{kb}");
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(ctx.out().join("metadata.json")).unwrap()).unwrap();
    let endpoints = metadata[0]["metadata"]["endpoints"].as_array().unwrap();
    assert!(
        endpoints
            .iter()
            .any(|e| e["url"].as_str().is_some_and(|u| u.ends_with("/api/v1/users")) && e["class"] == "rest"),
        "{endpoints:?}"
    );

    // without the flags neither appears
    let ctx = Ctx::new(&[&site.base]);
    let file = ctx.path("r.jsonl");
    let mut args = ctx.base();
    args.extend(strings(&["--jsonl", "-o", file.to_str().unwrap(), &seed]));
    crawl(&args).await.1.unwrap();
    assert!(read_jsonl(&file)[0]["response"].get("knowledgebase").is_none());
}

#[tokio::test]
async fn validating_secrets_without_validators_says_so_and_leaves_findings_unknown() {
    let site = Site::start(|_| {
        vec![(
            "/",
            // Synthetic detector canary, assembled from parts.
            Page::doc(
                "Config",
                concat!("<pre>aws_access_key_id = AKIA", "IOSFODNN7EXAMPLE</pre>"), // detection-data
            ),
        )]
    })
    .await;
    let ctx = Ctx::new(&[&site.base]);
    let mut args = ctx.base();
    args.extend(strings(&["--kb-validate-secrets", &format!("{}/", site.base)]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    assert!(stdout.contains("no validators configured"), "{stdout}");
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(ctx.out().join("metadata.json")).unwrap()).unwrap();
    let secrets = metadata[0]["metadata"]["secrets"].as_array().unwrap();
    assert!(!secrets.is_empty(), "{metadata}");
    assert!(
        secrets.iter().all(|s| s["validation"] == "unknown"),
        "{secrets:?}"
    );
    assert!(!std::fs::read_to_string(ctx.out().join("report.json"))
        .unwrap()
        .contains(concat!("AKIA", "IOSFODNN7EXAMPLE")));

    // --detect-secrets alone neither validates nor mentions validators
    let ctx = Ctx::new(&[&site.base]);
    let mut args = ctx.base();
    args.extend(strings(&["--kb-secrets", &format!("{}/", site.base)]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    assert!(!stdout.contains("no validators configured"));
}

// ---------------------------------------------------------------------------------------------
// -hc, -up, -nos, DEBUG, verbosity
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn health_check_prints_a_table_and_exits_nonzero_when_a_check_fails() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let seed = format!("{}/", site.base);

    let mut args = ctx.base();
    args.extend(strings(&["--health-check", &seed]));
    let (stdout, code) = crawl(&args).await;
    assert_eq!(code.unwrap(), ExitCode::SUCCESS, "{stdout}");
    assert!(stdout.starts_with("check"), "{stdout}");
    assert!(
        stdout.contains("request") && stdout.contains("admitted"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("network {}", site.authority())),
        "{stdout}"
    );
    assert!(stdout.contains("health check passed"), "{stdout}");
    assert!(site.hits().is_empty(), "a health check does not crawl");

    // a refused request fails the check
    let mut args = ctx.base();
    let at = args.iter().position(|a| a == "--allow-private-networks").unwrap();
    args.remove(at);
    args.extend(strings(&["--health-check", &seed]));
    let (stdout, code) = crawl(&args).await;
    assert_eq!(code.unwrap(), ExitCode::from(1), "{stdout}");
    assert!(
        stdout.contains("FAIL") && stdout.contains("health check failed"),
        "{stdout}"
    );

    // a seed nobody listens on fails the network check
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let mut args = ctx.base();
    args.extend(strings(&[
        "--health-check",
        &format!("http://127.0.0.1:{closed}/"),
    ]));
    let (stdout, code) = crawl(&args).await;
    assert_eq!(code.unwrap(), ExitCode::from(1), "{stdout}");
    assert!(
        stdout.contains(&format!("network 127.0.0.1:{closed}")) && stdout.contains("FAIL"),
        "{stdout}"
    );

    // a browser path that is not a file fails (the browser plane is needed in hybrid mode)
    let mut args = ctx.base();
    let at = args.iter().position(|a| a == "--mode").unwrap();
    args.splice(at..=at + 1, strings(&["--mode", "hybrid"]));
    args.extend(strings(&[
        "--health-check",
        "--system-chrome-path",
        "/nonexistent/chromium",
        &seed,
    ]));
    let (stdout, code) = crawl(&args).await;
    assert_eq!(code.unwrap(), ExitCode::from(1), "{stdout}");
    assert!(
        stdout.contains("launch options") && stdout.contains("FAIL"),
        "{stdout}"
    );
}

#[tokio::test]
async fn health_check_queries_every_custom_resolver() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let (dns, _task) = fake_dns([127, 0, 0, 1]).await;
    let mut args = ctx.base();
    args.extend(strings(&[
        "--health-check",
        "--resolvers",
        &dns.to_string(),
        &format!("{}/", site.base),
    ]));
    let (stdout, code) = crawl(&args).await;
    assert_eq!(code.unwrap(), ExitCode::SUCCESS, "{stdout}");
    assert!(stdout.contains(&format!("dns {dns}")), "{stdout}");

    // a resolver that does not exist fails
    let dead = {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap()
    };
    let mut args = ctx.base();
    args.extend(strings(&[
        "--health-check",
        "--resolvers",
        &dead.to_string(),
        &format!("{}/", site.base),
    ]));
    let (stdout, code) = crawl(&args).await;
    assert_eq!(code.unwrap(), ExitCode::from(1), "{stdout}");
    assert!(
        stdout.contains(&format!("dns {dead}")) && stdout.contains("FAIL"),
        "{stdout}"
    );
}

async fn release_server(
    tag: &'static str,
) -> (
    String,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use axum::routing::get;
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/latest",
        get(move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                axum::Json(
                    serde_json::json!({ "tag_name": tag, "html_url": "https://releases.example/latest" }),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/latest", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, hits, task)
}

#[tokio::test]
async fn update_asks_the_release_endpoint_once_and_reports_without_downloading() {
    let (url, hits, _task) = release_server("v99.0.0").await;
    let (stdout, code) = crawl_env(&strings(&["--update"]), &[("CRAWLX_RELEASE_URL", url.as_str())]).await;
    code.unwrap();
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        stdout.contains("a newer crawlx is available: 99.0.0")
            && stdout.contains("https://releases.example/latest"),
        "{stdout}"
    );
    let (url, _, _task) = release_server(concat!("v", env!("CARGO_PKG_VERSION"))).await;
    let (stdout, _) = crawl_env(&strings(&["--update"]), &[("CRAWLX_RELEASE_URL", url.as_str())]).await;
    assert!(stdout.contains("is up to date"), "{stdout}");
    let (url, _, _task) = release_server("v0.0.1").await;
    let (stdout, _) = crawl_env(&strings(&["--update"]), &[("CRAWLX_RELEASE_URL", url.as_str())]).await;
    assert!(
        stdout.contains("is newer than the latest release 0.0.1"),
        "{stdout}"
    );
    // an endpoint that does not answer is an error
    let (_, code) = crawl_env(
        &strings(&["--update"]),
        &[("CRAWLX_RELEASE_URL", "http://127.0.0.1:1/latest")],
    )
    .await;
    assert!(code.is_err());
}

#[tokio::test]
async fn the_automatic_update_check_is_off_by_default_and_disable_update_check_beats_the_env() {
    let (url, hits, _task) = release_server("v99.0.0").await;
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let mut args = ctx.base();
    args.push(format!("{}/", site.base));
    let count = || hits.load(std::sync::atomic::Ordering::SeqCst);

    crawl_env(&args, &[("CRAWLX_RELEASE_URL", url.as_str())])
        .await
        .1
        .unwrap();
    assert_eq!(count(), 0, "off unless CRAWLX_UPDATE_CHECK=1");
    let env = [("CRAWLX_RELEASE_URL", url.as_str()), ("CRAWLX_UPDATE_CHECK", "1")];
    crawl_env(&args, &env).await.1.unwrap();
    assert_eq!(count(), 1, "one request per crawl");
    let mut quiet = args.clone();
    quiet.push("--disable-update-check".to_owned());
    crawl_env(&quiet, &env).await.1.unwrap();
    assert_eq!(
        count(),
        1,
        "-duc suppresses the check even with CRAWLX_UPDATE_CHECK=1"
    );
    assert!(
        crawlx_cli::Cli::try_parse_from(["crawlx", "crawl", "--update", "--disable-update-check"]).is_err()
    );
}

#[tokio::test]
async fn no_sandbox_is_refused_without_the_ci_environment_switch() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let mut args = ctx.base();
    args.extend(strings(&["--no-sandbox", &format!("{}/", site.base)]));
    let err = crawl(&args).await.1.unwrap_err().to_string();
    assert!(err.contains("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI=1"), "{err}");
    assert!(site.hits().is_empty(), "nothing is crawled after the refusal");
    // with the switch the flag is accepted and the crawl runs
    let (_, code) = crawl_env(&args, &[("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI", "1")]).await;
    code.unwrap();
    assert!(!site.hits().is_empty());
}

/// Run the real binary and return its stderr.
async fn stderr_of(args: &[String], env: &[(&str, &str)]) -> (bool, String) {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_crawlx"));
    cmd.arg("crawl").args(args);
    cmd.env_remove("RUST_BACKTRACE")
        .env_remove("CRAWLX_LOG")
        .env_remove("RUST_LOG")
        .env_remove("DEBUG");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().await.unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test]
async fn debug_true_logs_at_debug_level_and_prints_the_full_error_chain_with_a_backtrace() {
    let site = small_site().await;
    let ctx = Ctx::new(&[&site.base]);
    let mut crawl_args = ctx.base();
    crawl_args.push(format!("{}/", site.base));

    // the milestone-gate note is logged at debug level only
    let marker = "milestone gate not attested";
    let (ok, quiet) = stderr_of(&crawl_args, &[]).await;
    assert!(ok && !quiet.contains(marker), "{quiet}");
    let (ok, debug) = stderr_of(&crawl_args, &[("DEBUG", "true")]).await;
    assert!(
        ok && debug.contains(marker),
        "DEBUG=true logs at debug level: {debug}"
    );
    let mut flagged = crawl_args.clone();
    flagged.push("--debug".to_owned());
    let (_, flag_debug) = stderr_of(&flagged, &[]).await;
    assert!(
        flag_debug.contains(marker),
        "--debug logs at debug level: {flag_debug}"
    );
    let mut verbose = crawl_args.clone();
    verbose.push("-v".to_owned());
    let (_, info) = stderr_of(&verbose, &[]).await;
    assert!(!info.contains(marker), "-v is info, not debug: {info}");
    // an explicit --log wins
    let mut warn = crawl_args.clone();
    warn.extend(strings(&["--debug"]));
    let (_, explicit) = {
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_crawlx"));
        cmd.args(["--log", "warn", "crawl"])
            .args(&warn)
            .env_remove("DEBUG")
            .env_remove("CRAWLX_LOG");
        let out = cmd.output().await.unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    assert!(!explicit.contains(marker), "{explicit}");

    // an error with a cause: one line normally, the chain and a backtrace under DEBUG=true
    let missing = ctx.path("missing-request.json");
    let failing = strings(&["--request", missing.to_str().unwrap()]);
    let (ok, plain) = stderr_of(&failing, &[]).await;
    assert!(!ok);
    assert!(
        plain.contains("reading") && !plain.contains("Caused by:") && !plain.contains("stack backtrace"),
        "{plain}"
    );
    let (ok, chain) = stderr_of(&failing, &[("DEBUG", "true")]).await;
    assert!(!ok);
    assert!(chain.contains("Caused by:"), "{chain}");
    assert!(chain.to_lowercase().contains("stack backtrace"), "{chain}");
}

// ---------------------------------------------------------------------------------------------
// browser plane (needs Chromium: CRAWLX_CHROMIUM_PATH)
// ---------------------------------------------------------------------------------------------

/// A request file whose browser strategies need no milestone gate (the test runs without
/// `gates/*.passed`).
fn ungated_request(ctx: &Ctx, base: &str) -> String {
    let path = ctx.path("ungated.json");
    std::fs::write(
        &path,
        serde_json::json!({ "seedUrl": format!("{base}/"), "dynamic": { "strategies": ["interaction_bfs"] } }).to_string(),
    )
    .unwrap();
    path.to_str().unwrap().to_owned()
}

#[tokio::test]
async fn enable_diagnostics_prints_one_record_per_browser_session() {
    if std::env::var_os("CRAWLX_CHROMIUM_PATH").is_none() {
        eprintln!("skipped: CRAWLX_CHROMIUM_PATH is not set");
        return;
    }
    let site = Site::start(|_| {
        vec![
            (
                "/",
                Page::doc(
                    "Home",
                    r#"<button onclick="document.title='x'">go</button><a href="/a">a</a>"#,
                ),
            ),
            ("/a", Page::doc("A", "<p>a</p>")),
        ]
    })
    .await;
    let ctx = Ctx::new(&[&site.base]);
    let request = ungated_request(&ctx, &site.base);
    let mut args = ctx.base();
    let at = args.iter().position(|a| a == "--mode").unwrap();
    args.splice(at..=at + 1, strings(&["--mode", "dynamic"]));
    args.extend(strings(&[
        "--enable-diagnostics",
        "--limit-interactions",
        "3",
        "--crawl-duration",
        "60s",
        "--request",
        &request,
        &format!("{}/", site.base),
    ]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    let at = stdout
        .find("diagnostics: ")
        .unwrap_or_else(|| panic!("no diagnostics block:\n{stdout}"));
    let mut lines = stdout[at..].lines();
    let head = lines.next().unwrap();
    let sessions: usize = head
        .trim_start_matches("diagnostics: ")
        .trim_end_matches(" session(s)")
        .parse()
        .unwrap();
    assert!(sessions >= 1);
    for line in lines.take(sessions) {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }
    // without the flag nothing is printed
    let ctx = Ctx::new(&[&site.base]);
    let request = ungated_request(&ctx, &site.base);
    let mut args = ctx.base();
    let at = args.iter().position(|a| a == "--mode").unwrap();
    args.splice(at..=at + 1, strings(&["--mode", "dynamic"]));
    args.extend(strings(&[
        "--limit-interactions",
        "1",
        "--request",
        &request,
        &format!("{}/", site.base),
    ]));
    let (stdout, code) = crawl(&args).await;
    code.unwrap();
    assert!(!stdout.contains("diagnostics:"), "{stdout}");
}
