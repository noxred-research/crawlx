//! `crawlx --help` snapshot and a smoke crawl against an in-process fixture site.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/site.rs"]
mod site;

use clap::Parser as _;
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;
use std::path::Path;
use std::process::Command;

fn help(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn top_level_help_lists_every_command() {
    let h = help(&["--help"]);
    for cmd in [
        "crawl", "inspect", "replay", "export", "serve", "worker", "migrate", "admin",
    ] {
        assert!(h.contains(cmd), "`{cmd}` missing from:\n{h}");
    }
    assert!(h.contains("Usage: crawlx"), "{h}");
}

#[test]
fn crawl_help_lists_every_flag() {
    let h = help(&["crawl", "--help"]);
    for flag in [
        "--mode",
        "--headless",
        "--profile",
        "--authorization-record",
        "--seed",
        "--output",
        "--observe-only",
        "--database-url",
        "--role",
        "--launch-profile",
        "--allow-private-networks",
        "--limit-urls",
        "--limit-interactions",
        "--request",
        "--trailing-slash",
        "--model-endpoint",
        "--system1-mode",
        "--planner-endpoint",
        "--delay-ms",
        "--delay",
        "--field-scope",
        "--no-scope",
        "--crawl-scope",
        "--crawl-out-scope",
        "--exclude-hosts",
        "--strategy",
        "--max-pages-per-host",
        "--known-files",
        "--extension-match",
        "--extension-filter",
        "--no-default-ext-filter",
        "--no-js-endpoints",
        "--filter-similar",
        "--filter-similar-threshold",
        "--filter-similar-budget",
        "--content-similar",
        "--page-content-similar",
        "--similarity-deduplication",
        "--page-content-similar-mode",
        "--content-similar-distance",
        "--content-similar-threshold",
        "--content-similar-budget",
        "--filter-page-type",
        "--rate-limit",
        "--rate-limit-minute",
        "--host-rate-limit",
        "--host-rate-limit-minute",
        "--concurrency",
        "--max-response-size",
        "--timeout",
        "--retries",
        "--no-redirects",
        "--proxy",
        "--custom-field-config",
        "--detect-secrets",
        "--form-extraction",
        "--no-form-extraction",
        "--page-hooks",
        "--page-load-strategy",
        "--dom-wait-time",
        "--display-out-scope",
        "--jsonl",
        "--field",
        "--output-template",
        "--store-fields",
        // compatibility flag group: input
        "--url",
        "--list",
        "--parallelism",
        "--resume",
        "--config",
        // compatibility flag group: configuration and scope
        "--crawl-duration",
        "--compat-defaults",
        "--health-check",
        "--update",
        "--disable-update-check",
        "--depth",
        "--path-climb",
        "--ignore-query-params",
        "--js-crawl",
        "--resolvers",
        "--headers",
        "--cookie",
        "--user-agent",
        "--robots-user-agent",
        "--skip-tls-verification",
        "--retry",
        "--disable-redirects",
        "--field-config",
        "--kb-secrets",
        // compatibility flag group: extraction and knowledge base
        "--automatic-form-fill",
        "--form-config",
        "--knowledge-base",
        "--kb-endpoints",
        "--kb-validate-secrets",
        "--secret-validators",
        "--tech-detect",
        "--xhr-extraction",
        // compatibility flag group: headless
        "--show-browser",
        "--headless-options",
        "--chrome-data-dir",
        "--system-chrome",
        "--system-chrome-path",
        "--no-sandbox",
        "--interaction-depth",
        "--interaction-selector",
        "--interaction-exclude",
        "--interaction-max-states",
        "--interaction-max-actions",
        "--interaction-settle",
        "--interaction-duration",
        "--max-scroll-steps",
        "--block-consent-banners",
        "--max-failure-count",
        "--enable-diagnostics",
        "--time-stable",
        "--recorded-flow",
        // compatibility flag group: filters and output
        "--disable-unique-filter",
        "--no-expand-page-type",
        "--match-regex",
        "--filter-regex",
        "--match-condition",
        "--filter-condition",
        "--output-file",
        "--no-clobber",
        "--store-response",
        "--store-response-dir",
        "--capture-raw",
        "--omit-raw",
        "--omit-body",
        "--list-output-fields",
        "--exclude-output-fields",
        "--error-log",
        "--no-color",
        "--silent",
        "--verbose",
        "--debug",
        // compatibility flag group: AI
        "--ai-url",
        "--ai-model",
        "--ai-key-env",
        "--ai-record",
        "--ai-replay",
        "--ai-max-calls",
        // compatibility flag group: operator environment named in the long help
        "CRAWLX_TRAFFIC_ENDPOINT",
        "CRAWLX_TRAFFIC_TOKEN",
        "CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI",
        "CRAWLX_UPDATE_CHECK",
    ] {
        assert!(h.contains(flag), "`{flag}` missing from:\n{h}");
    }
    for value in [
        "static",
        "dynamic",
        "hybrid",
        "read_only",
        "test_environment",
        "authorized_security_test",
        "standard",
        "stealth",
        "fqdn",
        "rdn",
        "breadth-first",
        "depth-first",
        "robots_paths",
        "sitemap",
        "simhash",
        "tfidf",
        "bm25",
        "captcha",
        "domcontentloaded",
        "networkidle",
        "priority",
    ] {
        assert!(h.contains(value), "value `{value}` missing from:\n{h}");
    }
}

#[test]
fn inspect_replay_export_help() {
    let h = help(&["inspect", "--help"]);
    for kind in [
        "run",
        "pages",
        "states",
        "epochs",
        "actions",
        "transitions",
        "coverage",
        "traffic",
    ] {
        assert!(h.contains(kind), "`{kind}` missing from:\n{h}");
    }
    assert!(h.contains("--status") && h.contains("--lane") && h.contains("--database-url"));
    let h = help(&["replay", "--help"]);
    assert!(
        h.contains("--to") && h.contains("verify") && h.contains("reproduce"),
        "{h}"
    );
    let h = help(&["export", "--help"]);
    for flag in [
        "--format",
        "--out",
        "--field",
        "--output-template",
        "--match-regex",
        "--filter-regex",
        "--extension-match",
        "--extension-filter",
        "--store-fields",
        "--exclude-fields",
        "--include-body",
        "--database-url",
        "--artifacts-dir",
    ] {
        assert!(h.contains(flag), "`{flag}` missing from:\n{h}");
    }
    for value in ["jsonl", "text", "dump"] {
        assert!(h.contains(value), "`{value}` missing from:\n{h}");
    }
    let h = help(&["worker", "--help"]);
    assert!(h.contains("--recover"), "{h}");
    let h = help(&["migrate", "--help"]);
    assert!(h.contains("--database-url"), "{h}");
    let h = help(&["admin", "--help"]);
    assert!(h.contains("audit-export"), "{h}");
    let h = help(&["admin", "audit-export", "--help"]);
    for flag in [
        "--tenant",
        "--all",
        "--day",
        "--audit-dir",
        "--s3-bucket",
        "--database-url",
    ] {
        assert!(h.contains(flag), "`{flag}` missing from:\n{h}");
    }
}

#[test]
fn admin_help_lists_durability_audit() {
    let h = help(&["admin", "--help"]);
    assert!(h.contains("durability-audit"), "{h}");
    let h = help(&["admin", "durability-audit", "--help"]);
    for needle in [
        "--since",
        "--json",
        "--database-url",
        "SEV-1",
        "missing / checked",
    ] {
        assert!(h.contains(needle), "`{needle}` missing from:\n{h}");
    }
}

/// The audit compares the `crawl.accepted` accept log against `crawl_runs`,
/// moves the two audit counters and exits 1 when any accepted run is gone. Needs
/// `CRAWLX_TEST_DATABASE_URL`; returns early without it.
#[tokio::test]
async fn admin_durability_audit_reports_accepted_runs_without_a_row() {
    use crawlx_storage::retention::append_audit;
    use crawlx_storage::testkit::{crawl_run, create_crawl};
    use crawlx_storage::{Pg, StoreConfig};
    use crawlx_telemetry::metrics::names;
    use crawlx_telemetry::Metrics;
    use std::process::ExitCode;

    let Ok(base) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let schema = format!("t_dur_{}", uuid::Uuid::now_v7().simple());
    let pg = Pg::connect(
        &base,
        StoreConfig {
            schema: Some(schema.clone()),
            max_connections: 4,
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "test").await.unwrap();
    // one accepted run that still exists, one whose row is gone
    let kept = crawl_run(tenant, create_crawl("https://example.test/", &["anonymous"], 1));
    crawlx_core::repo::RunRepo::create(&pg, &kept, None)
        .await
        .unwrap();
    let lost = crawlx_core::CrawlRunId::new();
    for run in [kept.id, lost] {
        append_audit(
            &pg,
            Some(tenant.0),
            Some(run.0),
            "key:test",
            "crawl.accepted",
            serde_json::json!({ "configDigest": "x" }),
        )
        .await
        .unwrap();
    }
    let sep = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{sep}options=-c%20search_path%3D{schema}");

    let checked = Metrics::global().counter(names::JOBS_DURABILITY_AUDIT_CHECKED);
    let missing = Metrics::global().counter(names::JOBS_DURABILITY_AUDIT_MISSING);
    let (checked0, missing0) = (checked.get(&[]), missing.get(&[]));
    let audit = |extra: &'static [&'static str]| {
        let url = url.clone();
        async move {
            let mut argv = vec![
                "crawlx",
                "admin",
                "durability-audit",
                "--database-url",
                url.as_str(),
                "--operator",
                "test",
            ];
            argv.extend_from_slice(extra);
            let cli = crawlx_cli::Cli::try_parse_from(argv).unwrap();
            let mut out = Vec::new();
            let code = crawlx_cli::execute(cli, &mut out).await.unwrap();
            (String::from_utf8(out).unwrap(), code)
        }
    };

    let (out, code) = audit(&[]).await;
    assert_eq!(code, ExitCode::from(1), "{out}");
    assert!(out.starts_with("checked 2 missing 1\n"), "{out}");
    assert!(out.contains(&format!("missing {lost}")), "{out}");
    assert!(!out.contains(&kept.id.to_string()), "{out}");
    assert_eq!(checked.get(&[]) - checked0, 2);
    assert_eq!(missing.get(&[]) - missing0, 1);

    let (out, code) = audit(&["--json"]).await;
    assert_eq!(code, ExitCode::from(1), "{out}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["checked"], 2);
    assert_eq!(v["missing"], serde_json::json!([lost.to_string()]));
    assert_eq!(checked.get(&[]) - checked0, 4);
    assert_eq!(missing.get(&[]) - missing0, 2);

    // a window after both accept rows is clean and exits 0
    let (out, code) = audit(&["--since", "2999-01-01T00:00:00Z"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{out}");
    assert_eq!(out, "checked 0 missing 0\n");
    assert_eq!(checked.get(&[]) - checked0, 4);
    assert_eq!(missing.get(&[]) - missing0, 2);

    pg.drop_schema().await.unwrap();
}

fn record_for(origin: &str) -> AuthorizationRecord {
    let now = SystemClock.now();
    AuthorizationRecord {
        authorized_networks: vec!["127.0.0.0/8".parse().unwrap()],
        ..sample_record(TenantId::new(), now, &[origin])
    }
}

fn write_record(dir: &Path, origin: &str) -> std::path::PathBuf {
    let path = dir.join("authz.local.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&record_for(origin)).unwrap()).unwrap();
    path
}

async fn crawl(args: &[&str]) -> (String, anyhow::Result<std::process::ExitCode>) {
    let mut argv = vec!["crawlx", "crawl"];
    argv.extend_from_slice(args);
    let cli = crawlx_cli::Cli::try_parse_from(argv).unwrap();
    let mut out = Vec::new();
    let code = crawlx_cli::execute(cli, &mut out).await;
    (String::from_utf8(out).unwrap(), code)
}

async fn export(args: &[&str]) -> (String, anyhow::Result<std::process::ExitCode>) {
    let mut argv = vec!["crawlx", "export"];
    argv.extend_from_slice(args);
    let cli = crawlx_cli::Cli::try_parse_from(argv).unwrap();
    let mut out = Vec::new();
    let code = crawlx_cli::execute(cli, &mut out).await;
    (String::from_utf8(out).unwrap(), code)
}

fn authored_field_report(dir: &Path) -> std::path::PathBuf {
    use crawlx_core::hash::Digest;
    use crawlx_core::repo::PageRecord;
    use crawlx_core::{CrawlRunId, TrustLane};

    let url = url::Url::parse("https://example.test:8443/a/b.php?x=1&y=2").unwrap();
    let page = PageRecord {
        run: CrawlRunId::new(),
        frontier_id: 1,
        url: crawlx_url::Canonicalizer::canonicalize_url(&url, &Default::default()).unwrap(),
        status: 200,
        content_type: Some("text/html".to_owned()),
        content_digest: Digest::of("fixture", b"body"),
        title: None,
        markdown: None,
        html: None,
        metadata: serde_json::json!({"custom_fields": {"email": ["a@example.test"]}}),
        links: Vec::new(),
        fetched_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        lane: TrustLane::Diagnostic,
    };
    let report = dir.join("report.json");
    std::fs::write(
        &report,
        serde_json::to_vec(&serde_json::json!({"pages": [page]})).unwrap(),
    )
    .unwrap();
    report
}

#[tokio::test]
async fn export_stores_only_selected_fields_in_an_independent_directory() {
    let dir = tempfile::tempdir().unwrap();
    let report = authored_field_report(dir.path());
    let words = dir.path().join("independent");
    std::fs::create_dir(&words).unwrap();
    let key_file = words.join("https_example.test_8443_key.txt");
    std::fs::write(&key_file, "existing\nx\n").unwrap();
    let (stdout, code) = export(&[
        report.to_str().unwrap(),
        "--format",
        "text",
        "--field",
        "url",
        "--store-field",
        "qurl",
        "--store-field",
        "key",
        "--store-field-dir",
        words.to_str().unwrap(),
    ])
    .await;
    let _exit = code.unwrap();
    assert_eq!(stdout, "https://example.test:8443/a/b.php?x=1&y=2\n");
    assert_eq!(
        std::fs::read_to_string(words.join("https_example.test_8443_qurl.txt")).unwrap(),
        stdout
    );
    assert_eq!(std::fs::read_to_string(&key_file).unwrap(), "existing\nx\ny\n");
    assert_eq!(std::fs::read_dir(&words).unwrap().count(), 2);
    assert!(!dir.path().join("field_wordlists").exists());

    let (stdout, code) = export(&[
        report.to_str().unwrap(),
        "--format",
        "text",
        "--output-template",
        "{{email}} {{path}}",
        "--store-field",
        "qurl,key",
        "--store-fields",
        words.to_str().unwrap(),
    ])
    .await;
    let _exit = code.unwrap();
    assert_eq!(stdout, "a@example.test /a/b.php\n");
    assert_eq!(std::fs::read_dir(&words).unwrap().count(), 2);
    assert_eq!(std::fs::read_to_string(key_file).unwrap(), "existing\nx\ny\n");
}

#[tokio::test]
async fn export_stored_custom_fields_default_beside_report_or_output_file() {
    let dir = tempfile::tempdir().unwrap();
    let report = authored_field_report(dir.path());
    let (stdout, code) = export(&[
        report.to_str().unwrap(),
        "--format",
        "text",
        "--output-template",
        "{{url}} {{path}}",
        "--store-field",
        "email,missing_custom",
    ])
    .await;
    let _exit = code.unwrap();
    assert_eq!(stdout, "https://example.test:8443/a/b.php?x=1&y=2 /a/b.php\n");
    let words = dir.path().join("field_wordlists");
    assert_eq!(
        std::fs::read_to_string(words.join("https_example.test_8443_email.txt")).unwrap(),
        "a@example.test\n"
    );
    assert_eq!(std::fs::read_dir(&words).unwrap().count(), 1);

    let output_dir = dir.path().join("output");
    std::fs::create_dir(&output_dir).unwrap();
    let output = output_dir.join("urls.txt");
    let (_, code) = export(&[
        report.to_str().unwrap(),
        "--format",
        "text",
        "--out",
        output.to_str().unwrap(),
        "--store-field",
        "key",
    ])
    .await;
    let _exit = code.unwrap();
    assert_eq!(
        std::fs::read_to_string(output_dir.join("field_wordlists/https_example.test_8443_key.txt")).unwrap(),
        "x\ny\n"
    );
    assert_eq!(std::fs::read_dir(&words).unwrap().count(), 1);
}

#[tokio::test]
async fn export_rejects_invalid_stored_field_names_before_writing_output() {
    let dir = tempfile::tempdir().unwrap();
    let report = authored_field_report(dir.path());
    let words = dir.path().join("words");
    let output = dir.path().join("urls.txt");
    let (_, code) = export(&[
        report.to_str().unwrap(),
        "--out",
        output.to_str().unwrap(),
        "--store-fields",
        words.to_str().unwrap(),
        "--store-field",
        "../email",
    ])
    .await;
    assert!(code.unwrap_err().to_string().contains("--store-field"));
    assert!(!words.exists());
    assert!(!output.exists());
}

#[tokio::test]
async fn crawl_explicit_wordlists_survive_missing_template_values_with_or_without_jsonl() {
    let site = site::start().await;
    for jsonl in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let authz = write_record(dir.path(), &site.base);
        let output = dir.path().join("output");
        let allowed = format!("{}/?kept=1", site.base);
        let denied = format!("{}/?denied=1", site.base);
        let mut args = vec![
            allowed.as_str(),
            "--url",
            denied.as_str(),
            "--mode",
            "static",
            "--authorization-record",
            authz.to_str().unwrap(),
            "--allow-private-networks",
            "--seed",
            "20261019",
            "--delay-ms",
            "0",
            "--output",
            output.to_str().unwrap(),
            "--output-template",
            "{{email}} {{url}}",
            "--store-field",
            "qurl,key",
            "--match-regex",
            "kept=1|denied=1",
            "--filter-regex",
            "denied=1",
            "--silent",
        ];
        if jsonl {
            args.push("--jsonl");
        }
        let (stdout, code) = crawl(&args).await;
        let _exit = code.unwrap();
        assert_eq!(stdout, "", "missing template field must not invent display text");
        let url = url::Url::parse(&site.base).unwrap();
        let stem = format!("http_{}_{}", url.host_str().unwrap(), url.port().unwrap());
        let words = output.join("field_wordlists");
        assert_eq!(
            std::fs::read_to_string(words.join(format!("{stem}_qurl.txt"))).unwrap(),
            format!("{allowed}\n")
        );
        assert_eq!(
            std::fs::read_to_string(words.join(format!("{stem}_key.txt"))).unwrap(),
            "kept\n"
        );
        assert_eq!(std::fs::read_dir(words).unwrap().count(), 2);
        if jsonl {
            let records = std::fs::read_to_string(output.join("results.jsonl")).unwrap();
            let records: Vec<serde_json::Value> = records
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["request"]["endpoint"], allowed);
        }
    }
}

#[tokio::test]
async fn export_reads_a_local_report_in_every_format() {
    let site = site::start().await;
    let dir = tempfile::tempdir().unwrap();
    let authz = write_record(dir.path(), &site.base);
    let out_dir = dir.path().join("out");
    let (_, code) = crawl(&[
        &format!("{}/", site.base),
        "--mode",
        "static",
        "--authorization-record",
        authz.to_str().unwrap(),
        "--allow-private-networks",
        "--seed",
        "20261019",
        "--delay-ms",
        "0",
        "--output",
        out_dir.to_str().unwrap(),
    ])
    .await;
    let _exit = code.unwrap();
    let report = out_dir.join("report.json");
    let report = report.to_str().unwrap();
    let host = site.base.trim_start_matches("http://");

    // text, default field `url`, to stdout, sorted by URL
    let (stdout, code) = export(&[report, "--format", "text"]).await;
    let _exit = code.unwrap();
    let urls: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        urls,
        ["/", "/a", "/b", "/c"].map(|p| format!("{}{p}", site.base)),
        "{stdout}"
    );

    // --field: path, fqdn, qurl (no page has a query), the directory form accepts a run dir
    let (stdout, code) = export(&[out_dir.to_str().unwrap(), "--format", "text", "--field", "path"]).await;
    let _exit = code.unwrap();
    assert_eq!(stdout, "/\n/a\n/b\n/c\n");
    let (stdout, _) = export(&[report, "--format", "text", "--field", "fqdn"]).await;
    assert_eq!(stdout.lines().collect::<Vec<_>>(), ["127.0.0.1"; 4]);
    let (stdout, code) = export(&[report, "--format", "text", "--field", "qurl"]).await;
    let _exit = code.unwrap();
    assert_eq!(stdout, "");
    let (_, code) = export(&[report, "--format", "text", "--field", "no such"]).await;
    assert!(code.is_err());

    // --output-template with --filter-regex and --match-regex
    let (stdout, code) = export(&[
        report,
        "--format",
        "text",
        "--output-template",
        "{{rurl}} {{path}}",
        "--filter-regex",
        "/c$",
        "--match-regex",
        "/[ab]$",
        "--match-regex",
        "/c$",
    ])
    .await;
    let _exit = code.unwrap();
    assert_eq!(
        stdout,
        format!("http://{host} /a\nhttp://{host} /b\n"),
        "{stdout}"
    );

    // --store-fields writes one wordlist per scheme/host/field and --out writes a file
    let wl = dir.path().join("wordlists");
    let out_file = dir.path().join("paths.txt");
    let (stdout, code) = export(&[
        report,
        "--format",
        "text",
        "--field",
        "path",
        "--store-fields",
        wl.to_str().unwrap(),
        "--out",
        out_file.to_str().unwrap(),
    ])
    .await;
    let _exit = code.unwrap();
    assert_eq!(stdout, format!("exported 4 lines to {}\n", out_file.display()));
    assert_eq!(std::fs::read_to_string(&out_file).unwrap(), "/\n/a\n/b\n/c\n");
    let wl_file = wl.join(format!("http_{}_path.txt", host.replace(':', "_")));
    assert_eq!(
        std::fs::read_to_string(&wl_file).unwrap(),
        "/\n/a\n/b\n/c\n",
        "{}",
        wl_file.display()
    );

    // jsonl: one record per page, no body unless asked, --exclude-fields drops names
    let (stdout, code) = export(&[report, "--exclude-fields", "timestamp,headers"]).await;
    let _exit = code.unwrap();
    let records: Vec<serde_json::Value> = stdout.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(records.len(), 4, "{stdout}");
    assert_eq!(records[0]["request"]["method"], "GET");
    assert_eq!(records[0]["request"]["endpoint"], format!("{}/", site.base));
    assert_eq!(records[0]["response"]["status_code"], 200);
    assert!(records[0].get("timestamp").is_none());
    assert!(records[0]["response"].get("headers").is_none());
    assert!(records[0]["response"].get("body").is_none());
    let (stdout, code) = export(&[report, "--format", "jsonl", "--extension-filter", "none"]).await;
    let _exit = code.unwrap();
    assert_eq!(stdout, "", "every fixture URL has no extension");
    let (stdout, code) = export(&[report, "--format", "jsonl", "--include-body"]).await;
    let _exit = code.unwrap();
    let first: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert!(first.get("timestamp").is_some());
    assert!(first["response"]["headers"].is_object());
    // a body is attached only when the run retained an HTML artifact for the page
    assert!(
        first["response"]["body"]
            .as_str()
            .is_none_or(|b| b.contains("<html")),
        "{first}"
    );

    // dump needs PostgreSQL
    let (_, code) = export(&[report, "--format", "dump"]).await;
    assert!(code.is_err());
}

#[tokio::test]
async fn static_crawl_smoke_writes_files_and_prints_the_counter_block() {
    let site = site::start().await;
    let dir = tempfile::tempdir().unwrap();
    let authz = write_record(dir.path(), &site.base);
    let out_dir = dir.path().join("out");
    let (stdout, code) = crawl(&[
        &format!("{}/", site.base),
        "--mode",
        "static",
        "--authorization-record",
        authz.to_str().unwrap(),
        "--allow-private-networks",
        "--seed",
        "20261019",
        "--delay-ms",
        "0",
        "--output",
        out_dir.to_str().unwrap(),
    ])
    .await;
    let _exit = code.unwrap();

    // the summary block
    let mut lines = stdout.lines();
    let head = lines.next().unwrap();
    assert!(
        head.starts_with("crawl ") && head.ends_with("mode=static terminal_reason=frontier_exhausted"),
        "{head}"
    );
    // `{:<20}{:>3}`: name padded to 20 columns, value right-aligned in 3
    for (name, value) in [
        ("urls.discovered", 13),
        ("urls.admitted", 5),
        ("urls.deduplicated", 6),
        ("urls.policy_blocked", 1),
        ("urls.robots_blocked", 1),
        ("urls.attempted", 5),
        ("urls.succeeded", 4),
        ("urls.failed", 1),
        ("unknown_outcome", 0),
    ] {
        let expected = format!("{name:<20}{value:>3}");
        assert!(
            stdout.lines().any(|l| l == expected),
            "`{expected}` missing from:\n{stdout}"
        );
    }
    assert!(stdout
        .lines()
        .any(|l| l == "urls.deduplicated    6" || l == "urls.deduplicated     6"));
    assert!(stdout.contains("pages written: 4"), "{stdout}");
    assert!(
        stdout.contains("pages/*.md  (+ metadata.json, links.json)"),
        "{stdout}"
    );

    // files
    let mut md: Vec<String> = std::fs::read_dir(out_dir.join("pages"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    md.sort();
    assert_eq!(md.len(), 4, "{md:?}");
    assert!(md.iter().all(|n| n.ends_with(".md")));
    let home = std::fs::read_to_string(out_dir.join("pages").join(&md[0])).unwrap()
        + &std::fs::read_to_string(out_dir.join("pages").join(&md[1])).unwrap();
    assert!(
        home.contains("Welcome to the fixture site.") || home.contains("Page A text."),
        "{home}"
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out_dir.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(metadata.as_array().unwrap().len(), 4);
    assert!(metadata
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["title"] == "Home" && p["status"] == 200));
    let links: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out_dir.join("links.json")).unwrap()).unwrap();
    assert_eq!(links.as_object().unwrap().len(), 4);

    // report.json carries the counters and the invariants hold
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out_dir.join("report.json")).unwrap()).unwrap();
    let u = &report["counters"]["urls"];
    let n = |k: &str| u[k].as_u64().unwrap();
    assert_eq!(
        n("discovered"),
        n("admitted") + n("deduplicated") + n("policy_blocked") + n("robots_blocked")
    );
    assert_eq!(
        n("attempted"),
        n("succeeded") + n("failed") + n("abandoned") + n("unreachable") + n("unknown_outcome")
    );
    assert_eq!(report["status"], "completed");
    assert_eq!(report["request"]["mode"], "static");
    // the tracking-parameter duplicate and the robots-blocked page were not fetched
    let urls: Vec<&str> = metadata
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["url"].as_str().unwrap())
        .collect();
    assert!(
        urls.iter()
            .all(|u| !u.contains("utm_source") && !u.contains("/private/")),
        "{urls:?}"
    );
}

#[tokio::test]
async fn static_crawl_with_jsonl_field_and_store_fields() {
    let site = site::start().await;
    let dir = tempfile::tempdir().unwrap();
    let authz = write_record(dir.path(), &site.base);
    let out_dir = dir.path().join("out");
    let words = dir.path().join("words");
    let (stdout, code) = crawl(&[
        &format!("{}/", site.base),
        "--mode",
        "static",
        "--authorization-record",
        authz.to_str().unwrap(),
        "--allow-private-networks",
        "--seed",
        "20261019",
        "--delay-ms",
        "0",
        "--output",
        out_dir.to_str().unwrap(),
        "--jsonl",
        "--field",
        "path",
        "--store-fields",
        words.to_str().unwrap(),
    ])
    .await;
    let _exit = code.unwrap();

    // one line per page path, URL order, before the counter block
    let paths: Vec<&str> = stdout.lines().take_while(|l| !l.starts_with("crawl ")).collect();
    assert_eq!(paths, ["/", "/a", "/b", "/c"], "{stdout}");
    assert!(stdout.contains("urls.succeeded"), "{stdout}");

    // results.jsonl: the contract shape, one record per page
    let jsonl = std::fs::read_to_string(out_dir.join("results.jsonl")).unwrap();
    let records: Vec<serde_json::Value> = jsonl.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(records.len(), 4, "{jsonl}");
    for r in &records {
        assert_eq!(r["request"]["method"], "GET", "{r}");
        assert!(r["request"]["endpoint"].as_str().unwrap().starts_with(&site.base));
        assert!(r["response"]["status_code"].is_number(), "{r}");
        assert!(r["timestamp"].is_string(), "{r}");
    }
    assert!(records.iter().any(|r| r["response"]["status_code"] == 200));

    // the per-host wordlist of the selected field
    let base = url::Url::parse(&site.base).unwrap();
    let list = words.join(format!(
        "{}_{}_{}_path.txt",
        base.scheme(),
        base.host_str().unwrap(),
        base.port().unwrap()
    ));
    let list = std::fs::read_to_string(&list).unwrap_or_else(|e| panic!("{}: {e}", list.display()));
    assert_eq!(list.lines().collect::<Vec<_>>(), ["/", "/a", "/b", "/c"]);
}

#[tokio::test]
async fn a_bad_output_field_is_refused_before_anything_runs() {
    for flag in ["--field", "--store-field"] {
        let dir = tempfile::tempdir().unwrap();
        let (_, code) = crawl(&[
            "https://example.test/",
            "--mode",
            "static",
            "--output",
            dir.path().join("out").to_str().unwrap(),
            flag,
            "no such field",
        ])
        .await;
        let err = code.unwrap_err().to_string();
        assert!(err.contains(flag), "{err}");
        assert!(!dir.path().join("out").join("report.json").exists());
    }
}

#[tokio::test]
async fn private_networks_without_an_authorization_record_are_refused() {
    let site = site::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (_, code) = crawl(&[
        &format!("{}/", site.base),
        "--mode",
        "static",
        "--allow-private-networks",
        "--output",
        dir.path().join("out").to_str().unwrap(),
    ])
    .await;
    let err = code.unwrap_err().to_string();
    assert!(
        err.contains("request rejected") && err.contains("authorization"),
        "{err}"
    );
    assert!(!dir.path().join("out").join("report.json").exists());
}

#[tokio::test]
async fn private_addresses_are_blocked_by_default() {
    // without the exemption the fetch plane refuses the loopback seed: nothing is crawled
    let site = site::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (_, code) = crawl(&[
        &format!("{}/", site.base),
        "--mode",
        "static",
        "--output",
        dir.path().join("out").to_str().unwrap(),
    ])
    .await;
    let err = code.unwrap_err().to_string();
    assert!(
        err.contains("request rejected") && err.contains("url_denied"),
        "{err}"
    );
}

#[tokio::test]
async fn inspect_needs_a_database() {
    let cli = crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "inspect",
        "states",
        "0198c0de-0000-7000-8000-000000000000",
    ])
    .unwrap();
    let mut out = Vec::new();
    let err = crawlx_cli::execute(cli, &mut out).await.unwrap_err().to_string();
    assert!(err.contains("--database-url"), "{err}");
}

#[test]
fn malformed_role_specs_are_rejected_by_the_request_builder() {
    let cli =
        crawlx_cli::Cli::try_parse_from(["crawlx", "crawl", "https://example.com/", "--role", "no-equals"])
            .unwrap();
    let crawlx_cli::Command::Crawl(args) = cli.command else {
        panic!()
    };
    assert!(crawlx_cli::crawl::build_request(&args).is_err());
    let cli = crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "crawl",
        "https://example.com/",
        "--role",
        "admin=env://ADMIN",
        "--limit-urls",
        "7",
        "--profile",
        "test_environment",
        "--observe-only",
    ])
    .unwrap();
    let crawlx_cli::Command::Crawl(args) = cli.command else {
        panic!()
    };
    let crawl = crawlx_cli::crawl::build_request(&args).unwrap();
    assert_eq!(crawl.limits.urls, 7);
    assert_eq!(crawl.roles[0].name, "admin");
    assert_eq!(crawl.roles[0].credential_ref.as_ref().unwrap().0, "env://ADMIN");
    assert!(crawl.dynamic.observe_only);
    assert_eq!(crawl.safety.profile, crawlx_core::SafetyProfile::TestEnvironment);
}

#[tokio::test]
async fn a_system1_mode_without_a_model_endpoint_is_refused_before_anything_runs() {
    let dir = tempfile::tempdir().unwrap();
    let (_, code) = crawl(&[
        "https://example.test/",
        "--mode",
        "dynamic",
        "--system1-mode",
        "shadow",
        "--output",
        dir.path().join("out").to_str().unwrap(),
    ])
    .await;
    let err = code.unwrap_err().to_string();
    assert!(err.contains("--model-endpoint"), "{err}");
    assert!(!dir.path().join("out").join("report.json").exists());
}

#[tokio::test]
async fn empty_checkpoint_kms_key_is_refused_before_crawl_worker_or_replay_admission() {
    let dir = tempfile::tempdir().unwrap();
    let run = "0198c0de-0000-7000-8000-000000000000";
    let cases = [
        vec![
            "crawlx",
            "crawl",
            "https://example.test/",
            "--mode",
            "static",
            "--output",
            dir.path().to_str().unwrap(),
        ],
        vec![
            "crawlx",
            "worker",
            "--database-url",
            "postgresql://127.0.0.1:1/not-contacted",
        ],
        vec!["crawlx", "replay", run, "--to", run],
    ];
    for arguments in cases {
        let cli = crawlx_cli::Cli::try_parse_from(arguments).unwrap();
        let error = crawlx_cli::execute_with_env(cli, &mut Vec::new(), &|name| {
            (name == "CRAWLX_CHECKPOINT_KMS_KEY_ID").then(String::new)
        })
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("checkpoint KMS key id must not be empty"),
            "{error}"
        );
        assert!(!dir.path().join("report.json").exists());
    }
}

#[test]
fn model_flags_shape_the_request() {
    let cli = crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "crawl",
        "https://example.test/",
        "--mode",
        "dynamic",
        "--model-endpoint",
        "http://decision.test/",
        "--system1-mode",
        "advisory",
        "--planner-endpoint",
        "http://planner.test/",
    ])
    .unwrap();
    let crawlx_cli::Command::Crawl(args) = cli.command else {
        panic!("crawl command");
    };
    let crawl = crawlx_cli::crawl::build_request(&args).unwrap();
    assert_eq!(
        crawl.dynamic.system1_mode,
        crawlx_core::config::System1Mode::Advisory
    );
    assert!(crawl
        .dynamic
        .strategies
        .contains(&crawlx_core::config::StrategyName::System1));
    assert_eq!(
        crawl.dynamic.llm_planner,
        crawlx_core::config::LlmPlannerMode::StalledOnly
    );
}

#[test]
fn active_mode_is_not_a_flag_value() {
    assert!(crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "crawl",
        "https://example.test/",
        "--system1-mode",
        "active",
    ])
    .is_err());
}

#[test]
fn worker_help_lists_attach_flags() {
    let h = help(&["worker", "--help"]);
    assert!(
        h.contains("--cdp-ws-url") && h.contains("--cdp-ws-url-file") && h.contains("--no-incognito"),
        "{h}"
    );
    // `--no-incognito` only makes sense for an attached browser; the sources can also come from
    // the environment, so the check runs where the attach settings are resolved
    let cli = crawlx_cli::Cli::try_parse_from(["crawlx", "worker", "--no-incognito"]).unwrap();
    let crawlx_cli::Command::Worker(args) = cli.command else {
        panic!("not a worker command");
    };
    assert!(args.cdp.resolve(&|_| None).is_err());
    let attached = args.cdp.resolve(&|name| {
        (name == "CRAWLX_CDP_WS_URL").then(|| "ws://127.0.0.1:9222/devtools/browser/x".to_owned())
    });
    assert!(!attached.unwrap().unwrap().incognito);
}

fn parse_crawl(args: &[&str]) -> crawlx_cli::crawl::CrawlArgs {
    let mut argv = vec!["crawlx", "crawl", "https://example.test/"];
    argv.extend_from_slice(args);
    let cli = crawlx_cli::Cli::try_parse_from(argv).unwrap();
    let crawlx_cli::Command::Crawl(args) = cli.command else {
        panic!("crawl command");
    };
    *args
}

#[test]
fn compat_flags_map_onto_the_request() {
    use crawlx_core::config::{
        CrawlStrategy, CustomFieldPart, HostScope, KnownFile, PageLoadStrategy, PageType, SimilarityMode,
    };
    let dir = tempfile::tempdir().unwrap();
    let fields = dir.path().join("fields.yaml");
    std::fs::write(
        &fields,
        "- name: email\n  regex: ['[a-z]+@[a-z]+\\.[a-z]+']\n  part: body\n  group: 0\n",
    )
    .unwrap();
    let fields = fields.to_str().unwrap().to_owned();
    let crawl = crawlx_cli::crawl::build_request(&parse_crawl(&[
        "--field-scope",
        "rdn",
        "--crawl-scope",
        "^https://example\\.test/docs/",
        "--crawl-scope",
        "^https://example\\.test/api/",
        "--crawl-out-scope",
        "logout",
        "--exclude-hosts",
        "private-ips,10.0.0.0/8,cdn\\..*",
        "--strategy",
        "depth-first",
        "--max-pages-per-host",
        "50",
        "--known-files",
        "robots_paths,sitemap",
        "--extension-match",
        "html,php,none",
        "--extension-filter",
        "woff2,map",
        "--no-default-ext-filter",
        "--no-js-endpoints",
        "--filter-similar",
        "--filter-similar-threshold",
        "7",
        "--filter-similar-budget",
        "2",
        "--content-similar",
        "tfidf",
        "--content-similar-distance",
        "5",
        "--content-similar-threshold",
        "0.9",
        "--content-similar-budget",
        "3",
        "--no-expand-page-type",
        "login,error",
        "--rate-limit",
        "20",
        "--host-rate-limit-minute",
        "600",
        "--concurrency",
        "4",
        "--max-response-size",
        "1048576",
        "--timeout",
        "15",
        "--retries",
        "3",
        "--no-redirects",
        "--proxy",
        "socks5://127.0.0.1:1080",
        "--custom-field-config",
        &fields,
        "--detect-secrets",
        "--no-form-extraction",
        "--page-hooks",
        "--page-load-strategy",
        "networkidle",
        "--dom-wait-time",
        "2",
        "--display-out-scope",
    ]))
    .unwrap();

    // (flag, observed, expected): one row per mapping
    let s = &crawl.scope;
    let rows: Vec<(&str, String, String)> = vec![
        (
            "--field-scope",
            format!("{:?}", s.host_scope),
            format!("{:?}", HostScope::Rdn),
        ),
        (
            "--crawl-scope",
            format!("{:?}", s.url_include),
            format!(
                "{:?}",
                ["^https://example\\.test/docs/", "^https://example\\.test/api/"]
            ),
        ),
        (
            "--crawl-out-scope",
            format!("{:?}", s.url_exclude),
            format!("{:?}", ["logout"]),
        ),
        (
            "--exclude-hosts",
            format!("{:?}", s.exclude_hosts),
            format!("{:?}", ["private-ips", "10.0.0.0/8", "cdn\\..*"]),
        ),
        (
            "--strategy",
            format!("{:?}", s.strategy),
            format!("{:?}", CrawlStrategy::DepthFirst),
        ),
        (
            "--max-pages-per-host",
            format!("{:?}", s.max_pages_per_host),
            format!("{:?}", Some(50)),
        ),
        (
            "--known-files",
            format!("{:?}", s.known_files),
            format!("{:?}", [KnownFile::RobotsPaths, KnownFile::Sitemap]),
        ),
        (
            "--extension-match",
            format!("{:?}", s.extension_match),
            format!("{:?}", ["html", "php", "none"]),
        ),
        (
            "--extension-filter",
            format!("{:?}", s.extension_filter),
            format!("{:?}", ["woff2", "map"]),
        ),
        (
            "--no-default-ext-filter",
            s.no_default_extension_filter.to_string(),
            "true".into(),
        ),
        ("--no-js-endpoints", s.js_endpoints.to_string(), "false".into()),
        ("--filter-similar", s.filter_similar.to_string(), "true".into()),
        (
            "--filter-similar-threshold",
            s.filter_similar_threshold.to_string(),
            "7".into(),
        ),
        (
            "--filter-similar-budget",
            s.filter_similar_budget.to_string(),
            "2".into(),
        ),
        (
            "--content-similar",
            format!("{:?}", s.content_similarity.mode),
            format!("{:?}", SimilarityMode::Tfidf),
        ),
        (
            "--content-similar-distance",
            s.content_similarity.distance.to_string(),
            "5".into(),
        ),
        (
            "--content-similar-threshold",
            s.content_similarity.threshold.to_string(),
            "0.9".into(),
        ),
        (
            "--content-similar-budget",
            s.content_similarity.budget.to_string(),
            "3".into(),
        ),
        (
            "--no-expand-page-type",
            format!("{:?}", s.filter_page_types),
            format!("{:?}", [PageType::Login, PageType::Error]),
        ),
        (
            "--rate-limit",
            format!("{:?}", crawl.politeness.global_rps),
            format!("{:?}", Some(20)),
        ),
        (
            "--rate-limit-minute (unset)",
            format!("{:?}", crawl.politeness.global_rpm),
            "None".into(),
        ),
        (
            "--host-rate-limit (unset)",
            format!("{:?}", crawl.politeness.per_host_rps),
            "None".into(),
        ),
        (
            "--host-rate-limit-minute",
            format!("{:?}", crawl.politeness.per_host_rpm),
            format!("{:?}", Some(600)),
        ),
        (
            "--concurrency",
            crawl.politeness.max_concurrency.to_string(),
            "4".into(),
        ),
        (
            "--max-response-size",
            crawl.fetch.max_response_bytes.to_string(),
            "1048576".into(),
        ),
        ("--timeout", crawl.fetch.timeout_ms.to_string(), "15000".into()),
        ("--retries", crawl.fetch.retries.to_string(), "3".into()),
        (
            "--no-redirects",
            crawl.fetch.follow_redirects.to_string(),
            "false".into(),
        ),
        (
            "--proxy",
            format!("{:?}", crawl.fetch.proxy.as_ref().map(url::Url::as_str)),
            format!("{:?}", Some("socks5://127.0.0.1:1080")),
        ),
        (
            "--custom-field-config (name)",
            crawl.extract.custom_fields[0].name.clone(),
            "email".into(),
        ),
        (
            "--custom-field-config (part)",
            format!("{:?}", crawl.extract.custom_fields[0].part),
            format!("{:?}", CustomFieldPart::Body),
        ),
        (
            "--detect-secrets",
            crawl.extract.detect_secrets.to_string(),
            "true".into(),
        ),
        (
            "--no-form-extraction",
            crawl.extract.forms.to_string(),
            "false".into(),
        ),
        (
            "--page-hooks",
            crawl.dynamic.page_hooks.to_string(),
            "true".into(),
        ),
        (
            "--page-load-strategy",
            format!("{:?}", crawl.dynamic.page_load_strategy),
            format!("{:?}", PageLoadStrategy::NetworkIdle),
        ),
        (
            "--dom-wait-time",
            crawl.dynamic.dom_wait_ms.to_string(),
            "2000".into(),
        ),
        (
            "--display-out-scope",
            crawl.output.include_out_of_scope.to_string(),
            "true".into(),
        ),
    ];
    for (flag, got, want) in rows {
        assert_eq!(got, want, "{flag}");
    }
    assert_eq!(crawl.extract.custom_fields.len(), 1);

    // the pair conflicts and the boolean pair conflict are enforced by clap
    for conflicting in [
        &["--rate-limit", "1", "--rate-limit-minute", "60"][..],
        &["--host-rate-limit", "1", "--host-rate-limit-minute", "60"],
        &["--form-extraction", "--no-form-extraction"],
        &["--field", "url", "--output-template", "{{url}}"],
    ] {
        let mut argv = vec!["crawlx", "crawl", "https://example.test/"];
        argv.extend_from_slice(conflicting);
        assert!(crawlx_cli::Cli::try_parse_from(argv).is_err(), "{conflicting:?}");
    }
    // `--form-extraction` alone keeps forms on (the default)
    let crawl = crawlx_cli::crawl::build_request(&parse_crawl(&["--form-extraction"])).unwrap();
    assert!(crawl.extract.forms);
}

#[test]
fn flags_override_a_request_file() {
    let dir = tempfile::tempdir().unwrap();
    let request = dir.path().join("request.json");
    std::fs::write(
        &request,
        serde_json::to_vec(&serde_json::json!({
            "seedUrl": "https://example.test/",
            "scope": { "hostScope": "dn", "urlInclude": ["^https://example\\.test/keep/"], "strategy": "depth_first" },
            "politeness": { "globalRps": 3 },
            "fetch": { "timeoutMs": 1234, "followRedirects": true },
        }))
        .unwrap(),
    )
    .unwrap();
    let crawl = crawlx_cli::crawl::build_request(&parse_crawl(&[
        "--request",
        request.to_str().unwrap(),
        "--field-scope",
        "fqdn",
        "--timeout",
        "5",
        "--no-redirects",
    ]))
    .unwrap();
    assert_eq!(crawl.scope.host_scope, crawlx_core::config::HostScope::Fqdn);
    assert_eq!(crawl.fetch.timeout_ms, 5000);
    assert!(!crawl.fetch.follow_redirects);
    // untouched file values survive
    assert_eq!(crawl.scope.url_include, ["^https://example\\.test/keep/"]);
    assert_eq!(
        crawl.scope.strategy,
        crawlx_core::config::CrawlStrategy::DepthFirst
    );
    assert_eq!(crawl.politeness.global_rps, Some(3));
}

#[test]
fn custom_field_config_parses_yaml_and_json() {
    use crawlx_core::config::CustomFieldPart;
    let dir = tempfile::tempdir().unwrap();
    // the compatibility field-config.yaml shape: `type` is optional and
    // an absent `part` scans the whole response
    let yaml = dir.path().join("fields.yaml");
    std::fs::write(
        &yaml,
        "- name: email\n  type: regex\n  part: response\n  regex:\n    - '([a-z0-9._-]+@[a-z0-9._-]+\\.[a-z_-]+)'\n- name: server\n  part: header\n  group: 1\n  regex: ['^server: (.*)$']\n- name: whole\n  regex: ['x']\n",
    )
    .unwrap();
    let json = dir.path().join("fields.json");
    std::fs::write(
        &json,
        serde_json::to_vec(&serde_json::json!([
            { "name": "email", "type": "regex", "part": "response", "regex": ["([a-z0-9._-]+@[a-z0-9._-]+\\.[a-z_-]+)"] },
            { "name": "server", "part": "header", "group": 1, "regex": ["^server: (.*)$"] },
            { "name": "whole", "regex": ["x"] },
        ]))
        .unwrap(),
    )
    .unwrap();
    let from_yaml = crawlx_cli::crawl::load_custom_fields(&yaml).unwrap();
    let from_json = crawlx_cli::crawl::load_custom_fields(&json).unwrap();
    assert_eq!(from_yaml, from_json);
    assert_eq!(from_yaml.len(), 3);
    assert_eq!(from_yaml[0].name, "email");
    assert_eq!(from_yaml[0].part, CustomFieldPart::Response);
    assert_eq!(from_yaml[0].group, 0);
    assert_eq!(from_yaml[1].part, CustomFieldPart::Header);
    assert_eq!(from_yaml[1].group, 1);
    assert_eq!(from_yaml[1].regex, ["^server: (.*)$"]);
    assert_eq!(from_yaml[2].part, CustomFieldPart::Response);

    // unsupported `type` and unknown keys are rejected
    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, "- name: x\n  type: xpath\n  regex: ['x']\n").unwrap();
    let err = crawlx_cli::crawl::load_custom_fields(&bad)
        .unwrap_err()
        .to_string();
    assert!(err.contains("xpath"), "{err}");
    std::fs::write(&bad, "- name: x\n  regexp: ['x']\n").unwrap();
    assert!(crawlx_cli::crawl::load_custom_fields(&bad).is_err());
}
