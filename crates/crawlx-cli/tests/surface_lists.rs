//! List-valued and configuration flags of `crawlx crawl`, asserted on the request they build:
//! resolver list files, known-file spellings without duplicates, `--cache-mode`, the layered
//! configuration precedence, and `--print-config`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use clap::Parser as _;
use crawlx_core::cache::CacheModeV1;
use crawlx_core::config::KnownFile;
use crawlx_core::CreateCrawl;
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Stdio};

fn parse(args: &[&str]) -> Result<crawlx_cli::CrawlArgs, clap::Error> {
    let mut argv = vec!["crawlx", "crawl", "https://example.test/"];
    argv.extend_from_slice(args);
    let cli = crawlx_cli::Cli::try_parse_from(crawlx_cli::normalize_args(argv))?;
    let crawlx_cli::Command::Crawl(args) = cli.command else {
        panic!("crawl command");
    };
    Ok(*args)
}

fn request_of(args: &[&str]) -> CreateCrawl {
    crawlx_cli::crawl::build_request(&parse(args).unwrap()).unwrap()
}

fn request_error(args: &[&str]) -> String {
    match parse(args) {
        Err(e) => e.to_string(),
        Ok(parsed) => format!("{:#}", crawlx_cli::crawl::build_request(&parsed).unwrap_err()),
    }
}

fn write(dir: &Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_owned()
}

// --- resolver lists -----------------------------------------------------------------------

#[test]
fn resolver_files_hold_comma_and_space_separated_entries_comments_and_repeats() {
    let dir = tempfile::tempdir().unwrap();
    let list = write(
        dir.path(),
        "resolvers.txt",
        "# DNS servers\n1.1.1.1, 9.9.9.9:5353   # pair\n\n[2606:4700:4700::1111]:53\n9.9.9.9:5353\n",
    );
    let c = request_of(&["--resolvers", &list, "-r", "8.8.8.8", "-r", "1.1.1.1"]);
    assert_eq!(
        c.fetch.resolvers,
        ["1.1.1.1", "9.9.9.9:5353", "[2606:4700:4700::1111]:53", "8.8.8.8"]
    );
}

#[test]
fn resolver_errors_name_the_flag_the_entry_and_the_cap() {
    let dir = tempfile::tempdir().unwrap();
    let bad = write(dir.path(), "bad.txt", "1.1.1.1\ndns.example\n");
    let error = request_error(&["--resolvers", &bad]);
    assert!(
        error.contains("--resolvers") && error.contains("dns.example"),
        "{error}"
    );
    let nine = (1..=9)
        .map(|n| format!("10.0.0.{n}"))
        .collect::<Vec<_>>()
        .join(",");
    let error = request_error(&["--resolvers", &nine]);
    assert!(error.contains("9 distinct resolvers"), "{error}");
    // eight distinct servers named nine times fit
    let repeated = format!(
        "{},10.0.0.1",
        (1..=8)
            .map(|n| format!("10.0.0.{n}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(request_of(&["--resolvers", &repeated]).fetch.resolvers.len(), 8);
}

// --- known files ----------------------------------------------------------------------------

#[test]
fn known_file_spellings_and_all_never_name_a_file_twice() {
    let files = |args: &[&str]| {
        let mut c = request_of(args);
        c.normalize().unwrap();
        c.scope.known_files
    };
    assert_eq!(files(&["--known-files", "sitemap"]), [KnownFile::Sitemap]);
    assert_eq!(files(&["-kf", "robotstxt"]), [KnownFile::RobotsPaths]);
    assert_eq!(files(&["-kf", "sitemapxml"]), [KnownFile::Sitemap]);
    for spelling in [
        "all",
        "robotstxt,sitemapxml",
        "all,sitemap,robots_paths",
        "sitemap-xml,robots,all",
    ] {
        assert_eq!(
            files(&["-kf", spelling]),
            [KnownFile::RobotsPaths, KnownFile::Sitemap],
            "{spelling}"
        );
    }
    // repeated flags add up, still once each
    assert_eq!(
        files(&["-kf", "sitemap", "-kf", "all"]),
        [KnownFile::RobotsPaths, KnownFile::Sitemap]
    );
    assert!(parse(&["-kf", "sitemap.xml"]).is_err());
}

#[test]
fn path_climb_has_the_compatibility_and_native_spellings() {
    assert!(request_of(&["-pc"]).scope.path_climb);
    assert!(request_of(&["-path-climb"]).scope.path_climb);
    assert!(request_of(&["--path-climb"]).scope.path_climb);
    assert!(!request_of(&[]).scope.path_climb);
}

// --- cache mode and layered configuration ---------------------------------------------------

#[test]
fn cache_mode_replaces_the_layers_below_it_and_unknown_modes_are_refused() {
    assert!(
        request_of(&[]).cache.is_none(),
        "no flag leaves the facade semantics alone"
    );
    for (flag, mode) in [
        ("read_write", CacheModeV1::ReadWrite),
        ("read-write", CacheModeV1::ReadWrite),
        ("bypass", CacheModeV1::Bypass),
        ("disabled", CacheModeV1::Disabled),
        ("read_only", CacheModeV1::ReadOnly),
        ("write-only", CacheModeV1::WriteOnly),
    ] {
        assert_eq!(
            request_of(&["--cache-mode", flag]).cache.unwrap().mode,
            mode,
            "{flag}"
        );
    }
    assert!(parse(&["--cache-mode", "forever"]).is_err());

    let dir = tempfile::tempdir().unwrap();
    let request = write(
        dir.path(),
        "request.json",
        r#"{"seedUrl":"https://example.test/","cache":{"mode":"read_only","maxAgeMs":1000}}"#,
    );
    let from_file = request_of(&["--request", &request]).cache.unwrap();
    assert_eq!(
        (from_file.mode, from_file.max_age_ms),
        (CacheModeV1::ReadOnly, 1000)
    );
    let flagged = request_of(&["--request", &request, "--cache-mode", "bypass"])
        .cache
        .unwrap();
    assert_eq!(
        (flagged.mode, flagged.max_age_ms),
        (CacheModeV1::Bypass, 1000),
        "the flag wins its field and keeps the rest of the file's policy"
    );
}

#[test]
fn configuration_layers_apply_defaults_then_config_then_request_then_flags() {
    let dir = tempfile::tempdir().unwrap();
    let config = write(
        dir.path(),
        "config.json",
        r#"{"limits":{"urls":500},"scope":{"maxDiscoveryDepth":7},"politeness":{"delayMs":400}}"#,
    );
    let request = write(
        dir.path(),
        "request.json",
        r#"{"seedUrl":"https://example.test/","limits":{"urls":200},"scope":{"maxDiscoveryDepth":6}}"#,
    );
    let c = request_of(&["--config", &config]);
    assert_eq!(
        (c.limits.urls, c.scope.max_discovery_depth, c.politeness.delay_ms),
        (500, 7, 400)
    );
    let c = request_of(&["--config", &config, "--request", &request]);
    assert_eq!(
        (c.limits.urls, c.scope.max_discovery_depth, c.politeness.delay_ms),
        (200, 6, 400),
        "the request beats the config, the config beats the defaults"
    );
    let c = request_of(&["--config", &config, "--request", &request, "--depth", "2"]);
    assert_eq!(
        (c.limits.urls, c.scope.max_discovery_depth),
        (200, 2),
        "a flag beats every file"
    );
}

#[test]
fn configuration_files_cannot_name_executable_imports_or_unknown_keys() {
    let dir = tempfile::tempdir().unwrap();
    for (name, text) in [
        ("a.json", r#"{"extractionStrategy":"module.Plugin"}"#),
        ("b.json", r#"{"imports":["os"]}"#),
        ("c.json", r#"{"scope":{"filterClass":"module.Filter"}}"#),
        ("d.toml", "[crawl]\nhooks = [\"module.hook\"]\n"),
        ("e.yaml", "extraction-strategy: module.Plugin\n"),
        ("f.yaml", "import: [os]\n"),
    ] {
        let file = write(dir.path(), name, text);
        let error = request_error(&["--config", &file]);
        assert!(error.contains("unknown"), "{name}: {error}");
        assert!(
            !error.contains("module.Plugin"),
            "{name}: values are not echoed: {error}"
        );
    }
    // deprecated spellings are rejected explicitly, never silently mapped
    let file = write(dir.path(), "g.yaml", "disable-redirects-default: true\n");
    assert!(request_error(&["--config", &file]).contains("unknown"));
}

// --- --print-config -------------------------------------------------------------------------

fn print_config(args: &[&str], env: &[(&str, &str)]) -> (Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .arg("crawl")
        .arg("--print-config")
        .args(args)
        .arg("https://example.test/")
        .env_remove("DEBUG")
        .env_remove("CRAWLX_LOG")
        .envs(env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        serde_json::from_slice(&output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn print_config_shows_the_admitted_request_with_a_digest_that_follows_the_config() {
    let (a, _) = print_config(&["--depth", "4"], &[]);
    let (b, _) = print_config(&["--depth", "4"], &[]);
    let (c, _) = print_config(&["--depth", "5"], &[]);
    let entry = &a[0];
    assert_eq!(entry["seedUrl"], "https://example.test/");
    assert_eq!(entry["request"]["scope"]["maxDiscoveryDepth"], 4);
    let digest = entry["configDigest"].as_str().unwrap();
    assert_eq!(digest.len(), 64);
    assert_eq!(a, b, "the same inputs print the same document");
    assert_ne!(digest, c[0]["configDigest"].as_str().unwrap());
}

#[test]
fn print_config_redacts_secrets_and_keeps_them_out_of_the_digest() {
    let (with_a, _) = print_config(&["-H", "Authorization: Bearer secret-one"], &[]);
    let (with_b, _) = print_config(&["-H", "Authorization: Bearer secret-two"], &[]);
    let text = with_a.to_string();
    assert!(!text.contains("secret-one"), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
    assert_eq!(with_a[0]["configDigest"], with_b[0]["configDigest"]);
}

#[test]
fn print_config_prints_one_entry_per_seed_and_stdout_stays_json_under_debug() {
    let dir = tempfile::tempdir().unwrap();
    let seeds = write(
        dir.path(),
        "seeds.txt",
        "https://one.example.test/\nhttps://two.example.test/\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["crawl", "--print-config", "--debug", "--list", &seeds])
        .env("DEBUG", "true")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let documents: Value = serde_json::from_slice(&output.stdout).unwrap();
    let seeds: Vec<&str> = documents
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["seedUrl"].as_str().unwrap())
        .collect();
    assert_eq!(seeds, ["https://one.example.test/", "https://two.example.test/"]);
}
