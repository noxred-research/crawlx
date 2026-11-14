//! `crawlx crawl` and the deployment lists (RB-10 step 5): the operator blocklist
//! refuses a seed host with `url_denied`, a record whose `authorizedNetworks` lie outside the
//! deployment allowlist is refused, and a list file that does not parse stops the command before
//! anything runs. The lists reach the process through the configuration file or the environment
//! (`getenv` here, so no test touches the process environment).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/site.rs"]
mod site;

use clap::Parser as _;
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const BLOCKLIST_FILE: &str = "CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE";
const ALLOWLIST_FILE: &str = "CRAWLX_EGRESS_DEPLOYMENT_ALLOWLIST_FILE";

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

/// A record covering `origin` and the loopback network, valid now.
fn write_record(dir: &Path, origin: &str) -> PathBuf {
    let record = AuthorizationRecord {
        authorized_networks: vec!["127.0.0.0/8".parse().unwrap()],
        ..sample_record(TenantId::new(), SystemClock.now(), &[origin])
    };
    write(dir, "authz.json", &serde_json::to_string_pretty(&record).unwrap())
}

/// `crawlx crawl ARGS` in-process with `env` as the environment.
async fn crawl(args: &[&str], env: &[(&str, &str)]) -> anyhow::Result<ExitCode> {
    let mut argv = vec!["crawlx", "crawl"];
    argv.extend_from_slice(args);
    let cli = crawlx_cli::Cli::try_parse_from(argv).unwrap();
    let env: BTreeMap<String, String> = env
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let mut out = Vec::new();
    crawlx_cli::execute_with_env(cli, &mut out, &|k| env.get(k).cloned()).await
}

fn local_args<'a>(seed: &'a str, authz: &'a str, out: &'a str) -> Vec<&'a str> {
    vec![
        seed,
        "--mode",
        "static",
        "--authorization-record",
        authz,
        "--allow-private-networks",
        "--seed",
        "20261028",
        "--delay-ms",
        "0",
        "--output",
        out,
    ]
}

#[tokio::test]
async fn a_blocklisted_seed_host_is_refused_with_url_denied() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let out = out.to_str().unwrap();
    let args = ["https://www.takedown.test/", "--mode", "static", "--output", out];

    // through a list file named by the environment: the host and its subdomains
    let file = write(dir.path(), "block.txt", "# takedown 2026-10-28\ntakedown.test\n");
    let err = crawl(&args, &[(BLOCKLIST_FILE, file.to_str().unwrap())])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("request rejected"), "{err}");
    assert!(err.contains("/seedUrl: url_denied"), "{err}");
    assert!(err.contains("operator_blocklist"), "{err}");

    // through crawlx.toml (CRAWLX_CONFIG)
    let config = write(
        dir.path(),
        "crawlx.toml",
        "[egress]\noperator_blocklist = [\"takedown.test\"]\n",
    );
    let err = crawl(&args, &[("CRAWLX_CONFIG", config.to_str().unwrap())])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("/seedUrl: url_denied"), "{err}");

    // through the nested environment form
    let err = crawl(
        &args,
        &[("CRAWLX_EGRESS__OPERATOR_BLOCKLIST", "[\"takedown.test\"]")],
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("/seedUrl: url_denied"), "{err}");
    assert!(!Path::new(out).join("report.json").exists(), "nothing ran");
}

#[tokio::test]
async fn a_blocklisted_address_stops_an_authorized_private_crawl_and_an_unrelated_entry_does_not() {
    let site = site::start().await;
    let dir = tempfile::tempdir().unwrap();
    let authz = write_record(dir.path(), &site.base);
    let seed = format!("{}/", site.base);

    // the record authorizes the loopback network; the operator's blocklist still wins
    let out_blocked = dir.path().join("blocked");
    let blocklist = write(dir.path(), "block.txt", "127.0.0.1\n");
    let args = local_args(&seed, authz.to_str().unwrap(), out_blocked.to_str().unwrap());
    let err = crawl(&args, &[(BLOCKLIST_FILE, blocklist.to_str().unwrap())])
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("/seedUrl: url_denied") && err.contains("operator_blocklist"),
        "{err}"
    );
    assert!(!out_blocked.join("report.json").exists());

    // an entry that names something else leaves the crawl alone
    let out_ok = dir.path().join("ok");
    let unrelated = write(dir.path(), "other.txt", "takedown.test\n203.0.113.0/24\n");
    let args = local_args(&seed, authz.to_str().unwrap(), out_ok.to_str().unwrap());
    let _exit = crawl(&args, &[(BLOCKLIST_FILE, unrelated.to_str().unwrap())])
        .await
        .unwrap();
    assert!(out_ok.join("report.json").exists());
}

#[tokio::test]
async fn a_record_whose_networks_lie_outside_the_deployment_allowlist_is_refused() {
    let site = site::start().await;
    let dir = tempfile::tempdir().unwrap();
    let authz = write_record(dir.path(), &site.base);
    let seed = format!("{}/", site.base);

    // the record's 127.0.0.0/8 is not inside the deployment's 10.0.0.0/8
    let out_refused = dir.path().join("refused");
    let allow = write(dir.path(), "allow.txt", "10.0.0.0/8\n");
    let args = local_args(&seed, authz.to_str().unwrap(), out_refused.to_str().unwrap());
    let err = crawl(&args, &[(ALLOWLIST_FILE, allow.to_str().unwrap())])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("request rejected"), "{err}");
    assert!(err.contains("outside the deployment allowlist"), "{err}");
    assert!(!out_refused.join("report.json").exists());

    // a set but empty allowlist admits no private network at all
    let empty = write(dir.path(), "empty.txt", "# no private network\n");
    let err = crawl(&args, &[(ALLOWLIST_FILE, empty.to_str().unwrap())])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("outside the deployment allowlist"), "{err}");

    // the same record inside the deployment's bound runs (the worker carries the same lists)
    let out_ok = dir.path().join("ok");
    let inside = write(dir.path(), "inside.txt", "127.0.0.0/8\n");
    let args = local_args(&seed, authz.to_str().unwrap(), out_ok.to_str().unwrap());
    let _exit = crawl(&args, &[(ALLOWLIST_FILE, inside.to_str().unwrap())])
        .await
        .unwrap();
    assert!(out_ok.join("report.json").exists());
}

#[tokio::test]
async fn a_list_file_that_does_not_parse_stops_the_crawl_before_anything_runs() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let args = [
        "https://example.test/",
        "--mode",
        "static",
        "--output",
        out.to_str().unwrap(),
    ];

    let malformed = write(dir.path(), "allow.txt", "10.0.0.0/8\nnot-a-network\n");
    let err = crawl(&args, &[(ALLOWLIST_FILE, malformed.to_str().unwrap())])
        .await
        .unwrap_err();
    let err = format!("{err:#}");
    assert!(
        err.contains("egress lists") && err.contains("allow.txt") && err.contains("line 2"),
        "{err}"
    );

    let missing = dir.path().join("missing.txt");
    let err = crawl(&args, &[(BLOCKLIST_FILE, missing.to_str().unwrap())])
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("missing.txt"), "{err:#}");
    assert!(!out.join("report.json").exists());
}
