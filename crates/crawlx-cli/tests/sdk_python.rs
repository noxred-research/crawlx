#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The official drop-in SDKs and CLI against the compatibility API (see
//! `docs/integrations.md`).
//!
//! Each test starts the compatibility API IN-PROCESS on TCP ports with a real worker lease loop, a fixture
//! site, a mock LLM and a metasearch stand-in (`support/sdk_rig.rs`), installs the official package
//! from its registry into a temporary directory and spawns the driver script, which prints one
//! JSON row per SDK method: the Python SDK through `pip install --target` (pinned by
//! `tests/sdk/requirements.txt`, driver `tests/sdk/test_sdk.py`), the Node SDK and the
//! Node CLI through `npm ci` (`tests/sdk/package.json` + lockfile, driver
//! `tests/sdk/test_node.mjs`). Every row is asserted below: passing rows on the returned markdown,
//! links and results, expected failures on the HTTP status the SDK saw.
//!
//! A test prints `skipping: <why>` and returns when its interpreter (`python3`/`pip`,
//! `node`/`npm`) or its registry is unavailable. `CRAWLX_SDK_PYTHONPATH` names an already
//! installed `pip --target` directory and `CRAWLX_SDK_NODE_DIR` an already installed `npm ci`
//! directory (it must hold `test_node.mjs` and `node_modules`); either skips the install.

#[path = "support/sdk_install.rs"]
mod sdk_install;
#[path = "support/sdk_rig.rs"]
mod sdk_rig;

use sdk_install::{install_python_sdk, pinned_python_sdk, repo_root, run_install};
use sdk_rig::SdkRig;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Budget of one driver script (crawls and extract jobs poll until done).
const RUN_TIMEOUT: Duration = Duration::from_secs(300);

type Rows = BTreeMap<String, Value>;

/// Install the pinned Node packages into `dir` together with the driver script (an ES module
/// resolves the Node SDK import next to itself); `Err(reason)` when node, npm or the registry is
/// unavailable.
async fn install_node_packages(dir: &Path) -> Result<(), String> {
    let mut version = Command::new("node");
    version.arg("--version");
    run_install("node --version", version).await?;
    let sdk = repo_root().join("tests/sdk");
    for file in ["package.json", "package-lock.json", "test_node.mjs"] {
        std::fs::copy(sdk.join(file), dir.join(file)).map_err(|e| format!("cannot copy {file}: {e}"))?;
    }
    let mut npm = Command::new("npm");
    npm.args(["ci", "--no-audit", "--no-fund", "--loglevel=error"])
        .current_dir(dir);
    run_install("npm ci of tests/sdk/package-lock.json", npm).await
}

/// Parse the JSON rows a driver printed to stdout.
fn parse_rows(stdout: &str) -> Rows {
    let mut rows = BTreeMap::new();
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("not a JSON row ({e}): {line}"));
        let method = row["method"].as_str().expect("row.method").to_owned();
        assert!(row["ok"].is_boolean() && row["detail"].is_string(), "{row}");
        assert!(
            rows.insert(method.clone(), row).is_none(),
            "duplicate row {method}"
        );
    }
    rows
}

/// Run a driver command to completion and return its rows.
async fn run_driver(label: &str, mut cmd: Command) -> Rows {
    let run = cmd
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .env_remove("FIRECRAWL_API_KEY") // wire-compat: variable the official SDKs read
        .env_remove("FIRECRAWL_API_URL") // wire-compat: variable the official SDKs read
        .output();
    let out = tokio::time::timeout(RUN_TIMEOUT, run)
        .await
        .unwrap_or_else(|_| panic!("the {label} driver ran longer than {RUN_TIMEOUT:?}"))
        .unwrap_or_else(|e| panic!("the {label} driver could not be started: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!("--- {label} driver stdout ---\n{stdout}\n--- {label} driver stderr ---\n{stderr}");
    assert!(out.status.success(), "the {label} driver failed: {}", out.status);
    parse_rows(&stdout)
}

/// The rows of `tests/sdk/test_sdk.py`.
async fn run_python(rig: &SdkRig, python_path: &Path) -> Rows {
    let mut cmd = Command::new("python3");
    cmd.arg(repo_root().join("tests/sdk/test_sdk.py"))
        .env("PYTHONPATH", python_path)
        .env("PYTHONUNBUFFERED", "1")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("CRAWLX_SDK_FACADE_URL", format!("{}/compat", rig.facade_root))
        .env("CRAWLX_SDK_REWRITE_URL", &rig.rewritten_root)
        .env("CRAWLX_SDK_API_KEY", &rig.key)
        .env("CRAWLX_SDK_SITE", rig.site.url(""));
    run_driver("python", cmd).await
}

/// The rows of `tests/sdk/test_node.mjs` run from `node_dir`.
async fn run_node(rig: &SdkRig, node_dir: &Path) -> Rows {
    let home = node_dir.join("home");
    let work = node_dir.join("work");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    let mut cmd = Command::new("node");
    cmd.arg(node_dir.join("test_node.mjs"))
        .current_dir(&work)
        .env("HOME", &home)
        .env("CRAWLX_SDK_FACADE_URL", format!("{}/compat", rig.facade_root))
        .env("CRAWLX_SDK_API_KEY", &rig.key)
        .env("CRAWLX_SDK_SITE", rig.site.url(""))
        .env(
            "CRAWLX_SDK_CLI",
            node_dir.join("node_modules/firecrawl-cli/dist/index.js"), // wire-compat: npm package path of the official CLI
        );
    run_driver("node", cmd).await
}

fn row<'a>(rows: &'a Rows, method: &str) -> &'a Value {
    rows.get(method)
        .unwrap_or_else(|| panic!("the driver printed no row for {method}: {rows:#?}"))
}

/// The row of a method that must have passed.
fn passed<'a>(rows: &'a Rows, method: &str) -> &'a Value {
    let r = row(rows, method);
    assert_eq!(r["ok"], true, "{method} must pass: {r}");
    r
}

/// Assert a row failed with HTTP `status`, SDK exception class `error` and `needle` in its detail.
fn failed_with(rows: &Rows, method: &str, status: u16, error: &str, needle: &str) {
    let r = row(rows, method);
    assert_eq!(r["ok"], false, "{method} must fail: {r}");
    assert_eq!(r["status"], status, "{method}: {r}");
    assert_eq!(r["error"], error, "{method}: {r}");
    let detail = r["detail"].as_str().unwrap();
    assert!(detail.contains(needle), "{method}: {detail}");
}

fn strings(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap_or_else(|| panic!("not an array: {v}"))
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect()
}

/// A crawl or batch row: finished with `total` documents, pages `/`, `/a` and `/b` of the
/// fixture (a crawl limited to three pages from the home page) with their markdown.
fn assert_site_pages(r: &Value, site: &sdk_rig::Site, paths: &[&str]) {
    assert_eq!(r["status"], "completed", "{r}");
    assert_eq!(r["total"], paths.len(), "{r}");
    let urls: Vec<String> = paths.iter().map(|p| site.url(p)).collect();
    let mut got: Vec<&str> = r["markdown"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    got.sort_unstable();
    assert_eq!(got, urls, "{r}");
    for (path, text) in [("/a", "# Page A\n\nText of A."), ("/b", "# Page B\n\nText of B.")] {
        if paths.contains(&path) {
            assert!(
                r["markdown"][site.url(path)].as_str().unwrap().starts_with(text),
                "{path}: {r}"
            );
        }
    }
    if paths.contains(&"/") {
        let home = r["markdown"][site.url("/")].as_str().unwrap();
        assert!(
            home.starts_with("# Fixture Home\n\nWelcome to the fixture site. The answer is forty-two."),
            "{home}"
        );
    }
}

#[tokio::test]
async fn official_python_sdk_runs_against_the_facade() {
    let dir = tempfile::tempdir().unwrap();
    let python_path = match std::env::var_os("CRAWLX_SDK_PYTHONPATH") {
        Some(p) => PathBuf::from(p),
        None => {
            if let Err(why) = install_python_sdk(dir.path()).await {
                println!("skipping: {why}");
                return;
            }
            dir.path().to_path_buf()
        }
    };
    let rig = SdkRig::start().await;
    let rows = run_python(&rig, &python_path).await;
    let site = &rig.site;

    // the pinned package is the one that ran
    let version = pinned_python_sdk();
    assert_eq!(passed(&rows, "sdk_version")["version"], version.as_str());

    // `api_url` with a path: the Python SDK joins the rooted `/v2/scrape` with urljoin, which drops
    // the `/compat` prefix, so the request lands on `/v2/scrape` of the host: 404
    failed_with(
        &rows,
        "scrape@prefix_base_url",
        404,
        "FirecrawlError", // wire-compat: SDK error class name
        "route not found",
    );

    // scrape through the `/v2/*` rewrite
    let r = passed(&rows, "scrape");
    assert_eq!(
        r["markdown"],
        format!(
            "# Fixture Home\n\nWelcome to the fixture site. The answer is forty-two.\n\n[Page A]({}) [Page B]({})",
            site.url("/a"),
            site.url("/b")
        )
    );
    assert_eq!(strings(&r["links"]), [site.url("/a"), site.url("/b")]);
    assert!(r["html"].as_str().unwrap().contains("<h1>Fixture Home</h1>"));
    assert_eq!(r["title"], "Fixture Home");
    assert_eq!(r["description"], "The fixture home page");
    assert_eq!(r["source_url"], site.url("/"));
    assert_eq!(r["status_code"], 200);

    // a json format: the mock LLM answers the schema the SDK sent
    let r = passed(&rows, "scrape_json");
    assert_eq!(r["json"], sdk_rig::extract_answer());
    assert!(
        r["markdown"].as_str().unwrap().starts_with("# Fixture Home"),
        "{r}"
    );

    // crawl: start, poll, wait
    let r = passed(&rows, "start_crawl+get_crawl_status");
    assert_site_pages(r, site, &["/", "/a", "/b"]);
    assert_eq!(r["completed"], 3);
    assert_eq!(r["credits_used"], 3);
    assert_eq!(r["statuses"].as_array().unwrap().last().unwrap(), "completed");
    assert!(
        strings(&r["statuses"])
            .iter()
            .all(|s| *s == "scraping" || *s == "completed"),
        "{r}"
    );
    let id = r["id"].as_str().unwrap();
    assert!(
        r["url"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/compat/v2/crawl/{id}")),
        "the start response names the crawl status URL: {r}"
    );
    assert_site_pages(passed(&rows, "crawl"), site, &["/", "/a", "/b"]);
    let r = passed(&rows, "get_crawl_errors");
    assert_eq!(r["errors"], json!([]));
    assert_eq!(r["robots_blocked"], json!([]));
    assert_eq!(
        passed(&rows, "cancel_crawl")["cancelled"],
        false,
        "a finished crawl answers 409, which the SDK reads as `not cancelled`"
    );
    assert_eq!(passed(&rows, "get_active_crawls")["count"], 0);

    // map
    assert_eq!(
        strings(&passed(&rows, "map")["urls"]),
        [site.url("/"), site.url("/a"), site.url("/b")]
    );

    // search through the metasearch stand-in; with scrapeOptions the hits carry markdown
    assert_eq!(
        passed(&rows, "search")["web"],
        json!([
            {"url": site.url("/a"), "title": "Page A", "description": "the first hit"},
            {"url": site.url("/b"), "title": "Page B", "description": "the second hit"},
        ])
    );
    let r = passed(&rows, "search+scrape_options");
    let hits = r["web"].as_array().unwrap();
    assert_eq!(hits.len(), 2, "{r}");
    assert_eq!(hits[0]["url"], site.url("/a"));
    assert!(hits[0]["markdown"].as_str().unwrap().starts_with("# Page A"));
    assert_eq!(hits[1]["url"], site.url("/b"));
    assert!(hits[1]["markdown"].as_str().unwrap().starts_with("# Page B"));
    let queries = rig.metasearch.received_requests().await.unwrap();
    assert!(
        !queries.is_empty()
            && queries
                .iter()
                .all(|q| q.url.query_pairs().any(|(k, v)| k == "q" && v == "fixture")),
        "the metasearch stand-in saw `q=fixture`: {queries:?}"
    );

    // extract: the mock LLM answers the SDK's schema, with and without polling by hand
    let r = passed(&rows, "extract");
    assert_eq!(r["status"], "completed", "{r}");
    assert_eq!(r["data"], sdk_rig::extract_answer());
    assert!(r["tokens_used"].as_u64().unwrap() > 0, "{r}");
    let r = passed(&rows, "start_extract+get_extract_status");
    assert_eq!(r["status"], "completed", "{r}");
    assert_eq!(r["data"], sdk_rig::extract_answer());
    let schemas: Vec<Value> = rig.llm.calls().into_iter().filter_map(|c| c.schema).collect();
    assert!(
        schemas
            .iter()
            .any(|s| s["properties"]["answer"]["type"] == "integer"),
        "the mock LLM received the SDK's schema: {schemas:?}"
    );

    // batch scrape
    assert_site_pages(passed(&rows, "batch_scrape"), site, &["/a", "/b"]);
    assert_eq!(passed(&rows, "batch_scrape")["completed"], 2);

    // team usage (crawlx has no balance: -1 is the compatibility API's `unlimited`)
    assert_eq!(passed(&rows, "get_credit_usage")["remaining_credits"], -1);
    assert_eq!(passed(&rows, "get_token_usage")["remaining_tokens"], -1);

    // the document-loader integration (`integration="..."` rides in every request body)
    let docs_of = |method: &str| -> Vec<Value> { passed(&rows, method)["docs"].as_array().unwrap().clone() };
    let d = docs_of("loader.scrape");
    assert_eq!(d.len(), 1);
    assert!(d[0]["page_content"]
        .as_str()
        .unwrap()
        .starts_with("# Fixture Home\n\nWelcome to the fixture site. The answer is forty-two."));
    assert_eq!(d[0]["metadata"]["title"], "Fixture Home");
    assert_eq!(d[0]["metadata"]["source_url"], site.url("/"));
    assert_eq!(d[0]["metadata"]["status_code"], 200);
    let d = docs_of("loader.crawl");
    let mut urls: Vec<&str> = d
        .iter()
        .map(|x| x["metadata"]["source_url"].as_str().unwrap())
        .collect();
    urls.sort_unstable();
    assert_eq!(urls, [site.url("/"), site.url("/a"), site.url("/b")]);
    assert!(d.iter().any(|x| x["page_content"]
        .as_str()
        .unwrap()
        .starts_with("# Page B\n\nText of B.")));
    let d = docs_of("loader.map");
    let urls: Vec<&str> = d.iter().map(|x| x["page_content"].as_str().unwrap()).collect();
    assert_eq!(urls, [site.url("/"), site.url("/a"), site.url("/b")]);
    assert_eq!(d[0]["metadata"]["title"], "Fixture Home");
    assert_eq!(
        docs_of("loader.search"),
        [
            json!({"page_content": "the first hit", "metadata": {"url": site.url("/a"), "title": "Page A", "type": "web"}}),
            json!({"page_content": "the second hit", "metadata": {"url": site.url("/b"), "title": "Page B", "type": "web"}}),
        ]
    );
    let d = docs_of("loader.extract");
    assert_eq!(d.len(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(d[0]["page_content"].as_str().unwrap()).unwrap(),
        sdk_rig::extract_answer()
    );

    // the v1 names: the v1 client alias is the v2 client; `.v1` calls `{api_url}/v1/...`, which the
    // facade does not serve by design
    passed(&rows, "v1_client_alias");
    for method in [
        "v1.scrape_url",
        "v1.crawl_url",
        "v1.check_crawl_status",
        "v1.map_url",
    ] {
        failed_with(&rows, method, 404, "HTTPError", "route not found");
    }

    // nothing else ran: every row of the driver is asserted above
    assert_eq!(rows.len(), 27, "{:?}", rows.keys().collect::<Vec<_>>());
    rig.stop().await;
}

#[tokio::test]
async fn official_node_sdk_and_cli_run_against_the_facade() {
    let dir = tempfile::tempdir().unwrap();
    let node_dir = match std::env::var_os("CRAWLX_SDK_NODE_DIR") {
        Some(p) => PathBuf::from(p),
        None => {
            if let Err(why) = install_node_packages(dir.path()).await {
                println!("skipping: {why}");
                return;
            }
            dir.path().to_path_buf()
        }
    };
    let rig = SdkRig::start().await;
    let rows = run_node(&rig, &node_dir).await;
    let site = &rig.site;

    // the Node SDK builds `{apiUrl}/v2/...` by concatenation: the facade prefix survives
    let r = passed(&rows, "node.scrape");
    assert!(r["markdown"]
        .as_str()
        .unwrap()
        .starts_with("# Fixture Home\n\nWelcome to the fixture site. The answer is forty-two."));
    assert_eq!(strings(&r["links"]), [site.url("/a"), site.url("/b")]);
    assert_eq!(r["title"], "Fixture Home");
    assert_eq!(r["source_url"], site.url("/"));
    assert_site_pages(
        passed(&rows, "node.startCrawl+getCrawlStatus"),
        site,
        &["/", "/a", "/b"],
    );
    assert_eq!(passed(&rows, "node.startCrawl+getCrawlStatus")["completed"], 3);
    assert_site_pages(passed(&rows, "node.crawl"), site, &["/", "/a", "/b"]);
    assert_eq!(
        strings(&passed(&rows, "node.map")["urls"]),
        [site.url("/"), site.url("/a"), site.url("/b")]
    );
    assert_eq!(
        passed(&rows, "node.search")["web"],
        json!([
            {"url": site.url("/a"), "title": "Page A"},
            {"url": site.url("/b"), "title": "Page B"},
        ])
    );
    let r = passed(&rows, "node.extract");
    assert_eq!(r["status"], "completed", "{r}");
    assert_eq!(r["data"], sdk_rig::extract_answer());
    assert_site_pages(passed(&rows, "node.batchScrape"), site, &["/a", "/b"]);

    // the official CLI (what the agent skills of its `init` command tell agents to run)
    let cli_json = |method: &str| -> Value {
        let r = passed(&rows, method);
        serde_json::from_str(r["stdout"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{method} printed no JSON ({e}): {r}"))
    };
    let v = cli_json("cli.scrape");
    assert!(v["markdown"]
        .as_str()
        .unwrap()
        .starts_with("# Fixture Home\n\nWelcome to the fixture site."));
    assert_eq!(strings(&v["links"]), [site.url("/a"), site.url("/b")]);
    assert_eq!(v["metadata"]["sourceURL"], site.url("/"));
    assert_eq!(v["metadata"]["statusCode"], 200);
    let v = cli_json("cli.map");
    assert_eq!(v["success"], true);
    let urls: Vec<&str> = v["data"]["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["url"].as_str().unwrap())
        .collect();
    assert_eq!(urls, [site.url("/"), site.url("/a"), site.url("/b")]);
    let v = cli_json("cli.search");
    assert_eq!(v["success"], true);
    let urls: Vec<&str> = v["data"]["web"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["url"].as_str().unwrap())
        .collect();
    assert_eq!(urls, [site.url("/a"), site.url("/b")]);
    assert!(
        v["warning"].as_str().unwrap().contains("alexandria"),
        "the CLI also asks for the hosted `alexandria` source; the facade ignores it with a warning: {v}"
    );
    let v = cli_json("cli.crawl");
    assert_eq!(v["status"], "completed");
    assert_eq!((v["completed"].as_u64(), v["total"].as_u64()), (Some(3), Some(3)));
    let mut pages: Vec<&str> = v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["metadata"]["sourceURL"].as_str().unwrap())
        .collect();
    pages.sort_unstable();
    assert_eq!(pages, [site.url("/"), site.url("/a"), site.url("/b")]);
    assert_eq!(cli_json("cli.credit-usage")["data"]["remainingCredits"], -1);

    assert_eq!(rows.len(), 12, "{:?}", rows.keys().collect::<Vec<_>>());
    rig.stop().await;
}

/// How `crawlx serve` is told to accept `fc-` keys.
#[derive(Clone, Copy)]
enum FcKeys {
    /// `--compat-keys`.
    Flag,
    /// `CRAWLX_COMPAT_KEYS=1`.
    Env,
    /// Neither.
    Off,
}

/// Spawn `crawlx serve --api-key acme=<key>` on `port` over the in-memory store.
fn spawn_serve(dir: &Path, port: u16, key: &str, fc_keys: FcKeys) -> tokio::process::Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    cmd.arg("serve")
        .args(["--bind", &format!("127.0.0.1:{port}")])
        .arg("--artifacts-dir")
        .arg(dir.join("artifacts"))
        .args(["--rate-limit-per-minute", "0"])
        .args(["--api-key", &format!("acme={key}")]);
    match fc_keys {
        FcKeys::Flag => {
            cmd.arg("--compat-keys");
        }
        FcKeys::Env => {
            cmd.env("CRAWLX_COMPAT_KEYS", "1");
        }
        FcKeys::Off => {
            cmd.env_remove("CRAWLX_COMPAT_KEYS");
        }
    }
    cmd.current_dir(dir)
        .env_remove("CRAWLX_DATABASE_URL")
        .env_remove("CRAWLX_DATABASE_URL_FILE")
        // the CLI rejects CRAWLX_* variables it does not know: these two belong to this test
        .env_remove("CRAWLX_SDK_PYTHONPATH")
        .env_remove("CRAWLX_SDK_NODE_DIR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("crawlx serve starts")
}

/// `GET path` with `Authorization: Bearer key`; the HTTP status.
#[allow(
    clippy::disallowed_types,
    reason = "test client speaks HTTP to an owned local fixture server"
)]
async fn get_status(client: &reqwest::Client, port: u16, path: &str, key: &str) -> u16 {
    client
        .get(format!("http://127.0.0.1:{port}{path}"))
        .bearer_auth(key)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// A loopback port nobody listens on (bound and released: `crawlx serve` takes an address).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `crawlx serve --api-key acme=fc-...` with `--compat-keys` (or the environment variable)
/// serves the facade to that `fc-` key (and never a native `/v1` route); without either, the
/// bootstrap key is refused at startup (docs/integrations.md, "Enable `fc-` keys").
#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "test client speaks HTTP to an owned local fixture server"
)]
async fn serve_bootstraps_fc_keys_with_the_flag_or_the_environment() {
    let key = format!("fc-{}", "0123456789abcdef".repeat(2));
    for fc_keys in [FcKeys::Flag, FcKeys::Env] {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let mut child = spawn_serve(dir.path(), port, &key, fc_keys);
        let client = reqwest::Client::new();
        let mut ready = false;
        for _ in 0..200 {
            if let Some(status) = child.try_wait().unwrap() {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    tokio::io::AsyncReadExt::read_to_string(&mut pipe, &mut stderr)
                        .await
                        .unwrap();
                }
                panic!("crawlx serve exited early: {status}; stderr: {stderr}");
            }
            if client
                .get(format!("http://127.0.0.1:{port}/v0/health/liveness"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(ready, "crawlx serve did not come up on port {port}");
        let usage = "/compat/v2/team/credit-usage";
        assert_eq!(get_status(&client, port, usage, &key).await, 200);
        assert_eq!(
            get_status(&client, port, usage, &format!("fc-{}", "f".repeat(32))).await,
            401,
            "an unknown fc- key"
        );
        assert_eq!(
            get_status(
                &client,
                port,
                "/v1/crawls/00000000-0000-0000-0000-000000000000",
                &key
            )
            .await,
            401,
            "an fc- key never opens a native /v1 route"
        );
        child.kill().await.unwrap();
    }

    // without the switch the bootstrap key is not a valid key: the server refuses to start
    let dir = tempfile::tempdir().unwrap();
    let child = spawn_serve(dir.path(), free_port(), &key, FcKeys::Off);
    let out = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("crawlx serve exits")
        .unwrap();
    assert!(!out.status.success(), "{:?}", out.status);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("must look like cx_live_"), "stderr: {stderr}");
}
