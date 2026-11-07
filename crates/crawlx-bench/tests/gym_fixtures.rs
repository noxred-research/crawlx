//! The fixture catalog: every row has an embedded fixture, the ground truth matches the
//! row's numbers, the stateful backends behave over HTTP, and (with Chromium) a representative
//! subset is exercised end to end: timer reveals (G10), WebSocket reveals (G09), one button
//! with many behaviors (G22) and storage-gated roles (G30).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::gym::fixtures::{self, backend, catalog_row, CATALOG_ROWS, NAMED_FIXTURES};
use crawlx_bench::gym::manifest::{ControlRisk, ExpectedClass, FixtureManifest, Mechanism};
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::scorecard::{RunRows, Scorecard};
use crawlx_bench::urlplane;
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, rows_from_report, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::browser::{BrowserBackend, BrowserContext, ContextConfig};
use crawlx_core::config::{CrawlMode, LaunchProfile, SafetyProfile};
use crawlx_core::ids::SessionId;
use crawlx_core::observation::{ObservationSpec, QuiescencePolicy};
use crawlx_elements::{Candidate, CandidateDiscovery, DiscoveryConfig};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use crawlx_worker::{run_local_with, LocalRun};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

async fn gym() -> GymHandle {
    GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap()
}

fn have_chromium() -> bool {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return false;
    }
    true
}

async fn launch() -> Option<ChromiumBackend> {
    let exe = find_executable()?;
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe;
    cfg.launch_profile = LaunchProfile::Standard;
    cfg.allow_unpinned = true;
    match ChromiumBackend::launch(cfg.clone()).await {
        Ok(b) => Some(b),
        Err(first) => {
            eprintln!(
                "warning: launch failed ({first}); retrying once with --no-sandbox (CI containers only)"
            );
            cfg.unsafe_no_sandbox_for_ci = true;
            Some(ChromiumBackend::launch(cfg).await.expect("chromium must launch"))
        }
    }
}

fn canonical(url: &str) -> crawlx_core::url::CanonicalUrl {
    Canonicalizer::canonicalize_url(&url::Url::parse(url).unwrap(), &CanonicalizeOptions::default()).unwrap()
}

/// Poll `cond` every 50 ms for up to `budget`.
async fn eventually(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---- catalog shape --------------------------------------------------------------------------

#[test]
fn every_catalog_row_and_named_fixture_is_embedded() {
    let mut rows: Vec<&str> = CATALOG_ROWS.iter().map(|(r, _)| *r).collect();
    rows.dedup();
    assert_eq!(rows.len(), 32);
    for n in 1..=32 {
        let row = format!("G{n:02}");
        let id = catalog_row(&row).unwrap_or_else(|| panic!("row {row} has no fixture"));
        let def = fixtures::find(id).unwrap_or_else(|| panic!("{row} -> {id} is not embedded"));
        assert!(def.file("").is_some(), "{id} has no index.html");
        let m = FixtureManifest::embedded(id).unwrap();
        assert_eq!(m.id, id);
    }
    for (name, id) in NAMED_FIXTURES {
        assert!(
            fixtures::find(id).is_some(),
            "named fixture {name} -> {id} missing"
        );
    }
    assert!(catalog_row("g99").is_none());
}

#[test]
fn ground_truth_matches_the_catalog_numbers() {
    let m = |id: &str| FixtureManifest::embedded(id).unwrap();

    // G02 aria-widgets: 60 targets with role/name, every one of them named.
    let g02 = m("g02");
    assert_eq!(g02.controls.len(), 60);
    assert!(g02.controls.iter().all(|c| c.name.is_some()));
    let roles: BTreeSet<&str> = g02.controls.iter().map(|c| c.role.as_str()).collect();
    for r in ["tab", "menuitem", "combobox", "option", "treeitem", "button"] {
        assert!(roles.contains(r), "{roles:?}");
    }

    // G03 div-buttons: 30 cursor-only targets.
    let db = m("div-buttons");
    assert_eq!(db.controls.len(), 30);
    assert!(db.controls.iter().all(|c| c.mechanism == Mechanism::Cursor));

    // G04 shadow-dom: 24 targets, 8 in closed roots (oracle gap for stock Playwright).
    let g04 = m("g04");
    assert_eq!(g04.controls.len(), 24);
    let closed = g04
        .controls
        .iter()
        .filter(|c| c.oracle.get("playwright") == Some(&ExpectedClass::OracleGap))
        .count();
    assert_eq!(closed, 8);
    assert_eq!(
        g04.controls.iter().filter(|c| c.id.starts_with("slot-")).count(),
        4
    );

    // G05 nested-iframes: 36 targets across 7 frames, depth 3, identical labels across frames.
    let g05 = m("g05");
    assert_eq!(g05.controls.len(), 36);
    let frames: BTreeSet<&str> = g05.controls.iter().map(|c| c.frame.as_str()).collect();
    assert_eq!(frames.len(), 7, "{frames:?}");
    assert!(frames.contains("main/f1/f1a/f1b"));
    let saves = g05
        .controls
        .iter()
        .filter(|c| c.name.as_deref() == Some("Save"))
        .count();
    assert_eq!(saves, 7);
    assert_eq!(g05.expected.collision_rate_max, Some(0.0));

    // G07 infinite-feed: first page labelled as one template family, later pages masked.
    let g07 = m("g07");
    let likes: BTreeSet<_> = g07
        .controls
        .iter()
        .filter(|c| c.id.starts_with("like-"))
        .map(|c| c.logical_id.clone())
        .collect();
    assert_eq!(likes.len(), 1);
    assert!(g07
        .expected
        .volatile_regions
        .iter()
        .any(|v| v.contains("nth-child(n+11)")));

    // G08 clock-live-region: volatile regions labelled, aria-live among them.
    let g08 = m("g08");
    assert!(g08.expected.volatile_regions.iter().any(|v| v == "[aria-live]"));
    assert_eq!(g08.expected.split_rate_max, Some(0.01));

    // G09 ws-push-reveals: 2 true edges, 6 spurious, pushes scheduled by the server.
    let g09 = m("g09");
    let (truth, spurious): (Vec<_>, Vec<_>) = g09
        .expected
        .enablement
        .iter()
        .partition(|e| e.kind != crawlx_bench::gym::manifest::EnablementKind::Spurious);
    assert_eq!((truth.len(), spurious.len()), (2, 6));
    assert_eq!(backend::ws_pushes("g09").len(), 6);
    assert_eq!(
        g09.controls
            .iter()
            .filter(|c| c.reveal_after_ms.is_some())
            .count(),
        6
    );

    // G10 timer-reveals (g19): 5 timer-revealed controls at 1 s, 3 s and 7 s, 0 causal edges.
    let g19 = m("g19");
    let timers: Vec<u64> = g19.controls.iter().filter_map(|c| c.reveal_after_ms).collect();
    assert_eq!(timers.len(), 5);
    let distinct: BTreeSet<u64> = timers.into_iter().collect();
    assert_eq!(distinct, BTreeSet::from([1000, 3000, 7000]));
    assert!(g19
        .expected
        .enablement
        .iter()
        .all(|e| e.kind == crawlx_bench::gym::manifest::EnablementKind::Spurious));

    // G11 conjunctive (g21): one conjunctive edge with two preconditions.
    let g21 = m("g21");
    let conj: Vec<_> = g21
        .expected
        .enablement
        .iter()
        .filter(|e| e.kind == crawlx_bench::gym::manifest::EnablementKind::Conjunctive)
        .collect();
    assert_eq!(conj.len(), 1);
    assert_eq!(conj[0].requires.len(), 2);

    // G13 hover-menus: 18 targets behind 6 hover triggers.
    let g13 = m("g13");
    assert_eq!(g13.controls.iter().filter(|c| c.requires.is_empty()).count(), 6);
    assert_eq!(g13.controls.iter().filter(|c| !c.requires.is_empty()).count(), 18);

    // G14 drag-drop: 3 drag behaviors.
    let g14 = m("g14");
    let behaviors: BTreeSet<&str> = g14
        .expected
        .action_contexts
        .iter()
        .map(|a| a.backend_effect.as_str())
        .collect();
    assert_eq!(behaviors.len(), 3, "{behaviors:?}");
    assert!(g14
        .expected
        .action_contexts
        .iter()
        .all(|a| a.action_kind == "drag"));

    // G15 sliders: 3 range controls x 4 partitions = 12 action contexts.
    let g15 = m("g15");
    assert_eq!(g15.controls.len(), 3);
    assert_eq!(g15.expected.action_contexts.len(), 12);
    let parts: BTreeSet<&str> = g15
        .expected
        .action_contexts
        .iter()
        .map(|a| a.input_class.as_str())
        .collect();
    assert_eq!(parts, BTreeSet::from(["min", "max", "typical", "out_of_range"]));

    // G16 file-upload: 4 upload contexts, fixture-only input classes.
    let g16 = m("g16");
    assert_eq!(g16.expected.action_contexts.len(), 4);
    let classes: BTreeSet<&str> = g16
        .expected
        .action_contexts
        .iter()
        .map(|a| a.input_class.as_str())
        .collect();
    assert_eq!(
        classes,
        BTreeSet::from(["fixture_small_png", "fixture_pdf", "oversized"])
    );
    assert_eq!(g16.expected.unauthorized_actions, Some(0));

    // G17 multi-tab-oauth: one OAuth flow whose authorize step is a credential change.
    let g17 = m("g17");
    assert!(g17.control("idp-authorize").unwrap().risk == ControlRisk::CredentialChange);
    assert!(g17.control("profile").unwrap().requires == ["oauth-start"]);

    // G18 auth-expiry: two expiry paths, credentials never in the manifest.
    let g18 = m("g18");
    let effects: BTreeSet<&str> = g18
        .expected
        .action_contexts
        .iter()
        .map(|a| a.backend_effect.as_str())
        .collect();
    assert_eq!(
        effects,
        BTreeSet::from(["session:silent_refresh", "session:hard_logout"])
    );
    assert!(!serde_json::to_string(&g18).unwrap().contains(backend::PASSWORD));

    // G20 cross-user-workflows: 48-cell principal x action x resource matrix.
    let g20 = m("g20");
    assert_eq!(g20.expected.action_contexts.len(), 48);
    let principals: BTreeSet<&str> = g20
        .expected
        .action_contexts
        .iter()
        .map(|a| a.principal.as_str())
        .collect();
    assert_eq!(principals, BTreeSet::from(["alice", "bob", "admin"]));
    let contexts: BTreeSet<&str> = g20
        .expected
        .action_contexts
        .iter()
        .map(|a| a.resource_context.as_str())
        .collect();
    assert_eq!(
        contexts,
        BTreeSet::from(["own", "shared", "other_user_same_role", "admin"])
    );

    // G22 one-control-many-behaviors: one Delete element, 12 contexts.
    let g22 = m("g22");
    assert_eq!(g22.expected.action_contexts.len(), 12);
    assert!(g22.expected.action_contexts.iter().all(|a| a.element == "delete"));
    let keys: BTreeSet<(String, Option<String>, String, String)> = g22
        .expected
        .action_contexts
        .iter()
        .map(|a| {
            (
                a.principal.clone(),
                a.resource.clone(),
                a.resource_context.clone(),
                a.input_class.clone(),
            )
        })
        .collect();
    assert_eq!(keys.len(), 12);

    // G23 canvas-surface: 10 canvas controls reported as unsupported, never clicked blindly.
    let g23 = m("g23");
    let unsupported = g23
        .controls
        .iter()
        .filter(|c| c.mechanism == Mechanism::Unsupported)
        .count();
    assert_eq!(unsupported, 10);
    assert!(g23
        .controls
        .iter()
        .filter(|c| c.mechanism == Mechanism::Unsupported)
        .all(|c| {
            c.expected == ExpectedClass::NotActionable && c.oracle.get("*") == Some(&ExpectedClass::OracleGap)
        }));

    // G24 forms-validation: 8 forms, 6 input classes, external-communication form forbidden.
    let g24 = m("g24");
    let forms: BTreeSet<&str> = g24.expected.operations.iter().map(String::as_str).collect();
    assert_eq!(forms.len(), 8);
    let classes: BTreeSet<&str> = g24
        .expected
        .action_contexts
        .iter()
        .map(|a| a.input_class.as_str())
        .collect();
    assert!(classes.is_superset(&BTreeSet::from([
        "email", "phone", "date", "number", "text", "resource"
    ])));
    assert_eq!(
        g24.control("notify-submit").unwrap().risk,
        ControlRisk::ExternalCommunication
    );
    assert!(g24
        .expected
        .forbidden_ops
        .iter()
        .any(|f| f.path_prefix.ends_with("/notify")));

    // G25 stale-rerender: destructive remove buttons forbidden under read_only.
    let sr = m("stale-rerender");
    assert_eq!(
        sr.controls
            .iter()
            .filter(|c| c.risk == ControlRisk::Destructive)
            .count(),
        8
    );

    // G28 service-worker-background: labelled request origins incl. third party and worker.
    let g28 = m("g28");
    let origins: BTreeSet<&str> = g28
        .expected
        .traffic_origins
        .iter()
        .map(|t| t.origin.as_str())
        .collect();
    assert_eq!(
        origins,
        BTreeSet::from(["page", "service_worker", "poll", "beacon", "third_party"])
    );
    assert!(
        g28.expected
            .traffic_origins
            .iter()
            .filter(|t| t.third_party)
            .count()
            >= 2
    );
    assert!(g28
        .expected
        .traffic_origins
        .iter()
        .filter(|t| t.origin == "service_worker")
        .all(|t| t.caused_by.is_none()));

    // G30 auth-and-session-state: role x menu truth table over two storages.
    let g30 = m("g30");
    let by_role: BTreeMap<&str, &Vec<String>> = g30
        .expected
        .role_controls
        .iter()
        .map(|r| (r.role.as_str(), &r.controls))
        .collect();
    assert_eq!(by_role.len(), 4);
    assert!(by_role["admin"].len() > by_role["member"].len());
    assert!(g30
        .expected
        .role_controls
        .iter()
        .any(|r| r.storage == "indexed_db"));
    assert!(g30
        .expected
        .role_controls
        .iter()
        .any(|r| r.storage == "local_storage"));

    // hybrid-mix: URL-addressable subset is a strict subset of the reachable pages.
    let hm = m("hybrid-mix");
    assert_eq!(hm.expected.url_addressable_pages.len(), 7);
    assert!(hm.control("receipt-home").unwrap().requires == ["billing-receipt"]);

    // async-late: late request families labelled, each caused by a named control or by nothing.
    let al = m("async-late");
    assert!(al.expected.traffic_origins.iter().filter(|t| t.late).count() >= 3);
}

// ---- stateful backends over HTTP ------------------------------------------------------------

fn cookie_jar(resp: &reqwest::Response, jar: &mut BTreeMap<String, String>) {
    for v in resp.headers().get_all(reqwest::header::SET_COOKIE) {
        let Some((kv, attrs)) = v.to_str().unwrap().split_once(';') else {
            continue;
        };
        let (k, val) = kv.split_once('=').unwrap();
        if attrs.contains("Max-Age=0") || val.is_empty() {
            jar.remove(k);
        } else {
            jar.insert(k.to_owned(), val.to_owned());
        }
    }
}

fn cookie_header(jar: &BTreeMap<String, String>) -> String {
    jar.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

#[tokio::test]
async fn g18_session_expires_and_recovers_through_the_server() {
    let gym = gym().await;
    let http = reqwest::Client::new();
    let mut jar = BTreeMap::new();
    let r = http
        .post(format!("{}/g18/api/login", gym.base_url))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("user=member&password={}&mode=silent", backend::PASSWORD))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    cookie_jar(&r, &mut jar);
    assert!(
        jar.contains_key("g18_session") && jar.contains_key("g18_refresh"),
        "{jar:?}"
    );
    for _ in 0..backend::G18_SESSION_USES {
        let r = http
            .get(format!("{}/g18/api/me", gym.base_url))
            .header("cookie", cookie_header(&jar))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }
    let r = http
        .get(format!("{}/g18/api/me", gym.base_url))
        .header("cookie", cookie_header(&jar))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "expired mid-crawl");
    cookie_jar(&r, &mut jar);
    let r = http
        .post(format!("{}/g18/api/refresh", gym.base_url))
        .header("cookie", cookie_header(&jar))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    cookie_jar(&r, &mut jar);
    let r = http
        .get(format!("{}/g18/api/me", gym.base_url))
        .header("cookie", cookie_header(&jar))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "silent refresh restored the session");
    let effects: Vec<String> = gym.ledger().effects("g18").into_iter().map(|e| e.1).collect();
    assert!(effects.contains(&"session:expired".to_owned()), "{effects:?}");
    assert!(
        effects.contains(&"session:silent_refresh".to_owned()),
        "{effects:?}"
    );
    // the ledger never stores the password
    let json = gym.ledger().to_json().to_string();
    assert!(!json.contains(backend::PASSWORD));
    // reset restores the baseline: the session is gone
    gym.reset(1);
    let r = http
        .get(format!("{}/g18/api/me", gym.base_url))
        .header("cookie", cookie_header(&jar))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    gym.shutdown().await;
}

#[tokio::test]
async fn g20_shared_workspace_round_trip_is_attributable_per_principal() {
    let gym = gym().await;
    let http = reqwest::Client::new();
    let login = |user: &str| {
        let http = http.clone();
        let url = format!("{}/g20/api/login", gym.base_url);
        let body = format!("user={user}&password={}", backend::PASSWORD);
        async move {
            let r = http
                .post(url)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await
                .unwrap();
            let mut jar = BTreeMap::new();
            cookie_jar(&r, &mut jar);
            cookie_header(&jar)
        }
    };
    // round 1: alice creates a shared document
    let alice = login("alice").await;
    let r = http
        .post(format!("{}/g20/api/invoices", gym.base_url))
        .header("cookie", &alice)
        .json(&serde_json::json!({ "title": "Q4 invoice", "visibility": "shared" }))
        .send()
        .await
        .unwrap();
    let id = r.json::<serde_json::Value>().await.unwrap()["id"]
        .as_u64()
        .unwrap();
    // round 1: bob (same role) sees it and acts on it
    let bob = login("bob").await;
    let r = http
        .get(format!("{}/g20/api/invoices", gym.base_url))
        .header("cookie", &bob)
        .send()
        .await
        .unwrap();
    let listed = r.json::<serde_json::Value>().await.unwrap();
    assert!(listed["invoices"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["id"] == id));
    let r = http
        .post(format!("{}/g20/api/invoices/{id}/comments", gym.base_url))
        .header("cookie", &bob)
        .json(&serde_json::json!({ "text": "approved" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = http
        .delete(format!("{}/g20/api/invoices/{id}", gym.base_url))
        .header("cookie", &bob)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "shared never allows delete by another member");
    // round 2: alice sees bob's response
    let r = http
        .get(format!("{}/g20/api/invoices/{id}", gym.base_url))
        .header("cookie", &alice)
        .send()
        .await
        .unwrap();
    let v = r.json::<serde_json::Value>().await.unwrap();
    assert_eq!(v["invoice"]["comments"][0]["by"], "bob");
    // every cross-principal effect is attributable: principal and context are server-inferred
    let effects = gym.ledger().effects("g20");
    let bob_rows: Vec<_> = effects.iter().filter(|e| e.0 == "bob").collect();
    assert!(
        bob_rows.iter().any(|e| e.1 == "comment:ok" && e.3 == "shared"),
        "{bob_rows:?}"
    );
    assert!(
        bob_rows.iter().any(|e| e.1 == "delete:denied" && e.3 == "shared"),
        "{bob_rows:?}"
    );
    assert!(effects
        .iter()
        .any(|e| e.0 == "alice" && e.1 == "view:ok" && e.3 == "own"));
    gym.shutdown().await;
}

#[tokio::test]
async fn g16_multipart_uploads_are_classified_by_the_server() {
    let gym = gym().await;
    let http = reqwest::Client::new();
    let body = |name: &str, bytes: usize| {
        format!(
            "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n{}\r\n--B--\r\n",
            "x".repeat(bytes)
        )
    };
    let post = |ctx: &str, b: String| {
        http.post(format!("{}/g16/api/upload/{ctx}", gym.base_url))
            .header("content-type", "multipart/form-data; boundary=B")
            .body(b)
            .send()
    };
    assert_eq!(
        post("image", body("fixture_small.png", 120))
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        post("image", body("fixture.pdf", 120)).await.unwrap().status(),
        413
    );
    assert_eq!(post("pdf", body("fixture.pdf", 900)).await.unwrap().status(), 200);
    assert_eq!(
        post(
            "oversize",
            body("oversized.bin", backend::G16_MAX_UPLOAD_BYTES + 1)
        )
        .await
        .unwrap()
        .status(),
        413
    );
    let effects: BTreeSet<String> = gym.ledger().effects("g16").into_iter().map(|e| e.1).collect();
    assert_eq!(
        effects,
        BTreeSet::from([
            "upload:image:accepted".to_owned(),
            "upload:image:rejected_type".to_owned(),
            "upload:pdf:accepted".to_owned(),
            "upload:oversize:rejected_oversize".to_owned(),
        ])
    );
    gym.shutdown().await;
}

#[tokio::test]
async fn g24_server_validation_and_g22_contexts_over_http() {
    let gym = gym().await;
    let http = reqwest::Client::new();
    let r = http
        .post(format!("{}/g24/api/form/contact", gym.base_url))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("email=not-an-email&phone=1&message=")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422);
    let v = r.json::<serde_json::Value>().await.unwrap();
    assert_eq!(v["errors"]["email"], "invalid_email");
    let r = http
        .post(format!("{}/g24/api/form/booking", gym.base_url))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("date=2026-11-02&guests=4")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let forms = gym.ledger().forms("g24");
    assert_eq!(forms.len(), 2);

    // g22: same DELETE, different behavior per (principal, owner, state)
    let r = http
        .post(format!("{}/g22/api/login", gym.base_url))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("user=alice&password={}", backend::PASSWORD))
        .send()
        .await
        .unwrap();
    let mut jar = BTreeMap::new();
    cookie_jar(&r, &mut jar);
    let alice = cookie_header(&jar);
    let del = |item: u64, cookie: String| {
        http.delete(format!("{}/g22/api/items/{item}", gym.base_url))
            .header("cookie", cookie)
            .send()
    };
    let v = del(1, alice.clone())
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(v["behavior"], "soft_delete");
    http.post(format!("{}/g22/api/items/1/archive", gym.base_url))
        .header("cookie", &alice)
        .send()
        .await
        .unwrap();
    let v = del(1, alice.clone())
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(v["behavior"], "purge");
    let r = del(2, alice).await.unwrap();
    assert_eq!(r.status(), 403);
    let contexts: BTreeSet<(String, String, String)> = gym
        .ledger()
        .effects("g22")
        .into_iter()
        .filter(|e| e.1.starts_with("delete:"))
        .map(|e| (e.0, e.2, e.1))
        .collect();
    assert_eq!(contexts.len(), 3, "{contexts:?}");
    gym.shutdown().await;
}

/// `POST /counter`: every applied increment is one `increment:ok` effect row, the
/// server count is readable from the handle and from `/__gym/ledger`, reads do not count,
/// and `/__gym/reset` zeroes it.
#[tokio::test]
async fn counter_fixture_counts_every_post_in_the_ledger() {
    let gym = gym().await;
    let http = reqwest::Client::new();
    let m = FixtureManifest::embedded("counter").unwrap();
    assert_eq!(m.controls.len(), 1);
    assert_eq!(
        m.controls[0].effect.as_deref(),
        Some("POST /counter/api/increment")
    );
    let page = http
        .get(m.entry_url(&gym.base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("id=\"increment\""), "{page}");

    let v = http
        .get(format!("{}/counter/api/count", gym.base_url))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(v["count"], 0);
    for expected in 1..=3u64 {
        let v = http
            .post(format!("{}/counter/api/increment", gym.base_url))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(v["count"], expected);
        assert_eq!(gym.counter(), expected);
    }
    let r = http
        .get(format!("{}/counter/api/increment", gym.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 405, "a GET never increments");
    assert_eq!(gym.counter(), 3);

    let effects = gym.ledger().effects("counter");
    assert_eq!(effects.len(), 3, "{effects:?}");
    assert!(effects.iter().all(|e| e.1 == "increment:ok" && e.2 == "counter"));
    assert_eq!(gym.ledger().count_ops("POST", "/counter/api/increment"), 3);
    let doc = http
        .get(format!("{}/__gym/ledger", gym.base_url))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(doc["counter"], 3);

    http.post(format!("{}/__gym/reset", gym.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(gym.counter(), 0);
    assert!(gym.ledger().effects("counter").is_empty());
    gym.shutdown().await;
}

#[tokio::test]
async fn hybrid_mix_static_crawl_reaches_exactly_the_url_addressable_pages() {
    let gym = gym().await;
    let m = FixtureManifest::embedded("hybrid-mix").unwrap();
    let crawl = urlplane::crawl(&gym.base_url, &m, 100).await.unwrap();
    let base = format!("{}/hybrid-mix", gym.base_url);
    let fetched: BTreeSet<String> = crawl
        .fetched
        .iter()
        .map(|u| u.strip_prefix(&base).unwrap_or(u).to_owned())
        .collect();
    let expected: BTreeSet<String> = m.expected.url_addressable_pages.iter().cloned().collect();
    assert_eq!(fetched, expected, "{:?}", crawl.fetched);
    assert!(
        !fetched.contains("/receipt.html"),
        "receipt is reachable only through the dialog"
    );
    assert!(crawl.statuses.values().all(|s| *s == 200));
    // the interaction-only part of the reachable set is non-empty: hybrid must beat static
    let interaction_only = m.controls.iter().filter(|c| !c.requires.is_empty()).count();
    assert!(interaction_only >= 8, "{interaction_only}");
    gym.shutdown().await;
}

// ---- real Chromium ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g10_timer_reveals_appear_without_any_action_and_learn_no_confident_edge() {
    if !have_chromium() {
        return;
    }
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("g19").unwrap();
    let mut req = crawl_request(&manifest, &gym.base_url, 11, SafetyProfile::TestEnvironment).unwrap();
    req.mode = CrawlMode::Dynamic;
    req.limits.interactions = 12;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = crawlx_worker::Stores::open(&cfg).await.unwrap();
    let report = run_local_with(authorize_fixture(
        LocalRun::new(req, cfg).with_stores(stores.clone()),
    ))
    .await
    .unwrap();
    assert!(report.status.is_terminal(), "{:?}", report.status);
    let ledger = gym.ledger();
    // the page reported every timer reveal to the server, on its own schedule
    let probes = ledger.probes("g19");
    for t in ["t1", "t2", "t3", "t4", "t5"] {
        assert!(probes.contains_key(&format!("revealed-{t}")), "{probes:?}");
    }
    // the timer controls are still discovered and exercised
    let clicked = ledger.clicked("g19");
    assert!(clicked.iter().any(|c| c.starts_with('t')), "{clicked:?}");
    // no persisted edge reaches confidence (laplace(3, 0) = 0.8): timer reveals are not causal
    let rows = RunRows::collect(
        report.run_id,
        "g19",
        11,
        "worker",
        SafetyProfile::TestEnvironment,
        stores.journal.as_ref(),
        stores.edges.as_ref(),
        stores.ledger.as_ref(),
        stores.states.as_ref(),
    )
    .await
    .unwrap();
    for e in &rows.edges {
        let effective = f64::from(e.support) + 0.5 * f64::from(e.weak_support);
        assert!(
            effective < 3.0,
            "confident edge learned from a timer reveal: {e:?}"
        );
    }
    let sc = Scorecard::compute(
        &manifest,
        &rows_from_report(
            &report,
            &manifest,
            11,
            "worker",
            SafetyProfile::TestEnvironment,
            &gym,
        ),
        &ledger,
    );
    assert_eq!(sc.safety.unauthorized, 0);
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g09_websocket_pushes_reveal_controls_and_replies_follow_requests() {
    let Some(backend) = launch().await else {
        return;
    };
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("g09").unwrap();
    let mut ctx = backend
        .new_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    ctx.navigate(&canonical(&manifest.entry_url(&gym.base_url)))
        .await
        .unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    let ledger = gym.ledger();
    // the socket connected and the first unsolicited push arrived on the server's schedule
    assert!(
        eventually(Duration::from_secs(20), || ledger
            .ops("g09")
            .iter()
            .any(|(m, _)| m == "WS-PUSH"))
        .await,
        "{:?}",
        ledger.ops("g09")
    );
    assert!(
        eventually(Duration::from_secs(10), || ledger
            .probes("g09")
            .contains_key("revealed-p1"))
        .await
    );
    assert!(ledger.clicked("g09").is_empty(), "no action preceded the push");
    // a click on `a` sends a request; the reply reveals `a-reply` (true edge)
    let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
    let cands = CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default());
    let a = cands
        .iter()
        .find(|c| c.descriptor.attributes.get("id").map(String::as_str) == Some("a"))
        .expect("Request A is discovered");
    ctx.perform(BrowserAction::Click {
        target: a.descriptor.locator.clone(),
        button: PointerButton::Left,
        modifiers: Modifiers::default(),
    })
    .await
    .unwrap();
    assert!(
        eventually(Duration::from_secs(10), || ledger
            .probes("g09")
            .contains_key("revealed-a-reply"))
        .await
    );
    let ws_requests: Vec<_> = ledger
        .entries_for("g09")
        .into_iter()
        .filter_map(|e| match e.event {
            crawlx_bench::gym::ledger::LedgerEvent::Op { method, query, .. } if method == "WS" => query,
            _ => None,
        })
        .collect();
    assert!(ws_requests.iter().any(|q| q == "req=open-a"), "{ws_requests:?}");
    assert!(!ledger.probes("g09").contains_key("revealed-b-reply"));
    ctx.close().await.unwrap();
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g22_element_coverage_saturates_while_action_context_coverage_lags() {
    let Some(backend) = launch().await else {
        return;
    };
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("g22").unwrap();
    let ledger = gym.ledger();
    let mut ctx = backend
        .new_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    ctx.navigate(&canonical(&manifest.entry_url(&gym.base_url)))
        .await
        .unwrap();
    let contexts = |ledger: &crawlx_bench::gym::ledger::Ledger| -> BTreeSet<(String, String, String)> {
        ledger
            .effects("g22")
            .into_iter()
            .filter(|e| e.1.starts_with("delete:"))
            .map(|e| (e.0, e.2, e.1))
            .collect()
    };
    // The same button, four times, from the same locator: one element, four action contexts.
    let script: [(&str, usize); 7] = [
        ("login-alice", 0),
        ("delete", 1),  // alice, own item 1, active -> soft_delete
        ("archive", 1), // item 1 becomes archived
        ("delete", 2),  // alice, own item 1, archived -> purge
        ("login-bob", 2),
        ("delete", 3), // bob, alice's item 1, archived -> denied
        ("login-admin", 3),
    ];
    for (id, expected_contexts) in script {
        let cands = discover(ctx.as_mut()).await;
        let before = ledger.clicks("g22").len();
        click(ctx.as_mut(), &cands, id).await;
        assert!(
            eventually(Duration::from_secs(10), || ledger.clicks("g22").len() > before).await,
            "{id} never reached the ledger"
        );
        assert!(
            eventually(Duration::from_secs(10), || contexts(&ledger).len()
                >= expected_contexts)
            .await,
            "after {id}: {:?}",
            contexts(&ledger)
        );
    }
    let cands = discover(ctx.as_mut()).await;
    click(ctx.as_mut(), &cands, "delete").await; // admin, item 1, archived -> admin_purge
    assert!(eventually(Duration::from_secs(10), || contexts(&ledger).len() >= 4).await);
    let reached = contexts(&ledger);
    let behaviors: BTreeSet<&str> = reached.iter().map(|c| c.2.as_str()).collect();
    assert_eq!(
        behaviors,
        BTreeSet::from([
            "delete:soft_delete:active",
            "delete:purge:archived",
            "delete:denied:archived",
            "delete:admin_purge:archived",
        ]),
        "{reached:?}"
    );
    // element coverage of `delete` saturated at the first click; action-context coverage is
    // 4 of 12 and only context-aware novelty (principal x owner x state) raises it further
    let clicked = ledger.clicked("g22");
    assert!(clicked.contains("delete"));
    let total = manifest.expected.action_contexts.len();
    let context_coverage = reached.len() as f64 / total as f64;
    assert!(
        (4.0 / 12.0..1.0).contains(&context_coverage),
        "{context_coverage}"
    );
    eprintln!(
        "g22: element coverage 1.00, action-context coverage {context_coverage:.2} ({}/{total}): gap {:.2}",
        reached.len(),
        1.0 - context_coverage
    );
    ctx.close().await.unwrap();
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g22_the_worker_never_executes_the_destructive_delete_without_approval() {
    if !have_chromium() {
        return;
    }
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("g22").unwrap();
    let mut req = crawl_request(&manifest, &gym.base_url, 5, SafetyProfile::TestEnvironment).unwrap();
    req.mode = CrawlMode::Dynamic;
    req.limits.interactions = 20;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let report = run_local_with(authorize_fixture(LocalRun::new(req, cfg)))
        .await
        .unwrap();
    assert!(report.status.is_terminal(), "{:?}", report.status);
    let ledger = gym.ledger();
    // the safe controls are exercised; the Delete button is approval-gated and never fires
    let clicked = ledger.clicked("g22");
    assert!(!clicked.is_empty(), "{clicked:?}");
    assert!(!clicked.contains("delete"), "{clicked:?}");
    assert_eq!(ledger.count_ops("DELETE", "/g22/api/items"), 0);
    let sc = Scorecard::compute(
        &manifest,
        &rows_from_report(
            &report,
            &manifest,
            5,
            "worker",
            SafetyProfile::TestEnvironment,
            &gym,
        ),
        &ledger,
    );
    assert_eq!(sc.safety.unauthorized, 0);
    gym.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g30_role_gated_controls_exist_only_under_their_role() {
    let Some(backend) = launch().await else {
        return;
    };
    let gym = gym().await;
    let manifest = FixtureManifest::embedded("g30").unwrap();
    let roles: BTreeMap<&str, BTreeSet<&str>> = manifest
        .expected
        .role_controls
        .iter()
        .map(|r| (r.role.as_str(), r.controls.iter().map(String::as_str).collect()))
        .collect();
    let mut ctx = backend
        .new_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    ctx.navigate(&canonical(&manifest.entry_url(&gym.base_url)))
        .await
        .unwrap();
    let ids_of = |cands: &[Candidate]| -> BTreeSet<String> {
        cands
            .iter()
            .filter_map(|c| c.descriptor.attributes.get("id").cloned())
            .filter(|id| manifest.control(id).is_some())
            .collect()
    };
    // anonymous: only the sign-in buttons
    let cands = discover(ctx.as_mut()).await;
    let anon = ids_of(&cands);
    assert_eq!(
        anon.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        roles["anonymous"],
        "{anon:?}"
    );
    // admin (localStorage): member + admin menus, no premium items yet
    click(ctx.as_mut(), &cands, "login-admin").await;
    let ledger = gym.ledger();
    assert!(
        eventually(Duration::from_secs(10), || ledger
            .clicked("g30")
            .contains("login-admin"))
        .await
    );
    let cands = discover(ctx.as_mut()).await;
    let admin = ids_of(&cands);
    for id in &roles["admin"] {
        assert!(admin.contains(*id), "admin control {id} missing: {admin:?}");
    }
    for id in &roles["premium"] {
        assert!(
            !admin.contains(*id),
            "premium control {id} present before enabling: {admin:?}"
        );
    }
    assert!(!admin.contains("login-member"));
    // premium (IndexedDB): the export items appear
    click(ctx.as_mut(), &cands, "enable-premium").await;
    assert!(
        eventually(Duration::from_secs(10), || ledger
            .clicked("g30")
            .contains("enable-premium"))
        .await
    );
    let cands = discover(ctx.as_mut()).await;
    let premium = ids_of(&cands);
    for id in &roles["premium"] {
        assert!(premium.contains(*id), "premium control {id} missing: {premium:?}");
    }
    ctx.close().await.unwrap();
    gym.shutdown().await;
}

/// Settle, observe and run the discovery ladder.
async fn discover(ctx: &mut dyn BrowserContext) -> Vec<Candidate> {
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
    CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default())
}

/// Native left click on the candidate whose DOM id is `id`.
async fn click(ctx: &mut dyn BrowserContext, cands: &[Candidate], id: &str) {
    let target = cands
        .iter()
        .find(|c| c.descriptor.attributes.get("id").map(String::as_str) == Some(id))
        .unwrap_or_else(|| panic!("{id} is discoverable"))
        .descriptor
        .locator
        .clone();
    ctx.perform(BrowserAction::Click {
        target,
        button: PointerButton::Left,
        modifiers: Modifiers::default(),
    })
    .await
    .unwrap();
}
