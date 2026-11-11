//! Gym server, manifests and URL-plane ground truth (no browser).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::gym::fixtures::{self, CATALOG_IDS};
use crawlx_bench::gym::ledger::LedgerEvent;
use crawlx_bench::gym::manifest::{ExpectedClass, FixtureManifest};
use crawlx_bench::gym::GymServer;
use crawlx_bench::urlplane;

async fn gym() -> crawlx_bench::gym::GymHandle {
    GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap()
}

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary"
)]
#[tokio::test]
async fn every_fixture_serves_200_and_its_manifest_parses() {
    let gym = gym().await;
    let http = reqwest::Client::new();
    let manifests = FixtureManifest::embedded_all().unwrap();
    assert_eq!(manifests.len(), CATALOG_IDS.len());
    for id in CATALOG_IDS {
        let m = FixtureManifest::embedded(id).unwrap();
        assert_eq!(m.id, id);
        let r = http.get(m.entry_url(&gym.base_url)).send().await.unwrap();
        assert_eq!(r.status().as_u16(), 200, "{id} entry page");
        let ct = r.headers()["content-type"].to_str().unwrap().to_owned();
        assert!(ct.starts_with("text/html"), "{id}: {ct}");
        let body = r.text().await.unwrap();
        assert!(!body.contains("{{"), "{id}: unexpanded placeholder");
        // every other page of the fixture serves too
        let def = fixtures::find(id).unwrap();
        for f in def.files {
            let url = format!("{}/{id}/{}", gym.base_url, f.name);
            let r = http.get(&url).send().await.unwrap();
            assert_eq!(r.status().as_u16(), 200, "{url}");
        }
    }
    // s1 pages
    for p in crawlx_bench::gym::fixtures::s1::page_paths() {
        let r = http.get(format!("{}{p}", gym.base_url)).send().await.unwrap();
        assert_eq!(r.status().as_u16(), 200, "{p}");
    }
    assert_eq!(
        http.get(format!("{}/s1/missing", gym.base_url))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        http.get(format!("{}/s1/error", gym.base_url))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        500
    );
    assert_eq!(
        http.get(format!("{}/nope/", gym.base_url))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    gym.shutdown().await;
}

#[test]
fn manifests_agree_with_their_pages() {
    for m in FixtureManifest::embedded_all().unwrap() {
        if m.id == "s1" {
            continue;
        }
        let def = fixtures::find(&m.id).unwrap();
        let all_text: String = def.files.iter().map(|f| f.body).collect::<Vec<_>>().join("\n");
        for c in &m.controls {
            // g31 controls live in closed shadow roots and several fixtures generate ids from a
            // prefix (`like-` + n, `tree-` + g + `-` + i, a frame prefix `'f1a'`, a host attribute
            // `data-prefix="o1"`): accept the id itself or any `-`-delimited prefix of it, raw
            // when it ends with the dash or quoted otherwise.
            let dom_id = c.selector.trim_start_matches('#');
            let mut candidates = vec![dom_id.to_owned(), c.id.clone()];
            let mut cut = dom_id;
            while let Some(pos) = cut.rfind('-') {
                candidates.push(cut[..=pos].to_owned());
                candidates.push(cut[..pos].to_owned());
                cut = &cut[..pos];
            }
            let mentioned = candidates.iter().any(|cand| {
                let exact = cand == dom_id || cand == &c.id;
                (exact || cand.len() >= 2)
                    && (all_text.contains(cand.as_str()) && (exact || cand.ends_with('-'))
                        || all_text.contains(&format!("'{cand}'"))
                        || all_text.contains(&format!("\"{cand}\"")))
            });
            assert!(
                mentioned,
                "{}: control {} ({}) is not mentioned by any page",
                m.id, c.id, c.selector
            );
        }
        assert!(m.expected.unauthorized_actions.is_none_or(|n| n == 0), "{}", m.id);
        let actionable = m
            .controls
            .iter()
            .filter(|c| c.expected == ExpectedClass::Actionable)
            .count();
        assert!(
            m.controls.is_empty() || actionable > 0,
            "{} has no actionable control",
            m.id
        );
    }
    // Catalog sizes called out by the catalog.
    let n = |id: &str| FixtureManifest::embedded(id).unwrap().controls.len();
    assert_eq!(n("g01"), 40);
    assert_eq!(n("g31"), 6);
    assert_eq!(n("g06"), 102);
    let g29 = FixtureManifest::embedded("g29").unwrap();
    assert_eq!(g29.expected.denied_destinations.len(), 24);
    let g27 = FixtureManifest::embedded("g27").unwrap();
    assert!(g27
        .controls
        .iter()
        .any(|c| c.expected == ExpectedClass::NotActionable));
    assert!(g27
        .controls
        .iter()
        .any(|c| c.expected == ExpectedClass::Actionable));
}

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary"
)]
#[tokio::test]
async fn ledger_records_beacons_ops_and_forms_and_reset_clears_it() {
    let gym = gym().await;
    let http = reqwest::Client::new();
    let base = &gym.base_url;
    http.post(format!("{base}/__gym/click?fixture=g01&control=c07&trusted=1"))
        .send()
        .await
        .unwrap();
    http.post(format!("{base}/__gym/click?fixture=g01&control=c08&trusted=0"))
        .send()
        .await
        .unwrap();
    http.delete(format!("{base}/g25/api/projects/7"))
        .send()
        .await
        .unwrap();
    http.post(format!("{base}/g25/api/form/invite"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("email=a%40b.test&note=hi")
        .send()
        .await
        .unwrap();
    http.post(format!(
        "{base}/__gym/probe?fixture=g31&name=webdriver&value=true"
    ))
    .send()
    .await
    .unwrap();
    http.get(format!("{base}/g12/invoice?id=2&utm_source=x"))
        .send()
        .await
        .unwrap();

    let ledger = gym.ledger();
    assert_eq!(
        ledger.clicks("g01"),
        [("c07".to_owned(), true), ("c08".to_owned(), false)]
    );
    assert_eq!(ledger.count_ops("DELETE", "/g25/api/projects"), 1);
    let forms = ledger.forms("g25");
    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0].0, "invite");
    assert_eq!(forms[0].1["email"], "a@b.test");
    assert_eq!(ledger.probes("g31")["webdriver"], "true");
    let g12_ops = ledger.ops("g12");
    assert_eq!(g12_ops, [("GET".to_owned(), "/g12/invoice".to_owned())]);
    assert!(ledger
        .entries()
        .iter()
        .any(|e| matches!(&e.event, LedgerEvent::Op { query: Some(q), .. } if q.contains("utm_source"))));

    // served JSON equals the in-process ledger
    let json: serde_json::Value = http
        .get(format!("{base}/__gym/ledger"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        usize::try_from(json["count"].as_u64().unwrap()).unwrap(),
        ledger.len()
    );
    let alias: serde_json::Value = http
        .get(format!("{base}/ledger"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alias["count"], json["count"]);

    // reset reseeds pages and clears the ledger; snapshot digest is stable per seed
    let a: serde_json::Value = http
        .post(format!("{base}/__gym/reset?seed=41&snapshot=baseline"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(a["seed"], 41);
    assert_eq!(a["snapshot"], "baseline");
    assert!(ledger.is_empty());
    let b: serde_json::Value = http
        .get(format!("{base}/__gym/snapshot"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(a["digest"], b["digest"]);
    let page = http
        .get(format!("{base}/g01/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("var SEED = 41 >>> 0;"));
    gym.shutdown().await;
}

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary"
)]
#[tokio::test]
async fn checkpoints_restore_exact_fixture_state_without_rewinding_evidence() {
    let gym = gym().await;
    let http = reqwest::Client::new();
    gym.reset(41);
    let mut checkpoints = Vec::new();
    for _ in 0..2 {
        http.post(format!("{}/g22/api/items/1/archive", gym.base_url))
            .header("cookie", "g22_user=admin")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let snapshot = http
            .get(format!(
                "{}/__gym/snapshot?checkpoint=same-turn-name",
                gym.base_url
            ))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        checkpoints.push(
            snapshot.headers()["x-gym-checkpoint"]
                .to_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_ne!(
        checkpoints[0], checkpoints[1],
        "every capture must have distinct custody"
    );
    gym.reset(99);
    http.delete(format!("{}/g22/api/items/1", gym.base_url))
        .header("cookie", "g22_user=admin")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(gym.ledger().count_ops("DELETE", "/g22/api/items"), 1);
    for (checkpoint, archived) in checkpoints.iter().zip([true, false]) {
        let evidence = gym.ledger().entries();
        assert!(gym.restore_checkpoint(checkpoint));
        assert_eq!(gym.seed(), 41);
        assert_eq!(gym.ledger().entries(), evidence);
        assert_eq!(gym.ledger().count_ops("DELETE", "/g22/api/items"), 1);
        let items: serde_json::Value = http
            .get(format!("{}/g22/api/items", gym.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(items["items"][0]["archived"], archived);
    }
    let evidence = gym.ledger().entries();
    assert!(!gym.restore_checkpoint("not-captured"));
    assert_eq!(gym.ledger().entries(), evidence);
    gym.shutdown().await;
}

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary"
)]
#[tokio::test]
async fn pages_are_deterministic_for_a_seed() {
    let gym = gym().await;
    let http = reqwest::Client::new();
    gym.reset(9);
    let first = http
        .get(format!("{}/g06/", gym.base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let second = http
        .get(format!("{}/g06/", gym.base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(first, second);
    gym.reset(10);
    let third = http
        .get(format!("{}/g06/", gym.base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_ne!(first, third, "the seed is injected into the page");
    gym.shutdown().await;
}

#[tokio::test]
async fn s1_link_graph_matches_the_manifest_counters() {
    let gym = gym().await;
    let m = FixtureManifest::embedded("s1").unwrap();
    let expected = m.expected.url_counters.unwrap();
    let crawl = urlplane::crawl(&gym.base_url, &m, 200).await.unwrap();
    let c = crawl.counters;
    assert!(c.invariants_hold(), "{c:?}");
    assert_eq!(c.discovered, expected.discovered, "discovered");
    assert_eq!(c.admitted, expected.admitted, "admitted");
    assert_eq!(c.deduplicated, expected.deduplicated, "deduplicated");
    assert_eq!(c.robots_blocked, expected.robots_blocked, "robots_blocked");
    assert_eq!(c.policy_blocked, expected.policy_blocked, "policy_blocked");
    assert_eq!(
        (c.attempted, c.succeeded, c.failed),
        (expected.attempted, expected.succeeded, expected.failed)
    );
    assert_eq!((c.abandoned, c.unreachable, c.unknown_outcome), (0, 0, 0));
    assert_eq!(c, expected);

    // 404 and 500 are the two failures; the sitemap-only pages were fetched.
    let failed: Vec<_> = crawl
        .statuses
        .iter()
        .filter(|(_, s)| **s >= 400)
        .map(|(u, s)| (u.as_str(), *s))
        .collect();
    assert_eq!(failed.len(), 2, "{failed:?}");
    assert!(
        crawl.fetched.iter().any(|u| u.ends_with("/s1/archive/y3")),
        "{:?}",
        crawl.fetched
    );
    assert!(crawl.fetched.len() >= 28);

    // The server-side ledger shows politeness: nothing under /s1/private was ever requested,
    // external hosts were never contacted, robots.txt and the sitemap were.
    let ledger = gym.ledger();
    let ops = ledger.ops("s1");
    assert!(ops.iter().all(|(_, p)| !p.starts_with("/s1/private")), "{ops:?}");
    assert!(ops.iter().any(|(_, p)| p == "/s1/sitemap.xml"));
    assert!(ledger.count_ops("GET", "/robots.txt") >= 1);
    assert!(
        ops.iter().all(|(_, p)| !p.starts_with("/d1")),
        "out-of-scope link must not be fetched"
    );
    // tracking-parameter and trailing-slash duplicates never produce a second fetch
    let about = ops
        .iter()
        .filter(|(_, p)| p.trim_end_matches('/') == "/s1/about")
        .count();
    assert_eq!(about, 1, "{ops:?}");

    // A second run reproduces the page set exactly (determinism).
    gym.reset(0);
    let again = urlplane::crawl(&gym.base_url, &m, 200).await.unwrap();
    assert_eq!(again.fetched, crawl.fetched);
    assert_eq!(again.counters, crawl.counters);
    gym.shutdown().await;
}

/// A client that never follows redirects, so tests see the 3xx responses themselves.
#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary"
)]
fn no_redirects() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

#[tokio::test]
async fn d2_robots_txt_follows_the_request_host_once_the_origin_is_claimed() {
    let gym = gym().await;
    let http = no_redirects();
    let robots = |host: String| {
        let http = http.clone();
        let url = format!("{}/robots.txt", gym.base_url);
        async move {
            let r = http
                .get(url)
                .header(reqwest::header::HOST, host)
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        }
    };

    // unclaimed: the default s1 rules whatever the host
    let (status, body) = robots(format!("big.gym.test:{}", gym.port)).await;
    assert_eq!(status, 200);
    assert!(body.contains("Disallow: /s1/private"), "{body}");

    gym.claim_origin("d2");
    let (status, big) = robots(format!("big.gym.test:{}", gym.port)).await;
    assert_eq!(status, 200);
    assert!(big.len() > 520_000 && big.len() < 600_000, "{}", big.len());
    assert!(big.starts_with("User-agent: *\nDisallow: /d2/robots/early-blocked\n"));
    assert!(big.find("late-blocked").unwrap() > 520_000);

    let (status, main) = robots(format!("gym.test:{}", gym.port)).await;
    assert_eq!(status, 200);
    assert!(main.contains("Allow: /d2/robots/private/open/"), "{main}");
    assert_eq!(robots(format!("e404.gym.test:{}", gym.port)).await.0, 404);
    assert_eq!(robots(format!("e403.gym.test:{}", gym.port)).await.0, 403);
    assert_eq!(robots(format!("e503.gym.test:{}", gym.port)).await.0, 503);
    let (status, ua) = robots(format!("ua.gym.test:{}", gym.port)).await;
    assert_eq!(status, 200);
    assert!(
        ua.contains("User-agent: FirecrawlAgent\nDisallow: /d2/robots/fc-only\n"), // wire-compat: robots product token
        "{ua}"
    );
    // any other host, the bare gym address included, allows everything
    let open = (200, "User-agent: *\nDisallow:\n".to_owned());
    assert_eq!(robots(format!("127.0.0.1:{}", gym.port)).await, open);
    assert_eq!(robots(format!("other.test:{}", gym.port)).await, open);
    gym.shutdown().await;
}

#[tokio::test]
async fn d2_serves_redirects_scoped_links_and_slow_pages() {
    let gym = gym().await;
    let http = no_redirects();
    let url = |p: &str| format!("{}{p}", gym.base_url);

    let r = http.get(url("/d2/redir/go/301")).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 301);
    assert_eq!(r.headers()["location"], "/d2/redir/target");
    let r = http.get(url("/d2/redir/go/rel")).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 302);
    assert_eq!(r.headers()["location"], "../target");
    let r = http.get(url("/d2/redir/go/cross")).send().await.unwrap();
    assert_eq!(
        r.headers()["location"].to_str().unwrap(),
        format!("http://other.test:{}/d2/redir/cross-target", gym.port)
    );
    for (case, status) in [("303", 303), ("307", 307), ("308", 308)] {
        let r = http
            .get(url(&format!("/d2/redir/go/{case}")))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), status, "{case}");
    }
    // the redirect to a missing page ends in the gym's own 404
    let r = http.get(url("/d2/redir/go/missing")).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 302);
    assert_eq!(
        http.get(url("/d2/redir/nope"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    // a default client follows the three-hop chain to the target
    let r = reqwest::get(url("/d2/redir/go/302chain")).await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert!(r.url().path().ends_with("/d2/redir/target"), "{}", r.url());

    // links name the alias hosts with the port of the request `Host`
    let body = http
        .get(url("/d2/scope/"))
        .header(reqwest::header::HOST, "gym.test:4101")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("href=\"http://app.gym.test:4101/d2/scope/sub\""),
        "{body}"
    );
    assert!(
        body.contains("href=\"//other.test:4101/d2/scope/ext-proto\""),
        "{body}"
    );

    // slow pages wait, the index does not; unknown pages are the gym's 404
    let started = std::time::Instant::now();
    let r = http.get(url("/d2/slow/p/1")).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        http.get(url("/d2/slow/")).send().await.unwrap().status().as_u16(),
        200
    );
    assert_eq!(
        http.get(url("/d2/slow/p/41"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    gym.shutdown().await;
}

#[tokio::test]
async fn the_ledger_records_the_request_host_header() {
    let gym = gym().await;
    let http = no_redirects();
    http.get(format!("{}/d2/", gym.base_url))
        .header(reqwest::header::HOST, "app.gym.test:1")
        .send()
        .await
        .unwrap();
    http.get(format!("{}/robots.txt", gym.base_url))
        .header(reqwest::header::HOST, "other.test:2")
        .send()
        .await
        .unwrap();
    let doc: serde_json::Value = http
        .get(format!("{}/__gym/ledger", gym.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = doc["entries"].as_array().unwrap();
    let host_of = |path: &str| {
        entries
            .iter()
            .find(|e| e["path"] == path)
            .unwrap_or_else(|| panic!("{path} not in ledger: {entries:?}"))["host"]
            .clone()
    };
    assert_eq!(host_of("/d2/"), "app.gym.test:1");
    assert_eq!(host_of("/robots.txt"), "other.test:2");
    // the ledger of the in-process handle agrees
    assert_eq!(
        gym.ledger().entries_for("d2").len(),
        1,
        "{:?}",
        gym.ledger().entries()
    );
    gym.shutdown().await;
}
