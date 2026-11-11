//! `fetch.identityProfile` and `fetch.acquisitionService` admission: installed digest only, no
//! unsupported controls, and exact coupling with the acquisition policy backend list.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::{identity_profile::IdentityProfileV1, CreateCrawl};
use serde_json::{json, Value};

fn installed() -> String {
    IdentityProfileV1::pinned_chromium().digest().unwrap().to_hex()
}

fn request(mode: &str, fetch: Value, extra: Value) -> CreateCrawl {
    let mut body = json!({"seedUrl": "https://site.test/", "mode": mode, "fetch": fetch});
    for (key, value) in extra.as_object().unwrap() {
        body[key] = value.clone();
    }
    serde_json::from_value(body).unwrap()
}

fn refused(crawl: &mut CreateCrawl, field: &str) -> bool {
    crawl
        .normalize()
        .err()
        .is_some_and(|errors| errors.iter().any(|error| format!("{error:?}").contains(field)))
}

#[test]
fn installed_identity_profile_is_admitted_and_round_trips() {
    let mut crawl = request("static", json!({"identityProfile": installed()}), json!({}));
    crawl.normalize().unwrap();
    assert_eq!(
        serde_json::to_value(&crawl).unwrap()["fetch"]["identityProfile"],
        installed()
    );
}

#[test]
fn unselected_controls_leave_the_exported_fetch_unchanged() {
    let mut crawl = request("static", json!({}), json!({}));
    crawl.normalize().unwrap();
    let fetch = serde_json::to_value(&crawl).unwrap()["fetch"].clone();
    assert!(fetch.get("identityProfile").is_none());
    assert!(fetch.get("acquisitionService").is_none());
}

#[test]
fn identity_profile_digest_must_be_the_installed_profile() {
    let mut crawl = request("static", json!({"identityProfile": "0".repeat(64)}), json!({}));
    assert!(refused(&mut crawl, "fetch.identityProfile"));
}

#[test]
fn identity_profile_conflicts_with_every_other_transport_selection() {
    let profile = installed();
    for (mode, fetch) in [
        ("hybrid", json!({"identityProfile": profile})),
        ("dynamic", json!({"identityProfile": profile})),
        (
            "static",
            json!({"identityProfile": profile, "tlsImpersonation": "randomized"}),
        ),
        (
            "static",
            json!({"identityProfile": profile, "userAgent": "custom/1"}),
        ),
        (
            "static",
            json!({"identityProfile": profile, "skipTlsVerification": true}),
        ),
        (
            "static",
            json!({"identityProfile": profile, "acquisitionService": "svc"}),
        ),
    ] {
        let mut crawl = request(mode, fetch.clone(), json!({}));
        assert!(refused(&mut crawl, "fetch.identityProfile"), "{mode} {fetch}");
    }
}

#[test]
fn acquisition_service_derives_its_exclusive_backend_policy() {
    let mut crawl = request("static", json!({"acquisitionService": "render-1"}), json!({}));
    crawl.normalize().unwrap();
    let policy = crawl.acquisition.unwrap();
    assert_eq!(policy.backend_ids, ["acquisition_service"]);
    assert!(policy.fallback_backend_ids.is_empty());
}

#[test]
fn acquisition_service_refuses_unsupported_controls_and_reserved_ids() {
    for (mode, fetch) in [
        ("static", json!({"acquisitionService": ""})),
        ("static", json!({"acquisitionService": "x".repeat(129)})),
        ("static", json!({"acquisitionService": "native_ftp"})),
        ("static", json!({"acquisitionService": "native_whois"})),
        (
            "static",
            json!({"acquisitionService": "svc", "userAgent": "custom/1"}),
        ),
        (
            "static",
            json!({"acquisitionService": "svc", "skipTlsVerification": true}),
        ),
        (
            "static",
            json!({"acquisitionService": "svc", "proxy": "http://proxy.test:8080"}),
        ),
        ("hybrid", json!({"acquisitionService": "svc"})),
        ("dynamic", json!({"acquisitionService": "svc"})),
    ] {
        let mut crawl = request(mode, fetch.clone(), json!({}));
        assert!(refused(&mut crawl, "fetch.acquisitionService"), "{mode} {fetch}");
    }
}

#[test]
fn acquisition_service_and_backend_policy_require_each_other() {
    let mut native = request(
        "static",
        json!({"acquisitionService": "svc"}),
        json!({"acquisition": {"backendIds": ["native_http"]}}),
    );
    assert!(refused(&mut native, "acquisition.backendIds"));
    let mut unselected = request(
        "static",
        json!({}),
        json!({"acquisition": {"backendIds": ["acquisition_service"]}}),
    );
    assert!(refused(&mut unselected, "fetch.acquisitionService"));
    let mut fallback = request(
        "static",
        json!({"acquisitionService": "svc"}),
        json!({"acquisition": {"backendIds": ["acquisition_service", "native_browser"]}}),
    );
    assert!(refused(&mut fallback, "acquisition.fallbackBackendIds"));
}
