//! `dynamic.browserProfile.generation` names the exact retained generation to restore.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::CreateCrawl;
use serde_json::{json, Value};

fn request(profile: Value) -> CreateCrawl {
    serde_json::from_value(json!({
        "seedUrl": "https://site.test/", "mode": "dynamic",
        "dynamic": {"enabled": true, "browserProfile": profile}
    }))
    .unwrap()
}

#[test]
fn omitted_generation_is_zero_and_stays_off_the_wire() {
    let mut crawl = request(json!({"name": "main"}));
    crawl.normalize().unwrap();
    let profile = crawl.dynamic.browser_profile.as_ref().unwrap();
    assert_eq!((profile.generation, profile.save_changes), (0, true));
    let exported = serde_json::to_value(&crawl).unwrap();
    assert!(exported["dynamic"]["browserProfile"].get("generation").is_none());
}

#[test]
fn explicit_generation_round_trips() {
    let mut crawl = request(json!({"name": "main", "saveChanges": false, "generation": 7}));
    crawl.normalize().unwrap();
    let exported = serde_json::to_value(&crawl).unwrap();
    assert_eq!(exported["dynamic"]["browserProfile"]["generation"], 7);
    let again: CreateCrawl = serde_json::from_value(exported).unwrap();
    assert_eq!(again.dynamic.browser_profile.unwrap().generation, 7);
}

#[test]
fn generations_beyond_the_database_range_are_refused() {
    let mut crawl = request(json!({"name": "main", "generation": u64::try_from(i64::MAX).unwrap()}));
    crawl.normalize().unwrap();
    let mut too_large = request(json!({"name": "main", "generation": u64::MAX}));
    let errors = too_large.normalize().unwrap_err();
    assert!(errors
        .iter()
        .any(|error| format!("{error:?}").contains("dynamic.browserProfile.generation")));
}

#[test]
fn the_generation_distinguishes_otherwise_identical_requests() {
    let digest = |profile: Value| {
        let mut crawl = request(profile);
        crawl.normalize().unwrap();
        crawl.digest().unwrap()
    };
    assert_ne!(
        digest(json!({"name": "main"})),
        digest(json!({"name": "main", "generation": 1}))
    );
    assert_eq!(
        digest(json!({"name": "main"})),
        digest(json!({"name": "main", "generation": 0}))
    );
}
