//! Configuration of adaptive crawling: wire shape, defaults that leave existing digests alone,
//! and the checks `normalize` applies.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::adaptive::AdaptiveStopConfigV1;
use crawlx_core::config::CrawlMode;
use crawlx_core::orchestration::OrchestrationConfigV1;
use crawlx_core::CreateCrawl;

fn limits() -> String {
    serde_json::to_string(&OrchestrationConfigV1::default()).unwrap()
}

fn acquisition() -> String {
    serde_json::to_string(&crawlx_core::acquisition::AcquisitionPolicyV1::default()).unwrap()
}

fn request(json: &str) -> CreateCrawl {
    let json = json
        .replace(
            "\"orchestration\": {}",
            &format!("\"orchestration\": {}", limits()),
        )
        .replace(
            "\"acquisition\": {}",
            &format!("\"acquisition\": {}", acquisition()),
        );
    serde_json::from_str(&json).unwrap()
}

fn invalid_fields(json: &str) -> Vec<String> {
    let mut crawl = request(json);
    crawl
        .normalize()
        .err()
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect()
}

#[test]
fn a_crawl_without_adaptive_settings_serializes_exactly_as_before() {
    let wire = serde_json::to_value(CreateCrawl::new(url::Url::parse("https://a.test/").unwrap())).unwrap();
    assert!(wire.get("adaptive").is_none());
    assert!(wire["dynamic"].get("adaptive").is_none());
    for key in ["hops", "queueCost", "seeding"] {
        assert!(
            wire["scope"].get(key).is_none(),
            "{key} stays off the wire when unset"
        );
    }
}

#[test]
fn every_adaptive_setting_round_trips_on_the_wire() {
    let json = r#"{
        "seedUrl": "https://a.test/",
        "orchestration": {},
        "dynamic": {"adaptive": {"probePerMille": 250, "maxProbes": 4, "probeEffects": 2}},
        "scope": {
            "hops": {"followEmbeds": true, "maxHops": 6},
            "queueCost": {"calendarPenalty": 9, "successStep": 5},
            "seeding": {"fixtures": [{"kind": "robots", "content": "Allow: /a"}], "liveCheck": "head"}
        },
        "adaptive": {"query": "rust async", "maxPages": 20, "targetConfidencePermille": 900}
    }"#;
    let mut crawl = request(json);
    crawl.normalize().unwrap();
    let again = request(&serde_json::to_string(&crawl).unwrap());
    assert_eq!(again, crawl);
    let adaptive = crawl.dynamic.adaptive.as_ref().unwrap();
    assert_eq!(
        (
            adaptive.probe_per_mille,
            adaptive.max_probes,
            adaptive.probe_effects
        ),
        (250, 4, 2)
    );
    assert!(crawl.scope.hops.as_ref().unwrap().follow_embeds);
    assert_eq!(crawl.scope.queue_cost.as_ref().unwrap().calendar_penalty, 9);
}

#[test]
fn render_prediction_needs_hybrid_mode_and_effect_limits() {
    let probe = r#""dynamic": {"adaptive": {}}"#;
    assert!(invalid_fields(&format!(
        r#"{{"seedUrl":"https://a.test/", "orchestration": {{}}, {probe}}}"#
    ))
    .is_empty());
    let without_limits = invalid_fields(&format!(r#"{{"seedUrl":"https://a.test/", {probe}}}"#));
    assert!(
        without_limits.iter().any(|e| e.contains("dynamic.adaptive")),
        "{without_limits:?}"
    );
    let static_mode = invalid_fields(&format!(
        r#"{{"seedUrl":"https://a.test/", "mode":"static", "orchestration": {{}}, {probe}}}"#
    ));
    assert!(
        static_mode.iter().any(|e| e.contains("hybrid")),
        "{static_mode:?}"
    );
    let native_acquisition = invalid_fields(&format!(
        r#"{{"seedUrl":"https://a.test/", "orchestration": {{}}, "acquisition": {{}}, {probe}}}"#
    ));
    assert!(
        native_acquisition.iter().any(|e| e.contains("dynamic.adaptive")),
        "{native_acquisition:?}"
    );
    let bad_ratio = invalid_fields(
        r#"{"seedUrl":"https://a.test/", "orchestration": {}, "dynamic": {"adaptive": {"probePerMille": 1001}}}"#,
    );
    assert!(
        bad_ratio.iter().any(|e| e.contains("probePerMille")),
        "{bad_ratio:?}"
    );
    let mut programmatic = CreateCrawl::new(url::Url::parse("https://a.test/").unwrap());
    programmatic.mode = CrawlMode::Hybrid;
    programmatic.orchestration = Some(OrchestrationConfigV1::default());
    programmatic.dynamic.adaptive = Some(crawlx_core::adaptive::AdaptiveRendering::default());
    programmatic.normalize().unwrap();
}

#[test]
fn hop_cost_seed_and_stop_settings_are_bounds_checked() {
    let cases = [
        (r#""scope": {"hops": {"maxHops": 0}}"#, "scope.hops"),
        (r#""scope": {"queueCost": {"maxCost": 0}}"#, "scope.queueCost"),
        (r#""scope": {"queueCost": {"maxCost": 32001}}"#, "scope.queueCost"),
        (r#""scope": {"seeding": {"fixtures": []}}"#, "scope.seeding"),
        (
            r#""scope": {"seeding": {"fixtures": [{"kind":"feed","content":"x"}], "maxUrls": 0}}"#,
            "scope.seeding",
        ),
        (r#""adaptive": {"query": "the of"}"#, "adaptive"),
        (
            r#""adaptive": {"query": "rust", "targetConfidencePermille": 1000}"#,
            "adaptive",
        ),
    ];
    for (fragment, field) in cases {
        let errors = invalid_fields(&format!(r#"{{"seedUrl":"https://a.test/", {fragment}}}"#));
        assert!(errors.iter().any(|e| e.contains(field)), "{fragment}: {errors:?}");
    }
    assert!(
        serde_json::from_str::<CreateCrawl>(
            r#"{"seedUrl":"https://a.test/","scope":{"hops":{"maxHopz":1}}}"#
        )
        .is_err(),
        "unknown keys are refused, not ignored"
    );
}

#[test]
fn imported_stop_state_must_belong_to_the_query() {
    let mut first = AdaptiveStopConfigV1::new("rust async");
    first.max_pages = 5;
    let state = crawlx_core::adaptive::AdaptiveStopExportV1 {
        version: 1,
        query_digest: crawlx_core::adaptive::query_digest("rust async"),
        pages: 2,
        relevant_pages: 2,
        recent_gains: vec![900, 400],
        term_pages: std::collections::BTreeMap::from([("async".to_owned(), 2), ("rust".to_owned(), 1)]),
        vocabulary: vec!["async".to_owned(), "rust".to_owned()],
        stopped: None,
    };
    let mut same = AdaptiveStopConfigV1::new("Async, rust!");
    same.import = Some(state.clone());
    assert!(
        same.validate().is_ok(),
        "the digest binds to the normalized terms"
    );
    let mut other = AdaptiveStopConfigV1::new("rust tokio");
    other.import = Some(state);
    assert!(other.validate().is_err());
}
