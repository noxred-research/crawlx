//! Native worker control DTO serialization and admission bounds.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::acquisition::{HeadPreflight, HttpErrorStatuses, OversizePolicy, ResponseDeclaration};
use crawlx_core::config::{CreateCrawl, Extract, Fetch};
use crawlx_core::hash::Digest;
use serde_json::{json, Value};

#[test]
fn absent_worker_controls_preserve_serialization_and_digest() {
    let request = CreateCrawl::new("https://example.test/".parse().unwrap());
    let mut serialized = serde_json::to_value(&request).unwrap();
    for field in ["preflight", "declaration", "oversize"] {
        assert!(serialized["fetch"].get(field).is_none());
    }
    for field in ["outputs", "decode", "markup"] {
        assert!(serialized["extract"].get(field).is_none());
    }
    let original = serde_json::to_vec(&serialized).unwrap();
    for field in ["preflight", "declaration", "oversize"] {
        serialized["fetch"][field] = Value::Null;
    }
    for field in ["outputs", "decode", "markup"] {
        serialized["extract"][field] = Value::Null;
    }
    let roundtrip: CreateCrawl = serde_json::from_value(serialized).unwrap();
    let restored = serde_json::to_vec(&serde_json::to_value(roundtrip).unwrap()).unwrap();
    assert_eq!(original, restored);
    assert_eq!(
        Digest::of("worker-controls/v1", &original),
        Digest::of("worker-controls/v1", &restored)
    );
    assert_eq!(OversizePolicy::default(), OversizePolicy::Truncate);
}

#[test]
fn fetch_controls_use_native_camel_case_objects() {
    let controls = json!({
        "preflight": {"maxContentLength": 4096, "contentTypes": ["text/html"]},
        "declaration": {
            "contentType": "text/html",
            "charset": "utf-8",
            "statuses": {"allow": [404, 429], "deny": [403]}
        },
        "oversize": "refuse"
    });
    let fetch: Fetch = serde_json::from_value(controls.clone()).unwrap();
    fetch.preflight.as_ref().unwrap().validate().unwrap();
    fetch.declaration.as_ref().unwrap().validate().unwrap();
    assert_eq!(fetch.oversize, Some(OversizePolicy::Refuse));
    let serialized = serde_json::to_value(&fetch).unwrap();
    for field in ["preflight", "declaration", "oversize"] {
        assert_eq!(serialized[field], controls[field]);
    }
    let statuses: HttpErrorStatuses = serde_json::from_value(json!({"allow": [429, 404, 429]})).unwrap();
    assert_eq!(
        serde_json::to_value(statuses).unwrap(),
        json!({"allow": [404, 429], "deny": []})
    );
}

#[test]
fn extract_options_remain_opaque_and_roundtrip_without_core_dependencies() {
    let controls = json!({
        "outputs": {"text": true},
        "decode": {"maxBytes": 4096},
        "markup": "none"
    });
    let extract: Extract = serde_json::from_value(controls.clone()).unwrap();
    let serialized = serde_json::to_value(extract).unwrap();
    for field in ["outputs", "decode", "markup"] {
        assert_eq!(serialized[field], controls[field]);
    }
}

#[test]
fn preflight_bounds_reject_zero_excessive_lengths_and_invalid_media_types() {
    for invalid in [
        json!({"maxContentLength": 0}),
        json!({"maxContentLength": 67_108_865_u64}),
        json!({"contentTypes": vec!["text/html"; 17]}),
        json!({"contentTypes": [""]}),
        json!({"contentTypes": ["text/html; charset=utf-8"]}),
        json!({"contentTypes": [format!("text/{}", "a".repeat(96))]}),
    ] {
        let preflight: HeadPreflight = serde_json::from_value(invalid).unwrap();
        assert!(preflight.validate().is_err());
    }
    let valid: HeadPreflight = serde_json::from_value(json!({
        "maxContentLength": 67_108_864_u64,
        "contentTypes": vec!["text/html"; 16]
    }))
    .unwrap();
    valid.validate().unwrap();
    HeadPreflight::default().validate().unwrap();
}

#[test]
fn declaration_bounds_reject_invalid_mime_charset_and_status_sets() {
    for invalid in [
        json!({"contentType": "html"}),
        json!({"contentType": "text/html; charset=utf-8"}),
        json!({"contentType": format!("text/{}", "a".repeat(96))}),
        json!({"charset": ""}),
        json!({"charset": "   "}),
        json!({"charset": "utf-8\r\n"}),
        json!({"charset": "a".repeat(129)}),
        json!({"statuses": {"allow": [99]}}),
        json!({"statuses": {"deny": [600]}}),
        json!({"statuses": {"allow": [404], "deny": [404]}}),
    ] {
        let declaration: ResponseDeclaration = serde_json::from_value(invalid).unwrap();
        assert!(declaration.validate().is_err());
    }
    let valid: ResponseDeclaration = serde_json::from_value(json!({
        "contentType": format!("text/{}", "a".repeat(95)),
        "charset": "utf-8",
        "statuses": {"allow": [100], "deny": [599]}
    }))
    .unwrap();
    valid.validate().unwrap();
    ResponseDeclaration::default().validate().unwrap();
}

#[test]
fn request_normalization_reports_both_invalid_fetch_controls() {
    let mut request = CreateCrawl::new("https://example.test/".parse().unwrap());
    request.fetch.preflight = Some(serde_json::from_value(json!({"maxContentLength": 0})).unwrap());
    request.fetch.declaration = Some(
        serde_json::from_value(json!({
            "statuses": {"allow": [404], "deny": [404]}
        }))
        .unwrap(),
    );
    let errors = request.normalize().unwrap_err();
    for expected in ["fetch.preflight", "fetch.declaration"] {
        assert!(errors.iter().any(|error| matches!(
            error,
            crawlx_core::CoreError::Invalid { field, .. } if *field == expected
        )));
    }
}

#[test]
fn control_objects_reject_unknown_fields_and_unknown_overflow_policy() {
    assert!(serde_json::from_value::<HeadPreflight>(json!({"maxLength": 1})).is_err());
    assert!(serde_json::from_value::<ResponseDeclaration>(json!({"encoding": "utf-8"})).is_err());
    assert!(serde_json::from_value::<HttpErrorStatuses>(json!({"allowed": [404]})).is_err());
    assert!(serde_json::from_value::<OversizePolicy>(json!("ignore")).is_err());
}
