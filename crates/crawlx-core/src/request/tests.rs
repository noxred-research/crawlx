#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::url::RouteTemplate;
use serde_json::json;

fn url(value: &str) -> CanonicalUrl {
    let url = url::Url::parse(value).unwrap();
    CanonicalUrl {
        key: Digest::of("test/url", value.as_bytes()),
        origin: url.origin().ascii_serialization(),
        route_template: RouteTemplate(url.path().to_owned()),
        params: Vec::new(),
        url,
    }
}
#[test]
fn legacy_get_keeps_native_canonical_key_and_principals_do_not_share_identity() {
    let request = RequestEnvelopeV1::get(url("https://example.test/page"), 0, None);
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    assert_eq!(
        request
            .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
            .unwrap()
            .key,
        request.url.key
    );
    assert_ne!(
        request
            .identity(tenant, run, "member", &BTreeMap::new(), 1)
            .unwrap()
            .key,
        request.url.key
    );
}

#[test]
fn native_head_identity_stays_distinct_from_get_after_envelope_roundtrip() {
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let get = RequestEnvelopeV1::get(url("https://example.test/page"), 0, None);
    let head = RequestEnvelopeV1::new(url("https://example.test/page"), "HEAD".into(), 0, None);
    assert_eq!(head.method, "HEAD");
    let identity = head
        .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
        .unwrap();
    assert_ne!(
        identity,
        get.identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
            .unwrap()
    );
    let restored: RequestEnvelopeV1 = serde_json::from_slice(&serde_json::to_vec(&head).unwrap()).unwrap();
    assert_eq!(restored.method, "HEAD");
    assert_eq!(
        identity,
        restored
            .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
            .unwrap()
    );
}
#[test]
fn native_bodies_vary_digests_and_strict_generation_change_identity() {
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let mut request = RequestEnvelopeV1::get(url("https://example.test/form"), 0, None);
    request.method = "POST".into();
    request.body = Some(RequestBodyV1 {
        handle: "volatile:body".into(),
        digest: Digest::keyed(&[1; 32], "test", b"one"),
        key_version: 1,
        length: 3,
        media_type: "text/plain".into(),
    });
    let one = request
        .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
        .unwrap();
    request.body.as_mut().unwrap().digest = Digest::keyed(&[1; 32], "test", b"two");
    assert_ne!(
        one.key,
        request
            .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
            .unwrap()
            .key
    );
    let two = request
        .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
        .unwrap();
    request.session_generation = Some(2);
    assert_ne!(
        two.key,
        request
            .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
            .unwrap()
            .key
    );
    let headers = BTreeMap::from([("accept-language".into(), Digest::keyed(&[1; 32], "test", b"fr"))]);
    assert_ne!(
        request
            .identity(tenant, run, "anonymous", &headers, 1)
            .unwrap()
            .key,
        request
            .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
            .unwrap()
            .key
    );
}
#[test]
fn exported_custom_key_is_opaque_authoritative_but_remains_principal_scoped() {
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let mut request = RequestEnvelopeV1::get(url("https://example.test/one"), 0, None);
    request.dialect = IdentityDialectV1::JsActor318;
    request.source_key = Some(Digest::keyed(&[7; 32], "test", b"custom-secret-key"));
    let one = request
        .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
        .unwrap();
    request.url = url("https://example.test/two");
    assert_eq!(
        one.key,
        request
            .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
            .unwrap()
            .key
    );
    assert_ne!(
        one.key,
        request
            .identity(tenant, run, "member", &BTreeMap::new(), 1)
            .unwrap()
            .key
    );
}
#[test]
fn metadata_schema_denies_sensitive_keys_and_non_bool_throttle_option() {
    let mut request = RequestEnvelopeV1::get(url("https://example.test/"), 0, None);
    request.metadata.insert("authorization".into(), json!("canary"));
    assert!(request.validate().is_err());
    request.metadata.clear();
    request
        .metadata
        .insert("autothrottle_dont_adjust_delay".into(), json!("true"));
    assert!(request.validate().is_err());
    request
        .metadata
        .insert("autothrottle_dont_adjust_delay".into(), json!(true));
    assert!(request.validate().is_ok());
}
#[test]
fn pinned_dialects_are_distinct_repeatable_and_never_keep_raw_source_keys() {
    let mut keys = std::collections::BTreeSet::new();
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let batch_id = Digest::keyed(&[7; 32], "test/import-batch", b"one");
    for (dialect, release, commit) in import::SOURCE_PINS {
        let source = json!({"version":1,"source":{"dialect":dialect,"release":release,"commit":commit},
            "requests":[{"url":"https://example.test/","sourceKey":"private-canary-key"}]});
        let bytes = serde_json::to_vec(&source).unwrap();
        let requests =
            import::decode_export(&bytes, &[7; 32], batch_id, |raw| Ok(url(raw.as_str()))).unwrap();
        assert_eq!(
            requests,
            import::decode_export(&bytes, &[7; 32], batch_id, |raw| Ok(url(raw.as_str()))).unwrap()
        );
        assert!(!serde_json::to_string(&requests)
            .unwrap()
            .contains("private-canary-key"));
        keys.insert(
            requests[0]
                .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
                .unwrap()
                .key,
        );
        let other = import::decode_export(&bytes, &[8; 32], batch_id, |raw| Ok(url(raw.as_str()))).unwrap();
        assert_ne!(requests[0].source_key, other[0].source_key);
    }
    assert_eq!(keys.len(), 4);
}

#[test]
fn all_pinned_dialects_preserve_head_and_separate_same_source_key_from_get() {
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let tenant_key = [7; 32];
    let batch_id = Digest::keyed(&tenant_key, "test/import-batch", b"head");
    for (dialect, release, commit) in import::SOURCE_PINS {
        let source = json!({"version":1,
        "source":{"dialect":dialect,"release":release,"commit":commit},
        "requests":[
            {"url":"https://example.test/","method":"GET","sourceKey":"same"},
            {"url":"https://example.test/","method":"HEAD","sourceKey":"same"},
            {"url":"https://example.test/","method":"HEAD","sourceKey":"same"}
        ]});
        let bytes = serde_json::to_vec(&source).unwrap();
        let requests =
            import::decode_export(&bytes, &tenant_key, batch_id, |raw| Ok(url(raw.as_str()))).unwrap();
        assert_eq!(requests[0].method, "GET", "{dialect}");
        assert_eq!(requests[1].method, "HEAD", "{dialect}");
        assert!(requests.iter().all(|request| request.body.is_none()));
        // Source dedupe remains authoritative within each method.
        assert_eq!(requests[0].source_key, requests[1].source_key);
        let get = requests[0]
            .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
            .unwrap();
        let head = requests[1]
            .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
            .unwrap();
        assert_ne!(get, head, "{dialect}");
        assert_eq!(
            get.key,
            Digest::of_value(
                "crawlx/imported-request-identity/v1",
                &(
                    &tenant,
                    &run,
                    "anonymous",
                    requests[0].dialect,
                    requests[0].source_key.unwrap(),
                    None::<u64>,
                    1_u32,
                )
            )
            .unwrap(),
            "{dialect}"
        );
        let restored: Vec<RequestEnvelopeV1> =
            serde_json::from_slice(&serde_json::to_vec(&requests).unwrap()).unwrap();
        assert_eq!(restored, requests, "{dialect}");
        assert_eq!(
            head,
            restored[1]
                .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
                .unwrap(),
            "{dialect}"
        );
        assert_eq!(
            head,
            requests[2]
                .identity(tenant, run, "anonymous", &BTreeMap::new(), 1)
                .unwrap(),
            "{dialect}"
        );
        let next_batch = Digest::keyed(&tenant_key, "test/import-batch", b"next");
        assert_eq!(
            requests,
            import::decode_export(&bytes, &tenant_key, next_batch, |raw| { Ok(url(raw.as_str())) }).unwrap(),
            "{dialect}"
        );
    }
}

#[test]
fn pinned_head_import_keeps_method_and_authority_restrictions() {
    let batch_id = Digest::keyed(&[7; 32], "test/import-batch", b"head");
    for (dialect, release, commit) in import::SOURCE_PINS {
        let mut source = json!({"version":1,
            "source":{"dialect":dialect,"release":release,"commit":commit},
            "requests":[{"url":"https://example.test/","method":"HEAD","sourceKey":"same"}]});
        for method in ["POST", "head", "get", "HEAD ", "OPTIONS"] {
            source["requests"][0]["method"] = json!(method);
            assert_eq!(
                import::decode_export(&serde_json::to_vec(&source).unwrap(), &[7; 32], batch_id, |raw| {
                    Ok(url(raw.as_str()))
                }),
                Err(import::ImportError::JournalRequired),
                "{dialect}: {method}"
            );
        }
        source["requests"][0]["method"] = json!("HEAD");
        for (field, value) in [
            ("body", json!("inline content")),
            ("headers", json!({"Authorization":"secret"})),
            ("headerControl", json!("credential")),
            ("sessionGeneration", json!(1)),
            ("principal", json!("member")),
        ] {
            let mut invalid = source.clone();
            invalid["requests"][0][field] = value;
            assert_eq!(
                import::decode_export(
                    &serde_json::to_vec(&invalid).unwrap(),
                    &[7; 32],
                    batch_id,
                    |raw| { Ok(url(raw.as_str())) }
                ),
                Err(import::ImportError::Format),
                "{dialect}: {field}"
            );
        }
    }
}
#[test]
fn python_always_enqueue_is_bounded_deterministic_and_conflicts_with_explicit_key() {
    let mut source = json!({"version":1,"source":{"dialect":"py_actor_1_11","release":"1.11.0", "commit":import::SOURCE_PINS[1].2},
        "requests":[{"url":"https://example.test/","sourceKey":"same","alwaysEnqueue":true},
                    {"url":"https://example.test/","sourceKey":"same","alwaysEnqueue":true}]});
    let batch_id = Digest::keyed(&[1; 32], "test/import-batch", b"one");
    let requests = import::decode_export(&serde_json::to_vec(&source).unwrap(), &[1; 32], batch_id, |raw| {
        Ok(url(raw.as_str()))
    })
    .unwrap();
    assert_ne!(requests[0].source_key, requests[1].source_key);
    source["requests"][0]["explicitKey"] = json!(true);
    assert!(matches!(
        import::decode_export(&serde_json::to_vec(&source).unwrap(), &[1; 32], batch_id, |raw| {
            Ok(url(raw.as_str()))
        },),
        Err(import::ImportError::DialectConflict)
    ));
}
#[test]
fn importer_rejects_code_opaque_objects_unknown_keys_and_incorrect_pins() {
    let batch_id = Digest::keyed(&[1; 32], "test/import-batch", b"one");
    for bytes in [b"pickle".as_slice(), b"import os", b"{\"callback\":\"eval\"}"] {
        assert!(import::decode_export(bytes, &[1; 32], batch_id, |raw| Ok(url(raw.as_str()))).is_err());
    }
    let source = json!({"version":1,"source":{"dialect":"python_spider_2_19","release":"2.19.0","commit":"wrong"},"requests":[]});
    assert!(matches!(
        import::decode_export(&serde_json::to_vec(&source).unwrap(), &[1; 32], batch_id, |raw| {
            Ok(url(raw.as_str()))
        },),
        Err(import::ImportError::SourcePin)
    ));
}

#[test]
fn imported_bypass_identity_is_batch_scoped_without_changing_normal_dedupe() {
    let tenant_key = [7; 32];
    let one = Digest::keyed(&tenant_key, "test/import-batch", b"one");
    let two = Digest::keyed(&tenant_key, "test/import-batch", b"two");
    for (pin, flag, method) in [
        (import::SOURCE_PINS[1], "alwaysEnqueue"),
        (import::SOURCE_PINS[2], "dontFilter"),
        (import::SOURCE_PINS[3], "allowUrlRevisit"),
    ]
    .into_iter()
    .flat_map(|(pin, flag)| ["GET", "HEAD"].map(|method| (pin, flag, method)))
    {
        let mut bypass = json!({"url":"https://example.test/","sourceKey":"same","method":method});
        bypass[flag] = json!(true);
        let normal = json!({"url":"https://example.test/","sourceKey":"same","method":method});
        let source = json!({"version":1,
            "source":{"dialect":pin.0,"release":pin.1,"commit":pin.2},
            "requests":[bypass.clone(),bypass,normal.clone(),normal]});
        let bytes = serde_json::to_vec(&source).unwrap();
        let first = import::decode_export(&bytes, &tenant_key, one, |raw| Ok(url(raw.as_str()))).unwrap();
        let retry = import::decode_export(&bytes, &tenant_key, one, |raw| Ok(url(raw.as_str()))).unwrap();
        let next = import::decode_export(&bytes, &tenant_key, two, |raw| Ok(url(raw.as_str()))).unwrap();
        assert_eq!(first, retry, "{}", pin.0);
        assert!(first.iter().all(|request| request.method == method));
        assert_ne!(first[0].source_key, first[1].source_key, "{}", pin.0);
        for index in 0..2 {
            assert_ne!(first[index].source_key, next[index].source_key, "{}", pin.0);
            assert_ne!(first[index].source_key, first[2].source_key, "{}", pin.0);
        }
        assert_eq!(first[2].source_key, first[3].source_key, "{}", pin.0);
        assert_eq!(first[2], next[2], "{}", pin.0);
    }
}

#[test]
fn import_batch_identity_does_not_bypass_row_or_byte_limits() {
    let tenant_key = [7; 32];
    let batch_id = Digest::keyed(&tenant_key, "test/import-batch", b"one");
    let pin = import::SOURCE_PINS[2];
    let row = json!({"url":"https://example.test/","sourceKey":"same","dontFilter":true});
    let mut source = json!({"version":1,
        "source":{"dialect":pin.0,"release":pin.1,"commit":pin.2},
        "requests":vec![row.clone(); MAX_REQUEST_BATCH]});
    let bytes = serde_json::to_vec(&source).unwrap();
    assert_eq!(
        import::decode_export(&bytes, &tenant_key, batch_id, |raw| Ok(url(raw.as_str())))
            .unwrap()
            .len(),
        MAX_REQUEST_BATCH
    );
    source["requests"].as_array_mut().unwrap().push(row);
    assert_eq!(
        import::decode_export(
            &serde_json::to_vec(&source).unwrap(),
            &tenant_key,
            batch_id,
            |raw| Ok(url(raw.as_str())),
        ),
        Err(import::ImportError::Limit)
    );
    assert_eq!(
        import::decode_export(
            &vec![b' '; MAX_REQUEST_BATCH_BYTES + 1],
            &tenant_key,
            batch_id,
            |raw| Ok(url(raw.as_str())),
        ),
        Err(import::ImportError::Limit)
    );
}
