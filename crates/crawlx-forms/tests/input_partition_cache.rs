//! Cache tests: same identity with different `(role, locale)` produces separate
//! entries; a model-version change invalidates them; keys are namespaced by tenant and run.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::hash::Digest;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::ids::{CrawlRunId, PrincipalId, TenantId};
use crawlx_forms::{FormCacheKey, FormClassificationCache, FormSemantics, ModelStamp};

const TENANT: TenantId = TenantId(uuid::Uuid::from_u128(0x11));
const RUN: CrawlRunId = CrawlRunId(uuid::Uuid::from_u128(0x22));

fn stamp(model_id: &str, model_version: &str, calibration_version: &str) -> ModelStamp {
    ModelStamp {
        model_id: model_id.to_owned(),
        model_version: model_version.to_owned(),
        calibration_version: calibration_version.to_owned(),
    }
}

fn key(element: &str, role: &str, locale: &str) -> FormCacheKey {
    FormCacheKey::new(
        TENANT,
        RUN,
        ElementIdentityHash(Digest::of("form-identity", element.as_bytes())),
        PrincipalId(role.to_owned()),
        locale,
    )
}

#[test]
fn same_identity_with_different_role_or_locale_is_a_separate_entry() {
    let mut cache = FormClassificationCache::new(stamp("decision-http", "1", "c1"));
    cache.insert(key("checkout", "member", "en-US"), FormSemantics::Contact, 0.9);
    cache.insert(key("checkout", "admin", "en-US"), FormSemantics::Search, 0.9);
    cache.insert(key("checkout", "member", "de-DE"), FormSemantics::Login, 0.9);
    assert_eq!(
        cache.len(),
        3,
        "three distinct (role, locale) entries for one identity"
    );
    assert_eq!(
        cache.get(&key("checkout", "member", "en-US")).unwrap().semantics,
        FormSemantics::Contact
    );
    assert_eq!(
        cache.get(&key("checkout", "admin", "en-US")).unwrap().semantics,
        FormSemantics::Search
    );
    assert_eq!(
        cache.get(&key("checkout", "member", "de-DE")).unwrap().semantics,
        FormSemantics::Login
    );
    // locale normalisation is part of the key, not a second entry
    cache.insert(key("checkout", "member", " en_us "), FormSemantics::Unknown, 0.1);
    assert_eq!(cache.len(), 3);
    assert_eq!(
        cache.get(&key("checkout", "member", "en-US")).unwrap().semantics,
        FormSemantics::Unknown
    );
    assert!(cache.get(&key("checkout", "guest", "en-US")).is_none());
    assert!(cache.get(&key("checkout", "member", "fr-FR")).is_none());
}

#[test]
fn model_version_change_misses_every_cached_entry() {
    let v1 = stamp("decision-http", "1", "c1");
    let mut cache = FormClassificationCache::new(v1.clone());
    for (element, role, locale) in [("a", "member", "en"), ("b", "admin", "en"), ("a", "member", "de")] {
        cache.insert(key(element, role, locale), FormSemantics::Contact, 0.9);
    }
    assert_eq!(cache.len(), 3);
    assert_eq!(cache.set_stamp(v1), 0, "the same stamp keeps every entry");
    assert_eq!(cache.len(), 3);

    // a new model version drops every entry: the next lookup is a miss and `advise` falls
    // back to the deterministic class
    let evicted = cache.set_stamp(stamp("decision-http", "2", "c1"));
    assert_eq!(evicted, 3);
    assert!(cache.is_empty());
    for (element, role, locale) in [("a", "member", "en"), ("b", "admin", "en"), ("a", "member", "de")] {
        assert!(cache.get(&key(element, role, locale)).is_none());
        assert_eq!(
            cache.advise(&key(element, role, locale), FormSemantics::Search),
            (FormSemantics::Search, false)
        );
    }

    // entries written under the new version carry the new stamp ...
    cache.insert(key("a", "member", "en"), FormSemantics::Contact, 0.9);
    assert_eq!(
        cache.get(&key("a", "member", "en")).unwrap().stamp.model_version,
        "2"
    );
    // ... and a model-id or calibration-version change invalidates just the same
    assert_eq!(cache.set_stamp(stamp("onnx-ranker", "2", "c1")), 1);
    cache.insert(key("a", "member", "en"), FormSemantics::Contact, 0.9);
    assert_eq!(cache.set_stamp(stamp("onnx-ranker", "2", "c2")), 1);
    assert!(cache.get(&key("a", "member", "en")).is_none());
}

#[test]
fn entries_are_namespaced_by_tenant_and_run() {
    let mut cache = FormClassificationCache::new(stamp("decision-http", "1", "c1"));
    cache.insert(key("checkout", "member", "en"), FormSemantics::Contact, 0.9);
    let mut other_tenant = key("checkout", "member", "en");
    other_tenant.tenant = TenantId(uuid::Uuid::from_u128(0x99));
    let mut other_run = key("checkout", "member", "en");
    other_run.run = CrawlRunId(uuid::Uuid::from_u128(0x99));
    assert!(
        cache.get(&other_tenant).is_none(),
        "another tenant never sees the entry"
    );
    assert!(
        cache.get(&other_run).is_none(),
        "another run never sees the entry"
    );
    assert_eq!(
        cache.advise(&other_tenant, FormSemantics::Search),
        (FormSemantics::Search, false)
    );
    assert!(cache.get(&key("checkout", "member", "en")).is_some());
    assert_eq!(cache.len(), 1);
}
