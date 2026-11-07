//! Model-advisory form classification cache.
//!
//! Keyed by `(element identity, principal, locale)` rather than globally: the
//! same identity can carry different forms for different principals or locales.
//! Keys are namespaced by tenant and run: a cache shared by a
//! worker process never serves one tenant's or run's verdict to another.
//! Entries record the model stamp (`model_id`, `model_version`, calibration
//! version); any stamp change invalidates them. The deterministic result
//! always wins when the model disagrees, except that a model may raise a form
//! to external communication (never lower it): see [`FormSemantics::merge_advisory`].

use crate::classify::FormSemantics;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::ids::{CrawlRunId, PrincipalId, TenantId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Cache key `(tenant, run, ElementIdentityHash, PrincipalId, locale)`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct FormCacheKey {
    /// Tenant namespace.
    pub tenant: TenantId,
    /// Run namespace.
    pub run: CrawlRunId,
    /// Identity hash of the form element.
    pub element: ElementIdentityHash,
    /// Principal the form was observed under.
    pub principal: PrincipalId,
    /// BCP 47 tag, normalised to lower case with `-` separators.
    pub locale: String,
}

impl FormCacheKey {
    /// Build a key, normalising `locale` (trimmed, `_` to `-`, lower case).
    #[must_use]
    pub fn new(
        tenant: TenantId,
        run: CrawlRunId,
        element: ElementIdentityHash,
        principal: PrincipalId,
        locale: &str,
    ) -> Self {
        Self {
            tenant,
            run,
            element,
            principal,
            locale: locale.trim().replace('_', "-").to_ascii_lowercase(),
        }
    }
}

/// Identity of the model that produced entries.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct ModelStamp {
    /// Model identifier.
    pub model_id: String,
    /// Model version.
    pub model_version: String,
    /// Calibration version of the model's confidence output.
    pub calibration_version: String,
}

/// One cached advisory verdict.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct CachedFormClassification {
    /// Model that produced the verdict.
    pub stamp: ModelStamp,
    /// Semantics the model assigned to the form.
    pub semantics: FormSemantics,
    /// Calibrated model confidence.
    pub confidence: f32,
}

/// Ordered (`BTreeMap`) cache with stamp-based invalidation.
#[derive(Clone, PartialEq, Debug)]
pub struct FormClassificationCache {
    stamp: ModelStamp,
    entries: BTreeMap<FormCacheKey, CachedFormClassification>,
}

impl FormClassificationCache {
    /// Empty cache for the model identified by `stamp`.
    #[must_use]
    pub fn new(stamp: ModelStamp) -> Self {
        Self {
            stamp,
            entries: BTreeMap::new(),
        }
    }

    /// The model stamp entries must carry to be served.
    #[must_use]
    pub const fn stamp(&self) -> &ModelStamp {
        &self.stamp
    }

    /// Switch to a new model. When the stamp differs every entry is dropped
    /// and the number of evicted entries is returned; otherwise nothing changes.
    pub fn set_stamp(&mut self, stamp: ModelStamp) -> usize {
        if stamp == self.stamp {
            return 0;
        }
        self.stamp = stamp;
        let evicted = self.entries.len();
        self.entries.clear();
        evicted
    }

    /// Store a verdict from the current model.
    pub fn insert(&mut self, key: FormCacheKey, semantics: FormSemantics, confidence: f32) {
        self.entries.insert(
            key,
            CachedFormClassification {
                stamp: self.stamp.clone(),
                semantics,
                confidence,
            },
        );
    }

    /// The cached verdict, only if it was produced by the current model.
    #[must_use]
    pub fn get(&self, key: &FormCacheKey) -> Option<&CachedFormClassification> {
        self.entries.get(key).filter(|e| e.stamp == self.stamp)
    }

    /// Combine the deterministic class with any cached model verdict.
    /// Returns the effective semantics and whether the model disagreed.
    #[must_use]
    pub fn advise(&self, key: &FormCacheKey, deterministic: FormSemantics) -> (FormSemantics, bool) {
        match self.get(key) {
            Some(e) => FormSemantics::merge_advisory(deterministic, e.semantics),
            None => (deterministic, false),
        }
    }

    /// Drop and return the entry for `key`, if present.
    pub fn remove(&mut self, key: &FormCacheKey) -> Option<CachedFormClassification> {
        self.entries.remove(key)
    }

    /// Number of stored entries, including entries whose stamp no longer
    /// matches (those are only dropped by [`Self::set_stamp`]).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries in key order (deterministic).
    pub fn iter(&self) -> impl Iterator<Item = (&FormCacheKey, &CachedFormClassification)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::hash::Digest;

    fn stamp(v: &str) -> ModelStamp {
        ModelStamp {
            model_id: "decision-http".into(),
            model_version: v.into(),
            calibration_version: "c1".into(),
        }
    }

    const TENANT: TenantId = TenantId(uuid::Uuid::from_u128(1));
    const RUN: CrawlRunId = CrawlRunId(uuid::Uuid::from_u128(2));

    fn key(e: &str, p: &str, l: &str) -> FormCacheKey {
        FormCacheKey::new(
            TENANT,
            RUN,
            ElementIdentityHash(Digest::of("t", e.as_bytes())),
            PrincipalId(p.into()),
            l,
        )
    }

    #[test]
    fn keyed_by_identity_principal_and_locale() {
        let mut c = FormClassificationCache::new(stamp("1"));
        c.insert(key("form", "member", "en-US"), FormSemantics::Contact, 0.9);
        assert!(
            c.get(&key("form", "member", "en_us")).is_some(),
            "locale normalised"
        );
        assert!(c.get(&key("form", "admin", "en-US")).is_none());
        assert!(c.get(&key("form", "member", "de-DE")).is_none());
        assert!(c.get(&key("other", "member", "en-US")).is_none());
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn namespaced_by_tenant_and_run() {
        let mut c = FormClassificationCache::new(stamp("1"));
        c.insert(key("form", "member", "en"), FormSemantics::Contact, 0.9);
        let mut other_tenant = key("form", "member", "en");
        other_tenant.tenant = TenantId(uuid::Uuid::from_u128(9));
        let mut other_run = key("form", "member", "en");
        other_run.run = CrawlRunId(uuid::Uuid::from_u128(9));
        assert!(c.get(&other_tenant).is_none());
        assert!(c.get(&other_run).is_none());
        assert!(c.get(&key("form", "member", "en")).is_some());
    }

    #[test]
    fn model_version_change_invalidates() {
        let mut c = FormClassificationCache::new(stamp("1"));
        c.insert(key("a", "m", "en"), FormSemantics::Login, 0.8);
        c.insert(key("b", "m", "en"), FormSemantics::Search, 0.8);
        assert_eq!(c.set_stamp(stamp("1")), 0, "same stamp keeps entries");
        assert_eq!(c.len(), 2);
        assert_eq!(c.set_stamp(stamp("2")), 2);
        assert!(c.is_empty());
        assert!(c.get(&key("a", "m", "en")).is_none());
        c.insert(key("a", "m", "en"), FormSemantics::Login, 0.8);
        assert_eq!(c.get(&key("a", "m", "en")).unwrap().stamp.model_version, "2");
        // calibration or id changes invalidate as well
        let mut s = stamp("2");
        s.calibration_version = "c2".into();
        assert_eq!(c.set_stamp(s), 1);
    }

    #[test]
    fn advise_raises_but_never_lowers_external_communication() {
        let mut c = FormClassificationCache::new(stamp("1"));
        c.insert(key("a", "m", "en"), FormSemantics::Contact, 0.9);
        c.insert(key("b", "m", "en"), FormSemantics::Search, 0.9);
        assert_eq!(
            c.advise(&key("a", "m", "en"), FormSemantics::Search),
            (FormSemantics::Contact, true)
        );
        assert_eq!(
            c.advise(&key("b", "m", "en"), FormSemantics::Contact),
            (FormSemantics::Contact, true)
        );
        assert_eq!(
            c.advise(&key("zz", "m", "en"), FormSemantics::Login),
            (FormSemantics::Login, false)
        );
    }

    #[test]
    fn iteration_is_ordered() {
        let mut c = FormClassificationCache::new(stamp("1"));
        for e in ["c", "a", "b"] {
            c.insert(key(e, "m", "en"), FormSemantics::Unknown, 0.5);
        }
        let keys: Vec<_> = c.iter().map(|(k, _)| k.clone()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }
}
