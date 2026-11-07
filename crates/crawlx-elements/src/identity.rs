//! `ElementIdentityV1` construction and the
//! collision/split metrics used by identity fixtures.

use std::collections::{BTreeMap, BTreeSet};

use crawlx_core::identity::{ElementIdentityHash, ElementIdentityV1};
use crawlx_core::observation::ObservedDescriptor;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use unicode_normalization::UnicodeNormalization;

use crate::normalize::{
    collapse_ws, container_signature, control_type, label_signature, normalize_accessible_name,
    stable_ancestor_role_path, truncate_chars, MAX_NAME_CHARS,
};
use crate::ElementsError;

/// Locale-aware V2 identity. Components retain V1's evidence schema, but names use
/// the page language and hashes use a separate domain.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct ElementIdentityV2 {
    /// Identity evidence with locale-normalized names.
    pub components: ElementIdentityV1,
}

impl ElementIdentityV2 {
    /// Version tag included in every V2 hash.
    pub const DOMAIN: &'static str = "crawlx/element-identity/v2";

    /// Hash the complete evidence under the V2 domain.
    ///
    /// # Errors
    /// Returns an encoding error when canonical CBOR serialization fails.
    pub fn hash(&self) -> Result<ElementIdentityHash, ElementsError> {
        crawlx_core::hash::Digest::of_value(Self::DOMAIN, &self.components)
            .map(ElementIdentityHash)
            .map_err(|e| ElementsError::Hash(Box::new(e)))
    }
}

/// Builds durable identities from descriptors.
pub struct IdentityBuilder;

impl IdentityBuilder {
    /// Identity of `desc`. `destination_key` is the link destination from
    /// [`Self::destination_key`] (links only; pass `None` otherwise).
    ///
    /// The name falls back to the DOM text when the AX name is absent, so a
    /// listener-only `div` still has a label to hash. A name that normalization
    /// empties entirely (`"2024"`, `"42"`) is the control's whole semantics, so
    /// the identity keeps it verbatim (NFKC, lowercased, whitespace collapsed)
    /// rather than colliding every such sibling onto the empty name; counters
    /// inside a name (`"Cart (3)"`) are still stripped.
    #[must_use]
    pub fn build(desc: &ObservedDescriptor, destination_key: Option<String>) -> ElementIdentityV1 {
        let name = desc
            .accessible_name
            .as_deref()
            .or(desc.text.as_deref())
            .unwrap_or("");
        ElementIdentityV1 {
            frame_lineage: desc.frame_lineage.clone(),
            role: desc.role.trim().to_ascii_lowercase(),
            normalized_accessible_name: identity_name(name),
            stable_ancestor_role_path: stable_ancestor_role_path(&desc.ancestor_roles),
            container_signature: container_signature(desc.container_text.as_deref()),
            destination_key,
            label_signature: label_signature(&desc.role, desc.tag.as_deref(), &desc.attributes),
            control_type: control_type(desc.tag.as_deref(), &desc.attributes),
        }
    }

    /// Build V2 from V1's evidence and the page's BCP-47 `lang`.
    /// Unknown or missing languages retain language-agnostic normalization.
    #[must_use]
    pub fn build_v2(
        desc: &ObservedDescriptor,
        destination_key: Option<String>,
        lang: &str,
    ) -> ElementIdentityV2 {
        let mut components = Self::build(desc, destination_key);
        let raw = desc
            .accessible_name
            .as_deref()
            .or(desc.text.as_deref())
            .unwrap_or("");
        let name = crate::normalize::normalize_accessible_name_v2(raw, lang);
        components.normalized_accessible_name = if name.is_empty() {
            collapse_ws(&raw.nfkc().collect::<String>().to_lowercase())
        } else {
            name
        };
        ElementIdentityV2 { components }
    }

    /// Destination key of a link-like descriptor: its `href` resolved against
    /// `base` (the page URL), canonicalized with parameter classification and
    /// keyed by `crawlx_url::destination_key`. `None` for non-links, links
    /// without `href`, and non-HTTP(S) targets (`mailto:`, `javascript:`).
    #[must_use]
    pub fn destination_key(
        desc: &ObservedDescriptor,
        base: &url::Url,
        opts: &CanonicalizeOptions,
    ) -> Option<String> {
        if !is_link_like(desc) {
            return None;
        }
        let href = desc.href.as_deref()?;
        let canonical = Canonicalizer::canonicalize(href, base, opts).ok()?;
        Some(crawlx_url::destination_key(&canonical))
    }

    /// Hash of an identity (`BLAKE3` over canonical CBOR, domain
    /// `crawlx/element-identity/v1`).
    ///
    /// # Errors
    /// [`ElementsError::Hash`] when the canonical CBOR encoding of `identity`
    /// fails (not expected for in-memory writers).
    pub fn hash(identity: &ElementIdentityV1) -> Result<ElementIdentityHash, ElementsError> {
        identity.hash().map_err(|e| ElementsError::Hash(Box::new(e)))
    }
}

/// [`normalize_accessible_name`], falling back to the verbatim (NFKC, lowercased,
/// whitespace-collapsed) name when normalization strips everything.
fn identity_name(raw: &str) -> String {
    let normalized = normalize_accessible_name(raw);
    if normalized.is_empty() {
        let verbatim = collapse_ws(&raw.nfkc().collect::<String>().to_lowercase());
        return truncate_chars(&verbatim, MAX_NAME_CHARS);
    }
    normalized
}

/// Links get destination keys: `a`/`area` with `href`, or role `link`.
#[must_use]
pub fn is_link_like(desc: &ObservedDescriptor) -> bool {
    desc.role.eq_ignore_ascii_case("link")
        || matches!(
            desc.tag.as_deref().map(str::to_ascii_lowercase).as_deref(),
            Some("a" | "area")
        )
}

/// `(collision_rate, split_rate)` over labelled fixtures.
///
/// `truth` pairs the identity hash assigned to an observation with the
/// logical control it really was. Both rates are fractions of the distinct
/// logical controls:
///
/// * collision: logical controls whose hash is shared with a *different*
///   logical control (a collision may hide a reachable action);
/// * split: logical controls observed under more than one hash.
///
/// Empty input yields `(0.0, 0.0)`.
#[must_use]
pub fn rates<L: Ord>(truth: &[(ElementIdentityHash, L)]) -> (f64, f64) {
    let mut by_logical: BTreeMap<&L, BTreeSet<ElementIdentityHash>> = BTreeMap::new();
    let mut by_hash: BTreeMap<ElementIdentityHash, BTreeSet<&L>> = BTreeMap::new();
    for (h, l) in truth {
        by_logical.entry(l).or_default().insert(*h);
        by_hash.entry(*h).or_default().insert(l);
    }
    let total = by_logical.len();
    if total == 0 {
        return (0.0, 0.0);
    }
    let collided = by_logical
        .values()
        .filter(|hashes| {
            hashes
                .iter()
                .any(|h| by_hash.get(h).is_some_and(|ls| ls.len() > 1))
        })
        .count();
    let split = by_logical.values().filter(|hashes| hashes.len() > 1).count();
    (collided as f64 / total as f64, split as f64 / total as f64)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::ladder::{CandidateDiscovery, DiscoveryConfig};
    use crate::testutil::{attrs, card_page, descriptor, page_url};
    use crawlx_core::observation::ObservedDescriptor;

    #[test]
    fn v2_locale_names_are_stable_and_domains_never_overlap() {
        for (language, names, stable) in [
            (
                "fr-FR",
                [
                    "Messages il y a 3 minutes 1\u{202f}234 20 octobre 2026",
                    "Messages il y a 15 heures ９,８７６ 21 novembre 2027",
                ],
                "messages",
            ),
            (
                "de-DE",
                [
                    "Nachrichten vor 3 Minuten 1.234 20. Oktober 2026",
                    "Nachrichten vor 15 Stunden ９.８７６ 21. November 2027",
                ],
                "nachrichten",
            ),
            (
                "es-ES",
                [
                    "Mensajes hace 3 minutos 1.234 20 de octubre de 2026",
                    "Mensajes hace 15 horas ９.８７６ 21 de noviembre de 2027",
                ],
                "mensajes",
            ),
        ] {
            let a = descriptor("button", names[0]);
            let b = descriptor("button", names[1]);
            let first = IdentityBuilder::build_v2(&a, None, language);
            let second = IdentityBuilder::build_v2(&b, None, language);
            assert_eq!(first.components.normalized_accessible_name, stable);
            assert_eq!(first.hash().unwrap(), second.hash().unwrap());
        }
        let d = descriptor("button", "Save");
        let v1 = IdentityBuilder::build(&d, None);
        let v2 = IdentityBuilder::build_v2(&d, None, "fr");
        assert_eq!(v1, v2.components);
        assert_ne!(v1.hash().unwrap(), v2.hash().unwrap());
    }

    #[test]
    fn v1_replay_and_v2_index_never_cross_version_boundary() {
        use crate::{IdentityResolver, InMemoryIdentityIndex, MatchDecision, MatchWeights};
        use crawlx_core::config::IdentityVersion;
        let d = descriptor("button", "Save");
        let v1 = IdentityResolver::new();
        let v2 = IdentityResolver::new().with_identity_version(IdentityVersion::V2, "fr");
        assert!(!v2.accepts_replay_version(1));
        assert!(!v1.accepts_replay_version(2));
        let mut index = InMemoryIdentityIndex::new();
        let known = v1.resolve(&d, &index, &MatchWeights::default()).unwrap();
        index.record(&known);
        let result = v2.resolve(&d, &index, &MatchWeights::default()).unwrap();
        assert_eq!(result.version, 2);
        assert!(matches!(
            result.decision,
            MatchDecision::MintedNew { alias: None, .. }
        ));
        assert_ne!(known.hash, result.hash);
    }

    fn hashes(page: &crate::testutil::Page) -> Vec<ElementIdentityHash> {
        CandidateDiscovery::discover(&page.bundle, &DiscoveryConfig::default())
            .iter()
            .map(|c| IdentityBuilder::hash(&IdentityBuilder::build(&c.descriptor, None)).unwrap())
            .collect()
    }

    fn base() -> ObservedDescriptor {
        let mut d = descriptor("button", "Add to cart (3)");
        d.tag = Some("button".into());
        d.attributes = attrs(&[("type", "button"), ("id", "add-3")]);
        d.ancestor_roles = ["RootWebArea", "main", "list", "listitem"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        d.container_text = Some("heading|Blue Widget".into());
        d.frame_lineage = vec!["f1".into()];
        d
    }

    fn link(href: &str) -> ObservedDescriptor {
        let mut d = descriptor("link", "View invoice");
        d.tag = Some("a".into());
        d.href = Some(href.into());
        d.attributes = attrs(&[("href", href)]);
        d
    }

    fn dest(d: &ObservedDescriptor) -> Option<String> {
        IdentityBuilder::destination_key(d, &page_url(), &CanonicalizeOptions::default())
    }

    /// Pinned so that any change to normalization or encoding shows up in review.
    const GOLDEN_BUTTON: &str = "4b747932d0046eaf2568c3ebff24d10fa06f1875380312f7c359cc10ec832f3b";
    const GOLDEN_LINK: &str = "1e7f09502fcfd863f3942dd6cc61893ef2da3914820108acc0dae00fffac3120";

    #[test]
    fn identity_fields() {
        let id = IdentityBuilder::build(&base(), None);
        assert_eq!(id.frame_lineage, vec!["f1".to_owned()]);
        assert_eq!(id.role, "button");
        assert_eq!(id.normalized_accessible_name, "add to cart");
        assert_eq!(id.stable_ancestor_role_path, vec!["main", "list", "listitem"]);
        assert_eq!(id.container_signature.as_deref(), Some("heading"));
        assert_eq!(id.destination_key, None);
        assert_eq!(id.label_signature, None);
        assert_eq!(id.control_type.as_deref(), Some("button"));
    }

    #[test]
    fn golden_hashes() {
        let b = IdentityBuilder::hash(&IdentityBuilder::build(&base(), None)).unwrap();
        assert_eq!(b.to_string(), GOLDEN_BUTTON);
        let l = link("/invoice/41");
        let key = dest(&l);
        assert_eq!(key.as_deref(), Some("https://shop.example/invoice/:id"));
        let h = IdentityBuilder::hash(&IdentityBuilder::build(&l, key)).unwrap();
        assert_eq!(h.to_string(), GOLDEN_LINK);
    }

    #[test]
    fn wrappers_and_counters_leave_hash_unchanged() {
        let plain = hashes(&card_page(&["Blue Widget", "Red Widget"], 0, 3));
        let wrapped = hashes(&card_page(&["Blue Widget", "Red Widget"], 5, 3));
        let counted = hashes(&card_page(&["Blue Widget", "Red Widget"], 0, 4711));
        assert_eq!(plain, wrapped);
        assert_eq!(plain, counted);
        // repeated template: every card shares one identity regardless of its title
        assert_eq!(plain[0], plain[1]);
    }

    #[test]
    fn names_that_are_only_a_number_keep_the_number() {
        // counters inside a name are still stripped (digits-only changes are no change)
        let mut a = base();
        a.accessible_name = Some("Cart (3)".into());
        let mut b = base();
        b.accessible_name = Some("Cart (12)".into());
        assert_eq!(
            IdentityBuilder::build(&a, None).normalized_accessible_name,
            "cart"
        );
        assert_eq!(
            IdentityBuilder::hash(&IdentityBuilder::build(&a, None)).unwrap(),
            IdentityBuilder::hash(&IdentityBuilder::build(&b, None)).unwrap()
        );
        // a name that is nothing but a number is the control's whole label (year tabs,
        // pagination): siblings must not collide on the empty name
        let mut y1 = base();
        y1.accessible_name = Some(" ２０２４ ".into());
        let mut y2 = base();
        y2.accessible_name = Some("2025".into());
        assert_eq!(
            IdentityBuilder::build(&y1, None).normalized_accessible_name,
            "2024"
        );
        assert_ne!(
            IdentityBuilder::hash(&IdentityBuilder::build(&y1, None)).unwrap(),
            IdentityBuilder::hash(&IdentityBuilder::build(&y2, None)).unwrap()
        );
        assert_eq!(identity_name(""), "");
    }

    #[test]
    fn real_differences_change_the_hash() {
        let h0 = IdentityBuilder::hash(&IdentityBuilder::build(&base(), None)).unwrap();
        let mut d = base();
        d.role = "link".into();
        assert_ne!(
            h0,
            IdentityBuilder::hash(&IdentityBuilder::build(&d, None)).unwrap()
        );
        let mut d = base();
        d.accessible_name = Some("Remove from cart".into());
        assert_ne!(
            h0,
            IdentityBuilder::hash(&IdentityBuilder::build(&d, None)).unwrap()
        );
        let mut d = base();
        d.ancestor_roles.push("dialog".into());
        assert_ne!(
            h0,
            IdentityBuilder::hash(&IdentityBuilder::build(&d, None)).unwrap()
        );
        let mut d = base();
        d.container_text = Some("dialog|Checkout".into());
        assert_ne!(
            h0,
            IdentityBuilder::hash(&IdentityBuilder::build(&d, None)).unwrap()
        );
        let mut d = base();
        d.frame_lineage = vec!["f2".into()];
        assert_ne!(
            h0,
            IdentityBuilder::hash(&IdentityBuilder::build(&d, None)).unwrap()
        );
        let mut d = base();
        d.attributes.insert("type".into(), "submit".into());
        assert_ne!(
            h0,
            IdentityBuilder::hash(&IdentityBuilder::build(&d, None)).unwrap()
        );
        // the instance ordinal and the durable id are not identity
        let mut d = base();
        d.instance_ordinal = 7;
        d.attributes.insert("id".into(), "other".into());
        assert_eq!(
            h0,
            IdentityBuilder::hash(&IdentityBuilder::build(&d, None)).unwrap()
        );
    }

    #[test]
    fn destination_key_follows_template_and_class() {
        let a = link("/invoice/41");
        let b = link("/invoice/42");
        let c = link("/receipt/41");
        assert_eq!(dest(&a), dest(&b), "resource-id slot is templated");
        assert_ne!(dest(&a), dest(&c), "different route, different destination");
        let hash =
            |d: &ObservedDescriptor| IdentityBuilder::hash(&IdentityBuilder::build(d, dest(d))).unwrap();
        assert_eq!(hash(&a), hash(&b));
        assert_ne!(hash(&a), hash(&c));
        // tracking parameters never reach the key
        assert_eq!(dest(&link("/invoice/41?utm_source=mail")), dest(&a));
    }

    #[test]
    fn destination_key_only_for_http_links() {
        assert_eq!(dest(&link("mailto:a@b.example")), None);
        assert_eq!(dest(&link("javascript:void(0)")), None);
        assert_eq!(dest(&base()), None);
        let mut no_href = link("/x");
        no_href.href = None;
        assert_eq!(dest(&no_href), None);
    }

    #[test]
    fn collision_and_split_rates() {
        let h =
            |s: &str| IdentityBuilder::hash(&IdentityBuilder::build(&descriptor("button", s), None)).unwrap();
        let (a, b) = (h("alpha"), h("beta"));
        assert_eq!(rates::<&str>(&[]), (0.0, 0.0));
        // two logical controls, distinct hashes, stable
        assert_eq!(rates(&[(a, "x"), (b, "y"), (a, "x"), (b, "y")]), (0.0, 0.0));
        // collision: x and y share a hash
        assert_eq!(rates(&[(a, "x"), (a, "y")]), (1.0, 0.0));
        // split: x seen under two hashes (1 of 2 logical controls)
        assert_eq!(rates(&[(a, "x"), (b, "x"), (b, "y")]), (1.0, 0.5));
        // 1 split among 4 logical controls
        let c = h("gamma");
        let d = h("delta");
        let (col, split) = rates(&[(a, "w"), (b, "x"), (c, "y"), (d, "z"), (a, "w"), (c, "x")]);
        assert!((split - 0.25).abs() < 1e-9);
        assert!(col > 0.0);
    }
}
