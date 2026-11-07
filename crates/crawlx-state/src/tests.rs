//! Behavioural tests: determinism, mask stability, clustering guards, splits, diff.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::testutil::{cluster_ids, orders_page, state_id, Page};
use crate::*;
use crawlx_core::hash::Digest;
use crawlx_core::observation::ObservationBundle;
use crawlx_core::state::{MaskReason, MaskSet, StateSignature};
use crawlx_core::url::RouteTemplate;
use crawlx_core::{ActionContextId, StateClusterId, Timestamp};

fn fp() -> Fingerprinter {
    Fingerprinter::default()
}

fn t0() -> Timestamp {
    Timestamp::default()
}

fn ctx(n: u8) -> ActionContextId {
    ActionContextId([n; 16])
}

fn outcome(route: &str) -> OutcomeClass {
    OutcomeClass {
        after_route_template: RouteTemplate(route.to_owned()),
        after_cluster_family: None,
        network_operation_digest: None,
        status_class: 2,
        unreliable: false,
    }
}

// ---------- fingerprint ----------

#[test]
fn fingerprint_is_deterministic() {
    let b = orders_page().page.bundle("/orders");
    let masks = MaskBuilder::build(&b, &[], &MaskConfig::default());
    let a = fp().fingerprint(&b, &masks);
    let c = fp().fingerprint(&b, &masks);
    assert_eq!(a, c);
    assert_eq!(a.exact_digest().unwrap(), c.exact_digest().unwrap());
    assert_eq!(a.semantic_affordance_minhash.len(), 128);
    assert_eq!(a.version, StateSignature::VERSION);
    assert!(a.visual_phash.is_none());
    assert!(a.browser_storage_digest.is_none());
}

#[test]
fn classified_view_values_partition_states_without_partitioning_resource_ids_or_secrets() {
    use crawlx_core::url::{ClassifiedParam, ParamClass};
    let page = orders_page().page;
    let bundle = |tab: &str, filter: &str, resource: &str, secret: &str| {
        let mut bundle = page.bundle("/orders");
        bundle.url.params = vec![
            ClassifiedParam {
                name: "id".into(),
                class: ParamClass::ResourceId,
                value: Some(resource.into()),
            },
            ClassifiedParam {
                name: "q".into(),
                class: ParamClass::Filter,
                value: Some(filter.into()),
            },
            ClassifiedParam {
                name: "sid".into(),
                class: ParamClass::Session,
                value: Some(secret.into()),
            },
            ClassifiedParam {
                name: "tab".into(),
                class: ParamClass::Navigation,
                value: Some(tab.into()),
            },
            ClassifiedParam {
                name: "utm_source".into(),
                class: ParamClass::Tracking,
                value: Some(secret.into()),
            },
        ];
        bundle.route = bundle.url.route_key();
        bundle
    };
    let first = bundle("open", "num", "hashed-resource-1", "session-1");
    let profile = fp().profile(&first, &MaskSet::default());
    assert_ne!(
        profile.signature.route_key,
        fp().fingerprint(
            &bundle("archived", "num", "hashed-resource-1", "session-1"),
            &MaskSet::default()
        )
        .route_key,
        "identical affordances do not erase a distinct native tab"
    );
    assert_ne!(
        profile.signature.route_key,
        fp().fingerprint(
            &bundle("open", "enum", "hashed-resource-1", "session-1"),
            &MaskSet::default()
        )
        .route_key,
        "classified filter buckets remain functional view state"
    );
    assert_eq!(
        profile.signature,
        fp().fingerprint(
            &bundle("open", "num", "hashed-resource-2", "session-2"),
            &MaskSet::default()
        ),
        "resource IDs and session/tracking values do not split state clusters"
    );
    let restored = crawlx_core::observation::FingerprintInput::from_bundle(&first).to_bundle();
    assert_eq!(
        profile.signature,
        fp().fingerprint(&restored, &MaskSet::default())
    );
    let mut index = ClusterIndex::with_id_source(cluster_ids());
    let old = attach(&mut index, 1, &profile);
    let other = fp().profile(
        &bundle("archived", "num", "hashed-resource-1", "session-1"),
        &MaskSet::default(),
    );
    assert_ne!(
        old.decision.cluster,
        attach(&mut index, 2, &other).decision.cluster
    );
}

#[test]
fn persisted_signature_versions_never_compare_or_attach_across_the_cutover() {
    let current = profile_of(&orders_page().page, "/orders");
    let mut old = current.signature.clone();
    old.version = StateSignature::VERSION - 1;
    let mut index = ClusterIndex::with_id_source(cluster_ids());
    index.restore(StateClusterId(uuid::Uuid::from_u128(99)), 1, old.clone(), 1);
    let prototype = Prototype {
        minhash_union: old.semantic_affordance_minhash.clone(),
        signature: old,
        consequence: None,
    };
    assert!(score(&current.signature, &prototype).abs() < f32::EPSILON);
    assert!(index.candidates(&current.signature).is_empty());
    assert!(attach(&mut index, 1, &current).decision.created_new);
}

#[test]
fn text_only_addition_changes_only_structure() {
    let a = orders_page().page.bundle("/orders");
    let mut moved = orders_page();
    moved.page.add(Some(moved.main), "paragraph", "Extra text block");
    let b = moved.page.bundle("/orders");
    let sa = fp().fingerprint(&a, &MaskSet::default());
    let sb = fp().fingerprint(&b, &MaskSet::default());
    // text-only addition: same affordances, same identities, only structure differs a little
    assert_eq!(sa.semantic_affordance_minhash, sb.semantic_affordance_minhash);
    assert_eq!(
        sa.visible_element_identity_digest,
        sb.visible_element_identity_digest
    );
    assert!(hamming(sa.dom_structure_simhash, sb.dom_structure_simhash) <= 6);
}

#[test]
fn digits_in_names_do_not_change_the_signature() {
    let signature = |clock: &str, paragraph: &str| {
        let mut p = orders_page();
        p.page.rename(p.clock, clock);
        p.page.rename(p.paragraph, paragraph);
        fp().fingerprint(&p.page.bundle("/orders"), &MaskSet::default())
    };
    let a = signature("Updated 7 minutes ago", "Showing 4 orders");
    let b = signature("Updated 12 minutes ago", "Showing 40 orders");
    assert_eq!(a, b);
    assert_ne!(a, signature("Updated yesterday", "Showing 4 orders"));
}

#[test]
fn route_network_frame_and_storage_signals() {
    let page = orders_page().page;
    let mut b = page.bundle("/orders");
    let base = fp().fingerprint(&b, &MaskSet::default());
    assert_ne!(
        base.route_key,
        fp().fingerprint(&page.bundle("/cart"), &MaskSet::default())
            .route_key
    );

    b.network.operations = vec!["POST /api/cart".into(), "GET /api/orders".into()];
    let n1 = fp().fingerprint(&b, &MaskSet::default());
    b.network.operations = vec![
        "GET /api/orders".into(),
        "POST /api/cart".into(),
        "GET /api/orders".into(),
    ];
    let n2 = fp().fingerprint(&b, &MaskSet::default());
    assert_ne!(base.network_operation_digest, n1.network_operation_digest);
    assert_eq!(
        n1.network_operation_digest, n2.network_operation_digest,
        "order and duplicates do not matter"
    );

    // storage names only count behind the privacy gate
    let extra = ExtraSignals {
        visual_phash: Some(0xAB),
        storage_names: vec!["theme".into(), "session_cookie".into()],
    };
    let off = Fingerprinter::new(FingerprintConfig {
        privacy_gate_storage: false,
    })
    .profile_with(&b, &MaskSet::default(), &extra);
    assert!(off.signature.browser_storage_digest.is_none());
    assert_eq!(off.signature.visual_phash, Some(0xAB));
    let on = Fingerprinter::new(FingerprintConfig {
        privacy_gate_storage: true,
    })
    .profile_with(&b, &MaskSet::default(), &extra);
    let d1 = on.signature.browser_storage_digest.unwrap();
    let swapped = ExtraSignals {
        storage_names: vec!["session_cookie".into(), "theme".into()],
        ..extra.clone()
    };
    let on2 = Fingerprinter::new(FingerprintConfig {
        privacy_gate_storage: true,
    })
    .profile_with(&b, &MaskSet::default(), &swapped);
    assert_eq!(Some(d1), on2.signature.browser_storage_digest);
    assert_ne!(d1, Digest::of("x", b""));
}

// ---------- masks ----------

#[test]
fn mask_stability_under_volatile_text() {
    let mut p = orders_page();
    let a = p.page.bundle("/orders");
    let masks = MaskBuilder::build(&a, &[], &MaskConfig::default());
    assert!(masks.reasons.contains(&MaskReason::ClockOrCounter));
    assert!(masks.reasons.contains(&MaskReason::LiveRegion));
    let sig_a = fp().fingerprint(&a, &masks);

    p.page.rename(p.clock, "Updated yesterday");
    p.page.rename(p.status, "Error: could not save");
    let b = p.page.bundle("/orders");
    let masks_b = MaskBuilder::build(&b, &[], &MaskConfig::default());
    assert_eq!(masks, masks_b, "node keys are stable across text changes");
    assert_eq!(
        sig_a,
        fp().fingerprint(&b, &masks),
        "masked change leaves the signature unchanged"
    );

    // the same change without masks is visible
    let none = MaskSet::default();
    assert_ne!(fp().fingerprint(&a, &none), fp().fingerprint(&b, &none));
}

#[test]
fn feed_tail_is_masked_and_length_independent() {
    let build = |n: usize| {
        let mut p = Page::default();
        let root = p.add(None, "RootWebArea", "Feed");
        let feed = p.add(Some(root), "feed", "Posts");
        for i in 0..n {
            let art = p.add(Some(feed), "article", "");
            p.add(
                Some(art),
                "link",
                &format!("Post title {}", if i < 20 { "x" } else { "tail" }),
            );
        }
        p.bundle("/feed")
    };
    let b30 = build(30);
    let b45 = build(45);
    let m30 = MaskBuilder::build(&b30, &[], &MaskConfig::default());
    let m45 = MaskBuilder::build(&b45, &[], &MaskConfig::default());
    assert_eq!(m30.masked_node_keys.len(), 10);
    assert_eq!(m45.masked_node_keys.len(), 25);
    assert!(m30.reasons.iter().all(|r| *r == MaskReason::FeedBeyondFirstPage));
    assert_eq!(fp().fingerprint(&b30, &m30), fp().fingerprint(&b45, &m45));
    // exactly the first page is not masked
    let b20 = build(20);
    assert!(MaskBuilder::build(&b20, &[], &MaskConfig::default())
        .masked_node_keys
        .is_empty());
    // the masked first page equals the 20-item page's affordances; unmasked it does not
    assert_eq!(
        fp().fingerprint(&b30, &m30).semantic_affordance_minhash,
        fp().fingerprint(&b20, &MaskSet::default())
            .semantic_affordance_minhash
    );
    assert_ne!(
        fp().fingerprint(&b30, &MaskSet::default())
            .semantic_affordance_minhash,
        fp().fingerprint(&b20, &MaskSet::default())
            .semantic_affordance_minhash
    );
}

#[test]
fn configured_selectors_and_hints_mask() {
    let p = orders_page();
    let b = p.page.bundle("/orders");
    let cfg = MaskConfig {
        configured: vec![
            MaskSelector {
                role: Some("BUTTON".into()),
                name_contains: Some("reorder".into()),
            },
            MaskSelector::default(), // matches nothing
        ],
        ..MaskConfig::default()
    };
    let m = MaskBuilder::build(&b, &[], &cfg);
    let configured = m.reasons.iter().filter(|r| **r == MaskReason::Configured).count();
    assert_eq!(configured, 8);

    let keys = MaskBuilder::node_keys(&b);
    let hint = VolatileHint {
        node_key: keys[p.paragraph],
        reason: MaskReason::ChangedWithoutAction,
    };
    let m2 = MaskBuilder::build(&b, std::slice::from_ref(&hint), &MaskConfig::default());
    assert!(m2.masked_node_keys.contains(&hint.node_key));
    // keys are sorted and parallel to reasons
    assert!(m2.masked_node_keys.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(m2.masked_node_keys.len(), m2.reasons.len());

    // disabling live-region masking leaves clock and status unmasked
    let off = MaskBuilder::build(
        &b,
        &[],
        &MaskConfig {
            live_regions: false,
            ..MaskConfig::default()
        },
    );
    assert!(off.masked_node_keys.is_empty());
}

#[test]
fn aria_live_property_masks_a_generic_region() {
    let mut p = orders_page();
    let idx = p.page.add(Some(p.main), "generic", "Toast");
    p.page.nodes[idx]
        .properties
        .insert("live".into(), "polite".into());
    let idx2 = p.page.add(Some(p.main), "generic", "Quiet");
    p.page.nodes[idx2].properties.insert("live".into(), "off".into());
    let b = p.page.bundle("/orders");
    let keys = MaskBuilder::node_keys(&b);
    let m = MaskBuilder::build(&b, &[], &MaskConfig::default());
    assert!(m.masked_node_keys.contains(&keys[idx]));
    assert!(!m.masked_node_keys.contains(&keys[idx2]));
}

#[test]
fn no_action_probe_finds_changed_nodes() {
    let mut p = orders_page();
    let first = p.page.bundle("/orders");
    p.page.rename(p.clock, "Updated 1 minute ago");
    let probe = p.page.bundle("/orders");
    let hints = MaskBuilder::probe_hints(&first, &probe);
    let keys = MaskBuilder::node_keys(&first);
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].node_key, keys[p.clock]);
    assert_eq!(hints[0].reason, MaskReason::ChangedWithoutAction);
    assert!(MaskBuilder::probe_hints(&first, &first).is_empty());
}

#[test]
fn node_keys_ignore_text_but_track_structure() {
    let mut p = orders_page();
    let before = MaskBuilder::node_keys(&p.page.bundle("/orders"));
    p.page.rename(p.paragraph, "totally different words");
    assert_eq!(before, MaskBuilder::node_keys(&p.page.bundle("/orders")));
    let unique: std::collections::BTreeSet<_> = before.iter().collect();
    assert_eq!(unique.len(), before.len(), "keys are unique per node");
}

// ---------- clustering ----------

fn attach(idx: &mut ClusterIndex, n: u128, profile: &StateProfile) -> Attachment {
    idx.attach(state_id(n), profile, &ClusterConfig::default())
}

fn profile_of(page: &Page, path: &str) -> StateProfile {
    let b = page.bundle(path);
    let masks = MaskBuilder::build(&b, &[], &MaskConfig::default());
    fp().profile(&b, &masks)
}

#[test]
fn near_identical_pages_attach() {
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let p = orders_page();
    let first = attach(&mut idx, 1, &profile_of(&p.page, "/orders"));
    assert!(first.decision.created_new);

    let mut q = orders_page();
    q.page.rename(q.paragraph, "Showing 4 orders");
    q.page.rename(q.clock, "Updated 9 minutes ago");
    q.page.rename(q.status, "Saved just now");
    let second = attach(&mut idx, 2, &profile_of(&q.page, "/orders"));
    assert!(!second.decision.created_new);
    assert_eq!(second.decision.cluster, first.decision.cluster);
    assert!(
        second.decision.similarity >= 0.90,
        "{}",
        second.decision.similarity
    );
    assert!(!second.review);
    assert_eq!(idx.active_len(), 1);
    assert_eq!(idx.get(first.decision.cluster).unwrap().size, 2);
}

#[test]
fn pages_on_different_routes_never_attach() {
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let p = orders_page();
    let a = profile_of(&p.page, "/orders");
    let b = profile_of(&p.page, "/invoices");
    assert_eq!(
        a.signature.semantic_affordance_minhash,
        b.signature.semantic_affordance_minhash
    );
    assert!(score(&b.signature, &Prototype::from_profile(&a)).abs() < f32::EPSILON);
    let first = attach(&mut idx, 1, &a);
    let second = attach(&mut idx, 2, &b);
    assert!(second.decision.created_new);
    assert_ne!(first.decision.cluster, second.decision.cluster);
    assert!(idx
        .candidates(&b.signature)
        .iter()
        .all(|(id, _)| *id != first.decision.cluster));
}

#[test]
fn false_merge_guard_extra_delete_button() {
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let p = orders_page();
    let base = profile_of(&p.page, "/orders");
    let first = attach(&mut idx, 1, &base);

    let mut q = orders_page();
    let form = q.main; // place the extra control inside the same list item region
    q.page.add(Some(form), "button", "Delete");
    let with_delete = profile_of(&q.page, "/orders");
    assert_ne!(base.consequence, with_delete.consequence);
    let second = attach(&mut idx, 2, &with_delete);
    assert!(
        second.decision.created_new,
        "extra consequence-bearing control must not merge"
    );
    assert_ne!(second.decision.cluster, first.decision.cluster);
    assert_eq!(idx.active_len(), 2);
}

#[test]
fn compatibility_veto_beats_a_high_score() {
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let base = profile_of(&orders_page().page, "/orders");
    let first = attach(&mut idx, 1, &base);

    // identical signature (score 1.0) but one more consequence-bearing affordance
    let mut sneaky = base.clone();
    sneaky.consequence.push(u64::MAX);
    let s = attach(&mut idx, 2, &sneaky);
    assert!(s.decision.created_new);
    assert!(s.vetoed);
    assert_eq!(s.near_of, Some(first.decision.cluster));
    assert!((s.decision.similarity - 1.0).abs() < 1e-4);

    // a *removed* consequence-bearing affordance is also refused
    let mut fewer = base.clone();
    fewer.consequence.pop();
    assert!(attach(&mut idx, 3, &fewer).decision.created_new);
}

#[test]
fn review_band_attaches_with_flag_and_low_scores_split() {
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let base = profile_of(&orders_page().page, "/orders");
    let first = attach(&mut idx, 1, &base);

    // identity digest differs: 1.0 - 0.15 = 0.85 -> review band
    let mut mid = base.clone();
    mid.signature.visible_element_identity_digest = Digest::of("t", b"other");
    let r = attach(&mut idx, 2, &mid);
    assert!(!r.decision.created_new);
    assert!(r.review);
    assert_eq!(r.decision.cluster, first.decision.cluster);
    assert!(
        (r.decision.similarity - 0.85).abs() < 1e-3,
        "{}",
        r.decision.similarity
    );

    // identity and frame digests differ: 0.80 boundary minus -> below review
    let mut low = base.clone();
    low.signature.visible_element_identity_digest = Digest::of("t", b"other2");
    low.signature.frame_tree_digest = Digest::of("t", b"frames");
    low.signature.dom_structure_simhash ^= 0b11_1111; // 6 bits: still passes the prefilter
    let l = attach(&mut idx, 3, &low);
    assert!(l.decision.created_new, "score {}", l.decision.similarity);
    assert!(!l.vetoed);
}

#[test]
fn simhash_prefilter_limits_candidates() {
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let base = profile_of(&orders_page().page, "/orders");
    attach(&mut idx, 1, &base);
    let mut near = base.signature.clone();
    near.dom_structure_simhash ^= 0b11_1111;
    assert_eq!(idx.candidates(&near).len(), 1);
    let mut far = base.signature.clone();
    far.dom_structure_simhash ^= 0b111_1111;
    assert!(idx.candidates(&far).is_empty());
}

#[test]
fn score_weights_and_route_gate() {
    let base = profile_of(&orders_page().page, "/orders");
    let proto = Prototype::from_profile(&base);
    assert!((score(&base.signature, &proto) - 1.0).abs() < 1e-4);
    let mut other = base.signature.clone();
    other.frame_tree_digest = Digest::of("t", b"f");
    assert!((score(&other, &proto) - 0.95).abs() < 1e-4);
    let mut diff_route = base.signature.clone();
    diff_route.route_key = Digest::of("t", b"elsewhere");
    assert!(score(&diff_route, &proto).abs() < f32::EPSILON);
    assert!((W_MINHASH + W_SIMHASH + W_IDENTITY + W_ROUTE + W_FRAME - 1.0).abs() < 1e-6);
}

#[test]
fn prototype_unions_minhash_and_keeps_first_signature() {
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let base = profile_of(&orders_page().page, "/orders");
    let first = attach(&mut idx, 1, &base);
    // decorative variation: same consequence set, enabled flag flips on a control
    let mut q = orders_page();
    q.page.nodes[q.list].disabled = false;
    let search_btn = q
        .page
        .nodes
        .iter()
        .position(|n| n.role == "button" && n.name.as_deref() == Some("Search"))
        .unwrap();
    q.page.nodes[search_btn].disabled = true;
    let variant = profile_of(&q.page, "/orders");
    assert_eq!(base.consequence, variant.consequence);
    assert_ne!(base.affordances, variant.affordances);
    let r = attach(&mut idx, 2, &variant);
    assert_eq!(
        r.decision.cluster, first.decision.cluster,
        "score {}",
        r.decision.similarity
    );
    let c = idx.get(first.decision.cluster).unwrap();
    assert_eq!(c.prototype.signature, base.signature);
    assert_ne!(
        c.prototype.minhash_union,
        base.signature.semantic_affordance_minhash
    );
    assert_eq!(c.members.len(), 2);
}

#[test]
fn cluster_ids_are_reproducible_with_an_id_source() {
    let run = || {
        let mut idx = ClusterIndex::with_id_source(cluster_ids());
        let p = orders_page();
        let a = attach(&mut idx, 1, &profile_of(&p.page, "/orders"))
            .decision
            .cluster;
        let b = attach(&mut idx, 2, &profile_of(&p.page, "/cart"))
            .decision
            .cluster;
        (a, b)
    };
    assert_eq!(run(), run());
    assert_eq!(run().0, StateClusterId(uuid::Uuid::from_u128(1)));
}

#[test]
fn restored_cluster_is_conservative() {
    let base = profile_of(&orders_page().page, "/orders");
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let id = StateClusterId(uuid::Uuid::from_u128(900));
    idx.restore(id, 3, base.signature.clone(), 10);
    let same = attach(&mut idx, 1, &base);
    assert_eq!(same.decision.cluster, id);
    assert_eq!(same.decision.decision_version, 3);
    assert_eq!(idx.get(id).unwrap().size, 11);

    let mut idx2 = ClusterIndex::with_id_source(cluster_ids());
    idx2.restore(id, 3, base.signature.clone(), 10);
    let mut changed = base.clone();
    changed.signature.visible_element_identity_digest = Digest::of("t", b"new identity");
    assert!(attach(&mut idx2, 2, &changed).decision.created_new);
}

// ---------- split ----------

/// A cluster of `n` identical states attached to one cluster.
fn cluster_of(n: u128) -> (ClusterIndex, StateClusterId) {
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let profile = profile_of(&orders_page().page, "/orders");
    let mut id = None;
    for i in 1..=n {
        id = Some(attach(&mut idx, i, &profile).decision.cluster);
    }
    (idx, id.unwrap())
}

#[test]
fn split_on_contradiction_creates_two_clusters_and_supersedes() {
    let (mut idx, id) = cluster_of(6);
    assert_eq!(idx.active_len(), 1);
    let cluster = idx.get(id).unwrap().clone();

    // members 1..=3 see outcome A, members 4..=5 see outcome B, member 6 unobserved
    let mut outcomes = Vec::new();
    for i in 1..=3u128 {
        outcomes.push((state_id(i), ctx(7), outcome("/ok")));
    }
    for i in 4..=5u128 {
        outcomes.push((state_id(i), ctx(7), outcome("/denied")));
    }
    let plan = Splitter::default()
        .check(&cluster, &outcomes)
        .expect("contradiction");
    assert_eq!(plan.source, id);
    assert_eq!(plan.evidence.action_context, ctx(7));
    assert_eq!(plan.evidence.total, 5);
    assert_eq!(plan.evidence.outcomes[0].1, 3);
    assert_eq!(plan.evidence.outcomes[1].1, 2);
    assert_eq!(
        plan.groups[0].len() + plan.groups[1].len(),
        6,
        "every member is placed"
    );
    let states = |g: &[Member]| g.iter().map(|m| m.state).collect::<Vec<_>>();
    assert!(states(&plan.groups[0]).starts_with(&[state_id(1), state_id(2), state_id(3)]));
    assert_eq!(states(&plan.groups[1]), vec![state_id(4), state_id(5)]);
    assert!(
        plan.groups[0].iter().any(|m| m.state == state_id(6)),
        "ties follow the dominant group"
    );

    let now = t0();
    let result = idx.split(&plan, now).unwrap();
    assert_eq!(result.clusters.len(), 2);
    assert_eq!(result.superseded.len(), 6);
    assert!(result
        .clusters
        .iter()
        .all(|c| c.version == 2 && c.near_of == Some(id)));
    assert!(result
        .superseded
        .iter()
        .all(|m| m.from_cluster == id && m.from_version == 1 && m.to_version == 2));
    assert!(result.superseded.iter().all(|m| m.decided_at == now));

    // old cluster stays queryable but is superseded; raw members still listed
    let old = idx.get(id).unwrap();
    assert!(!old.is_active());
    assert_eq!(old.members.len(), 6);
    assert_eq!(old.superseded_by.len(), 2);
    assert_eq!(idx.active_len(), 2);
    let sig = &old.prototype.signature;
    let cands = idx.candidates(sig);
    assert!(
        cands.iter().all(|(c, _)| *c != id),
        "superseded cluster leaves candidate lookup"
    );
    assert_eq!(cands.len(), 2);

    // plans are single-use against a version
    assert_eq!(idx.split(&plan, now), Err(StateError::AlreadySuperseded(id)));
}

#[test]
fn split_thresholds_ignore_noise() {
    let (idx, id) = cluster_of(12);
    let cluster = idx.get(id).unwrap();
    let splitter = Splitter::default();

    // one dissenting outcome (n = 1) never splits
    let mut noisy: Vec<_> = (1..=11u128)
        .map(|i| (state_id(i), ctx(1), outcome("/ok")))
        .collect();
    noisy.push((state_id(12), ctx(1), outcome("/odd")));
    assert!(splitter.check(cluster, &noisy).is_none());

    // 2 of 12 = 16.7% < 20% never splits
    let mut sparse: Vec<_> = (1..=10u128)
        .map(|i| (state_id(i), ctx(1), outcome("/ok")))
        .collect();
    sparse.push((state_id(11), ctx(1), outcome("/odd")));
    sparse.push((state_id(12), ctx(1), outcome("/odd")));
    assert!(splitter.check(cluster, &sparse).is_none());

    // 2 of 10 = 20% splits
    let mut edge: Vec<_> = (1..=8u128)
        .map(|i| (state_id(i), ctx(1), outcome("/ok")))
        .collect();
    edge.push((state_id(9), ctx(1), outcome("/odd")));
    edge.push((state_id(10), ctx(1), outcome("/odd")));
    assert!(splitter.check(cluster, &edge).is_some());

    // outcomes tagged settle_timeout/late are excluded
    let mut unreliable = edge.clone();
    for row in &mut unreliable[8..] {
        row.2.unreliable = true;
    }
    assert!(splitter.check(cluster, &unreliable).is_none());

    // contradictions only count within one action context
    let mixed = vec![
        (state_id(1), ctx(1), outcome("/ok")),
        (state_id(2), ctx(1), outcome("/ok")),
        (state_id(3), ctx(2), outcome("/other")),
        (state_id(4), ctx(2), outcome("/other")),
    ];
    assert!(splitter.check(cluster, &mixed).is_none());

    // outcomes of non-members are ignored
    let strangers = vec![
        (state_id(100), ctx(1), outcome("/a")),
        (state_id(101), ctx(1), outcome("/b")),
        (state_id(102), ctx(1), outcome("/b")),
    ];
    assert!(splitter.check(cluster, &strangers).is_none());
}

#[test]
fn stale_plan_is_rejected_and_unknown_cluster_errors() {
    let (mut idx, id) = cluster_of(4);
    let cluster = idx.get(id).unwrap().clone();
    let outcomes: Vec<_> = (1..=4u128)
        .map(|i| (state_id(i), ctx(1), outcome(if i <= 2 { "/a" } else { "/b" })))
        .collect();
    let mut plan = Splitter::default().check(&cluster, &outcomes).unwrap();
    plan.source_version = 9;
    assert!(matches!(
        idx.split(&plan, t0()),
        Err(StateError::StaleSplitPlan { .. })
    ));
    plan.source = StateClusterId(uuid::Uuid::from_u128(12345));
    assert_eq!(
        idx.split(&plan, t0()),
        Err(StateError::UnknownCluster(plan.source))
    );
}

#[test]
fn split_is_deterministic_and_prefers_larger_contradiction() {
    let (idx, id) = cluster_of(8);
    let cluster = idx.get(id).unwrap();
    let mut outcomes = Vec::new();
    // ctx 1: 2 vs 6 ; ctx 2: 3 vs 5 -> ctx 2 has the larger runner-up
    for i in 1..=8u128 {
        outcomes.push((state_id(i), ctx(1), outcome(if i <= 6 { "/a" } else { "/b" })));
        outcomes.push((state_id(i), ctx(2), outcome(if i <= 5 { "/a" } else { "/b" })));
    }
    let p1 = Splitter::default().check(cluster, &outcomes).unwrap();
    let p2 = Splitter::default().check(cluster, &outcomes).unwrap();
    assert_eq!(p1, p2);
    assert_eq!(p1.evidence.action_context, ctx(2));
    assert_eq!(p1.groups[0].len(), 5);
    assert_eq!(p1.groups[1].len(), 3);
}

// ---------- state-identity quality gates ----------

/// One labelled pair of the synthetic state-pair corpus: two bundles and whether they are
/// the same logical state.
struct LabelledPair {
    name: &'static str,
    a: Page,
    b: Page,
    route_b: &'static str,
    same: bool,
}

/// Builds the corpus: `same` pairs differ only in volatile text, counters, item ordinals,
/// feed-tail length or wrapper nodes; `different` pairs differ in route, in a
/// consequence-bearing control, in a landmark, in an open dialog or in the set of links.
fn state_pair_corpus() -> Vec<LabelledPair> {
    let mut corpus = Vec::new();
    let base = || orders_page();
    // ---- same ----
    for i in 0..6usize {
        let mut q = base();
        q.page
            .rename(q.clock, &format!("Updated {} minutes ago", i * 3 + 1));
        q.page.rename(
            q.status,
            [
                "Saved",
                "Saving…",
                "Saved just now",
                "All changes saved",
                "Synced",
                "Saved 2s ago",
            ][i],
        );
        q.page.rename(q.paragraph, &format!("Showing {} orders", 3 + i));
        corpus.push(LabelledPair {
            name: "volatile-text",
            a: base().page,
            b: q.page,
            route_b: "/orders",
            same: true,
        });
    }
    for i in 0..4usize {
        // Order numbers (digits) differ; the list has the same shape.
        let mut q = base();
        for n in &mut q.page.nodes {
            if n.role == "StaticText" {
                if let Some(name) = &n.name {
                    if let Some(rest) = name.strip_prefix("Order #") {
                        let num: usize = rest.parse().unwrap();
                        n.name = Some(format!("Order #{}", num + 1_000 * (i + 1)));
                    }
                }
            }
        }
        corpus.push(LabelledPair {
            name: "order-numbers",
            a: base().page,
            b: q.page,
            route_b: "/orders",
            same: true,
        });
    }
    for extra in [1usize, 2, 3] {
        // Wrapper nodes between main and the list (framework re-render).
        let mut q = base();
        let mut parent = q.main;
        for _ in 0..extra {
            parent = q.page.add(Some(parent), "generic", "");
        }
        let moved = q.page.add(Some(parent), "status", "Saved");
        q.page.nodes[q.status].role = "generic".to_owned();
        q.page.nodes[q.status].name = None;
        let _ = moved;
        corpus.push(LabelledPair {
            name: "wrappers",
            a: base().page,
            b: q.page,
            route_b: "/orders",
            same: true,
        });
    }
    for n in [30usize, 45, 60] {
        // A feed whose tail beyond the first page keeps growing.
        let feed = |n: usize| {
            let mut p = Page::default();
            let root = p.add(None, "RootWebArea", "Feed");
            let f = p.add(Some(root), "feed", "Posts");
            for i in 0..n {
                let art = p.add(Some(f), "article", "");
                p.add(
                    Some(art),
                    "link",
                    &format!("Post title {}", if i < 20 { "x" } else { "tail" }),
                );
            }
            p
        };
        corpus.push(LabelledPair {
            name: "feed-tail",
            a: feed(25),
            b: feed(n),
            route_b: "/feed",
            same: true,
        });
    }
    // ---- different ----
    for route in ["/invoices", "/orders/archive", "/cart"] {
        corpus.push(LabelledPair {
            name: "route",
            a: base().page,
            b: base().page,
            route_b: route,
            same: false,
        });
    }
    for label in ["Delete", "Cancel order", "Refund"] {
        let mut q = base();
        q.page.add(Some(q.main), "button", label);
        corpus.push(LabelledPair {
            name: "consequence-control",
            a: base().page,
            b: q.page,
            route_b: "/orders",
            same: false,
        });
    }
    for title in ["Confirm deletion", "Edit address", "Choose a plan"] {
        let mut q = base();
        let dialog = q.page.add(Some(0), "dialog", title);
        q.page.add(Some(dialog), "heading", title);
        q.page.add(Some(dialog), "button", "Confirm");
        q.page.add(Some(dialog), "button", "Cancel");
        corpus.push(LabelledPair {
            name: "dialog-open",
            a: base().page,
            b: q.page,
            route_b: "/orders",
            same: false,
        });
    }
    {
        // The search form is gone (logged-out variant of the page).
        let mut q = base();
        for n in &mut q.page.nodes {
            if n.role == "form"
                || n.role == "textbox"
                || (n.role == "button" && n.name.as_deref() == Some("Search"))
            {
                n.role = "generic".to_owned();
                n.name = None;
            }
        }
        corpus.push(LabelledPair {
            name: "form-removed",
            a: base().page,
            b: q.page,
            route_b: "/orders",
            same: false,
        });
    }
    for links in [
        ["Home", "Products", "Cart", "Sign in"],
        ["Dashboard", "Reports", "Billing", "Account"],
    ] {
        let mut q = base();
        let mut i = 0;
        for n in &mut q.page.nodes {
            if n.role == "link" && i < 4 {
                n.name = Some(links[i].to_owned());
                i += 1;
            }
        }
        corpus.push(LabelledPair {
            name: "nav-links",
            a: base().page,
            b: q.page,
            route_b: "/orders",
            same: false,
        });
    }
    {
        // Empty state: no orders at all.
        let mut q = base();
        for n in &mut q.page.nodes {
            if n.role == "listitem"
                || (n.role == "link" && n.name.as_deref() == Some("View order"))
                || (n.role == "button" && n.name.as_deref() == Some("Reorder"))
            {
                n.role = "generic".to_owned();
                n.name = None;
            }
        }
        q.page.rename(q.paragraph, "You have no orders yet");
        corpus.push(LabelledPair {
            name: "empty-state",
            a: base().page,
            b: q.page,
            route_b: "/orders",
            same: false,
        });
    }
    corpus
}

#[test]
fn state_pair_corpus_has_zero_false_merges_and_at_most_15_percent_false_splits() {
    let corpus = state_pair_corpus();
    let mut tp = 0usize;
    let mut fp_ = 0usize;
    let mut fn_ = 0usize;
    let mut tn = 0usize;
    let mut false_merges = Vec::new();
    let mut false_splits = Vec::new();
    for pair in &corpus {
        let mut idx = ClusterIndex::with_id_source(cluster_ids());
        let route_a = if pair.route_b == "/feed" {
            "/feed"
        } else {
            "/orders"
        };
        let first = attach(&mut idx, 1, &profile_of(&pair.a, route_a));
        let second = attach(&mut idx, 2, &profile_of(&pair.b, pair.route_b));
        let predicted_same = second.decision.cluster == first.decision.cluster;
        match (pair.same, predicted_same) {
            (true, true) => tp += 1,
            (true, false) => {
                fn_ += 1;
                false_splits.push((pair.name, second.decision.similarity));
            }
            (false, true) => {
                fp_ += 1;
                false_merges.push((pair.name, second.decision.similarity));
            }
            (false, false) => tn += 1,
        }
    }
    assert_eq!(tp + fp_ + fn_ + tn, corpus.len());
    assert!(corpus.iter().filter(|p| p.same).count() >= 10);
    assert!(corpus.iter().filter(|p| !p.same).count() >= 10);
    let precision = tp as f64 / (tp + fp_) as f64;
    let recall = tp as f64 / (tp + fn_) as f64;
    assert!(
        false_merges.is_empty(),
        "false merges (gate = 0): {false_merges:?}; precision {precision}"
    );
    assert!(
        recall >= 0.85,
        "recall {recall} < 0.85 (false-split rate > 15%, gate): {false_splits:?}"
    );
}

#[test]
fn split_conserves_every_member_and_the_cluster_size() {
    let n = 10u128;
    let (mut idx, id) = cluster_of(n);
    let cluster = idx.get(id).unwrap().clone();
    let before_size = cluster.size;
    let before_members: std::collections::BTreeSet<_> = cluster.members.iter().map(|m| m.state).collect();
    let outcomes: Vec<_> = (1..=n)
        .map(|i| {
            (
                state_id(i),
                ctx(3),
                outcome(if i % 3 == 0 { "/denied" } else { "/ok" }),
            )
        })
        .collect();
    let plan = Splitter::default()
        .check(&cluster, &outcomes)
        .expect("contradiction");
    let result = idx.split(&plan, t0()).unwrap();

    // Every member lands in exactly one new cluster; nothing is duplicated or dropped.
    let mut after_members = Vec::new();
    let mut after_size = 0u32;
    for c in &result.clusters {
        after_members.extend(c.members.iter().map(|m| m.state));
        after_size += c.size;
        assert_eq!(c.size as usize, c.members.len());
    }
    after_members.sort();
    let distinct: std::collections::BTreeSet<_> = after_members.iter().copied().collect();
    assert_eq!(after_members.len(), distinct.len(), "a member was placed twice");
    assert_eq!(
        distinct, before_members,
        "membership is conserved across the split"
    );
    assert_eq!(after_size, before_size, "total size is conserved");
    // The supersession records re-key every member exactly once, old version -> new version.
    assert_eq!(result.superseded.len(), usize::try_from(n).unwrap());
    let rekeyed: std::collections::BTreeSet<_> = result.superseded.iter().map(|m| m.state).collect();
    assert_eq!(rekeyed, before_members);
    assert!(result
        .superseded
        .iter()
        .all(|m| m.from_cluster == id && result.clusters.iter().any(|c| c.id == m.to_cluster)));
    // The old cluster keeps its raw members for audit but is no longer active.
    let old = idx.get(id).unwrap();
    assert!(!old.is_active());
    assert_eq!(old.members.len(), usize::try_from(n).unwrap());
    assert_eq!(idx.active_len(), 2);
    assert_eq!(
        idx.iter().filter(|c| c.is_active()).map(|c| c.size).sum::<u32>(),
        before_size
    );
}

// ---------- diff ----------

#[test]
fn diff_reports_added_removed_and_renamed() {
    let p = orders_page();
    let a = p.page.bundle("/orders");

    let same = StateDiff::between(&a, &a);
    assert!(same.added_affordances.is_empty() && same.removed_affordances.is_empty());
    assert!(same.changed_names.is_empty());
    assert!(same.novelty.abs() < f32::EPSILON);

    let mut q = orders_page();
    q.page.add(Some(q.main), "button", "Delete");
    let d = StateDiff::between(&a, &q.page.bundle("/orders"));
    assert_eq!(d.added_affordances, vec!["button|delete".to_owned()]);
    assert!(d.removed_affordances.is_empty());
    assert!(d.novelty > 0.0 && d.novelty <= 1.0);

    let mut r = orders_page();
    let search = r
        .page
        .nodes
        .iter()
        .position(|n| n.role == "button" && n.name.as_deref() == Some("Search"))
        .unwrap();
    r.page.rename(search, "Find");
    let d = StateDiff::between(&a, &r.page.bundle("/orders"));
    assert_eq!(d.changed_names.len(), 1);
    assert_eq!(d.changed_names[0].before, "Search");
    assert_eq!(d.changed_names[0].after, "Find");
    assert!(d.added_affordances.is_empty() && d.removed_affordances.is_empty());

    let reverse = StateDiff::between(&q.page.bundle("/orders"), &a);
    assert_eq!(reverse.removed_affordances, vec!["button|delete".to_owned()]);
    assert!(reverse.novelty.abs() < f32::EPSILON);
}

#[test]
fn diff_respects_masks() {
    let p = orders_page();
    let a = p.page.bundle("/orders");
    let mut q = orders_page();
    let idx = q.page.add(Some(q.main), "generic", "Toast");
    q.page.nodes[idx].focusable = true;
    q.page.nodes[idx]
        .properties
        .insert("live".into(), "polite".into());
    let b = q.page.bundle("/orders");
    let masks = MaskBuilder::build(&b, &[], &MaskConfig::default());
    let unmasked = StateDiff::between(&a, &b);
    assert_eq!(unmasked.added_affordances, vec!["generic|toast".to_owned()]);
    let masked = StateDiff::between_masked(&a, &MaskSet::default(), &b, &masks);
    assert!(masked.added_affordances.is_empty());
}

// ---------- structure ----------

#[test]
fn simhash_small_for_small_edits_large_for_different_pages() {
    let a = orders_page();
    let mut b = orders_page();
    b.page.add(Some(b.main), "link", "Export");
    let sa = fp().fingerprint(&a.page.bundle("/orders"), &MaskSet::default());
    let sb = fp().fingerprint(&b.page.bundle("/orders"), &MaskSet::default());
    assert!(hamming(sa.dom_structure_simhash, sb.dom_structure_simhash) <= 6);

    let mut other = Page::default();
    let root = other.add(None, "RootWebArea", "Other");
    let tabs = other.add(Some(root), "tablist", "");
    for i in 0..12 {
        let t = other.add(Some(tabs), "tab", &format!("Tab {i}"));
        other.add(Some(t), "image", "");
        other.add(Some(root), "table", "");
    }
    let so = fp().fingerprint(&other.bundle("/orders"), &MaskSet::default());
    assert!(hamming(sa.dom_structure_simhash, so.dom_structure_simhash) > 10);
}

#[test]
fn broken_parent_links_do_not_panic() {
    let mut p = orders_page();
    // dangling parent and a two-node cycle
    p.page.nodes[3].parent = Some(crawlx_core::AxNodeId("missing".into()));
    p.page.nodes[1].parent = Some(crawlx_core::AxNodeId("n2".into()));
    p.page.nodes[2].parent = Some(crawlx_core::AxNodeId("n1".into()));
    let b = p.page.bundle("/orders");
    let masks = MaskBuilder::build(&b, &[], &MaskConfig::default());
    let a = fp().fingerprint(&b, &masks);
    assert_eq!(a, fp().fingerprint(&b, &masks));
    assert_eq!(MaskBuilder::node_keys(&b).len(), b.ax.nodes.len());
}

#[test]
fn empty_bundle_fingerprints() {
    let b = Page::default().bundle("/blank");
    let s = fp().fingerprint(&b, &MaskSet::default());
    assert_eq!(s.dom_structure_simhash, 0);
    assert!(s
        .semantic_affordance_minhash
        .iter()
        .all(|x| *x == minhash::EMPTY_SLOT));
}

// ---------- performance (manual) ----------

/// 10k-node bundle; `cargo test -p crawlx-state --release -- --ignored --nocapture`.
#[test]
#[ignore = "timing measurement; run in release with --nocapture"]
fn fingerprint_10k_nodes_timing() {
    let mut p = Page::default();
    let root = p.add(None, "RootWebArea", "Big");
    let mut count = 1;
    let mut section = 0;
    while count < 10_000 {
        let sec = p.add(Some(root), "region", &format!("Section {section}"));
        count += 1;
        for i in 0..99 {
            let (role, name) = match i % 4 {
                0 => ("link", format!("Item link {}", i % 13)),
                1 => ("button", format!("Action {}", i % 7)),
                2 => ("paragraph", format!("Body text number {i}")),
                _ => ("StaticText", format!("Label {i}")),
            };
            p.add(Some(sec), role, &name);
            count += 1;
        }
        section += 1;
    }
    let b = p.bundle("/big");
    let masks = MaskBuilder::build(&b, &[], &MaskConfig::default());
    let f = fp();
    let mut samples: Vec<f64> = (0..60)
        .map(|_| {
            let t = std::time::Instant::now();
            let s = f.fingerprint(&b, &masks);
            std::hint::black_box(&s);
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    samples.sort_by(f64::total_cmp);
    let p50 = samples[samples.len() / 2];
    let p95 = samples[(samples.len() * 95) / 100];
    println!(
        "fingerprint {} nodes: p50 {p50:.2} ms, p95 {p95:.2} ms (target < 15 ms release)",
        b.ax.nodes.len()
    );
    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let profile = f.profile(&b, &masks);
    idx.attach(state_id(1), &profile, &ClusterConfig::default());
    let t = std::time::Instant::now();
    idx.attach(state_id(2), &profile, &ClusterConfig::default());
    println!("cluster decision: {:.3} ms", t.elapsed().as_secs_f64() * 1000.0);
    if !cfg!(debug_assertions) {
        assert!(p95 < 15.0, "p95 {p95} ms");
    }
}

/// Crawljax-style state equivalence over the raw, unmasked tree: the DOM string is the
/// pre-order `role|name|value` token stream and two observations are one state when the
/// token-level edit distance, normalized by the longer stream, is at most `threshold`
/// (Crawljax's default comparator is exact equality, `threshold = 0.0`). States are formed
/// greedily against the first representative that matches, like Crawljax's state machine.
fn crawljax_states(bundles: &[ObservationBundle], threshold: f64) -> usize {
    let tokens = |b: &ObservationBundle| -> Vec<u64> {
        b.ax.nodes
            .iter()
            .filter(|n| !n.ignored)
            .map(|n| {
                let mut h = crate::text::Hasher64::new();
                h.write_lower(&n.role);
                h.sep();
                h.write(n.name.as_deref().unwrap_or("").as_bytes());
                h.sep();
                h.write(n.value.as_deref().unwrap_or("").as_bytes());
                h.finish()
            })
            .collect()
    };
    let mut reps: Vec<Vec<u64>> = Vec::new();
    for b in bundles {
        let t = tokens(b);
        let known = reps.iter().any(|r| {
            if threshold <= 0.0 {
                return *r == t;
            }
            let longest = r.len().max(t.len()).max(1);
            if r.len().abs_diff(t.len()) as f64 / longest as f64 > threshold {
                return false;
            }
            token_edit_distance(r, &t) as f64 / longest as f64 <= threshold
        });
        if !known {
            reps.push(t);
        }
    }
    reps.len()
}

fn token_edit_distance(a: &[u64], b: &[u64]) -> usize {
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, x) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, y) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(x != y);
            cur[j + 1] = sub.min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Explosion guard on `feed-and-clock`: 300 observations (10 scroll pages of a
/// growing feed x 30 clock ticks each) stay within 5 clusters per 100 observations under
/// the masked fingerprint, while the Crawljax-style unmasked baseline exceeds that bound.
#[test]
fn feed_and_clock_stays_under_five_clusters_per_100_while_crawljax_baseline_explodes() {
    let build = |scroll_page: usize, tick: usize| {
        let mut p = Page::default();
        let root = p.add(None, "RootWebArea", "Feed");
        let banner = p.add(Some(root), "banner", "");
        p.add(Some(banner), "link", "Home");
        p.add(
            Some(banner),
            "timer",
            &format!("12:{:02}:{:02}", tick / 60, tick % 60),
        );
        let main = p.add(Some(root), "main", "");
        let status = p.add(Some(main), "status", "");
        p.rename(status, &format!("Updated {tick} seconds ago"));
        let feed = p.add(Some(main), "feed", "Posts");
        for i in 0..(10 * scroll_page) {
            let art = p.add(Some(feed), "article", "");
            p.add(Some(art), "link", &format!("Post title {i}"));
            p.add(
                Some(art),
                "StaticText",
                &format!("Body of post {i} with {} words", i * 7 % 11),
            );
            p.add(Some(art), "button", "Like");
        }
        p.add(Some(main), "button", "Load more");
        p.bundle("/feed")
    };
    let mut bundles = Vec::with_capacity(300);
    for scroll_page in 1..=10 {
        for tick in 0..30 {
            bundles.push(build(scroll_page, (scroll_page - 1) * 30 + tick));
        }
    }
    assert_eq!(bundles.len(), 300);

    let mut idx = ClusterIndex::with_id_source(cluster_ids());
    let cfg = ClusterConfig::default();
    let f = fp();
    for (n, b) in bundles.iter().enumerate() {
        let masks = MaskBuilder::build(b, &[], &MaskConfig::default());
        let profile = f.profile(b, &masks);
        idx.attach(state_id(n as u128 + 1), &profile, &cfg);
    }
    let masked = idx.active_len();
    let per_100 = masked as f64 / (bundles.len() as f64 / 100.0);
    let baseline_exact = crawljax_states(&bundles, 0.0);
    let baseline_5pct = crawljax_states(&bundles, 0.05);
    println!(
        "feed-and-clock: {} observations -> {masked} masked clusters ({per_100:.2} per 100); \
         Crawljax baseline exact {baseline_exact} ({:.2} per 100), edit-distance 5% {baseline_5pct} ({:.2} per 100)",
        bundles.len(),
        baseline_exact as f64 / (bundles.len() as f64 / 100.0),
        baseline_5pct as f64 / (bundles.len() as f64 / 100.0)
    );
    assert!(masked >= 1);
    assert!(
        per_100 <= 5.0,
        "{masked} clusters for {} observations",
        bundles.len()
    );
    assert!(
        baseline_exact as f64 / (bundles.len() as f64 / 100.0) > 5.0,
        "Crawljax baseline {baseline_exact} does not exceed the bound"
    );
    assert!(baseline_exact > masked);
    assert!(baseline_5pct > masked);
}
