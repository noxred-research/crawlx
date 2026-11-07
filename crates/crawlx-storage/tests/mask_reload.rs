//! Mask reproducibility: a state's signature recomputed from its stored AX
//! artifact plus its stored mask set is bit-identical to the signature persisted with the
//! state. Offline and deterministic: the bundle is synthetic, the stores are the in-memory
//! and filesystem artifact stores.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Utc;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::observation::{
    AxNode, BoundingBox, DomNodeSupplement, FrameInfo, ObservationBundle, RuntimeLocator,
};
use crawlx_core::repo::{ArtifactStore, NewState, RunRepo, Sensitivity, StateRepo};
use crawlx_core::state::{MaskReason, MaskSet, StateSignature};
use crawlx_core::time::ManualClock;
use crawlx_core::url::{CanonicalUrl, RouteTemplate};
use crawlx_core::{
    ArtifactRef, AxNodeId, BackendNodeId, FrameId, SessionId, StateClusterId, StateId, TabId, TenantId,
    WorkerId,
};
use crawlx_state::{Fingerprinter, MaskBuilder, MaskConfig, StateProfile, MASK_VERSION};
use crawlx_storage::artifacts::{FsArtifactStore, MemoryArtifactStore};
use crawlx_storage::ax_artifact::{AxArtifact, ARTIFACT_CONTENT_TYPE, AX_ARTIFACT_KIND, MASKS_ARTIFACT_KIND};
use crawlx_storage::testkit::{crawl_run, create_crawl, sessions};
use crawlx_storage::{LeaseRepo, MemoryStore};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Incremental AX tree builder (the `crawlx-state` test fixture shape).
#[derive(Default)]
struct Page {
    nodes: Vec<AxNode>,
}

impl Page {
    fn add(&mut self, parent: Option<usize>, role: &str, name: &str) -> usize {
        let idx = self.nodes.len();
        let id = i64::try_from(idx).unwrap() + 1;
        self.nodes.push(AxNode {
            locator: RuntimeLocator {
                tab: TabId("tab-1".into()),
                frame: FrameId("frame-main".into()),
                backend_node_id: BackendNodeId(id),
                object_id: None,
                ax_node_id: Some(AxNodeId(format!("ax{idx}"))),
                epoch: ObservationEpoch {
                    navigation_seq: 1,
                    document_seq: 1,
                    mutation_seq: 7,
                },
            },
            role: role.to_owned(),
            name: (!name.is_empty()).then(|| name.to_owned()),
            description: None,
            value: None,
            ignored: false,
            focusable: false,
            disabled: false,
            expanded: None,
            checked: None,
            properties: BTreeMap::new(),
            parent: parent.map(|p| AxNodeId(format!("ax{p}"))),
            children: Vec::new(),
            bbox: Some(BoundingBox {
                x: 0.0,
                y: 10.0 * idx as f64,
                width: 300.0,
                height: 20.0,
            }),
        });
        if let Some(p) = parent {
            self.nodes[p].children.push(AxNodeId(format!("ax{idx}")));
        }
        idx
    }
}

/// A page with every mask source and every signature input: a clock, a live status, a
/// 25-item feed (tail masked), a listening generic control, an iframe and network ops.
fn bundle() -> ObservationBundle {
    let mut p = Page::default();
    let root = p.add(None, "RootWebArea", "Orders");
    let banner = p.add(Some(root), "banner", "");
    let nav = p.add(Some(banner), "navigation", "Primary");
    for label in ["Home", "Products", "Cart", "Account"] {
        p.add(Some(nav), "link", label);
    }
    p.add(Some(banner), "timer", "Updated 12:00:41");
    let main = p.add(Some(root), "main", "");
    p.add(Some(main), "heading", "Your orders");
    p.add(Some(main), "paragraph", "Showing 25 orders");
    let form = p.add(Some(main), "form", "Search orders");
    p.add(Some(form), "textbox", "Search");
    p.add(Some(form), "button", "Search");
    let custom = p.add(Some(main), "generic", "Sort by date");
    let feed = p.add(Some(main), "feed", "Orders");
    for i in 0..25 {
        let li = p.add(Some(feed), "article", "");
        p.add(Some(li), "link", "View order");
        p.add(Some(li), "StaticText", &format!("Order #{}", 1000 + i));
        p.add(Some(li), "button", "Reorder");
    }
    p.add(Some(main), "status", "Saved 3 seconds ago");
    let disabled = p.add(Some(main), "button", "Checkout");
    p.nodes[disabled].disabled = true;
    let hidden = p.add(Some(main), "button", "Hidden");
    p.nodes[hidden].bbox = Some(BoundingBox::default());
    let footer = p.add(Some(root), "contentinfo", "");
    p.add(Some(footer), "link", "Help");

    let url = CanonicalUrl {
        url: url::Url::parse("https://shop.test/orders?page=2").unwrap(),
        key: Digest::of("t", b"/orders"),
        origin: "https://shop.test".to_owned(),
        route_template: RouteTemplate("/orders".to_owned()),
        params: Vec::new(),
    };
    let mut b = ObservationBundle::empty(SessionId::new(), TabId("tab-1".into()), url);
    b.epoch = ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq: 7,
    };
    b.title = Some("Orders".to_owned());
    b.ax.nodes = p.nodes;
    b.dom_supplement.nodes.insert(
        i64::try_from(custom).unwrap() + 1,
        DomNodeSupplement {
            tag: "div".to_owned(),
            attributes: [("class".to_owned(), "sorter".to_owned())].into_iter().collect(),
            cursor: Some("pointer".to_owned()),
            listeners: vec!["click".to_owned()],
            text: Some("Sort by date".to_owned()),
            bbox: None,
            in_shadow_root: false,
            shadow_root_closed: false,
        },
    );
    b.dom_supplement.listener_candidates = vec![BackendNodeId(i64::try_from(custom).unwrap() + 1)];
    b.frames = vec![
        FrameInfo {
            id: FrameId("frame-main".into()),
            parent: None,
            url: "https://shop.test/orders?page=2".to_owned(),
            same_origin: true,
            lineage: vec!["main".to_owned()],
        },
        FrameInfo {
            id: FrameId("frame-ads".into()),
            parent: Some(FrameId("frame-main".into())),
            url: "https://ads.test/slot/8472".to_owned(),
            same_origin: false,
            lineage: vec!["main".to_owned(), "ads".to_owned()],
        },
    ];
    b.network.operations = vec!["GET /api/orders".to_owned(), "POST /api/cart".to_owned()];
    b
}

/// Everything persisted for one state: the artifact references and the row.
struct Persisted {
    ax: ArtifactRef,
    masks: ArtifactRef,
    state: NewState,
}

async fn persist(
    artifacts: &dyn ArtifactStore,
    states: &dyn StateRepo,
    run: crawlx_core::CrawlRunId,
    session: SessionId,
    bundle: &ObservationBundle,
    masks: &MaskSet,
    profile: &StateProfile,
) -> Persisted {
    let ax = artifacts
        .put(
            run,
            Sensitivity::Sensitive,
            ARTIFACT_CONTENT_TYPE,
            &AxArtifact::from_bundle(bundle).to_json().unwrap(),
        )
        .await
        .unwrap();
    let mask_ref = artifacts
        .put(
            run,
            Sensitivity::Sensitive,
            ARTIFACT_CONTENT_TYPE,
            &serde_json::to_vec(masks).unwrap(),
        )
        .await
        .unwrap();
    let state = NewState {
        id: StateId::new(),
        session,
        epoch: bundle.epoch,
        url: bundle.url.clone(),
        signature: profile.signature.clone(),
        masks: masks.clone(),
        cluster: StateClusterId::new(),
        cluster_similarity: 1.0,
        cluster_is_new: true,
        artifacts: vec![
            (AX_ARTIFACT_KIND.to_owned(), ax.clone()),
            (MASKS_ARTIFACT_KIND.to_owned(), mask_ref.clone()),
        ],
        observed_at: Utc::now(),
    };
    states.put_state(&state).await.unwrap();
    Persisted {
        ax,
        masks: mask_ref,
        state,
    }
}

/// Reload by content hash, rebuild, and compare bit for bit.
async fn assert_reproducible(
    artifacts: &dyn ArtifactStore,
    states: &dyn StateRepo,
    run: crawlx_core::CrawlRunId,
    original: &Persisted,
    profile: &StateProfile,
) {
    let fp = Fingerprinter::default();
    // the row's artifact references are the ones to reload (what an operator would follow)
    let rows = states.list_states(run).await.unwrap();
    let row = rows.iter().find(|s| s.id == original.state.id).unwrap();
    let by_kind: BTreeMap<&str, &ArtifactRef> = row.artifacts.iter().map(|(k, r)| (k.as_str(), r)).collect();
    assert_eq!(by_kind[AX_ARTIFACT_KIND], &original.ax);
    assert_eq!(by_kind[MASKS_ARTIFACT_KIND], &original.masks);

    let ax_bytes = artifacts.get(by_kind[AX_ARTIFACT_KIND]).await.unwrap();
    assert_eq!(
        Digest::of("crawlx/artifact/v1", &ax_bytes),
        by_kind[AX_ARTIFACT_KIND].digest,
        "content-addressed"
    );
    let mask_bytes = artifacts.get(by_kind[MASKS_ARTIFACT_KIND]).await.unwrap();
    let stored_masks: MaskSet = serde_json::from_slice(&mask_bytes).unwrap();
    assert_eq!(
        stored_masks.version, MASK_VERSION,
        "MASK_VERSION travels with the mask set"
    );
    assert_eq!(
        stored_masks, row.masks,
        "the artifact and the row carry the same masks"
    );
    assert_eq!(stored_masks.masked_node_keys.len(), stored_masks.reasons.len());
    assert!(stored_masks.reasons.contains(&MaskReason::ClockOrCounter));
    assert!(stored_masks.reasons.contains(&MaskReason::LiveRegion));
    assert_eq!(
        stored_masks
            .reasons
            .iter()
            .filter(|r| **r == MaskReason::FeedBeyondFirstPage)
            .count(),
        5
    );

    let reloaded = AxArtifact::from_json(&ax_bytes)
        .unwrap()
        .to_bundle(row.session, TabId("tab-1".into()));
    // the stored masks are the ones the artifact derives again
    assert_eq!(
        MaskBuilder::build(&reloaded, &[], &MaskConfig::default()),
        stored_masks,
        "masks re-derived from the artifact equal the stored set"
    );
    let rebuilt = fp.profile(&reloaded, &stored_masks);
    let sig = &rebuilt.signature;
    let orig = &profile.signature;
    assert_eq!(sig.version, orig.version);
    assert_eq!(sig.route_key, orig.route_key);
    assert_eq!(sig.semantic_affordance_minhash, orig.semantic_affordance_minhash);
    assert_eq!(sig.dom_structure_simhash, orig.dom_structure_simhash);
    assert_eq!(
        sig.visible_element_identity_digest,
        orig.visible_element_identity_digest
    );
    assert_eq!(sig.frame_tree_digest, orig.frame_tree_digest);
    assert_eq!(sig.network_operation_digest, orig.network_operation_digest);
    assert_eq!(sig.visual_phash, orig.visual_phash);
    assert_eq!(sig.browser_storage_digest, orig.browser_storage_digest);
    assert_eq!(
        rebuilt, *profile,
        "profile (signature + affordance sets) is identical"
    );
    assert_eq!(
        *sig, row.signature,
        "the persisted row carries the same signature"
    );
    assert_eq!(
        serde_json::to_vec(sig).unwrap(),
        serde_json::to_vec(orig).unwrap()
    );
    assert_eq!(sig.exact_digest().unwrap(), orig.exact_digest().unwrap());
    assert_eq!(
        sig.exact_digest().unwrap(),
        StateSignature::exact_digest(&row.signature).unwrap()
    );
}

#[tokio::test]
async fn signature_recomputed_from_stored_artifact_and_masks_is_bit_identical() {
    let clock = ManualClock::new(Utc::now());
    let store = Arc::new(MemoryStore::with_clock(Arc::new(clock.clone())));
    let run = crawl_run(TenantId::new(), create_crawl("https://shop.test/", &[], 1));
    store.create(&run, None).await.unwrap();
    let ss = sessions(run.id, 1, 1);
    store.create_sessions(&ss).await.unwrap();
    store
        .claim_session(run.id, WorkerId::new(), false)
        .await
        .unwrap()
        .unwrap();
    let session = ss[0].id;

    let b = bundle();
    let masks = MaskBuilder::build(&b, &[], &MaskConfig::default());
    assert!(!masks.masked_node_keys.is_empty());
    let profile = Fingerprinter::default().profile(&b, &masks);
    // the masks change the signature, so reproducing it needs the stored set
    assert_ne!(
        Fingerprinter::default().fingerprint(&b, &MaskSet::default()),
        profile.signature
    );

    let runs: Arc<dyn RunRepo> = store.clone();
    let mem = MemoryArtifactStore::in_memory(runs.clone(), Arc::new(clock.clone()));
    let p = persist(&mem, store.as_ref(), run.id, session, &b, &masks, &profile).await;
    assert_reproducible(&mem, store.as_ref(), run.id, &p, &profile).await;

    let dir = tempfile::tempdir().unwrap();
    let fs = FsArtifactStore::open(dir.path(), runs, Arc::new(clock.clone()))
        .await
        .unwrap();
    let p = persist(&fs, store.as_ref(), run.id, session, &b, &masks, &profile).await;
    assert_reproducible(&fs, store.as_ref(), run.id, &p, &profile).await;
    // the same bytes hash to the same reference in both stores
    assert_eq!(
        p.ax.digest,
        Digest::of(
            "crawlx/artifact/v1",
            &AxArtifact::from_bundle(&b).to_json().unwrap()
        )
    );
}

#[tokio::test]
async fn ax_artifact_round_trips_every_signature_input() {
    let b = bundle();
    let artifact = AxArtifact::from_bundle(&b);
    let json = artifact.to_json().unwrap();
    let back = AxArtifact::from_json(&json).unwrap();
    assert_eq!(back, artifact);
    let rebuilt = back.to_bundle(b.session_id, b.tab.clone());
    assert_eq!(rebuilt.url, b.url);
    assert_eq!(rebuilt.route, b.route);
    assert_eq!(rebuilt.epoch, b.epoch);
    assert_eq!(rebuilt.frames, b.frames);
    assert_eq!(rebuilt.ax, b.ax);
    assert_eq!(rebuilt.dom_supplement, b.dom_supplement);
    assert_eq!(rebuilt.network, b.network);
    assert_eq!(rebuilt.title, b.title);
    // an artifact of another version is refused rather than silently reinterpreted
    let mut v: serde_json::Value = serde_json::from_slice(&json).unwrap();
    v["version"] = serde_json::json!(99);
    assert!(AxArtifact::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
}
