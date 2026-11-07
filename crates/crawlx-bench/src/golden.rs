//! Golden traces for the Chromium pin bump: golden-trace comparison on identity,
//! fingerprint and action outcomes, and identity stability across builds.
//!
//! A golden trace is one deterministic walk over a fixture on the pinned Chromium: observe
//! the entry page, then click every ground-truth control in manifest order, observing after
//! each click. Every step records what the observation *derives* — the [`StateSignature`],
//! the element identity hash of every ground-truth control that is a candidate, candidate
//! and unsupported-surface counts — and the action's outcome (fidelity, lane, whether it
//! navigated). Raw CDP payloads are deliberately not stored: they differ between builds in
//! ways crawlx does not care about; the derived sequence is what a pin bump must keep.
//!
//! [`record`] walks a fixture on the running browser; [`diff`] compares a recording with
//! the golden file field by field. `crates/crawlx-bench/tests/golden_traces.rs` runs the
//! comparison (and re-blesses with `CRAWLX_BLESS=1`); the `chromium-next` job publishes
//! its diff as the pin-bump review artifact.

use crate::error::BenchError;
use crate::gym::manifest::FixtureManifest;
use crate::trail::signature_diff;
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::browser::BrowserContext;
use crawlx_core::observation::{BrowserBuildInfo, ObservationBundle, ObservationSpec, QuiescencePolicy};
use crawlx_core::state::StateSignature;
use crawlx_elements::{CandidateDiscovery, Discovery, DiscoveryConfig, IdentityBuilder};
use crawlx_state::{Fingerprinter, MaskBuilder, MaskConfig};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Format version of the golden file.
pub const VERSION: u32 = 1;

/// Browser build a trace was recorded on.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct RecordedWith {
    /// Chromium version string.
    pub chromium_version: String,
    /// CDP protocol revision.
    pub cdp_revision: String,
    /// Whether that build matched `chromium-pin.toml` at recording time.
    pub pinned: bool,
}

impl From<&BrowserBuildInfo> for RecordedWith {
    fn from(b: &BrowserBuildInfo) -> Self {
        Self {
            chromium_version: b.chromium_version.clone(),
            cdp_revision: b.cdp_revision.clone(),
            pinned: b.pinned,
        }
    }
}

/// The click a step performed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct GoldenAction {
    /// Ground-truth control id (its DOM id).
    pub control: String,
    /// Fidelity the browser reported.
    pub fidelity: String,
    /// Trust lane the browser reported.
    pub lane: String,
    /// `true` when the main document URL changed.
    pub navigated: bool,
}

/// One observation of the walk.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct GoldenStep {
    /// 0 for the entry observation, then one per manifest control.
    pub index: u32,
    /// Control the step tried to click; `None` for the entry observation.
    #[serde(default)]
    pub control: Option<String>,
    /// The click, when the control was a candidate and the click was dispatched.
    #[serde(default)]
    pub action: Option<GoldenAction>,
    /// Why no click happened (`not a candidate`, or the browser error).
    #[serde(default)]
    pub skipped: Option<String>,
    /// Path and query of the observed main document.
    pub url_path: String,
    /// Fingerprint of the observation (empty masks, default `Fingerprinter`).
    pub signature: StateSignature,
    /// Identity hash per ground-truth control that is a candidate, hex.
    pub identities: BTreeMap<String, String>,
    /// Discovery-ladder candidates in the observation.
    pub candidates: usize,
    /// `unsupported_surface` reports in the observation.
    pub unsupported: usize,
}

/// A recorded walk.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct GoldenTrace {
    /// [`VERSION`].
    pub version: u32,
    /// Fixture id.
    pub fixture: String,
    /// Gym base URL the walk ran against; the comparison binds the same port so
    /// origin-bearing digests (`route_key`, `frame_tree_digest`) stay comparable.
    pub base_url: String,
    /// Browser build of the recording.
    pub recorded_with: RecordedWith,
    /// Observations, entry first.
    pub steps: Vec<GoldenStep>,
}

impl GoldenTrace {
    /// Load a golden file.
    ///
    /// # Errors
    /// I/O, JSON, or a version other than [`VERSION`].
    pub fn load(path: &Path) -> Result<Self, BenchError> {
        let text = std::fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;
        let t: Self = serde_json::from_str(&text)?;
        if t.version != VERSION {
            return Err(BenchError::manifest(
                path.display().to_string(),
                format!("golden trace version {} (expected {VERSION})", t.version),
            ));
        }
        Ok(t)
    }

    /// Write the golden file (creating parent directories).
    ///
    /// # Errors
    /// I/O or JSON failures.
    pub fn save(&self, path: &Path) -> Result<(), BenchError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| BenchError::io(parent, e))?;
        }
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(path, text).map_err(|e| BenchError::io(path, e))
    }
}

fn url_path(url: &str) -> String {
    crate::oracle::discovery::frame_path_of(url)
}

fn derive(
    bundle: &ObservationBundle,
    manifest: &FixtureManifest,
    discovery: &Discovery,
) -> (StateSignature, BTreeMap<String, String>) {
    let masks = MaskBuilder::build(bundle, &[], &MaskConfig::default());
    let signature = Fingerprinter::default().fingerprint(bundle, &masks);
    let page = Some(bundle.url.url.clone());
    let mut identities = BTreeMap::new();
    for c in &discovery.candidates {
        let Some(id) = c.descriptor.attributes.get("id") else {
            continue;
        };
        if manifest.control(id).is_none() {
            continue;
        }
        let dest = page.as_ref().and_then(|p| {
            IdentityBuilder::destination_key(&c.descriptor, p, &CanonicalizeOptions::default())
        });
        let identity = IdentityBuilder::build(&c.descriptor, dest);
        if let Ok(hash) = IdentityBuilder::hash(&identity) {
            identities.insert(id.clone(), hash.0.to_hex());
        }
    }
    (signature, identities)
}

/// Observe the current page and derive a step.
async fn observe_step(
    ctx: &mut dyn BrowserContext,
    manifest: &FixtureManifest,
    index: u32,
) -> Result<(GoldenStep, Discovery), BenchError> {
    ctx.settle(QuiescencePolicy::default()).await?;
    let bundle = ctx.observe(ObservationSpec::default()).await?;
    let discovery = CandidateDiscovery::discover_report(&bundle, &DiscoveryConfig::default());
    let (signature, identities) = derive(&bundle, manifest, &discovery);
    let step = GoldenStep {
        index,
        control: None,
        action: None,
        skipped: None,
        url_path: url_path(bundle.url.url.as_str()),
        signature,
        identities,
        candidates: discovery.candidates.len(),
        unsupported: discovery.unsupported.len(),
    };
    Ok((step, discovery))
}

/// Walk `manifest` on `ctx`: observe the entry page, then click every control in manifest
/// order (when it is a candidate of the current observation) and observe again.
///
/// # Errors
/// Navigation or observation failures; a failed click is recorded on its step instead.
pub async fn record(
    ctx: &mut dyn BrowserContext,
    manifest: &FixtureManifest,
    base_url: &str,
    build: &BrowserBuildInfo,
) -> Result<GoldenTrace, BenchError> {
    let entry = url::Url::parse(&manifest.entry_url(base_url))?;
    let canonical = Canonicalizer::canonicalize_url(&entry, &CanonicalizeOptions::default())?;
    ctx.navigate(&canonical).await?;
    let (first, mut discovery) = observe_step(ctx, manifest, 0).await?;
    let mut steps = vec![first];
    for (index, control) in (1u32..).zip(manifest.controls.iter()) {
        let before = steps.last().map(|s| s.url_path.clone()).unwrap_or_default();
        let target = discovery
            .candidates
            .iter()
            .find(|c| c.descriptor.attributes.get("id") == Some(&control.id))
            .map(|c| c.descriptor.locator.clone());
        let (action, skipped) = match target {
            None => (None, Some("not a candidate".to_owned())),
            Some(locator) => match ctx
                .perform(BrowserAction::Click {
                    target: locator,
                    button: PointerButton::Left,
                    modifiers: Modifiers::default(),
                })
                .await
            {
                Ok(receipt) => (
                    Some((
                        receipt.fidelity.as_str().to_owned(),
                        receipt.lane.as_str().to_owned(),
                    )),
                    None,
                ),
                Err(e) => (None, Some(format!("click failed: {e}"))),
            },
        };
        let (mut step, next) = observe_step(ctx, manifest, index).await?;
        step.control = Some(control.id.clone());
        step.skipped = skipped;
        step.action = action.map(|(fidelity, lane)| GoldenAction {
            control: control.id.clone(),
            fidelity,
            lane,
            navigated: step.url_path != before,
        });
        steps.push(step);
        discovery = next;
    }
    Ok(GoldenTrace {
        version: VERSION,
        fixture: manifest.id.clone(),
        base_url: base_url.trim_end_matches('/').to_owned(),
        recorded_with: RecordedWith::from(build),
        steps,
    })
}

/// Differences of one step.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct StepDiff {
    /// Step index.
    pub index: u32,
    /// Human-readable differences, one per field.
    pub differences: Vec<String>,
}

/// Outcome of [`diff`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct GoldenDiff {
    /// Fixture id.
    pub fixture: String,
    /// Build the golden was recorded on.
    pub golden_build: RecordedWith,
    /// Build the fresh recording ran on.
    pub fresh_build: RecordedWith,
    /// `false` when the fresh walk ran on another gym port, so origin-bearing digests were
    /// excluded from the comparison.
    pub origin_comparable: bool,
    /// Step-count mismatch, when any.
    #[serde(default)]
    pub step_count: Option<String>,
    /// Steps that differ, in order.
    pub steps: Vec<StepDiff>,
}

impl GoldenDiff {
    /// `true` when the fresh recording reproduces the golden sequence.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.step_count.is_none() && self.steps.is_empty()
    }

    /// Steps that differ, as one line each.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = String::new();
        if let Some(s) = &self.step_count {
            out.push_str(s);
            out.push('\n');
        }
        for s in &self.steps {
            for d in &s.differences {
                out.push_str(&format!("step {}: {d}\n", s.index));
            }
        }
        out
    }
}

fn diff_identities(
    golden: &BTreeMap<String, String>,
    fresh: &BTreeMap<String, String>,
    out: &mut Vec<String>,
) {
    for (id, hash) in golden {
        match fresh.get(id) {
            None => out.push(format!("identity of `{id}` missing (golden {})", &hash[..12])),
            Some(f) if f != hash => out.push(format!(
                "identity of `{id}` changed ({} -> {})",
                &hash[..12],
                &f[..12]
            )),
            Some(_) => {}
        }
    }
    for id in fresh.keys().filter(|id| !golden.contains_key(*id)) {
        out.push(format!("identity of `{id}` is new"));
    }
}

/// Compare `fresh` with `golden`. With `origin_comparable == false` the `route_key` and
/// `frame_tree_digest` fields (which embed the gym origin) are not compared.
#[must_use]
pub fn diff(golden: &GoldenTrace, fresh: &GoldenTrace, origin_comparable: bool) -> GoldenDiff {
    let mut steps = Vec::new();
    for (g, f) in golden.steps.iter().zip(&fresh.steps) {
        let mut d = Vec::new();
        if g.control != f.control {
            d.push(format!("control {:?} -> {:?}", g.control, f.control));
        }
        if g.action != f.action {
            d.push(format!("action outcome {:?} -> {:?}", g.action, f.action));
        }
        if g.skipped != f.skipped {
            d.push(format!("skipped {:?} -> {:?}", g.skipped, f.skipped));
        }
        if g.url_path != f.url_path {
            d.push(format!("url {} -> {}", g.url_path, f.url_path));
        }
        for field in signature_diff(&g.signature, &f.signature) {
            if !origin_comparable && matches!(field, "route_key" | "frame_tree_digest") {
                continue;
            }
            d.push(format!("signature.{field} differs"));
        }
        diff_identities(&g.identities, &f.identities, &mut d);
        if g.candidates != f.candidates {
            d.push(format!("candidates {} -> {}", g.candidates, f.candidates));
        }
        if g.unsupported != f.unsupported {
            d.push(format!(
                "unsupported surfaces {} -> {}",
                g.unsupported, f.unsupported
            ));
        }
        if !d.is_empty() {
            steps.push(StepDiff {
                index: g.index,
                differences: d,
            });
        }
    }
    let step_count = (golden.steps.len() != fresh.steps.len())
        .then(|| format!("{} golden steps, {} fresh", golden.steps.len(), fresh.steps.len()));
    GoldenDiff {
        fixture: golden.fixture.clone(),
        golden_build: golden.recorded_with.clone(),
        fresh_build: fresh.recorded_with.clone(),
        origin_comparable,
        step_count,
        steps,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::hash::Digest;

    fn signature(seed: u8) -> StateSignature {
        StateSignature {
            version: StateSignature::VERSION,
            route_key: Digest::of("t", &[seed]),
            semantic_affordance_minhash: vec![u64::from(seed); 4],
            dom_structure_simhash: u64::from(seed),
            visible_element_identity_digest: Digest::of("i", &[seed]),
            frame_tree_digest: Digest::of("f", &[seed]),
            network_operation_digest: Digest::of("n", &[seed]),
            visual_phash: None,
            browser_storage_digest: None,
        }
    }

    fn step(index: u32, seed: u8, identities: &[(&str, &str)]) -> GoldenStep {
        GoldenStep {
            index,
            control: (index > 0).then(|| format!("c{index}")),
            action: (index > 0).then(|| GoldenAction {
                control: format!("c{index}"),
                fidelity: "native_pointer".to_owned(),
                lane: "trusted_ui".to_owned(),
                navigated: false,
            }),
            skipped: None,
            url_path: "/g03/".to_owned(),
            signature: signature(seed),
            identities: identities
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).repeat(16)))
                .collect(),
            candidates: 3,
            unsupported: 0,
        }
    }

    fn trace(steps: Vec<GoldenStep>) -> GoldenTrace {
        GoldenTrace {
            version: VERSION,
            fixture: "g03".to_owned(),
            base_url: "http://127.0.0.1:47831".to_owned(),
            recorded_with: RecordedWith {
                chromium_version: "155.0.8059.84".to_owned(),
                cdp_revision: "1.3".to_owned(),
                pinned: true,
            },
            steps,
        }
    }

    #[test]
    fn identical_traces_are_clean_and_round_trip_through_json() {
        let t = trace(vec![step(0, 1, &[("a", "ab")]), step(1, 2, &[("a", "ab")])]);
        let d = diff(&t, &t, true);
        assert!(d.is_clean(), "{}", d.summary());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("golden/g03.json");
        t.save(&path).unwrap();
        assert_eq!(GoldenTrace::load(&path).unwrap(), t);
    }

    #[test]
    fn every_derived_field_is_reported() {
        let golden = trace(vec![step(0, 1, &[("a", "ab"), ("b", "cd")]), step(1, 2, &[])]);
        let mut fresh = golden.clone();
        fresh.steps[0].signature.dom_structure_simhash = 99;
        fresh.steps[0].identities.insert("a".to_owned(), "ff".repeat(16));
        fresh.steps[0].identities.remove("b");
        fresh.steps[0].identities.insert("z".to_owned(), "00".repeat(16));
        fresh.steps[0].candidates = 4;
        fresh.steps[1].action.as_mut().unwrap().lane = "diagnostic".to_owned();
        fresh.steps.push(step(2, 3, &[]));
        let d = diff(&golden, &fresh, true);
        let s = d.summary();
        assert!(s.contains("signature.dom_structure_simhash differs"), "{s}");
        assert!(s.contains("identity of `a` changed"), "{s}");
        assert!(s.contains("identity of `b` missing"), "{s}");
        assert!(s.contains("identity of `z` is new"), "{s}");
        assert!(s.contains("candidates 3 -> 4"), "{s}");
        assert!(s.contains("action outcome"), "{s}");
        assert!(s.contains("2 golden steps, 3 fresh"), "{s}");
        assert!(!d.is_clean());
    }

    #[test]
    fn incompatible_signature_versions_never_compare_clean() {
        let mut legacy = trace(vec![step(0, 1, &[])]);
        legacy.steps[0].signature.version = StateSignature::VERSION - 1;
        let fresh = trace(vec![step(0, 1, &[])]);
        for origin_comparable in [true, false] {
            assert!(!diff(&legacy, &fresh, origin_comparable).is_clean());
        }
    }

    #[test]
    fn origin_bearing_digests_are_skipped_on_another_port() {
        let golden = trace(vec![step(0, 1, &[])]);
        let mut fresh = golden.clone();
        fresh.steps[0].signature.route_key = Digest::of("t", &[7]);
        fresh.steps[0].signature.frame_tree_digest = Digest::of("f", &[7]);
        assert!(!diff(&golden, &fresh, true).is_clean());
        assert!(diff(&golden, &fresh, false).is_clean());
    }
}
