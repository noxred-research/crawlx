//! Worker-local approval and immutable pin verification for declarative recipes.

use crate::error::WorkerError;
use crawlx_core::{
    archive_behaviors::{RecipeReferenceV1, RecipeV1},
    hash::Digest,
    TenantId,
};
use hmac::{KeyInit as _, Mac as _};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};
use tokio::io::AsyncReadExt;

const MAX_REGISTRY_BYTES: usize = 1_048_576;

/// Immutable operator-owned registry. Tenant requests can select entries, never register them.
#[derive(Default)]
pub struct RecipeRegistry {
    entries: BTreeMap<String, BTreeMap<u32, ApprovedRegistration>>,
}
impl std::fmt::Debug for RecipeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipeRegistry")
            .field("entries", &self.entries.len())
            .finish()
    }
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryFile {
    schema_version: u16,
    recipes: Vec<Registration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Registration {
    recipe: RecipeV1,
    digest: Digest,
    approved_tenants: BTreeSet<TenantId>,
    approval_id: String,
    /// Operator explicitly attests that any site-specific legal decision is settled.
    legal_review_approved: bool,
}

struct ApprovedRegistration {
    recipe: Arc<RecipeV1>,
    digest: Digest,
    approved_tenants: BTreeSet<TenantId>,
}

impl RecipeRegistry {
    /// Read a bounded regular operator file; never downloads or executes a recipe.
    ///
    /// # Errors
    /// Refuses symlinks, special files, malformed schemas, duplicate revisions and invalid pins.
    pub async fn from_file(path: &Path) -> Result<Arc<Self>, WorkerError> {
        let metadata = tokio::fs::symlink_metadata(path)
            .await
            .map_err(|_| refuse("recipe registry unavailable"))?;
        if !metadata.file_type().is_file() || metadata.len() > 1_048_576 {
            return Err(refuse("recipe registry must be a bounded regular file"));
        }
        let mut bytes = Vec::new();
        tokio::fs::File::open(path)
            .await
            .map_err(|_| refuse("recipe registry unavailable"))?
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| refuse("recipe registry unreadable"))?;
        let reference = std::env::var("CRAWLX_RECIPE_APPROVAL_KEY_REF")
            .map_err(|_| refuse("recipe approval key reference absent"))?;
        let key = load_approval_key(&crawlx_core::secret::CredentialRef(reference)).await?;
        Self::from_bytes(&bytes, key.expose().as_bytes())
    }

    /// Parse bounded operator bytes and freeze every validated recipe revision.
    ///
    /// # Errors
    /// Refuses unknown fields, unsafe actions, mismatched pins, missing approvals and oversized registries.
    pub fn from_bytes(bytes: &[u8], approval_key: &[u8]) -> Result<Arc<Self>, WorkerError> {
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(refuse("recipe registry byte cap"));
        }
        // Round-trip each action to reject unknown action fields rather than silently losing semantics.
        let raw: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| refuse("invalid recipe registry schema"))?;
        let mut file: RegistryFile =
            RegistryFile::deserialize(&raw).map_err(|_| refuse("invalid recipe registry schema"))?;
        if file.schema_version != 1 || file.recipes.len() > 32 {
            return Err(refuse("recipe registry version or count"));
        }
        let signature = file
            .signature
            .take()
            .ok_or_else(|| refuse("recipe registry signature absent"))?;
        let mut proof = [0_u8; 32];
        hex::decode_to_slice(&signature, &mut proof)
            .map_err(|_| refuse("invalid recipe registry signature"))?;
        registry_mac(&file, approval_key)?
            .verify_slice(&proof)
            .map_err(|_| refuse("recipe registry signature verification failed"))?;
        let mut entries: BTreeMap<String, BTreeMap<u32, ApprovedRegistration>> = BTreeMap::new();
        for (index, registration) in file.recipes.into_iter().enumerate() {
            if raw["recipes"][index]["recipe"]["initialViewport"]
                .as_object()
                .is_some_and(|viewport| {
                    viewport
                        .keys()
                        .any(|key| !matches!(key.as_str(), "width" | "height"))
                })
            {
                return Err(refuse("unsupported recipe viewport field"));
            }
            let recipe = &registration.recipe;
            let digest = recipe.digest().map_err(|_| refuse("invalid or unsafe recipe"))?;
            if digest != registration.digest {
                return Err(refuse("recipe digest mismatch"));
            }
            if registration.approved_tenants.is_empty()
                || registration.approved_tenants.len() > 256
                || registration.approval_id.is_empty()
                || registration.approval_id.len() > 128
                || !registration
                    .approval_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                || !registration.legal_review_approved
            {
                return Err(refuse("recipe operator or legal approval missing"));
            }
            for (step_index, step) in recipe.steps.iter().enumerate() {
                let original = &raw["recipes"][index]["recipe"]["steps"][step_index]["action"];
                let normalized =
                    serde_json::to_value(&step.action).map_err(|_| refuse("invalid recipe action"))?;
                if original
                    .as_object()
                    .is_none_or(|obj| obj.keys().any(|key| normalized.get(key).is_none()))
                {
                    return Err(refuse("unsupported recipe action field"));
                }
                if let crawlx_core::scrape::ScrapeAction::Press { key } = &step.action {
                    // Same parser used by the real ActionRunner, so admission cannot overclaim a key.
                    if crate::scrape::render::recipe_key_supported(key).is_none() {
                        return Err(refuse("unsupported recipe key"));
                    }
                }
            }
            let id = recipe.id.clone();
            let version = recipe.version;
            let approved = ApprovedRegistration {
                recipe: Arc::new(registration.recipe),
                digest: registration.digest,
                approved_tenants: registration.approved_tenants,
            };
            if entries.entry(id).or_default().insert(version, approved).is_some() {
                return Err(refuse("duplicate immutable recipe revision"));
            }
        }
        Ok(Arc::new(Self { entries }))
    }

    /// Resolve the exact version and digest under operator approval before browser allocation.
    ///
    /// # Errors
    /// Refuses unknown revisions, tampered pins, unsupported timing and unapproved tenants.
    pub fn resolve(
        &self,
        reference: &RecipeReferenceV1,
        tenant: TenantId,
    ) -> Result<Arc<RecipeV1>, WorkerError> {
        reference
            .validate()
            .map_err(|_| refuse("unsupported recipe reference or timing"))?;
        let registration = self
            .entries
            .get(&reference.id)
            .and_then(|versions| versions.get(&reference.version))
            .ok_or_else(|| refuse("unknown approved recipe revision"))?;
        if registration.digest != reference.digest || registration.recipe.phase != reference.phase {
            return Err(refuse("recipe reference digest or timing mismatch"));
        }
        if !registration.approved_tenants.contains(&tenant) {
            return Err(refuse("recipe tenant approval missing"));
        }
        Ok(Arc::clone(&registration.recipe))
    }
}

fn registry_mac(file: &RegistryFile, key: &[u8]) -> Result<hmac::Hmac<sha2::Sha256>, WorkerError> {
    if !(32..=4_096).contains(&key.len()) {
        return Err(refuse("recipe approval key length"));
    }
    let bytes = serde_json::to_vec(file).map_err(|_| refuse("invalid canonical recipe registry"))?;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
        .map_err(|_| refuse("recipe approval key unavailable"))?;
    mac.update(b"crawlx/operator-approved-recipe-registry/v1\0");
    mac.update(&bytes);
    Ok(mac)
}

/// Resolve an operator-only local approval key without writing or logging its contents.
///
/// # Errors
/// Refuses nonlocal secret schemes, missing values and keys outside 32..=4096 bytes.
pub async fn load_approval_key(
    reference: &crawlx_core::secret::CredentialRef,
) -> Result<crawlx_core::SecretOr<String>, WorkerError> {
    use crawlx_core::SecretResolver as _;
    if reference.0.len() > 4_096 || !matches!(reference.scheme(), Some("env" | "file")) {
        return Err(refuse(
            "recipe approval key requires a local operator secret reference",
        ));
    }
    let resolver = crate::secrets::ChainResolver::new()
        .with("env", Arc::new(crate::secrets::EnvSecretResolver))
        .with("file", Arc::new(crate::secrets::FileSecretResolver));
    let key = resolver
        .resolve(reference)
        .await
        .map_err(|_| refuse("recipe approval key unavailable"))?;
    if !(32..=4_096).contains(&key.expose().len()) {
        return Err(refuse("recipe approval key length"));
    }
    Ok(key)
}

/// Sign a complete finite operator registry offline, including every tenant and legal approval.
///
/// The HMAC-SHA256 signature covers domain-separated canonical typed JSON without `signature`.
/// The same strict admission parser validates the signed result before this function returns.
///
/// # Errors
/// Refuses malformed or unsafe registry bytes, invalid pins and unavailable approval keys.
pub fn sign_registry_bytes(bytes: &[u8], approval_key: &[u8]) -> Result<Vec<u8>, WorkerError> {
    if bytes.len() > MAX_REGISTRY_BYTES {
        return Err(refuse("recipe registry byte cap"));
    }
    let mut raw: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| refuse("invalid recipe registry schema"))?;
    let mut file = RegistryFile::deserialize(&raw).map_err(|_| refuse("invalid recipe registry schema"))?;
    file.signature = None;
    let signature = hex::encode(registry_mac(&file, approval_key)?.finalize().into_bytes());
    let object = raw
        .as_object_mut()
        .ok_or_else(|| refuse("invalid recipe registry schema"))?;
    object.insert("signature".into(), serde_json::Value::String(signature));
    let signed = serde_json::to_vec_pretty(&raw).map_err(|_| refuse("invalid signed recipe registry"))?;
    RecipeRegistry::from_bytes(&signed, approval_key)?;
    Ok(signed)
}

/// In-memory execution cursor borrowed by the existing ActionRunner, not another action engine.
#[derive(Default)]
pub(crate) struct RecipeProgress {
    completed: usize,
    in_flight: Option<usize>,
    failed: Option<usize>,
    pub(crate) emulation_completed: bool,
    pub(crate) navigation_completed: bool,
    pub(crate) emulation_started: bool,
    pub(crate) navigation_started: bool,
}

impl RecipeProgress {
    pub(crate) fn start(&mut self, index: usize) {
        self.in_flight = Some(index);
    }
    pub(crate) fn finish(&mut self, index: usize, succeeded: bool) {
        self.in_flight = None;
        if succeeded {
            self.completed = index.saturating_add(1);
        } else {
            self.failed = Some(index);
        }
    }

    fn disposition(
        &self,
        index: usize,
        cancelled: bool,
    ) -> crawlx_core::archive_behaviors::RecipeStepDispositionV1 {
        use crawlx_core::archive_behaviors::RecipeStepDispositionV1 as D;
        if index < self.completed {
            D::Completed
        } else if self.failed == Some(index) {
            D::Failed
        } else if self.in_flight == Some(index) {
            if cancelled {
                D::Cancelled
            } else {
                D::Failed
            }
        } else {
            D::NotRun
        }
    }

    pub(crate) async fn record(
        &self,
        rc: &crate::run::RunContext,
        session: crawlx_core::SessionId,
        recipe: &RecipeV1,
        cancelled: bool,
    ) -> Result<(), crate::scrape::RenderError> {
        let digest = recipe
            .digest()
            .map_err(|_| crate::scrape::RenderError::Unavailable("invalid approved recipe".into()))?;
        use crawlx_core::archive_behaviors::RecipeStepDispositionV1 as D;
        let mut dispositions: Vec<(u32, serde_json::Value)> = recipe.steps.iter().enumerate().map(|(index, step)| {
            (step.source_index, serde_json::json!({
                "sourceIndex": step.source_index, "kind": step.action.name(),
                "disposition": self.disposition(index, cancelled),
                "actualPhase": (index < self.completed || self.in_flight == Some(index) || self.failed == Some(index))
                    .then_some("post_navigation"),
            }))
        }).collect();
        if let Some(source) = &recipe.source {
            for (index, kind, started, completed, phase) in [
                (
                    source.initial_viewport_index,
                    "initial_viewport",
                    self.emulation_started,
                    self.emulation_completed,
                    "before_initial_navigation",
                ),
                (
                    source.initial_navigation_index,
                    "initial_navigation",
                    self.navigation_started,
                    self.navigation_completed,
                    "initial_navigation",
                ),
            ] {
                if let Some(index) = index {
                    let disposition = if completed {
                        D::Completed
                    } else if started {
                        if cancelled {
                            D::Cancelled
                        } else {
                            D::Failed
                        }
                    } else {
                        D::NotRun
                    };
                    dispositions.push((
                        index,
                        serde_json::json!({
                            "sourceIndex": index, "kind": kind, "disposition": disposition,
                            "actualPhase": started.then_some(phase),
                        }),
                    ));
                }
            }
        }
        dispositions.sort_unstable_by_key(|(index, _)| *index);
        let dispositions: Vec<_> = dispositions.into_iter().map(|(_, value)| value).collect();
        rc.stores.events.append(rc.run, "archive.recipe", serde_json::json!({
            "session_id": session.0, "recipeId": recipe.id, "recipeVersion": recipe.version,
            "recipeDigest": digest, "sourceDigest": recipe.source.as_ref().map(|source| source.digest),
            "requestedPhase": recipe.phase,
            "actualPhase": self.navigation_completed.then_some("post_navigation"),
            "initialEmulationCompleted": self.emulation_completed,
            "initialEmulationPhase": self.emulation_completed.then_some("before_initial_navigation"),
            "initialNavigationCompleted": self.navigation_completed,
            "steps": dispositions,
        })).await.map_err(|_| crate::scrape::RenderError::Browser("recipe provenance journal unavailable".into()))?;
        Ok(())
    }
}

fn refuse(reason: &str) -> WorkerError {
    WorkerError::Config(reason.to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::scrape::ScrapeAction;

    fn registry() -> (Arc<RecipeRegistry>, RecipeReferenceV1, TenantId) {
        let recipe = RecipeV1::new("fixture".into(), 1);
        let reference = RecipeReferenceV1::for_recipe(&recipe).unwrap();
        let tenant = TenantId::new();
        let bytes = serde_json::to_vec(&serde_json::json!({"schemaVersion": 1, "recipes": [{
            "recipe": recipe, "digest": reference.digest, "approvedTenants": [tenant],
            "approvalId": "fixture-approval", "legalReviewApproved": true
        }]}))
        .unwrap();
        let signed = sign_registry_bytes(&bytes, &[7; 32]).unwrap();
        (
            RecipeRegistry::from_bytes(&signed, &[7; 32]).unwrap(),
            reference,
            tenant,
        )
    }

    #[test]
    fn unknown_tampered_unapproved_and_wrong_timing_fail_closed() {
        let (registry, reference, tenant) = registry();
        assert!(registry.resolve(&reference, tenant).is_ok());
        assert!(registry.resolve(&reference, TenantId::new()).is_err());
        let mut bad = reference.clone();
        bad.id = "unknown".into();
        assert!(registry.resolve(&bad, tenant).is_err());
        bad = reference.clone();
        bad.digest = Digest::of("test", b"tampered");
        assert!(registry.resolve(&bad, tenant).is_err());
        bad = reference;
        bad.phase = crawlx_core::archive_behaviors::RecipePhaseV1::BeforePageScripts;
        assert!(registry.resolve(&bad, tenant).is_err());
    }

    #[test]
    fn operator_cannot_register_executable_steps_or_unsettled_legal_decisions() {
        let (registry, reference, tenant) = registry();
        let mut recipe = (*registry.resolve(&reference, tenant).unwrap()).clone();
        recipe
            .steps
            .push(crawlx_core::archive_behaviors::RecipeStepV1::new(
                0,
                ScrapeAction::ExecuteJavascript {
                    script: "private-marker".into(),
                },
            ));
        let bytes = serde_json::to_vec(&serde_json::json!({"schemaVersion": 1, "recipes": [{
            "recipe": recipe, "digest": reference.digest, "approvedTenants": [tenant],
            "approvalId": "fixture", "legalReviewApproved": false
        }]}))
        .unwrap();
        let error = sign_registry_bytes(&bytes, &[7; 32]).unwrap_err().to_string();
        assert!(!error.contains("private-marker"));
    }

    #[test]
    fn first_failure_and_cancel_leave_all_later_steps_unrun() {
        use crawlx_core::archive_behaviors::RecipeStepDispositionV1 as D;
        let mut progress = RecipeProgress::default();
        progress.start(0);
        progress.finish(0, true);
        progress.start(1);
        progress.finish(1, false);
        assert_eq!(progress.disposition(0, false), D::Completed);
        assert_eq!(progress.disposition(1, false), D::Failed);
        assert_eq!(progress.disposition(2, false), D::NotRun);
        let mut progress = RecipeProgress::default();
        progress.start(0);
        assert_eq!(progress.disposition(0, true), D::Cancelled);
        assert_eq!(progress.disposition(1, true), D::NotRun);
    }

    #[test]
    fn signature_binds_approvals_and_refuses_wrong_keys_or_tampered_bytes() {
        let recipe = RecipeV1::new("fixture".into(), 1);
        let tenant = TenantId::new();
        let unsigned = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1, "recipes": [{
                "digest": recipe.digest().unwrap(), "recipe": recipe,
                "approvedTenants": [tenant], "approvalId": "fixture", "legalReviewApproved": true
            }]
        }))
        .unwrap();
        assert!(RecipeRegistry::from_bytes(&unsigned, &[7; 32]).is_err());
        let signed = sign_registry_bytes(&unsigned, &[7; 32]).unwrap();
        assert!(RecipeRegistry::from_bytes(&signed, &[8; 32]).is_err());
        let mut tampered: serde_json::Value = serde_json::from_slice(&signed).unwrap();
        tampered["recipes"][0]["approvedTenants"] = serde_json::json!([TenantId::new()]);
        assert!(RecipeRegistry::from_bytes(&serde_json::to_vec(&tampered).unwrap(), &[7; 32]).is_err());
        tampered["recipes"][0]["legalReviewApproved"] = serde_json::json!(false);
        assert!(sign_registry_bytes(&serde_json::to_vec(&tampered).unwrap(), &[7; 32]).is_err());
    }
}
