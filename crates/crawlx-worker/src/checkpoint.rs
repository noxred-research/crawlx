//! Checkpoint and restore: authenticated encryption protects every URL,
//! cookie and storage payload before its `CredentialBearing` artifact is written.
//! Restore authenticates tenant/run/session/checkpoint ownership and never replays writes.

use crate::error::SessionError;
use base64::Engine as _;
use crawlx_core::checkpoint_crypto::Ciphertext;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ArtifactStore, CheckpointRecord, CheckpointRepo, Sensitivity};
use crawlx_core::secret::ArtifactSink;
use crawlx_core::{
    BrowserContext, CheckpointId, Clock, CrawlRunId, ObservationEpoch, SessionId, TenantId, Timestamp,
};
use crawlx_scheduler::CheckpointReason;
use crawlx_storage::checkpoint_crypto::{CheckpointContext, CheckpointKeys, UnavailableCheckpointKeys};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::{Zeroize as _, Zeroizing};

/// Content of the checkpoint artifact.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CheckpointPayload {
    /// Version.
    pub version: u8,
    /// Exact security identity and generation; lease renewal alone does not change identity.
    #[serde(default)]
    pub binding: Option<crawlx_core::session_binding::SessionBindingV1>,
    /// URL of the page at checkpoint time (restore navigates here).
    pub url: String,
    /// Admitted handler label, independent of the checkpoint's redirected location.
    pub request_route: Option<String>,
    /// Epoch.
    pub epoch: ObservationEpoch,
    /// Action seq.
    pub action_seq: u64,
    /// `BrowserContext::export_storage` bytes, base64.
    pub storage_b64: String,
}

impl std::fmt::Debug for CheckpointPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointPayload")
            .field("version", &self.version)
            .field("url", &"[REDACTED]")
            .field("epoch", &self.epoch)
            .field("action_seq", &self.action_seq)
            .field("storage_b64", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CheckpointPayload {
    fn drop(&mut self) {
        self.url.zeroize();
        self.storage_b64.zeroize();
    }
}

impl CheckpointPayload {
    /// Version.
    pub const VERSION: u8 = 3;

    /// Decoded storage blob.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub fn storage(&self) -> Result<Vec<u8>, SessionError> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.storage_b64)
            .map_err(|e| SessionError::Other(format!("checkpoint storage is not base64: {e}")))
    }
}

/// Writes and loads checkpoints of one session.
#[derive(Clone)]
pub struct Checkpointer {
    tenant: TenantId,
    keys: Arc<dyn CheckpointKeys>,
    /// Run.
    pub run: CrawlRunId,
    /// Session.
    pub session: SessionId,
    repo: Arc<dyn CheckpointRepo>,
    artifacts: Arc<dyn ArtifactStore>,
    clock: Arc<dyn Clock>,
    retention_days: u16,
    binding: Option<crawlx_core::session_binding::SessionBindingV1>,
}

impl Checkpointer {
    #[must_use]
    /// New.
    pub fn new(
        tenant: TenantId,
        run: CrawlRunId,
        session: SessionId,
        repo: Arc<dyn CheckpointRepo>,
        artifacts: Arc<dyn ArtifactStore>,
        clock: Arc<dyn Clock>,
        retention_days: u16,
    ) -> Self {
        Self {
            tenant,
            keys: Arc::new(UnavailableCheckpointKeys),
            run,
            session,
            repo,
            artifacts,
            clock,
            retention_days,
            binding: None,
        }
    }

    /// Use the run's explicit checkpoint secret provider; the default refuses all I/O.
    #[must_use]
    pub fn with_keys(mut self, keys: Arc<dyn CheckpointKeys>) -> Self {
        self.keys = keys;
        self
    }

    /// Bind checkpoint I/O to the actor's strict identity. Legacy unbound payloads cannot
    /// restore into a bound actor. Lease fence renewal preserves the same generation.
    #[must_use]
    pub fn with_binding(mut self, binding: crawlx_core::session_binding::SessionBindingV1) -> Self {
        self.binding = Some(binding);
        self
    }

    /// Shorten a binding after its bounded login reservation has settled.
    pub(crate) fn narrow_binding_deadline(&mut self, deadline: Timestamp) {
        if let Some(binding) = &mut self.binding {
            binding.expires_at = binding.expires_at.min(deadline);
        }
    }

    /// Export the context's storage and persist it (artifact first, then the row: T3).
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn write(
        &self,
        ctx: &mut dyn BrowserContext,
        url: &str,
        request_route: Option<&str>,
        epoch: ObservationEpoch,
        action_seq: u64,
        reason: CheckpointReason,
    ) -> Result<CheckpointRecord, SessionError> {
        if let Some(binding) = &self.binding {
            if binding.identity.tenant != self.tenant
                || binding.identity.run != self.run
                || binding.identity.session != self.session
            {
                return Err(SessionError::Other(
                    "checkpoint session ownership conflict".into(),
                ));
            }
            if binding.expires_at <= self.clock.now() {
                return Err(SessionError::Binding(
                    crawlx_core::session_binding::SessionBindingError::Expired,
                ));
            }
        }
        let id = CheckpointId::new();
        let context = CheckpointContext::new(self.tenant, self.run, self.session, id);
        let storage = Zeroizing::new(ctx.export_storage().await?);
        let payload = CheckpointPayload {
            version: CheckpointPayload::VERSION,
            binding: self.binding.clone(),
            url: url.to_owned(),
            request_route: request_route.map(str::to_owned),
            epoch,
            action_seq,
            storage_b64: base64::engine::general_purpose::STANDARD.encode(storage.as_slice()),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&payload).map_err(SessionError::CheckpointEncoding)?);
        let ciphertext: Ciphertext = self.keys.seal(&context, bytes).await?;
        let now = self.clock.now();
        let expires_at = self.binding.as_ref().map_or(
            now + chrono::Duration::days(i64::from(self.retention_days.max(1))),
            |binding| binding.expires_at,
        );
        let artifact = ArtifactSink::over(self.artifacts.as_ref())
            .put_until(
                self.run,
                Sensitivity::CredentialBearing,
                "application/vnd.crawlx.checkpoint-encrypted",
                &ciphertext,
                expires_at,
            )
            .await?;
        let record = CheckpointRecord {
            id,
            run: self.run,
            session: self.session,
            epoch,
            action_seq,
            reason: reason.as_str().to_owned(),
            storage: artifact,
            url_hash: Some(Digest::of("crawlx/checkpoint-url/v1", url.as_bytes())),
            created_at: now,
            expires_at,
        };
        self.repo.put(&record).await?;
        Ok(record)
    }

    /// The newest checkpoint of the session.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn latest(&self) -> Result<Option<CheckpointRecord>, SessionError> {
        Ok(self.repo.latest(self.session).await?)
    }

    /// A specific checkpoint (must belong to this session).
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn get(&self, id: CheckpointId) -> Result<CheckpointRecord, SessionError> {
        self.repo
            .list(self.session)
            .await?
            .into_iter()
            .find(|c| c.id == id)
            .ok_or(SessionError::NoCheckpoint)
    }

    /// Download and decode the artifact of `record`.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn load(&self, record: &CheckpointRecord) -> Result<CheckpointPayload, SessionError> {
        if record.run != self.run || record.session != self.session || record.expires_at <= self.clock.now() {
            return Err(SessionError::Other(
                "checkpoint ownership or expiry conflict".into(),
            ));
        }
        let bytes = self.artifacts.get(&record.storage).await?;
        let context = CheckpointContext::new(self.tenant, self.run, self.session, record.id);
        let plaintext = self.keys.open(&context, bytes).await?;
        let payload: CheckpointPayload =
            serde_json::from_slice(&plaintext).map_err(SessionError::CheckpointEncoding)?;
        if payload.version != CheckpointPayload::VERSION {
            return Err(SessionError::CheckpointVersion);
        }
        if !payload.url.is_empty() && payload.request_route.is_none() {
            return Err(crawlx_core::extensions::ExtensionError::UnknownRoute.into());
        }
        if payload.action_seq != record.action_seq {
            return Err(SessionError::Other("checkpoint sequence conflict".into()));
        }
        if let Some(current) = &self.binding {
            let saved = payload
                .binding
                .as_ref()
                .ok_or_else(|| SessionError::Other("checkpoint has no strict session binding".into()))?;
            if saved.checkpoint_identity() != current.checkpoint_identity()
                || saved.expires_at <= self.clock.now()
            {
                return Err(SessionError::Other(
                    "checkpoint session binding generation conflict".into(),
                ));
            }
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn debug_never_exposes_checkpoint_credentials() {
        let payload = CheckpointPayload {
            version: CheckpointPayload::VERSION,
            binding: None,
            url: "https://example.test/?token=checkpoint-query-canary".to_owned(),
            request_route: Some("checkpoint-article".into()),
            epoch: ObservationEpoch::default(),
            action_seq: 7,
            storage_b64: base64::engine::general_purpose::STANDARD.encode(b"checkpoint-storage-canary"),
        };
        let debug = format!("{payload:?}");
        assert!(!debug.contains("checkpoint-query-canary"));
        assert!(!debug.contains(&payload.storage_b64));
        assert_eq!(payload.storage().unwrap(), b"checkpoint-storage-canary");
    }

    #[tokio::test]
    async fn restore_refuses_stale_generation_and_cross_principal_secret_state() {
        use crawlx_core::session_binding::{SessionBindingV1, SessionIdentityV1};
        let directory = tempfile::tempdir().unwrap();
        let memory = Arc::new(crawlx_storage::MemoryStore::new());
        let stores = crate::Stores::over_memory(memory, directory.path())
            .await
            .unwrap();
        let run = crawlx_storage::testkit::crawl_run(
            stores.tenant,
            crawlx_storage::testkit::create_crawl("https://example.test/", &["role0"], 1),
        );
        stores.runs.create(&run, None).await.unwrap();
        let session = crawlx_storage::testkit::sessions(run.id, 1, 1).remove(0);
        stores
            .runs
            .create_sessions(std::slice::from_ref(&session))
            .await
            .unwrap();
        let now = crawlx_core::SystemClock.now();
        let digest = Digest::of("checkpoint-fixture", b"policy");
        let identity = SessionIdentityV1::new(stores.tenant, &session, digest, digest, digest, digest, None);
        let binding = SessionBindingV1::new(identity, 5, now + chrono::Duration::minutes(10));
        let payload = CheckpointPayload {
            version: CheckpointPayload::VERSION,
            binding: Some(binding.clone()),
            url: "https://example.test/".into(),
            request_route: Some("default".into()),
            epoch: ObservationEpoch::default(),
            action_seq: 7,
            storage_b64: base64::engine::general_purpose::STANDARD.encode(b"principal-secret-state"),
        };
        let id = CheckpointId::new();
        let context = CheckpointContext::new(stores.tenant, run.id, session.id, id);
        let ciphertext = stores
            .checkpoint_keys
            .seal(
                &context,
                zeroize::Zeroizing::new(serde_json::to_vec(&payload).unwrap()),
            )
            .await
            .unwrap();
        let artifact = ArtifactSink::over(stores.artifacts.as_ref())
            .put(
                run.id,
                Sensitivity::CredentialBearing,
                "application/vnd.crawlx.checkpoint-encrypted",
                &ciphertext,
            )
            .await
            .unwrap();
        let record = CheckpointRecord {
            id,
            run: run.id,
            session: session.id,
            epoch: payload.epoch,
            action_seq: 7,
            reason: "shutdown".into(),
            storage: artifact,
            url_hash: None,
            created_at: now,
            expires_at: binding.expires_at,
        };
        stores.checkpoints.put(&record).await.unwrap();
        let checkpointer = Checkpointer::new(
            stores.tenant,
            run.id,
            session.id,
            stores.checkpoints.clone(),
            stores.artifacts.clone(),
            Arc::new(crawlx_core::SystemClock),
            1,
        )
        .with_keys(Arc::clone(&stores.checkpoint_keys));
        let mut stale = binding.clone();
        stale.generation += 1;
        assert!(checkpointer
            .clone()
            .with_binding(stale)
            .load(&record)
            .await
            .is_err());
        let mut wrong = binding.clone();
        wrong.identity.principal = crawlx_core::PrincipalId("admin".into());
        assert!(checkpointer
            .clone()
            .with_binding(wrong)
            .load(&record)
            .await
            .is_err());
        let mut renewed = binding;
        renewed.lease_fence += 1;
        assert_eq!(
            checkpointer
                .clone()
                .with_binding(renewed)
                .load(&record)
                .await
                .unwrap()
                .storage()
                .unwrap(),
            b"principal-secret-state",
            "renewing a lease preserves the same strict generation"
        );
        for version in [2, CheckpointPayload::VERSION] {
            let mut route_less = serde_json::to_value(&payload).unwrap();
            route_less["version"] = serde_json::json!(version);
            let _ = route_less.as_object_mut().unwrap().remove("request_route");
            let ciphertext = stores
                .checkpoint_keys
                .seal(&context, Zeroizing::new(serde_json::to_vec(&route_less).unwrap()))
                .await
                .unwrap();
            let artifact = ArtifactSink::over(stores.artifacts.as_ref())
                .put(
                    run.id,
                    Sensitivity::CredentialBearing,
                    "application/vnd.crawlx.checkpoint-encrypted",
                    &ciphertext,
                )
                .await
                .unwrap();
            let mut refused = record.clone();
            refused.storage = artifact;
            let error = checkpointer.load(&refused).await.unwrap_err();
            if version == 2 {
                assert!(matches!(error, SessionError::CheckpointVersion));
            } else {
                assert!(matches!(
                    error,
                    SessionError::Extension(crawlx_core::extensions::ExtensionError::UnknownRoute,)
                ));
            }
        }
    }
}
