//! Operator-approved encrypted profile runtime. Plaintext is confined to private tmpfs
//! directories and erased only after the owned browser's resource death is confirmed.

use crate::actor::SessionConfig;
use crate::config::RetainedProfilePolicy;
use crate::error::WorkerError;
use crate::run::RunContext;
use crawlx_core::browser::{NavigationGuard, NavigationVerdict, ProfileSpec};
use crawlx_core::hash::Digest;
use crawlx_core::session_binding::SessionIdentityV1;
use crawlx_core::StoreError;
use crawlx_storage::leases::SessionLease;
use crawlx_storage::profiles::{BrowserProfileRepo, ProfileCipher, ProfileFiles, ProfileScopeV1};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Linux tmpfs path. No fallback to a disk-backed temporary directory is permitted.
pub(crate) const PROFILE_TMPFS: &str = crawlx_storage::profiles::PROFILE_RUNTIME_ROOT;

/// An owned runtime copy and its fenced encrypted save operation.
pub(crate) struct ProfileRun {
    pg: crawlx_storage::Pg,
    cipher: Arc<ProfileCipher>,
    scope: ProfileScopeV1,
    lease: SessionLease,
    binding: crawlx_core::session_binding::ProfileLeaseV1,
    policy: RetainedProfilePolicy,
    save: bool,
    dir: tempfile::TempDir,
    cpu: crate::runtime::CpuPool,
}

#[derive(Debug)]
struct ProfileGuard {
    origins: BTreeSet<String>,
    inner: Option<Arc<dyn NavigationGuard>>,
}

#[async_trait::async_trait]
impl NavigationGuard for ProfileGuard {
    async fn check(&self, url: &url::Url) -> NavigationVerdict {
        if !self.origins.contains(&url.origin().ascii_serialization()) {
            return NavigationVerdict::RobotsBlocked {
                reason: "profile_origin_binding",
            };
        }
        match &self.inner {
            Some(inner) => inner.check(url).await,
            None => NavigationVerdict::Allow,
        }
    }
    async fn check_request(&self, url: &url::Url) -> NavigationVerdict {
        if !self.origins.contains(&url.origin().ascii_serialization()) {
            return NavigationVerdict::RobotsBlocked {
                reason: "profile_origin_binding",
            };
        }
        match &self.inner {
            Some(inner) => inner.check_request(url).await,
            None => NavigationVerdict::Allow,
        }
    }
    fn intercepts_subresources(&self) -> bool {
        true
    }
    async fn check_subresource(&self, url: &url::Url) -> NavigationVerdict {
        if !self.origins.contains(&url.origin().ascii_serialization()) {
            return NavigationVerdict::RobotsBlocked {
                reason: "profile_origin_binding",
            };
        }
        match &self.inner {
            Some(inner) => inner.check_subresource(url).await,
            None => NavigationVerdict::Allow,
        }
    }
}

fn unavailable(message: &str) -> WorkerError {
    WorkerError::Config(format!("profile_unavailable: {message}"))
}

fn check_tmpfs() -> Result<(), StoreError> {
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|_| StoreError::Conflict("profile tmpfs mount evidence unavailable".into()))?;
    if !mounts.lines().any(|line| {
        let mut parts = line.split(" - ");
        let mount = parts.next().and_then(|head| head.split_whitespace().nth(4));
        let kind = parts.next().and_then(|tail| tail.split_whitespace().next());
        mount == Some(PROFILE_TMPFS) && kind == Some("tmpfs")
    }) {
        return Err(StoreError::Conflict(
            "profile plaintext requires /dev/shm tmpfs".into(),
        ));
    }
    Ok(())
}

impl ProfileRun {
    /// Resolve operator key and require tmpfs before any browser process is launched.
    pub(crate) async fn encryption(rc: &RunContext) -> Result<(Arc<ProfileCipher>, Digest), WorkerError> {
        let policy = rc
            .retained_profiles
            .as_ref()
            .ok_or_else(|| unavailable("operator retained-profile policy missing"))?;
        if policy.max_ttl.is_zero() || policy.max_ttl > std::time::Duration::from_secs(86_400) {
            return Err(unavailable("operator profile TTL must be 1..=86400 seconds"));
        }
        if rc
            .crawl
            .dynamic
            .browser_profile
            .as_ref()
            .is_some_and(|profile| profile.save_changes)
            && !policy.executable_preferences
        {
            return Err(unavailable(
                "saving full Chromium profiles requires operator executable-preferences approval",
            ));
        }
        rc.cpu_pool
            .run(check_tmpfs)
            .await
            .map_err(|_| unavailable("tmpfs capability check failed"))??;
        let secret = rc
            .secrets
            .resolve(&policy.key_ref)
            .await
            .map_err(|_| unavailable("profile encryption key cannot be resolved"))?;
        let key = Zeroizing::new(
            Digest::from_hex(secret.expose())
                .map_err(|_| unavailable("profile key must resolve to 64 hexadecimal characters"))?
                .0,
        );
        let cipher = Arc::new(ProfileCipher::new(key.as_slice())?);
        // A stable secret-keyed egress identity distinguishes sticky credentials without
        // exposing them or changing identity merely because the loopback proxy port changed.
        let egress = Digest::keyed(
            &key,
            "crawlx/profile-egress/v1",
            rc.egress.route_for(&rc.crawl)?.identity().as_bytes(),
        );
        Ok((cipher, egress))
    }

    /// Acquire exact encrypted profile under the existing live scheduler lease.
    pub(crate) async fn prepare(
        rc: &RunContext,
        lease: &SessionLease,
        identity: &SessionIdentityV1,
        cfg: &mut SessionConfig,
        cipher: Arc<ProfileCipher>,
        egress: Digest,
    ) -> Result<Self, WorkerError> {
        let requested = rc
            .crawl
            .dynamic
            .browser_profile
            .as_ref()
            .ok_or_else(|| unavailable("profile not requested"))?;
        let policy = rc
            .retained_profiles
            .clone()
            .ok_or_else(|| unavailable("operator retained-profile policy missing"))?;
        if rc.crawl.retention.mode == crawlx_core::config::RetentionMode::Zdr {
            return Err(unavailable("durable profiles forbidden under zdr"));
        }
        let pg = rc
            .stores
            .pg
            .clone()
            .ok_or_else(|| unavailable("cross-process PostgreSQL fence required"))?;
        let scope = ProfileScopeV1::new(
            identity.tenant,
            identity.principal.clone(),
            requested.name.clone(),
            BTreeSet::from([rc.seed_origin()]),
            identity.backend_build,
            egress,
        )?;
        let repo = BrowserProfileRepo::new(&pg, cipher.as_ref());
        let (inspection, files) = match repo.acquire(lease, &scope, policy.executable_preferences).await? {
            Some(profile) => profile,
            None => {
                let run = rc.stores.runs.get_metadata(rc.run).await?;
                let retention_end =
                    run.created_at + chrono::Duration::days(i64::from(rc.crawl.retention.days));
                let ttl = i64::try_from(policy.max_ttl.as_secs())
                    .map_err(|_| unavailable("profile TTL overflow"))?;
                let expires_at = (rc.clock.now() + chrono::Duration::seconds(ttl)).min(retention_end);
                let empty = ProfileFiles::new(BTreeMap::new(), policy.executable_preferences)?;
                let bundle = cipher.seal(&scope, 1, expires_at, empty)?;
                let digest = Digest::of("crawlx/profile-bundle/v1", &bundle);
                repo.import(
                    lease,
                    &scope,
                    &bundle,
                    digest,
                    0,
                    true,
                    policy.executable_preferences,
                )
                .await?;
                repo.acquire(lease, &scope, policy.executable_preferences)
                    .await?
                    .ok_or_else(|| unavailable("new profile vanished before acquisition"))?
            }
        };
        let executable = policy.executable_preferences;
        pg.reap_profile_directories().await?;
        let descriptor = crawlx_storage::profiles::ProfileRuntimeLease::new(
            pg.profile_authority().await?,
            scope.tenant,
            lease,
        );
        let dir = rc
            .cpu_pool
            .run(move || {
                check_tmpfs()?;
                files.materialize(Path::new(PROFILE_TMPFS), &descriptor, executable)
            })
            .await
            .map_err(|_| unavailable("profile materialization task failed"))??;
        let name = dir
            .path()
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| unavailable("profile runtime directory invalid"))?
            .to_owned();
        cfg.context.browser_profile = Some(ProfileSpec {
            dir: name,
            save_changes: true,
        });
        cfg.context.incognito = false;
        cfg.exclusive_browser = true;
        cfg.context.navigation_guard = Some(Arc::new(ProfileGuard {
            origins: scope.allowed_origins.clone(),
            inner: cfg.context.navigation_guard.take(),
        }));
        let mut bound_identity = identity.clone();
        bound_identity.egress = egress;
        bound_identity.profile = Some(
            Digest::of_value("crawlx/profile-identity/v1", &(&scope, inspection.generation))
                .map_err(|error| StoreError::Serialization(error.to_string()))?,
        );
        let binding = crawlx_core::session_binding::ProfileLeaseV1::new(
            bound_identity,
            inspection.generation,
            scope.allowed_origins.clone(),
            lease.fencing_token,
            inspection.expires_at,
        );
        Ok(Self {
            pg,
            cipher,
            scope,
            lease: lease.clone(),
            binding,
            policy,
            save: requested.save_changes,
            dir,
            cpu: rc.cpu_pool.clone(),
        })
    }
    /// Exact measured session identity including profile generation and stable egress.
    pub(crate) fn identity(&self) -> &SessionIdentityV1 {
        &self.binding.identity
    }

    /// Deadline of this secret-bearing runtime copy.
    pub(crate) fn expires_at(&self) -> crawlx_core::Timestamp {
        self.binding.expires_at
    }

    /// Encrypt only after owned process death. The temporary copy is removed on every result.
    pub(crate) async fn finish(self) -> Result<(), StoreError> {
        if !self.save {
            return Ok(());
        }
        let generation = self
            .binding
            .generation
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict("profile generation exhausted".into()))?;
        let cipher = Arc::clone(&self.cipher);
        let scope = self.scope.clone();
        let expiry = self.binding.expires_at;
        let executable = self.policy.executable_preferences;
        let dir = self.dir;
        let bundle = self
            .cpu
            .run(move || {
                let files = ProfileFiles::read_directory(dir.path(), executable)?;
                cipher.seal(&scope, generation, expiry, files)
                // `dir` is dropped here: plaintext does not survive upload/database errors.
            })
            .await
            .map_err(|_| StoreError::Backend("profile export task failed".into()))??;
        let digest = Digest::of("crawlx/profile-bundle/v1", &bundle);
        BrowserProfileRepo::new(&self.pg, self.cipher.as_ref())
            .import(
                &self.lease,
                &self.scope,
                &bundle,
                digest,
                self.binding.generation,
                true,
                executable,
            )
            .await?;
        Ok(())
    }
}
