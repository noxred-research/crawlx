//! The recovery ladder. Each rung is bounded and logged as a
//! `session_recovery` event:
//!
//! 1. **Reattach** – the browser process is alive; probe the existing context.
//! 2. **New context + restore** – fresh incognito context, `Restore(latest checkpoint)`.
//! 3. **Re-login** – a fresh context, the stored `loginPlan`, then navigate to the checkpoint URL.
//! 4. **Fail** – the slot fails with `terminal_reason = recovery_exhausted`.
//!
//! Rung 3 does not replay a `PathPlan` to the checkpoint's cluster: the checkpoint URL is the
//! restore target (the enablement graph lives with the exploration driver, not the actor).

use crate::actor::{SessionActor, SessionState};
use crate::error::SessionError;
use crate::login::run_login;
use crawlx_observe::spec;
use std::sync::Arc;
use std::time::Duration;

/// Which rung brought the session back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum RecoveryRung {
    /// Reattach.
    Reattach,
    /// New context.
    NewContext,
    /// Relogin.
    Relogin,
}

impl RecoveryRung {
    #[must_use]
    /// As str.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reattach => "reattach",
            Self::NewContext => "new_context_restore",
            Self::Relogin => "relogin",
        }
    }
}

impl SessionActor {
    /// Run the ladder. On success the session is `Ready` again; on failure it is `Failed`.
    pub(crate) async fn recover(&mut self) -> Result<RecoveryRung, SessionError> {
        self.verify_current_binding().await?;
        self.set_state(SessionState::Recovering);
        let attempts = self.cfg.recovery_attempts.max(1);
        let mut last_error = String::from("no rung attempted");
        for rung in [
            RecoveryRung::Reattach,
            RecoveryRung::NewContext,
            RecoveryRung::Relogin,
        ] {
            if rung == RecoveryRung::Relogin && self.login.is_none() {
                continue;
            }
            for attempt in 1..=attempts {
                let result = match rung {
                    RecoveryRung::Reattach => self.rung_reattach().await,
                    RecoveryRung::NewContext => self.rung_new_context().await,
                    RecoveryRung::Relogin => self.rung_relogin().await,
                };
                match result {
                    Ok(()) => {
                        self.audit(
                            "session_recovery",
                            serde_json::json!({ "rung": rung.as_str(), "attempt": attempt, "ok": true }),
                        )
                        .await;
                        self.set_state(if self.cfg.awaits_login && self.login.is_none() {
                            SessionState::Authenticating
                        } else {
                            SessionState::Ready
                        });
                        return Ok(rung);
                    }
                    Err(e) => {
                        last_error = e.to_string();
                        self.audit(
                            "session_recovery",
                            serde_json::json!({ "rung": rung.as_str(), "attempt": attempt, "ok": false, "error": last_error }),
                        )
                        .await;
                        tokio::time::sleep(Duration::from_millis(20 * u64::from(attempt))).await;
                    }
                }
            }
        }
        self.audit(
            "session_recovery",
            serde_json::json!({ "rung": "exhausted", "ok": false, "error": last_error }),
        )
        .await;
        self.set_state(SessionState::Failed);
        Err(SessionError::RecoveryExhausted(last_error))
    }

    async fn rung_reattach(&mut self) -> Result<(), SessionError> {
        self.observer.reset();
        let bundle = self
            .observer
            .observe_shared(&mut *self.ctx, &spec::cheap())
            .await?;
        self.last = Some(bundle);
        Ok(())
    }

    /// Replace the dead context. The old lease is released first so a saturated pool (or an
    /// exclusive-process session) can hand out the slot again.
    async fn replace_context(&mut self) -> Result<(), SessionError> {
        if self.cfg.context.browser_profile.is_some() {
            return Err(SessionError::Other(
                "session_unavailable: retained profile requires an explicit drained restart".into(),
            ));
        }
        self.close_context().await?;
        let pooled = self
            .svc
            .pool
            .acquire(self.cfg.context.clone(), self.cfg.exclusive_browser)
            .await?;
        let (ctx, build, lease) = pooled.into_parts();
        if let Some(binding) = &self.cfg.context.session_binding {
            let actual = crawlx_core::hash::Digest::of_value("crawlx/session-backend-build/v1", &build)
                .map_err(|error| SessionError::Other(error.to_string()))?;
            if actual != binding.identity.backend_build {
                let closed = tokio::time::timeout(Duration::from_secs(5), ctx.close()).await;
                lease.release(matches!(closed, Ok(Ok(())))).await?;
                return Err(SessionError::Other(
                    "session_unavailable: recovery browser build changed".into(),
                ));
            }
        }
        let (ctx, pacing) = crate::pacing::wrap(ctx, &self.cfg, Arc::clone(&self.svc.clock));
        self.ctx = ctx;
        self.pacing = pacing;
        self.lease = Some(lease);
        self.prepare_context().await;
        self.observer.reset();
        self.svc
            .runs
            .set_session_browser(self.cfg.session, &build)
            .await?;
        Ok(())
    }

    async fn rung_new_context(&mut self) -> Result<(), SessionError> {
        let resume_url = self.last.as_ref().map(|b| b.url.clone());
        self.replace_context().await?;
        match self.checkpointer.latest().await? {
            Some(checkpoint) => {
                self.restore_record(&checkpoint).await?;
            }
            // no checkpoint yet: the browser restarts on the page the session last observed
            None => match resume_url {
                Some(url) => {
                    let mut request = crawlx_core::request::RequestEnvelopeV1::get(url, 0, None);
                    if let Some(route) = &self.current_request_route {
                        request.route.clone_from(route);
                    }
                    self.navigate(&request).await?;
                }
                None => return Err(SessionError::NoCheckpoint),
            },
        }
        let bundle = self
            .observer
            .observe_shared(&mut *self.ctx, &spec::cheap())
            .await?;
        self.last = Some(bundle);
        Ok(())
    }

    /// Re-login after a crash. A recorded flow is replayed only once, through
    /// the session's driver; inside the actor the rung logs in again with `builtin:form` and
    /// the same credential.
    async fn rung_relogin(&mut self) -> Result<(), SessionError> {
        let mut material = self
            .login
            .clone()
            .ok_or_else(|| SessionError::LoginFailed("no stored login plan".to_owned()))?;
        if material.plan.is_recorded() {
            material.plan = crawlx_forms::LoginPlan::builtin_form();
        }
        self.replace_context().await?;
        if let Some(url) = self.cfg.login_url.clone() {
            self.ctx.navigate(&url).await?;
        }
        run_login(
            &mut *self.ctx,
            &mut self.observer,
            &material,
            &self.cfg.seed_origin,
            self.cfg.settle,
        )
        .await
        .map_err(|e| SessionError::LoginFailed(e.to_string()))?;
        if let Some(checkpoint) = self.checkpointer.latest().await? {
            let payload = self.checkpointer.load(&checkpoint).await?;
            if let Ok(u) = url::Url::parse(&payload.url) {
                if let Ok(canon) = crawlx_url::Canonicalizer::canonicalize_url(&u, &self.cfg.canonicalize) {
                    self.ctx.navigate(&canon).await?;
                    self.current_request_route = Some(
                        payload
                            .request_route
                            .clone()
                            .ok_or(crawlx_core::extensions::ExtensionError::UnknownRoute)?,
                    );
                }
            }
        }
        let bundle = self
            .observer
            .observe_shared(&mut *self.ctx, &spec::cheap())
            .await?;
        self.last = Some(bundle);
        Ok(())
    }
}
