//! Driver-owned local interactive profile control.
//!
//! In this explicit local mode the driver never explores autonomously. It receives bounded
//! operator commands from the shared [`InteractiveProfiles`](crate::interactive_profiles)
//! registry and turns each one into the ordinary pipeline: a fresh observation, fresh keyed
//! candidates, an `ActionProposal`, kernel adjudication (durable approval consumed through the
//! same fenced path as exploration), journaled actor execution and live confirmation. There is no
//! second admission path, raw CDP, script or stored locator. Every command re-verifies the live
//! session binding and lease through an actor round trip before it is acknowledged, a closed
//! reply fails closed before any effect, and cancellation or expiry shuts the actor down without
//! a profile commit.

use super::*;
use crate::durable::DurableAuthority;
use crate::interactive_profiles::{
    proposal_for_input, InteractiveCommand, InteractiveControl, InteractiveError, InteractiveReply,
    InteractiveScope, InteractiveStart, ProfileInput,
};
use crawlx_core::custody::{CustodyLease, SecretRegistrar};
use crawlx_core::observation::DomSelector;
use crawlx_core::{SecretOr, Timestamp};
use crawlx_storage::artifact_key_crypto::ArtifactKeys;
use crawlx_storage::custody::profiles::CustodyProfiles;
use crawlx_storage::profiles::ProfileScopeV1;
use crawlx_storage::SessionLease;

/// Everything the local interactive branch needs, all produced by the run owner. None of it is
/// ambient: the lease, custody producer and registrar are the session's own authorities.
#[non_exhaustive]
pub struct InteractiveDeps {
    /// Actor-owned mailbox; dropping it revokes every API control.
    pub control: InteractiveControl,
    /// The run's existing secret authority.
    pub authority: Arc<DurableAuthority>,
    /// The exact key provider artifact custody uses.
    pub keys: Arc<dyn ArtifactKeys>,
    /// The session's producer custody lease (never fabricated here).
    pub custody: CustodyLease,
    /// Run-wide registration of every secret before it can reach the browser.
    pub registrar: Arc<dyn SecretRegistrar>,
    /// Operator permission to retain an encrypted structured profile.
    pub retained_profile_approved: bool,
    /// Trusted scheduler lease of this session.
    pub lease: SessionLease,
}

impl InteractiveDeps {
    /// Assemble the authorities of one fresh local interactive session.
    #[must_use]
    pub fn new(
        control: InteractiveControl,
        authority: Arc<DurableAuthority>,
        keys: Arc<dyn ArtifactKeys>,
        custody: CustodyLease,
        registrar: Arc<dyn SecretRegistrar>,
        retained_profile_approved: bool,
        lease: SessionLease,
    ) -> Self {
        Self {
            control,
            authority,
            keys,
            custody,
            registrar,
            retained_profile_approved,
            lease,
        }
    }
}

struct Started {
    scope: ProfileScopeV1,
    expected_generation: u64,
    expires_at: Timestamp,
}

enum Failure {
    /// Operator-visible refusal; the session stays usable.
    Refused,
    /// Authority, storage or session failure; the session ends.
    Fatal(WorkerError),
}
impl From<WorkerError> for Failure {
    fn from(error: WorkerError) -> Self {
        Self::Fatal(error)
    }
}

impl From<SessionError> for Failure {
    fn from(error: SessionError) -> Self {
        Self::Fatal(error.into())
    }
}

impl From<crawlx_core::StoreError> for Failure {
    fn from(error: crawlx_core::StoreError) -> Self {
        Self::Fatal(error.into())
    }
}

fn refused<T>() -> Result<T, Failure> {
    Err(Failure::Refused)
}

type Reply = tokio::sync::oneshot::Sender<Result<InteractiveReply, InteractiveError>>;

impl ExplorationDriver {
    /// Select the manual interactive branch. It replaces autonomous exploration.
    #[must_use]
    pub fn with_interactive(mut self, deps: InteractiveDeps) -> Self {
        self.approval_lease = Some(deps.lease.clone());
        self.interactive = Some(deps);
        self
    }

    /// Close the owned actor without a profile commit and end the session.
    async fn interactive_abort(&mut self, terminal: TerminalReason) -> Result<DriverEnd, WorkerError> {
        // Cancelled shutdown never writes a checkpoint: nothing here may reach plaintext state.
        self.handle
            .shutdown(crate::actor::ShutdownReason::Cancelled)
            .await?;
        Ok(self.end(terminal))
    }

    /// Prove the live lease, binding and run authorization before acknowledging anything.
    async fn interactive_verify(
        &self,
        deps: &InteractiveDeps,
        scope: &InteractiveScope,
    ) -> Result<(), Failure> {
        let binding = deps.control.binding();
        let identity = &binding.identity;
        if identity.tenant != self.rc.stores.tenant
            || identity.run != self.rc.run
            || identity.session != self.session.id
            || scope.tenant != identity.tenant
            || scope.run != identity.run
            || scope.session != identity.session
            || scope.generation != binding.generation
            || scope.lease_fence != binding.lease_fence
            || deps.lease.fencing_token != binding.lease_fence
        {
            return refused();
        }
        if let Some(guard) = &self.rc.authorization {
            if guard.check_now().await.is_err() {
                return refused();
            }
        }
        // The actor re-verifies its binding and lease before every command it serves.
        self.handle.observe(spec::cheap()).await?;
        Ok(())
    }

    /// Fresh-only preflight and the exact retained-profile namespace.
    fn interactive_start(
        &self,
        deps: &InteractiveDeps,
        request: &InteractiveStart,
    ) -> Result<Started, Failure> {
        request.validate().map_err(|_| Failure::Refused)?;
        let binding = deps.control.binding();
        // Fresh incognito only: never a restored or persistent profile, never a prior login.
        if binding.identity.profile.is_some()
            || self.authenticated
            || !deps.retained_profile_approved
            || !deps.keys.is_available()
        {
            return refused();
        }
        let now = self.rc.clock.now();
        let expires_at = binding
            .expires_at
            .min(now + chrono::Duration::seconds(i64::from(request.ttl_seconds)));
        if expires_at <= now {
            return refused();
        }
        let scope = ProfileScopeV1::new(
            self.rc.stores.tenant,
            self.session.role.clone(),
            request.profile_name.clone(),
            std::collections::BTreeSet::from([self.rc.seed_origin()]),
            binding.identity.backend_build,
            binding.identity.egress,
        )
        .map_err(|_| Failure::Refused)?;
        Ok(Started {
            scope,
            expected_generation: request.expected_generation,
            expires_at,
        })
    }

    /// Resolve a credential reference only when it is exactly the one already admitted for this
    /// session's role. Registration with the run precedes any delivery; the value is never
    /// logged or serialized. The field typed follows the live element: password inputs receive
    /// the password, every other input the username.
    async fn interactive_secret(
        &self,
        deps: &InteractiveDeps,
        reference: &crawlx_core::secret::CredentialRef,
        password_field: bool,
    ) -> Result<SecretOr<String>, Failure> {
        let admitted = self
            .rc
            .crawl
            .effective_roles()
            .into_iter()
            .find(|role| role.name == self.session.role.0)
            .and_then(|role| role.credential_ref);
        if admitted.as_ref() != Some(reference) {
            return refused();
        }
        let resolved = self
            .rc
            .secrets
            .resolve(reference)
            .await
            .map_err(|_| Failure::Refused)?;
        let credential = crate::login::LoginCredential::parse(&resolved).map_err(|_| Failure::Refused)?;
        let value = if password_field {
            credential.password
        } else {
            credential.username
        };
        let value = SecretOr::secret(value.expose().to_owned());
        deps.registrar.register(&value).await?;
        self.rc
            .captcha_secrets
            .register(value.clone())
            .map_err(|_| Failure::Refused)?;
        let _ = self
            .rc
            .stores
            .events
            .append(
                self.rc.run,
                "secret.resolved",
                serde_json::json!({
                    "role": self.session.role.0,
                    "scheme": reference.scheme(),
                    "reference_hash": Digest::of("crawlx/worker/credential-ref", reference.0.as_bytes()).to_hex(),
                    "purpose": "interactive_profile",
                }),
            )
            .await;
        Ok(value)
    }

    /// Kernel adjudication with the durable approval path shared with exploration: only a
    /// consumed durable capability can grant; nothing presented by a caller does.
    async fn adjudicate_durable(
        &self,
        proposal: &ActionProposal,
        sc: &SafetyContext,
    ) -> Result<Adjudication, WorkerError> {
        let mut snapshot = None;
        if let Some(lease) = &self.approval_lease {
            let verdict = self.rc.kernel.classify(proposal, sc);
            if verdict.decision == SafetyDecision::ApprovalRequired {
                snapshot = self
                    .rc
                    .stores
                    .approvals
                    .find_approval(
                        self.rc.stores.tenant,
                        lease,
                        proposal.key.id(),
                        verdict.risk_class,
                        crawlx_safety::kernel::params_digest(&proposal.action),
                        proposal.epoch,
                    )
                    .await?;
            }
        }
        let Some(snapshot) = snapshot else {
            return Ok(self.rc.kernel.adjudicate(proposal.clone(), sc));
        };
        let lease = self
            .approval_lease
            .as_ref()
            .ok_or(crawlx_core::StoreError::LeaseLost)?;
        let receipt = self
            .rc
            .stores
            .approvals
            .consume_approval(self.rc.stores.tenant, lease, &snapshot)
            .await?;
        let r = receipt.request;
        let authority = ApprovalAuthority::new(
            self.rc.stores.tenant,
            self.rc.run,
            self.session.id,
            r.binding.action,
            receipt.fence,
            r.binding.epoch,
        );
        let request = ApprovalRequest {
            approval_id: r.id,
            action_key: r.binding.action_key,
            risk: r.binding.risk,
            params_digest: r.binding.params_digest,
            summary: r.summary,
            created_at: r.created_at,
            expires_at: r.expires_at,
        };
        let mut verified = VerifiedApproval::from_consumed(request, authority);
        Ok(self
            .rc
            .kernel
            .adjudicate_verified(proposal.clone(), sc, authority, &mut verified))
    }

    /// One typed operator input through the full ordinary pipeline. `Ok(true)` means a secret
    /// was delivered, so frames stay suppressed.
    async fn interactive_input(
        &mut self,
        deps: &InteractiveDeps,
        input: &ProfileInput,
    ) -> Result<bool, Failure> {
        // 1. Fresh observation and candidates; no cached locator is ever reused.
        let bundle = self.observe().await?;
        let state = self.persist_observation(&bundle).await?;
        let mut current = self.prepare(bundle, state.id, state.cluster).await;
        let target = self
            .handle
            .resolve_selector(DomSelector::css(input.selector()))
            .await?
            .ok_or(Failure::Refused)?;
        // 2. A credential fill is the existing documented actor-only login path, not a kernel
        // proposal (a password Type is deliberately a security change there). It runs only after
        // fresh structural checks on the live target, an exactly admitted reference and run-wide
        // registration of the selected value. The actor re-checks live origin and actionability.
        if let ProfileInput::TypeSecret { credential, .. } = input {
            let descriptor = current
                .candidates
                .iter()
                .find(|candidate| {
                    let locator = &candidate.descriptor.locator;
                    locator.backend_node_id == target.backend_node_id
                        && locator.tab == target.tab
                        && locator.frame == target.frame
                        && locator.epoch == target.epoch
                })
                .map(|candidate| &candidate.descriptor)
                .ok_or(Failure::Refused)?;
            let kind = descriptor
                .attributes
                .get("type")
                .map(|kind| kind.to_ascii_lowercase());
            let password_field = kind.as_deref() == Some("password");
            let username_field = matches!(kind.as_deref(), None | Some("" | "text" | "email" | "tel"));
            if descriptor.tag.as_deref() != Some("input")
                || descriptor.disabled
                || !descriptor.visible
                || descriptor.in_closed_shadow_root
                || !(password_field || username_field)
            {
                return refused();
            }
            let value = self.interactive_secret(deps, credential, password_field).await?;
            match self.handle.type_credential(target, value).await {
                Ok(()) => {}
                // Wrong origin or a field that stopped being actionable: refuse, keep the session.
                Err(SessionError::LoginFailed(_)) => return refused(),
                Err(error) => return Err(Failure::Fatal(error.into())),
            }
            self.charge_budget(BudgetKind::Interactions);
            self.rc.counters.attempt(Plane::Interactions, Attempt::Succeeded);
            return Ok(true);
        }
        // 3. Ordinary decision context and proposal over an existing keyed candidate only.
        self.decision_index += 1;
        self.state.begin_round(self.decision_index);
        let base = self.safety_base();
        let round_input = RoundInput::new(
            Arc::clone(&current.bundle),
            std::mem::take(&mut current.candidates),
            std::mem::take(&mut current.resolved),
            current.cluster,
            self.stream_index(),
            self.rc.crawl.safety.profile,
            self.budget_view(),
            self.rc.clock.now(),
        );
        let (proposal, sc) = {
            let ctx = self
                .state
                .context(round_input)
                .map_err(|error| WorkerError::Other(error.to_string()))?;
            let mut proposal = proposal_for_input(&ctx, input, &target).map_err(|_| Failure::Refused)?;
            ctx.ledger.normalize_key(&mut proposal.key);
            let sc = ctx.safety_context(&base, &proposal.key);
            (proposal, sc)
        };
        // 4. Kernel adjudication; a denial or pending approval is journaled and refused.
        let admitted = match self.adjudicate_durable(&proposal, &sc).await? {
            Adjudication::Allow(admitted) => admitted,
            Adjudication::Deny(verdict) | Adjudication::ApprovalRequired(verdict, _) => {
                self.rc
                    .counters
                    .discovery(Plane::Interactions, DiscoveryOutcome::PolicyBlocked);
                if self.blocked_seen.insert(proposal.key.id()) {
                    self.journal_blocked(&proposal, &verdict).await?;
                    if let Some(approval) = verdict.approval {
                        self.pending_approvals.insert(proposal.key.id(), approval);
                    }
                }
                return refused();
            }
        };
        // 5. Journaled actor execution with live target and epoch confirmation.
        self.rc
            .counters
            .discovery(Plane::Interactions, DiscoveryOutcome::Admitted);
        let outcome = match self.handle.execute(admitted, self.cfg.action_settle()).await {
            Ok(outcome) => outcome,
            Err(error) => {
                self.rc.counters.attempt(Plane::Interactions, Attempt::Failed);
                return Err(Failure::Fatal(error.into()));
            }
        };
        if outcome.dropped.is_some() {
            self.rc.counters.attempt(Plane::Interactions, Attempt::Abandoned);
            return refused();
        }
        self.charge_budget(BudgetKind::Interactions);
        let succeeded = outcome.status == ActionStatus::Succeeded;
        self.rc.counters.attempt(
            Plane::Interactions,
            if succeeded {
                Attempt::Succeeded
            } else {
                Attempt::Failed
            },
        );
        if !succeeded {
            return refused();
        }
        Ok(false)
    }

    /// Strict export, encrypted custody commit, confirmed actor death, then the registry mark.
    async fn interactive_finish(
        &mut self,
        deps: &InteractiveDeps,
        started: &Started,
    ) -> Result<u64, Failure> {
        let storage = self.handle.export_profile_storage().await?;
        let inspection = crate::on_authority!(deps.authority.as_ref(), authority => {
            CustodyProfiles::new(authority, deps.keys.as_ref())
                .commit(
                    &deps.lease,
                    &deps.custody,
                    &started.scope,
                    started.expected_generation,
                    started.expires_at,
                    deps.retained_profile_approved,
                    &storage,
                )
                .await?
        });
        // The plaintext snapshot leaves memory before cleanup begins.
        drop(storage);
        // Resource death must be confirmed before success is reported. Cancelled shutdown never
        // writes a checkpoint, so no plaintext fallback exists.
        self.handle
            .shutdown(crate::actor::ShutdownReason::Cancelled)
            .await?;
        Ok(inspection.generation)
    }

    /// Serve operator commands until finish, cancellation, expiry or a stop reason.
    pub(super) async fn run_interactive(
        &mut self,
        mut deps: InteractiveDeps,
    ) -> Result<DriverEnd, WorkerError> {
        let cancel = deps.control.cancellation();
        let mut started: Option<Started> = None;
        loop {
            if let Some(reason) = self.stop_reason().await? {
                return self.interactive_abort(reason).await;
            }
            let command = tokio::select! {
                biased;
                () = self.rc.cancel.cancelled() => None,
                command = deps.control.recv() => command,
            };
            let Some(command) = command else {
                return self.interactive_abort(TerminalReason::Cancelled).await;
            };
            let (scope, closed) = match &command {
                InteractiveCommand::Start { scope, reply, .. }
                | InteractiveCommand::Inspect { scope, reply }
                | InteractiveCommand::Input { scope, reply, .. }
                | InteractiveCommand::Finish { scope, reply } => (scope.clone(), reply.is_closed()),
            };
            if closed {
                // The API request was dropped: refuse before any effect and close.
                return self.interactive_abort(TerminalReason::Cancelled).await;
            }
            match self.interactive_verify(&deps, &scope).await {
                Ok(()) => {}
                Err(Failure::Refused) => {
                    reply_refused(command);
                    return self.interactive_abort(TerminalReason::Cancelled).await;
                }
                Err(Failure::Fatal(error)) => {
                    reply_refused(command);
                    let _ = self.interactive_abort(TerminalReason::Cancelled).await;
                    return Err(error);
                }
            }
            match command {
                InteractiveCommand::Inspect { reply, .. } => {
                    let _ = reply.send(Ok(InteractiveReply::Accepted));
                }
                InteractiveCommand::Start { request, reply, .. } => {
                    if started.is_some() {
                        let _ = reply.send(Err(InteractiveError::Refused));
                        continue;
                    }
                    match self.interactive_start(&deps, &request) {
                        Ok(value) => {
                            started = Some(value);
                            let _ = reply.send(Ok(InteractiveReply::Ready));
                        }
                        Err(_) => {
                            let _ = reply.send(Err(InteractiveError::Refused));
                        }
                    }
                }
                InteractiveCommand::Input { input, reply, .. } => {
                    if started.is_none() {
                        let _ = reply.send(Err(InteractiveError::Refused));
                        continue;
                    }
                    let outcome = tokio::select! {
                        biased;
                        () = cancel.cancelled() => None,
                        result = self.interactive_input(&deps, &input) => Some(result),
                    };
                    match outcome {
                        None => {
                            let _ = reply.send(Err(InteractiveError::Refused));
                            return self.interactive_abort(TerminalReason::Cancelled).await;
                        }
                        Some(Ok(secret_present)) => {
                            let _ = deps.control.suppress_frame(secret_present);
                            let _ = reply.send(Ok(InteractiveReply::Accepted));
                        }
                        Some(Err(Failure::Refused)) => {
                            let _ = reply.send(Err(InteractiveError::Refused));
                        }
                        Some(Err(Failure::Fatal(error))) => {
                            let _ = reply.send(Err(InteractiveError::Refused));
                            let _ = self.interactive_abort(TerminalReason::FatalError).await;
                            return Err(error);
                        }
                    }
                }
                InteractiveCommand::Finish { reply, .. } => {
                    let Some(profile) = started.take() else {
                        let _ = reply.send(Err(InteractiveError::Refused));
                        continue;
                    };
                    let outcome = tokio::select! {
                        biased;
                        () = cancel.cancelled() => None,
                        result = self.interactive_finish(&deps, &profile) => Some(result),
                    };
                    let generation = match outcome {
                        Some(Ok(generation)) => generation,
                        _ => {
                            let _ = reply.send(Err(InteractiveError::Refused));
                            return self.interactive_abort(TerminalReason::Cancelled).await;
                        }
                    };
                    // Registry mark BEFORE the reply: only then is a structural tombstone kept.
                    if deps.control.committed(generation).is_err() {
                        let _ = reply.send(Err(InteractiveError::Refused));
                        return Ok(self.end(TerminalReason::Cancelled));
                    }
                    let _ = reply.send(Ok(InteractiveReply::Committed { generation }));
                    return Ok(self.end(TerminalReason::FrontierExhausted));
                }
            }
        }
    }
}

fn reply_refused(command: InteractiveCommand) {
    let reply: Reply = match command {
        InteractiveCommand::Start { reply, .. }
        | InteractiveCommand::Inspect { reply, .. }
        | InteractiveCommand::Input { reply, .. }
        | InteractiveCommand::Finish { reply, .. } => reply,
    };
    let _ = reply.send(Err(InteractiveError::Unavailable));
}
