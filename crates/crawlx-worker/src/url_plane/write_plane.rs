//! Admitted HTTP writes: `POST`, `PUT`, `PATCH` and `DELETE` rows of the request queue.
//!
//! A write is a typed intent, never a fetch. It runs only after every gate below, in order, and
//! no gate can be skipped:
//!
//! 1. **Verdict.** The class of the method (`DELETE` is destructive, the other mutating methods
//!    are persistent writes) is decided by the same profile table, run options and authorization
//!    record narrowing the safety kernel applies to observed traffic. `read_only` refuses with
//!    its own typed reason. A class the table gates on a reviewer is sent only when the envelope
//!    carries that reviewer's approval for exactly that class; an approval never lifts a denial.
//! 2. **Never replayed.** A row that is leased again is not sent again when the journal holds an
//!    intent of an earlier holder (it may have sent the write and died before recording the
//!    answer: an unknown outcome) or cannot be read. Nothing is sent without its intent, so a
//!    row leased but never started is still sent, once.
//! 3. **Spooled body.** The body bytes must still be retained, have the recorded length and match
//!    their tenant-keyed digest. A missing or altered body refuses; nothing is reconstructed.
//! 4. **Effect charge.** One effect is reserved durably before dispatch and never refunded, so
//!    every send of a row, including one a later holder would make, counts against the total
//!    effect cap.
//! 5. **Journal.** A `request.write_intent` event is committed before the first byte is sent. If
//!    it cannot be written nothing is sent.
//!
//! The send itself ([`Fetcher::send_write`](crawlx_fetch::Fetcher)) is exactly one dispatch: no
//! retry, no redirect, no replay. A failure after dispatch is recorded as an unknown outcome.

use super::*;
use bytes::Bytes;
use crawlx_core::config::SafetyProfile;
use crawlx_core::identity::ActionKind;
use crawlx_core::orchestration::{QueuedRequestV1, WRITE_DISPATCH_EFFECTS};
use crawlx_core::request::{keyed_body_digest, RequestEnvelopeV1};
use crawlx_core::safety::{RiskClass, SafetyDecision};
use crawlx_fetch::client::WriteRequest;
use crawlx_safety::profiles::{decide, narrow_by_record, ProfileOptions};

/// Frontier reasons of a write that was refused or could not be sent.
mod reason {
    /// The run's profile is `read_only`.
    pub(super) const READ_ONLY: &str = "write_read_only";
    /// The profile table, a run option or the authorization record denies the class.
    pub(super) const DENIED: &str = "write_denied";
    /// The class needs a reviewer's approval and the envelope carries none.
    pub(super) const APPROVAL_REQUIRED: &str = "write_approval_required";
    /// The request is queued under a role principal; a role acts through its strict HTTP session,
    /// which a write does not use.
    pub(super) const PRINCIPAL_UNAVAILABLE: &str = "write_principal_unavailable";
    /// The run has no finite effect cap to charge.
    pub(super) const EFFECT_BUDGET_REQUIRED: &str = "write_effect_budget_required";
    /// The run's transport cannot send a write.
    pub(super) const BACKEND_UNAVAILABLE: &str = "write_backend_unavailable";
    /// The retained body is gone, expired or cannot be verified.
    pub(super) const BODY_UNAVAILABLE: &str = "write_body_unavailable";
    /// The retained body differs from the recorded length or digest.
    pub(super) const BODY_MISMATCH: &str = "write_body_mismatch";
    /// An earlier holder may have sent the request; it is never sent again.
    pub(super) const OUTCOME_UNKNOWN: &str = "write_outcome_unknown";
}

/// Events read per page when looking for earlier holders' write intents.
const JOURNAL_PAGE: u32 = 1000;

/// The write intents of the run learned so far, as the frontier ids they name, and how far into
/// the event log they were read. Intents are only ever appended, so reading resumes where the
/// last read stopped.
#[derive(Default)]
pub(super) struct WriteJournalScan {
    after_seq: u64,
    intents: std::collections::BTreeSet<i64>,
}

/// What the write admission decided.
enum WriteVerdict {
    Allow {
        rules: Vec<String>,
        approved_by: Option<String>,
    },
    Refuse {
        reason: &'static str,
        rules: Vec<String>,
    },
}

impl UrlPlaneRunner {
    /// Decide `request`, of class `risk`, under the run's profile, options and authorization
    /// record. Pure: it reads run state and never grants anything the kernel's table withholds.
    fn write_verdict(&self, request: &RequestEnvelopeV1, risk: RiskClass) -> WriteVerdict {
        let profile = self.crawl.safety.profile;
        let options = ProfileOptions {
            destructive: self.crawl.safety.destructive_actions,
            external: self.crawl.safety.external_communication,
            sink_verified: false,
        };
        let mut decided = decide(risk, profile, ActionKind::Click, &options);
        if let Some(guard) = &self.authorization {
            decided = narrow_by_record(decided, risk, &guard.narrowing());
        }
        let mut rules = decided.rules;
        match decided.decision {
            SafetyDecision::Allow => WriteVerdict::Allow {
                rules,
                approved_by: None,
            },
            SafetyDecision::Deny => WriteVerdict::Refuse {
                reason: if profile == SafetyProfile::ReadOnly {
                    reason::READ_ONLY
                } else {
                    reason::DENIED
                },
                rules,
            },
            SafetyDecision::ApprovalRequired => match &request.approval {
                Some(approval) if approval.risk == risk => {
                    rules.push("approval.envelope".to_owned());
                    WriteVerdict::Allow {
                        rules,
                        approved_by: Some(approval.approved_by.clone()),
                    }
                }
                _ => WriteVerdict::Refuse {
                    reason: reason::APPROVAL_REQUIRED,
                    rules,
                },
            },
        }
    }

    /// Complete a refused write as `policy_blocked` with its typed reason; nothing was sent.
    async fn refuse_write(
        &self,
        entry: &FrontierEntry,
        reason: &'static str,
        risk: RiskClass,
        rules: &[String],
    ) -> Result<(), WorkerError> {
        self.event(
            "request.write_refused",
            serde_json::json!({
                "version": 1, "requestId": entry.id, "reason": reason,
                "riskClass": risk.as_str(), "rules": rules,
            }),
        )
        .await;
        self.finish(entry, FrontierStatus::PolicyBlocked, Some(reason.to_owned()))
            .await
    }

    /// Complete a write that cannot be trusted to have been applied or not: the row fails with
    /// the unknown-outcome reason and is counted as such.
    async fn write_unknown(
        &self,
        entry: &FrontierEntry,
        why: &'static str,
        payload: serde_json::Value,
    ) -> Result<(), WorkerError> {
        self.finish(
            entry,
            FrontierStatus::Failed,
            Some(reason::OUTCOME_UNKNOWN.to_owned()),
        )
        .await?;
        self.counters
            .attempt_with_reason(Plane::Urls, Attempt::UnknownOutcome, reason::OUTCOME_UNKNOWN);
        self.event(
            "request.write_outcome",
            serde_json::json!({
                "version": 1, "requestId": entry.id, "outcome": "unknown", "cause": why,
                "detail": payload,
            }),
        )
        .await;
        Ok(())
    }

    /// Retained body bytes of `envelope`, verified against their recorded length and keyed digest.
    /// The refusal reason is returned for any body that is not exactly what was admitted.
    async fn resolve_write_body(
        &self,
        envelope: &RequestEnvelopeV1,
    ) -> Result<Result<Bytes, &'static str>, WorkerError> {
        let Some(body) = &envelope.body else {
            return Ok(Ok(Bytes::new()));
        };
        let (Some(artifact), Some(root)) = (body.artifact(), self.request_identity_key.as_ref()) else {
            return Ok(Err(reason::BODY_UNAVAILABLE));
        };
        let bytes = match self.deps.artifacts.get(&artifact).await {
            Ok(bytes) => bytes,
            Err(
                StoreError::NotFound { .. } | StoreError::RetentionDenied(_) | StoreError::AccessDenied(_),
            ) => return Ok(Err(reason::BODY_UNAVAILABLE)),
            Err(error) => return Err(error.into()),
        };
        let tenant = self.deps.runs.get_metadata(self.run).await?.tenant;
        let intact = u64::try_from(bytes.len()).is_ok_and(|length| length == body.length)
            && keyed_body_digest(root.expose(), tenant, &bytes) == body.digest;
        Ok(if intact {
            Ok(Bytes::from(bytes))
        } else {
            Err(reason::BODY_MISMATCH)
        })
    }

    /// Run one admitted write row to its terminal state. See the module documentation for the
    /// gates, which run in the order written there.
    ///
    /// # Errors
    /// Storage or lease failures. A write that was refused, failed or has an unknown outcome is
    /// completed on its row and is not an error.
    pub(super) async fn process_write_entry(
        &self,
        entry: &FrontierEntry,
        queued: &QueuedRequestV1,
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        let envelope = &queued.envelope;
        let Some(risk) = envelope.write_risk() else {
            return self
                .fail(
                    entry,
                    "unsupported_request_method",
                    "unsupported_request_method",
                    Attempt::Failed,
                    serde_json::json!({"reason":"not an executable write method"}),
                )
                .await;
        };
        let native_http = self.scrape.is_none()
            && !self.crawl.cache_only()
            && self.crawl.fetch.acquisition_service.is_none()
            && self.crawl.fetch.identity_profile.is_none()
            && crate::protocol::select_route(&self.protocol_routes, &entry.url.url)
                .is_none_or(|route| route.backend == crawlx_core::protocol::ProtocolBackendV1::Http);
        if !native_http || envelope.session_generation.is_some() || envelope.header_control.is_some() {
            return self
                .fail(
                    entry,
                    reason::BACKEND_UNAVAILABLE,
                    reason::BACKEND_UNAVAILABLE,
                    Attempt::Failed,
                    serde_json::json!({"reason":"writes require the plain native HTTP transport"}),
                )
                .await;
        }
        if queued.principal != "anonymous" {
            return self
                .refuse_write(entry, reason::PRINCIPAL_UNAVAILABLE, risk, &[])
                .await;
        }
        if self.crawl.orchestration.is_none() {
            return self
                .fail(
                    entry,
                    reason::EFFECT_BUDGET_REQUIRED,
                    reason::EFFECT_BUDGET_REQUIRED,
                    Attempt::Failed,
                    serde_json::json!({"reason":"writes require orchestration attempt limits"}),
                )
                .await;
        }

        // 1. Verdict.
        let (rules, approved_by) = match self.write_verdict(envelope, risk) {
            WriteVerdict::Allow { rules, approved_by } => (rules, approved_by),
            WriteVerdict::Refuse { reason, rules } => {
                return self.refuse_write(entry, reason, risk, &rules).await;
            }
        };

        // 2. Never replayed: a row an earlier holder dispatched is not sent again.
        if entry.attempts > 1 {
            match self.write_intent_recorded(entry.id).await {
                // No earlier holder reached the journal, and nothing is sent without its
                // intent: the row was leased but never started.
                Ok(false) => {}
                Ok(true) => {
                    return self
                        .write_unknown(
                            entry,
                            "earlier_holder_dispatched",
                            serde_json::json!({"attempts": entry.attempts}),
                        )
                        .await;
                }
                // Absence cannot be proven: treat it as possibly sent.
                Err(_) => {
                    return self
                        .write_unknown(
                            entry,
                            "journal_unreadable",
                            serde_json::json!({"attempts": entry.attempts}),
                        )
                        .await;
                }
            }
        }

        // 3. Spooled body.
        let body = match self.resolve_write_body(envelope).await? {
            Ok(body) => body,
            Err(reason) => {
                return self
                    .fail(
                        entry,
                        reason,
                        reason,
                        Attempt::Failed,
                        serde_json::json!({"reason": reason}),
                    )
                    .await;
            }
        };
        let method = http::Method::from_bytes(envelope.method.as_bytes())
            .map_err(|_| WorkerError::Config("invalid request method".into()))?;
        let media_type = envelope.body.as_ref().map(|body| body.media_type.as_str());
        let write = WriteRequest::new(method, body, media_type.filter(|value| !value.is_empty()))?;

        if self.stop_requested(cancel) {
            return self.hand_back_unsent(entry, cancel).await;
        }

        // 4. Effect charge, durable before dispatch and never refunded.
        let fence = *self.held.lock().get(&entry.id).ok_or(StoreError::LeaseLost)?;
        match self
            .deps
            .frontier
            .reserve_effects_fenced(self.run, entry.id, fence, WRITE_DISPATCH_EFFECTS)
            .await
        {
            Ok(()) => {}
            Err(StoreError::Conflict(_)) => {
                return self
                    .fail(
                        entry,
                        "request_effect_budget",
                        "request_effect_budget",
                        Attempt::Failed,
                        serde_json::json!({"reason":"durable request effect or elapsed allowance exhausted"}),
                    )
                    .await;
            }
            Err(error) => return Err(error.into()),
        }

        // 5. Journal: the intent is durable before the first byte leaves.
        self.deps
            .events
            .append(
                self.run,
                "request.write_intent",
                serde_json::json!({
                    "version": 1,
                    "requestId": entry.id,
                    "method": envelope.method,
                    "riskClass": risk.as_str(),
                    "decision": "allow",
                    "rules": rules,
                    "principal": queued.principal,
                    "approvedBy": approved_by,
                    "urlKey": entry.url.key.to_hex(),
                    "identity": queued.identity.key.to_hex(),
                    "bodyDigest": envelope.body.as_ref().map(|body| body.digest.to_hex()),
                    "bodyBytes": envelope.body.as_ref().map_or(0, |body| body.length),
                    "mediaType": media_type,
                    "fence": fence,
                    "attempt": entry.attempts,
                    "effects": WRITE_DISPATCH_EFFECTS,
                }),
            )
            .await?;

        let admission = NativeHopAdmission::new(self, entry).map_err(|_| StoreError::LeaseLost)?;
        let check = || async {
            if self.stop_requested(cancel) {
                return Err(FetchError::AcquisitionCancelled);
            }
            admission.authority().await?;
            if self.stop_requested(cancel) {
                return Err(FetchError::AcquisitionCancelled);
            }
            Ok(())
        };
        let options = crate::acquisition::fetch_options(&self.crawl.fetch);
        let timer = ReportStageTimer::start();
        let (sent, dns) = crawlx_fetch::resolver::capture_dns_reports(self.fetcher.send_write(
            &entry.url.url,
            &write,
            &options,
            &check,
        ))
        .await;
        self.note_dns(entry.id, dns);
        self.note_stage(
            entry.id,
            &timer,
            crawlx_core::report_history::ProcessorStageV1::Fetch,
            if sent.is_ok() {
                crawlx_core::report_history::StageOutcomeV1::Succeeded
            } else {
                crawlx_core::report_history::StageOutcomeV1::Failed
            },
            crawlx_core::report_history::ProcessorIdentityV1::NativeHttp,
        );

        match sent {
            Ok(response) => {
                self.note_wire(entry.id, &response);
                let code = response.status.as_u16();
                let success = response.status.is_success();
                self.event(
                    "request.write_outcome",
                    serde_json::json!({
                        "version": 1, "requestId": entry.id, "outcome": "answered",
                        "method": envelope.method, "status": code,
                        "contentType": response.content_type,
                        "bodyBytes": response.body.len(), "truncated": response.truncated,
                        "attempts": response.attempts,
                    }),
                )
                .await;
                self.finish(
                    entry,
                    if success {
                        FrontierStatus::Succeeded
                    } else {
                        FrontierStatus::Failed
                    },
                    Some(format!("http_{code}")),
                )
                .await?;
                self.counters.attempt(
                    Plane::Urls,
                    if success {
                        Attempt::Succeeded
                    } else {
                        Attempt::Failed
                    },
                );
                Ok(())
            }
            Err(failure) if failure.dispatched => {
                self.write_unknown(
                    entry,
                    "transport_failed_after_dispatch",
                    serde_json::json!({"error": failure.error.code()}),
                )
                .await
            }
            Err(failure) => match failure.error {
                FetchError::AcquisitionCancelled => {
                    self.event(
                        "request.write_outcome",
                        serde_json::json!({
                            "version": 1, "requestId": entry.id, "outcome": "not_sent",
                            "cause": "acquisition_cancelled",
                        }),
                    )
                    .await;
                    self.hand_back_unsent(entry, cancel).await
                }
                error => {
                    self.event(
                        "request.write_outcome",
                        serde_json::json!({
                            "version": 1, "requestId": entry.id, "outcome": "not_sent",
                            "cause": error.code(),
                        }),
                    )
                    .await;
                    let attempt = match &error {
                        FetchError::Resolve { .. }
                        | FetchError::Transport(_)
                        | FetchError::Timeout(_)
                        | FetchError::PeerNotPinned { .. } => Attempt::Unreachable,
                        _ => Attempt::Failed,
                    };
                    self.fail(
                        entry,
                        error.code(),
                        error.code(),
                        attempt,
                        serde_json::json!({ "reason": error.code() }),
                    )
                    .await
                }
            },
        }
    }

    /// A stop arrived before any byte was sent. A graceful drain hands the row back for its next
    /// holder; any other stop abandons it. The send never started, so neither replays a write.
    async fn hand_back_unsent(
        &self,
        entry: &FrontierEntry,
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        if self.stop_requested(cancel)
            && self.shutdown_checkpoint_requested()
            && !self.authorization_lost().await
            && self.deps.runs.get_metadata(self.run).await?.status != RunStatus::Cancelled
        {
            self.release_attempt(
                entry,
                crawlx_core::extensions::ExtensionTerminalV1::Skipped(
                    crawlx_core::extensions::ExtensionReasonV1::Cancelled,
                ),
            )
            .await?;
            let fence = self.held.lock().remove(&entry.id).ok_or(StoreError::LeaseLost)?;
            self.deps.frontier.give_back(entry.id, fence).await?;
            return Ok(());
        }
        self.finish(
            entry,
            FrontierStatus::Abandoned,
            Some("acquisition_cancelled".to_owned()),
        )
        .await?;
        self.counters
            .attempt_with_reason(Plane::Urls, Attempt::Abandoned, "acquisition_cancelled");
        Ok(())
    }
}

impl UrlPlaneRunner {
    /// Whether the journal holds a write intent for frontier row `id`.
    ///
    /// # Errors
    /// The event log cannot be read, for example because a volatile payload expired. The caller
    /// must then treat the write as possibly sent.
    async fn write_intent_recorded(&self, id: i64) -> Result<bool, StoreError> {
        let mut after = {
            let scan = self.write_journal.lock();
            if scan.intents.contains(&id) {
                return Ok(true);
            }
            scan.after_seq
        };
        loop {
            let page = self.deps.events.list_after(self.run, after, JOURNAL_PAGE).await?;
            let Some(last) = page.last().map(|event| event.seq) else {
                return Ok(false);
            };
            let learned: Vec<i64> = page
                .iter()
                .filter(|event| event.kind == "request.write_intent")
                .filter_map(|event| event.payload["requestId"].as_i64())
                .collect();
            after = last;
            {
                let mut scan = self.write_journal.lock();
                scan.intents.extend(learned);
                scan.after_seq = scan.after_seq.max(after);
                if scan.intents.contains(&id) {
                    return Ok(true);
                }
            }
            if page.len() < usize::try_from(JOURNAL_PAGE).unwrap_or(usize::MAX) {
                return Ok(false);
            }
        }
    }
}
