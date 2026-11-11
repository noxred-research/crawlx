//! Bounded, authenticated, volatile screencast status delivery.
//!
//! Ordinary page observations cannot prove that pixels contain no secrets. This
//! module therefore never takes screenshots and exposes no pixel/byte publishing
//! API. Every observation produces only a typed suppression status. Consent does
//! not establish pixel safety. A future positive-delivery implementation requires
//! an owned, race-free classification capability, not a caller-supplied boolean.
//! Statuses are not retained, replayed, logged, or written to browser artifacts.

use crawlx_core::{CrawlRunId, SessionId, TenantId};
use parking_lot::Mutex;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Maximum pending suppression events per subscriber.
pub const SCREENCAST_CAPACITY: usize = 4;
/// Maximum lifetime of one channel, even if the session lives longer.
pub const SCREENCAST_MAX_TTL: Duration = Duration::from_secs(300);

/// Exact authority required to subscribe to one live session generation.
///
/// Fields remain private so a channel owns an immutable scope after creation.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScreencastScope {
    tenant: TenantId,
    run: CrawlRunId,
    session: SessionId,
    generation: u64,
    lease_fence: i64,
    owner: String,
}

impl ScreencastScope {
    /// Bind all tenancy, lease, session-generation, and principal dimensions.
    #[must_use]
    pub fn new(
        tenant: TenantId,
        run: CrawlRunId,
        session: SessionId,
        generation: u64,
        lease_fence: i64,
        owner: String,
    ) -> Self {
        Self {
            tenant,
            run,
            session,
            generation,
            lease_fence,
            owner,
        }
    }
}

/// Observation classification; neither variant permits screenshot capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScreencastObservation {
    /// The complete rendered page has no owned proof of pixel safety.
    Unproven,
    /// The actor knows the page contains a secret-bearing surface.
    SecretPresent,
}

/// Why a frame was suppressed before capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppressionReason {
    /// Full-frame privacy could not be proven.
    PrivacyUnproven,
    /// A secret-bearing surface was observed.
    SecretPresent,
}

/// The only deliverable event: no pixels, DOM, URLs, identifiers, or secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScreencastEvent {
    /// No screenshot was taken for this observation.
    Suppressed {
        /// Stable privacy-safe reason code.
        reason: SuppressionReason,
    },
}

impl ScreencastEvent {
    /// Return the suppression reason without exposing page data.
    #[must_use]
    pub fn reason(self) -> SuppressionReason {
        match self {
            Self::Suppressed { reason } => reason,
        }
    }
}

/// Safe aggregate counters; no scope identifiers or page data are included.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScreencastMetrics {
    /// Observations suppressed before any capture attempt.
    pub suppressed_observations: u64,
    /// Events discarded because no receiver could accept them.
    pub dropped_events: u64,
    /// Subscribers closed immediately when their bounded queue filled.
    pub slow_consumer_closures: u64,
    /// Receivers dropped while their channel was still live.
    pub receiver_disconnects: u64,
    /// Suppression events handed to a receiver.
    pub delivered_events: u64,
}

/// Typed channel failures, deliberately free of caller or page data.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScreencastError {
    /// Scope did not match every channel binding.
    #[error("screencast scope does not match")]
    ScopeMismatch,
    /// Both explicit consents are required, even for a suppression-only stream.
    #[error("screencast capture and privacy consent are required")]
    ConsentRequired,
    /// A zero TTL cannot create a live channel.
    #[error("screencast lifetime must be positive")]
    InvalidLifetime,
    /// The monotonic deadline has passed.
    #[error("screencast channel expired")]
    Expired,
    /// The owning actor or registry cancelled the channel.
    #[error("screencast channel is cancelled")]
    Cancelled,
    /// Only one active receiver may hold this session stream.
    #[error("screencast already has a subscriber")]
    AlreadySubscribed,
    /// No live subscriber can accept a status.
    #[error("screencast receiver is disconnected")]
    Disconnected,
    /// A full queue closes the subscriber instead of blocking the browser actor.
    #[error("screencast receiver is too slow")]
    SlowConsumer,
}

struct Subscription {
    sender: mpsc::Sender<ScreencastEvent>,
    cancellation: CancellationToken,
}

#[derive(Default)]
struct State {
    subscription: Option<Subscription>,
    metrics: ScreencastMetrics,
}

struct Shared {
    scope: ScreencastScope,
    deadline: Instant,
    cancellation: CancellationToken,
    state: Mutex<State>,
}

impl Shared {
    fn check_live(&self) -> Result<(), ScreencastError> {
        if self.cancellation.is_cancelled() {
            return Err(ScreencastError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(ScreencastError::Expired);
        }
        Ok(())
    }
}

/// Actor-owned publisher. Dropping it cancels its receiver, without a task spawn.
#[must_use]
#[non_exhaustive]
pub struct ScreencastPublisher {
    shared: Arc<Shared>,
}

impl ScreencastPublisher {
    /// Create a scope-bound channel with a monotonic, at-most-five-minute TTL.
    ///
    /// The registry must first authenticate the scope against its live actor and
    /// lease. This channel independently checks exact scope equality at subscribe.
    /// The cancellation token is inherited through a child, never cancelled upward.
    ///
    /// # Errors
    /// Returns [`ScreencastError::InvalidLifetime`] for a zero TTL.
    pub fn new(
        scope: ScreencastScope,
        ttl: Duration,
        cancellation: CancellationToken,
    ) -> Result<Self, ScreencastError> {
        if ttl.is_zero() {
            return Err(ScreencastError::InvalidLifetime);
        }
        Ok(Self {
            shared: Arc::new(Shared {
                scope,
                deadline: Instant::now() + ttl.min(SCREENCAST_MAX_TTL),
                cancellation: cancellation.child_token(),
                state: Mutex::new(State::default()),
            }),
        })
    }

    /// Subscribe once with an exact scope and both explicit consents.
    ///
    /// Reconnection starts an empty channel; no previous event is replayed.
    ///
    /// # Errors
    /// Returns scope/consent errors, expired/cancelled status, or
    /// [`ScreencastError::AlreadySubscribed`] for a second live consumer.
    pub fn subscribe(
        &self,
        scope: &ScreencastScope,
        capture_consent: bool,
        privacy_consent: bool,
    ) -> Result<ScreencastReceiver, ScreencastError> {
        if scope != &self.shared.scope {
            return Err(ScreencastError::ScopeMismatch);
        }
        if !capture_consent || !privacy_consent {
            return Err(ScreencastError::ConsentRequired);
        }
        self.shared.check_live()?;
        let mut state = self.shared.state.lock();
        if state.subscription.as_ref().is_some_and(|subscription| {
            !subscription.sender.is_closed() && !subscription.cancellation.is_cancelled()
        }) {
            return Err(ScreencastError::AlreadySubscribed);
        }
        let (sender, receiver) = mpsc::channel(SCREENCAST_CAPACITY);
        let cancellation = self.shared.cancellation.child_token();
        state.subscription = Some(Subscription {
            sender,
            cancellation: cancellation.clone(),
        });
        Ok(ScreencastReceiver {
            shared: Arc::clone(&self.shared),
            receiver,
            cancellation,
            finished: false,
        })
    }

    /// Suppress an actor observation before capture and try to deliver its status.
    ///
    /// This accepts no bytes, browser context, capture callback, or safety override.
    /// On overflow the whole subscriber closes and queued statuses are discarded.
    ///
    /// # Errors
    /// Returns expired/cancelled status, [`ScreencastError::Disconnected`], or
    /// [`ScreencastError::SlowConsumer`]. None of these trigger capture or retention.
    pub fn observe(&self, observation: ScreencastObservation) -> Result<(), ScreencastError> {
        self.shared.check_live()?;
        let reason = match observation {
            ScreencastObservation::Unproven => SuppressionReason::PrivacyUnproven,
            ScreencastObservation::SecretPresent => SuppressionReason::SecretPresent,
        };
        let mut state = self.shared.state.lock();
        state.metrics.suppressed_observations = state.metrics.suppressed_observations.saturating_add(1);
        let Some(subscription) = state.subscription.as_ref() else {
            state.metrics.dropped_events = state.metrics.dropped_events.saturating_add(1);
            return Err(ScreencastError::Disconnected);
        };
        match subscription
            .sender
            .try_send(ScreencastEvent::Suppressed { reason })
        {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                subscription.cancellation.cancel();
                state.metrics.dropped_events = state.metrics.dropped_events.saturating_add(1);
                state.metrics.slow_consumer_closures = state.metrics.slow_consumer_closures.saturating_add(1);
                state.subscription = None;
                Err(ScreencastError::SlowConsumer)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                state.metrics.dropped_events = state.metrics.dropped_events.saturating_add(1);
                state.subscription = None;
                Err(ScreencastError::Disconnected)
            }
        }
    }

    /// Cancel delivery and release the publisher's bounded sender immediately.
    pub fn cancel(&self) {
        self.shared.cancellation.cancel();
        self.shared.state.lock().subscription = None;
    }

    /// Read privacy-safe, in-memory aggregate metrics.
    #[must_use]
    pub fn metrics(&self) -> ScreencastMetrics {
        self.shared.state.lock().metrics
    }
}

impl Drop for ScreencastPublisher {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// A single authenticated receiver; dropping it never leaves a detached task.
#[must_use]
#[non_exhaustive]
pub struct ScreencastReceiver {
    shared: Arc<Shared>,
    receiver: mpsc::Receiver<ScreencastEvent>,
    cancellation: CancellationToken,
    finished: bool,
}

impl ScreencastReceiver {
    /// Receive a suppression status until disconnect, cancellation, or expiry.
    ///
    /// Queued statuses never escape after this method observes expiry or cancel.
    /// Pending receives wake at the monotonic deadline even without actor traffic.
    pub async fn recv(&mut self) -> Option<ScreencastEvent> {
        if self.finished {
            return None;
        }
        let event = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => None,
            () = tokio::time::sleep_until(self.shared.deadline) => None,
            event = self.receiver.recv() => event,
        };
        if self.cancellation.is_cancelled() || self.shared.check_live().is_err() || event.is_none() {
            self.finished = true;
            let dropped = self.discard_pending().saturating_add(u64::from(event.is_some()));
            let mut state = self.shared.state.lock();
            state.metrics.dropped_events = state.metrics.dropped_events.saturating_add(dropped);
            return None;
        }
        let mut state = self.shared.state.lock();
        state.metrics.delivered_events = state.metrics.delivered_events.saturating_add(1);
        event
    }

    fn discard_pending(&mut self) -> u64 {
        self.receiver.close();
        let mut dropped = 0_u64;
        while self.receiver.try_recv().is_ok() {
            dropped = dropped.saturating_add(1);
        }
        dropped
    }
}

impl Drop for ScreencastReceiver {
    fn drop(&mut self) {
        let disconnected =
            !self.finished && !self.cancellation.is_cancelled() && self.shared.check_live().is_ok();
        let dropped = self.discard_pending();
        self.cancellation.cancel();
        let mut state = self.shared.state.lock();
        state.metrics.dropped_events = state.metrics.dropped_events.saturating_add(dropped);
        if disconnected {
            state.metrics.receiver_disconnects = state.metrics.receiver_disconnects.saturating_add(1);
        }
        if state
            .subscription
            .as_ref()
            .is_some_and(|subscription| subscription.sender.is_closed())
        {
            state.subscription = None;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn scope() -> ScreencastScope {
        ScreencastScope::new(
            "00000000-0000-0000-0000-000000000001".parse().unwrap(),
            "00000000-0000-0000-0000-000000000002".parse().unwrap(),
            "00000000-0000-0000-0000-000000000003".parse().unwrap(),
            4,
            5,
            "api_key:fixture".to_owned(),
        )
    }

    fn publisher() -> ScreencastPublisher {
        ScreencastPublisher::new(scope(), Duration::from_secs(30), CancellationToken::new()).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn every_scope_dimension_and_both_consents_are_required() {
        let publisher = publisher();
        for dimension in 0..6 {
            let mut wrong = scope();
            match dimension {
                0 => wrong.tenant = "00000000-0000-0000-0000-000000000009".parse().unwrap(),
                1 => wrong.run = "00000000-0000-0000-0000-000000000009".parse().unwrap(),
                2 => wrong.session = "00000000-0000-0000-0000-000000000009".parse().unwrap(),
                3 => wrong.generation += 1,
                4 => wrong.lease_fence += 1,
                5 => wrong.owner = "api_key:other".to_owned(),
                _ => unreachable!(),
            }
            assert!(matches!(
                publisher.subscribe(&wrong, true, true),
                Err(ScreencastError::ScopeMismatch)
            ));
        }
        for (capture, privacy) in [(false, false), (true, false), (false, true)] {
            assert!(matches!(
                publisher.subscribe(&scope(), capture, privacy),
                Err(ScreencastError::ConsentRequired)
            ));
        }
        let _receiver = publisher.subscribe(&scope(), true, true).unwrap();
        assert!(matches!(
            publisher.subscribe(&scope(), true, true),
            Err(ScreencastError::AlreadySubscribed)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn unproven_and_secret_observations_deliver_only_suppression() {
        let publisher = publisher();
        let mut receiver = publisher.subscribe(&scope(), true, true).unwrap();
        for (observation, reason) in [
            (
                ScreencastObservation::Unproven,
                SuppressionReason::PrivacyUnproven,
            ),
            (
                ScreencastObservation::SecretPresent,
                SuppressionReason::SecretPresent,
            ),
        ] {
            publisher.observe(observation).unwrap();
            let event = receiver.recv().await.unwrap();
            assert_eq!(event.reason(), reason);
            let encoded = serde_json::to_value(event).unwrap();
            assert_eq!(encoded["type"], "suppressed");
            assert_eq!(encoded.as_object().unwrap().len(), 2);
        }
        assert_eq!(publisher.metrics().suppressed_observations, 2);
        assert_eq!(publisher.metrics().delivered_events, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_discards_queued_events_and_rejects_new_subscribers() {
        let publisher = publisher();
        let mut receiver = publisher.subscribe(&scope(), true, true).unwrap();
        publisher.observe(ScreencastObservation::Unproven).unwrap();
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_eq!(receiver.recv().await, None);
        assert_eq!(
            publisher.observe(ScreencastObservation::Unproven),
            Err(ScreencastError::Expired)
        );
        assert!(matches!(
            publisher.subscribe(&scope(), true, true),
            Err(ScreencastError::Expired)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn pending_receive_wakes_at_deadline_and_ttl_is_capped() {
        let publisher =
            ScreencastPublisher::new(scope(), Duration::from_secs(3600), CancellationToken::new()).unwrap();
        assert_eq!(publisher.shared.deadline - Instant::now(), SCREENCAST_MAX_TTL);
        let mut receiver = publisher.subscribe(&scope(), true, true).unwrap();
        assert_eq!(receiver.recv().await, None);
        assert!(matches!(
            publisher.subscribe(&scope(), true, true),
            Err(ScreencastError::Expired)
        ));
        assert!(matches!(
            ScreencastPublisher::new(scope(), Duration::ZERO, CancellationToken::new()),
            Err(ScreencastError::InvalidLifetime)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn overflow_closes_slow_receiver_and_reconnect_has_no_replay() {
        let publisher = publisher();
        let mut receiver = publisher.subscribe(&scope(), true, true).unwrap();
        for _ in 0..SCREENCAST_CAPACITY {
            publisher.observe(ScreencastObservation::Unproven).unwrap();
        }
        assert_eq!(
            publisher.observe(ScreencastObservation::Unproven),
            Err(ScreencastError::SlowConsumer)
        );
        assert_eq!(receiver.recv().await, None);
        assert_eq!(publisher.metrics().slow_consumer_closures, 1);
        assert_eq!(publisher.metrics().dropped_events, 5);
        let mut replacement = publisher.subscribe(&scope(), true, true).unwrap();
        drop(receiver);
        publisher.observe(ScreencastObservation::SecretPresent).unwrap();
        assert_eq!(
            replacement.recv().await.unwrap().reason(),
            SuppressionReason::SecretPresent
        );
    }

    #[tokio::test(start_paused = true)]
    async fn receiver_disconnect_releases_slot_and_counts_drop() {
        let publisher = publisher();
        let receiver = publisher.subscribe(&scope(), true, true).unwrap();
        drop(receiver);
        assert_eq!(publisher.metrics().receiver_disconnects, 1);
        assert_eq!(
            publisher.observe(ScreencastObservation::Unproven),
            Err(ScreencastError::Disconnected)
        );
        assert_eq!(publisher.metrics().dropped_events, 1);
        let _replacement = publisher.subscribe(&scope(), true, true).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn actor_cancel_and_publisher_drop_discard_queued_events() {
        let cancellation = CancellationToken::new();
        let publisher =
            ScreencastPublisher::new(scope(), Duration::from_secs(30), cancellation.clone()).unwrap();
        let mut receiver = publisher.subscribe(&scope(), true, true).unwrap();
        publisher.observe(ScreencastObservation::SecretPresent).unwrap();
        cancellation.cancel();
        assert_eq!(receiver.recv().await, None);
        assert_eq!(
            publisher.observe(ScreencastObservation::Unproven),
            Err(ScreencastError::Cancelled)
        );

        let parent = CancellationToken::new();
        let publisher = ScreencastPublisher::new(scope(), Duration::from_secs(30), parent.clone()).unwrap();
        let mut receiver = publisher.subscribe(&scope(), true, true).unwrap();
        drop(publisher);
        assert_eq!(receiver.recv().await, None);
        assert!(!parent.is_cancelled());
    }
}
