//! Bounded worker-local admission decisions. Replay uses recorded inputs and ceilings.

use crate::StoreError;
use serde::{Deserialize, Serialize};

/// Admission policy version one. Existing concurrency limits remain hard ceilings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RuntimeAdmissionV1 {
    /// Fixed by default; adaptive mode can only narrow the hard limit.
    pub mode: AdmissionModeV1,
    /// Logical sampling period. Version one requires one second.
    pub sample_ms: u32,
    /// Consecutive healthy samples required before one-slot growth.
    pub healthy_ticks_before_growth: u16,
    /// High-water CPU pressure, in permille.
    pub cpu_high_permille: u16,
    /// High-water memory budget occupancy, in permille.
    pub memory_high_permille: u16,
    /// High-water stage queue occupancy, in permille.
    pub queue_high_permille: u16,
}
impl Default for RuntimeAdmissionV1 {
    fn default() -> Self {
        Self {
            mode: AdmissionModeV1::Fixed,
            sample_ms: 1000,
            healthy_ticks_before_growth: 5,
            cpu_high_permille: 800,
            memory_high_permille: 800,
            queue_high_permille: 750,
        }
    }
}
impl RuntimeAdmissionV1 {
    /// Validate targets without changing any deployment limit.
    /// # Errors
    /// Returns a conflict for unsupported periods or unsafe thresholds.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.sample_ms != 1000
            || !(5..=60).contains(&self.healthy_ticks_before_growth)
            || !(1..=1000).contains(&self.cpu_high_permille)
            || !(1..=1000).contains(&self.memory_high_permille)
            || !(1..=1000).contains(&self.queue_high_permille)
        {
            return Err(StoreError::Conflict("invalid runtime admission bounds".into()));
        }
        Ok(())
    }
}
/// Worker-local dispatch algorithm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AdmissionModeV1 {
    /// Keep existing fixed concurrency, subject to emergency drain.
    #[default]
    Fixed,
    /// Immediate shrink and conservative one-slot growth.
    AdaptiveV1,
}
/// Source-specific feedback, applied inside the existing origin governor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PacingDialectV1 {
    /// Native seeded exponential backoff.
    #[default]
    Native,
    /// Mean of old spacing and latency divided by advisory concurrency.
    #[serde(rename = "latency-target-v1")]
    LatencyTargetThrottleV1,
    /// Coalesced two-second exponential 429 cooldown, capped at sixty seconds.
    #[serde(rename = "adaptive-concurrency-v1")]
    AdaptiveConcurrencyThrottleV1,
}
/// Constant-size sample. Missing values are unknown, never zero load.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct PressureSnapshotV1 {
    /// CPU scheduling pressure, bounded to 0..=1000.
    pub cpu_permille: Option<u16>,
    /// Actual process RSS or container usage divided by its memory budget.
    pub memory_permille: Option<u16>,
    /// Measured resident bytes of the worker process, absent when unavailable.
    pub rss_bytes: Option<u64>,
    /// Measured finite deployment/container budget, absent when unbounded or unknown.
    pub memory_limit_bytes: Option<u64>,
    /// Observed async timer wakeup delay, capped at 60000 ms; absent on older recordings.
    pub event_loop_lag_ms: Option<u32>,
    /// Actual blocking closures holding CPU permits.
    pub cpu_active: u32,
    /// Actual closures waiting for CPU permits.
    pub cpu_waiting: u32,
    /// Highest measured stage queue occupancy, bounded to 0..=1000.
    pub queue_permille: Option<u16>,
    /// Actual bounded upload-spool occupancy, bounded to 0..=1000.
    pub spool_permille: Option<u16>,
    /// Browser capacity still safe to admit; absent for an unmeasured browser pool.
    pub browser_available: Option<u32>,
    /// Browser resources with unconfirmed cleanup.
    pub browser_quarantined: Option<u32>,
    /// Latest correctness-store round-trip duration, capped at 60000 ms.
    pub store_latency_ms: Option<u32>,
    /// Latest correctness-store health, absent before any observation.
    pub store_available: Option<bool>,
}
impl PressureSnapshotV1 {
    fn complete(&self) -> bool {
        self.cpu_permille.is_some()
            && self.memory_permille.is_some()
            && self.queue_permille.is_some()
            && self.spool_permille.is_some()
            && self.store_latency_ms.is_some()
            && self.store_available.is_some()
            && self.browser_available.is_some()
            && self.browser_quarantined.is_some()
    }
    fn bounded(&self) -> bool {
        [
            self.cpu_permille,
            self.memory_permille,
            self.queue_permille,
            self.spool_permille,
        ]
        .into_iter()
        .flatten()
        .all(|n| n <= 1000)
            && self.store_latency_ms.is_none_or(|n| n <= 60_000)
            && self.event_loop_lag_ms.is_none_or(|n| n <= 60_000)
    }
}
/// Stable reason code for a recorded decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AdmissionReasonV1 {
    /// Existing fixed limit.
    Fixed,
    /// Missing metrics require conservative single-slot admission.
    MissingMetrics,
    /// Memory emergency or unavailable correctness storage stops new work.
    EmergencyDrain,
    /// Pressure immediately narrows admission.
    Pressure,
    /// Five or more healthy samples permit one additional slot.
    HealthyGrowth,
    /// Hold current ceiling while collecting healthy samples.
    Hold,
}
/// Recorded bounded decision; no URLs, tenant content, or credential-bearing values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AdmissionDecisionV1 {
    /// Algorithm/schema version, exactly one.
    pub version: u16,
    /// Monotonically increasing logical sample number.
    pub tick: u64,
    /// Existing deployment/run cap used for this decision.
    pub hard_limit: u32,
    /// New admission ceiling. Zero drains without cancelling in-flight work.
    pub ceiling: u32,
    /// Healthy streak after this decision.
    pub healthy_ticks: u16,
    /// Why this ceiling was selected.
    pub reason: AdmissionReasonV1,
    /// Actual bounded observations, including explicit unknowns.
    pub pressure: PressureSnapshotV1,
}

/// Privacy-safe trail record bound to its source run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AdmissionRecordV1 {
    /// Run that actually produced the observation.
    pub source_run: crate::CrawlRunId,
    /// Worker-local logical stream; independent workers never share tick counters.
    pub worker: crate::WorkerId,
    /// Versioned recorded input and decision.
    pub decision: AdmissionDecisionV1,
}
impl AdmissionRecordV1 {
    /// Bind a decision to its actual run before appending to the event trail.
    #[must_use]
    pub fn new(
        source_run: crate::CrawlRunId,
        worker: crate::WorkerId,
        decision: AdmissionDecisionV1,
    ) -> Self {
        Self {
            source_run,
            worker,
            decision,
        }
    }
}
/// Pure versioned recurrence; no wall clock or runtime sampling occurs here.
#[derive(Debug)]
#[non_exhaustive]
pub struct AdmissionControllerV1 {
    policy: RuntimeAdmissionV1,
    hard_limit: u32,
    ceiling: u32,
    healthy_ticks: u16,
    tick: u64,
}
impl AdmissionControllerV1 {
    /// Construct a controller bounded by the existing hard limit.
    /// # Errors
    /// Returns a conflict for invalid policy or zero hard capacity.
    pub fn new(policy: RuntimeAdmissionV1, hard_limit: u32) -> Result<Self, StoreError> {
        policy.validate()?;
        if hard_limit == 0 {
            return Err(StoreError::Conflict("runtime hard limit is zero".into()));
        }
        Ok(Self {
            policy,
            hard_limit,
            ceiling: hard_limit,
            healthy_ticks: 0,
            tick: 0,
        })
    }
    /// Slots available before taking leases or creating tasks.
    #[must_use]
    pub fn available(&self, in_flight: u32) -> u32 {
        self.ceiling.saturating_sub(in_flight)
    }
    /// Apply one bounded logical sample.
    /// # Errors
    /// Returns a conflict for out-of-range metric values or exhausted tick sequence.
    pub fn sample(&mut self, pressure: PressureSnapshotV1) -> Result<AdmissionDecisionV1, StoreError> {
        if !pressure.bounded() {
            return Err(StoreError::Conflict("invalid pressure snapshot".into()));
        }
        let tick = self
            .tick
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict("admission tick exhausted".into()))?;
        let emergency =
            pressure.memory_permille.is_some_and(|n| n >= 900) || pressure.store_available == Some(false);
        let high = pressure
            .cpu_permille
            .is_some_and(|n| n >= self.policy.cpu_high_permille)
            || pressure
                .memory_permille
                .is_some_and(|n| n >= self.policy.memory_high_permille)
            || pressure
                .queue_permille
                .is_some_and(|n| n >= self.policy.queue_high_permille)
            || pressure
                .spool_permille
                .is_some_and(|n| n >= self.policy.queue_high_permille)
            || pressure.cpu_waiting > 0
            || pressure.store_latency_ms.is_some_and(|n| n >= 1000)
            || pressure.event_loop_lag_ms.is_some_and(|n| n >= 100)
            || pressure.browser_quarantined.is_some_and(|n| n > 0)
            || pressure.browser_available == Some(0);
        let reason = if emergency {
            self.ceiling = 0;
            self.healthy_ticks = 0;
            AdmissionReasonV1::EmergencyDrain
        } else if self.policy.mode == AdmissionModeV1::Fixed {
            self.ceiling = self.hard_limit;
            AdmissionReasonV1::Fixed
        } else if !pressure.complete() {
            self.ceiling = self.ceiling.min(1);
            self.healthy_ticks = 0;
            AdmissionReasonV1::MissingMetrics
        } else if high {
            self.ceiling = self.ceiling.min((self.ceiling / 2).max(1));
            self.healthy_ticks = 0;
            AdmissionReasonV1::Pressure
        } else {
            self.healthy_ticks = self.healthy_ticks.saturating_add(1);
            if self.healthy_ticks >= self.policy.healthy_ticks_before_growth {
                self.ceiling = self.ceiling.saturating_add(1).min(self.hard_limit);
                self.healthy_ticks = 0;
                AdmissionReasonV1::HealthyGrowth
            } else {
                AdmissionReasonV1::Hold
            }
        };
        self.tick = tick;
        Ok(AdmissionDecisionV1 {
            version: 1,
            tick,
            hard_limit: self.hard_limit,
            ceiling: self.ceiling,
            healthy_ticks: self.healthy_ticks,
            reason,
            pressure,
        })
    }
    /// Consume a recorded decision without resampling machine pressure.
    /// # Errors
    /// Returns a conflict for version, sequence, ceiling, or input bounds mismatch.
    pub fn replay(&mut self, decision: &AdmissionDecisionV1) -> Result<(), StoreError> {
        if decision.version != 1
            || self.tick.checked_add(1) != Some(decision.tick)
            || decision.hard_limit != self.hard_limit
            || decision.ceiling > self.hard_limit
            || decision.healthy_ticks >= self.policy.healthy_ticks_before_growth
            || !decision.pressure.bounded()
        {
            return Err(StoreError::Conflict(
                "incompatible recorded admission decision".into(),
            ));
        }
        let mut expected = Self {
            policy: self.policy.clone(),
            hard_limit: self.hard_limit,
            ceiling: self.ceiling,
            healthy_ticks: self.healthy_ticks,
            tick: self.tick,
        };
        if expected.sample(decision.pressure.clone())? != *decision {
            return Err(StoreError::Conflict(
                "recorded admission recurrence mismatch".into(),
            ));
        }
        self.tick = decision.tick;
        self.ceiling = decision.ceiling;
        self.healthy_ticks = decision.healthy_ticks;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    fn healthy() -> PressureSnapshotV1 {
        PressureSnapshotV1 {
            cpu_permille: Some(100),
            memory_permille: Some(100),
            queue_permille: Some(0),
            spool_permille: Some(0),
            store_available: Some(true),
            browser_available: Some(8),
            browser_quarantined: Some(0),
            store_latency_ms: Some(1),
            ..PressureSnapshotV1::default()
        }
    }
    fn controller() -> AdmissionControllerV1 {
        AdmissionControllerV1::new(
            RuntimeAdmissionV1 {
                mode: AdmissionModeV1::AdaptiveV1,
                ..RuntimeAdmissionV1::default()
            },
            8,
        )
        .unwrap()
    }
    #[test]
    fn pressure_shrinks_immediately_and_growth_is_one_after_five_ticks() {
        let mut c = controller();
        let mut p = healthy();
        p.cpu_permille = Some(900);
        assert_eq!(c.sample(p).unwrap().ceiling, 4);
        for _ in 0..4 {
            assert_eq!(c.sample(healthy()).unwrap().ceiling, 4);
        }
        assert_eq!(c.sample(healthy()).unwrap().ceiling, 5);
        for _ in 0..100 {
            assert!(c.sample(healthy()).unwrap().ceiling <= 8);
        }
    }
    #[test]
    fn unknown_metrics_are_not_idle_and_emergency_drains() {
        let mut c = controller();
        assert_eq!(c.sample(PressureSnapshotV1::default()).unwrap().ceiling, 1);
        let mut p = healthy();
        p.memory_permille = Some(900);
        assert_eq!(c.sample(p).unwrap().ceiling, 0);
        assert_eq!(c.available(2), 0);
    }
    #[test]
    fn replay_consumes_recorded_decisions_and_rejects_wrong_sequence() {
        let mut live = controller();
        let mut replay = controller();
        for p in [healthy(), PressureSnapshotV1::default(), healthy()] {
            let recorded = live.sample(p).unwrap();
            replay.replay(&recorded).unwrap();
            assert_eq!(replay.available(0), live.available(0));
            assert!(replay.replay(&recorded).is_err());
        }
    }

    #[test]
    fn emergency_does_not_reopen_on_pressure_or_missing_metrics() {
        let mut c = controller();
        let mut unavailable = healthy();
        unavailable.store_available = Some(false);
        assert_eq!(c.sample(unavailable).unwrap().ceiling, 0);
        let mut pressured = healthy();
        pressured.cpu_waiting = 1;
        assert_eq!(c.sample(pressured).unwrap().ceiling, 0);
        assert_eq!(c.sample(PressureSnapshotV1::default()).unwrap().ceiling, 0);
        for _ in 0..4 {
            assert_eq!(c.sample(healthy()).unwrap().ceiling, 0);
        }
        assert_eq!(c.sample(healthy()).unwrap().ceiling, 1);
    }

    #[test]
    fn missing_sensor_dominates_partial_pressure_and_replay_rejects_tampering() {
        let mut c = controller();
        let mut missing = healthy();
        missing.memory_permille = None;
        missing.cpu_waiting = 1;
        let mut decision = c.sample(missing).unwrap();
        assert_eq!(decision.ceiling, 1);
        assert_eq!(decision.reason, AdmissionReasonV1::MissingMetrics);
        decision.ceiling = 2;
        assert!(controller().replay(&decision).is_err());
    }

    #[test]
    fn async_lag_shrinks_within_one_tick_and_replays_without_host_sampling() {
        let mut live = controller();
        let mut replay = controller();
        let mut pressure = healthy();
        pressure.event_loop_lag_ms = Some(100);
        let decision = live.sample(pressure).unwrap();
        assert_eq!(decision.ceiling, 4);
        assert_eq!(decision.reason, AdmissionReasonV1::Pressure);
        replay.replay(&decision).unwrap();
        assert_eq!(replay.available(0), 4);
        for _ in 0..4 {
            assert_eq!(live.sample(healthy()).unwrap().ceiling, 4);
        }
        assert_eq!(live.sample(healthy()).unwrap().ceiling, 5);
    }

    #[test]
    fn async_lag_bounds_and_legacy_unknown_are_explicit() {
        let mut live = controller();
        let mut pressure = healthy();
        pressure.event_loop_lag_ms = Some(60_001);
        assert!(live.sample(pressure).is_err());
        let legacy: PressureSnapshotV1 = serde_json::from_str("{}").unwrap();
        assert_eq!(legacy.event_loop_lag_ms, None);
        assert_eq!(
            live.sample(legacy).unwrap().reason,
            AdmissionReasonV1::MissingMetrics
        );
    }

    #[test]
    fn version_one_rejects_unsupported_sampling_and_unbounded_metric_values() {
        let policy = RuntimeAdmissionV1 {
            sample_ms: 500,
            ..RuntimeAdmissionV1::default()
        };
        assert!(AdmissionControllerV1::new(policy, 8).is_err());
        let policy = RuntimeAdmissionV1 {
            healthy_ticks_before_growth: 4,
            ..RuntimeAdmissionV1::default()
        };
        assert!(AdmissionControllerV1::new(policy, 8).is_err());
        assert!(serde_json::from_str::<RuntimeAdmissionV1>(r#"{"ignoredPressureFlag":true}"#).is_err());
        let mut controller = controller();
        let mut pressure = healthy();
        pressure.cpu_permille = Some(1001);
        assert!(controller.sample(pressure).is_err());
        assert_eq!(controller.sample(healthy()).unwrap().tick, 1);
    }
}
