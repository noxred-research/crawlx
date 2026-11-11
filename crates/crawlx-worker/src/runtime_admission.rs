//! Runtime pressure sampling around the pure recorded admission recurrence.
//!
//! No sampler task is spawned. The dispatch loop polls this bounded state before
//! taking leases; unknown operating-system or storage metrics remain unknown.

use crate::pool::BrowserPool;
use crate::runtime::CpuPool;
use crawlx_core::repo::ArtifactStore;
use crawlx_core::runtime_admission::AdmissionRecordV1;
use crawlx_core::runtime_admission::{
    AdmissionControllerV1, AdmissionDecisionV1, PressureSnapshotV1, RuntimeAdmissionV1,
};
use crawlx_core::StoreError;
use crawlx_core::{CrawlRunId, Timestamp, WorkerId};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::Instant;

/// One worker-local controller, sampled at most once per one-second logical tick.
#[derive(Debug)]
#[non_exhaustive]
pub struct RuntimeAdmission {
    controller: AdmissionControllerV1,
    next_sample: Instant,
}
impl RuntimeAdmission {
    /// Construct a bounded controller before any leases or task creation.
    /// # Errors
    /// Returns a conflict for invalid policy or zero hard capacity.
    pub fn new(policy: RuntimeAdmissionV1, hard_limit: u32) -> Result<Self, StoreError> {
        Ok(Self {
            controller: AdmissionControllerV1::new(policy, hard_limit)?,
            next_sample: Instant::now(),
        })
    }
    /// Remaining admission capacity; never exceeds the immutable hard limit.
    #[must_use]
    pub fn available(&self, in_flight: u32) -> u32 {
        self.controller.available(in_flight)
    }
    /// Capture real bounded pressure only when the next logical sample is due.
    ///
    /// `store_latency` must come from a completed correctness-store operation.
    /// A missing browser pool means browser metrics stay unknown, not idle.
    /// # Errors
    /// Returns a conflict if the pure controller rejects the observations.
    pub async fn tick(
        &mut self,
        cpu: &CpuPool,
        artifacts: &dyn ArtifactStore,
        browser: Option<&BrowserPool>,
        store_latency: Option<Duration>,
        store_available: Option<bool>,
    ) -> Result<Option<AdmissionDecisionV1>, StoreError> {
        if Instant::now() < self.next_sample {
            return Ok(None);
        }
        let pressure = snapshot(cpu, artifacts, browser, store_latency, store_available).await;
        let decision = self.controller.sample(pressure)?;
        // Do not synthesize healthy observations for ticks missed during long work.
        self.next_sample = Instant::now() + Duration::from_secs(1);
        Ok(Some(decision))
    }
    /// Apply recorded pressure decisions without invoking any runtime sensor.
    /// # Errors
    /// Returns a conflict for incompatible version, sequence, or ceiling.
    pub fn replay(&mut self, decision: &AdmissionDecisionV1) -> Result<(), StoreError> {
        self.controller.replay(decision)
    }
}

/// Recorded worker streams, validated without reading runtime or wall-clock sensors.
pub(crate) struct RecordedAdmissionReplay {
    policy: RuntimeAdmissionV1,
    hard_limit: u32,
    streams: BTreeMap<WorkerId, AdmissionControllerV1>,
}
impl RecordedAdmissionReplay {
    pub(crate) fn new(policy: RuntimeAdmissionV1, hard_limit: u32) -> Self {
        Self {
            policy,
            hard_limit,
            streams: BTreeMap::new(),
        }
    }
    pub(crate) fn apply(&mut self, record: &AdmissionRecordV1) -> Result<(), StoreError> {
        if !self.streams.contains_key(&record.worker) {
            if self.streams.len() >= 1024 {
                return Err(StoreError::Conflict(
                    "recorded admission worker bound exceeded".into(),
                ));
            }
            self.streams.insert(
                record.worker,
                AdmissionControllerV1::new(self.policy.clone(), self.hard_limit)?,
            );
        }
        self.streams
            .get_mut(&record.worker)
            .ok_or_else(|| StoreError::Conflict("recorded admission stream missing".into()))?
            .replay(&record.decision)
    }
}

/// Read a bounded source trail in event order, not observation timestamp order.
pub(crate) async fn load_recorded(
    events: &dyn crawlx_core::repo::EventRepo,
    source_run: CrawlRunId,
    through: Timestamp,
) -> Result<Vec<AdmissionRecordV1>, StoreError> {
    let mut cursor = 0;
    let mut records = Vec::new();
    loop {
        let page = events.list_after(source_run, cursor, 256).await?;
        if page.is_empty() {
            break;
        }
        for event in page {
            if event.seq <= cursor {
                return Err(StoreError::Conflict(
                    "admission event sequence is not increasing".into(),
                ));
            }
            cursor = event.seq;
            if event.kind != "runtime.admission" || event.at > through {
                continue;
            }
            let record: AdmissionRecordV1 = serde_json::from_value(event.payload)
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            if record.source_run != source_run {
                return Err(StoreError::Conflict(
                    "admission record source run mismatch".into(),
                ));
            }
            if records.len() >= 100_000 {
                return Err(StoreError::Conflict(
                    "recorded admission sample bound exceeded".into(),
                ));
            }
            records.push(record);
        }
    }
    Ok(records)
}
async fn snapshot(
    cpu: &CpuPool,
    artifacts: &dyn ArtifactStore,
    browser: Option<&BrowserPool>,
    store_latency: Option<Duration>,
    store_available: Option<bool>,
) -> PressureSnapshotV1 {
    let mut pressure = PressureSnapshotV1::default();
    pressure.event_loop_lag_ms = Some(event_loop_lag_ms().await);
    pressure.cpu_active = count(cpu.active());
    pressure.cpu_waiting = count(cpu.queue_depth());
    pressure.queue_permille = Some(ratio(
        u128::from(pressure.cpu_waiting),
        u128::try_from(cpu.capacity()).unwrap_or(u128::MAX),
    ));
    pressure.spool_permille = artifacts.spool_pressure_permille();
    pressure.browser_available = browser.map(|pool| count(pool.admission_available_contexts()));
    pressure.browser_quarantined = browser.map(|pool| count(pool.quarantined_contexts()));
    pressure.store_latency_ms =
        store_latency.map(|duration| u32::try_from(duration.as_millis().min(60_000)).unwrap_or(60_000));
    pressure.store_available = store_available;
    #[cfg(target_os = "linux")]
    {
        pressure.cpu_permille = tokio::fs::read_to_string("/proc/pressure/cpu")
            .await
            .ok()
            .as_deref()
            .and_then(cpu_pressure);
        // A finite container limit is an actual deployment budget. Host RAM size
        // is not a substitute when no container/deployment budget was measured.
        let (usage, limit, status) = tokio::join!(
            tokio::fs::read_to_string("/sys/fs/cgroup/memory.current"),
            tokio::fs::read_to_string("/sys/fs/cgroup/memory.max"),
            tokio::fs::read_to_string("/proc/self/status"),
        );
        pressure.rss_bytes = status.ok().as_deref().and_then(rss_from_status);
        pressure.memory_limit_bytes = limit
            .ok()
            .and_then(|limit| limit.trim().parse::<u64>().ok())
            .filter(|limit| *limit > 0);
        pressure.memory_permille = usage.ok().and_then(|usage| {
            let used = usage.trim().parse::<u64>().ok()?;
            let limit = pressure.memory_limit_bytes?;
            Some(ratio(u128::from(used), u128::from(limit)))
        });
    }
    pressure
}

/// Constant-size process observations around one admitted task, not allocation attribution.
pub(crate) struct TaskResourceSample {
    started: Instant,
    rss_before: Option<u64>,
}

impl TaskResourceSample {
    pub(crate) async fn start() -> Self {
        Self {
            started: Instant::now(),
            rss_before: process_rss_bytes().await,
        }
    }

    pub(crate) async fn finish(self, frontier: i64, succeeded: bool) -> serde_json::Value {
        let rss_after = process_rss_bytes().await;
        serde_json::json!({
            "version": 1,
            "frontier_id": frontier,
            "succeeded": succeeded,
            "elapsed_ms": u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "process_rss_before_bytes": self.rss_before,
            "process_rss_after_bytes": rss_after,
        })
    }
}

async fn process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        tokio::fs::read_to_string("/proc/self/status")
            .await
            .ok()
            .as_deref()
            .and_then(rss_from_status)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn rss_from_status(status: &str) -> Option<u64> {
    let line = status.lines().find_map(|line| line.strip_prefix("VmRSS:"))?;
    let mut parts = line.split_whitespace();
    let kib = parts.next()?.parse::<u64>().ok()?;
    if parts.next()? != "kB" || parts.next().is_some() {
        return None;
    }
    kib.checked_mul(1024)
}

async fn event_loop_lag_ms() -> u32 {
    // Probe an actual timer wakeup, not time between dispatch calls: long I/O and
    // origin cooldowns do not themselves imply a stalled async runtime.
    let deadline = Instant::now() + Duration::from_millis(1);
    tokio::time::sleep_until(deadline).await;
    u32::try_from(
        Instant::now()
            .saturating_duration_since(deadline)
            .as_millis()
            .min(60_000),
    )
    .unwrap_or(60_000)
}
fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
fn ratio(used: u128, capacity: u128) -> u16 {
    u16::try_from(
        used.saturating_mul(1000)
            .checked_div(capacity)
            .unwrap_or(1000)
            .min(1000),
    )
    .unwrap_or(1000)
}
#[cfg(target_os = "linux")]
fn cpu_pressure(text: &str) -> Option<u16> {
    let line = text.lines().find(|line| line.starts_with("some "))?;
    let value = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix("avg10="))?;
    // PSI is a percentage with two decimals. Parse fixed-point, never NaN/inf.
    let (whole, fraction) = value.split_once('.')?;
    let whole = whole.parse::<u16>().ok()?;
    let first = fraction.as_bytes().first()?.checked_sub(b'0')?;
    if first > 9 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(
        whole
            .saturating_mul(10)
            .saturating_add(u16::from(first))
            .min(1000),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn psi_uses_actual_sample_and_rejects_missing_or_malformed_values() {
        assert_eq!(cpu_pressure("some avg10=81.23 avg60=1.00 total=4\n"), Some(812));
        assert_eq!(cpu_pressure("full avg10=0.00\n"), None);
        assert_eq!(cpu_pressure("some avg10=nan\n"), None);
    }
    #[test]
    fn occupancy_is_bounded_and_zero_capacity_is_not_idle() {
        assert_eq!(ratio(2, 1), 1000);
        assert_eq!(ratio(0, 0), 1000);
        assert_eq!(ratio(1, 4), 250);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_rss_requires_observed_units_and_checked_bytes() {
        assert_eq!(rss_from_status("Name: crawlx\nVmRSS:\t123 kB\n"), Some(125_952));
        assert_eq!(rss_from_status("VmRSS: 123 B\n"), None);
        assert_eq!(rss_from_status("VmRSS: 123 kB extra\n"), None);
        assert_eq!(rss_from_status("VmRSS: 18446744073709551615 kB\n"), None);
        assert_eq!(rss_from_status("Name: crawlx\n"), None);
    }

    #[tokio::test(start_paused = true)]
    async fn task_resources_record_elapsed_and_explicit_rss_observations() {
        let sample = TaskResourceSample::start().await;
        tokio::time::advance(Duration::from_millis(123)).await;
        let record = sample.finish(7, false).await;
        assert_eq!(record["frontier_id"], 7);
        assert_eq!(record["succeeded"], false);
        assert_eq!(record["elapsed_ms"], 123);
        assert!(
            record["process_rss_before_bytes"].is_null()
                || record["process_rss_before_bytes"].as_u64().is_some()
        );
        assert!(
            record["process_rss_after_bytes"].is_null()
                || record["process_rss_after_bytes"].as_u64().is_some()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timer_probe_records_wakeup_lag_and_caps_long_stalls() {
        for (advance, expected) in [(1, 0), (101, 100), (70_000, 60_000)] {
            let mut probe = Box::pin(event_loop_lag_ms());
            tokio::select! {
                biased;
                _ = &mut probe => panic!("timer must be pending before its deadline"),
                () = std::future::ready(()) => {}
            }
            tokio::time::advance(Duration::from_millis(advance)).await;
            assert_eq!(probe.await, expected);
        }
    }

    #[test]
    fn recorded_workers_keep_independent_sequences_without_sampling() {
        let run = CrawlRunId::new();
        let worker_a = WorkerId::new();
        let worker_b = WorkerId::new();
        let policy = RuntimeAdmissionV1::default();
        let mut live_a = AdmissionControllerV1::new(policy.clone(), 4).unwrap();
        let mut live_b = AdmissionControllerV1::new(policy.clone(), 4).unwrap();
        let first = AdmissionRecordV1::new(
            run,
            worker_a,
            live_a.sample(PressureSnapshotV1::default()).unwrap(),
        );
        let other = AdmissionRecordV1::new(
            run,
            worker_b,
            live_b.sample(PressureSnapshotV1::default()).unwrap(),
        );
        let second = AdmissionRecordV1::new(
            run,
            worker_a,
            live_a.sample(PressureSnapshotV1::default()).unwrap(),
        );
        let mut replay = RecordedAdmissionReplay::new(policy, 4);
        replay.apply(&first).unwrap();
        replay.apply(&other).unwrap();
        replay.apply(&second).unwrap();
        assert!(replay.apply(&first).is_err());
        let mut altered = second;
        altered.decision.ceiling = 5;
        assert!(RecordedAdmissionReplay::new(RuntimeAdmissionV1::default(), 4)
            .apply(&altered)
            .is_err());
    }
}
