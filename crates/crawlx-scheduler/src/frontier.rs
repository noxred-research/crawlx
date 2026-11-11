//! Deterministic advisory frontier fairness and actual admitted-task drain accounting.
//!
//! Share one controller between local workers. These reservations never replace deployment-wide
//! origin/IP governor permits, live authorization, resolver pinning, or robots admission. All time
//! values are injected monotonic milliseconds from one run clock; no wall clock is read here.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use crawlx_core::url::CanonicalUrl;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// Advisory dispatch failure without destination contents.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DispatchError {
    /// Configuration is not finite or version-pinned.
    #[error("invalid advisory dispatch policy")]
    Policy,
    /// Partition inputs do not match the checked destination.
    #[error("invalid advisory partition")]
    Partition,
    /// Injected time moved backwards or cannot represent a deadline.
    #[error("invalid advisory dispatch clock")]
    Clock,
    /// Bounded partition state is full; existing queues remain serviceable.
    #[error("advisory partition capacity exhausted")]
    Capacity,
    /// The proposal fails the native bounded request schema.
    #[error("invalid narrowed request")]
    Request(#[from] crawlx_core::request::RequestError),
}

/// Versioned quota policy; every cap additionally narrows the shared governor's hard ceilings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct FairnessPolicyV1 {
    /// Exactly one.
    pub version: u16,
    /// Maximum locally admitted tasks across all partitions.
    pub max_in_flight: u32,
    /// Per-host simultaneous tasks.
    pub host_in_flight: u32,
    /// Per-operator-domain simultaneous tasks.
    pub domain_in_flight: u32,
    /// Per-checked-IP simultaneous tasks, including host aliases.
    pub ip_in_flight: u32,
    /// Starts per partition within a logical quota window.
    pub starts_per_window: u32,
    /// Logical quota window duration.
    pub window_ms: u64,
    /// Maximum partition records; no silent eviction resets a quota.
    pub max_partitions: usize,
    /// Hard configured minimum spacing; feedback cannot accelerate below it.
    pub spacing_floor_ms: u64,
    /// Maximum adaptive delay, excluding robots and Retry-After floors.
    pub max_adaptive_delay_ms: u64,
    /// Divisor for duration-based latency feedback; not a concurrency grant.
    pub latency_target: u32,
}

impl Default for FairnessPolicyV1 {
    fn default() -> Self {
        Self {
            version: 1,
            max_in_flight: 32,
            host_in_flight: 4,
            domain_in_flight: 8,
            ip_in_flight: 4,
            starts_per_window: 100,
            window_ms: 1000,
            max_partitions: 4096,
            spacing_floor_ms: 0,
            max_adaptive_delay_ms: 60_000,
            latency_target: 1,
        }
    }
}

impl FairnessPolicyV1 {
    fn validate(&self) -> Result<(), DispatchError> {
        if self.version != 1
            || self.max_in_flight == 0
            || self.max_in_flight > 1_000_000
            || self.host_in_flight == 0
            || self.domain_in_flight == 0
            || self.ip_in_flight == 0
            || self.starts_per_window == 0
            || self.window_ms == 0
            || self.window_ms > 86_400_000
            || self.max_partitions == 0
            || self.max_partitions > 1_000_000
            || self.max_adaptive_delay_ms > 86_400_000
            || self.spacing_floor_ms > 86_400_000
            || self.latency_target == 0
        {
            return Err(DispatchError::Policy);
        }
        Ok(())
    }
}

/// Destination-derived host/domain/IP advisory partitions, never source Host-header metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdvisoryPartitionV1 {
    origin: Arc<str>,
    keys: Arc<[(Arc<str>, PartitionKind)]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PartitionKind {
    Host,
    Domain,
    Ip,
}

impl AdvisoryPartitionV1 {
    /// Derive partitions from a canonical target and already checked resolver addresses.
    /// `domain` is an operator-selected DNS suffix, not an inferred public-suffix assertion.
    /// Empty IP input is allowed only before resolution; reserve again after checked resolution.
    ///
    /// # Errors
    /// Rejects non-HTTP destinations, suffix mismatches, and more than 16 distinct addresses.
    pub fn checked(
        url: &CanonicalUrl,
        domain: Option<&str>,
        checked_ips: &[IpAddr],
    ) -> Result<Self, DispatchError> {
        let host = url.url.host_str().ok_or(DispatchError::Partition)?;
        if !matches!(url.url.scheme(), "http" | "https") || checked_ips.len() > 16 {
            return Err(DispatchError::Partition);
        }
        let domain = domain.unwrap_or(host);
        if domain.is_empty()
            || domain.len() > 253
            || !domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
            || !(host == domain
                || host
                    .strip_suffix(domain)
                    .is_some_and(|prefix| prefix.ends_with('.')))
        {
            return Err(DispatchError::Partition);
        }
        let mut keys = Vec::with_capacity(2 + checked_ips.len());
        keys.push((Arc::<str>::from(format!("host:{host}")), PartitionKind::Host));
        keys.push((
            Arc::<str>::from(format!("domain:{domain}")),
            PartitionKind::Domain,
        ));
        let mut ips = checked_ips.to_vec();
        ips.sort_unstable();
        ips.dedup();
        for ip in ips {
            keys.push((Arc::<str>::from(format!("ip:{ip}")), PartitionKind::Ip));
        }
        Ok(Self {
            origin: url.url.origin().ascii_serialization().into(),
            keys: keys.into(),
        })
    }
}

/// Narrowing overlay. Data cannot widen admitted caps or shorten spacing floors.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct NarrowingV1 {
    /// Optional smaller simultaneous-task ceiling.
    pub max_in_flight: Option<u32>,
    /// Optional additional spacing floor.
    pub spacing_floor_ms: u64,
}

impl NarrowingV1 {
    /// Intersect overlays in declaration order without ever increasing authority.
    #[must_use]
    pub fn intersect(self, other: Self) -> Self {
        Self {
            max_in_flight: match (self.max_in_flight, other.max_in_flight) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
            spacing_floor_ms: self.spacing_floor_ms.max(other.spacing_floor_ms),
        }
    }
}

/// Borrowed bounded dispatch candidate. Native priority keys precede stable row ID.
#[derive(Debug)]
#[non_exhaustive]
pub struct DispatchCandidateV1<'a> {
    partition: &'a AdvisoryPartitionV1,
    not_before_ms: u64,
    rank: (i64, i64),
    narrowing: NarrowingV1,
}

impl<'a> DispatchCandidateV1<'a> {
    /// Prepare a candidate after native eligibility and hard-deny evaluation.
    #[must_use]
    pub fn new(
        partition: &'a AdvisoryPartitionV1,
        not_before_ms: u64,
        rank: (i64, i64),
        narrowing: NarrowingV1,
    ) -> Self {
        Self {
            partition,
            not_before_ms,
            rank,
            narrowing,
        }
    }
}

#[derive(Debug, Default)]
struct QueueState {
    in_flight: u32,
    window: u64,
    starts: u32,
}

#[derive(Debug, Default)]
struct OriginState {
    turn: u64,
    last_start_ms: Option<u64>,
    delay_ms: u64,
    robots_floor_ms: u64,
    blocked_until_ms: u64,
    blocked_forever: bool,
}

#[derive(Debug, Default)]
struct State {
    now_ms: u64,
    sequence: u64,
    in_flight: u32,
    queues: BTreeMap<Arc<str>, QueueState>,
    origins: BTreeMap<Arc<str>, OriginState>,
    drain: Option<DrainSnapshotV1>,
}

/// Measured drain facts. Missing completion timestamps remain explicit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DrainSnapshotV1 {
    /// Injected requested drain deadline.
    pub deadline_ms: u64,
    /// Actual admitted tasks when drain began.
    pub admitted_at_start: u32,
    /// Actual tasks still held by live tickets.
    pub in_flight: u32,
    /// Largest observed completion/ongoing excess beyond the drain deadline.
    pub overrun_ms: u64,
    /// Tickets dropped without an injected completion timestamp.
    pub completion_time_unknown: u32,
    /// Latest actual completion timestamp, retained when later overlays narrow the deadline.
    pub last_completed_ms: Option<u64>,
}

/// When a refused candidate may next be reserved; see [`AdvisoryFrontierV1::wait_hint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WaitHintV1 {
    /// Nothing refuses it now; another reservation took the slot first.
    Ready,
    /// Every time gate (spacing, `Retry-After`, quota window) has cleared at this injected
    /// instant. Slot gates may still refuse it then.
    At(u64),
    /// No instant is known: a concurrency slot, the drain or a closed origin refuses it, and only
    /// another event clears that.
    Release,
}

/// Cloneable local fairness coordinator. Clones share counters across worker tasks.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AdvisoryFrontierV1 {
    policy: FairnessPolicyV1,
    state: Arc<Mutex<State>>,
}

impl AdvisoryFrontierV1 {
    /// Create a bounded controller; use existing shared governor for actual transport permits.
    ///
    /// # Errors
    /// Rejects unsupported versions and non-finite bounds.
    pub fn new(policy: FairnessPolicyV1) -> Result<Self, DispatchError> {
        policy.validate()?;
        Ok(Self {
            policy,
            state: Arc::new(Mutex::new(State::default())),
        })
    }

    /// Atomically select and reserve the least-recently-served eligible origin.
    /// Rank and row ID break ties. Quotas span cloned workers and checked-IP aliases.
    /// A reservation is not permission to dispatch; keep every existing hard gate.
    ///
    /// # Errors
    /// Rejects backward time, unbounded candidate batches, or exhausted state capacity.
    pub fn reserve(
        &self,
        now_ms: u64,
        candidates: &[DispatchCandidateV1<'_>],
    ) -> Result<Option<(usize, DispatchTicketV1)>, DispatchError> {
        if candidates.len() > 1000 {
            return Err(DispatchError::Capacity);
        }
        let mut state = self.state.lock();
        advance(&mut state, now_ms)?;
        if state.drain.is_some() || state.in_flight >= self.policy.max_in_flight {
            return Ok(None);
        }
        let window = now_ms / self.policy.window_ms;
        let mut capacity_blocked = false;
        let selected = candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| {
                let cap = candidate
                    .narrowing
                    .max_in_flight
                    .unwrap_or(self.policy.max_in_flight)
                    .min(self.policy.max_in_flight);
                if state.in_flight >= cap || now_ms < candidate.not_before_ms {
                    return false;
                }
                let missing = candidate
                    .partition
                    .keys
                    .iter()
                    .filter(|(key, _)| !state.queues.contains_key(key))
                    .count();
                if state
                    .queues
                    .len()
                    .saturating_add(state.origins.len())
                    .saturating_add(missing)
                    .saturating_add(usize::from(
                        !state.origins.contains_key(&candidate.partition.origin),
                    ))
                    > self.policy.max_partitions
                {
                    capacity_blocked = true;
                    return false;
                }
                if let Some(origin) = state.origins.get(&candidate.partition.origin) {
                    let floor = origin
                        .delay_ms
                        .max(origin.robots_floor_ms)
                        .max(self.policy.spacing_floor_ms)
                        .max(candidate.narrowing.spacing_floor_ms);
                    if origin.blocked_forever
                        || now_ms < origin.blocked_until_ms
                        || origin
                            .last_start_ms
                            .is_some_and(|start| now_ms.saturating_sub(start) < floor)
                    {
                        return false;
                    }
                }
                candidate.partition.keys.iter().all(|(key, kind)| {
                    let limit = match kind {
                        PartitionKind::Host => self.policy.host_in_flight,
                        PartitionKind::Domain => self.policy.domain_in_flight,
                        PartitionKind::Ip => self.policy.ip_in_flight,
                    }
                    .min(cap);
                    state.queues.get(key).is_none_or(|queue| {
                        queue.in_flight < limit
                            && (queue.window != window || queue.starts < self.policy.starts_per_window)
                    })
                })
            })
            .min_by_key(|(_, candidate)| {
                (
                    state
                        .origins
                        .get(&candidate.partition.origin)
                        .map_or(0, |origin| origin.turn),
                    candidate.rank,
                )
            })
            .map(|(index, _)| index);
        let Some(index) = selected else {
            return if capacity_blocked {
                Err(DispatchError::Capacity)
            } else {
                Ok(None)
            };
        };
        let candidate = &candidates[index];
        let turn = state.sequence.checked_add(1).ok_or(DispatchError::Capacity)?;
        state.sequence = turn;
        for (key, _) in candidate.partition.keys.iter() {
            let queue = state.queues.entry(key.clone()).or_default();
            if queue.window != window {
                queue.window = window;
                queue.starts = 0;
            }
            queue.starts = queue.starts.saturating_add(1);
            queue.in_flight = queue.in_flight.saturating_add(1);
        }
        let origin = state
            .origins
            .entry(candidate.partition.origin.clone())
            .or_default();
        origin.turn = turn;
        origin.last_start_ms = Some(now_ms);
        state.in_flight = state.in_flight.saturating_add(1);
        Ok(Some((
            index,
            DispatchTicketV1 {
                state: Arc::clone(&self.state),
                partition: candidate.partition.clone(),
                policy: self.policy.clone(),
                started_ms: now_ms,
                released: false,
            },
        )))
    }

    /// When a candidate `reserve` refused may next be eligible, from the controller's own state.
    /// The caller keeps the row it holds and waits; this never reserves anything and the answer
    /// is only a hint, since another worker may take the slot first.
    ///
    /// # Errors
    /// Rejects backward injected time.
    pub fn wait_hint(
        &self,
        now_ms: u64,
        candidate: &DispatchCandidateV1<'_>,
    ) -> Result<WaitHintV1, DispatchError> {
        let mut state = self.state.lock();
        advance(&mut state, now_ms)?;
        if state.drain.is_some() {
            return Ok(WaitHintV1::Release);
        }
        let cap = candidate
            .narrowing
            .max_in_flight
            .unwrap_or(self.policy.max_in_flight)
            .min(self.policy.max_in_flight);
        // Time gates: the instant every one of them has cleared.
        let mut at = candidate.not_before_ms;
        if let Some(origin) = state.origins.get(&candidate.partition.origin) {
            if origin.blocked_forever {
                return Ok(WaitHintV1::Release);
            }
            let floor = origin
                .delay_ms
                .max(origin.robots_floor_ms)
                .max(self.policy.spacing_floor_ms)
                .max(candidate.narrowing.spacing_floor_ms);
            at = at.max(origin.blocked_until_ms);
            if let Some(start) = origin.last_start_ms {
                at = at.max(start.saturating_add(floor));
            }
        }
        let window = now_ms / self.policy.window_ms;
        // Slot gates: only another ticket's release frees these.
        let mut slot_blocked = state.in_flight >= cap;
        for (key, kind) in candidate.partition.keys.iter() {
            let limit = match kind {
                PartitionKind::Host => self.policy.host_in_flight,
                PartitionKind::Domain => self.policy.domain_in_flight,
                PartitionKind::Ip => self.policy.ip_in_flight,
            }
            .min(cap);
            if let Some(queue) = state.queues.get(key) {
                slot_blocked |= queue.in_flight >= limit;
                if queue.window == window && queue.starts >= self.policy.starts_per_window {
                    at = at.max(window.saturating_add(1).saturating_mul(self.policy.window_ms));
                }
            }
        }
        Ok(if at > now_ms {
            WaitHintV1::At(at)
        } else if slot_blocked {
            WaitHintV1::Release
        } else {
            WaitHintV1::Ready
        })
    }

    /// Raise robots spacing for an existing checked origin; never lowers any existing floor.
    /// Feed this same measured floor into the shared origin governor.
    ///
    /// # Errors
    /// Rejects a full partition table.
    pub fn set_robots_floor(
        &self,
        partition: &AdvisoryPartitionV1,
        floor_ms: u64,
    ) -> Result<(), DispatchError> {
        let mut state = self.state.lock();
        if !state.origins.contains_key(&partition.origin)
            && state.queues.len().saturating_add(state.origins.len()) >= self.policy.max_partitions
        {
            return Err(DispatchError::Capacity);
        }
        let origin = state.origins.entry(partition.origin.clone()).or_default();
        origin.robots_floor_ms = origin.robots_floor_ms.max(floor_ms);
        Ok(())
    }

    /// Freeze new reservations and measure only already admitted tasks.
    /// Repeated calls may narrow, never extend, the original drain deadline.
    ///
    /// # Errors
    /// Rejects backward injected time.
    pub fn begin_drain(&self, now_ms: u64, deadline_ms: u64) -> Result<DrainSnapshotV1, DispatchError> {
        let mut state = self.state.lock();
        advance(&mut state, now_ms)?;
        let in_flight = state.in_flight;
        let drain = state.drain.get_or_insert(DrainSnapshotV1 {
            deadline_ms,
            admitted_at_start: in_flight,
            in_flight,
            ..DrainSnapshotV1::default()
        });
        drain.deadline_ms = drain.deadline_ms.min(deadline_ms);
        snapshot(&mut state, now_ms).ok_or(DispatchError::Policy)
    }

    /// Snapshot actual drain overrun, including tasks that remain live after the deadline.
    ///
    /// # Errors
    /// Rejects backward injected time.
    pub fn drain_snapshot(&self, now_ms: u64) -> Result<Option<DrainSnapshotV1>, DispatchError> {
        let mut state = self.state.lock();
        advance(&mut state, now_ms)?;
        Ok(snapshot(&mut state, now_ms))
    }
}

fn advance(state: &mut State, now_ms: u64) -> Result<(), DispatchError> {
    if now_ms < state.now_ms {
        return Err(DispatchError::Clock);
    }
    state.now_ms = now_ms;
    Ok(())
}

fn snapshot(state: &mut State, now_ms: u64) -> Option<DrainSnapshotV1> {
    let drain = state.drain.as_mut()?;
    drain.in_flight = state.in_flight;
    if let Some(completed) = drain.last_completed_ms {
        drain.overrun_ms = drain.overrun_ms.max(completed.saturating_sub(drain.deadline_ms));
    }
    if state.in_flight != 0 {
        drain.overrun_ms = drain.overrun_ms.max(now_ms.saturating_sub(drain.deadline_ms));
    }
    Some(*drain)
}

/// Owned actual-task reservation. Drop releases all partition counters on cancellation.
/// Call `complete` or `cancel` with injected time for measured drain completion evidence.
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub struct DispatchTicketV1 {
    state: Arc<Mutex<State>>,
    partition: AdvisoryPartitionV1,
    policy: FairnessPolicyV1,
    started_ms: u64,
    released: bool,
}

impl DispatchTicketV1 {
    /// Finish an actual response and update bounded duration-based latency feedback.
    /// A non-success response never lowers delay. Retry-After is never capped or jittered.
    /// Transport must also publish response feedback through its shared governor.
    ///
    /// # Errors
    /// Rejects backward time. An overflowing Retry-After fails closed for this controller's lifetime.
    pub fn complete(
        mut self,
        now_ms: u64,
        status: Option<u16>,
        retry_after_ms: Option<u64>,
    ) -> Result<(), DispatchError> {
        {
            let mut state = self.state.lock();
            advance(&mut state, now_ms)?;
            let elapsed = now_ms.checked_sub(self.started_ms).ok_or(DispatchError::Clock)?;
            let origin = state
                .origins
                .get_mut(&self.partition.origin)
                .ok_or(DispatchError::Partition)?;
            let target = elapsed / u64::from(self.policy.latency_target);
            let proposal = (origin.delay_ms / 2)
                .saturating_add(target / 2)
                .saturating_add((origin.delay_ms % 2 + target % 2) / 2)
                .min(self.policy.max_adaptive_delay_ms)
                .max(self.policy.spacing_floor_ms)
                .max(origin.robots_floor_ms);
            if status.is_some_and(|status| (200..300).contains(&status)) || proposal >= origin.delay_ms {
                origin.delay_ms = proposal;
            }
            if let Some(retry_after) = retry_after_ms {
                match now_ms.checked_add(retry_after) {
                    Some(until) => origin.blocked_until_ms = until.max(origin.blocked_until_ms),
                    None => origin.blocked_forever = true,
                }
            }
            release(&mut state, &self.partition, Some(now_ms));
            self.released = true;
        }
        Ok(())
    }

    /// Release cancelled actual work with an observed completion timestamp.
    ///
    /// # Errors
    /// Rejects backward injected time, while Drop still releases counters.
    pub fn cancel(mut self, now_ms: u64) -> Result<(), DispatchError> {
        let mut state = self.state.lock();
        advance(&mut state, now_ms)?;
        release(&mut state, &self.partition, Some(now_ms));
        self.released = true;
        Ok(())
    }
}

fn release(state: &mut State, partition: &AdvisoryPartitionV1, completed_at: Option<u64>) {
    state.in_flight = state.in_flight.saturating_sub(1);
    for (key, _) in partition.keys.iter() {
        if let Some(queue) = state.queues.get_mut(key) {
            queue.in_flight = queue.in_flight.saturating_sub(1);
        }
    }
    if let Some(drain) = &mut state.drain {
        drain.in_flight = state.in_flight;
        if let Some(now_ms) = completed_at {
            drain.last_completed_ms = Some(
                drain
                    .last_completed_ms
                    .map_or(now_ms, |previous| previous.max(now_ms)),
            );
            drain.overrun_ms = drain.overrun_ms.max(now_ms.saturating_sub(drain.deadline_ms));
        } else {
            drain.completion_time_unknown = drain.completion_time_unknown.saturating_add(1);
        }
    }
}

impl Drop for DispatchTicketV1 {
    fn drop(&mut self) {
        if !self.released {
            release(&mut self.state.lock(), &self.partition, None);
        }
    }
}

/// One declarative narrowing rule. Matching never grants network or cookie authority.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct NarrowingRuleV1 {
    /// Exact canonical host match; absent matches all admitted hosts.
    pub host: Option<String>,
    /// Canonical URL path prefix, never query or header input.
    pub path_prefix: String,
    /// Sticky refusal, even if an earlier matching rule supplied metadata.
    pub deny: bool,
    /// Intersected with every other matching rule and the admitted hard limits.
    pub narrowing: NarrowingV1,
    /// Public identifier only; first matching label wins over inherited parent label.
    pub label: Option<String>,
}

/// Ordered version-pinned rules and restricted parent metadata inheritance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct OrderedNarrowingV1 {
    /// Exactly one.
    pub version: u16,
    /// At most 128 ordered rules.
    pub rules: Vec<NarrowingRuleV1>,
    /// Inherit only `crawlx_public_label`; credentials, routes and arbitrary metadata never propagate.
    pub inherit_public_label: bool,
}

impl Default for OrderedNarrowingV1 {
    fn default() -> Self {
        Self {
            version: 1,
            rules: Vec::new(),
            inherit_public_label: false,
        }
    }
}

/// A narrowed child proposal; not transport admission.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[must_use]
pub struct NarrowedRequestV1 {
    /// Validated proposal, with only bounded public label inheritance.
    pub request: crawlx_core::request::RequestEnvelopeV1,
    /// Effective intersected advisory overlay.
    pub narrowing: NarrowingV1,
    /// Matching rule declaration indices.
    pub matched_rules: Vec<u16>,
}

impl OrderedNarrowingV1 {
    /// Evaluate all matching denies before projecting first-match metadata.
    /// Child labels take precedence, then ordered rule labels, then allowed parent labels.
    /// A parent label cannot carry a route, cookie, principal, header control or privilege.
    ///
    /// # Errors
    /// Rejects malformed policy, public labels or request metadata. Hard denial returns `None`.
    pub fn apply(
        &self,
        hard_allowed: bool,
        parent: Option<&crawlx_core::request::RequestEnvelopeV1>,
        child: &crawlx_core::request::RequestEnvelopeV1,
    ) -> Result<Option<NarrowedRequestV1>, DispatchError> {
        if !hard_allowed {
            return Ok(None);
        }
        if self.version != 1
            || self.rules.len() > 128
            || self.rules.iter().any(|rule| {
                rule.path_prefix.len() > 2048
                    || (!rule.path_prefix.is_empty() && !rule.path_prefix.starts_with('/'))
                    || rule.path_prefix.bytes().any(|byte| byte.is_ascii_control())
                    || rule.host.as_ref().is_some_and(|host| {
                        host.is_empty()
                            || host.len() > 253
                            || !host.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric()
                                    || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
                            })
                    })
                    || rule.label.as_ref().is_some_and(|label| !public_label(label))
            })
        {
            return Err(DispatchError::Policy);
        }
        child.validate()?;
        let mut narrowing = NarrowingV1::default();
        let mut matched_rules = Vec::new();
        let mut label = None;
        for (index, rule) in self.rules.iter().enumerate() {
            if rule
                .host
                .as_deref()
                .is_some_and(|host| Some(host) != child.url.url.host_str())
                || !child.url.url.path().starts_with(&rule.path_prefix)
            {
                continue;
            }
            if rule.deny {
                return Ok(None);
            }
            narrowing = narrowing.intersect(rule.narrowing);
            matched_rules.push(u16::try_from(index).map_err(|_| DispatchError::Policy)?);
            if label.is_none() {
                label = rule.label.as_deref();
            }
        }
        const KEY: &str = "crawlx_public_label";
        let inherited = if self.inherit_public_label {
            parent.and_then(|parent| parent.metadata.get(KEY))
        } else {
            None
        };
        let value = child
            .metadata
            .get(KEY)
            .cloned()
            .or_else(|| label.map(|label| serde_json::Value::String(label.into())))
            .or_else(|| inherited.cloned());
        if value
            .as_ref()
            .is_some_and(|value| value.as_str().is_none_or(|label| !public_label(label)))
        {
            return Err(DispatchError::Policy);
        }
        let mut request = child.clone();
        if let Some(value) = value {
            request.metadata.insert(KEY.into(), value);
        }
        request.validate()?;
        Ok(Some(NarrowedRequestV1 {
            request,
            narrowing,
            matched_rules,
        }))
    }
}

fn public_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 128
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crawlx_core::hash::Digest;
    use crawlx_core::request::RequestEnvelopeV1;
    use crawlx_core::url::RouteTemplate;

    fn url(value: &str) -> CanonicalUrl {
        CanonicalUrl {
            url: value.parse().unwrap(),
            origin: String::new(),
            key: Digest::of("frontier-test", value.as_bytes()),
            route_template: RouteTemplate("/".into()),
            params: Vec::new(),
        }
    }

    fn partition(value: &str, ips: &[IpAddr]) -> AdvisoryPartitionV1 {
        AdvisoryPartitionV1::checked(&url(value), None, ips).unwrap()
    }

    fn candidate(partition: &AdvisoryPartitionV1, id: i64) -> DispatchCandidateV1<'_> {
        DispatchCandidateV1::new(partition, 0, (0, id), NarrowingV1::default())
    }

    #[test]
    fn cloned_workers_share_checked_ip_alias_caps_and_cancel_releases() {
        let policy = FairnessPolicyV1 {
            ip_in_flight: 1,
            ..FairnessPolicyV1::default()
        };
        let a = AdvisoryFrontierV1::new(policy).unwrap();
        let b = a.clone();
        let ip = "203.0.113.1".parse().unwrap();
        let one = partition("https://one.test/a", &[ip]);
        let two = partition("https://two.test/b", &[ip]);
        let (_, ticket) = a.reserve(0, &[candidate(&one, 1)]).unwrap().unwrap();
        assert!(b.reserve(0, &[candidate(&two, 2)]).unwrap().is_none());
        ticket.cancel(1).unwrap();
        let (_, ticket) = b.reserve(1, &[candidate(&two, 2)]).unwrap().unwrap();
        drop(ticket);
        assert_eq!(a.state.lock().in_flight, 0);
        assert!(a.state.lock().queues.values().all(|queue| queue.in_flight == 0));
    }

    #[test]
    fn host_domain_partitions_and_quota_windows_remain_independent() {
        let controller = AdvisoryFrontierV1::new(FairnessPolicyV1 {
            domain_in_flight: 1,
            starts_per_window: 1,
            ..FairnessPolicyV1::default()
        })
        .unwrap();
        let a =
            AdvisoryPartitionV1::checked(&url("https://a.example.test/"), Some("example.test"), &[]).unwrap();
        let b =
            AdvisoryPartitionV1::checked(&url("https://b.example.test/"), Some("example.test"), &[]).unwrap();
        let c = partition("https://independent.test/", &[]);
        let (_, ticket) = controller.reserve(0, &[candidate(&a, 1)]).unwrap().unwrap();
        assert!(controller.reserve(0, &[candidate(&b, 2)]).unwrap().is_none());
        let (_, other) = controller.reserve(0, &[candidate(&c, 3)]).unwrap().unwrap();
        ticket.cancel(0).unwrap();
        other.cancel(0).unwrap();
        assert!(controller.reserve(999, &[candidate(&b, 2)]).unwrap().is_none());
        assert!(controller.reserve(1000, &[candidate(&b, 2)]).unwrap().is_some());
        assert!(
            AdvisoryPartitionV1::checked(&url("https://badexample.test/"), Some("example.test"), &[])
                .is_err()
        );
    }

    #[test]
    fn round_robin_ties_are_stable_and_busy_origin_cannot_starve_peer() {
        let controller = AdvisoryFrontierV1::new(FairnessPolicyV1::default()).unwrap();
        let a = partition("https://a.test/", &[]);
        let b = partition("https://b.test/", &[]);
        let candidates = [candidate(&a, 1), candidate(&b, 2)];
        for expected in [0, 1, 0, 1, 0, 1] {
            let (selected, ticket) = controller.reserve(0, &candidates).unwrap().unwrap();
            assert_eq!(selected, expected);
            ticket.complete(0, Some(200), None).unwrap();
        }
    }

    #[test]
    fn non_success_latency_samples_cannot_accelerate_spacing() {
        let controller = AdvisoryFrontierV1::new(FairnessPolicyV1::default()).unwrap();
        let a = partition("https://latency.test/", &[]);
        let (_, ticket) = controller.reserve(0, &[candidate(&a, 1)]).unwrap().unwrap();
        ticket.complete(1000, Some(200), None).unwrap();
        assert_eq!(controller.state.lock().origins[&a.origin].delay_ms, 500);
        let (_, ticket) = controller.reserve(1000, &[candidate(&a, 1)]).unwrap().unwrap();
        ticket.complete(1000, Some(500), None).unwrap();
        assert_eq!(controller.state.lock().origins[&a.origin].delay_ms, 500);
        assert!(controller.reserve(1499, &[candidate(&a, 1)]).unwrap().is_none());
        let (_, ticket) = controller.reserve(1500, &[candidate(&a, 1)]).unwrap().unwrap();
        ticket.complete(1500, Some(200), None).unwrap();
        assert_eq!(controller.state.lock().origins[&a.origin].delay_ms, 250);
    }

    #[test]
    fn wait_hint_names_the_instant_a_latency_paced_origin_clears() {
        let controller = AdvisoryFrontierV1::new(FairnessPolicyV1::default()).unwrap();
        let a = partition("https://paced.test/", &[]);
        let (_, ticket) = controller.reserve(0, &[candidate(&a, 1)]).unwrap().unwrap();
        ticket.complete(1000, Some(200), None).unwrap();
        let (_, ticket) = controller.reserve(1000, &[candidate(&a, 2)]).unwrap().unwrap();
        ticket.complete(1000, Some(200), None).unwrap();
        let clears = 1000 + controller.state.lock().origins[&a.origin].delay_ms;
        assert!(clears > 1100);
        assert!(controller.reserve(1100, &[candidate(&a, 3)]).unwrap().is_none());
        assert_eq!(
            controller.wait_hint(1100, &candidate(&a, 3)).unwrap(),
            WaitHintV1::At(clears)
        );
        assert_eq!(
            controller.wait_hint(clears, &candidate(&a, 3)).unwrap(),
            WaitHintV1::Ready
        );
    }

    #[test]
    fn wait_hint_reports_slot_and_retry_after_gates() {
        let controller = AdvisoryFrontierV1::new(FairnessPolicyV1 {
            host_in_flight: 1,
            ..FairnessPolicyV1::default()
        })
        .unwrap();
        let a = partition("https://slots.test/", &[]);
        let (_, held) = controller.reserve(0, &[candidate(&a, 1)]).unwrap().unwrap();
        assert_eq!(
            controller.wait_hint(0, &candidate(&a, 2)).unwrap(),
            WaitHintV1::Release
        );
        held.complete(10, Some(429), Some(5000)).unwrap();
        assert_eq!(
            controller.wait_hint(10, &candidate(&a, 2)).unwrap(),
            WaitHintV1::At(5010)
        );
    }

    #[test]
    fn duration_feedback_never_caps_retry_after_or_robots_floor() {
        let controller = AdvisoryFrontierV1::new(FairnessPolicyV1 {
            max_adaptive_delay_ms: 100,
            ..FairnessPolicyV1::default()
        })
        .unwrap();
        let a = partition("https://slow.test/", &[]);
        let b = partition("https://fast.test/", &[]);
        controller.set_robots_floor(&a, 3000).unwrap();
        let (_, slow) = controller.reserve(0, &[candidate(&a, 1)]).unwrap().unwrap();
        let (_, fast) = controller.reserve(0, &[candidate(&b, 2)]).unwrap().unwrap();
        fast.complete(0, Some(200), None).unwrap();
        slow.complete(1000, Some(503), Some(5000)).unwrap();
        assert!(controller.reserve(5999, &[candidate(&a, 1)]).unwrap().is_none());
        assert!(controller.reserve(5999, &[candidate(&b, 2)]).unwrap().is_some());
        let (_, slow) = controller.reserve(6000, &[candidate(&a, 1)]).unwrap().unwrap();
        slow.complete(6000, Some(200), None).unwrap();
        assert!(controller.reserve(8999, &[candidate(&a, 1)]).unwrap().is_none());
        assert!(controller.reserve(9000, &[candidate(&a, 1)]).unwrap().is_some());
    }

    #[test]
    fn drain_records_actual_live_completion_overrun_and_unknown_drop_time() {
        let controller = AdvisoryFrontierV1::new(FairnessPolicyV1::default()).unwrap();
        let a = partition("https://one.test/", &[]);
        let b = partition("https://two.test/", &[]);
        let (_, one) = controller.reserve(0, &[candidate(&a, 1)]).unwrap().unwrap();
        let (_, two) = controller.reserve(0, &[candidate(&b, 2)]).unwrap().unwrap();
        assert_eq!(controller.begin_drain(50, 100).unwrap().admitted_at_start, 2);
        assert!(controller.reserve(50, &[candidate(&a, 1)]).unwrap().is_none());
        one.complete(150, Some(200), None).unwrap();
        let live = controller.drain_snapshot(175).unwrap().unwrap();
        assert_eq!((live.in_flight, live.overrun_ms), (1, 75));
        two.cancel(200).unwrap();
        let final_state = controller.drain_snapshot(250).unwrap().unwrap();
        assert_eq!((final_state.in_flight, final_state.overrun_ms), (0, 100));
        assert_eq!(final_state.completion_time_unknown, 0);
        assert_eq!(controller.begin_drain(250, 1000).unwrap().deadline_ms, 100);
        assert_eq!(controller.begin_drain(250, 50).unwrap().overrun_ms, 150);

        let controller = AdvisoryFrontierV1::new(FairnessPolicyV1::default()).unwrap();
        let (_, ticket) = controller.reserve(0, &[candidate(&a, 1)]).unwrap().unwrap();
        controller.begin_drain(0, 100).unwrap();
        drop(ticket);
        assert_eq!(
            controller
                .drain_snapshot(200)
                .unwrap()
                .unwrap()
                .completion_time_unknown,
            1
        );
    }

    #[test]
    fn retry_after_overflow_fails_closed_without_blocking_other_origins() {
        let controller = AdvisoryFrontierV1::new(FairnessPolicyV1::default()).unwrap();
        let a = partition("https://closed.test/", &[]);
        let b = partition("https://independent.test/", &[]);
        let (_, ticket) = controller.reserve(1, &[candidate(&a, 1)]).unwrap().unwrap();
        ticket.complete(1, Some(503), Some(u64::MAX)).unwrap();
        assert!(controller
            .reserve(u64::MAX, &[candidate(&a, 1)])
            .unwrap()
            .is_none());
        assert!(controller
            .reserve(u64::MAX, &[candidate(&b, 2)])
            .unwrap()
            .is_some());
    }

    #[test]
    fn overlays_only_narrow_and_full_state_does_not_starve_existing_queue() {
        let controller = AdvisoryFrontierV1::new(FairnessPolicyV1 {
            max_partitions: 3,
            ..FairnessPolicyV1::default()
        })
        .unwrap();
        let a = partition("https://a.test/", &[]);
        let b = partition("https://b.test/", &[]);
        let (_, ticket) = controller.reserve(0, &[candidate(&a, 9)]).unwrap().unwrap();
        ticket.cancel(0).unwrap();
        let candidates = [candidate(&b, 1), candidate(&a, 9)];
        let (index, ticket) = controller.reserve(0, &candidates).unwrap().unwrap();
        assert_eq!(index, 1);
        drop(ticket);
        let overlay = NarrowingV1 {
            max_in_flight: Some(1000),
            spacing_floor_ms: 2,
        }
        .intersect(NarrowingV1 {
            max_in_flight: Some(1),
            spacing_floor_ms: 5,
        });
        assert_eq!(overlay.max_in_flight, Some(1));
        assert_eq!(overlay.spacing_floor_ms, 5);
        let closed = DispatchCandidateV1::new(
            &a,
            0,
            (0, 1),
            NarrowingV1 {
                max_in_flight: Some(0),
                ..NarrowingV1::default()
            },
        );
        assert!(controller.reserve(0, &[closed]).unwrap().is_none());
        assert!(controller.reserve(1, &[candidate(&a, 1)]).is_ok());
        assert!(matches!(
            controller.reserve(0, &[candidate(&a, 1)]),
            Err(DispatchError::Clock)
        ));
    }

    #[test]
    fn ordered_rules_keep_denial_sticky_and_never_inherit_credentials_or_routes() {
        let mut parent = RequestEnvelopeV1::get(url("https://parent.test/"), 0, None);
        parent.route = "privileged".into();
        parent.header_control = Some("private_headers".into());
        parent
            .metadata
            .insert("crawlx_public_label".into(), serde_json::json!("parent_label"));
        parent
            .metadata
            .insert("arbitrary".into(), serde_json::json!("not_inherited"));
        let child = RequestEnvelopeV1::get(url("https://child.test/private/page"), 1, Some(1));
        let mut policy = OrderedNarrowingV1 {
            inherit_public_label: true,
            rules: vec![
                NarrowingRuleV1 {
                    label: Some("first".into()),
                    narrowing: NarrowingV1 {
                        max_in_flight: Some(2),
                        spacing_floor_ms: 10,
                    },
                    ..NarrowingRuleV1::default()
                },
                NarrowingRuleV1 {
                    path_prefix: "/private".into(),
                    label: Some("second".into()),
                    narrowing: NarrowingV1 {
                        max_in_flight: Some(1),
                        spacing_floor_ms: 20,
                    },
                    ..NarrowingRuleV1::default()
                },
            ],
            ..OrderedNarrowingV1::default()
        };
        assert!(policy.apply(false, Some(&parent), &child).unwrap().is_none());
        let result = policy.apply(true, Some(&parent), &child).unwrap().unwrap();
        assert_eq!(result.request.metadata["crawlx_public_label"], "first");
        assert!(!result.request.metadata.contains_key("arbitrary"));
        assert_eq!(result.request.route, "default");
        assert_eq!(result.request.header_control, None);
        assert_eq!(result.narrowing.max_in_flight, Some(1));
        assert_eq!(result.narrowing.spacing_floor_ms, 20);
        assert_eq!(result.matched_rules, vec![0, 1]);
        let mut labelled_child = child.clone();
        labelled_child
            .metadata
            .insert("crawlx_public_label".into(), serde_json::json!("child_label"));
        let labelled = policy
            .apply(true, Some(&parent), &labelled_child)
            .unwrap()
            .unwrap();
        assert_eq!(labelled.request.metadata["crawlx_public_label"], "child_label");
        policy.rules[1].deny = true;
        assert!(policy.apply(true, Some(&parent), &child).unwrap().is_none());
        policy.rules.clear();
        let inherited = policy.apply(true, Some(&parent), &child).unwrap().unwrap();
        assert_eq!(inherited.request.metadata["crawlx_public_label"], "parent_label");
    }
}
