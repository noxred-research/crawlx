//! Projection of completed, masked traffic; never drains the raw capture queue.

use super::CdpContext;
use crawlx_core::browser::BrowserError;
use crawlx_core::browser_capture::BrowserEvidenceConfig;
use crawlx_core::browser_projection::{
    BrowserDiagnostics, BrowserProjection, BrowserResponse, ConsoleAvailability, ConsoleProjection,
    NetworkProjection,
};
use crawlx_core::traffic::TrafficEvent;
use serde::Serialize;
use std::collections::VecDeque;
use std::io::{self, Write};

const MAX_RECORDS: u32 = 5000;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PATTERNS: usize = 128;
const MAX_PATTERN_BYTES: usize = 8192;

fn is_xhr_resource(event: &TrafficEvent) -> bool {
    event
        .request_headers
        .iter()
        .any(|(name, value)| name == "x-crawlx-resource-type" && matches!(value.as_str(), "xhr" | "fetch"))
}

const MAX_CONSOLE_MESSAGE_BYTES: usize = 4096;

#[derive(Default)]
struct ByteCount(u64);

impl Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_bytes(value: &impl Serialize) -> u64 {
    let mut counter = ByteCount::default();
    if serde_json::to_writer(&mut counter, value).is_err() {
        return u64::MAX;
    }
    counter.0
}

struct Ring {
    records: VecDeque<(BrowserResponse, u64)>,
    max_records: usize,
    max_bytes: u64,
    bytes: u64,
    dropped: u64,
}

impl Ring {
    fn new(max_records: u32, max_bytes: u64) -> Self {
        Self {
            records: VecDeque::new(),
            max_records: usize::try_from(max_records.min(MAX_RECORDS)).unwrap_or(0),
            max_bytes: max_bytes.min(MAX_BYTES),
            bytes: 0,
            dropped: 0,
        }
    }

    fn can_fit(&self, event: &TrafficEvent) -> bool {
        let max_bytes = usize::try_from(self.max_bytes).unwrap_or(usize::MAX);
        let base = event.url.len().saturating_add(event.method.len());
        if self.max_records == 0 || base > max_bytes {
            return false;
        }
        event
            .request_headers
            .iter()
            .chain(&event.response_headers)
            .try_fold(base, |sum, (name, value)| {
                sum.checked_add(name.len())?
                    .checked_add(value.len())
                    .filter(|bytes| *bytes <= max_bytes)
            })
            .is_some()
    }

    fn append(&mut self, event: &TrafficEvent) {
        // Reject obviously oversized metadata before copying capture-owned strings.
        if !self.can_fit(event) {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let record = BrowserResponse::from(event.clone());
        let bytes = serialized_bytes(&record);
        if bytes > self.max_bytes {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        while self.records.len() >= self.max_records || self.bytes.saturating_add(bytes) > self.max_bytes {
            let Some((_, removed)) = self.records.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(removed);
            self.dropped = self.dropped.saturating_add(1);
        }
        self.records.push_back((record, bytes));
        self.bytes = self.bytes.saturating_add(bytes);
    }

    fn snapshot(&self) -> NetworkProjection {
        let mut result = NetworkProjection::default();
        result.records = self.records.iter().map(|(record, _)| record.clone()).collect();
        result.metadata_bytes = self.bytes;
        result.dropped_records = self.dropped;
        result.truncated = self.dropped != 0;
        result
    }
}

/// Context-local, independently bounded copies of already masked traffic.
pub(super) struct ProjectionBuffer {
    xhr: Option<Ring>,
    diagnostics: Option<Ring>,
    patterns: Vec<String>,
    last_seq: u64,
}

impl ProjectionBuffer {
    pub(super) fn new(config: &BrowserEvidenceConfig) -> Self {
        Self {
            xhr: config
                .xhr
                .as_ref()
                .map(|spec| Ring::new(spec.max_records, spec.max_bytes)),
            diagnostics: config
                .diagnostics
                .as_ref()
                .map(|spec| Ring::new(spec.max_records, spec.max_bytes)),
            // Context creation validates these bounds. Retain defensive bounds for internal callers.
            patterns: config
                .xhr
                .as_ref()
                .map(|spec| {
                    spec.url_patterns
                        .iter()
                        .take(MAX_PATTERNS)
                        .filter(|pattern| pattern.len() <= MAX_PATTERN_BYTES)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
            last_seq: 0,
        }
    }

    fn matches_xhr(&self, event: &TrafficEvent) -> bool {
        // Reject metadata beyond this projection's cap before scanning URL patterns.
        self.xhr.as_ref().is_some_and(|ring| ring.can_fit(event))
            && is_xhr_resource(event)
            && self
                .patterns
                .iter()
                .any(|pattern| wildcard_matches(pattern, &event.url))
    }

    fn can_fit(&self, event: &TrafficEvent) -> bool {
        self.diagnostics.as_ref().is_some_and(|ring| ring.can_fit(event))
            || (self.xhr.as_ref().is_some_and(|ring| ring.can_fit(event))
                && !self.patterns.is_empty()
                && is_xhr_resource(event))
    }

    fn discard_oversized(&mut self, event: &TrafficEvent) {
        self.last_seq = event.seq;
        if let Some(ring) = &mut self.diagnostics {
            ring.dropped = ring.dropped.saturating_add(1);
        }
        // Oversized tagged candidates count as drops without scanning their unbounded URLs.
        if !self.patterns.is_empty() && is_xhr_resource(event) {
            if let Some(ring) = &mut self.xhr {
                ring.dropped = ring.dropped.saturating_add(1);
            }
        }
    }

    /// Append only the completion-ordered, CAPTCHA-masked output of `drain_traffic`.
    pub(super) fn append(&mut self, events: &[TrafficEvent]) {
        if self.xhr.is_none() && self.diagnostics.is_none() {
            return;
        }
        for event in events {
            if event.seq <= self.last_seq {
                continue;
            }
            if !self.can_fit(event) {
                self.discard_oversized(event);
                continue;
            }
            self.last_seq = event.seq;
            if let Some(ring) = &mut self.diagnostics {
                ring.append(event);
            }
            if self.matches_xhr(event) {
                if let Some(ring) = &mut self.xhr {
                    ring.append(event);
                }
            } else if !self.patterns.is_empty() && is_xhr_resource(event) {
                if let Some(ring) = &mut self.xhr {
                    if !ring.can_fit(event) {
                        ring.dropped = ring.dropped.saturating_add(1);
                    }
                }
            }
        }
    }

    fn snapshot(&self, availability: ConsoleAvailability, messages: Vec<String>) -> BrowserProjection {
        let mut result = BrowserProjection::default();
        result.xhr = self.xhr.as_ref().map(Ring::snapshot);
        if let Some(ring) = &self.diagnostics {
            let mut diagnostics = BrowserDiagnostics::default();
            diagnostics.network = ring.snapshot();
            diagnostics.console = console_projection(
                availability,
                messages,
                ring.max_records.saturating_sub(ring.records.len()),
                ring.max_bytes.saturating_sub(ring.bytes),
            );
            result.diagnostics = Some(diagnostics);
        }
        result
    }
}

fn redact_console(
    messages: Vec<String>,
    controls: &crawlx_core::request_controls::RequestControls,
) -> Vec<String> {
    let redactor = crawlx_core::secret::Redactor::new();
    messages
        .into_iter()
        .map(
            |message| match redactor.scrub_bytes(message.as_bytes(), controls.secret_values()) {
                std::borrow::Cow::Borrowed(_) => message,
                std::borrow::Cow::Owned(bytes) => {
                    String::from_utf8(bytes).unwrap_or_else(|_| "[REDACTED]".to_owned())
                }
            },
        )
        .collect()
}

// Only '*' is special. Literal segments use substring search; no regex compilation or backtracking.
fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let mut segments = pattern.split('*');
    let first = segments.next().unwrap_or_default();
    let Some(mut rest) = value.strip_prefix(first) else {
        return false;
    };
    let mut remaining = segments.peekable();
    while let Some(segment) = remaining.next() {
        if remaining.peek().is_none() {
            return rest.ends_with(segment);
        }
        let Some(offset) = rest.find(segment) else {
            return false;
        };
        rest = &rest[offset.saturating_add(segment.len())..];
    }
    rest.is_empty()
}

fn console_projection(
    availability: ConsoleAvailability,
    messages: Vec<String>,
    max_records: usize,
    max_bytes: u64,
) -> ConsoleProjection {
    let mut result = ConsoleProjection::default();
    result.availability = availability;
    if availability != ConsoleAvailability::Available {
        return result;
    }
    for mut message in messages {
        if message.len() > MAX_CONSOLE_MESSAGE_BYTES {
            let mut boundary = MAX_CONSOLE_MESSAGE_BYTES;
            while !message.is_char_boundary(boundary) {
                boundary = boundary.saturating_sub(1);
            }
            message.truncate(boundary);
            result.truncated = true;
        }
        let bytes = serialized_bytes(&message);
        if result.messages.len() >= max_records || result.metadata_bytes.saturating_add(bytes) > max_bytes {
            result.dropped_messages = result.dropped_messages.saturating_add(1);
            result.truncated = true;
            continue;
        }
        result.metadata_bytes = result.metadata_bytes.saturating_add(bytes);
        result.messages.push(message);
    }
    result
}

impl CdpContext {
    /// Capture bounded response and console metadata without consuming raw traffic.
    ///
    /// Response references come only from the existing retention-policy body sink.
    /// Diagnostics distinguish unavailable console capture from an observed empty console.
    ///
    /// # Errors
    /// Returns privacy-projection errors if current completed traffic cannot be masked.
    pub async fn capture_projection(&mut self) -> Result<BrowserProjection, BrowserError> {
        if self.ctl.config.browser_evidence.xhr.is_none()
            && self.ctl.config.browser_evidence.diagnostics.is_none()
        {
            return Ok(BrowserProjection::default());
        }
        // Include completed traffic not yet drained by the actor, without stealing it.
        {
            let state = self.state.lock();
            let first_pending = state.pending_bodies.first().copied();
            for event in state
                .traffic
                .iter()
                .take_while(|event| first_pending.is_none_or(|seq| event.seq < seq))
            {
                if event.seq <= self.projection.last_seq {
                    continue;
                }
                // Preflight oversized/ineligible records without copying their payload metadata.
                if !self.projection.can_fit(event) {
                    self.projection.discard_oversized(event);
                    continue;
                }
                let masked = self.mask_captcha(event.clone())?;
                self.projection.append(std::slice::from_ref(&masked));
            }
        }
        let availability = if self.ctl.behavior.is_stealth() {
            ConsoleAvailability::Stealth
        } else if !self.ctl.behavior.console_capture {
            ConsoleAvailability::Disabled
        } else {
            ConsoleAvailability::Available
        };
        let messages = if self.ctl.config.browser_evidence.diagnostics.is_some()
            && availability == ConsoleAvailability::Available
        {
            redact_console(self.console_messages(), &self.ctl.config.request_controls)
        } else {
            Vec::new()
        };
        let mut result = self.projection.snapshot(availability, messages);
        if let Some(diagnostics) = result.diagnostics.as_mut() {
            if availability == ConsoleAvailability::Available {
                if let Some(tab) = self.state.lock().active_tab() {
                    diagnostics.console.dropped_messages = diagnostics
                        .console
                        .dropped_messages
                        .saturating_add(tab.console_dropped);
                    diagnostics.console.truncated |= tab.console_truncated || tab.console_dropped != 0;
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::traffic::TrafficOrigin;

    fn event(seq: u64) -> TrafficEvent {
        TrafficEvent {
            seq,
            epoch_id: None,
            unattributed_reason: None,
            origin: TrafficOrigin::Page,
            method: "GET".into(),
            url: format!("http://example.test/api/{seq}"),
            status: Some(200),
            request_headers: vec![("x-crawlx-resource-type".into(), "fetch".into())],
            response_headers: vec![("x-crawlx-body-state".into(), "policy_denied".into())],
            request_body: None,
            response_body: None,
            third_party: false,
            late: false,
            protocol: None,
            started_at: crawlx_core::Timestamp::UNIX_EPOCH,
            finished_at: None,
        }
    }

    #[test]
    fn ring_keeps_newest_in_capture_order_and_counts_drops() {
        let mut ring = Ring::new(2, MAX_BYTES);
        for seq in 1..=4 {
            ring.append(&event(seq));
        }
        let result = ring.snapshot();
        assert_eq!(
            result.records.iter().map(|record| record.seq).collect::<Vec<_>>(),
            [3, 4]
        );
        assert_eq!(result.dropped_records, 2);
        assert!(result.truncated);
        assert!(result.records.iter().all(|record| record.response_body.is_none()));
    }

    #[test]
    fn serialized_metadata_budget_is_exact_and_never_overflows() {
        let record = BrowserResponse::from(event(1));
        let size = serialized_bytes(&record);
        let mut exact = Ring::new(3, size);
        exact.append(&event(1));
        assert_eq!(exact.snapshot().records.len(), 1);
        assert_eq!(exact.snapshot().metadata_bytes, size);
        let mut short = Ring::new(3, size - 1);
        short.append(&event(1));
        assert!(short.snapshot().records.is_empty());
        assert_eq!(short.snapshot().dropped_records, 1);
        let mut zero = Ring::new(0, 0);
        zero.append(&event(1));
        assert_eq!(zero.snapshot().metadata_bytes, 0);
    }

    #[test]
    fn projection_filters_untagged_requests_and_deduplicates_snapshots() {
        let config: BrowserEvidenceConfig = serde_json::from_value(serde_json::json!({
            "xhr": {"urlPatterns": ["*/api/*"], "maxRecords": 3, "maxBytes": 65536},
            "diagnostics": {"maxRecords": 10, "maxBytes": 65536}
        }))
        .unwrap();
        let mut buffer = ProjectionBuffer::new(&config);
        let mut untagged = event(2);
        untagged.request_headers.clear();
        let mut excluded = event(3);
        excluded.url = "http://example.test/excluded".into();
        let traffic = [event(1), untagged, excluded, event(4)];
        buffer.append(&traffic);
        buffer.append(&traffic);
        let result = buffer.snapshot(ConsoleAvailability::Disabled, Vec::new());
        let xhr = result.xhr.unwrap();
        assert_eq!(
            xhr.records.iter().map(|record| record.seq).collect::<Vec<_>>(),
            [1, 4]
        );
        assert_eq!(result.diagnostics.unwrap().network.records.len(), 4);
        assert_eq!(xhr.dropped_records, 0);
    }

    #[tokio::test]
    async fn console_redacts_control_values_and_unregistered_credential_syntax() {
        let mut fetch = crawlx_core::config::Fetch::default();
        fetch
            .extra_headers
            .insert("x-projection-secret", "controlled-console-canary-834");
        let controls = crawlx_core::request_controls::RequestControls::resolve(&fetch, "example.test", None)
            .await
            .unwrap();
        let messages = redact_console(
            vec![
                "log controlled-console-canary-834".into(),
                "Bearer unknown-console-credential-942".into(),
                "public message".into(),
            ],
            &controls,
        );
        assert!(!messages.join(" ").contains("controlled-console-canary-834"));
        assert!(!messages.join(" ").contains("unknown-console-credential-942"));
        assert_eq!(messages[2], "public message");
    }

    #[test]
    fn diagnostics_share_total_record_budget_with_console() {
        let config: BrowserEvidenceConfig = serde_json::from_value(serde_json::json!({
            "diagnostics": {"maxRecords": 2, "maxBytes": 65536}
        }))
        .unwrap();
        let mut buffer = ProjectionBuffer::new(&config);
        buffer.append(&[event(1)]);
        let projection = buffer.snapshot(ConsoleAvailability::Available, vec!["one".into(), "two".into()]);
        let diagnostics = projection.diagnostics.unwrap();
        assert_eq!(diagnostics.network.records.len(), 1);
        assert_eq!(diagnostics.console.messages.len(), 1);
        assert_eq!(diagnostics.console.dropped_messages, 1);
        assert!(diagnostics.console.truncated);
    }

    #[test]
    fn oversized_urls_skip_pattern_scans_and_count_tagged_drops() {
        let config: BrowserEvidenceConfig = serde_json::from_value(serde_json::json!({
            "xhr": {"urlPatterns": ["*/api/*"], "maxRecords": 3, "maxBytes": 4096}
        }))
        .unwrap();
        let mut buffer = ProjectionBuffer::new(&config);
        let mut excluded = event(1);
        excluded.url = "http://example.test/excluded".into();
        buffer.append(&[excluded]);
        assert_eq!(buffer.xhr.as_ref().unwrap().dropped, 0);
        let mut oversized = event(2);
        oversized.url = format!("http://example.test/api/{}", "x".repeat(16384));
        assert!(!buffer.can_fit(&oversized));
        assert!(!buffer.matches_xhr(&oversized));
        buffer.append(&[oversized]);
        let xhr = buffer
            .snapshot(ConsoleAvailability::Disabled, Vec::new())
            .xhr
            .unwrap();
        assert!(xhr.records.is_empty());
        assert_eq!(xhr.dropped_records, 1);
        assert!(xhr.truncated);
    }

    #[test]
    fn patterns_support_only_star_and_preserve_anchoring() {
        assert!(wildcard_matches("http://*/api/*", "http://example.test/api/1"));
        assert!(wildcard_matches("*", "anything"));
        assert!(wildcard_matches("a**b*c", "a12b34c"));
        assert!(!wildcard_matches("/api/*", "http://example.test/api/1"));
        assert!(!wildcard_matches("a?", "ab"));
        assert!(!wildcard_matches("ab", "abc"));
    }

    #[test]
    fn console_bounds_utf8_json_escaping_and_unavailable_state() {
        let huge = "é".repeat(5000);
        let console = console_projection(ConsoleAvailability::Available, vec![huge, "last".into()], 1, 5000);
        assert_eq!(console.messages[0].len(), MAX_CONSOLE_MESSAGE_BYTES);
        assert_eq!(console.dropped_messages, 1);
        assert!(console.truncated);
        assert!(console.metadata_bytes <= 5000);
        let escaped = console_projection(ConsoleAvailability::Available, vec!["\"".repeat(100)], 10, 100);
        assert!(escaped.messages.is_empty());
        assert_eq!(escaped.dropped_messages, 1);
        let unavailable = console_projection(ConsoleAvailability::Stealth, vec!["secret".into()], 10, 100);
        assert_eq!(unavailable.availability, ConsoleAvailability::Stealth);
        assert!(unavailable.messages.is_empty());
    }
}
