//! Webhook delivery of job events (`extract.*`, `agent.*`, `monitor.*`).
//!
//! A job request carries `webhook` as a URL string or `{url, headers, metadata, events}`. Each
//! event is POSTed as `{success, type, id, data, metadata, error?}` with
//! `X-Firecrawl-Signature: sha256=<hex HMAC-SHA256(secret, body)>` (the compat header; the
//! native `Crawlx-*` headers ride along). Delivery runs in the background: three attempts
//! (immediately, after 1 s, after 5 s); a `410` or an egress denial stops at once. Failures are
//! logged, never surfaced to the job.

use crate::errors::{Detail, HttpError};
use crate::webhooks::{TransportError, WebhookRequest, WebhookTransport};
use crawlx_policy::EgressPolicy;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Pause before attempts 2 and 3.
pub const RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(5)];

/// A job's `webhook` configuration.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct JobWebhook {
    /// Destination.
    pub url: url::Url,
    /// Extra request headers.
    pub headers: BTreeMap<String, String>,
    /// Echoed back as `metadata` in every payload.
    pub metadata: Value,
    /// Event names wanted (`started`, `completed`, ...); empty means every event.
    pub events: Vec<String>,
}

impl JobWebhook {
    /// Parse the `webhook` request member (`None` when absent or null).
    ///
    /// `allowed` lists the event names of the product (`["started", "completed", "failed"]`).
    ///
    /// # Errors
    /// `422 validation` for a malformed destination, header map or unknown event.
    pub fn parse(value: Option<&Value>, path: &str, allowed: &[&str]) -> Result<Option<Self>, HttpError> {
        let Some(value) = value.filter(|v| !v.is_null()) else {
            return Ok(None);
        };
        let bad = |p: &str, m: &str| HttpError::validation(vec![Detail::new(p, "invalid", m)]);
        let (url_text, headers, metadata, events) = match value {
            Value::String(s) => (s.clone(), BTreeMap::new(), Value::Object(Map::new()), Vec::new()),
            Value::Object(o) => {
                let url = o
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad(&format!("{path}/url"), "webhook.url is required"))?
                    .to_owned();
                let mut headers = BTreeMap::new();
                if let Some(h) = o.get("headers").filter(|h| !h.is_null()) {
                    let m = h.as_object().ok_or_else(|| {
                        bad(&format!("{path}/headers"), "headers must be an object of strings")
                    })?;
                    for (k, v) in m {
                        let s = v.as_str().ok_or_else(|| {
                            bad(&format!("{path}/headers/{k}"), "header values must be strings")
                        })?;
                        headers.insert(k.clone(), s.to_owned());
                    }
                }
                let metadata = o
                    .get("metadata")
                    .filter(|m| !m.is_null())
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Map::new()));
                if !metadata.is_object() {
                    return Err(bad(&format!("{path}/metadata"), "metadata must be an object"));
                }
                let mut events = Vec::new();
                if let Some(e) = o.get("events").filter(|e| !e.is_null()) {
                    let list = e.as_array().ok_or_else(|| {
                        bad(&format!("{path}/events"), "events must be an array of strings")
                    })?;
                    for item in list {
                        let name = item.as_str().ok_or_else(|| {
                            bad(&format!("{path}/events"), "events must be an array of strings")
                        })?;
                        if !allowed.contains(&name) {
                            return Err(bad(
                                &format!("{path}/events"),
                                &format!("unknown event {name:?}; expected one of {}", allowed.join(", ")),
                            ));
                        }
                        events.push(name.to_owned());
                    }
                }
                (url, headers, metadata, events)
            }
            _ => return Err(bad(path, "webhook must be a URL string or an object")),
        };
        let url = url::Url::parse(&url_text)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .ok_or_else(|| {
                bad(
                    &format!("{path}/url"),
                    "webhook url must be an absolute http(s) URL",
                )
            })?;
        Ok(Some(Self {
            url,
            headers,
            metadata,
            events,
        }))
    }

    /// Whether `event` (short name such as `completed`) is delivered.
    #[must_use]
    pub fn wants(&self, event: &str) -> bool {
        self.events.is_empty() || self.events.iter().any(|e| e == event)
    }

    /// The request-body form stored with a job (`url`, `headers`, `metadata`, `events`).
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({
            "url": self.url.as_str(),
            "headers": self.headers,
            "metadata": self.metadata,
            "events": self.events,
        })
    }
}

/// Signs and delivers job events through a [`WebhookTransport`].
#[derive(Clone)]
pub struct JobWebhookSink {
    transport: Arc<dyn WebhookTransport>,
    secret: String,
    allow_private: bool,
    delays: [Duration; 2],
}

impl std::fmt::Debug for JobWebhookSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobWebhookSink")
            .field("secret", &"<redacted>")
            .field("allow_private", &self.allow_private)
            .finish_non_exhaustive()
    }
}

/// One job event to deliver.
#[derive(Clone, PartialEq, Debug)]
pub struct JobEvent<'a> {
    /// Product family (`extract`, `agent`, `monitor`).
    pub kind: &'a str,
    /// Event name after the family (`started`, `completed`, `page`, `check.completed`, ...).
    pub event: &'a str,
    /// Job (or monitor) id.
    pub id: Uuid,
    /// `data` member of the payload.
    pub data: Value,
    /// Error text of a failed event; makes `success` false.
    pub error: Option<&'a str>,
}

/// `sha256=<hex>` of `HMAC-SHA256(secret, body)`, the `X-Firecrawl-Signature` value.
#[must_use]
pub fn firecrawl_signature(secret: &str, body: &[u8]) -> String {
    // HMAC accepts keys of any length, so construction cannot fail.
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()) else {
        return String::new();
    };
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

impl JobWebhookSink {
    /// A sink signing with `secret` through `transport`.
    #[must_use]
    pub fn new(transport: Arc<dyn WebhookTransport>, secret: &str) -> Self {
        Self {
            transport,
            secret: secret.to_owned(),
            allow_private: false,
            delays: RETRY_DELAYS,
        }
    }

    /// Allow loopback/private destinations (self-host and tests).
    #[must_use]
    pub const fn allow_private_networks(mut self, allow: bool) -> Self {
        self.allow_private = allow;
        self
    }

    /// Override the pauses before attempts 2 and 3 (tests).
    #[must_use]
    pub const fn retry_delays(mut self, delays: [Duration; 2]) -> Self {
        self.delays = delays;
        self
    }

    /// Body of one event: `{success, type, id, data, metadata, error?}`.
    #[must_use]
    pub fn payload(hook: &JobWebhook, ev: &JobEvent<'_>) -> Value {
        let mut body = json!({
            "success": ev.error.is_none(),
            "type": format!("{}.{}", ev.kind, ev.event),
            "id": ev.id,
            "webhookId": Uuid::now_v7(),
            "data": ev.data,
            "metadata": hook.metadata,
        });
        if let Some(e) = ev.error {
            body["error"] = json!(e);
        }
        body
    }

    /// Deliver `ev` when `hook` wants it; returns once the attempts finish, `true` when the
    /// destination acknowledged with a 2xx.
    pub async fn deliver(&self, hook: &JobWebhook, ev: &JobEvent<'_>, cancel: &CancellationToken) -> bool {
        let JobEvent { kind, event, id, .. } = *ev;
        if !hook.wants(event) {
            return false;
        }
        let body = Self::payload(hook, ev).to_string().into_bytes();
        let mut headers = vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Crawlx-Event".to_owned(), format!("{kind}.{event}")),
            (
                "X-Firecrawl-Signature".to_owned(),
                firecrawl_signature(&self.secret, &body),
            ),
        ];
        for (k, v) in &hook.headers {
            headers.push((k.clone(), v.clone()));
        }
        let egress = EgressPolicy::new(self.allow_private);
        for attempt in 0..=self.delays.len() {
            if attempt > 0 {
                let delay = self.delays[attempt - 1];
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    () = cancel.cancelled() => return false,
                }
            }
            let req = WebhookRequest {
                url: hook.url.clone(),
                headers: headers.clone(),
                body: body.clone(),
                egress: egress.clone(),
            };
            match self.transport.post(req).await {
                Ok(s) if (200..300).contains(&s) => return true,
                Ok(410) => {
                    tracing::warn!(kind, event, job = %id, "job webhook destination returned 410; dropped");
                    return false;
                }
                Ok(status) => {
                    tracing::warn!(kind, event, job = %id, status, attempt, "job webhook not accepted")
                }
                Err(TransportError::Egress(reason)) => {
                    tracing::warn!(kind, event, job = %id, reason, "job webhook destination denied");
                    return false;
                }
                Err(TransportError::Network(reason)) => {
                    tracing::warn!(kind, event, job = %id, reason, attempt, "job webhook delivery failed");
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn parses_string_and_object_forms() {
        let hook = JobWebhook::parse(Some(&json!("https://h.example/x")), "/webhook", &["completed"])
            .unwrap()
            .unwrap();
        assert_eq!(hook.url.as_str(), "https://h.example/x");
        assert!(hook.wants("completed") && hook.wants("anything"));
        let hook = JobWebhook::parse(
            Some(&json!({"url": "https://h.example/x", "headers": {"X-A": "b"}, "metadata": {"k": 1}, "events": ["completed"]})),
            "/webhook",
            &["started", "completed"],
        )
        .unwrap()
        .unwrap();
        assert!(hook.wants("completed") && !hook.wants("started"));
        assert_eq!(hook.headers["X-A"], "b");
        assert_eq!(hook.metadata, json!({"k": 1}));
    }

    #[test]
    fn rejects_bad_destinations_and_events() {
        for bad in [
            json!("ftp://h/x"),
            json!(5),
            json!({"events": ["completed"]}),
            json!({"url": "https://h/x", "events": ["nope"]}),
            json!({"url": "https://h/x", "headers": {"a": 1}}),
            json!({"url": "https://h/x", "metadata": []}),
        ] {
            assert!(
                JobWebhook::parse(Some(&bad), "/webhook", &["completed"]).is_err(),
                "{bad}"
            );
        }
        assert!(JobWebhook::parse(None, "/webhook", &[]).unwrap().is_none());
        assert!(JobWebhook::parse(Some(&Value::Null), "/webhook", &[])
            .unwrap()
            .is_none());
    }

    #[test]
    fn signature_is_sha256_hmac_of_body() {
        let a = firecrawl_signature("s", b"{}");
        assert!(a.starts_with("sha256="));
        assert_eq!(a.len(), "sha256=".len() + 64);
        assert_eq!(a, firecrawl_signature("s", b"{}"));
        assert_ne!(a, firecrawl_signature("t", b"{}"));
    }
}
