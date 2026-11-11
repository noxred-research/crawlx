//! Bounded retained-body capture. Raw bytes stay in this task until the policy sink accepts them.

use super::{Ctl, State};
use base64::Engine as _;
use parking_lot::Mutex;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Hard bound per decoded response. Chromium's own resource buffer uses the same cap.
pub(super) const MAX_BODY_BYTES: usize = 1024 * 1024;

pub(super) fn network_params() -> serde_json::Value {
    json!({
        "maxTotalBufferSize": 8 * MAX_BODY_BYTES,
        "maxResourceBufferSize": MAX_BODY_BYTES,
        "maxPostDataSize": 0,
    })
}

pub(super) async fn flush(ctl: &Ctl, state: &Arc<Mutex<State>>) {
    let mut notified = ctl.notify.subscribe();
    // Each retained-body task already has a 10-second deadline. Keep the final action's
    // traffic drain from racing its final artifact reference.
    let _ = tokio::time::timeout(Duration::from_secs(11), async {
        loop {
            if state.lock().pending_bodies.is_empty() {
                break;
            }
            if notified.changed().await.is_err() {
                break;
            }
        }
    })
    .await;
}

pub(super) async fn retain(
    ctl: &Ctl,
    state: &Arc<Mutex<State>>,
    session: &str,
    request_id: &str,
    seq: u64,
    content_type: &str,
) {
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let response = ctl
            .client
            .call_budgeted(
                "Network.getResponseBody",
                Some(session),
                json!({ "requestId": request_id }),
            )
            .await
            .map_err(|_| "unavailable")?;
        let response = response.value();
        let body = response
            .get("body")
            .and_then(serde_json::Value::as_str)
            .ok_or("unavailable")?;
        // Bound before decoding or copying. CDP may use base64 for non-text bodies.
        let encoded = response
            .get("base64Encoded")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let bound = if encoded {
            MAX_BODY_BYTES.div_ceil(3) * 4
        } else {
            MAX_BODY_BYTES
        };
        if body.len() > bound {
            return Err("oversized");
        }
        let bytes = if encoded {
            std::borrow::Cow::Owned(
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .map_err(|_| "unavailable")?,
            )
        } else {
            std::borrow::Cow::Borrowed(body.as_bytes())
        };
        if bytes.len() > MAX_BODY_BYTES {
            return Err("oversized");
        }
        let sink = ctl.config.response_body_sink.as_ref().ok_or("policy_denied")?;
        sink.store(content_type, &bytes, false)
            .await
            .map_err(|_| "storage_failed")?
            .ok_or("policy_denied")
    })
    .await
    .unwrap_or(Err("unavailable"));
    let mut state = state.lock();
    if let Some(event) = state.traffic.iter_mut().find(|event| event.seq == seq) {
        let status = match result {
            Ok(artifact) => {
                event.response_body = Some(artifact);
                "stored"
            }
            Err(status) => status,
        };
        if let Some((_, value)) = event
            .response_headers
            .iter_mut()
            .find(|(name, _)| name == "x-crawlx-body-state")
        {
            *value = status.to_owned();
        }
    }
    state.pending_bodies.remove(&seq);
    ctl.notify.send_modify(|value| *value = value.wrapping_add(1));
}

const TEXT_PREFIX_BYTES: usize = 64 * 1024;

fn append_base64_prefix(prefix: &mut Vec<u8>, encoded: &str) -> Result<(), &'static str> {
    let remaining = TEXT_PREFIX_BYTES.saturating_sub(prefix.len());
    let encoded_limit = remaining.div_ceil(3).saturating_mul(4).min(encoded.len());
    let start = prefix.len();
    // Base64 decoding can need two scratch bytes beyond the retained UTF-8 prefix.
    prefix.resize(start + encoded_limit.div_ceil(4) * 3, 0);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode_slice(&encoded.as_bytes()[..encoded_limit], &mut prefix[start..])
        .map_err(|_| "unavailable")?;
    prefix.truncate(start + decoded.min(remaining));
    Ok(())
}

pub(super) async fn retain_prefix(
    ctl: &Ctl,
    state: &Arc<Mutex<State>>,
    session: &str,
    request_id: &str,
    content_type: &str,
) {
    let key = (session.to_owned(), request_id.to_owned());
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut events = ctl.client.subscribe();
        let mut prefix = Vec::with_capacity(TEXT_PREFIX_BYTES + 2);
        let streamed = ctl
            .client
            .call_budgeted(
                "Network.streamResourceContent",
                Some(session),
                json!({ "requestId": request_id }),
            )
            .await;
        match streamed {
            Ok(response) => {
                let response = response.value();
                let buffered = response
                    .get("bufferedData")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("unavailable")?;
                append_base64_prefix(&mut prefix, buffered)?;
                while prefix.len() < TEXT_PREFIX_BYTES {
                    let event = match events.try_recv() {
                        Ok(event) => event,
                        Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                            if state
                                .lock()
                                .text_prefixes
                                .get(&key)
                                .is_some_and(|entry| entry.seq.is_some())
                            {
                                break;
                            }
                            events.recv().await.map_err(|_| "unavailable")?
                        }
                        Err(_) => return Err("unavailable"),
                    };
                    if event.session_id.as_deref() != Some(session)
                        || event.params.get("requestId").and_then(serde_json::Value::as_str)
                            != Some(request_id)
                    {
                        continue;
                    }
                    match event.method.as_str() {
                        "Network.dataReceived" => {
                            if let Some(data) = event.params.get("data").and_then(serde_json::Value::as_str) {
                                append_base64_prefix(&mut prefix, data)?;
                            }
                        }
                        "Network.loadingFinished" => break,
                        "Network.loadingFailed" => return Err("unavailable"),
                        _ => {}
                    }
                }
            }
            Err(_) => {
                // A cached/already-complete response may finish before streaming starts.
                // Chromium's resource buffer still bounds this fallback to 1 MiB.
                let response = ctl
                    .client
                    .call_budgeted(
                        "Network.getResponseBody",
                        Some(session),
                        json!({ "requestId": request_id }),
                    )
                    .await
                    .map_err(|_| "unavailable")?;
                let response = response.value();
                let body = response
                    .get("body")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("unavailable")?;
                if response.get("base64Encoded").and_then(serde_json::Value::as_bool) == Some(true) {
                    append_base64_prefix(&mut prefix, body)?;
                } else {
                    prefix.extend_from_slice(&body.as_bytes()[..body.len().min(TEXT_PREFIX_BYTES)]);
                }
            }
        }
        if let Err(error) = std::str::from_utf8(&prefix) {
            if error.error_len().is_some() {
                return Err("policy_denied");
            }
            prefix.truncate(error.valid_up_to());
        }
        let mut notified = ctl.notify.subscribe();
        loop {
            let status = {
                let state = state.lock();
                state
                    .text_prefixes
                    .get(&key)
                    .and_then(|entry| entry.seq)
                    .and_then(|seq| {
                        state
                            .traffic
                            .iter()
                            .find(|event| event.seq == seq)
                            .and_then(|event| {
                                event
                                    .response_headers
                                    .iter()
                                    .find(|(name, _)| name == "x-crawlx-body-state")
                                    .map(|(_, value)| value.clone())
                            })
                    })
            };
            match status.as_deref() {
                Some("pending") => break,
                Some("policy_denied") => return Err("policy_denied"),
                Some("unavailable") => return Err("unavailable"),
                _ => {
                    notified.changed().await.map_err(|_| "unavailable")?;
                }
            }
        }
        let sink = ctl.config.response_body_sink.as_ref().ok_or("policy_denied")?;
        sink.store(content_type, &prefix, true)
            .await
            .map_err(|_| "storage_failed")?
            .ok_or("policy_denied")
    })
    .await
    .unwrap_or(Err("unavailable"));
    let mut state = state.lock();
    if let Some(entry) = state.text_prefixes.get_mut(&key) {
        entry.result = Some(result);
    }
    state.finish_prefix(&key);
    ctl.notify.send_modify(|value| *value = value.wrapping_add(1));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn streamed_prefix_is_bounded_across_chunks_and_binary_boundaries() {
        let first = vec![b'a'; TEXT_PREFIX_BYTES - 2];
        let second = vec![b'b'; TEXT_PREFIX_BYTES];
        let mut prefix = Vec::new();
        append_base64_prefix(
            &mut prefix,
            &base64::engine::general_purpose::STANDARD.encode(first),
        )
        .unwrap();
        append_base64_prefix(
            &mut prefix,
            &base64::engine::general_purpose::STANDARD.encode(second),
        )
        .unwrap();
        assert_eq!(prefix.len(), TEXT_PREFIX_BYTES);
        assert_eq!(&prefix[TEXT_PREFIX_BYTES - 2..], b"bb");
        append_base64_prefix(&mut prefix, "ignored-invalid-extra-data").unwrap();
        assert_eq!(prefix.len(), TEXT_PREFIX_BYTES);
    }
}
