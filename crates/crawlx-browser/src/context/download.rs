//! Memory-only, explicitly authorized downloads. Response interception consumes bounded chunks
//! before Chromium can create a native download. Browser download behavior remains `deny`.
//! An owned transport task outlives a dropped waiter until paused requests, stream handles and
//! temporary interception are cleaned up. Neither raw bytes nor host paths leave the policy sink.

use super::{CdpContext, Ctl};
use crate::cdp::{CdpEvent, CdpSession};
use base64::Engine;
use crawlx_core::browser::BrowserError;
use crawlx_core::browser_capture::{CaptureArtifact, CaptureCompleteness, CaptureDescriptor, CaptureKind};
use crawlx_core::browser_download::DownloadSpec;
use crawlx_core::secret::Redactor;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
const READ_CHUNK: u64 = 64 * 1024;
const PAUSE_LIMIT: usize = 64;
static DOWNLOAD_LEASE: Mutex<()> = Mutex::const_new(());

/// One session's bounded event routing, owned until its transport finishes cleanup.
pub(super) struct Intercept {
    frame: String,
    events: mpsc::Sender<Arc<CdpEvent>>,
    pending: BTreeSet<String>,
    cancel: CancellationToken,
}

/// Offer a paused main-frame request to its explicitly registered download operation.
/// Queue exhaustion cancels the operation; the request remains tracked for fail-closed cleanup.
pub(super) fn intercept(ctl: &Ctl, event: Arc<CdpEvent>) -> bool {
    let Some(session) = event.session_id.as_ref() else {
        return false;
    };
    let mut downloads = ctl.downloads.lock();
    let Some(owner) = downloads.get_mut(session) else {
        return false;
    };
    if text(&event.params, "frameId") != owner.frame || text(&event.params, "resourceType") != "Document" {
        return false;
    }
    let request = text(&event.params, "requestId");
    if request.is_empty() {
        owner.cancel.cancel();
        return true;
    }
    if owner.pending.len() >= PAUSE_LIMIT {
        owner.cancel.cancel();
        return true;
    }
    owner.pending.insert(request.to_owned());
    if owner.events.try_send(event).is_err() {
        owner.cancel.cancel();
    }
    true
}

fn refused(reason: &'static str) -> BrowserError {
    BrowserError::Unsupported(reason.to_owned())
}

async fn bounded<T>(
    cancel: &CancellationToken,
    deadline: Instant,
    timeout_ms: u32,
    operation: impl Future<Output = Result<T, BrowserError>>,
) -> Result<T, BrowserError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(refused("download cancelled")),
        () = tokio::time::sleep_until(deadline) => Err(BrowserError::Timeout(u64::from(timeout_ms))),
        result = operation => result,
    }
}

impl CdpContext {
    /// Download a guarded HTTP(S) resource through the configured retention-policy capture sink.
    ///
    /// Authorization precedes interception and navigation. Response bytes stream into bounded
    /// memory; Chromium's native downloads remain denied. Original filename suggestions are
    /// checked before reading. Only immutable redactor-approved bytes reach the artifact sink.
    /// The context cancellation token, deadline and dropping this future all cancel transport.
    /// Cleanup aborts paused requests, closes the stream and restores original Fetch patterns.
    ///
    /// # Errors
    /// Refuses absent/denied policy, unsafe names, invalid bounds, redirects denied by the guard,
    /// oversize data and cancellation. Returns protocol, approval, storage or deadline failures.
    pub async fn download(&mut self, spec: DownloadSpec) -> Result<CaptureArtifact, BrowserError> {
        spec.validate().map_err(refused)?;
        let deadline = Instant::now() + Duration::from_millis(u64::from(spec.timeout_ms));
        let cancel = self.ctl.config.captcha_cancel.child_token();
        let _cancel_on_drop = cancel.clone().drop_guard();
        let sink = self
            .ctl
            .config
            .browser_capture_sink
            .as_ref()
            .ok_or_else(|| refused("download requires a retention-policy artifact sink"))?;
        bounded(&cancel, deadline, spec.timeout_ms, async {
            if !sink
                .authorize(CaptureKind::Download)
                .await
                .map_err(BrowserError::CapturePolicy)?
            {
                return Err(refused("download artifact policy denied"));
            }
            super::guard::check_navigation(self.ctl.config.navigation_guard.as_ref(), &spec.url).await
        })
        .await?;
        let (target, session) = self.session_for(None)?;
        let frame = self
            .state
            .lock()
            .tabs
            .get(&target)
            .map(|tab| tab.main_frame.clone())
            .ok_or(BrowserError::TargetClosed)?;
        let ctl = Arc::clone(&self.ctl);
        let transfer_cancel = cancel.clone();
        let timeout_ms = spec.timeout_ms;
        let (tx, rx) = oneshot::channel();
        tokio::spawn(crawlx_core::custody::inherit(async move {
            let result = transport(ctl, session, frame, spec, transfer_cancel, deadline).await;
            let _ = tx.send(result);
        }));
        // Normal cancellation waits for cleanup. A dropped waiter triggers its cancellation guard;
        // the transport owner keeps running until browser state is restored.
        let output = rx.await.map_err(|_| BrowserError::TargetClosed)??;
        bounded(&cancel, deadline, timeout_ms, async {
            let Output {
                bytes,
                filename,
                source_url,
                content_type,
            } = output;
            let bytes = tokio::task::spawn_blocking(move || Redactor::default().verify_binary(&bytes))
                .await
                .map_err(|_| refused("download approval task failed"))?
                .map_err(BrowserError::CapturePolicy)?;
            let size =
                u64::try_from(bytes.as_ref().len()).map_err(|_| refused("download exceeds byte limit"))?;
            let redactor = Redactor::default();
            let mut descriptor = CaptureDescriptor::new(
                CaptureKind::Download,
                redactor.redact_text(&content_type).into_inner(),
                redactor.redact_text(&source_url).into_inner(),
            );
            descriptor.filename = Some(redactor.redact_text(&filename).into_inner());
            let artifact = sink
                .store(&descriptor, &bytes)
                .await
                .map_err(BrowserError::CapturePolicy)?
                .ok_or_else(|| refused("download artifact policy denied"))?;
            Ok(CaptureArtifact::new(
                descriptor,
                artifact,
                size,
                CaptureCompleteness::Complete,
            ))
        })
        .await
    }
}

struct Output {
    bytes: Vec<u8>,
    filename: String,
    source_url: String,
    content_type: String,
}

struct Transfer {
    ctl: Arc<Ctl>,
    session: CdpSession,
    events: mpsc::Receiver<Arc<CdpEvent>>,
    stream: Option<String>,
}

async fn transport(
    ctl: Arc<Ctl>,
    session: CdpSession,
    frame: String,
    spec: DownloadSpec,
    cancel: CancellationToken,
    deadline: Instant,
) -> Result<Output, BrowserError> {
    let _lease = bounded(&cancel, deadline, spec.timeout_ms, async {
        Ok(DOWNLOAD_LEASE.lock().await)
    })
    .await?;
    let (tx, rx) = mpsc::channel(16);
    ctl.downloads.lock().insert(
        session.session_id.clone(),
        Intercept {
            frame,
            events: tx,
            pending: BTreeSet::new(),
            cancel: cancel.clone(),
        },
    );
    let mut transfer = Transfer {
        ctl,
        session,
        events: rx,
        stream: None,
    };
    let result = bounded(&cancel, deadline, spec.timeout_ms, async {
        let mut patterns = original_patterns(&transfer.ctl);
        // A Request pause is required even without a configured guard: every redirect is checked
        // before it leaves. The registry owns only the active main frame's events.
        if patterns.is_empty() {
            patterns.push(json!({ "resourceType": "Document", "requestStage": "Request" }));
        }
        patterns.push(json!({ "resourceType": "Document", "requestStage": "Response" }));
        transfer
            .session
            .send("Fetch.enable", json!({ "patterns": patterns }))
            .await?;
        let session = transfer.session.clone();
        let navigate = async {
            let reply = session
                .send("Page.navigate", json!({ "url": spec.url.as_str() }))
                .await?;
            if reply
                .get("errorText")
                .and_then(Value::as_str)
                .is_some_and(|error| error != "net::ERR_ABORTED")
            {
                return Err(BrowserError::Navigation("download navigation failed".to_owned()));
            }
            Ok(())
        };
        let (_, output) = tokio::try_join!(navigate, transfer.receive(spec.max_bytes))?;
        Ok(output)
    })
    .await;
    let cleanup = transfer.cleanup().await;
    cleanup?;
    result
}

fn original_patterns(ctl: &Ctl) -> Vec<Value> {
    super::guard::fetch_patterns(ctl, ctl.rules_fetch.load(std::sync::atomic::Ordering::Acquire))
}

impl Transfer {
    async fn receive(&mut self, max_bytes: u64) -> Result<Output, BrowserError> {
        for _ in 0..PAUSE_LIMIT {
            let event = self
                .events
                .recv()
                .await
                .ok_or_else(|| refused("download event stream lost"))?;
            let request = text(&event.params, "requestId");
            let url = url::Url::parse(text(&event.params["request"], "url"))
                .map_err(|_| refused("invalid download source URL"))?;
            if !matches!(url.scheme(), "http" | "https")
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(refused("invalid download source URL"));
            }
            if event.params.get("responseErrorReason").is_some() {
                return Err(BrowserError::Navigation("download response failed".to_owned()));
            }
            let Some(status) = event.params.get("responseStatusCode").and_then(Value::as_u64) else {
                super::guard::check_navigation(self.ctl.config.navigation_guard.as_ref(), &url).await?;
                self.session
                    .send("Fetch.continueRequest", json!({ "requestId": request }))
                    .await?;
                continue;
            };
            if (300..400).contains(&status) {
                self.session
                    .send("Fetch.continueResponse", json!({ "requestId": request }))
                    .await?;
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(BrowserError::Navigation(
                    "download response was not successful".to_owned(),
                ));
            }
            let mut filename = "download".to_owned();
            let mut content_type = "application/octet-stream".to_owned();
            let headers = event
                .params
                .get("responseHeaders")
                .and_then(Value::as_array)
                .ok_or_else(|| refused("download response has no headers"))?;
            for header in headers {
                let value = text(header, "value");
                if value.len() > 64 * 1024 {
                    return Err(refused("download response header exceeds limit"));
                }
                match text(header, "name").to_ascii_lowercase().as_str() {
                    "content-disposition" => {
                        if let Some(name) = disposition(value)? {
                            filename = name;
                        }
                    }
                    "content-type" => content_type = value.to_owned(),
                    "content-length"
                        if value
                            .parse::<u64>()
                            .map_err(|_| refused("invalid download length"))?
                            > max_bytes =>
                    {
                        return Err(refused("download exceeds byte limit"));
                    }
                    _ => {}
                }
            }
            let stream = self
                .session
                .send("Fetch.takeResponseBodyAsStream", json!({ "requestId": request }))
                .await?;
            self.stream = Some(text(&stream, "stream").to_owned());
            if self.stream.as_deref().is_none_or(str::is_empty) {
                return Err(refused("download response has no stream"));
            }
            let bytes = self.read(max_bytes).await?;
            // Taking a response stream makes continuing it invalid. Abort instead: the approved
            // artifact is the result, not a native browser file or a second network request.
            self.session
                .send(
                    "Fetch.failRequest",
                    json!({ "requestId": request, "errorReason": "Aborted" }),
                )
                .await?;
            return Ok(Output {
                bytes,
                filename,
                source_url: super::guard::loggable(&url),
                content_type,
            });
        }
        Err(refused("download redirect limit exceeded"))
    }

    async fn read(&self, max_bytes: u64) -> Result<Vec<u8>, BrowserError> {
        let stream = self
            .stream
            .as_deref()
            .ok_or_else(|| refused("download response has no stream"))?;
        let mut bytes = Vec::new();
        loop {
            let used = u64::try_from(bytes.len()).map_err(|_| refused("download exceeds byte limit"))?;
            let size = max_bytes.saturating_sub(used).saturating_add(1).min(READ_CHUNK);
            let reply = self
                .session
                .send("IO.read", json!({ "handle": stream, "size": size }))
                .await?;
            let data = reply
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| refused("invalid download stream chunk"))?;
            if reply
                .get("base64Encoded")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let encoded_limit = size.saturating_add(2).saturating_div(3).saturating_mul(4);
                if u64::try_from(data.len()).unwrap_or(u64::MAX) > encoded_limit {
                    return Err(refused("download stream chunk exceeds limit"));
                }
                base64::engine::general_purpose::STANDARD
                    .decode_vec(data, &mut bytes)
                    .map_err(|_| refused("invalid download stream encoding"))?;
            } else {
                if u64::try_from(data.len()).unwrap_or(u64::MAX) > size {
                    return Err(refused("download stream chunk exceeds limit"));
                }
                bytes.extend_from_slice(data.as_bytes());
            }
            let total = u64::try_from(bytes.len()).map_err(|_| refused("download exceeds byte limit"))?;
            if total.saturating_sub(used) > size || total > max_bytes {
                return Err(refused("download exceeds byte limit"));
            }
            if reply.get("eof").and_then(Value::as_bool).unwrap_or(false) {
                return Ok(bytes);
            }
        }
    }

    async fn cleanup(&mut self) -> Result<(), BrowserError> {
        let _ = self
            .ctl
            .client
            .call_with_timeout(
                "Page.stopLoading",
                Some(&self.session.session_id),
                json!({}),
                CLEANUP_TIMEOUT,
            )
            .await;
        let pending = self
            .ctl
            .downloads
            .lock()
            .get(&self.session.session_id)
            .map(|owner| owner.pending.clone())
            .unwrap_or_default();
        for request in pending {
            // A completed Request pause and its Response pause can share an ID. Already-resumed
            // IDs are harmless protocol refusals; all still-paused IDs must be aborted.
            let _ = self
                .ctl
                .client
                .call_with_timeout(
                    "Fetch.failRequest",
                    Some(&self.session.session_id),
                    json!({ "requestId": request, "errorReason": "Aborted" }),
                    CLEANUP_TIMEOUT,
                )
                .await;
        }
        if let Some(stream) = self.stream.take() {
            let _ = self
                .ctl
                .client
                .call_with_timeout(
                    "IO.close",
                    Some(&self.session.session_id),
                    json!({ "handle": stream }),
                    CLEANUP_TIMEOUT,
                )
                .await;
        }
        let patterns = original_patterns(&self.ctl);
        let restored = if patterns.is_empty() {
            self.ctl
                .client
                .call_with_timeout(
                    "Fetch.disable",
                    Some(&self.session.session_id),
                    json!({}),
                    CLEANUP_TIMEOUT,
                )
                .await
        } else {
            self.ctl
                .client
                .call_with_timeout(
                    "Fetch.enable",
                    Some(&self.session.session_id),
                    json!({ "patterns": patterns }),
                    CLEANUP_TIMEOUT,
                )
                .await
        };
        self.ctl.downloads.lock().remove(&self.session.session_id);
        restored.map(|_| ())
    }
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value.get(name).and_then(Value::as_str).unwrap_or_default()
}

fn safe_filename(name: &str) -> Result<(), BrowserError> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
    {
        return Err(refused("unsafe download filename"));
    }
    Ok(())
}

fn disposition(header: &str) -> Result<Option<String>, BrowserError> {
    if header.contains('\\') {
        return Err(refused("unsafe download filename"));
    }
    let mut filename = None;
    let mut quoted = false;
    for part in header
        .split(|c| {
            if c == '"' {
                quoted = !quoted;
            }
            c == ';' && !quoted
        })
        .skip(1)
    {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("filename") && !key.trim().eq_ignore_ascii_case("filename*") {
            continue;
        }
        let value = value.trim().trim_matches('"');
        let value = if key.trim().ends_with('*') {
            value
                .splitn(3, '\'')
                .nth(2)
                .ok_or_else(|| refused("invalid download filename header"))?
        } else {
            value
        };
        let mut decoded = Vec::with_capacity(value.len());
        let mut bytes = value.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                let high = bytes.next().and_then(|b| char::from(b).to_digit(16));
                let low = bytes.next().and_then(|b| char::from(b).to_digit(16));
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(refused("invalid download filename header"));
                };
                decoded.push(
                    u8::try_from(high * 16 + low).map_err(|_| refused("invalid download filename header"))?,
                );
            } else {
                decoded.push(byte);
            }
        }
        let name = String::from_utf8(decoded).map_err(|_| refused("invalid download filename header"))?;
        safe_filename(&name)?;
        filename = Some(name);
    }
    if quoted {
        return Err(refused("invalid download filename header"));
    }
    Ok(filename)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn traversal_suggestions_fail_before_becoming_paths() {
        for name in [
            "../escape",
            "..\\escape",
            "/tmp/escape",
            "C:escape",
            ".",
            "..",
            "x\0y",
        ] {
            assert!(safe_filename(name).is_err(), "{name:?}");
        }
        for header in [
            "attachment; filename=../escape",
            "attachment; filename*=UTF-8''..%2fescape",
            "attachment; filename=..%5cescape",
            "attachment; filename=\"safe;../escape\"",
        ] {
            assert!(disposition(header).is_err(), "{header}");
        }
        assert_eq!(
            disposition("attachment; filename=public.txt").unwrap().as_deref(),
            Some("public.txt")
        );
    }
}
