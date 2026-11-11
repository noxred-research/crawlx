//! Policy-gated browser renditions. Only artifact references leave this module.
//!
//! MHTML retains the browser's resource snapshot, not original wire responses. Resource
//! failures mark it truncated; even a clean resource tree cannot prove that every remote
//! asset was loaded, so its completeness remains unknown. Image dimensions come from the
//! encoded image, rather than CSS dimensions or an assumed device scale factor.

use super::CdpContext;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use crawlx_core::browser::{BrowserContext, BrowserError};
use crawlx_core::browser_capture::{
    BrowserCaptureSink, CaptureArtifact, CaptureCompleteness, CaptureDescriptor, CaptureKind, CaptureSpec,
};
use crawlx_core::page_op::{PageOp, PageOpResult, ShotSpec};
use crawlx_core::parser_memory::{global, AdmittedBytes};
use crawlx_core::secret::Redactor;
use serde_json::{json, Value};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(120);
const MAX_BYTES: u64 = 32 * 1024 * 1024;
const SOURCE_BYTES: usize = 1024 * 1024;
const RESOURCE_BYTES: usize = 8 * SOURCE_BYTES;
const RESOURCE_COUNT: usize = 128;
const SHOT_EDGE: f64 = 16_384.0;

// Bound the browser-to-host projection before serializing its result. Live control values
// matter: outerHTML alone does not contain values entered after document construction.
const SOURCE_PROBE: &str = r#"(() => {
  const root = document.documentElement;
  const source = root ? root.outerHTML : '';
  if (source.length > 1048576) return { denied: true };
  const controls = document.querySelectorAll('input,textarea,select');
  if (controls.length > 128) return { denied: true };
  const values = [];
  let size = source.length;
  for (const node of controls) {
    const value = String(node.value || '');
    if (node.type === 'password' && value) return { denied: true };
    const name = String(node.name || node.id || 'value');
    size += name.length + value.length;
    if (size > 1048576) return { denied: true };
    values.push({ name, value });
  }
  const url = String(location.href);
  if (url.length > 8192) return { denied: true };
  return { source, values, url, dpr: devicePixelRatio };
})()"#;

fn denied(reason: &'static str) -> BrowserError {
    BrowserError::Unsupported(reason.to_owned())
}

/// Charge an owned buffer against the shared budget before retaining it as capture evidence.
fn charge(bytes: Vec<u8>) -> Result<AdmittedBytes, BrowserError> {
    let permit = global().try_reserve(bytes.capacity())?;
    Ok(AdmittedBytes::new(bytes, permit))
}

/// Reserve first, then copy a borrowed slice into a charged buffer; refusal allocates nothing.
fn charge_copy(bytes: &[u8]) -> Result<AdmittedBytes, BrowserError> {
    let permit = global().try_reserve(bytes.len())?;
    Ok(AdmittedBytes::new(bytes.to_vec(), permit))
}

fn byte_limit(value: u64) -> Result<usize, BrowserError> {
    if value == 0 || value > MAX_BYTES {
        return Err(denied("capture byte limit must be within 1..=33554432"));
    }
    usize::try_from(value).map_err(|_| denied("capture byte limit is not representable"))
}

fn request_kind(spec: &CaptureSpec) -> Result<(CaptureKind, usize), BrowserError> {
    let (kind, limit) = match spec {
        CaptureSpec::Mhtml { max_bytes } => (CaptureKind::Mhtml, *max_bytes),
        CaptureSpec::Screenshot {
            max_bytes,
            max_pixels,
            ..
        } => {
            if *max_pixels == 0 {
                return Err(denied("capture pixel limit must be positive"));
            }
            (CaptureKind::Screenshot, *max_bytes)
        }
        CaptureSpec::Pdf { max_bytes, .. } => (CaptureKind::Pdf, *max_bytes),
        CaptureSpec::Text { max_bytes } => (CaptureKind::Text, *max_bytes),
        _ => return Err(denied("unsupported retained capture representation")),
    };
    Ok((kind, byte_limit(limit)?))
}

async fn approve_source(sink: &dyn BrowserCaptureSink, bytes: &[u8]) -> Result<(), BrowserError> {
    if bytes.len() > SOURCE_BYTES {
        return Err(denied("capture source exceeds privacy inspection bound"));
    }
    // Keep source checks independent of final binary approval: encoded images and archive
    // parts can conceal a registered literal that is visible in their decoded source.
    let approved = Redactor::new()
        .verify_binary(bytes)
        .map_err(BrowserError::CapturePolicy)?;
    if !sink
        .authorize_source(approved.as_ref())
        .await
        .map_err(BrowserError::CapturePolicy)?
    {
        return Err(denied("capture source privacy policy refused retention"));
    }
    Ok(())
}

fn image_dimensions(bytes: &[u8], mime: &str) -> Result<(u32, u32), BrowserError> {
    if mime == "image/png" && bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        if bytes.get(12..16) == Some(b"IHDR".as_slice()) {
            let width = bytes.get(16..20).and_then(|v| <[u8; 4]>::try_from(v).ok());
            let height = bytes.get(20..24).and_then(|v| <[u8; 4]>::try_from(v).ok());
            if let (Some(w), Some(h)) = (width, height) {
                return positive_dimensions(u32::from_be_bytes(w), u32::from_be_bytes(h));
            }
        }
    } else if mime == "image/jpeg" && bytes.starts_with(&[0xff, 0xd8]) {
        let mut offset = 2usize;
        while let Some(&marker) = bytes.get(offset) {
            if marker != 0xff {
                break;
            }
            offset += 1;
            while bytes.get(offset) == Some(&0xff) {
                offset += 1;
            }
            let Some(&kind) = bytes.get(offset) else { break };
            offset += 1;
            if kind == 0xda || kind == 0xd9 {
                break;
            }
            if kind == 0x01 || (0xd0..=0xd7).contains(&kind) {
                continue;
            }
            let Some(length) = bytes.get(offset..offset.saturating_add(2)) else {
                break;
            };
            let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
            if length < 2 || offset.saturating_add(length) > bytes.len() {
                break;
            }
            if matches!(kind, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
                if length < 7 {
                    break;
                }
                let height = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]);
                let width = u16::from_be_bytes([bytes[offset + 5], bytes[offset + 6]]);
                return positive_dimensions(u32::from(width), u32::from(height));
            }
            offset += length;
        }
    }
    Err(denied("capture image encoding or dimensions are unavailable"))
}

fn positive_dimensions(width: u32, height: u32) -> Result<(u32, u32), BrowserError> {
    if width == 0 || height == 0 {
        return Err(denied("capture image dimensions must be positive"));
    }
    Ok((width, height))
}

fn metric(value: &Value, key: &str) -> Result<f64, BrowserError> {
    value
        .get(key)
        .and_then(Value::as_f64)
        .filter(|n| n.is_finite() && *n > 0.0)
        .ok_or_else(|| denied("capture layout dimensions are unavailable"))
}

fn shot_bounds(
    shot: &ShotSpec,
    layout: &Value,
    viewport: (u32, u32),
    dpr: f64,
    max_pixels: u64,
) -> Result<(f64, f64), BrowserError> {
    if !dpr.is_finite() || dpr <= 0.0 || dpr > 16.0 {
        return Err(denied("capture device scale factor is unavailable"));
    }
    if viewport.0 == 0
        || viewport.1 == 0
        || f64::from(viewport.0) > SHOT_EDGE
        || f64::from(viewport.1) > SHOT_EDGE
    {
        return Err(denied("capture viewport exceeds texture bounds"));
    }
    let (width, height) = if shot.full_page {
        let content = layout
            .get("cssContentSize")
            .ok_or_else(|| denied("capture CSS content dimensions are unavailable"))?;
        (
            metric(content, "width")?.max(f64::from(viewport.0)).ceil(),
            metric(content, "height")?.ceil(),
        )
    } else {
        (f64::from(viewport.0), f64::from(viewport.1))
    };
    let (bounded_width, bounded_height) = if shot.full_page && shot.viewport.is_some() {
        // A viewport override can reflow the document. Its post-reflow extent is not yet
        // known; reserve the existing page operation's full texture bound, not a guess.
        (SHOT_EDGE, SHOT_EDGE)
    } else if shot.full_page {
        (width.min(SHOT_EDGE), height.min(SHOT_EDGE))
    } else {
        (width, height)
    };
    let pixels = (bounded_width * dpr).ceil() * (bounded_height * dpr).ceil();
    // All allowed texture dimensions fit exactly in f64. Capping the caller's u64
    // allowance at 2^53 avoids an upward-rounded integer conversion at this boundary.
    #[allow(clippy::cast_precision_loss)]
    let limit = max_pixels.min(1u64 << 53) as f64;
    if !pixels.is_finite() || pixels > limit {
        return Err(denied("capture exceeds pixel limit"));
    }
    Ok((width * dpr, height * dpr))
}

fn resources<'a>(tree: &'a Value, out: &mut Vec<(&'a str, &'a str)>) -> Result<bool, BrowserError> {
    if out.len() >= RESOURCE_COUNT {
        return Err(denied("capture resource inspection count exceeded"));
    }
    let frame = tree
        .get("frame")
        .ok_or_else(|| denied("capture resource tree is unavailable"))?;
    let id = frame
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| denied("capture resource frame is unavailable"))?;
    let url = frame
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| denied("capture resource URL is unavailable"))?;
    out.push((id, url));
    let mut missing = false;
    if let Some(entries) = tree.get("resources").and_then(Value::as_array) {
        for entry in entries {
            if entry.get("failed").and_then(Value::as_bool) == Some(true)
                || entry.get("canceled").and_then(Value::as_bool) == Some(true)
            {
                missing = true;
                continue;
            }
            if out.len() >= RESOURCE_COUNT {
                return Err(denied("capture resource inspection count exceeded"));
            }
            let url = entry
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| denied("capture resource URL is unavailable"))?;
            out.push((id, url));
        }
    }
    if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
        for child in children {
            missing |= resources(child, out)?;
        }
    }
    Ok(missing)
}

impl CdpContext {
    /// Retain a bounded browser rendition through the configured policy sink.
    ///
    /// No raw bytes are returned. Missing policy, denied source privacy, secret request
    /// controls, logged-in profiles and solver-enabled contexts fail before capture.
    /// Full-page screenshots report clipping, including the existing 16384 CSS-pixel edge
    /// cap. PNG/JPEG dimensions are read from actual encoded bytes, so DPR is not assumed.
    /// MHTML completeness is always unknown; observed missing resources set `truncated`.
    /// Encoded byte limits must be within 1..=32 MiB. Source inspection accepts at most
    /// 1 MiB per document/resource, 128 resources and 8 MiB of resources in total.
    ///
    /// # Errors
    /// Returns policy/source refusal, invalid bounds, unavailable resource inspection,
    /// target/protocol failures, capture timeout or the policy sink's chained store error.
    pub async fn retained_capture(&mut self, spec: CaptureSpec) -> Result<CaptureArtifact, BrowserError> {
        tokio::time::timeout(DEADLINE, self.retained_capture_impl(spec))
            .await
            .map_err(|_| BrowserError::Timeout(120_000))?
    }

    async fn retained_capture_impl(&mut self, spec: CaptureSpec) -> Result<CaptureArtifact, BrowserError> {
        let (kind, limit) = request_kind(&spec)?;
        let sink = self
            .ctl
            .config
            .browser_capture_sink
            .clone()
            .ok_or_else(|| denied("retained capture requires an explicit policy sink"))?;
        if !sink.authorize(kind).await.map_err(BrowserError::CapturePolicy)? {
            return Err(denied("capture retention policy refused representation"));
        }
        if !self.ctl.config.request_controls.headers().is_empty()
            || !self.ctl.config.request_controls.cookies().is_empty()
            || self.ctl.config.captcha.is_some()
            || !self.ctl.config.incognito
            || self.ctl.config.browser_profile.is_some()
        {
            return Err(denied(
                "retained capture is unavailable for secret-bearing browser contexts",
            ));
        }
        let epoch = self.current_epoch();
        let PageOpResult::Json(source) = self
            .page_op(PageOp::EvaluateScript {
                script: SOURCE_PROBE.to_owned(),
            })
            .await?
        else {
            return Err(denied("capture source privacy inspection is unavailable"));
        };
        if source.get("denied").and_then(Value::as_bool) == Some(true) {
            return Err(denied("capture source exceeds privacy inspection bound"));
        }
        let html = source
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| denied("capture source DOM is unavailable"))?;
        approve_source(sink.as_ref(), html.as_bytes()).await?;
        let values = source
            .get("values")
            .and_then(Value::as_array)
            .ok_or_else(|| denied("capture control inspection is unavailable"))?;
        if values.len() > RESOURCE_COUNT {
            return Err(denied("capture control inspection count exceeded"));
        }
        let redactor = Redactor::new();
        for control in values {
            let name = control
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| denied("capture control name is unavailable"))?;
            let value = control
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| denied("capture control value is unavailable"))?;
            if !value.is_empty() && redactor.is_sensitive_name(name) {
                return Err(denied("capture source has a secret-bearing control"));
            }
            approve_source(sink.as_ref(), value.as_bytes()).await?;
        }
        let url = source
            .get("url")
            .and_then(Value::as_str)
            .filter(|url| url.len() <= 8192 && redactor.is_clean_text(url))
            .ok_or_else(|| denied("capture source URL is not approved"))?;
        let mut descriptor = CaptureDescriptor::new(kind, "", url);
        // Opaque renditions can encode secrets from styles, images and child frames,
        // even when the main document's markup itself is clean.
        let missing_resources = if kind == CaptureKind::Text {
            false
        } else {
            self.inspect_capture_resources(sink.as_ref()).await?
        };
        let mut dimensions = None;
        let mut completeness = CaptureCompleteness::Complete;
        let bytes = match spec {
            CaptureSpec::Mhtml { .. } => {
                descriptor.truncated = missing_resources;
                completeness = CaptureCompleteness::Unknown;
                let (_, session) = self.session_for(None)?;
                let mut snapshot = session
                    .send("Page.captureSnapshot", json!({"format": "mhtml"}))
                    .await?;
                snapshot
                    .get("data")
                    .and_then(Value::as_str)
                    .filter(|body| body.len() <= limit)
                    .ok_or_else(|| denied("MHTML capture is unavailable or exceeds byte limit"))?;
                descriptor.content_type = "multipart/related".to_owned();
                match snapshot.get_mut("data").map(Value::take) {
                    Some(Value::String(body)) => charge(body.into_bytes())?,
                    _ => return Err(denied("MHTML capture data is unavailable")),
                }
            }
            CaptureSpec::Screenshot { shot, max_pixels, .. } => {
                let (_, session) = self.session_for(None)?;
                let layout = session.send("Page.getLayoutMetrics", json!({})).await?;
                let viewport = shot
                    .viewport
                    .or_else(|| {
                        self.state
                            .lock()
                            .overrides
                            .emulation
                            .as_ref()
                            .and_then(|em| em.viewport)
                    })
                    .unwrap_or((self.ctl.config.viewport.width, self.ctl.config.viewport.height));
                let dpr = source
                    .get("dpr")
                    .and_then(Value::as_f64)
                    .ok_or_else(|| denied("capture device scale factor is unavailable"))?;
                let expected = shot_bounds(&shot, &layout, viewport, dpr, max_pixels)?;
                let expected_mime = if shot.quality.is_some() {
                    "image/jpeg"
                } else {
                    "image/png"
                };
                let full_page = shot.full_page;
                let viewport_override = shot.viewport.is_some();
                let PageOpResult::Bytes { bytes, content_type } =
                    self.page_op(PageOp::Screenshot(shot)).await?
                else {
                    return Err(denied("screenshot bytes are unavailable"));
                };
                if bytes.len() > limit || content_type != expected_mime {
                    return Err(denied("screenshot exceeds byte limit or has unexpected encoding"));
                }
                let (width, height) = image_dimensions(&bytes, content_type)?;
                if u64::from(width) * u64::from(height) > max_pixels {
                    return Err(denied("screenshot exceeds pixel limit"));
                }
                if full_page
                    && (f64::from(width) < expected.0.ceil() || f64::from(height) < expected.1.ceil())
                {
                    descriptor.truncated = true;
                    completeness = CaptureCompleteness::Clipped;
                }
                // Reflow under a temporary override means the original layout cannot prove
                // full coverage, even when the encoded size happens to match the old one.
                if full_page && viewport_override && !descriptor.truncated {
                    completeness = CaptureCompleteness::Unknown;
                }
                descriptor.content_type = content_type.to_owned();
                dimensions = Some((width, height));
                bytes
            }
            CaptureSpec::Pdf { spec, .. } => {
                let PageOpResult::Bytes { bytes, content_type } =
                    self.page_op(PageOp::PrintToPdf(spec)).await?
                else {
                    return Err(denied("PDF capture bytes are unavailable"));
                };
                if content_type != "application/pdf" || !bytes.starts_with(b"%PDF-") {
                    return Err(denied("PDF capture has unexpected encoding"));
                }
                descriptor.content_type = content_type.to_owned();
                completeness = CaptureCompleteness::Unknown;
                bytes
            }
            CaptureSpec::Text { .. } => {
                let PageOpResult::Json(text) = self.page_op(PageOp::EvaluateScript {
                    script: format!("(() => {{ const t = document.body ? document.body.innerText : ''; return {{ text: t.slice(0, {limit}), clipped: t.length > {limit} }}; }})()"),
                }).await? else {
                    return Err(denied("rendered text capture is unavailable"));
                };
                let mut body = text
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(|| denied("rendered text capture is unavailable"))?;
                let mut end = body.len().min(limit);
                while !body.is_char_boundary(end) {
                    end -= 1;
                }
                descriptor.truncated =
                    end < body.len() || text.get("clipped").and_then(Value::as_bool) == Some(true);
                body = &body[..end];
                if descriptor.truncated {
                    completeness = CaptureCompleteness::Clipped;
                }
                descriptor.content_type = "text/plain; charset=utf-8".to_owned();
                charge_copy(body.as_bytes())?
            }
            _ => return Err(denied("unsupported retained capture representation")),
        };
        if bytes.len() > limit {
            return Err(denied("capture exceeds byte limit"));
        }
        if self.current_epoch() != epoch {
            return Err(denied("capture document changed during privacy inspection"));
        }
        let PageOpResult::Json(after) = self
            .page_op(PageOp::EvaluateScript {
                script: SOURCE_PROBE.to_owned(),
            })
            .await?
        else {
            return Err(denied("capture source reinspection is unavailable"));
        };
        if after != source || self.current_epoch() != epoch {
            return Err(denied("capture source changed during privacy inspection"));
        }
        let approved = redactor
            .verify_binary(&bytes)
            .map_err(BrowserError::CapturePolicy)?;
        let count = u64::try_from(approved.as_inner().len())
            .map_err(|_| denied("capture size is not representable"))?;
        let artifact = sink
            .store(&descriptor, &approved)
            .await
            .map_err(BrowserError::CapturePolicy)?
            .ok_or_else(|| denied("capture retention policy refused bytes"))?;
        let mut result = CaptureArtifact::new(descriptor, artifact, count, completeness);
        if let Some((width, height)) = dimensions {
            result.width = Some(width);
            result.height = Some(height);
        }
        Ok(result)
    }

    async fn inspect_capture_resources(&self, sink: &dyn BrowserCaptureSink) -> Result<bool, BrowserError> {
        let (_, session) = self.session_for(None)?;
        let tree = session.send("Page.getResourceTree", json!({})).await?;
        let mut entries = Vec::new();
        let mut missing = resources(
            tree.get("frameTree")
                .ok_or_else(|| denied("capture resource tree is unavailable"))?,
            &mut entries,
        )?;
        let mut total = 0usize;
        for (frame, url) in entries {
            if url == "about:blank" {
                continue;
            }
            if url.len() > 8192 || !Redactor::new().is_clean_text(url) {
                return Err(denied("capture resource URL is not approved"));
            }
            approve_source(sink, url.as_bytes()).await?;
            let (owner, request_id) = self
                .state
                .lock()
                .resource_requests
                .get(frame)
                .and_then(|requests| requests.get(url))
                .cloned()
                .flatten()
                .ok_or_else(|| denied("capture original response identity is unavailable or ambiguous"))?;
            let resource = self
                .ctl
                .client
                .call(
                    "Network.getResponseBody",
                    Some(&owner),
                    json!({"requestId":request_id}),
                )
                .await?;
            let content = resource
                .get("body")
                .and_then(Value::as_str)
                .ok_or_else(|| denied("capture resource privacy inspection is unavailable"))?;
            let encoded = resource.get("base64Encoded").and_then(Value::as_bool) == Some(true);
            let bound = if encoded {
                SOURCE_BYTES.div_ceil(3) * 4
            } else {
                SOURCE_BYTES
            };
            if content.len() > bound {
                return Err(denied("capture resource exceeds privacy inspection bound"));
            }
            let decoded;
            let bytes = if encoded {
                decoded = STANDARD
                    .decode(content)
                    .map_err(|_| denied("capture resource encoding is unavailable"))?;
                decoded.as_slice()
            } else {
                content.as_bytes()
            };
            total = total
                .checked_add(bytes.len())
                .filter(|n| *n <= RESOURCE_BYTES)
                .ok_or_else(|| denied("capture resource privacy inspection total exceeded"))?;
            approve_source(sink, bytes).await?;
        }
        // Traffic is already a bounded projection. It may have been drained or evicted;
        // absence of failures therefore does not upgrade unknown to complete.
        missing |= self
            .state
            .lock()
            .traffic
            .iter()
            .any(|event| event.status.is_none_or(|status| status >= 400) || event.finished_at.is_none());
        Ok(missing)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn request_event(state: &mut super::super::state::State, frame: &str, id: &str, url: &str, kind: &str) {
        let event = crate::cdp::CdpEvent {
            session_id: Some("source-session".to_owned()),
            method: "Network.requestWillBeSent".to_owned(),
            params: json!({
                "requestId": id, "type": kind, "frameId": frame,
                "request": {"url": url, "method": "GET", "headers": {}}
            }),
            charge: None,
        };
        state.handle_event(
            &event,
            std::time::Instant::now(),
            crawlx_core::Timestamp::default(),
        );
    }

    fn source_state() -> super::super::state::State {
        use super::super::state::{State, Tab};
        let mut graph = crate::target::TabGraph::new(1);
        graph.add_home("source-tab", "about:blank");
        let mut state = State::new("source-context", graph, false);
        state.tabs.insert(
            "source-tab".to_owned(),
            Tab::new(
                "source-tab",
                "source-session",
                "source-frame",
                "about:blank",
                std::time::Instant::now(),
            ),
        );
        state
    }

    #[test]
    fn disabled_source_capture_does_not_populate_identity_maps() {
        let mut state = source_state();
        assert!(!state.capture_sources);
        request_event(
            &mut state,
            "source-frame",
            "default-request",
            "http://127.0.0.1/default",
            "Document",
        );
        assert!(state.resource_requests.is_empty());
    }

    #[test]
    fn original_response_identities_are_bounded_and_survive_traffic_drain() {
        let mut state = source_state();
        state.capture_sources = true;
        for index in 0..129 {
            request_event(
                &mut state,
                "source-frame",
                &index.to_string(),
                &format!("http://127.0.0.1/{index:03}"),
                "Image",
            );
        }
        assert_eq!(state.resource_requests["source-frame"].len(), 128);
        assert!(!state.resource_requests["source-frame"].contains_key("http://127.0.0.1/000"));
        state.traffic.clear();
        assert_eq!(
            state.resource_requests["source-frame"].get("http://127.0.0.1/128"),
            Some(&Some(("source-session".to_owned(), "128".to_owned()))),
        );
        request_event(
            &mut state,
            "source-frame",
            "128",
            "http://127.0.0.1/redirected",
            "Image",
        );
        assert!(!state.resource_requests["source-frame"].contains_key("http://127.0.0.1/128"));
        assert!(state.resource_requests["source-frame"].contains_key("http://127.0.0.1/redirected"));
        request_event(
            &mut state,
            "source-frame",
            &"x".repeat(1025),
            "http://127.0.0.1/001",
            "Image",
        );
        assert_eq!(
            state.resource_requests["source-frame"]["http://127.0.0.1/001"],
            None
        );
        request_event(
            &mut state,
            "source-frame",
            "oversized-url",
            &format!("http://127.0.0.1/{}", "x".repeat(8192)),
            "Image",
        );
        assert!(state
            .resource_requests
            .values()
            .flat_map(|requests| requests.keys())
            .all(|url| url.len() <= 8192));
    }

    #[test]
    fn source_response_identity_is_frame_scoped_and_duplicates_are_ambiguous() {
        let mut state = source_state();
        state.capture_sources = true;
        let url = "http://127.0.0.1/shared";
        request_event(&mut state, "source-frame", "first-frame", url, "Image");
        request_event(&mut state, "another-frame", "other-frame", url, "Image");
        assert_eq!(
            state.resource_requests["source-frame"][url],
            Some(("source-session".to_owned(), "first-frame".to_owned()))
        );
        assert_eq!(
            state.resource_requests["another-frame"][url],
            Some(("source-session".to_owned(), "other-frame".to_owned()))
        );
        request_event(&mut state, "source-frame", "first-frame", url, "Image");
        assert!(state.resource_requests["source-frame"][url].is_some());
        request_event(&mut state, "source-frame", "different-response", url, "Image");
        assert_eq!(state.resource_requests["source-frame"][url], None);
        request_event(&mut state, "source-frame", "different-response", url, "Image");
        assert_eq!(state.resource_requests["source-frame"][url], None);
        request_event(
            &mut state,
            "source-frame",
            "new-document",
            "http://127.0.0.1/new",
            "Document",
        );
        assert!(!state.resource_requests["source-frame"].contains_key(url));
        assert!(state.resource_requests["another-frame"][url].is_some());
    }

    #[test]
    fn hard_limits_reject_zero_and_transport_overflow() {
        assert!(byte_limit(0).is_err());
        assert!(byte_limit(MAX_BYTES + 1).is_err());
        assert_eq!(byte_limit(MAX_BYTES).unwrap(), 32 * 1024 * 1024);
    }

    #[test]
    fn png_and_jpeg_dimensions_are_encoding_facts() {
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&640u32.to_be_bytes());
        png.extend_from_slice(&320u32.to_be_bytes());
        assert_eq!(image_dimensions(&png, "image/png").unwrap(), (640, 320));
        assert!(image_dimensions(&png, "image/jpeg").is_err());
        let jpeg = [0xff, 0xd8, 0xff, 0xc0, 0, 7, 8, 0, 100, 0, 200];
        assert_eq!(image_dimensions(&jpeg, "image/jpeg").unwrap(), (200, 100));
        assert!(image_dimensions(&jpeg[..8], "image/jpeg").is_err());
    }

    #[test]
    fn full_page_bounds_keep_unclamped_extent_for_clipping() {
        let layout = json!({"cssContentSize":{"width": 800,"height":20000}});
        let shot = ShotSpec {
            full_page: true,
            ..ShotSpec::default()
        };
        assert_eq!(
            shot_bounds(&shot, &layout, (800, 600), 2.0, 100_000_000).unwrap(),
            (1600.0, 40000.0)
        );
        assert!(shot_bounds(&shot, &layout, (800, 600), 2.0, 1_000).is_err());
        assert!(shot_bounds(&shot, &layout, (800, 600), f64::NAN, 100_000_000).is_err());
    }

    #[test]
    fn failed_resources_cannot_claim_complete() {
        let tree = json!({"frame":{"id":"main","url":"http://127.0.0.1/"},"resources":[
            {"url":"http://127.0.0.1/picture","failed":true},
            {"url":"http://127.0.0.1/style","failed":false}
        ]});
        let mut entries = Vec::new();
        assert!(resources(&tree, &mut entries).unwrap());
        assert_eq!(entries.len(), 2);
        let mut full = vec![("frame", "url"); RESOURCE_COUNT];
        assert!(resources(&tree, &mut full).is_err());
    }
}
