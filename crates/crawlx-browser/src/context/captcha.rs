//! Opt-in widget discovery and secret token delivery. Provider calls require an admitted action.

use super::CdpContext;
use crawlx_core::browser::{BrowserContext as _, BrowserError};
use crawlx_core::captcha::{CaptchaChallenge, CaptchaError, CaptchaKind};
use serde::Deserialize;
use serde_json::{json, Value};

pub(super) const INIT: &str = include_str!("captcha.js");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Widget {
    id: u64,
    kind: String,
    site_key: String,
    website_url: String,
    action: Option<String>,
    data: Option<String>,
    pagedata: Option<String>,
    enterprise_payload: Option<Value>,
}

impl Widget {
    fn challenge(&self) -> Result<CaptchaChallenge, BrowserError> {
        let kind = match self.kind.as_str() {
            "recaptcha_v2" => CaptchaKind::RecaptchaV2,
            "recaptcha_v3" => CaptchaKind::RecaptchaV3,
            "recaptcha_v2_enterprise" => CaptchaKind::RecaptchaV2Enterprise,
            "recaptcha_v3_enterprise" => CaptchaKind::RecaptchaV3Enterprise,
            "turnstile" => CaptchaKind::Turnstile,
            "hcaptcha" => CaptchaKind::Hcaptcha,
            _ => return Err(CaptchaError::UnsupportedChallenge.into()),
        };
        let mut challenge = CaptchaChallenge::new(kind, self.website_url.clone(), self.site_key.clone());
        challenge.action.clone_from(&self.action);
        challenge.enterprise_payload.clone_from(&self.enterprise_payload);
        challenge.data.clone_from(&self.data);
        challenge.pagedata.clone_from(&self.pagedata);
        Ok(challenge)
    }
}

impl CdpContext {
    pub(super) fn mask_captcha_error(&self, mut error: BrowserError) -> BrowserError {
        if self.ctl.config.captcha.is_none() {
            return error;
        }
        let text = match &mut error {
            BrowserError::Launch(text)
            | BrowserError::Transport(text)
            | BrowserError::Navigation(text)
            | BrowserError::EgressDenied(text)
            | BrowserError::Unsupported(text)
            | BrowserError::Script(text)
            | BrowserError::Io(text) => Some(text),
            BrowserError::Protocol { message, .. } => Some(message),
            BrowserError::RobotsBlocked { url, .. } => Some(url),
            _ => None,
        };
        if let Some(text) = text {
            *text = self
                .ctl
                .config
                .captcha_secrets
                .redact(text)
                .unwrap_or_else(|_| "[REDACTED]".to_owned());
        }
        error
    }

    pub(super) fn mask_captcha<T>(&self, data: T) -> Result<T, BrowserError>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        if self.ctl.config.captcha.is_none() || !self.ctl.config.captcha_secrets.has_values()? {
            return Ok(data);
        }
        let mut json = serde_json::to_value(data).map_err(|_| CaptchaError::Delivery)?;
        self.ctl.config.captcha_secrets.redact_json(&mut json)?;
        serde_json::from_value(json).map_err(|_| CaptchaError::Delivery.into())
    }

    pub(super) fn mask_captcha_page_result(
        &self,
        mut result: crawlx_core::page_op::PageOpResult,
    ) -> Result<crawlx_core::page_op::PageOpResult, BrowserError> {
        use crawlx_core::page_op::PageOpResult;
        if self.ctl.config.captcha.is_none() {
            return Ok(result);
        }
        let secrets = &self.ctl.config.captcha_secrets;
        match &mut result {
            PageOpResult::Json(value) => secrets.redact_json(value)?,
            PageOpResult::VirtualRows(window) => {
                for row in &mut window.rows {
                    *row = secrets.redact(row)?;
                }
            }
            PageOpResult::Html { html, url } => {
                *html = secrets.redact(html)?;
                *url = secrets.redact(url)?;
            }
            PageOpResult::Response {
                headers,
                content_type,
                ..
            } => {
                *headers = self.mask_captcha(std::mem::take(headers))?;
                *content_type = self.mask_captcha(content_type.take())?;
            }
            _ => {}
        }
        Ok(result)
    }

    pub(super) fn mask_captcha_observation(
        &self,
        mut bundle: crawlx_core::observation::ObservationBundle,
    ) -> Result<crawlx_core::observation::ObservationBundle, BrowserError> {
        let secrets = &self.ctl.config.captcha_secrets;
        if !secrets.has_values()? {
            return Ok(bundle);
        }
        bundle.url = self.mask_captcha(bundle.url)?;
        bundle.route = self.mask_captcha(bundle.route)?;
        for frame in &mut bundle.frames {
            frame.url = secrets.redact(&frame.url)?;
        }
        for tab in &mut bundle.tabs {
            tab.url = secrets.redact(&tab.url)?;
        }
        for node in &mut bundle.ax.nodes {
            node.role = secrets.redact(&node.role)?;
            node.name = self.mask_captcha(node.name.take())?;
            node.description = self.mask_captcha(node.description.take())?;
            node.value = self.mask_captcha(node.value.take())?;
            node.checked = self.mask_captcha(node.checked.take())?;
            node.properties = self.mask_captcha(std::mem::take(&mut node.properties))?;
        }
        bundle.dom_supplement.nodes = self.mask_captcha(bundle.dom_supplement.nodes)?;
        bundle.network = self.mask_captcha(bundle.network)?;
        bundle.dialogs = self.mask_captcha(bundle.dialogs)?;
        bundle.html = self.mask_captcha(bundle.html)?;
        bundle.title = self.mask_captcha(bundle.title)?;
        bundle.discovered_urls = self.mask_captcha(bundle.discovered_urls)?;
        Ok(bundle)
    }

    async fn captcha_widgets(&self) -> Result<Vec<Widget>, BrowserError> {
        if self.ctl.config.captcha.is_none() {
            return Ok(Vec::new());
        }
        let (_, session) = self.session_for(None)?;
        let response = session
            .send(
                "Runtime.evaluate",
                json!({
                    "expression": "window.__crawlxCaptcha ? window.__crawlxCaptcha.scan() : []",
                    "returnByValue": true,
                    "silent": true,
                }),
            )
            .await
            .map_err(|_| CaptchaError::Delivery)?;
        if response.get("exceptionDetails").is_some() {
            return Err(CaptchaError::Delivery.into());
        }
        let value = response
            .pointer("/result/value")
            .cloned()
            .ok_or(CaptchaError::Delivery)?;
        let widgets: Vec<Widget> =
            serde_json::from_value(value).map_err(|_| CaptchaError::UnsupportedChallenge)?;
        if widgets.len() > 32 {
            return Err(CaptchaError::UnsupportedChallenge.into());
        }
        for widget in &widgets {
            let _ = widget.challenge()?;
        }
        Ok(widgets)
    }

    pub(super) async fn has_captcha(&self) -> Result<bool, BrowserError> {
        Ok(!self.captcha_widgets().await?.is_empty())
    }

    pub(super) async fn solve_captcha(&mut self) -> Result<(), BrowserError> {
        let credentials = self
            .ctl
            .config
            .captcha
            .as_ref()
            .ok_or(CaptchaError::Configuration)?;
        let client = crate::captcha::CapsolverClient::new(&credentials.config, credentials.key.clone())?;
        let widgets = self.captcha_widgets().await?;
        if widgets.is_empty() {
            return Err(CaptchaError::UnsupportedChallenge.into());
        }
        let (_, session) = self.session_for(None)?;
        for widget in widgets {
            let challenge = widget.challenge()?;
            let claimed = session.send("Runtime.evaluate", json!({
                "expression": format!("!!window.__crawlxCaptcha && window.__crawlxCaptcha.claim({})", widget.id),
                "returnByValue": true,
                "silent": true,
            })).await.map_err(|_| CaptchaError::Delivery)?;
            if claimed.pointer("/result/value").and_then(Value::as_bool) != Some(true) {
                return Err(CaptchaError::Delivery.into());
            }
            // The document can navigate while a billed task runs: never deliver to a new page.
            let epoch = self.current_epoch();
            let token = client.solve(&challenge, &self.ctl.config.captcha_cancel).await?;
            // Run-wide first: a token must be visible to every worker's publication check
            // before any page can reflect it. A failure never authorizes delivery.
            if let Some(registrar) = &self.ctl.config.secret_registrar {
                registrar
                    .register(&token)
                    .await
                    .map_err(|_| CaptchaError::Delivery)?;
            }
            self.ctl.config.captcha_secrets.register(token.clone())?;
            if self.current_epoch().document_seq != epoch.document_seq
                || self.current_epoch().navigation_seq != epoch.navigation_seq
            {
                return Err(CaptchaError::Delivery.into());
            }
            let object_id = self.captcha_main_world(&session).await?;
            let delivery = session.send(
                "Runtime.callFunctionOn",
                json!({
                    "functionDeclaration": super::synthetic::CAPTCHA_DELIVERY,
                    "arguments": [{"value": widget.id}, {"value": token.expose()}],
                    "objectId": object_id,
                    "awaitPromise": true,
                    "returnByValue": true,
                    "silent": true,
                }),
            );
            let delivered = tokio::select! {
                biased;
                () = self.ctl.config.captcha_cancel.cancelled() => return Err(CaptchaError::Cancelled.into()),
                response = tokio::time::timeout(std::time::Duration::from_secs(10), delivery) => {
                    response.map_err(|_| CaptchaError::Timeout)?.map_err(|_| CaptchaError::Delivery)?
                }
            };
            let _ = session
                .send("Runtime.releaseObject", json!({"objectId": object_id}))
                .await;
            if delivered.get("exceptionDetails").is_some()
                || delivered.pointer("/result/value").and_then(Value::as_bool) != Some(true)
            {
                return Err(CaptchaError::Delivery.into());
            }
        }
        Ok(())
    }

    async fn captcha_main_world(&self, session: &crate::cdp::CdpSession) -> Result<String, BrowserError> {
        // A main-world object supplies an execution context without relying on Runtime.enable.
        let object = session
            .send("Runtime.evaluate", json!({"expression":"window", "silent":true}))
            .await
            .map_err(|_| CaptchaError::Delivery)?;
        let object_id = object
            .pointer("/result/objectId")
            .and_then(Value::as_str)
            .ok_or(CaptchaError::Delivery)?;
        Ok(object_id.to_owned())
    }
}
