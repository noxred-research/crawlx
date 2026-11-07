//! Bounded, cancellation-aware CapSolver transport for explicit CAPTCHA opt-in.
//!
//! Task names and token fields follow Katana's MIT-licensed CapSolver adapter:
//! <https://github.com/projectdiscovery/katana/blob/main/pkg/engine/headless/captcha/capsolver/capsolver.go>.
//! No provider text or underlying HTTP errors cross the secret boundary.

use crawlx_core::captcha::{CaptchaChallenge, CaptchaConfig, CaptchaError, CaptchaKind, CaptchaProvider};
use crawlx_core::secret::SecretOr;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;

const MAX_RESPONSE_BYTES: usize = 65_536;
const MAX_TOKEN_BYTES: usize = 16_384;

/// CapSolver client. Debug never exposes keys, endpoints, task IDs, or tokens.
pub struct CapsolverClient {
    http: reqwest::Client,
    create_url: Url,
    result_url: Url,
    key: SecretOr<String>,
    timeout: Duration,
    poll_interval: Duration,
}

impl std::fmt::Debug for CapsolverClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapsolverClient").finish_non_exhaustive()
    }
}

impl CapsolverClient {
    /// Build a client with redirects, HTTP retries, and ambient proxies disabled.
    /// Plain key inputs are promoted to secrets before storage.
    ///
    /// # Errors
    /// Returns [`CaptchaError::Configuration`] for invalid settings or empty keys,
    /// or [`CaptchaError::Transport`] if the HTTP client cannot be initialized.
    pub fn new(config: &CaptchaConfig, key: SecretOr<String>) -> Result<Self, CaptchaError> {
        config.validate()?;
        if config.provider != CaptchaProvider::Capsolver || key.expose().trim().is_empty() {
            return Err(CaptchaError::Configuration);
        }
        let key = match key {
            SecretOr::Secret(_) => key,
            SecretOr::Plain(value) => SecretOr::secret(value),
        };
        let mut base = config.endpoint.clone();
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        let create_url = base.join("createTask").map_err(|_| CaptchaError::Configuration)?;
        let result_url = base
            .join("getTaskResult")
            .map_err(|_| CaptchaError::Configuration)?;
        let timeout = Duration::from_secs(config.timeout_seconds);
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .timeout(timeout)
            .build()
            .map_err(|_| CaptchaError::Transport)?;
        Ok(Self {
            http,
            create_url,
            result_url,
            key,
            timeout,
            poll_interval: Duration::from_millis(config.poll_interval_ms),
        })
    }

    /// Create exactly one paid task and poll until its token is ready.
    /// The deadline includes creation, every poll, and complete response bodies.
    /// An ambiguous create failure ends the solve without retrying the task.
    ///
    /// # Errors
    /// Returns bounded, secret-free [`CaptchaError`] variants for invalid challenges,
    /// cancellation, timeout, transport/service failures, or malformed responses.
    pub async fn solve(
        &self,
        challenge: &CaptchaChallenge,
        cancel: &CancellationToken,
    ) -> Result<SecretOr<String>, CaptchaError> {
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(CaptchaError::Cancelled),
            result = tokio::time::timeout(self.timeout, self.solve_inner(challenge)) => {
                result.map_err(|_| CaptchaError::Timeout)?
            }
        }
    }

    async fn solve_inner(&self, challenge: &CaptchaChallenge) -> Result<SecretOr<String>, CaptchaError> {
        let task = Task::from_challenge(challenge)?;
        let created: Created = self
            .post(
                &self.create_url,
                &Create {
                    client_key: self.key.expose(),
                    task,
                },
            )
            .await?;
        if created.error_id != 0 {
            return Err(CaptchaError::Service);
        }
        if created
            .status
            .as_deref()
            .is_some_and(|status| status != "processing" && status != "idle")
        {
            return Err(CaptchaError::InvalidResponse);
        }
        let task_id = created
            .task_id
            .filter(|id| {
                !id.is_empty()
                    && id.len() <= 256
                    && !id.chars().any(char::is_whitespace)
                    && !id.chars().any(char::is_control)
            })
            .ok_or(CaptchaError::InvalidResponse)?;
        loop {
            tokio::time::sleep(self.poll_interval).await;
            let result: Polled = self
                .post(
                    &self.result_url,
                    &Poll {
                        client_key: self.key.expose(),
                        task_id: &task_id,
                    },
                )
                .await?;
            if result.error_id != 0 {
                return Err(CaptchaError::Service);
            }
            match result.status.as_deref() {
                Some("processing" | "idle") => continue,
                Some("ready") => {
                    let solution = result.solution.ok_or(CaptchaError::InvalidResponse)?;
                    let token = if challenge.kind == CaptchaKind::Turnstile {
                        solution.token
                    } else {
                        solution.g_recaptcha_response
                    }
                    .filter(|token| !token.trim().is_empty() && token.len() <= MAX_TOKEN_BYTES)
                    .ok_or(CaptchaError::InvalidResponse)?;
                    return Ok(SecretOr::secret(token));
                }
                _ => return Err(CaptchaError::InvalidResponse),
            }
        }
    }

    async fn post<T: Serialize + ?Sized, R: serde::de::DeserializeOwned>(
        &self,
        url: &Url,
        request: &T,
    ) -> Result<R, CaptchaError> {
        let mut response = self
            .http
            .post(url.clone())
            .json(request)
            .send()
            .await
            .map_err(transport_error)?;
        if !response.status().is_success() {
            return Err(CaptchaError::Service);
        }
        if response.content_length().is_some_and(|length| length > 65_536) {
            return Err(CaptchaError::InvalidResponse);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
            if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(body.len()) {
                return Err(CaptchaError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| CaptchaError::InvalidResponse)
    }
}

fn transport_error(error: reqwest::Error) -> CaptchaError {
    if error.is_timeout() {
        CaptchaError::Timeout
    } else {
        CaptchaError::Transport
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Create<'a> {
    client_key: &'a str,
    task: Task<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Poll<'a> {
    client_key: &'a str,
    task_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Task<'a> {
    #[serde(rename = "type")]
    task_type: &'static str,
    #[serde(rename = "websiteURL")]
    website_url: &'a str,
    website_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enterprise_payload: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Metadata<'a>>,
}

#[derive(Serialize)]
struct Metadata<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cdata: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chlpagedata: Option<&'a str>,
}

impl<'a> Task<'a> {
    fn from_challenge(challenge: &'a CaptchaChallenge) -> Result<Self, CaptchaError> {
        let page = Url::parse(&challenge.website_url).map_err(|_| CaptchaError::UnsupportedChallenge)?;
        if !matches!(page.scheme(), "http" | "https")
            || page.host().is_none()
            || challenge.site_key.trim().is_empty()
        {
            return Err(CaptchaError::UnsupportedChallenge);
        }
        let task_type = match challenge.kind {
            CaptchaKind::RecaptchaV2 => "ReCaptchaV2TaskProxyLess",
            CaptchaKind::RecaptchaV3 => "ReCaptchaV3TaskProxyLess",
            CaptchaKind::RecaptchaV2Enterprise => "ReCaptchaV2EnterpriseTaskProxyLess",
            CaptchaKind::RecaptchaV3Enterprise => "ReCaptchaV3EnterpriseTaskProxyLess",
            CaptchaKind::Turnstile => "AntiTurnstileTaskProxyLess",
            CaptchaKind::Hcaptcha => "HCaptchaTaskProxyLess",
            _ => return Err(CaptchaError::UnsupportedChallenge),
        };
        let page_action = matches!(
            challenge.kind,
            CaptchaKind::RecaptchaV3 | CaptchaKind::RecaptchaV3Enterprise
        )
        .then_some(challenge.action.as_deref())
        .flatten();
        let enterprise_payload = matches!(
            challenge.kind,
            CaptchaKind::RecaptchaV2Enterprise | CaptchaKind::RecaptchaV3Enterprise
        )
        .then_some(challenge.enterprise_payload.as_ref())
        .flatten();
        if enterprise_payload.is_some_and(|payload| !payload.is_object()) {
            return Err(CaptchaError::UnsupportedChallenge);
        }
        let metadata = (challenge.kind == CaptchaKind::Turnstile).then_some(Metadata {
            action: challenge.action.as_deref(),
            cdata: challenge.data.as_deref(),
            chlpagedata: challenge.pagedata.as_deref(),
        });
        Ok(Self {
            task_type,
            website_url: &challenge.website_url,
            website_key: &challenge.site_key,
            page_action,
            enterprise_payload,
            metadata,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Created {
    error_id: u64,
    task_id: Option<String>,
    status: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Polled {
    error_id: u64,
    status: Option<String>,
    solution: Option<Solution>,
}

#[derive(Deserialize)]
struct Solution {
    #[serde(rename = "gRecaptchaResponse")]
    g_recaptcha_response: Option<String>,
    token: Option<String>,
}
