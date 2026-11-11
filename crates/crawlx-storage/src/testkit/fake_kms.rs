//! Explicit loopback KMS protocol fixture, available only through `fake-kms`.
//!
//! This is not a production provider. It implements the cloud KMS JSON wire operations
//! `GenerateDataKey` and `Decrypt` using real AES-256-GCM wrapping and random data
//! keys. Each fixture owns a fresh OS-random root; retain one fixture across
//! producer/recovery subprocesses. It accepts authored test credentials without
//! verifying request signatures and binds only to loopback. Never route production
//! cloud traffic here. No fixture endpoint is selected automatically.

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback key-service fixture exposes only its private HTTP protocol boundary"
)]
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use parking_lot::Mutex;
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    rand::{SecureRandom, SystemRandom},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, io, sync::Arc};
use zeroize::Zeroizing;

const KEY_ID: &str = "arn:aws:kms:us-east-1:111122223333:key/crawlx-loopback-fixture"; // wire-compat: key ARN shape

struct Service {
    root: Zeroizing<[u8; 32]>,
    observations: Mutex<Observations>,
}

#[derive(Default)]
struct Observations {
    generated: usize,
    decrypted: usize,
    contexts: Vec<BTreeMap<String, String>>,
    last_data_key: Zeroizing<Vec<u8>>,
}

/// Test-only loopback cloud KMS protocol server with independent private key custody.
#[non_exhaustive]
pub struct LoopbackKms {
    endpoint: String,
    state: Arc<Service>,
    task: tokio::task::JoinHandle<()>,
}

impl LoopbackKms {
    /// Start one loopback fixture. Keep it alive through producer and recovery processes.
    ///
    /// # Errors
    /// Returns an I/O error for unavailable entropy or a failed loopback bind.
    pub async fn start() -> io::Result<Self> {
        let mut root = Zeroizing::new([0; 32]);
        SystemRandom::new()
            .fill(root.as_mut())
            .map_err(|_| io::Error::other("loopback kms entropy unavailable"))?;
        let state = Arc::new(Service {
            root,
            observations: Mutex::new(Observations::default()),
        });
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let router = Router::new()
            .route("/", post(operation))
            .layer(DefaultBodyLimit::max(128 * 1024))
            .with_state(Arc::clone(&state));
        let task = tokio::spawn(async move {
            // Test clients observe server errors through their real SDK requests.
            let _ = axum::serve(listener, router).await;
        });
        Ok(Self {
            endpoint,
            state,
            task,
        })
    }

    /// Endpoint for the child-only SDK KMS endpoint-override environment variable.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Explicit fixture-only KMS key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        KEY_ID
    }

    /// Successful `(GenerateDataKey, Decrypt)` operation counts.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        let observed = self.state.observations.lock();
        (observed.generated, observed.decrypted)
    }

    /// Accepted ownership contexts, bounded to the most recent 64 calls.
    #[must_use]
    pub fn contexts(&self) -> Vec<BTreeMap<String, String>> {
        self.state.observations.lock().contexts.clone()
    }

    /// Whether an artifact contains raw fixture root or most recently generated data-key bytes.
    ///
    /// Does not export key bytes. Used to catch accidental cleartext serialization.
    #[must_use]
    pub fn contains_key_material(&self, artifact: &[u8]) -> bool {
        let observed = self.state.observations.lock();
        artifact.windows(32).any(|window| {
            window == self.state.root.as_ref()
                || (!observed.last_data_key.is_empty() && window == observed.last_data_key.as_slice())
        })
    }
}

impl Drop for LoopbackKms {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn operation(
    State(service): State<Arc<Service>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // The KMS JSON protocol uses application/x-amz-json-1.1, not Axum's JSON media type.
    let result = serde_json::from_slice::<Value>(&body)
        .map_err(|_| ())
        .and_then(|request| execute(&service, &headers, &request));
    match result {
        Ok(response) => (
            StatusCode::OK,
            [("content-type", "application/x-amz-json-1.1")],
            Json(response),
        )
            .into_response(),
        Err(()) => (
            StatusCode::BAD_REQUEST,
            [
                ("content-type", "application/x-amz-json-1.1"),
                ("x-amzn-errortype", "InvalidCiphertextException"),
            ],
            Json(json!({
                "__type": "InvalidCiphertextException",
                // Deliberately sensitive sentinel: provider error formatting must redact this.
                "message": "fixture-secret-response-body https://sensitive-endpoint.invalid"
            })),
        )
            .into_response(),
    }
}

fn execute(service: &Service, headers: &HeaderMap, request: &Value) -> Result<Value, ()> {
    if request.get("KeyId").and_then(Value::as_str) != Some(KEY_ID) {
        return Err(());
    }
    let context: BTreeMap<String, String> =
        serde_json::from_value(request.get("EncryptionContext").ok_or(())?.clone()).map_err(|_| ())?;
    let checkpoint_context = context.len() == 5
        && context.get("domain").map(String::as_str) == Some("crawlx/checkpoint/v1")
        && ["tenant", "run", "session", "checkpoint"]
            .iter()
            .all(|key| context.get(*key).is_some_and(|value| !value.is_empty()));
    let artifact_context = context.len() == 4
        && context.get("domain").map(String::as_str) == Some("crawlx/artifact-key/v1")
        && ["tenant", "run", "artifact"]
            .iter()
            .all(|key| context.get(*key).is_some_and(|value| !value.is_empty()));
    if !checkpoint_context && !artifact_context {
        return Err(());
    }
    let aad = serde_json::to_vec(&context).map_err(|_| ())?;
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, service.root.as_ref()).map_err(|_| ())?);
    let target = headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .ok_or(())?;
    let (response, generated, data_key) = match target {
        "TrentService.GenerateDataKey" => {
            if request.get("KeySpec").and_then(Value::as_str) != Some("AES_256") {
                return Err(());
            }
            let mut data_key = Zeroizing::new(vec![0; 32]);
            let mut nonce = [0; 12];
            SystemRandom::new().fill(&mut data_key).map_err(|_| ())?;
            SystemRandom::new().fill(&mut nonce).map_err(|_| ())?;
            // Reserve before copying secret material so plaintext never gets reallocated.
            let mut wrapped = Zeroizing::new(Vec::with_capacity(48));
            wrapped.extend_from_slice(&data_key);
            key.seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut *wrapped,
            )
            .map_err(|_| ())?;
            let mut blob = Vec::with_capacity(60);
            blob.extend_from_slice(&nonce);
            blob.extend_from_slice(&wrapped);
            (
                json!({ "KeyId": KEY_ID, "Plaintext": STANDARD.encode(&data_key), "CiphertextBlob": STANDARD.encode(&blob) }),
                true,
                data_key,
            )
        }
        "TrentService.Decrypt" => {
            let encoded = request.get("CiphertextBlob").and_then(Value::as_str).ok_or(())?;
            if encoded.len() > 128 {
                return Err(());
            }
            let blob = STANDARD.decode(encoded).map_err(|_| ())?;
            if blob.len() != 60 {
                return Err(());
            }
            let nonce: [u8; 12] = blob[..12].try_into().map_err(|_| ())?;
            let mut data_key = Zeroizing::new(blob[12..].to_vec());
            let len = key
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    &mut data_key,
                )
                .map_err(|_| ())?
                .len();
            data_key.truncate(len);
            (
                json!({ "KeyId": KEY_ID, "Plaintext": STANDARD.encode(&data_key), "EncryptionAlgorithm": "SYMMETRIC_DEFAULT" }),
                false,
                data_key,
            )
        }
        _ => return Err(()),
    };
    let mut observed = service.observations.lock();
    if generated {
        observed.generated = observed.generated.saturating_add(1);
        observed.last_data_key = data_key;
    } else {
        observed.decrypted = observed.decrypted.saturating_add(1);
    }
    if observed.contexts.len() == 64 {
        observed.contexts.remove(0);
    }
    observed.contexts.push(context);
    Ok(response)
}
