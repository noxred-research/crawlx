//! `crawlx authz`: authorization records.
//!
//! * `create`, `show`, `revoke`, `verify` call the lifecycle routes of a crawlx API
//!   (`/v1/authorizations`, scopes `authorizations:write` and `authorizations:read`). A `2xx`
//!   answer is printed as pretty JSON on stdout; a `4xx` or `5xx` answer exits `1` with the API's
//!   error envelope on stderr. The bearer key travels only in the `Authorization` header and is
//!   never printed.
//! * `sign` and `challenge` work offline. `sign` fills the `operator_signature` proof of a record
//!   with an operator key; `challenge` prints what the operator must publish for a `dns_txt` or
//!   `well_known_file` proof.

use anyhow::{anyhow, bail, Context as _};
use clap::{Args, Subcommand};
use crawlx_core::AuthorizationRecordId;
use crawlx_policy::attestation::OperatorKeys;
use crawlx_policy::authorization::{origin_string, DNS_CHALLENGE_LABEL, WELL_KNOWN_CHALLENGE_PATH};
use crawlx_policy::{AuthorizationRecord, OwnershipProof};
use reqwest::Method;
use serde_json::{json, Value};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use url::Url;

/// API used when neither a flag nor `CRAWLX_API_URL` names one.
const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";
/// Timeout of every request to the API.
const TIMEOUT: Duration = Duration::from_secs(30);
/// Largest response body read; a record with its verification is a few kilobytes.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Longest non-JSON error body quoted on stderr, in characters.
const MAX_QUOTED_CHARS: usize = 2048;

/// Which API to call and how to authenticate.
#[derive(Args, Clone)]
pub struct ApiTarget {
    /// Base URL of the crawlx API.
    #[arg(
        long,
        env = "CRAWLX_API_URL",
        default_value = DEFAULT_API_URL,
        value_name = "URL"
    )]
    pub api_url: String,
    /// Bearer API key (scope `authorizations:write` to create, revoke and verify, `authorizations:read`
    /// to show). Prefer the environment variable: command-line arguments are visible to other
    /// users. Never printed.
    #[arg(long, env = "CRAWLX_API_KEY", hide_env_values = true, value_name = "KEY")]
    pub api_key: Option<String>,
}

impl fmt::Debug for ApiTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiTarget")
            .field("api_url", &shown(&self.api_url))
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Arguments of `crawlx authz`.
#[derive(Args, Debug)]
pub struct AuthzArgs {
    /// What to do with a record.
    #[command(subcommand)]
    pub command: AuthzCommand,
}

/// `crawlx authz` subcommands.
#[derive(Subcommand, Debug)]
pub enum AuthzCommand {
    /// Register a record (`POST /v1/authorizations`): the API validates it, checks the ownership
    /// proof it names (DNS TXT, well-known file or operator signature) and stores it, verified.
    /// The record is immutable once stored; an amendment is a new record with a new id.
    Create(CreateArgs),
    /// Print a stored record with its status and verification (`GET /v1/authorizations/{id}`).
    Show(ShowArgs),
    /// Revoke a record (`POST /v1/authorizations/{id}/revoke`): runs under it stop at once.
    Revoke(RevokeArgs),
    /// Re-check the ownership proof of a stored record (`POST /v1/authorizations/{id}/verify`).
    Verify(VerifyArgs),
    /// Offline: sign a record with an operator key (`ownership.kind = operator_signature`).
    Sign(SignArgs),
    /// Offline: print what to publish for a `dns_txt` or `well_known_file` ownership proof.
    Challenge(ChallengeArgs),
}

/// Arguments of `crawlx authz create`.
#[derive(Args, Debug)]
pub struct CreateArgs {
    /// The record (JSON). `tenant` may be left out: the API fills in the key's tenant. `id` and
    /// `ownership` are required; `verifiedAt`, `revokedAt` and `revokedReason` are refused.
    #[arg(long, value_name = "FILE")]
    pub record: PathBuf,
    /// The API to call.
    #[command(flatten)]
    pub api: ApiTarget,
}

/// Arguments of `crawlx authz show`.
#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Record id (UUID).
    #[arg(value_name = "ID")]
    pub id: AuthorizationRecordId,
    /// The API to call.
    #[command(flatten)]
    pub api: ApiTarget,
}

/// Arguments of `crawlx authz revoke`.
#[derive(Args, Debug)]
pub struct RevokeArgs {
    /// Record id (UUID).
    #[arg(value_name = "ID")]
    pub id: AuthorizationRecordId,
    /// Why the record is revoked; stored with the revocation.
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
    /// The API to call.
    #[command(flatten)]
    pub api: ApiTarget,
}

/// Arguments of `crawlx authz verify`.
#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Record id (UUID).
    #[arg(value_name = "ID")]
    pub id: AuthorizationRecordId,
    /// The API to call.
    #[command(flatten)]
    pub api: ApiTarget,
}

/// Arguments of `crawlx authz sign`.
#[derive(Args, Debug)]
pub struct SignArgs {
    /// The complete record (JSON), `tenant` included: the signature covers every field. Its
    /// `ownership` is absent or already `operator_signature`; the signature value is replaced.
    #[arg(long, value_name = "FILE")]
    pub record: PathBuf,
    /// Which operator key signs; the API must hold the same key (`CRAWLX_AUTHZ_OPERATOR_KEYS_FILE`).
    #[arg(long, value_name = "ID")]
    pub key_id: String,
    /// The operator keys file (`key_id hex-key` per line, the format of
    /// `CRAWLX_AUTHZ_OPERATOR_KEYS_FILE`), or a file holding one hex key used under `--key-id`.
    #[arg(long, value_name = "FILE")]
    pub key_file: PathBuf,
    /// Write the signed record here instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

/// Arguments of `crawlx authz challenge`.
#[derive(Args, Debug)]
pub struct ChallengeArgs {
    /// The record (JSON); only `id`, `origins` and `urlPrefixes` are read.
    #[arg(long, value_name = "FILE")]
    pub record: PathBuf,
    /// Print JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

pub(crate) async fn run(args: AuthzArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    match args.command {
        AuthzCommand::Create(a) => {
            let body = read_json(&a.record)?;
            call(&a.api, Method::POST, &[], Some(body), out).await
        }
        AuthzCommand::Show(a) => call(&a.api, Method::GET, &[&a.id.to_string()], None, out).await,
        AuthzCommand::Revoke(a) => {
            let body = a
                .reason
                .as_ref()
                .map_or_else(|| json!({}), |r| json!({ "reason": r }));
            call(
                &a.api,
                Method::POST,
                &[&a.id.to_string(), "revoke"],
                Some(body),
                out,
            )
            .await
        }
        AuthzCommand::Verify(a) => {
            call(
                &a.api,
                Method::POST,
                &[&a.id.to_string(), "verify"],
                Some(json!({})),
                out,
            )
            .await
        }
        AuthzCommand::Sign(a) => sign(&a, out),
        AuthzCommand::Challenge(a) => challenge(&a, out),
    }
}

/// The URL as printed in messages: no credentials, no query, no fragment.
fn shown(url: &str) -> String {
    match Url::parse(url.trim()) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => "<not a URL>".to_owned(),
    }
}

/// The error and its `source` chain (reqwest keeps the cause in the chain).
fn chain(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        text.push_str(": ");
        text.push_str(&s.to_string());
        source = s.source();
    }
    text
}

fn read_json(path: &Path) -> anyhow::Result<Value> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {} as JSON", path.display()))
}

/// The record as the policy crate reads it (unknown and missing fields are errors).
fn read_record(path: &Path) -> anyhow::Result<AuthorizationRecord> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing authorization record {}", path.display()))
}

/// One request to `/v1/authorizations[/…]`; prints the answer.
#[allow(
    clippy::disallowed_types,
    reason = "authorization API client builds the raw reqwest client"
)]
async fn call(
    target: &ApiTarget,
    method: Method,
    tail: &[&str],
    body: Option<Value>,
    out: &mut dyn Write,
) -> anyhow::Result<ExitCode> {
    let mut url =
        Url::parse(target.api_url.trim()).map_err(|e| anyhow!("the api url is not a valid URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") || !url.has_host() {
        bail!("the api url must be an absolute http or https URL");
    }
    url.set_query(None);
    url.set_fragment(None);
    url.path_segments_mut()
        .map_err(|()| anyhow!("the api url cannot carry a path"))?
        .pop_if_empty()
        .extend(["v1", "authorizations"])
        .extend(tail);
    let http = reqwest::Client::builder()
        .user_agent(concat!("crawlx-authz/", env!("CARGO_PKG_VERSION")))
        .timeout(TIMEOUT)
        .connect_timeout(TIMEOUT)
        .build()
        .map_err(|e| anyhow!("building the HTTP client: {}", chain(&e.without_url())))?;
    let mut request = http.request(method, url);
    if let Some(key) = target.api_key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
        request = request.bearer_auth(key);
    }
    if let Some(body) = &body {
        request = request.json(body);
    }
    let response = request.send().await.map_err(|e| {
        anyhow!(
            "cannot reach the crawlx API at {}: {}",
            shown(&target.api_url),
            chain(&e.without_url())
        )
    })?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| anyhow!("reading the API answer: {}", chain(&e.without_url())))?;
    if bytes.len() > MAX_BODY_BYTES {
        bail!("the API answer is larger than {MAX_BODY_BYTES} bytes");
    }
    let parsed = serde_json::from_slice::<Value>(&bytes).ok();
    if status.is_success() {
        match parsed {
            Some(v) => writeln!(out, "{}", serde_json::to_string_pretty(&v)?)?,
            None => writeln!(out, "{}", String::from_utf8_lossy(&bytes).trim_end())?,
        }
        return Ok(ExitCode::SUCCESS);
    }
    match parsed {
        Some(v) => eprintln!("{}", serde_json::to_string_pretty(&v)?),
        None => {
            let text = String::from_utf8_lossy(&bytes);
            let cut = text
                .char_indices()
                .nth(MAX_QUOTED_CHARS)
                .map_or(text.len(), |(i, _)| i);
            eprintln!("HTTP {status}: {}", text[..cut].trim());
        }
    }
    Ok(ExitCode::from(1))
}

/// A keys file for signing: the `OperatorKeys` format, or one bare hex key stored under `key_id`.
fn signing_keys(text: &str, key_id: &str) -> anyhow::Result<OperatorKeys> {
    match OperatorKeys::parse(text) {
        Ok(keys) if !keys.is_empty() => Ok(keys),
        parsed => {
            let bare = text.trim();
            if !bare.is_empty() && !bare.contains(char::is_whitespace) {
                if let Ok(bytes) = hex::decode(bare) {
                    let mut keys = OperatorKeys::new();
                    keys.insert(key_id, bytes)?;
                    return Ok(keys);
                }
            }
            match parsed {
                Ok(_) => bail!("the keys file defines no key"),
                Err(e) => Err(e.into()),
            }
        }
    }
}

fn sign(args: &SignArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let mut record = read_record(&args.record)?;
    if record.verified_at.is_some() || record.revoked_at.is_some() || record.revoked_reason.is_some() {
        bail!("the record carries lifecycle fields (verifiedAt, revokedAt, revokedReason); the API sets them and refuses them at creation");
    }
    match &record.ownership {
        None => {}
        Some(OwnershipProof::OperatorSignature { key_id, .. }) if *key_id == args.key_id => {}
        Some(OwnershipProof::OperatorSignature { key_id, .. }) => {
            bail!(
                "the record names operator key {key_id:?}, not {:?}; the key id is part of the signed digest",
                args.key_id
            );
        }
        Some(_) => {
            bail!("the record names another ownership proof; `sign` is for operator_signature records")
        }
    }
    let text = std::fs::read_to_string(&args.key_file)
        .with_context(|| format!("reading the key file {}", args.key_file.display()))?;
    let keys = signing_keys(&text, &args.key_id)
        .with_context(|| format!("the key file {}", args.key_file.display()))?;
    record.ownership = Some(OwnershipProof::OperatorSignature {
        key_id: args.key_id.clone(),
        signature: String::new(),
    });
    record
        .validate()
        .map_err(|e| anyhow!("the record is not valid: {e}"))?;
    let signature = keys.sign(&args.key_id, &record)?;
    record.ownership = Some(OwnershipProof::OperatorSignature {
        key_id: args.key_id.clone(),
        signature,
    });
    keys.verify(&record)?;
    let signed = serde_json::to_string_pretty(&record)?;
    match &args.out {
        Some(path) => {
            std::fs::write(path, format!("{signed}\n"))
                .with_context(|| format!("writing {}", path.display()))?;
            writeln!(
                out,
                "signed record {} with operator key {}; wrote {}",
                record.id,
                args.key_id,
                path.display()
            )?;
        }
        None => writeln!(out, "{signed}")?,
    }
    Ok(ExitCode::SUCCESS)
}

/// A host that cannot carry a DNS TXT record.
fn is_ip_literal(host: &str) -> bool {
    host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok()
}

fn challenge(args: &ChallengeArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let mut value = read_json(&args.record)?;
    // the challenge covers the id and the target only: a record without `tenant` is fine here
    if let Some(object) = value.as_object_mut() {
        object
            .entry("tenant")
            .or_insert_with(|| json!(uuid::Uuid::nil().to_string()));
    }
    let record: AuthorizationRecord = serde_json::from_value(value)
        .with_context(|| format!("parsing authorization record {}", args.record.display()))?;
    let id = record.id.to_string();
    let hosts = record.challenge_hosts();
    let mut origins: Vec<String> = Vec::new();
    for entry in record.origins.iter().chain(&record.url_prefixes) {
        if let Ok(url) = Url::parse(entry) {
            let origin = origin_string(&url);
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
    }
    let proof = match &record.ownership {
        Some(OwnershipProof::DnsTxt {}) => Some("dns_txt"),
        Some(OwnershipProof::WellKnownFile {}) => Some("well_known_file"),
        Some(OwnershipProof::OperatorSignature { .. }) => Some("operator_signature"),
        _ => None,
    };
    if args.json {
        let doc = json!({
            "id": id,
            "ownership": proof,
            "dnsTxt": hosts.iter().map(|h| json!({
                "name": format!("{DNS_CHALLENGE_LABEL}.{h}"),
                "type": "TXT",
                "value": id,
                "publishable": !is_ip_literal(h),
            })).collect::<Vec<_>>(),
            "wellKnownFile": origins.iter().map(|o| json!({
                "url": format!("{o}{WELL_KNOWN_CHALLENGE_PATH}"),
                "body": id,
            })).collect::<Vec<_>>(),
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&doc)?)?;
        return Ok(ExitCode::SUCCESS);
    }
    writeln!(out, "record {id}")?;
    match proof {
        Some("operator_signature") => writeln!(
            out,
            "ownership: operator_signature: nothing to publish; sign the record with `crawlx authz sign`"
        )?,
        Some(kind) => writeln!(out, "ownership: {kind}")?,
        None => writeln!(out, "ownership: not set (the API requires one)")?,
    }
    writeln!(
        out,
        "dns_txt: publish a TXT record holding the record id at each name"
    )?;
    for host in &hosts {
        let note = if is_ip_literal(host) {
            "  # an IP address cannot carry a TXT record: use the well-known file"
        } else {
            ""
        };
        writeln!(out, "  {DNS_CHALLENGE_LABEL}.{host} TXT \"{id}\"{note}")?;
    }
    writeln!(
        out,
        "well_known_file: serve the record id as the whole body of each URL (HTTP 200)"
    )?;
    for origin in &origins {
        writeln!(out, "  {origin}{WELL_KNOWN_CHALLENGE_PATH}")?;
    }
    writeln!(out, "  body: {id}")?;
    Ok(ExitCode::SUCCESS)
}
