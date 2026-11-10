//! S3-compatible object-store backend for the artifact store.
//!
//! [`S3Blobs`] implements [`ArtifactBlobs`] over `aws-sdk-s3`; wrapping it in
//! [`crate::ObjectArtifactStore`] gives the content-addressed key layout
//! `{class}/{tenant}/{run}/{blake3}`, the ZDR gate and the "object `PUT` first,
//! `artifacts` row second" ordering. Retries and backoff come from the SDK's
//! standard retry mode; server-side encryption headers are passed through on
//! every `PUT` from [`S3Config::sse`]. Credentials come from the process
//! environment (the SDK access key id, secret access key and optional session
//! token variables) unless the caller supplies them.

use crate::artifacts::{ArtifactBlobs, BlobEntry, ObjectArtifactStore};
use async_trait::async_trait;
use aws_config::environment::EnvironmentVariableCredentialsProvider;
use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
    SharedCredentialsProvider,
};
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::ServerSideEncryption;
use aws_sdk_s3::Client;
use aws_smithy_http_client::tls;
use bytes::Bytes;
use chrono::TimeZone;
use crawlx_core::{StoreError, Timestamp};
use std::time::Duration;

/// Artifacts in an S3-compatible bucket.
pub type S3ArtifactStore = ObjectArtifactStore<S3Blobs>;

/// Server-side encryption requested on every `PUT` (the bucket's own default applies when unset).
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Sse {
    /// `x-amz-server-side-encryption: AES256`.
    Aes256,
    /// KMS-managed server-side encryption, optionally with a key id.
    CloudKms {
        /// KMS key id sent with the encryption header; `None` uses the account's default key.
        key_id: Option<String>,
    },
}

impl Sse {
    /// Parse `CRAWLX_S3_SSE` (`aes256` or `kms`) with an optional KMS key id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] for an unknown algorithm label.
    pub fn parse(algorithm: &str, kms_key_id: Option<String>) -> Result<Self, StoreError> {
        match algorithm.trim().to_ascii_lowercase().as_str() {
            "aes256" => Ok(Self::Aes256),
            "aws:kms" | "cloud_kms" | "kms" => Ok(Self::CloudKms { key_id: kms_key_id }), // wire-compat: S3 SSE algorithm label
            other => Err(StoreError::Conflict(format!(
                "unknown server-side encryption {other:?} (expected aes256 or kms)"
            ))),
        }
    }
}

/// Connection settings for [`S3Blobs`].
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct S3Config {
    /// Bucket every object lives in (recorded in `artifacts.bucket`).
    pub bucket: String,
    /// Signing region (`us-east-1` for most S3-compatible stores).
    pub region: String,
    /// Custom endpoint (MinIO, Ceph RGW, local emulators); `None` for the default regional endpoint.
    pub endpoint: Option<String>,
    /// Path-style addressing (`https://host/bucket/key`); required for IP or single-host endpoints.
    pub path_style: bool,
    /// Server-side encryption header passthrough.
    pub sse: Option<Sse>,
    /// Attempts per operation under the SDK's standard retry mode (at least 1).
    pub max_attempts: u32,
    /// Per-attempt timeout.
    pub attempt_timeout: Duration,
}

impl S3Config {
    /// Settings for `bucket` against the default regional endpoint in `region` with the SDK defaults.
    #[must_use]
    pub fn new(bucket: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            region: region.into(),
            endpoint: None,
            path_style: false,
            sse: None,
            max_attempts: 3,
            attempt_timeout: Duration::from_secs(30),
        }
    }

    /// Settings from the process environment: `CRAWLX_S3_BUCKET` (required),
    /// `CRAWLX_S3_REGION` (default `us-east-1`), `CRAWLX_S3_ENDPOINT`, `CRAWLX_S3_PATH_STYLE`
    /// (`1`/`true`), `CRAWLX_S3_SSE` (`aes256` or `kms`) and `CRAWLX_S3_KMS_KEY_ID`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] if the bucket is unset or an SSE label is unknown.
    pub fn from_env() -> Result<Self, StoreError> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let bucket = var("CRAWLX_S3_BUCKET")
            .ok_or_else(|| StoreError::Conflict("CRAWLX_S3_BUCKET is not set".to_owned()))?;
        let mut cfg = Self::new(
            bucket,
            var("CRAWLX_S3_REGION").unwrap_or_else(|| "us-east-1".to_owned()),
        );
        cfg.endpoint = var("CRAWLX_S3_ENDPOINT");
        cfg.path_style = var("CRAWLX_S3_PATH_STYLE")
            .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
        cfg.sse = var("CRAWLX_S3_SSE")
            .map(|a| Sse::parse(&a, var("CRAWLX_S3_KMS_KEY_ID")))
            .transpose()?;
        Ok(cfg)
    }

    /// Use `endpoint` with path-style addressing (S3-compatible stores).
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self.path_style = true;
        self
    }

    /// Request `sse` on every `PUT`.
    #[must_use]
    pub fn with_sse(mut self, sse: Sse) -> Self {
        self.sse = Some(sse);
        self
    }
}

/// [`ArtifactBlobs`] over an S3-compatible bucket.
#[derive(Clone, Debug)]
pub struct S3Blobs {
    client: Client,
    bucket: String,
    sse: Option<Sse>,
}

impl S3Blobs {
    /// Backend with credentials from the environment.
    #[must_use]
    pub fn new(config: &S3Config) -> Self {
        Self::build(
            config,
            SharedCredentialsProvider::new(EnvironmentVariableCredentialsProvider::new()),
        )
    }

    /// Backend with explicit static credentials (tests, MinIO).
    #[must_use]
    pub fn with_credentials(config: &S3Config, credentials: Credentials) -> Self {
        Self::build(config, SharedCredentialsProvider::new(credentials))
    }

    fn build(config: &S3Config, credentials: SharedCredentialsProvider) -> Self {
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::Ring))
            .build_https();
        let mut builder = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .credentials_provider(credentials)
            .http_client(http)
            .force_path_style(config.path_style)
            // CRC32 trailers (chunked trailer encoding) are not understood by every S3-compatible store;
            // integrity is covered by the blake3 digest in the artifact row.
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            .retry_config(RetryConfig::standard().with_max_attempts(config.max_attempts.max(1)))
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_attempt_timeout(config.attempt_timeout)
                    .build(),
            );
        if let Some(endpoint) = &config.endpoint {
            builder = builder.endpoint_url(endpoint.clone());
        }
        Self {
            client: Client::from_conf(builder.build()),
            bucket: config.bucket.clone(),
            sse: config.sse.clone(),
        }
    }

    /// The SDK client (for bucket administration in tests and tooling).
    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.client
    }
}

/// Map an SDK failure to the store error classes: transport and timeout failures are
/// retryable `Unavailable`; service rejections are `Backend`. Messages carry the operation
/// and key, never credentials.
fn sdk_error<E: std::error::Error + 'static, R: std::fmt::Debug>(
    op: &str,
    key: &str,
    e: &SdkError<E, R>,
) -> StoreError {
    match e {
        SdkError::ConstructionFailure(_) | SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) => {
            StoreError::Unavailable(format!("s3 {op} {key}: {e}"))
        }
        SdkError::ResponseError(_) | SdkError::ServiceError(_) => StoreError::Backend(format!(
            "s3 {op} {key}: {}",
            aws_sdk_s3::error::DisplayErrorContext(e)
        )),
        _ => StoreError::Backend(format!("s3 {op} {key}: {e}")),
    }
}

fn to_timestamp(dt: Option<&aws_sdk_s3::primitives::DateTime>) -> Option<Timestamp> {
    let dt = dt?;
    chrono::Utc.timestamp_opt(dt.secs(), dt.subsec_nanos()).single()
}

#[async_trait]
impl ArtifactBlobs for S3Blobs {
    fn bucket(&self) -> &str {
        &self.bucket
    }
    async fn reader(&self, key: &str) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| sdk_error("get", key, &e))?;
        Ok(Box::new(output.body.into_async_read()))
    }
    async fn put_file(&self, key: &str, file: &std::path::Path, size: u64) -> Result<(), StoreError> {
        // Archive policy caps files at 1 GiB, below S3's 5 GiB single-PUT limit.
        // The SDK retries from the file; it does not buffer the archive in memory.
        let body = ByteStream::from_path(file)
            .await
            .map_err(|e| StoreError::Unavailable(format!("archive upload source: {e}")))?;
        let mut request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_length(i64::try_from(size).map_err(|_| StoreError::Conflict("archive size".into()))?)
            .body(body);
        match &self.sse {
            Some(Sse::Aes256) => request = request.server_side_encryption(ServerSideEncryption::Aes256),
            Some(Sse::CloudKms { key_id }) => {
                request = request.server_side_encryption(ServerSideEncryption::AwsKms);
                if let Some(id) = key_id {
                    request = request.ssekms_key_id(id);
                }
            }
            None => {}
        }
        request.send().await.map_err(|e| sdk_error("put", key, &e))?;
        Ok(())
    }

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.put_shared(key, Bytes::copy_from_slice(bytes)).await
    }

    async fn put_shared(&self, key: &str, bytes: Bytes) -> Result<(), StoreError> {
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_length(i64::try_from(bytes.len()).map_err(|_| {
                StoreError::Serialization(format!("object {key} too large for content-length"))
            })?)
            .body(ByteStream::from(bytes));
        match &self.sse {
            Some(Sse::Aes256) => req = req.server_side_encryption(ServerSideEncryption::Aes256),
            Some(Sse::CloudKms { key_id }) => {
                req = req.server_side_encryption(ServerSideEncryption::AwsKms);
                if let Some(id) = key_id {
                    req = req.ssekms_key_id(id);
                }
            }
            None => {}
        }
        req.send().await.map_err(|e| sdk_error("put", key, &e))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let out = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(out) => out,
            Err(e) if e.as_service_error().is_some_and(|s| s.is_no_such_key()) => return Ok(None),
            Err(e) => return Err(sdk_error("get", key, &e)),
        };
        let bytes = out
            .body
            .collect()
            .await
            .map_err(|e| StoreError::Unavailable(format!("s3 get {key}: body: {e}")))?;
        Ok(Some(bytes.into_bytes().to_vec()))
    }

    async fn exists(&self, key: &str) -> Result<bool, StoreError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if e.as_service_error().is_some_and(|s| s.is_not_found()) => Ok(false),
            Err(e) => Err(sdk_error("head", key, &e)),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| sdk_error("delete", key, &e))?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<BlobEntry>, StoreError> {
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .into_paginator()
            .send();
        let mut out = Vec::new();
        while let Some(page) = pages.next().await {
            let page = page.map_err(|e| sdk_error("list", prefix, &e))?;
            for object in page.contents() {
                let Some(key) = object.key() else { continue };
                let Some(modified) = to_timestamp(object.last_modified()) else {
                    return Err(StoreError::Backend(format!(
                        "s3 list {prefix}: object {key} has no last-modified time"
                    )));
                };
                out.push(BlobEntry {
                    key: key.to_owned(),
                    modified,
                });
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    /// SigV4 query-string presigned `GET` (`X-Amz-Expires=<ttl>`), valid for `ttl` from now.
    async fn presign(&self, key: &str, ttl: Duration) -> Result<Option<url::Url>, StoreError> {
        let config = PresigningConfig::expires_in(ttl)
            .map_err(|e| StoreError::Conflict(format!("s3 presign {key}: {e}")))?;
        let request = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(config)
            .await
            .map_err(|e| sdk_error("presign", key, &e))?;
        let url = url::Url::parse(request.uri())
            .map_err(|e| StoreError::Backend(format!("s3 presign {key}: unparsable uri: {e}")))?;
        Ok(Some(url))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn sse_labels_parse() {
        assert_eq!(Sse::parse("AES256", None).unwrap(), Sse::Aes256);
        assert_eq!(
            Sse::parse("aws:kms", Some("k".to_owned())).unwrap(), // wire-compat: S3 SSE algorithm label
            Sse::CloudKms {
                key_id: Some("k".to_owned())
            }
        );
        assert!(matches!(Sse::parse("rot13", None), Err(StoreError::Conflict(_))));
    }

    #[test]
    fn endpoint_implies_path_style() {
        let cfg = S3Config::new("b", "us-east-1").with_endpoint("http://127.0.0.1:9000");
        assert!(cfg.path_style);
        assert_eq!(cfg.endpoint.as_deref(), Some("http://127.0.0.1:9000"));
        assert_eq!(cfg.max_attempts, 3);
    }

    #[test]
    fn smithy_timestamps_convert() {
        let dt = aws_sdk_s3::primitives::DateTime::from_secs(1_700_000_000);
        let ts = to_timestamp(Some(&dt)).unwrap();
        assert_eq!(ts.timestamp(), 1_700_000_000);
        assert!(to_timestamp(None).is_none());
    }
}
