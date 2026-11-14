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
//!
//! # Profiles
//!
//! Services that speak the S3 API differ in addressing, region handling, encryption,
//! object lock and checksum support. An [`S3Profile`] names one family of services and fixes
//! its defaults and its [`S3Capabilities`]; [`S3Config::validate`] refuses a configuration
//! that asks for something the profile cannot do instead of downgrading it silently. The
//! profile comes from `CRAWLX_S3_PROFILE` (default `standard`); see `docs/ops/object-storage.md`.
//!
//! Operations in this module and their profile behavior:
//!
//! * `PUT`, `GET`, `HEAD`, `DELETE`, `ListObjectsV2` and the SigV4 query-string presign work
//!   unchanged on every profile.
//! * Uploads are always one `PutObject` (never multipart); an object above
//!   [`S3Capabilities::single_put_max_bytes`] is refused with a typed error.
//! * No conditional write (`If-None-Match`) and no retention call is ever sent. "First write
//!   wins" for the audit export is a property of the bucket's object lock, declared with
//!   [`S3Config::object_lock`] and refused on profiles without object lock.

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
use aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{ChecksumAlgorithm, ServerSideEncryption};
use aws_sdk_s3::Client;
use aws_smithy_http_client::tls;
use bytes::Bytes;
use chrono::TimeZone;
use crawlx_core::{StoreError, Timestamp};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Artifacts in an S3-compatible bucket.
pub type S3ArtifactStore = ObjectArtifactStore<S3Blobs>;

/// Largest object one `PutObject` carries (5 GiB), the limit every profile shares.
pub const SINGLE_PUT_MAX_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Why an S3 configuration was refused. Raised when the configuration is built from the
/// environment and again when [`S3Blobs`] is constructed, never at request time.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum S3ConfigError {
    /// `CRAWLX_S3_BUCKET` (or the explicit bucket) is missing or blank.
    #[error("CRAWLX_S3_BUCKET is not set")]
    BucketMissing,
    /// `CRAWLX_S3_PROFILE` names no known profile.
    #[error("unknown s3 profile {0:?} (expected standard, compatible, edge or self-hosted)")]
    UnknownProfile(String),
    /// An environment value is not one of the accepted spellings.
    #[error("{var} has an invalid value {value:?} (expected {expected})")]
    InvalidValue {
        /// The variable name.
        var: &'static str,
        /// The rejected value.
        value: String,
        /// The accepted spellings.
        expected: &'static str,
    },
    /// The profile has no default endpoint and none was configured.
    #[error("the {profile} s3 profile requires CRAWLX_S3_ENDPOINT")]
    EndpointRequired {
        /// The profile that needs the endpoint.
        profile: S3Profile,
    },
    /// The endpoint is not an `http(s)` url with a host, or carries credentials, a query or a fragment.
    #[error("s3 endpoint is invalid: {0}")]
    EndpointInvalid(String),
    /// Plain `http` to a host the profile does not trust with it.
    #[error(
        "the {profile} s3 profile refuses plain http to {host}; use https or set CRAWLX_S3_ALLOW_HTTP=1"
    )]
    PlainHttpRefused {
        /// The profile that refused.
        profile: S3Profile,
        /// The endpoint host.
        host: String,
    },
    /// The signing region is blank.
    #[error("s3 region must not be empty")]
    RegionEmpty,
    /// `CRAWLX_S3_PREFIX` is not a safe key prefix.
    #[error("CRAWLX_S3_PREFIX {0:?} is invalid: use at most 128 characters of letters, digits and . _ - /, no leading slash, no empty or dot segments")]
    PrefixInvalid(String),
    /// The profile does not support the requested server-side encryption.
    #[error("the {profile} s3 profile does not support server-side encryption {sse}")]
    SseRefused {
        /// The profile that refused.
        profile: S3Profile,
        /// The encryption label (`aes256` or `kms`).
        sse: &'static str,
    },
    /// The profile supports KMS encryption only when the operator opts in.
    #[error("the {profile} s3 profile accepts kms encryption only with CRAWLX_S3_ALLOW_KMS=1")]
    KmsNotAllowed {
        /// The profile that refused.
        profile: S3Profile,
    },
    /// `CRAWLX_S3_KMS_KEY_ID` is set but the encryption is not `kms`.
    #[error("CRAWLX_S3_KMS_KEY_ID is set but CRAWLX_S3_SSE is not kms")]
    KmsKeyWithoutKms,
    /// The profile has no object lock (WORM) support.
    #[error("the {profile} s3 profile does not support object lock; point the audit export at a bucket of a profile that does")]
    ObjectLockRefused {
        /// The profile that refused.
        profile: S3Profile,
    },
    /// The profile supports only the `when_required` checksum mode.
    #[error("the {profile} s3 profile supports only the when_required checksum mode, not {mode}")]
    ChecksumRefused {
        /// The profile that refused.
        profile: S3Profile,
        /// The requested mode.
        mode: ChecksumMode,
    },
}

impl From<S3ConfigError> for StoreError {
    fn from(e: S3ConfigError) -> Self {
        Self::Conflict(e.to_string())
    }
}

/// A family of S3-compatible services, selected by `CRAWLX_S3_PROFILE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum S3Profile {
    /// The original hosted service: regional endpoints, virtual-hosted addressing, every
    /// encryption mode and object lock. The default.
    #[default]
    Standard,
    /// A generic S3-compatible service: custom endpoint, path-style addressing, only the
    /// checksums every implementation computes, KMS encryption only on request.
    Compatible,
    /// An edge-hosted service with an account-scoped https endpoint, region `auto`, no
    /// server-side encryption modes, no object lock and no extra checksums.
    Edge,
    /// A self-hosted server: custom endpoint, path-style addressing, plain http allowed on
    /// loopback and private hosts.
    SelfHosted,
}

impl S3Profile {
    /// Every profile, in documentation order.
    pub const ALL: [Self; 4] = [Self::Standard, Self::Compatible, Self::Edge, Self::SelfHosted];

    /// Parse a `CRAWLX_S3_PROFILE` label (case-insensitive; `self-hosted` also as `self_hosted`).
    ///
    /// # Errors
    ///
    /// [`S3ConfigError::UnknownProfile`] for any other label.
    pub fn parse(label: &str) -> Result<Self, S3ConfigError> {
        match label.trim().to_ascii_lowercase().as_str() {
            "standard" => Ok(Self::Standard),
            "compatible" => Ok(Self::Compatible),
            "edge" => Ok(Self::Edge),
            "self-hosted" | "self_hosted" => Ok(Self::SelfHosted),
            _ => Err(S3ConfigError::UnknownProfile(label.trim().to_owned())),
        }
    }

    /// The label `CRAWLX_S3_PROFILE` accepts for this profile.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Compatible => "compatible",
            Self::Edge => "edge",
            Self::SelfHosted => "self-hosted",
        }
    }

    /// What the profile defaults to and what it can do.
    #[must_use]
    pub const fn capabilities(self) -> S3Capabilities {
        match self {
            Self::Standard => S3Capabilities {
                endpoint_required: false,
                default_region: "us-east-1",
                default_path_style: false,
                plain_http: PlainHttp::Unrestricted,
                sse_aes256: true,
                sse_kms: true,
                kms_needs_opt_in: false,
                object_lock: true,
                extended_checksums: true,
                single_put_max_bytes: SINGLE_PUT_MAX_BYTES,
            },
            Self::Compatible => S3Capabilities {
                endpoint_required: true,
                default_region: "us-east-1",
                default_path_style: true,
                plain_http: PlainHttp::PrivateHostsOnly,
                sse_aes256: true,
                sse_kms: true,
                kms_needs_opt_in: true,
                object_lock: true,
                extended_checksums: false,
                single_put_max_bytes: SINGLE_PUT_MAX_BYTES,
            },
            Self::Edge => S3Capabilities {
                endpoint_required: true,
                default_region: "auto",
                default_path_style: true,
                plain_http: PlainHttp::Refused,
                sse_aes256: false,
                sse_kms: false,
                kms_needs_opt_in: false,
                object_lock: false,
                extended_checksums: false,
                single_put_max_bytes: SINGLE_PUT_MAX_BYTES,
            },
            Self::SelfHosted => S3Capabilities {
                endpoint_required: true,
                default_region: "us-east-1",
                default_path_style: true,
                plain_http: PlainHttp::PrivateHostsOnly,
                sse_aes256: true,
                sse_kms: true,
                kms_needs_opt_in: false,
                object_lock: true,
                extended_checksums: false,
                single_put_max_bytes: SINGLE_PUT_MAX_BYTES,
            },
        }
    }
}

impl std::fmt::Display for S3Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which hosts a profile reaches over plain `http` without `CRAWLX_S3_ALLOW_HTTP=1`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PlainHttp {
    /// Any endpoint (the default profile keeps its historical behavior).
    Unrestricted,
    /// Loopback, private-range and local-network names only.
    PrivateHostsOnly,
    /// No plain `http`.
    Refused,
}

/// Defaults and limits of one [`S3Profile`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct S3Capabilities {
    /// A custom endpoint must be configured.
    pub endpoint_required: bool,
    /// Signing region when `CRAWLX_S3_REGION` is unset.
    pub default_region: &'static str,
    /// Path-style addressing when `CRAWLX_S3_PATH_STYLE` is unset.
    pub default_path_style: bool,
    /// Plain `http` policy for a custom endpoint.
    pub plain_http: PlainHttp,
    /// `x-amz-server-side-encryption: AES256` is supported.
    pub sse_aes256: bool,
    /// KMS-managed server-side encryption is supported.
    pub sse_kms: bool,
    /// KMS encryption needs `CRAWLX_S3_ALLOW_KMS=1`.
    pub kms_needs_opt_in: bool,
    /// Object lock (WORM) buckets exist.
    pub object_lock: bool,
    /// The `when_supported` checksum mode (CRC trailers on every upload) is accepted.
    pub extended_checksums: bool,
    /// Largest single `PutObject`; larger objects are refused (multipart is not implemented).
    pub single_put_max_bytes: u64,
}

/// When the SDK adds integrity checksums to requests and validates them on responses.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum ChecksumMode {
    /// Only for operations that require one. Works against every implementation; integrity
    /// of artifacts is covered by the blake3 digest in the artifact row. The default.
    #[default]
    WhenRequired,
    /// A CRC32 trailer on every upload and validation of every download that carries one.
    WhenSupported,
}

impl ChecksumMode {
    /// Parse a `CRAWLX_S3_CHECKSUM` label.
    ///
    /// # Errors
    ///
    /// [`S3ConfigError::InvalidValue`] for any other label.
    pub fn parse(label: &str) -> Result<Self, S3ConfigError> {
        match label.trim().to_ascii_lowercase().as_str() {
            "when_required" | "required" => Ok(Self::WhenRequired),
            "when_supported" | "supported" => Ok(Self::WhenSupported),
            _ => Err(S3ConfigError::InvalidValue {
                var: "CRAWLX_S3_CHECKSUM",
                value: label.trim().to_owned(),
                expected: "when_required or when_supported",
            }),
        }
    }

    /// The label `CRAWLX_S3_CHECKSUM` accepts for this mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WhenRequired => "when_required",
            Self::WhenSupported => "when_supported",
        }
    }
}

impl std::fmt::Display for ChecksumMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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

    const fn label(&self) -> &'static str {
        match self {
            Self::Aes256 => "aes256",
            Self::CloudKms { .. } => "kms",
        }
    }
}

/// Connection settings for [`S3Blobs`].
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct S3Config {
    /// Service family; fixes the defaults and the refusals of [`S3Config::validate`].
    pub profile: S3Profile,
    /// Bucket every object lives in (recorded in `artifacts.bucket`).
    pub bucket: String,
    /// Signing region (`us-east-1` for most S3-compatible stores, `auto` on the edge profile).
    pub region: String,
    /// Custom endpoint (self-hosted servers, edge services, local emulators); `None` for the default regional endpoint.
    pub endpoint: Option<String>,
    /// Path-style addressing (`https://host/bucket/key`); required for IP or single-host endpoints.
    pub path_style: bool,
    /// Server-side encryption header passthrough.
    pub sse: Option<Sse>,
    /// Checksum mode; [`ChecksumMode::WhenSupported`] only where the profile allows it.
    pub checksum: ChecksumMode,
    /// The bucket is under object lock (WORM). Every `PUT` then carries a CRC32 checksum,
    /// which an object-lock bucket requires.
    pub object_lock: bool,
    /// Allow plain `http` to any host (`CRAWLX_S3_ALLOW_HTTP`).
    pub allow_http: bool,
    /// Allow KMS encryption on profiles that need an opt-in (`CRAWLX_S3_ALLOW_KMS`).
    pub allow_kms: bool,
    /// Attempts per operation under the SDK's standard retry mode (at least 1).
    pub max_attempts: u32,
    /// Per-attempt timeout.
    pub attempt_timeout: Duration,
    /// Key prefix every object of this deployment lives under (`CRAWLX_S3_PREFIX`), empty or
    /// ending in `/`. Several products or deployments can share one bucket by choosing
    /// different prefixes; CrawlX never lists, reads or deletes outside its own.
    pub prefix: String,
}

/// Normalize and check an object key prefix: empty, or `a/b/` form.
///
/// # Errors
/// [`S3ConfigError::PrefixInvalid`] for a leading slash, an empty, `.` or `..` segment, a
/// character outside `[A-Za-z0-9._-]` or more than 128 characters.
pub fn normalize_prefix(prefix: &str) -> Result<String, S3ConfigError> {
    let trimmed = prefix.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let body = trimmed.strip_suffix('/').unwrap_or(trimmed);
    let ok = body.len() <= 128
        && body.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        });
    if ok {
        Ok(format!("{body}/"))
    } else {
        Err(S3ConfigError::PrefixInvalid(trimmed.to_owned()))
    }
}

impl S3Config {
    /// Settings for `bucket` on the [`S3Profile::Standard`] profile against the default
    /// regional endpoint in `region` with the SDK defaults.
    #[must_use]
    pub fn new(bucket: impl Into<String>, region: impl Into<String>) -> Self {
        Self::for_profile(S3Profile::Standard, bucket).with_region(region)
    }

    /// Settings for `bucket` with the defaults of `profile`. Profiles that need an endpoint
    /// stay invalid ([`S3Config::validate`]) until one is set.
    #[must_use]
    pub fn for_profile(profile: S3Profile, bucket: impl Into<String>) -> Self {
        let caps = profile.capabilities();
        Self {
            profile,
            bucket: bucket.into(),
            region: caps.default_region.to_owned(),
            endpoint: None,
            path_style: caps.default_path_style,
            sse: None,
            checksum: ChecksumMode::WhenRequired,
            object_lock: false,
            allow_http: false,
            allow_kms: false,
            max_attempts: 3,
            attempt_timeout: Duration::from_secs(30),
            prefix: String::new(),
        }
    }

    /// Keep every object under `prefix` (see [`S3Config::prefix`]).
    ///
    /// # Errors
    /// [`S3ConfigError::PrefixInvalid`].
    pub fn with_prefix(mut self, prefix: &str) -> Result<Self, S3ConfigError> {
        self.prefix = normalize_prefix(prefix)?;
        Ok(self)
    }

    /// Settings from the process environment; see [`S3Config::from_lookup`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] carrying the [`S3ConfigError`] message.
    pub fn from_env() -> Result<Self, StoreError> {
        Ok(Self::from_lookup(&|name| std::env::var(name).ok())?)
    }

    /// Settings from the process environment for an explicit `bucket`
    /// (`CRAWLX_S3_BUCKET` is not read); see [`S3Config::from_lookup_for_bucket`].
    ///
    /// # Errors
    ///
    /// The [`S3ConfigError`] of [`S3Config::from_lookup_for_bucket`].
    pub fn from_env_for_bucket(bucket: &str) -> Result<Self, S3ConfigError> {
        Self::from_lookup_for_bucket(bucket, &|name| std::env::var(name).ok())
    }

    /// Settings from `get`, a lookup of environment variables: `CRAWLX_S3_BUCKET` (required),
    /// `CRAWLX_S3_PROFILE` (`standard`, `compatible`, `edge`, `self-hosted`; default
    /// `standard`), then the overrides `CRAWLX_S3_REGION`, `CRAWLX_S3_ENDPOINT`,
    /// `CRAWLX_S3_PATH_STYLE`, `CRAWLX_S3_SSE` (`aes256` or `kms`), `CRAWLX_S3_KMS_KEY_ID`,
    /// `CRAWLX_S3_CHECKSUM` (`when_required` or `when_supported`), `CRAWLX_S3_OBJECT_LOCK`,
    /// `CRAWLX_S3_ALLOW_HTTP` and `CRAWLX_S3_ALLOW_KMS` (booleans: `1`/`true`/`yes`/`on` or
    /// `0`/`false`/`no`/`off`). Blank values count as unset. The result is validated.
    ///
    /// # Errors
    ///
    /// [`S3ConfigError`] for a missing bucket, an unknown label, or any refusal of
    /// [`S3Config::validate`].
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, S3ConfigError> {
        let bucket = non_blank(get, "CRAWLX_S3_BUCKET").ok_or(S3ConfigError::BucketMissing)?;
        Self::from_lookup_for_bucket(&bucket, get)
    }

    /// [`S3Config::from_lookup`] for an explicit `bucket` (`CRAWLX_S3_BUCKET` is not read).
    ///
    /// # Errors
    ///
    /// As [`S3Config::from_lookup`].
    pub fn from_lookup_for_bucket(
        bucket: &str,
        get: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, S3ConfigError> {
        if bucket.trim().is_empty() {
            return Err(S3ConfigError::BucketMissing);
        }
        let profile = non_blank(get, "CRAWLX_S3_PROFILE")
            .map(|label| S3Profile::parse(&label))
            .transpose()?
            .unwrap_or_default();
        let mut cfg = Self::for_profile(profile, bucket.trim());
        if let Some(region) = non_blank(get, "CRAWLX_S3_REGION") {
            cfg.region = region;
        }
        cfg.endpoint = non_blank(get, "CRAWLX_S3_ENDPOINT");
        if let Some(prefix) = non_blank(get, "CRAWLX_S3_PREFIX") {
            cfg.prefix = normalize_prefix(&prefix)?;
        }
        if let Some(value) = non_blank(get, "CRAWLX_S3_PATH_STYLE") {
            cfg.path_style = parse_bool("CRAWLX_S3_PATH_STYLE", &value)?;
        }
        let key_id = non_blank(get, "CRAWLX_S3_KMS_KEY_ID");
        cfg.sse = non_blank(get, "CRAWLX_S3_SSE")
            .map(|label| {
                Sse::parse(&label, key_id.clone()).map_err(|_| S3ConfigError::InvalidValue {
                    var: "CRAWLX_S3_SSE",
                    value: label.clone(),
                    expected: "aes256 or kms",
                })
            })
            .transpose()?;
        if key_id.is_some() && !matches!(cfg.sse, Some(Sse::CloudKms { .. })) {
            return Err(S3ConfigError::KmsKeyWithoutKms);
        }
        if let Some(label) = non_blank(get, "CRAWLX_S3_CHECKSUM") {
            cfg.checksum = ChecksumMode::parse(&label)?;
        }
        for (var, slot) in [
            ("CRAWLX_S3_OBJECT_LOCK", &mut cfg.object_lock),
            ("CRAWLX_S3_ALLOW_HTTP", &mut cfg.allow_http),
            ("CRAWLX_S3_ALLOW_KMS", &mut cfg.allow_kms),
        ] {
            if let Some(value) = non_blank(get, var) {
                *slot = parse_bool(var, &value)?;
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Use `endpoint` with path-style addressing (S3-compatible stores).
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self.path_style = true;
        self
    }

    /// Sign for `region`.
    #[must_use]
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = region.into();
        self
    }

    /// Request `sse` on every `PUT`.
    #[must_use]
    pub fn with_sse(mut self, sse: Sse) -> Self {
        self.sse = Some(sse);
        self
    }

    /// Check the settings against the capabilities of [`S3Config::profile`].
    ///
    /// # Errors
    ///
    /// The first [`S3ConfigError`] found: a missing or malformed endpoint, plain `http` to an
    /// untrusted host, an empty region, unsupported or unopted encryption, object lock on a
    /// profile without it, or a checksum mode the profile does not accept.
    pub fn validate(&self) -> Result<(), S3ConfigError> {
        let caps = self.profile.capabilities();
        match &self.endpoint {
            None if caps.endpoint_required => {
                return Err(S3ConfigError::EndpointRequired {
                    profile: self.profile,
                });
            }
            None => {}
            Some(endpoint) => self.check_endpoint(endpoint, caps.plain_http)?,
        }
        if self.region.trim().is_empty() {
            return Err(S3ConfigError::RegionEmpty);
        }
        if normalize_prefix(&self.prefix)? != self.prefix {
            return Err(S3ConfigError::PrefixInvalid(self.prefix.clone()));
        }
        if let Some(sse) = &self.sse {
            let supported = match sse {
                Sse::Aes256 => caps.sse_aes256,
                Sse::CloudKms { .. } => caps.sse_kms,
            };
            if !supported {
                return Err(S3ConfigError::SseRefused {
                    profile: self.profile,
                    sse: sse.label(),
                });
            }
            if matches!(sse, Sse::CloudKms { .. }) && caps.kms_needs_opt_in && !self.allow_kms {
                return Err(S3ConfigError::KmsNotAllowed {
                    profile: self.profile,
                });
            }
        }
        if self.object_lock && !caps.object_lock {
            return Err(S3ConfigError::ObjectLockRefused {
                profile: self.profile,
            });
        }
        if self.checksum == ChecksumMode::WhenSupported && !caps.extended_checksums {
            return Err(S3ConfigError::ChecksumRefused {
                profile: self.profile,
                mode: self.checksum,
            });
        }
        Ok(())
    }

    fn check_endpoint(&self, endpoint: &str, policy: PlainHttp) -> Result<(), S3ConfigError> {
        let url =
            url::Url::parse(endpoint.trim()).map_err(|e| S3ConfigError::EndpointInvalid(format!("{e}")))?;
        let host = url
            .host()
            .ok_or_else(|| S3ConfigError::EndpointInvalid("no host".to_owned()))?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(S3ConfigError::EndpointInvalid(
                "credentials, query and fragment are not allowed".to_owned(),
            ));
        }
        match url.scheme() {
            "https" => Ok(()),
            "http" => {
                let trusted = match policy {
                    PlainHttp::Unrestricted => true,
                    PlainHttp::PrivateHostsOnly => is_private_host(&host),
                    PlainHttp::Refused => false,
                };
                if trusted || self.allow_http {
                    Ok(())
                } else {
                    Err(S3ConfigError::PlainHttpRefused {
                        profile: self.profile,
                        host: host.to_string(),
                    })
                }
            }
            other => Err(S3ConfigError::EndpointInvalid(format!(
                "scheme {other:?} is not http or https"
            ))),
        }
    }
}

fn non_blank(get: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    get(name).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

fn parse_bool(var: &'static str, value: &str) -> Result<bool, S3ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(S3ConfigError::InvalidValue {
            var,
            value: value.trim().to_owned(),
            expected: "1, true, yes, on, 0, false, no or off",
        }),
    }
}

/// Loopback and private-range addresses, `localhost`, single-label names and the
/// local-network suffixes `.localhost`, `.local`, `.lan`, `.internal` and `.home.arpa`.
fn is_private_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Ipv4(ip) => private_v4(*ip),
        url::Host::Ipv6(ip) => private_v6(*ip),
        url::Host::Domain(name) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            !name.contains('.')
                || [".localhost", ".local", ".lan", ".internal", ".home.arpa"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix))
        }
    }
}

fn private_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local()
}

fn private_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return private_v4(v4);
    }
    let first = ip.segments()[0];
    ip.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
}

/// [`ArtifactBlobs`] over an S3-compatible bucket.
#[derive(Clone, Debug)]
pub struct S3Blobs {
    client: Client,
    bucket: String,
    sse: Option<Sse>,
    profile: S3Profile,
    object_lock: bool,
    prefix: String,
}

impl S3Blobs {
    /// Backend with credentials from the environment.
    ///
    /// # Errors
    ///
    /// [`S3ConfigError`] when `config` fails [`S3Config::validate`].
    pub fn new(config: &S3Config) -> Result<Self, S3ConfigError> {
        Self::build(
            config,
            SharedCredentialsProvider::new(EnvironmentVariableCredentialsProvider::new()),
        )
    }

    /// Backend with explicit static credentials (tests, local servers).
    ///
    /// # Errors
    ///
    /// [`S3ConfigError`] when `config` fails [`S3Config::validate`].
    pub fn with_credentials(config: &S3Config, credentials: Credentials) -> Result<Self, S3ConfigError> {
        Self::build(config, SharedCredentialsProvider::new(credentials))
    }

    fn build(config: &S3Config, credentials: SharedCredentialsProvider) -> Result<Self, S3ConfigError> {
        config.validate()?;
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::Ring))
            .build_https();
        // WhenRequired keeps CRC32 trailers (chunked trailer encoding) off the wire: not every
        // S3-compatible store understands them, and artifact integrity is covered by the
        // blake3 digest in the artifact row. Only profiles that allow it get WhenSupported.
        let (calculation, validation) = match config.checksum {
            ChecksumMode::WhenRequired => (
                RequestChecksumCalculation::WhenRequired,
                ResponseChecksumValidation::WhenRequired,
            ),
            ChecksumMode::WhenSupported => (
                RequestChecksumCalculation::WhenSupported,
                ResponseChecksumValidation::WhenSupported,
            ),
        };
        let mut builder = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region.trim().to_owned()))
            .credentials_provider(credentials)
            .http_client(http)
            .force_path_style(config.path_style)
            .request_checksum_calculation(calculation)
            .response_checksum_validation(validation)
            .retry_config(RetryConfig::standard().with_max_attempts(config.max_attempts.max(1)))
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_attempt_timeout(config.attempt_timeout)
                    .build(),
            );
        if let Some(endpoint) = &config.endpoint {
            builder = builder.endpoint_url(endpoint.trim().to_owned());
        }
        Ok(Self {
            client: Client::from_conf(builder.build()),
            bucket: config.bucket.clone(),
            sse: config.sse.clone(),
            profile: config.profile,
            object_lock: config.object_lock,
            prefix: config.prefix.clone(),
        })
    }

    /// The SDK client (for bucket administration in tests and tooling).
    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.client
    }

    /// The object key of the logical `key`: the deployment prefix, then the key.
    fn full(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }

    /// The profile this backend was built for.
    #[must_use]
    pub const fn profile(&self) -> S3Profile {
        self.profile
    }

    /// A `PutObject` for `key` with the configured encryption and, on an object-lock bucket,
    /// the CRC32 checksum the lock requires.
    fn put_request(&self, key: &str) -> PutObjectFluentBuilder {
        let mut request = self.client.put_object().bucket(&self.bucket).key(self.full(key));
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
        if self.object_lock {
            request = request.checksum_algorithm(ChecksumAlgorithm::Crc32);
        }
        request
    }

    /// Refuse an object a single `PutObject` cannot carry on this profile.
    fn check_single_put(&self, key: &str, size: u64) -> Result<(), StoreError> {
        let max = self.profile.capabilities().single_put_max_bytes;
        if size > max {
            return Err(StoreError::Conflict(format!(
                "s3 put {key}: {size} bytes exceed the {max} byte single-put limit of the {} profile (multipart upload is not implemented)",
                self.profile
            )));
        }
        Ok(())
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
            .key(self.full(key))
            .send()
            .await
            .map_err(|e| sdk_error("get", key, &e))?;
        Ok(Box::new(output.body.into_async_read()))
    }
    async fn put_file(&self, key: &str, file: &std::path::Path, size: u64) -> Result<(), StoreError> {
        // The SDK retries from the file; it does not buffer the archive in memory.
        self.check_single_put(key, size)?;
        let body = ByteStream::from_path(file)
            .await
            .map_err(|e| StoreError::Unavailable(format!("archive upload source: {e}")))?;
        self.put_request(key)
            .content_length(i64::try_from(size).map_err(|_| StoreError::Conflict("archive size".into()))?)
            .body(body)
            .send()
            .await
            .map_err(|e| sdk_error("put", key, &e))?;
        Ok(())
    }

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.put_shared(key, Bytes::copy_from_slice(bytes)).await
    }

    async fn put_shared(&self, key: &str, bytes: Bytes) -> Result<(), StoreError> {
        let size = u64::try_from(bytes.len())
            .map_err(|_| StoreError::Serialization(format!("object {key} too large for content-length")))?;
        self.check_single_put(key, size)?;
        self.put_request(key)
            .content_length(i64::try_from(size).map_err(|_| {
                StoreError::Serialization(format!("object {key} too large for content-length"))
            })?)
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(|e| sdk_error("put", key, &e))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let out = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.full(key))
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
            .key(self.full(key))
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
            .key(self.full(key))
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
            .prefix(self.full(prefix))
            .into_paginator()
            .send();
        let mut out = Vec::new();
        while let Some(page) = pages.next().await {
            let page = page.map_err(|e| sdk_error("list", prefix, &e))?;
            for object in page.contents() {
                let Some(key) = object.key().and_then(|k| k.strip_prefix(self.prefix.as_str())) else {
                    continue;
                };
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
            .key(self.full(key))
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

    fn private(endpoint: &str) -> bool {
        let url = url::Url::parse(endpoint).unwrap();
        is_private_host(&url.host().unwrap())
    }

    #[test]
    fn plain_http_trust_covers_loopback_private_and_local_names_only() {
        for trusted in [
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
            "http://10.1.2.3",
            "http://172.16.0.9",
            "http://192.168.1.20:9000",
            "http://169.254.10.1",
            "http://[fd12:3456::1]",
            "http://[fe80::1]",
            "http://[::ffff:192.168.0.1]",
            "http://localhost:9000",
            "http://objects.localhost",
            "http://store",
            "http://store.lan",
            "http://store.local.",
            "http://store.internal",
            "http://store.home.arpa",
        ] {
            assert!(private(trusted), "{trusted}");
        }
        for public in [
            "http://8.8.8.8",
            "http://172.32.0.1",
            "http://[2001:db8::1]",
            "http://objects.example.test",
            "http://lan.example.test",
        ] {
            assert!(!private(public), "{public}");
        }
    }

    #[test]
    fn single_put_limit_is_checked_before_any_request() {
        let cfg = S3Config::new("b", "us-east-1").with_endpoint("http://127.0.0.1:9");
        let credentials = Credentials::new("a", "s", None, None, "test");
        let blobs = S3Blobs::with_credentials(&cfg, credentials).unwrap();
        assert!(blobs.check_single_put("k", SINGLE_PUT_MAX_BYTES).is_ok());
        match blobs.check_single_put("k", SINGLE_PUT_MAX_BYTES + 1) {
            Err(StoreError::Conflict(msg)) => {
                assert!(
                    msg.contains("single-put limit") && msg.contains("standard"),
                    "{msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }
}
