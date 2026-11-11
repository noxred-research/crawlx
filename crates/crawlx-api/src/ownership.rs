//! Ownership challenge of an authorization record (ownership or control of an
//! internet target is proven by one of the proofs below).
//!
//! A record carries one [`OwnershipProof`]:
//!
//! * `dns_txt`: a TXT record at `_crawlx-authz.<host>` for **every** host of the target holds the
//!   record id;
//! * `well_known_file`: `/.well-known/crawlx-authorization` of **every** origin of the target
//!   holds the record id;
//! * `operator_signature`: an HMAC by a configured operator key over the record
//!   ([`crawlx_policy::attestation`]), checked offline; the only proof that covers
//!   `authorizedNetworks`.
//!
//! "Holds the record id" means: one line of the TXT string or of the file, trimmed, equals the
//! record's UUID (ASCII case-insensitive). The record id is random and unguessable, so a third
//! party cannot publish it for a target it does not control, and the id is part of what an
//! operator signature covers.
//!
//! The network is reached through an [`OwnershipProbe`]: [`NetworkProbe`] in production (system
//! DNS, and the `crawlx-fetch` [`Fetcher`] under a strict public-only egress policy), and
//! [`StaticProbe`] in tests and offline deployments. [`verify_ownership`] runs the proof of one
//! record and answers with [`OwnershipOutcome`].

use async_trait::async_trait;
use bytes::Bytes;
use crawlx_core::Timestamp;
use crawlx_fetch::{FetchConfig, FetchOptions, Fetcher, HickoryResolver, Resolver, RetryPolicy};
use crawlx_policy::attestation::OperatorKeys;
use crawlx_policy::authorization::{
    origin_string, AuthorizationRecord, OwnershipProof, DNS_CHALLENGE_LABEL, WELL_KNOWN_CHALLENGE_PATH,
};
use crawlx_policy::EgressPolicy;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Largest challenge file the network probe reads, in bytes. The file holds one UUID.
pub const MAX_CHALLENGE_BYTES: usize = 4096;

/// Most hosts (`dns_txt`) or origins (`well_known_file`) one record may ask the server to probe.
pub const MAX_CHALLENGES: usize = 64;

/// Probes of one record that run at the same time (a record is probed in batches of this size).
const PROBE_CONCURRENCY: usize = 8;

/// Redirect hops the network probe follows to the challenge file; each hop is re-checked against
/// the egress policy.
const MAX_REDIRECTS: usize = 3;

/// Why a probe could not tell whether a challenge is published (as opposed to "it is not").
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    /// A DNS lookup failed (timeout, SERVFAIL, no usable resolver).
    #[error("lookup of {name} failed: {reason}")]
    Lookup {
        /// The queried name.
        name: String,
        /// What went wrong.
        reason: String,
    },
    /// The well-known file could not be fetched (egress denied, refused, timeout, bad status,
    /// redirected away).
    #[error("fetching {url} failed: {reason}")]
    Fetch {
        /// The requested URL.
        url: String,
        /// What went wrong.
        reason: String,
    },
}

/// The network side of an ownership check, behind a trait so tests and offline deployments can
/// answer without a network.
#[async_trait]
pub trait OwnershipProbe: Send + Sync {
    /// The TXT strings published at `name` (one string per TXT record); empty when the name has
    /// none.
    ///
    /// # Errors
    /// [`ProbeError::Lookup`] when the answer is unknown (as opposed to "no such record").
    async fn txt(&self, name: &str) -> Result<Vec<String>, ProbeError>;

    /// The body of `/.well-known/crawlx-authorization` on the origin `origin_url`
    /// (`scheme://host[:port]`, as written in the record); `None` when the origin answers that
    /// the file does not exist.
    ///
    /// # Errors
    /// [`ProbeError::Fetch`] when the answer is unknown.
    async fn well_known(&self, origin_url: &str) -> Result<Option<String>, ProbeError>;
}

/// A probe that answers from a table: for tests and for deployments that must not reach the
/// network. Names and origins nobody set answer "no record" / "no file".
#[derive(Default)]
pub struct StaticProbe {
    inner: Mutex<StaticAnswers>,
}

#[derive(Default)]
struct StaticAnswers {
    txt: BTreeMap<String, Result<Vec<String>, String>>,
    files: BTreeMap<String, Result<String, String>>,
    queries: Vec<String>,
}

impl StaticProbe {
    /// A probe with no answers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish `values` as the TXT records of `name`.
    pub fn set_txt(&self, name: &str, values: &[&str]) {
        self.inner.lock().txt.insert(
            name.to_owned(),
            Ok(values.iter().map(|v| (*v).to_owned()).collect()),
        );
    }

    /// Publish `body` as the well-known challenge file of `origin` (`scheme://host[:port]`).
    pub fn set_well_known(&self, origin: &str, body: &str) {
        self.inner
            .lock()
            .files
            .insert(origin.to_owned(), Ok(body.to_owned()));
    }

    /// Make the TXT lookup of `name` fail with `reason`.
    pub fn fail_txt(&self, name: &str, reason: &str) {
        self.inner
            .lock()
            .txt
            .insert(name.to_owned(), Err(reason.to_owned()));
    }

    /// Make the fetch of the challenge file of `origin` fail with `reason`.
    pub fn fail_well_known(&self, origin: &str, reason: &str) {
        self.inner
            .lock()
            .files
            .insert(origin.to_owned(), Err(reason.to_owned()));
    }

    /// Forget every answer and query.
    pub fn clear(&self) {
        *self.inner.lock() = StaticAnswers::default();
    }

    /// The queries made so far, in order: `txt <name>` and `well-known <origin>`.
    #[must_use]
    pub fn queries(&self) -> Vec<String> {
        self.inner.lock().queries.clone()
    }
}

#[async_trait]
impl OwnershipProbe for StaticProbe {
    async fn txt(&self, name: &str) -> Result<Vec<String>, ProbeError> {
        let mut inner = self.inner.lock();
        inner.queries.push(format!("txt {name}"));
        match inner.txt.get(name) {
            Some(Ok(values)) => Ok(values.clone()),
            Some(Err(reason)) => Err(ProbeError::Lookup {
                name: name.to_owned(),
                reason: reason.clone(),
            }),
            None => Ok(Vec::new()),
        }
    }

    async fn well_known(&self, origin_url: &str) -> Result<Option<String>, ProbeError> {
        let mut inner = self.inner.lock();
        inner.queries.push(format!("well-known {origin_url}"));
        match inner.files.get(origin_url) {
            Some(Ok(body)) => Ok(Some(body.clone())),
            Some(Err(reason)) => Err(ProbeError::Fetch {
                url: origin_url.to_owned(),
                reason: reason.clone(),
            }),
            None => Ok(None),
        }
    }
}

/// The production probe: TXT lookups through the system resolver and the challenge file through
/// the `crawlx-fetch` [`Fetcher`] under a strict public-only [`EgressPolicy`]. Private, loopback,
/// link-local and metadata addresses are never contacted (not even when the name resolves to
/// one), every redirect hop is re-checked, a redirect to another host is refused, only ports 80
/// and 443 are used and the body is read up to [`MAX_CHALLENGE_BYTES`]. Resolver and client are
/// built on first use, so constructing the probe never fails and never touches the network.
#[derive(Default)]
pub struct NetworkProbe {
    inner: tokio::sync::OnceCell<NetworkInner>,
}

struct NetworkInner {
    resolver: Arc<HickoryResolver>,
    fetcher: Fetcher,
}

impl NetworkProbe {
    /// A probe on the system resolver configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A probe on an explicit resolver (tests point it at a local DNS server).
    ///
    /// # Errors
    /// [`ProbeError::Fetch`] when the HTTP client cannot be built.
    pub fn with_resolver(resolver: HickoryResolver) -> Result<Self, ProbeError> {
        let inner = Self::build(Arc::new(resolver))?;
        Ok(Self {
            inner: tokio::sync::OnceCell::new_with(Some(inner)),
        })
    }

    fn build(resolver: Arc<HickoryResolver>) -> Result<NetworkInner, ProbeError> {
        let cfg = FetchConfig {
            max_body_bytes: MAX_CHALLENGE_BYTES,
            max_redirects: MAX_REDIRECTS,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            retry: RetryPolicy {
                max_retries: 0,
                ..RetryPolicy::default()
            },
            ..FetchConfig::default()
        };
        let dns: Arc<dyn Resolver> = resolver.clone();
        let fetcher =
            Fetcher::new(cfg, Arc::new(EgressPolicy::new(false)), dns).map_err(|e| ProbeError::Fetch {
                url: String::new(),
                reason: format!("cannot build the HTTP client: {e}"),
            })?;
        Ok(NetworkInner { resolver, fetcher })
    }

    async fn ready(&self, what: &str) -> Result<&NetworkInner, ProbeError> {
        self.inner
            .get_or_try_init(|| async {
                let resolver = HickoryResolver::from_system_conf().map_err(|e| ProbeError::Lookup {
                    name: what.to_owned(),
                    reason: e.to_string(),
                })?;
                Self::build(Arc::new(resolver))
            })
            .await
    }
}

#[async_trait]
impl OwnershipProbe for NetworkProbe {
    async fn txt(&self, name: &str) -> Result<Vec<String>, ProbeError> {
        let inner = self.ready(name).await?;
        inner
            .resolver
            .txt_lookup(name)
            .await
            .map_err(|e| ProbeError::Lookup {
                name: name.to_owned(),
                reason: e.to_string(),
            })
    }

    async fn well_known(&self, origin_url: &str) -> Result<Option<String>, ProbeError> {
        let fail = |reason: String| ProbeError::Fetch {
            url: format!("{origin_url}{WELL_KNOWN_CHALLENGE_PATH}"),
            reason,
        };
        let origin = Url::parse(origin_url).map_err(|e| fail(format!("not a URL: {e}")))?;
        if !matches!(origin.scheme(), "http" | "https") {
            return Err(fail("only http and https origins can serve the file".to_owned()));
        }
        let url = origin
            .join(WELL_KNOWN_CHALLENGE_PATH)
            .map_err(|e| fail(e.to_string()))?;
        let inner = self.ready(origin_url).await?;
        let opts = FetchOptions {
            max_body_bytes: Some(MAX_CHALLENGE_BYTES),
            max_redirects: Some(MAX_REDIRECTS),
            capture: false,
            ..FetchOptions::default()
        };
        let response = inner
            .fetcher
            .fetch(&url, &opts)
            .await
            .map_err(|e| fail(e.to_string()))?;
        // the owner of the host answers for the host: a redirect may change the scheme or the
        // path, never the host
        if response.final_url.host() != url.host() {
            return Err(fail("redirected to another host".to_owned()));
        }
        let status = response.status.as_u16();
        match status {
            200..=299 => Ok(Some(text(&response.body))),
            404 | 410 => Ok(None),
            other => Err(fail(format!("status {other}"))),
        }
    }
}

fn text(body: &Bytes) -> String {
    String::from_utf8_lossy(body).into_owned()
}

/// One proof requirement that did not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipFailure {
    /// The host, origin or key the requirement concerns (`app.example.test`,
    /// `https://app.example.test`, `ops-1`; `ownership` for the proof as a whole).
    pub subject: String,
    /// Why it did not hold.
    pub reason: String,
}

impl OwnershipFailure {
    fn new(subject: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            reason: reason.into(),
        }
    }
}

/// Result of [`verify_ownership`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum OwnershipOutcome {
    /// Every requirement of the proof held.
    Verified {
        /// What was checked, as stored in `authorization_records.verification`:
        /// `{kind, checkedAt, hosts}` for `dns_txt`, `{kind, checkedAt, hosts, origins}` for
        /// `well_known_file`, `{kind, checkedAt, keyId}` for `operator_signature`.
        verification: Value,
    },
    /// At least one requirement did not hold; every failing host or origin is listed.
    Unverified {
        /// One entry per failing requirement.
        failures: Vec<OwnershipFailure>,
    },
}

/// Does one line of `text`, trimmed, equal the record id `id` (ASCII case-insensitive)?
#[must_use]
pub fn holds_challenge(text: &str, id: &str) -> bool {
    text.lines().any(|line| line.trim().eq_ignore_ascii_case(id))
}

/// The distinct origins (`scheme://host[:port]`) of the record's `origins` and `urlPrefixes`, in
/// order. Entries that are not URLs are skipped: `validate()` rejects them.
fn origins_of(record: &AuthorizationRecord) -> Vec<String> {
    let mut seen = BTreeSet::new();
    record
        .origins
        .iter()
        .chain(record.url_prefixes.iter())
        .filter_map(|o| Url::parse(o).ok())
        .map(|u| origin_string(&u))
        .filter(|o| seen.insert(o.clone()))
        .collect()
}

/// Check the ownership proof of `record` at `now`. `record.ownership == None` never verifies.
/// The probe is asked once per host (`dns_txt`) or origin (`well_known_file`), a few at a time
/// ([`MAX_CHALLENGES`] at most); an operator signature is checked against `keys` offline.
pub async fn verify_ownership(
    record: &AuthorizationRecord,
    keys: &OperatorKeys,
    probe: &dyn OwnershipProbe,
    now: Timestamp,
) -> OwnershipOutcome {
    let id = record.id.to_string();
    match &record.ownership {
        None => OwnershipOutcome::Unverified {
            failures: vec![OwnershipFailure::new(
                "ownership",
                "the record carries no ownership proof",
            )],
        },
        Some(OwnershipProof::OperatorSignature { key_id, .. }) if keys.is_empty() => {
            OwnershipOutcome::Unverified {
                failures: vec![OwnershipFailure::new(
                    key_id.clone(),
                    "this API holds no operator keys: set CRAWLX_AUTHZ_OPERATOR_KEYS_FILE to a keys file \
                     containing this key id and restart it",
                )],
            }
        }
        Some(OwnershipProof::OperatorSignature { key_id, .. }) => match keys.verify(record) {
            Ok(()) => OwnershipOutcome::Verified {
                verification: json!({ "kind": "operator_signature", "checkedAt": now, "keyId": key_id }),
            },
            Err(e) => OwnershipOutcome::Unverified {
                failures: vec![OwnershipFailure::new(key_id.clone(), e.to_string())],
            },
        },
        Some(OwnershipProof::DnsTxt {}) => {
            let hosts = record.challenge_hosts();
            if let Some(failure) = too_many(hosts.len(), "hosts") {
                return OwnershipOutcome::Unverified {
                    failures: vec![failure],
                };
            }
            let mut failures = Vec::new();
            for batch in hosts.chunks(PROBE_CONCURRENCY) {
                let checks = batch.iter().map(|host| check_dns(probe, host, &id));
                failures.extend(futures::future::join_all(checks).await.into_iter().flatten());
            }
            finish(
                failures,
                json!({ "kind": "dns_txt", "checkedAt": now, "hosts": hosts }),
            )
        }
        Some(OwnershipProof::WellKnownFile {}) => {
            let origins = origins_of(record);
            if let Some(failure) = too_many(origins.len(), "origins") {
                return OwnershipOutcome::Unverified {
                    failures: vec![failure],
                };
            }
            let mut failures = Vec::new();
            for batch in origins.chunks(PROBE_CONCURRENCY) {
                let checks = batch.iter().map(|origin| check_file(probe, origin, &id));
                failures.extend(futures::future::join_all(checks).await.into_iter().flatten());
            }
            finish(
                failures,
                json!({
                    "kind": "well_known_file",
                    "checkedAt": now,
                    "hosts": record.challenge_hosts(),
                    "origins": origins,
                }),
            )
        }
        // `OwnershipProof` is non-exhaustive: a proof kind this build does not know cannot verify
        Some(_) => OwnershipOutcome::Unverified {
            failures: vec![OwnershipFailure::new(
                "ownership",
                "this build does not support the proof kind",
            )],
        },
    }
}

/// A record that names more than [`MAX_CHALLENGES`] hosts or origins cannot be probed.
fn too_many(count: usize, what: &str) -> Option<OwnershipFailure> {
    (count > MAX_CHALLENGES).then(|| {
        OwnershipFailure::new(
            "ownership",
            format!("the record names {count} {what}; at most {MAX_CHALLENGES} can be proven by probing"),
        )
    })
}

fn finish(failures: Vec<OwnershipFailure>, verification: Value) -> OwnershipOutcome {
    if failures.is_empty() {
        OwnershipOutcome::Verified { verification }
    } else {
        OwnershipOutcome::Unverified { failures }
    }
}

async fn check_dns(probe: &dyn OwnershipProbe, host: &str, id: &str) -> Option<OwnershipFailure> {
    if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        return Some(OwnershipFailure::new(
            host,
            "an IP address has no DNS name to carry a TXT challenge; use well_known_file or operator_signature",
        ));
    }
    let name = format!("{DNS_CHALLENGE_LABEL}.{host}");
    match probe.txt(&name).await {
        Ok(values) if values.iter().any(|v| holds_challenge(v, id)) => None,
        Ok(values) if values.is_empty() => Some(OwnershipFailure::new(
            host,
            format!("no TXT record at {name}; publish the record id there"),
        )),
        Ok(_) => Some(OwnershipFailure::new(
            host,
            format!("no TXT record at {name} holds the record id"),
        )),
        Err(e) => Some(OwnershipFailure::new(host, e.to_string())),
    }
}

async fn check_file(probe: &dyn OwnershipProbe, origin: &str, id: &str) -> Option<OwnershipFailure> {
    match probe.well_known(origin).await {
        Ok(Some(body)) if holds_challenge(&body, id) => None,
        Ok(Some(_)) => Some(OwnershipFailure::new(
            origin,
            format!("{WELL_KNOWN_CHALLENGE_PATH} does not hold the record id"),
        )),
        Ok(None) => Some(OwnershipFailure::new(
            origin,
            format!("no file at {WELL_KNOWN_CHALLENGE_PATH}; publish the record id there"),
        )),
        Err(e) => Some(OwnershipFailure::new(origin, e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::TenantId;
    use crawlx_policy::testkit::sample_record;

    fn now() -> Timestamp {
        chrono::Utc::now()
    }

    fn record(ownership: OwnershipProof, origins: &[&str]) -> AuthorizationRecord {
        let mut r = sample_record(TenantId::new(), now(), origins);
        r.ownership = Some(ownership);
        r
    }

    fn keys() -> OperatorKeys {
        OperatorKeys::parse("ops-1 00112233445566778899aabbccddeeff\n").unwrap()
    }

    #[test]
    fn a_challenge_is_a_trimmed_line_equal_to_the_id() {
        let id = "0198a0e2-7c1d-7a41-8f3e-5b1c9d2e4f60";
        assert!(holds_challenge(id, id));
        assert!(holds_challenge(&format!("  {id}\r\n"), id));
        assert!(holds_challenge(&format!("# crawlx\n{id}\n"), id));
        assert!(holds_challenge(&id.to_ascii_uppercase(), id));
        assert!(
            !holds_challenge(&format!("id={id}"), id),
            "a substring is not a line"
        );
        assert!(!holds_challenge(&format!("{id} extra"), id));
        assert!(!holds_challenge("", id));
        assert!(!holds_challenge("0198a0e2-7c1d-7a41-8f3e-5b1c9d2e4f61", id));
    }

    #[tokio::test]
    async fn dns_proof_needs_every_host() {
        let r = record(
            OwnershipProof::DnsTxt {},
            &["https://app.example.test", "https://api.example.test:8443"],
        );
        let probe = StaticProbe::new();
        probe.set_txt("_crawlx-authz.app.example.test", &[&r.id.to_string()]);
        let outcome = verify_ownership(&r, &keys(), &probe, now()).await;
        let OwnershipOutcome::Unverified { failures } = outcome else {
            panic!("api.example.test has no challenge");
        };
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].subject, "api.example.test");
        assert!(failures[0].reason.contains("_crawlx-authz.api.example.test"));

        probe.set_txt(
            "_crawlx-authz.api.example.test",
            &["unrelated", &r.id.to_string()],
        );
        let OwnershipOutcome::Verified { verification } = verify_ownership(&r, &keys(), &probe, now()).await
        else {
            panic!("both hosts publish the id");
        };
        assert_eq!(verification["kind"], "dns_txt");
        assert_eq!(
            verification["hosts"],
            json!(["api.example.test", "app.example.test"])
        );
        assert!(verification["checkedAt"].is_string());
    }

    #[tokio::test]
    async fn dns_failures_say_why_per_host() {
        let r = record(
            OwnershipProof::DnsTxt {},
            &[
                "https://a.example.test",
                "https://b.example.test",
                "https://203.0.113.9",
            ],
        );
        let probe = StaticProbe::new();
        probe.set_txt("_crawlx-authz.a.example.test", &["someone else's value"]);
        probe.fail_txt("_crawlx-authz.b.example.test", "timed out");
        let OwnershipOutcome::Unverified { failures } = verify_ownership(&r, &keys(), &probe, now()).await
        else {
            panic!("nothing verifies");
        };
        let by: BTreeMap<_, _> = failures
            .iter()
            .map(|f| (f.subject.as_str(), f.reason.as_str()))
            .collect();
        assert!(by["a.example.test"].contains("holds the record id"), "{by:?}");
        assert!(by["b.example.test"].contains("timed out"), "{by:?}");
        assert!(by["203.0.113.9"].contains("IP address"), "{by:?}");
        assert!(
            !probe.queries().iter().any(|q| q.contains("203.0.113.9")),
            "an IP literal is never queried"
        );
    }

    #[tokio::test]
    async fn well_known_proof_needs_every_origin_and_a_matching_line() {
        let mut r = record(OwnershipProof::WellKnownFile {}, &["https://app.example.test"]);
        r.url_prefixes = vec!["https://docs.example.test/guides/".to_owned()];
        let probe = StaticProbe::new();
        probe.set_well_known("https://app.example.test", &format!("{}\n", r.id));
        probe.set_well_known("https://docs.example.test", "not the id");
        let OwnershipOutcome::Unverified { failures } = verify_ownership(&r, &keys(), &probe, now()).await
        else {
            panic!("docs.example.test holds another value");
        };
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].subject, "https://docs.example.test");

        probe.set_well_known("https://docs.example.test", &format!("\n  {}  \n", r.id));
        let OwnershipOutcome::Verified { verification } = verify_ownership(&r, &keys(), &probe, now()).await
        else {
            panic!("both origins publish the id");
        };
        assert_eq!(verification["kind"], "well_known_file");
        assert_eq!(
            verification["origins"],
            json!(["https://app.example.test", "https://docs.example.test"])
        );

        probe.fail_well_known("https://app.example.test", "status 500");
        assert!(matches!(
            verify_ownership(&r, &keys(), &probe, now()).await,
            OwnershipOutcome::Unverified { .. }
        ));
    }

    #[tokio::test]
    async fn operator_signature_is_checked_offline() {
        let mut r = record(
            OwnershipProof::OperatorSignature {
                key_id: "ops-1".to_owned(),
                signature: String::new(),
            },
            &["https://app.example.test"],
        );
        r.ownership = Some(OwnershipProof::OperatorSignature {
            key_id: "ops-1".to_owned(),
            signature: keys().sign("ops-1", &r).unwrap(),
        });
        let probe = StaticProbe::new();
        let OwnershipOutcome::Verified { verification } = verify_ownership(&r, &keys(), &probe, now()).await
        else {
            panic!("a valid signature verifies");
        };
        assert_eq!(verification["keyId"], "ops-1");
        assert!(probe.queries().is_empty(), "no network involved");

        let mut tampered = r.clone();
        tampered.title = "edited after signing".to_owned();
        assert!(matches!(
            verify_ownership(&tampered, &keys(), &probe, now()).await,
            OwnershipOutcome::Unverified { .. }
        ));
        let OwnershipOutcome::Unverified { failures } =
            verify_ownership(&r, &OperatorKeys::new(), &probe, now()).await
        else {
            panic!("no operator keys never verifies");
        };
        assert!(
            failures[0].reason.contains("CRAWLX_AUTHZ_OPERATOR_KEYS_FILE"),
            "{}",
            failures[0].reason
        );
    }

    #[tokio::test]
    async fn a_record_cannot_ask_for_an_unbounded_number_of_probes() {
        let hosts: Vec<String> = (0..=MAX_CHALLENGES)
            .map(|n| format!("https://h{n}.example.test"))
            .collect();
        let origins: Vec<&str> = hosts.iter().map(String::as_str).collect();
        for proof in [OwnershipProof::DnsTxt {}, OwnershipProof::WellKnownFile {}] {
            let r = record(proof, &origins);
            let probe = StaticProbe::new();
            let OwnershipOutcome::Unverified { failures } =
                verify_ownership(&r, &keys(), &probe, now()).await
            else {
                panic!("too many hosts");
            };
            assert!(failures[0].reason.contains("at most 64"), "{failures:?}");
            assert!(probe.queries().is_empty(), "nothing was probed");
        }
    }

    #[tokio::test]
    async fn a_record_without_a_proof_never_verifies() {
        let mut r = record(OwnershipProof::DnsTxt {}, &["https://app.example.test"]);
        r.ownership = None;
        assert!(matches!(
            verify_ownership(&r, &keys(), &StaticProbe::new(), now()).await,
            OwnershipOutcome::Unverified { .. }
        ));
    }
}
