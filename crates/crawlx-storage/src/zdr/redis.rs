//! Atomic multi-node delivery on a dedicated Redis with persistence disabled.
//!
//! Lua serializes page mutation, aggregate bounds, oldest-first eviction, and index
//! deletion. Native page TTL is set only on first insertion and supplies the cleanup
//! backstop when every API/worker is down. Injected time controls API visibility and
//! explicit sweeps; Redis server time independently caps physical retention at one hour.

use super::{BufferLimits, BufferedBlob, BufferedPage, DEFAULT_TTL};
use ::redis::FromRedisValue;
use crawlx_core::{ArtifactId, ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const PREFIX: &str = "crawlx:zdr:{delivery}:page:";
const KEYS: [&str; 9] = [
    "crawlx:zdr:{delivery}:order",
    "crawlx:zdr:{delivery}:sizes",
    "crawlx:zdr:{delivery}:application-expiry",
    "crawlx:zdr:{delivery}:native-expiry",
    "crawlx:zdr:{delivery}:artifacts",
    "crawlx:zdr:{delivery}:page-artifacts",
    "crawlx:zdr:{delivery}:sequence",
    "crawlx:zdr:{delivery}:limits",
    "crawlx:zdr:{delivery}:bytes",
];
const SCRIPT: &str = include_str!("redis.lua");

// Strings preserve i64 page ids exactly; Lua/cjson numeric values cannot do that.
type PageWire = (
    String,
    String,
    String,
    String,
    String,
    Vec<(String, String, Vec<u8>)>,
);

#[derive(Serialize, Deserialize)]
struct BlobMetadata {
    artifact: ArtifactRef,
    content_type: String,
}

pub(super) struct RedisPages {
    connection: ::redis::aio::MultiplexedConnection,
    limits: BufferLimits,
}

struct Request<'a> {
    action: &'static str,
    now: Timestamp,
    tenant: Option<TenantId>,
    run: Option<CrawlRunId>,
    page: Option<i64>,
    kind: &'a str,
    wire: &'a str,
    bytes: &'a [u8],
    artifact: Option<ArtifactId>,
    size: usize,
    expires_at: Timestamp,
}

impl Request<'_> {
    fn new(action: &'static str, now: Timestamp) -> Self {
        Self {
            action,
            now,
            tenant: None,
            run: None,
            page: None,
            kind: "",
            wire: "",
            bytes: &[],
            artifact: None,
            size: 0,
            expires_at: now,
        }
    }
}

impl RedisPages {
    pub(super) async fn open(url: &str, limits: BufferLimits, now: Timestamp) -> Result<Self, StoreError> {
        // Redis Lua uses exact double integers for accounting and sorted-set scores.
        const MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_990;
        if u64::try_from(limits.max_bytes).map_err(serialization_error)? > MAX_EXACT_INTEGER
            || u64::try_from(limits.max_entries).map_err(serialization_error)? > MAX_EXACT_INTEGER
        {
            return Err(StoreError::RetentionDenied(
                "zdr redis limits exceed exact integer accounting".into(),
            ));
        }
        let client = ::redis::Client::open(url)
            .map_err(|_| StoreError::Backend("zdr redis connection configuration is invalid".into()))?;
        let config = ::redis::AsyncConnectionConfig::new()
            .set_connection_timeout(std::time::Duration::from_secs(10))
            .set_response_timeout(std::time::Duration::from_secs(30));
        let connection = client
            .get_multiplexed_async_connection_with_config(&config)
            .await
            .map_err(redis_error)?;
        let pages = Self { connection, limits };
        let _: u64 = pages.invoke(Request::new("startup", now)).await?;
        Ok(pages)
    }

    async fn validate_volatile(&self) -> Result<(), StoreError> {
        let mut connection = self.connection.clone();
        let (config, replication, persistence): (BTreeMap<String, String>, String, String) = ::redis::pipe()
            .cmd("CONFIG")
            .arg("GET")
            .arg(&["appendonly", "save", "maxmemory-policy"])
            .cmd("INFO")
            .arg("replication")
            .cmd("INFO")
            .arg("persistence")
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        let value = |name: &str| config.get(name).map(String::as_str);
        if value("appendonly") != Some("no")
            || value("save") != Some("")
            || value("maxmemory-policy") != Some("noeviction")
            || info_value(&replication, "role") != Some("master")
            || info_value(&replication, "connected_slaves") != Some("0")
            || info_value(&persistence, "aof_enabled") != Some("0")
            || info_value(&persistence, "rdb_bgsave_in_progress") != Some("0")
        {
            return Err(StoreError::RetentionDenied(
                "zdr redis requires disabled RDB/AOF, no replicas, and maxmemory-policy noeviction".into(),
            ));
        }
        Ok(())
    }

    async fn invoke<T: FromRedisValue>(&self, request: Request<'_>) -> Result<T, StoreError> {
        // Recheck before each operation, not only at startup. Deployment ACLs must
        // also deny CONFIG SET, SAVE/BGSAVE, REPLICAOF, and replica connections.
        self.validate_volatile().await?;
        let script = ::redis::Script::new(SCRIPT);
        let mut invocation = script.prepare_invoke();
        for key in KEYS {
            invocation.key(key);
        }
        let tenant = request.tenant.map(|id| id.to_string()).unwrap_or_default();
        let run = request.run.map(|id| id.to_string()).unwrap_or_default();
        let page = request.page.map(|id| id.to_string()).unwrap_or_default();
        let artifact = request.artifact.map(|id| id.to_string()).unwrap_or_default();
        let ttl_ms =
            u64::try_from(self.limits.ttl.min(DEFAULT_TTL).as_millis()).map_err(serialization_error)?;
        invocation
            .arg(request.action)
            .arg(request.now.timestamp_millis())
            .arg(self.limits.max_entries)
            .arg(self.limits.max_bytes)
            .arg(ttl_ms)
            .arg(PREFIX)
            .arg(tenant)
            .arg(run)
            .arg(page)
            .arg(request.kind)
            .arg(request.wire)
            .arg(artifact)
            .arg(request.size)
            .arg(request.now.to_rfc3339())
            .arg(request.expires_at.to_rfc3339())
            .arg(request.expires_at.timestamp_millis())
            .arg(request.bytes);
        let mut connection = self.connection.clone();
        invocation
            .invoke_async(&mut connection)
            .await
            .map_err(redis_error)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn insert(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        kind: String,
        content_type: String,
        bytes: Vec<u8>,
        now: Timestamp,
        expires_at: Timestamp,
    ) -> Result<ArtifactRef, StoreError> {
        let size = bytes.len();
        let (artifact, wire, bytes) = tokio::task::spawn_blocking(move || {
            let artifact = ArtifactRef {
                id: ArtifactId::new(),
                digest: crawlx_core::hash::Digest::of(crate::artifacts::DIGEST_DOMAIN, &bytes),
            };
            let metadata = BlobMetadata {
                artifact: artifact.clone(),
                content_type,
            };
            let wire = serde_json::to_string(&metadata).map_err(serialization_error)?;
            Ok::<_, StoreError>((artifact, wire, bytes))
        })
        .await
        .map_err(super::join_error)??;
        let mut request = Request::new("insert", now);
        request.tenant = Some(tenant);
        request.run = Some(run);
        request.page = Some(page);
        request.kind = &kind;
        request.wire = &wire;
        request.bytes = &bytes;
        request.artifact = Some(artifact.id);
        request.size = size;
        request.expires_at = expires_at;
        let result: String = self.invoke(request).await?;
        match result.as_str() {
            "OK" => Ok(artifact),
            "RENDITION_TOO_LARGE" | "PAGE_TOO_LARGE" | "METADATA_TOO_LARGE" => Err(
                StoreError::RetentionDenied("zdr redis page exceeds buffer capacity".into()),
            ),
            _ => Err(StoreError::Backend("unexpected zdr redis insert result".into())),
        }
    }

    pub(super) async fn get(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        now: Timestamp,
    ) -> Result<Option<BufferedPage>, StoreError> {
        let mut request = Request::new("get", now);
        request.tenant = Some(tenant);
        request.run = Some(run);
        request.page = Some(page);
        let wire: Option<PageWire> = self.invoke(request).await?;
        let decoded = tokio::task::spawn_blocking(move || wire.map(decode_page).transpose())
            .await
            .map_err(super::join_error)??;
        if decoded
            .as_ref()
            .is_some_and(|p| (p.tenant, p.run, p.page) != (tenant, run, page))
        {
            return Err(serialization_error(
                "redis page scope does not match requested scope",
            ));
        }
        Ok(decoded)
    }

    pub(super) async fn content_metadata(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        artifact: &ArtifactRef,
        now: Timestamp,
    ) -> Result<Option<(Timestamp, u64)>, StoreError> {
        let mut request = Request::new("content_metadata", now);
        request.tenant = Some(tenant);
        request.run = Some(run);
        request.page = Some(page);
        request.artifact = Some(artifact.id);
        let metadata: Option<(String, String, u64)> = self.invoke(request).await?;
        metadata
            .map(|(deadline, wire, size)| {
                let reference: BlobMetadata = serde_json::from_str(&wire).map_err(serialization_error)?;
                let deadline = deadline.parse().map_err(serialization_error)?;
                Ok((reference.artifact == *artifact).then_some((deadline, size)))
            })
            .transpose()
            .map(Option::flatten)
    }

    pub(super) async fn content_deadline(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        artifact: ArtifactId,
        now: Timestamp,
    ) -> Result<Option<Timestamp>, StoreError> {
        let mut request = Request::new("content_deadline", now);
        request.tenant = Some(tenant);
        request.run = Some(run);
        request.page = Some(page);
        request.artifact = Some(artifact);
        let deadline: Option<String> = self.invoke(request).await?;
        deadline
            .map(|value| value.parse().map_err(serialization_error))
            .transpose()
    }

    pub(super) async fn list(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        now: Timestamp,
    ) -> Result<Vec<BufferedPage>, StoreError> {
        let mut request = Request::new("list", now);
        request.tenant = Some(tenant);
        request.run = Some(run);
        let wires: Vec<PageWire> = self.invoke(request).await?;
        tokio::task::spawn_blocking(move || {
            let mut pages = wires
                .into_iter()
                .map(decode_page)
                .collect::<Result<Vec<_>, _>>()?;
            if pages.iter().any(|page| (page.tenant, page.run) != (tenant, run)) {
                return Err(serialization_error(
                    "redis page scope does not match requested scope",
                ));
            }
            pages.sort_unstable_by_key(|page| page.page);
            Ok(pages)
        })
        .await
        .map_err(super::join_error)?
    }

    pub(super) async fn find(
        &self,
        scope: Option<(TenantId, CrawlRunId)>,
        id: ArtifactId,
        now: Timestamp,
    ) -> Result<Option<BufferedBlob>, StoreError> {
        self.find_limited(scope, id, now, usize::MAX).await
    }

    pub(super) async fn find_limited(
        &self,
        scope: Option<(TenantId, CrawlRunId)>,
        id: ArtifactId,
        now: Timestamp,
        max_bytes: usize,
    ) -> Result<Option<BufferedBlob>, StoreError> {
        let mut request = Request::new("find", now);
        if let Some((tenant, run)) = scope {
            request.tenant = Some(tenant);
            request.run = Some(run);
        }
        request.artifact = Some(id);
        request.size = max_bytes.min(self.limits.max_bytes);
        let wire: Option<(String, Vec<u8>)> = self.invoke(request).await?;
        tokio::task::spawn_blocking(move || {
            wire.map(|(metadata, bytes)| {
                let blob = decode_blob(&metadata, bytes)?;
                if blob.artifact.id != id {
                    return Err(serialization_error("redis artifact index does not match blob"));
                }
                Ok(blob)
            })
            .transpose()
        })
        .await
        .map_err(super::join_error)?
    }

    pub(super) async fn ack(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        now: Timestamp,
    ) -> Result<bool, StoreError> {
        let mut request = Request::new("ack", now);
        request.tenant = Some(tenant);
        request.run = Some(run);
        request.page = Some(page);
        let count: u64 = self.invoke(request).await?;
        Ok(count != 0)
    }

    pub(super) async fn purge(
        &self,
        tenant: Option<TenantId>,
        run: CrawlRunId,
        now: Timestamp,
    ) -> Result<u64, StoreError> {
        let mut request = Request::new(if tenant.is_some() { "purge" } else { "purge_run_id" }, now);
        request.tenant = tenant;
        request.run = Some(run);
        self.invoke(request).await
    }

    pub(super) async fn sweep(&self, now: Timestamp) -> Result<u64, StoreError> {
        self.invoke(Request::new("sweep", now)).await
    }

    pub(super) async fn stats(&self, now: Timestamp) -> Result<(usize, usize), StoreError> {
        self.invoke(Request::new("stats", now)).await
    }
}

fn decode_page(wire: PageWire) -> Result<BufferedPage, StoreError> {
    let (tenant, run, page, inserted_at, expires_at, entries) = wire;
    let mut blobs = BTreeMap::new();
    for (kind, wire, bytes) in entries {
        let blob = decode_blob(&wire, bytes)?;
        if blobs.insert(kind, blob).is_some() {
            return Err(serialization_error("duplicate redis rendition"));
        }
    }
    let page = BufferedPage {
        tenant: tenant.parse().map_err(serialization_error)?,
        run: run.parse().map_err(serialization_error)?,
        page: page.parse().map_err(serialization_error)?,
        inserted_at: inserted_at.parse().map_err(serialization_error)?,
        expires_at: expires_at.parse().map_err(serialization_error)?,
        blobs,
    };
    let latest = page
        .inserted_at
        .checked_add_signed(chrono::Duration::from_std(DEFAULT_TTL).map_err(serialization_error)?)
        .ok_or_else(|| serialization_error("redis page expiry overflows timestamp"))?;
    if page.expires_at < page.inserted_at || page.expires_at > latest || page.blobs.is_empty() {
        return Err(serialization_error("invalid redis page lifetime or renditions"));
    }
    Ok(page)
}

fn decode_blob(wire: &str, bytes: Vec<u8>) -> Result<BufferedBlob, StoreError> {
    let metadata: BlobMetadata = serde_json::from_str(wire).map_err(serialization_error)?;
    let blob = BufferedBlob {
        artifact: metadata.artifact,
        content_type: metadata.content_type,
        bytes,
    };
    validate_blob(&blob)?;
    Ok(blob)
}

fn validate_blob(blob: &BufferedBlob) -> Result<(), StoreError> {
    if blob.artifact.digest != crawlx_core::hash::Digest::of(crate::artifacts::DIGEST_DOMAIN, &blob.bytes) {
        return Err(serialization_error("redis blob digest does not match content"));
    }
    Ok(())
}

fn info_value<'a>(info: &'a str, name: &str) -> Option<&'a str> {
    info.lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(key, value)| (key == name).then_some(value.trim_end_matches('\r')))
}

fn redis_error(error: ::redis::RedisError) -> StoreError {
    // Never format the client/URL, server details, credentials, or returned values.
    StoreError::Backend(format!("zdr redis operation failed: {:?}", error.kind()))
}

fn serialization_error(_error: impl std::fmt::Display) -> StoreError {
    // Decoder messages may quote arbitrary sensitive strings from the payload.
    StoreError::Serialization("invalid zdr redis page encoding or metadata".into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn info_parser_handles_crlf_and_ignores_sections() {
        let info = "# Replication\r\nrole:master\r\nconnected_slaves:0\r\n";
        assert_eq!(info_value(info, "role"), Some("master"));
        assert_eq!(info_value(info, "connected_slaves"), Some("0"));
        assert_eq!(info_value(info, "missing"), None);
    }

    #[test]
    fn binary_content_and_minimum_page_id_round_trip_exactly() {
        let tenant = TenantId::new();
        let run = CrawlRunId::new();
        let bytes = vec![0, 255, 128, b'\n', b'"', 0];
        let artifact = ArtifactRef {
            id: ArtifactId::new(),
            digest: crawlx_core::hash::Digest::of(crate::artifacts::DIGEST_DOMAIN, &bytes),
        };
        let metadata = BlobMetadata {
            artifact: artifact.clone(),
            content_type: "application/octet-stream".into(),
        };
        let wire = (
            tenant.to_string(),
            run.to_string(),
            i64::MIN.to_string(),
            "2026-01-01T00:00:00Z".into(),
            "2026-01-01T01:00:00Z".into(),
            vec![(
                "run_config".into(),
                serde_json::to_string(&metadata).unwrap(),
                bytes.clone(),
            )],
        );
        let page = decode_page(wire).unwrap();
        assert_eq!(page.tenant, tenant);
        assert_eq!(page.run, run);
        assert_eq!(page.page, i64::MIN);
        assert_eq!(page.blobs["run_config"].bytes, bytes);
        assert_eq!(page.blobs["run_config"].artifact, artifact);
    }

    #[test]
    fn malformed_metadata_errors_do_not_quote_sensitive_payloads() {
        let error = decode_blob("sensitive-body-should-never-appear", Vec::new()).unwrap_err();
        assert!(!error.to_string().contains("sensitive-body-should-never-appear"));
    }
}
