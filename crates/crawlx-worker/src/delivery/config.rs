//! Strict operator registry file. Crawl manifests can reference IDs, never these endpoint/secret fields.

use super::*;
use crawlx_core::secret::{CredentialRef, SecretResolver};
use serde::Deserialize;
use tokio::io::AsyncReadExt;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryFile {
    version: u16,
    destinations: Vec<DestinationSpec>,
}
#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Stdout,
    Local,
    S3,
    Http,
    SearchUpdate,
    SearchIndex,
    StreamRestV2,
    QueueHttpV1,
    ObjectJsonUpload,
    FtpServiceV1,
    Opensearch,
    Elasticsearch,
    Clickhouse,
    Kafka,
    Amqp,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DestinationSpec {
    id: String,
    kind: Kind,
    root: Option<PathBuf>,
    prefix: Option<String>,
    endpoint: Option<Url>,
    #[serde(default)]
    addresses: Vec<SocketAddr>,
    #[serde(default)]
    headers: BTreeMap<String, CredentialRef>,
    #[serde(default)]
    allows_zdr: bool,
    /// Search kinds: index name prefix of the deployment (default `crawlx-`).
    index_prefix: Option<String>,
    /// Search kinds: index (after the prefix) the feed is written to.
    index: Option<String>,
    /// ClickHouse: database of the deployment (default `crawlx`).
    database: Option<String>,
    /// ClickHouse: table (inside the database) the feed is appended to.
    table: Option<String>,
    /// Kafka: `host:port` bootstrap brokers.
    #[serde(default)]
    brokers: Vec<String>,
    /// Kafka: topic (after the prefix) the feed is produced to. AMQP: queue (after the prefix).
    topic: Option<String>,
    /// Kafka: topic name prefix of the deployment (default `crawlx.`). AMQP: exchange and queue
    /// prefix (default `crawlx.`).
    name_prefix: Option<String>,
    /// Kafka: partitions of a topic this sink has to create (default 1).
    partitions: Option<i32>,
    /// Kafka: replication factor of a topic this sink has to create (default 1).
    replication_factor: Option<i16>,
    /// Kafka: TLS to the brokers (AMQP takes `amqps` from the endpoint scheme).
    #[serde(default)]
    tls: bool,
    /// Kafka (SASL/PLAIN) and AMQP: `username` and `password` credential references.
    #[serde(default)]
    credentials: BTreeMap<String, CredentialRef>,
}

/// Registry fields a kind accepts besides `id` and `kind`. Anything else set on a spec is
/// refused, never ignored.
fn allowed_fields(kind: &Kind) -> &'static [&'static str] {
    match kind {
        Kind::Opensearch | Kind::Elasticsearch => &["endpoint", "headers", "indexPrefix", "index"],
        Kind::Clickhouse => &["endpoint", "headers", "database", "table"],
        Kind::Kafka => &[
            "brokers",
            "topic",
            "namePrefix",
            "partitions",
            "replicationFactor",
            "tls",
            "credentials",
        ],
        Kind::Amqp => &["endpoint", "topic", "namePrefix", "credentials"],
        _ => &[],
    }
}

/// Names of the infrastructure-sink fields `spec` sets.
fn set_sink_fields(spec: &DestinationSpec) -> Vec<&'static str> {
    let mut set = Vec::new();
    for (name, present) in [
        ("indexPrefix", spec.index_prefix.is_some()),
        ("index", spec.index.is_some()),
        ("database", spec.database.is_some()),
        ("table", spec.table.is_some()),
        ("brokers", !spec.brokers.is_empty()),
        ("topic", spec.topic.is_some()),
        ("namePrefix", spec.name_prefix.is_some()),
        ("partitions", spec.partitions.is_some()),
        ("replicationFactor", spec.replication_factor.is_some()),
        ("tls", spec.tls),
        ("credentials", !spec.credentials.is_empty()),
    ] {
        if present {
            set.push(name);
        }
    }
    set
}

fn is_infrastructure(kind: &Kind) -> bool {
    matches!(
        kind,
        Kind::Opensearch | Kind::Elasticsearch | Kind::Clickhouse | Kind::Kafka | Kind::Amqp
    )
}

async fn resolve_headers(
    references: BTreeMap<String, CredentialRef>,
    secrets: &dyn SecretResolver,
) -> Result<HeaderMap, DeliveryError> {
    let mut headers = HeaderMap::new();
    for (name, reference) in references {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| DeliveryError::Unavailable("invalid_provider_header_name"))?;
        if reference.scheme().is_none() {
            return Err(DeliveryError::Unavailable(
                "provider_header_requires_credential_reference",
            ));
        }
        let secret = secrets
            .resolve(&reference)
            .await
            .map_err(DeliveryError::Credential)?;
        let mut value = HeaderValue::from_str(secret.expose())
            .map_err(|_| DeliveryError::Unavailable("invalid_provider_header_value"))?;
        value.set_sensitive(true);
        headers.insert(name, value);
    }
    Ok(headers)
}

/// `username` and `password` references resolved to their values; both or neither.
async fn resolve_login(
    mut references: BTreeMap<String, CredentialRef>,
    secrets: &dyn SecretResolver,
) -> Result<Option<(String, String)>, DeliveryError> {
    if references.is_empty() {
        return Ok(None);
    }
    let (Some(user), Some(password)) = (references.remove("username"), references.remove("password")) else {
        return Err(DeliveryError::Unavailable(
            "credentials_need_username_and_password",
        ));
    };
    if !references.is_empty() || user.scheme().is_none() || password.scheme().is_none() {
        return Err(DeliveryError::Unavailable(
            "provider_header_requires_credential_reference",
        ));
    }
    let user = secrets.resolve(&user).await.map_err(DeliveryError::Credential)?;
    let password = secrets
        .resolve(&password)
        .await
        .map_err(DeliveryError::Credential)?;
    Ok(Some((user.expose().clone(), password.expose().clone())))
}

/// Build one infrastructure sink from its registry entry.
async fn infrastructure_destination(
    spec: DestinationSpec,
    secrets: &dyn SecretResolver,
) -> Result<Arc<dyn DeliveryDestination>, DeliveryError> {
    use super::backends::{
        connection_uri, valid_amqp_name, AmqpDestination, AmqpSettings, ClickHouseDestination,
        KafkaDestination, KafkaSettings, SearchDestination, SearchEngine, DEFAULT_AMQP_PREFIX,
        DEFAULT_DATABASE, DEFAULT_INDEX_PREFIX, DEFAULT_TOPIC_PREFIX,
    };
    let allowed = allowed_fields(&spec.kind);
    let http_endpoint = matches!(
        spec.kind,
        Kind::Opensearch | Kind::Elasticsearch | Kind::Clickhouse | Kind::Amqp
    );
    let stray = spec.root.is_some()
        || spec.prefix.is_some()
        || spec.allows_zdr
        || !spec.addresses.is_empty()
        || (spec.endpoint.is_some() && !http_endpoint)
        || (!spec.headers.is_empty() && !allowed.contains(&"headers"))
        || set_sink_fields(&spec)
            .iter()
            .any(|field| !allowed.contains(field));
    if stray {
        return Err(DeliveryError::Unavailable(
            "infrastructure_registry_has_inapplicable_fields",
        ));
    }
    match spec.kind {
        Kind::Opensearch | Kind::Elasticsearch => {
            let engine = if matches!(spec.kind, Kind::Opensearch) {
                SearchEngine::OpenSearch
            } else {
                SearchEngine::Elasticsearch
            };
            let headers = resolve_headers(spec.headers, secrets).await?;
            Ok(Arc::new(SearchDestination::new(
                spec.endpoint
                    .ok_or(DeliveryError::Unavailable("provider_endpoint_required"))?,
                headers,
                engine,
                spec.index_prefix.as_deref().unwrap_or(DEFAULT_INDEX_PREFIX),
                spec.index
                    .as_deref()
                    .ok_or(DeliveryError::Unavailable("search_index_required"))?,
            )?))
        }
        Kind::Clickhouse => {
            let headers = resolve_headers(spec.headers, secrets).await?;
            Ok(Arc::new(ClickHouseDestination::new(
                spec.endpoint
                    .ok_or(DeliveryError::Unavailable("provider_endpoint_required"))?,
                headers,
                spec.database.as_deref().unwrap_or(DEFAULT_DATABASE),
                spec.table
                    .as_deref()
                    .ok_or(DeliveryError::Unavailable("clickhouse_table_required"))?,
            )?))
        }
        Kind::Kafka => {
            let sasl = resolve_login(spec.credentials, secrets).await?;
            let prefix = spec.name_prefix.as_deref().unwrap_or(DEFAULT_TOPIC_PREFIX);
            let topic = spec
                .topic
                .as_deref()
                .ok_or(DeliveryError::Unavailable("kafka_topic_required"))?;
            Ok(Arc::new(KafkaDestination::new(KafkaSettings {
                brokers: spec.brokers,
                topic: format!("{prefix}{topic}"),
                tls: spec.tls,
                sasl,
                partitions: spec.partitions.unwrap_or(1),
                replication_factor: spec.replication_factor.unwrap_or(1),
            })?))
        }
        Kind::Amqp => {
            let login = resolve_login(spec.credentials, secrets).await?;
            let endpoint = spec
                .endpoint
                .ok_or(DeliveryError::Unavailable("provider_endpoint_required"))?;
            let prefix = spec.name_prefix.as_deref().unwrap_or(DEFAULT_AMQP_PREFIX);
            let queue = spec
                .topic
                .as_deref()
                .ok_or(DeliveryError::Unavailable("amqp_queue_required"))?;
            if !valid_amqp_name(queue) || (!prefix.is_empty() && !valid_amqp_name(prefix)) {
                return Err(DeliveryError::Unavailable("invalid_amqp_name"));
            }
            Ok(Arc::new(AmqpDestination::new(AmqpSettings {
                uri: connection_uri(&endpoint, login.as_ref())?,
                exchange: format!("{prefix}{queue}"),
                queue: format!("{prefix}{queue}"),
            })?))
        }
        _ => Err(DeliveryError::Unavailable("invalid_provider_registry_kind")),
    }
}

impl DeliveryRegistry {
    /// Read a bounded strict registry and resolve approved credential references at startup.
    ///
    /// Missing/malformed files and unavailable secrets are errors, never an empty-registry fallback.
    /// HTTP producer protocols are explicitly named; native stream/queue/FTP clients are not claimed.
    ///
    /// # Errors
    /// Returns file, schema, credential, unsupported capability or destination-construction errors.
    pub async fn from_file(path: &Path, secrets: &dyn SecretResolver) -> Result<Self, DeliveryError> {
        let input = tokio::fs::File::open(path).await?;
        let mut bytes = Vec::new();
        input.take(1_048_577).read_to_end(&mut bytes).await?;
        if bytes.len() > 1_048_576 {
            return Err(DeliveryError::Unavailable("delivery_registry_file_too_large"));
        }
        let file: RegistryFile = serde_json::from_slice(&bytes)
            .map_err(|_| DeliveryError::Unavailable("invalid_delivery_registry_schema_or_provider"))?;
        if file.version != 1 || file.destinations.len() > 64 {
            return Err(DeliveryError::Unavailable(
                "unsupported_delivery_registry_version_or_bounds",
            ));
        }
        let mut registry = Self::new();
        for spec in file.destinations {
            if spec.addresses.len() > 16 || spec.headers.len() > 16 {
                return Err(DeliveryError::Unavailable("provider_registry_bounds"));
            }
            if !is_infrastructure(&spec.kind) && !set_sink_fields(&spec).is_empty() {
                return Err(DeliveryError::Unavailable(
                    "provider_registry_has_infrastructure_fields",
                ));
            }
            let id = spec.id.clone();
            let destination: Arc<dyn DeliveryDestination> = match spec.kind {
                Kind::Stdout => {
                    if spec.root.is_some()
                        || spec.prefix.is_some()
                        || spec.endpoint.is_some()
                        || !spec.addresses.is_empty()
                        || !spec.headers.is_empty()
                    {
                        return Err(DeliveryError::Unavailable(
                            "stdout_registry_has_inapplicable_fields",
                        ));
                    }
                    Arc::new(StdoutDestination::new(spec.allows_zdr))
                }
                Kind::Local => {
                    if spec.prefix.is_some()
                        || spec.endpoint.is_some()
                        || !spec.addresses.is_empty()
                        || !spec.headers.is_empty()
                        || spec.allows_zdr
                    {
                        return Err(DeliveryError::Unavailable(
                            "local_registry_has_inapplicable_fields",
                        ));
                    }
                    Arc::new(
                        LocalDestination::open(
                            spec.root
                                .as_deref()
                                .ok_or(DeliveryError::Unavailable("local_root_required"))?,
                        )
                        .await?,
                    )
                }
                Kind::S3 => {
                    if spec.root.is_some()
                        || spec.endpoint.is_some()
                        || !spec.addresses.is_empty()
                        || !spec.headers.is_empty()
                        || spec.allows_zdr
                    {
                        return Err(DeliveryError::Unavailable(
                            "s3_registry_reuses_existing_object_sink_only",
                        ));
                    }
                    let config = crawlx_storage::s3::S3Config::from_env()?;
                    Arc::new(S3Destination::new(
                        Arc::new(
                            crawlx_storage::s3::S3Blobs::new(&config)
                                .map_err(crawlx_core::StoreError::from)?,
                        ),
                        spec.prefix
                            .ok_or(DeliveryError::Unavailable("s3_prefix_required"))?,
                    )?)
                }
                kind if is_infrastructure(&kind) => infrastructure_destination(spec, secrets).await?,
                kind => {
                    if spec.root.is_some() || spec.prefix.is_some() {
                        return Err(DeliveryError::Unavailable(
                            "provider_registry_has_filesystem_fields",
                        ));
                    }
                    let protocol = match kind {
                        Kind::Http => HttpDeliveryProtocol::Http,
                        Kind::SearchUpdate => HttpDeliveryProtocol::SearchUpdate,
                        Kind::SearchIndex => HttpDeliveryProtocol::SearchIndex,
                        Kind::StreamRestV2 => HttpDeliveryProtocol::StreamRestV2,
                        Kind::QueueHttpV1 => HttpDeliveryProtocol::QueueHttpV1,
                        Kind::ObjectJsonUpload => HttpDeliveryProtocol::ObjectJsonUpload,
                        Kind::FtpServiceV1 => HttpDeliveryProtocol::FtpServiceV1,
                        _ => return Err(DeliveryError::Unavailable("invalid_provider_registry_kind")),
                    };
                    let mut headers = HeaderMap::new();
                    for (name, reference) in spec.headers {
                        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                            .map_err(|_| DeliveryError::Unavailable("invalid_provider_header_name"))?;
                        if reference.scheme().is_none() {
                            return Err(DeliveryError::Unavailable(
                                "provider_header_requires_credential_reference",
                            ));
                        }
                        let secret = secrets
                            .resolve(&reference)
                            .await
                            .map_err(DeliveryError::Credential)?;
                        let mut value = HeaderValue::from_str(secret.expose())
                            .map_err(|_| DeliveryError::Unavailable("invalid_provider_header_value"))?;
                        value.set_sensitive(true);
                        headers.insert(name, value);
                    }
                    Arc::new(HttpDestination::approved(
                        spec.endpoint
                            .ok_or(DeliveryError::Unavailable("provider_endpoint_required"))?,
                        &spec.addresses,
                        headers,
                        protocol,
                        spec.allows_zdr,
                    )?)
                }
            };
            registry.register(id, destination)?;
        }
        Ok(registry)
    }
}
