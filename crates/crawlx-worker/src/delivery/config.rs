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
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Stdout,
    Local,
    S3,
    Http,
    Solr,
    Opensearch,
    KafkaRestV2,
    RabbitmqManagement,
    GcsJsonUpload,
    FtpServiceV1,
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
}
impl DeliveryRegistry {
    /// Read a bounded strict registry and resolve approved credential references at startup.
    ///
    /// Missing/malformed files and unavailable secrets are errors, never an empty-registry fallback.
    /// HTTP producer protocols are explicitly named; native Kafka/AMQP/FTP clients are not claimed.
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
                        Arc::new(crawlx_storage::s3::S3Blobs::new(&config)),
                        spec.prefix
                            .ok_or(DeliveryError::Unavailable("s3_prefix_required"))?,
                    )?)
                }
                kind => {
                    if spec.root.is_some() || spec.prefix.is_some() {
                        return Err(DeliveryError::Unavailable(
                            "provider_registry_has_filesystem_fields",
                        ));
                    }
                    let protocol = match kind {
                        Kind::Http => HttpDeliveryProtocol::Http,
                        Kind::Solr => HttpDeliveryProtocol::Solr,
                        Kind::Opensearch => HttpDeliveryProtocol::OpenSearch,
                        Kind::KafkaRestV2 => HttpDeliveryProtocol::KafkaRestV2,
                        Kind::RabbitmqManagement => HttpDeliveryProtocol::RabbitMqManagement,
                        Kind::GcsJsonUpload => HttpDeliveryProtocol::GcsJsonUpload,
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
            registry.register(spec.id, destination)?;
        }
        Ok(registry)
    }
}
