//! RabbitMQ (AMQP 0-9-1) sink with publisher confirms.
//!
//! Exchange and queue names live under a deployment prefix (default `crawlx.`) inside the
//! virtual host named by the endpoint path. The exchange (direct) and the durable queue are
//! declared on first use, each batch is one persistent message whose `message_id` is the batch
//! idempotency key, and the send returns only after the broker confirmed the publish and no
//! `mandatory` return came back. A retry after an unconfirmed send can deliver twice, so the sink
//! reports `duplicate_possible`; consumers deduplicate on `message_id`.

use crate::delivery::{DeliveryAuthority, DeliveryDestination, DeliveryError};
use async_trait::async_trait;
use bytes::Bytes;
use crawlx_core::config::RetentionMode;
use crawlx_core::dataset::DeliveryBatchV1;
use crawlx_core::repo::CrawlRun;
use lapin::options::{
    BasicPublishOptions, ConfirmSelectOptions, ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions,
};

use lapin::types::FieldTable;
use lapin::{BasicProperties, Channel, Confirmation, Connection, ConnectionProperties, ExchangeKind};
use tokio::sync::Mutex;
use url::Url;

/// Default exchange and queue prefix of a CrawlX deployment.
pub(crate) const DEFAULT_PREFIX: &str = "crawlx.";
/// Cooldown after a transport or broker failure.
const RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(30);
/// Largest message body sent.
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Exchange or queue name part: letters, digits and `. _ -`.
pub(crate) fn valid_name_part(text: &str) -> bool {
    (1..=100).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The connection URI: the endpoint with the resolved credentials set and an explicit vhost.
pub(crate) fn connection_uri(
    endpoint: &Url,
    credentials: Option<&(String, String)>,
) -> Result<String, DeliveryError> {
    if !matches!(endpoint.scheme(), "amqp" | "amqps")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path().len() <= 1
    {
        // the vhost must be explicit: `/%2f` is the default one
        return Err(DeliveryError::Unavailable("invalid_amqp_endpoint"));
    }
    let mut uri = endpoint.clone();
    if let Some((user, password)) = credentials {
        uri.set_username(user)
            .map_err(|()| DeliveryError::Unavailable("invalid_amqp_endpoint"))?;
        uri.set_password(Some(password))
            .map_err(|()| DeliveryError::Unavailable("invalid_amqp_endpoint"))?;
    }
    Ok(uri.to_string())
}

/// Settings of an AMQP destination.
pub(crate) struct AmqpSettings {
    /// Connection URI with credentials; never logged.
    pub(crate) uri: String,
    /// Full exchange name.
    pub(crate) exchange: String,
    /// Full queue name (also the routing key).
    pub(crate) queue: String,
}

/// A delivery destination publishing one persistent message per batch.
pub(crate) struct AmqpDestination {
    settings: AmqpSettings,
    channel: Mutex<Option<(Connection, Channel)>>,
}

impl std::fmt::Debug for AmqpDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AmqpDestination")
            .field("exchange", &self.settings.exchange)
            .field("queue", &self.settings.queue)
            .finish_non_exhaustive()
    }
}

fn backoff<E>(_error: E) -> DeliveryError {
    DeliveryError::ProviderBackoff(RETRY_AFTER)
}

impl AmqpDestination {
    pub(crate) fn new(settings: AmqpSettings) -> Result<Self, DeliveryError> {
        if settings.exchange.len() > 255 || settings.queue.len() > 255 {
            return Err(DeliveryError::Unavailable("invalid_amqp_name"));
        }
        Ok(Self {
            settings,
            channel: Mutex::new(None),
        })
    }

    /// A confirmed channel with the exchange, queue and binding declared.
    async fn connect(&self) -> Result<(Connection, Channel), DeliveryError> {
        let connection = Connection::connect(&self.settings.uri, ConnectionProperties::default())
            .await
            .map_err(backoff)?;
        let channel = connection.create_channel().await.map_err(backoff)?;
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await
            .map_err(backoff)?;
        channel
            .exchange_declare(
                self.settings.exchange.clone().into(),
                ExchangeKind::Direct,
                ExchangeDeclareOptions {
                    durable: true,
                    ..ExchangeDeclareOptions::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(backoff)?;
        channel
            .queue_declare(
                self.settings.queue.clone().into(),
                QueueDeclareOptions::durable(),
                FieldTable::default(),
            )
            .await
            .map_err(backoff)?;
        channel
            .queue_bind(
                self.settings.queue.clone().into(),
                self.settings.exchange.clone().into(),
                self.settings.queue.clone().into(),
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(backoff)?;
        Ok((connection, channel))
    }
}

#[async_trait]
impl DeliveryDestination for AmqpDestination {
    fn duplicate_possible(&self) -> bool {
        true
    }

    fn permits_zdr(&self) -> bool {
        false
    }

    async fn send(
        &self,
        _authority: &DeliveryAuthority,
        run: &CrawlRun,
        batch: &DeliveryBatchV1,
        bytes: Bytes,
    ) -> Result<(), DeliveryError> {
        if run.config.retention.mode == RetentionMode::Zdr {
            return Err(DeliveryError::Unavailable("amqp_persistence_forbidden_in_zdr"));
        }
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(DeliveryError::Rejected("provider_wire_byte_limit"));
        }
        // one publish at a time keeps the unconfirmed set bounded to a single message
        let mut slot = self.channel.lock().await;
        if slot.as_ref().is_none_or(|(connection, channel)| {
            !connection.status().connected() || !channel.status().connected()
        }) {
            *slot = Some(self.connect().await?);
        }
        let Some((_, channel)) = slot.as_ref() else {
            return Err(DeliveryError::Unavailable("amqp_channel_unavailable"));
        };
        let properties = BasicProperties::default()
            .with_message_id(batch.idempotency_key.clone().into())
            .with_delivery_mode(2)
            .with_content_type("application/octet-stream".into());
        let confirmation = match channel
            .basic_publish(
                self.settings.exchange.clone().into(),
                self.settings.queue.clone().into(),
                BasicPublishOptions {
                    mandatory: true,
                    ..BasicPublishOptions::default()
                },
                &bytes,
                properties,
            )
            .await
        {
            Ok(pending) => pending.await,
            Err(error) => Err(error),
        };
        match confirmation {
            Ok(Confirmation::Ack(None)) => Ok(()),
            Ok(Confirmation::Ack(Some(_))) => Err(DeliveryError::Rejected("amqp_unroutable")),
            Ok(Confirmation::Nack(_) | Confirmation::NotRequested) => {
                Err(DeliveryError::Rejected("provider_ack_rejected"))
            }
            Err(error) => {
                // drop a broken connection so the next attempt reconnects
                *slot = None;
                Err(backoff(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn endpoints_need_an_explicit_vhost_and_no_inline_credentials() {
        let creds = ("crawlx".to_owned(), "p@ss:word".to_owned());
        let ok: Url = "amqp://mq.internal:5672/%2f".parse().unwrap();
        let uri = connection_uri(&ok, Some(&creds)).unwrap();
        assert!(
            uri.starts_with("amqp://crawlx:p%40ss%3Aword@mq.internal:5672/"),
            "{uri}"
        );
        assert!(connection_uri(&"amqp://mq.internal".parse().unwrap(), None).is_err());
        assert!(connection_uri(&"amqp://u:p@mq.internal/v".parse().unwrap(), None).is_err());
        assert!(connection_uri(&"http://mq.internal/v".parse().unwrap(), None).is_err());
        assert!(connection_uri(&"amqps://mq.internal/vh".parse().unwrap(), None).is_ok());
        assert!(valid_name_part("crawlx.pages") && !valid_name_part("a b") && !valid_name_part(""));
    }
}
