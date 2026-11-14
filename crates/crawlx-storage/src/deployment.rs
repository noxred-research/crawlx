//! The identity of one CrawlX deployment: everything that shares one relational database.
//!
//! A deployment id is a random UUID stored once under `deployment.id` in the cluster-wide
//! `cluster_settings` table. Every process of the deployment (workers, API, CLI) reads the same
//! value and two deployments, having two databases, hold different ones, so it separates
//! deployments that share an object-store prefix (see [`crate::s3::S3Blobs::with_deployment`]).
//! The value is created on first use by a single atomic insert-if-absent: of any number of
//! concurrent first users exactly one creates it and all read the same value back.

use crate::backend::Dialect;
use crate::sql::{Sql, SqlRow, Stmt};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::StoreError;
use std::sync::Arc;
use uuid::Uuid;

/// `cluster_settings.key` holding the deployment id.
const DEPLOYMENT_ID_KEY: &str = "deployment.id";

/// Where a process learns the id of the deployment it belongs to.
#[async_trait]
pub trait DeploymentIdentity: Send + Sync + std::fmt::Debug {
    /// The stable id of this deployment; the same for every process and every restart.
    ///
    /// # Errors
    /// [`StoreError`] when the id cannot be read or created.
    async fn deployment_id(&self) -> Result<String, StoreError>;
}

#[async_trait]
impl<T: DeploymentIdentity + ?Sized> DeploymentIdentity for Arc<T> {
    async fn deployment_id(&self) -> Result<String, StoreError> {
        (**self).deployment_id().await
    }
}

/// A fixed id, for tests and for callers that already know it.
#[async_trait]
impl DeploymentIdentity for String {
    async fn deployment_id(&self) -> Result<String, StoreError> {
        Ok(self.clone())
    }
}

#[async_trait]
impl<B: Sql> DeploymentIdentity for Store<B> {
    async fn deployment_id(&self) -> Result<String, StoreError> {
        deployment_id_of(self).await
    }
}

/// The deployment id stored in `store`, created on first use.
///
/// # Errors
/// [`StoreError`] when the database cannot be read or written, or the stored value is not a UUID.
pub async fn deployment_id_of<B: Sql>(store: &Store<B>) -> Result<String, StoreError> {
    let key = <B::Dialect as Dialect>::reserved_ident("key");
    let select = format!("SELECT value FROM cluster_settings WHERE {key} = $1");
    let read = || async {
        Stmt::<B>::dynamic(&select)
            .text(DEPLOYMENT_ID_KEY)
            .fetch_optional_pool(&store.pool)
            .await?
            .map(|row| row.text("value"))
            .transpose()
    };
    let stored = match read().await? {
        Some(value) => value,
        None => {
            let sql = crate::repos::api::insert_if_absent::<B>(
                "cluster_settings",
                &[(&key, "$1"), ("value", "$2"), ("updated_by", "$3")],
                &[&key],
            );
            Stmt::<B>::dynamic(&sql)
                .text(DEPLOYMENT_ID_KEY)
                .text(&Uuid::now_v7().to_string())
                .text("deployment-id")
                .execute_write(&store.pool)
                .await?;
            read().await?.ok_or_else(|| {
                StoreError::Backend("cluster_settings deployment.id vanished after insert".to_owned())
            })?
        }
    };
    Uuid::parse_str(stored.trim())
        .map(|id| id.to_string())
        .map_err(|_| StoreError::Backend("cluster_settings deployment.id is not a uuid".to_owned()))
}
