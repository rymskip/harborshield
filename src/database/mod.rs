pub mod error;
pub mod models;
pub mod queries;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use bon::bon;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::{Sqlite, SqlitePool, Transaction};

pub use error::DatabaseError;
pub use models::ContainerIdentifiers;

type Result<T> = std::result::Result<T, DatabaseError>;

/// The record of which containers harborshield manages.
///
/// Every method runs in its own transaction; sqlx's pool handles concurrency under WAL.
pub struct DB {
    pool: SqlitePool,
}

#[bon]
impl DB {
    #[builder]
    pub async fn new(db_path: &Path) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(1))
            .journal_mode(SqliteJournalMode::Wal);
        let pool =
            SqlitePool::connect_with(options)
                .await
                .map_err(|source| DatabaseError::Open {
                    path: db_path.to_path_buf(),
                    source,
                })?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn close(self) {
        self.pool.close().await;
    }

    pub async fn upsert_container(&self, container: &ContainerIdentifiers) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::upsert_container_tx(&mut tx, container).await?;
        Self::commit(tx).await
    }

    pub async fn list_containers(&self) -> Result<Vec<ContainerIdentifiers>> {
        let mut tx = self.begin().await?;
        let containers = queries::list_containers_tx(&mut tx).await?;
        Self::commit(tx).await?;
        Ok(containers)
    }

    pub async fn delete_container(&self, id: &str) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::delete_container_tx(&mut tx, id).await?;
        Self::commit(tx).await
    }

    /// Make the stored set exactly `containers`, atomically.
    pub async fn replace_containers(&self, containers: &[ContainerIdentifiers]) -> Result<()> {
        let keep: BTreeSet<&str> = containers
            .iter()
            .map(|container| container.id.as_str())
            .collect();
        let mut tx = self.begin().await?;
        for stored in queries::list_containers_tx(&mut tx).await? {
            if !keep.contains(stored.id.as_str()) {
                queries::delete_container_tx(&mut tx, &stored.id).await?;
            }
        }
        for container in containers {
            queries::upsert_container_tx(&mut tx, container).await?;
        }
        Self::commit(tx).await
    }

    pub async fn delete_all_containers(&self) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::delete_all_containers_tx(&mut tx).await?;
        Self::commit(tx).await
    }

    async fn begin(&self) -> Result<Transaction<'_, Sqlite>> {
        self.pool
            .begin()
            .await
            .map_err(|source| DatabaseError::Query {
                operation: "begin transaction",
                source,
            })
    }

    // An uncommitted transaction rolls back when dropped, so every early return above undoes
    // its partial work.
    async fn commit(tx: Transaction<'_, Sqlite>) -> Result<()> {
        tx.commit().await.map_err(|source| DatabaseError::Query {
            operation: "commit transaction",
            source,
        })
    }
}
