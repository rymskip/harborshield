pub mod error;
pub mod models;
pub mod queries;

#[cfg(test)]
mod tests;

use crate::{Error, Result};
use bon::bon;
use sqlx::{Sqlite, SqlitePool, Transaction};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

pub use models::*;

/// Database connection pool.
///
/// All public methods take `&self` — sqlx's pool already manages connection
/// concurrency under WAL, so callers can hold a single `Arc<DB>` and issue
/// queries from many tasks. For multi-op atomic batches, use
/// [`DB::with_transaction`].
pub struct DB {
    pool: SqlitePool,
}

#[bon]
impl DB {
    #[builder]
    pub async fn new(db_path: &Path) -> Result<Self> {
        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

        let pool = SqlitePool::connect_with(
            db_url
                .parse::<sqlx::sqlite::SqliteConnectOptions>()
                .map_err(|e| Error::Database(format!("Failed to parse database URL: {}", e)))?
                .create_if_missing(true)
                .foreign_keys(true)
                .busy_timeout(std::time::Duration::from_secs(1))
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
        )
        .await
        .map_err(|e| Error::Database(format!("Failed to create database pool: {}", e)))?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to run migrations: {}", e)))?;

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn close(self) -> Result<()> {
        self.pool.close().await;
        Ok(())
    }

    /// Run a closure inside a single sqlx transaction. Commits on `Ok`,
    /// rolls back on `Err`. Use this for multi-op atomic batches.
    pub async fn with_transaction<R, F>(&self, f: F) -> Result<R>
    where
        F: for<'t> FnOnce(
            &'t mut Transaction<'_, Sqlite>,
        ) -> Pin<Box<dyn Future<Output = Result<R>> + Send + 't>>,
    {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::Database(format!("Failed to begin transaction: {}", e)))?;

        match f(&mut tx).await {
            Ok(value) => {
                tx.commit()
                    .await
                    .map_err(|e| Error::Database(format!("Failed to commit transaction: {}", e)))?;
                Ok(value)
            }
            Err(e) => {
                // Rollback is best-effort; the original error is what we propagate.
                let _ = tx.rollback().await;
                Err(e)
            }
        }
    }

    // ---- Containers ----------------------------------------------------

    pub async fn insert_container(&self, c: &ContainerIdentifiers) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::insert_container_tx(&mut tx, c).await?;
        Self::commit(tx).await
    }

    pub async fn list_containers(&self) -> Result<Vec<ContainerIdentifiers>> {
        let mut tx = self.begin().await?;
        let out = queries::list_containers_tx(&mut tx).await?;
        Self::commit(tx).await?;
        Ok(out)
    }

    pub async fn get_container(&self, id: &str) -> Result<Option<ContainerIdentifiers>> {
        let mut tx = self.begin().await?;
        let out = queries::get_container_tx(&mut tx, id).await?;
        Self::commit(tx).await?;
        Ok(out)
    }

    pub async fn get_container_by_name(
        &self,
        name: &str,
    ) -> Result<Option<ContainerIdentifiers>> {
        let mut tx = self.begin().await?;
        let out = queries::get_container_by_name_tx(&mut tx, name).await?;
        Self::commit(tx).await?;
        Ok(out)
    }

    pub async fn delete_container(&self, id: &str) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::delete_container_tx(&mut tx, id).await?;
        Self::commit(tx).await
    }

    pub async fn update_container_name(&self, id: &str, new_name: &str) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::update_container_name_tx(&mut tx, id, new_name).await?;
        Self::commit(tx).await
    }

    // ---- Addresses -----------------------------------------------------

    pub async fn insert_addr(&self, addr: &Addr) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::insert_addr_tx(&mut tx, addr).await?;
        Self::commit(tx).await
    }

    pub async fn get_addrs_by_container(&self, container_id: &str) -> Result<Vec<Addr>> {
        let mut tx = self.begin().await?;
        let out = queries::get_addrs_by_container_tx(&mut tx, container_id).await?;
        Self::commit(tx).await?;
        Ok(out)
    }

    pub async fn delete_addrs_by_container(&self, container_id: &str) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::delete_addrs_by_container_tx(&mut tx, container_id).await?;
        Self::commit(tx).await
    }

    // ---- Container aliases ---------------------------------------------

    pub async fn insert_container_alias(&self, alias: &ContainerAlias) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::insert_container_alias_tx(&mut tx, alias).await?;
        Self::commit(tx).await
    }

    pub async fn get_container_by_alias(
        &self,
        alias: &str,
    ) -> Result<Option<ContainerIdentifiers>> {
        let mut tx = self.begin().await?;
        let out = queries::get_container_by_alias_tx(&mut tx, alias).await?;
        Self::commit(tx).await?;
        Ok(out)
    }

    pub async fn delete_container_aliases(&self, container_id: &str) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::delete_container_aliases_tx(&mut tx, container_id).await?;
        Self::commit(tx).await
    }

    // ---- Established containers ----------------------------------------

    pub async fn insert_est_container(&self, est: &EstContainer) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::insert_est_container_tx(&mut tx, est).await?;
        Self::commit(tx).await
    }

    pub async fn delete_est_containers(&self, container_id: &str) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::delete_est_containers_tx(&mut tx, container_id).await?;
        Self::commit(tx).await
    }

    // ---- Waiting rules -------------------------------------------------

    pub async fn insert_waiting_rule(&self, rule: &WaitingContainerRule) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::insert_waiting_rule_tx(&mut tx, rule).await?;
        Self::commit(tx).await
    }

    pub async fn get_waiting_rules_for_container(
        &self,
        dst_container_name: &str,
    ) -> Result<Vec<WaitingContainerRule>> {
        let mut tx = self.begin().await?;
        let out = queries::get_waiting_rules_for_container_tx(&mut tx, dst_container_name).await?;
        Self::commit(tx).await?;
        Ok(out)
    }

    pub async fn delete_waiting_rules(&self, src_container_id: &str) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::delete_waiting_rules_tx(&mut tx, src_container_id).await?;
        Self::commit(tx).await
    }

    pub async fn delete_waiting_rule(
        &self,
        src_container_id: &str,
        dst_container_name: &str,
    ) -> Result<()> {
        let mut tx = self.begin().await?;
        queries::delete_waiting_rule_tx(&mut tx, src_container_id, dst_container_name).await?;
        Self::commit(tx).await
    }

    // ---- helpers -------------------------------------------------------

    async fn begin(&self) -> Result<Transaction<'_, Sqlite>> {
        self.pool
            .begin()
            .await
            .map_err(|e| Error::Database(format!("Failed to begin transaction: {}", e)))
    }

    async fn commit(tx: Transaction<'_, Sqlite>) -> Result<()> {
        tx.commit()
            .await
            .map_err(|e| Error::Database(format!("Failed to commit transaction: {}", e)))
    }
}
