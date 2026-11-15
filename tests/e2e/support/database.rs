use std::path::Path;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};

use super::failure::{Failure, TestResult};

/// Ids of the containers harborshield has persisted, read without disturbing the daemon.
pub async fn stored_container_ids(data_dir: &Path) -> TestResult<Vec<String>> {
    let options = SqliteConnectOptions::new()
        .filename(data_dir.join("db.sqlite"))
        .read_only(true);
    let pool = SqlitePool::connect_with(options)
        .await
        .map_err(|error| Failure::context("open harborshield database", error))?;
    let ids = sqlx::query_scalar::<_, String>("SELECT id FROM containers ORDER BY id")
        .fetch_all(&pool)
        .await
        .map_err(|error| Failure::context("read stored containers", error));
    pool.close().await;
    ids
}
