//! Transaction-scoped queries; each runs one statement inside the caller's transaction.

use sqlx::{Sqlite, Transaction, query, query_as};

use super::error::DatabaseError;
use super::models::ContainerIdentifiers;

type Result<T> = std::result::Result<T, DatabaseError>;

fn failed(operation: &'static str) -> impl FnOnce(sqlx::Error) -> DatabaseError {
    move |source| DatabaseError::Query { operation, source }
}

/// Insert or rename a container. A stale row holding the same name for another id is
/// removed first: Docker names are unique among existing containers.
pub async fn upsert_container_tx(
    tx: &mut Transaction<'_, Sqlite>,
    container: &ContainerIdentifiers,
) -> Result<()> {
    query!(
        "DELETE FROM containers WHERE name = ? AND id != ?",
        container.name,
        container.id
    )
    .execute(&mut **tx)
    .await
    .map_err(failed("free container name"))?;
    query!(
        "INSERT INTO containers (id, name) VALUES (?, ?) \
         ON CONFLICT(id) DO UPDATE SET name = excluded.name",
        container.id,
        container.name
    )
    .execute(&mut **tx)
    .await
    .map_err(failed("upsert container"))?;
    Ok(())
}

pub async fn list_containers_tx(
    tx: &mut Transaction<'_, Sqlite>,
) -> Result<Vec<ContainerIdentifiers>> {
    query_as!(
        ContainerIdentifiers,
        "SELECT id, name FROM containers ORDER BY id"
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(failed("list containers"))
}

pub async fn delete_container_tx(tx: &mut Transaction<'_, Sqlite>, id: &str) -> Result<()> {
    query!("DELETE FROM containers WHERE id = ?", id)
        .execute(&mut **tx)
        .await
        .map_err(failed("delete container"))?;
    Ok(())
}

pub async fn delete_all_containers_tx(tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
    query!("DELETE FROM containers")
        .execute(&mut **tx)
        .await
        .map_err(failed("delete all containers"))?;
    Ok(())
}
