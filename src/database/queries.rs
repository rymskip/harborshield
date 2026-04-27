//! Transaction-scoped database queries.
//!
//! Each `*_tx` function takes a borrowed sqlx transaction and runs one query.
//! Compose them inside [`crate::database::DB::with_transaction`] for atomic
//! multi-op batches; the `&self` methods on [`crate::database::DB`] wrap a
//! single call in its own transaction.

use sqlx::{Sqlite, Transaction, query, query_as};

use crate::{
    Error, Result,
    database::{Addr, ContainerAlias, ContainerIdentifiers, EstContainer, WaitingContainerRule},
};

// ---- Containers --------------------------------------------------------

pub async fn insert_container_tx(
    tx: &mut Transaction<'_, Sqlite>,
    container: &ContainerIdentifiers,
) -> Result<()> {
    query!(
        "INSERT OR IGNORE INTO containers (id, name) VALUES (?, ?)",
        container.id,
        container.name
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to insert container: {}", e)))?;
    Ok(())
}

pub async fn list_containers_tx(
    tx: &mut Transaction<'_, Sqlite>,
) -> Result<Vec<ContainerIdentifiers>> {
    query_as!(ContainerIdentifiers, "SELECT id, name FROM containers")
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| Error::Database(format!("Failed to list containers: {}", e)))
}

pub async fn get_container_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
) -> Result<Option<ContainerIdentifiers>> {
    query_as!(
        ContainerIdentifiers,
        "SELECT id, name FROM containers WHERE id = ?",
        id
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to get container: {}", e)))
}

pub async fn get_container_by_name_tx(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
) -> Result<Option<ContainerIdentifiers>> {
    query_as!(
        ContainerIdentifiers,
        "SELECT id, name FROM containers WHERE name = ?",
        name
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to get container by name: {}", e)))
}

pub async fn delete_container_tx(tx: &mut Transaction<'_, Sqlite>, id: &str) -> Result<()> {
    query!("DELETE FROM containers WHERE id = ?", id)
        .execute(&mut **tx)
        .await
        .map_err(|e| Error::Database(format!("Failed to delete container: {}", e)))?;
    Ok(())
}

pub async fn update_container_name_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
    new_name: &str,
) -> Result<()> {
    query!("UPDATE containers SET name = ? WHERE id = ?", new_name, id)
        .execute(&mut **tx)
        .await
        .map_err(|e| Error::Database(format!("Failed to update container name: {}", e)))?;
    Ok(())
}

// ---- Addresses ---------------------------------------------------------

pub async fn insert_addr_tx(tx: &mut Transaction<'_, Sqlite>, addr: &Addr) -> Result<()> {
    query!(
        "INSERT OR IGNORE INTO addrs (addr, container_id) VALUES (?, ?)",
        addr.addr,
        addr.container_id
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to insert address: {}", e)))?;
    Ok(())
}

pub async fn get_addrs_by_container_tx(
    tx: &mut Transaction<'_, Sqlite>,
    container_id: &str,
) -> Result<Vec<Addr>> {
    query_as!(
        Addr,
        "SELECT addr, container_id FROM addrs WHERE container_id = ?",
        container_id
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to get addresses: {}", e)))
}

pub async fn delete_addrs_by_container_tx(
    tx: &mut Transaction<'_, Sqlite>,
    container_id: &str,
) -> Result<()> {
    query!("DELETE FROM addrs WHERE container_id = ?", container_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| Error::Database(format!("Failed to delete addresses: {}", e)))?;
    Ok(())
}

// ---- Container aliases -------------------------------------------------

pub async fn insert_container_alias_tx(
    tx: &mut Transaction<'_, Sqlite>,
    alias: &ContainerAlias,
) -> Result<()> {
    query!(
        "INSERT OR IGNORE INTO container_aliases (container_id, container_alias) VALUES (?, ?)",
        alias.container_id,
        alias.container_alias
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to insert container alias: {}", e)))?;
    Ok(())
}

pub async fn get_container_by_alias_tx(
    tx: &mut Transaction<'_, Sqlite>,
    alias: &str,
) -> Result<Option<ContainerIdentifiers>> {
    query_as!(
        ContainerIdentifiers,
        r#"SELECT c.id, c.name
                   FROM containers c
                   JOIN container_aliases ca ON c.id = ca.container_id
                   WHERE ca.container_alias = ?"#,
        alias
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to get container by alias: {}", e)))
}

pub async fn delete_container_aliases_tx(
    tx: &mut Transaction<'_, Sqlite>,
    container_id: &str,
) -> Result<()> {
    query!(
        "DELETE FROM container_aliases WHERE container_id = ?",
        container_id
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to delete container aliases: {}", e)))?;
    Ok(())
}

// ---- Established containers --------------------------------------------

pub async fn insert_est_container_tx(
    tx: &mut Transaction<'_, Sqlite>,
    est: &EstContainer,
) -> Result<()> {
    query!(
        "INSERT INTO est_containers (src_container_id, dst_container_id) VALUES (?, ?)",
        est.src_container_id,
        est.dst_container_id
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to insert established container: {}", e)))?;
    Ok(())
}

pub async fn delete_est_containers_tx(
    tx: &mut Transaction<'_, Sqlite>,
    container_id: &str,
) -> Result<()> {
    query!(
        "DELETE FROM est_containers WHERE src_container_id = ? OR dst_container_id = ?",
        container_id,
        container_id
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to delete established containers: {}", e)))?;
    Ok(())
}

// ---- Waiting rules -----------------------------------------------------

pub async fn insert_waiting_rule_tx(
    tx: &mut Transaction<'_, Sqlite>,
    rule: &WaitingContainerRule,
) -> Result<()> {
    query!(
        "INSERT OR IGNORE INTO waiting_container_rules (src_container_id, dst_container_name, rule) VALUES (?, ?, ?)",
        rule.src_container_id,
        rule.dst_container_name,
        rule.rule
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to insert waiting rule: {}", e)))?;
    Ok(())
}

pub async fn get_waiting_rules_for_container_tx(
    tx: &mut Transaction<'_, Sqlite>,
    dst_container_name: &str,
) -> Result<Vec<WaitingContainerRule>> {
    query_as!(
        WaitingContainerRule,
        "SELECT src_container_id, dst_container_name, rule FROM waiting_container_rules WHERE dst_container_name = ?",
        dst_container_name
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to get waiting rules: {}", e)))
}

pub async fn delete_waiting_rules_tx(
    tx: &mut Transaction<'_, Sqlite>,
    src_container_id: &str,
) -> Result<()> {
    query!(
        "DELETE FROM waiting_container_rules WHERE src_container_id = ?",
        src_container_id
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to delete waiting rules: {}", e)))?;
    Ok(())
}

pub async fn delete_waiting_rule_tx(
    tx: &mut Transaction<'_, Sqlite>,
    src_container_id: &str,
    dst_container_name: &str,
) -> Result<()> {
    query!(
        "DELETE FROM waiting_container_rules WHERE src_container_id = ? AND dst_container_name = ?",
        src_container_id,
        dst_container_name
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| Error::Database(format!("Failed to delete waiting rule: {}", e)))?;
    Ok(())
}
