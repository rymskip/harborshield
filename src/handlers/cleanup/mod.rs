pub mod error;
pub mod guard;

#[cfg(test)]
mod tests;

use crate::database::DB;
use crate::{Error, Result};
use bon::bon;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Tracks resources that need cleanup on cancellation or error
///
pub struct CleanupTracker {
    cleanup_tx: mpsc::Sender<CleanupRequest>,
    cleanup_handle: Option<JoinHandle<()>>,
    cancellation_token: CancellationToken,
}

#[derive(Debug, Clone)]
pub enum CleanupResource {
    NftablesRule {
        table: String,
        chain: String,
        handle: u64,
    },
    NftablesChain {
        table: String,
        chain: String,
    },
    NftablesSet {
        table: String,
        set: String,
    },
    DatabaseContainer {
        id: String,
    },
    HarborshieldFilterRules,
}

#[derive(Debug)]
enum CleanupRequest {
    Register(CleanupResource),
    Unregister(CleanupResource),
    CleanupAll,
    /// Clean up just the listed resources right now. Used by `CleanupGuard`
    /// drops to undo a specific in-flight operation without flushing the
    /// tracker's whole resource set.
    CleanupSubset(Vec<CleanupResource>),
    Shutdown,
}

#[bon]
impl CleanupTracker {
    #[builder]
    pub fn new(db: Arc<DB>) -> Self {
        let (cleanup_tx, mut cleanup_rx) = mpsc::channel::<CleanupRequest>(100);
        let cancellation_token = CancellationToken::new();
        let token_clone = cancellation_token.clone();

        let cleanup_handle = tokio::spawn(async move {
            let mut resources_vec = Vec::new();

            loop {
                tokio::select! {
                    Some(request) = cleanup_rx.recv() => {
                        match request {
                            CleanupRequest::Register(resource) => {
                                resources_vec.push(resource);
                                debug!("Registered resource for cleanup");
                            }
                            CleanupRequest::Unregister(resource) => {
                                resources_vec.retain(|r| !matches_resource(r, &resource));
                                debug!("Unregistered resource from cleanup");
                            }
                            CleanupRequest::CleanupAll => {
                                info!("Performing cleanup of all tracked resources");
                                for resource in &resources_vec {
                                    if let Err(e) = cleanup_resource(resource, &db).await {
                                        error!("Failed to cleanup resource: {}", e);
                                    }
                                }
                            }
                            CleanupRequest::CleanupSubset(targets) => {
                                debug!(
                                    "Cleaning up subset of {} resources",
                                    targets.len()
                                );
                                for resource in &targets {
                                    if let Err(e) = cleanup_resource(resource, &db).await {
                                        error!("Failed to cleanup subset resource: {}", e);
                                    }
                                }
                                // Drop them from the tracked list so shutdown
                                // doesn't try to clean them up again.
                                resources_vec.retain(|r| {
                                    !targets.iter().any(|t| matches_resource(r, t))
                                });
                            }
                            CleanupRequest::Shutdown => {
                                debug!("Cleanup tracker shutting down");
                                break;
                            }
                        }
                    }
                    _ = token_clone.cancelled() => {
                        info!("Cleanup tracker cancelled, performing cleanup");
                        for resource in &resources_vec {
                            if let Err(e) = cleanup_resource(resource, &db).await {
                                error!("Failed to cleanup resource on cancellation: {}", e);
                            }
                        }
                        break;
                    }
                }
            }
        });

        Self {
            cleanup_tx,
            cleanup_handle: Some(cleanup_handle),
            cancellation_token,
        }
    }

    /// Register a nftables rule for cleanup
    pub async fn register_rule(&self, table: String, chain: String, handle: u64) -> Result<()> {
        self.cleanup_tx
            .send(CleanupRequest::Register(CleanupResource::NftablesRule {
                table,
                chain,
                handle,
            }))
            .await
            .map_err(|_| Error::invalid_state("Cleanup tracker closed", "open", "closed"))?;
        Ok(())
    }

    /// Register a nftables chain for cleanup
    pub async fn register_chain(&self, table: String, chain: String) -> Result<()> {
        self.cleanup_tx
            .send(CleanupRequest::Register(CleanupResource::NftablesChain {
                table,
                chain,
            }))
            .await
            .map_err(|_| Error::invalid_state("Cleanup tracker closed", "open", "closed"))?;
        Ok(())
    }

    /// Register a nftables set for cleanup
    pub async fn register_set(&self, table: String, set: String) -> Result<()> {
        self.cleanup_tx
            .send(CleanupRequest::Register(CleanupResource::NftablesSet {
                table,
                set,
            }))
            .await
            .map_err(|_| Error::invalid_state("Cleanup tracker closed", "open", "closed"))?;
        Ok(())
    }

    /// Register a database container for cleanup
    pub async fn register_db_container(&self, id: String) -> Result<()> {
        self.cleanup_tx
            .send(CleanupRequest::Register(
                CleanupResource::DatabaseContainer { id },
            ))
            .await
            .map_err(|_| Error::invalid_state("Cleanup tracker closed", "open", "closed"))?;
        Ok(())
    }

    /// Register Harborshield filter rules for cleanup
    pub async fn register_harborshield_filter_rules(&self) -> Result<()> {
        self.cleanup_tx
            .send(CleanupRequest::Register(
                CleanupResource::HarborshieldFilterRules,
            ))
            .await
            .map_err(|_| Error::invalid_state("Cleanup tracker closed", "open", "closed"))?;
        Ok(())
    }

    /// Unregister a resource (when successfully committed)
    pub async fn unregister_rule(&self, table: String, chain: String, handle: u64) -> Result<()> {
        self.cleanup_tx
            .send(CleanupRequest::Unregister(CleanupResource::NftablesRule {
                table,
                chain,
                handle,
            }))
            .await
            .map_err(|_| Error::invalid_state("Cleanup tracker closed", "open", "closed"))?;
        Ok(())
    }

    /// Cleanup all tracked resources (on error/cancellation)
    pub async fn cleanup_all(&self) -> Result<()> {
        self.cleanup_tx
            .send(CleanupRequest::CleanupAll)
            .await
            .map_err(|_| Error::invalid_state("Cleanup tracker closed", "open", "closed"))?;
        Ok(())
    }

    /// Cleanup only the given resources, removing them from the tracked set.
    /// Used by `CleanupGuard` when an operation it covers is dropped without
    /// having been committed.
    pub async fn cleanup_subset(&self, resources: Vec<CleanupResource>) -> Result<()> {
        self.cleanup_tx
            .send(CleanupRequest::CleanupSubset(resources))
            .await
            .map_err(|_| Error::invalid_state("Cleanup tracker closed", "open", "closed"))?;
        Ok(())
    }

    /// Send a register request for an already-constructed CleanupResource.
    pub async fn register_resource(&self, resource: CleanupResource) -> Result<()> {
        self.cleanup_tx
            .send(CleanupRequest::Register(resource))
            .await
            .map_err(|_| Error::invalid_state("Cleanup tracker closed", "open", "closed"))?;
        Ok(())
    }

    /// Send an unregister request for an already-constructed CleanupResource.
    pub async fn unregister_resource(&self, resource: CleanupResource) -> Result<()> {
        self.cleanup_tx
            .send(CleanupRequest::Unregister(resource))
            .await
            .map_err(|_| Error::invalid_state("Cleanup tracker closed", "open", "closed"))?;
        Ok(())
    }

    /// Shutdown the cleanup tracker
    pub async fn shutdown(mut self) -> Result<()> {
        let _ = self.cleanup_tx.send(CleanupRequest::Shutdown).await;
        if let Some(handle) = self.cleanup_handle.take() {
            handle.await.map_err(|e| {
                Error::invalid_state(format!("Cleanup task failed: {}", e), "running", "failed")
            })?;
        }
        Ok(())
    }

    /// Get a child cancellation token
    pub fn child_token(&self) -> CancellationToken {
        self.cancellation_token.child_token()
    }

    /// Cancel all operations
    pub fn cancel(&self) {
        self.cancellation_token.cancel();
    }
}

impl Drop for CleanupTracker {
    fn drop(&mut self) {
        // Cancel the token to trigger cleanup
        self.cancellation_token.cancel();

        // Note: We can't await the handle in Drop since it's not async
        // The cleanup will happen in the background
        if self.cleanup_handle.is_some() {
            warn!(
                "CleanupTracker dropped without explicit shutdown - cleanup will happen in background"
            );
        }
    }
}

fn matches_resource(a: &CleanupResource, b: &CleanupResource) -> bool {
    match (a, b) {
        (
            CleanupResource::NftablesRule {
                table: t1,
                chain: c1,
                handle: h1,
            },
            CleanupResource::NftablesRule {
                table: t2,
                chain: c2,
                handle: h2,
            },
        ) => t1 == t2 && c1 == c2 && h1 == h2,
        (
            CleanupResource::NftablesChain {
                table: t1,
                chain: c1,
            },
            CleanupResource::NftablesChain {
                table: t2,
                chain: c2,
            },
        ) => t1 == t2 && c1 == c2,
        (
            CleanupResource::NftablesSet { table: t1, set: s1 },
            CleanupResource::NftablesSet { table: t2, set: s2 },
        ) => t1 == t2 && s1 == s2,
        (
            CleanupResource::DatabaseContainer { id: id1 },
            CleanupResource::DatabaseContainer { id: id2 },
        ) => id1 == id2,
        (CleanupResource::HarborshieldFilterRules, CleanupResource::HarborshieldFilterRules) => true,
        _ => false,
    }
}

async fn cleanup_resource(resource: &CleanupResource, db: &Arc<DB>) -> Result<()> {
    match resource {
        CleanupResource::NftablesRule {
            table,
            chain,
            handle,
        } => {
            warn!(
                "Cleaning up nftables rule: table={}, chain={}, handle={}",
                table, chain, handle
            );

            // Try cleanup with retry logic
            let max_retries = 3;
            let mut attempt = 0;

            loop {
                attempt += 1;

                // Create a transaction to delete the rule
                let mut transaction =
                    crate::nftables::transaction::RuleSet::builder().build();

                // Create a rule object with the handle for deletion
                let rule = nftables::schema::Rule {
                    family: nftables::types::NfFamily::IP,
                    table: std::borrow::Cow::Owned(table.clone()),
                    chain: std::borrow::Cow::Owned(chain.clone()),
                    handle: Some(*handle as u32),
                    expr: std::borrow::Cow::Borrowed(&[]),
                    index: None,
                    comment: None,
                };

                // Delete the rule
                transaction.delete(nftables::schema::NfListObject::Rule(rule));

                // Commit the transaction with retry
                match transaction.commit().await {
                    Ok(_) => {
                        info!(
                            "Successfully cleaned up nftables rule with handle {}",
                            handle
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        if attempt >= max_retries {
                            error!(
                                "Failed to cleanup nftables rule after {} attempts: {}",
                                max_retries, e
                            );
                            return Err(e);
                        }
                        warn!("Attempt {} to cleanup nftables rule failed: {}", attempt, e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            100 * attempt as u64,
                        ))
                        .await;
                    }
                }
            }
        }
        CleanupResource::NftablesChain { table, chain } => {
            warn!(
                "Cleaning up nftables chain: table={}, chain={}",
                table, chain
            );

            // Try cleanup with retry logic
            let max_retries = 3;
            let mut attempt = 0;

            loop {
                attempt += 1;

                // Create a transaction to delete the chain
                let mut transaction =
                    crate::nftables::transaction::RuleSet::builder().build();

                // First, flush all rules from the chain
                transaction.flush_chain(table, chain);

                // Then delete the chain itself
                let chain_obj = nftables::schema::Chain {
                    family: nftables::types::NfFamily::IP,
                    table: std::borrow::Cow::Owned(table.clone()),
                    name: std::borrow::Cow::Owned(chain.clone()),
                    newname: None,
                    handle: None,
                    _type: None,
                    hook: None,
                    prio: None,
                    dev: None,
                    policy: None,
                };

                transaction.delete(nftables::schema::NfListObject::Chain(chain_obj));

                // Commit the transaction
                match transaction.commit().await {
                    Ok(_) => {
                        info!("Successfully cleaned up nftables chain {}", chain);
                        return Ok(());
                    }
                    Err(e) => {
                        if attempt >= max_retries {
                            error!(
                                "Failed to cleanup nftables chain after {} attempts: {}",
                                max_retries, e
                            );
                            return Err(e);
                        }
                        warn!(
                            "Attempt {} to cleanup nftables chain failed: {}",
                            attempt, e
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            100 * attempt as u64,
                        ))
                        .await;
                    }
                }
            }
        }
        CleanupResource::NftablesSet { table, set } => {
            warn!("Cleaning up nftables set: table={}, set={}", table, set);

            // Try cleanup with retry logic
            let max_retries = 3;
            let mut attempt = 0;

            loop {
                attempt += 1;

                // Create a transaction to delete the set
                let mut transaction =
                    crate::nftables::transaction::RuleSet::builder().build();

                // Create a set object for deletion
                let set_obj = Box::new(nftables::schema::Set {
                    family: nftables::types::NfFamily::IP,
                    table: std::borrow::Cow::Owned(table.clone()),
                    name: std::borrow::Cow::Owned(set.clone()),
                    handle: None,
                    set_type: nftables::schema::SetTypeValue::Single(
                        nftables::schema::SetType::Ipv4Addr,
                    ), // Dummy type for deletion
                    policy: None,
                    flags: None,
                    elem: None,
                    timeout: None,
                    gc_interval: None,
                    size: None,
                    comment: None,
                });

                transaction.delete(nftables::schema::NfListObject::Set(set_obj));

                // Commit the transaction
                match transaction.commit().await {
                    Ok(_) => {
                        info!("Successfully cleaned up nftables set {}", set);
                        return Ok(());
                    }
                    Err(e) => {
                        if attempt >= max_retries {
                            error!(
                                "Failed to cleanup nftables set after {} attempts: {}",
                                max_retries, e
                            );
                            return Err(e);
                        }
                        warn!("Attempt {} to cleanup nftables set failed: {}", attempt, e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            100 * attempt as u64,
                        ))
                        .await;
                    }
                }
            }
        }
        CleanupResource::DatabaseContainer { id } => {
            warn!("Cleaning up database container: id={}", id);

            let id_owned = id.clone();
            match db
                .with_transaction(|tx| {
                    Box::pin(async move {
                        crate::database::queries::delete_addrs_by_container_tx(tx, &id_owned)
                            .await?;
                        crate::database::queries::delete_container_aliases_tx(tx, &id_owned)
                            .await?;
                        crate::database::queries::delete_waiting_rules_tx(tx, &id_owned).await?;
                        crate::database::queries::delete_container_tx(tx, &id_owned).await?;
                        Ok(())
                    })
                })
                .await
            {
                Ok(()) => {
                    info!("Successfully cleaned up database container {}", id);
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to cleanup database container: {}", e);
                    Err(e)
                }
            }
        }
        CleanupResource::HarborshieldFilterRules => {
            warn!("Cleaning up all Harborshield rules from filter table");

            // First, get a list of all Harborshield chains (hs-* chains)
            let list_output = std::process::Command::new("nft")
                .args(&["-j", "list", "table", "ip", "filter"])
                .output()
                .map_err(|e| crate::Error::Config {
                    message: format!("Failed to list filter table: {}", e),
                    location: "cleanup_harborshield_filter_rules".to_string(),
                    suggestion: Some("Check nftables permissions".to_string()),
                })?;

            if !list_output.status.success() {
                warn!(
                    "Failed to list filter table: {}",
                    String::from_utf8_lossy(&list_output.stderr)
                );
                return Ok(()); // Don't fail cleanup if we can't list
            }

            let output_str = String::from_utf8_lossy(&list_output.stdout);

            // Parse JSON to find all chains starting with "hs-"
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&output_str) {
                if let Some(nftables) = json.get("nftables").and_then(|n| n.as_array()) {
                    let mut chains_to_delete = Vec::new();

                    for item in nftables {
                        if let Some(chain) = item.get("chain") {
                            if let Some(name) = chain.get("name").and_then(|n| n.as_str()) {
                                if name.starts_with("hs-") {
                                    chains_to_delete.push(name.to_string());
                                }
                            }
                        }
                    }

                    info!(
                        "Found {} Harborshield container chains to delete",
                        chains_to_delete.len()
                    );

                    // Delete each container chain
                    for chain_name in chains_to_delete {
                        // First flush the chain
                        let flush_result = std::process::Command::new("nft")
                            .args(&["flush", "chain", "ip", "filter", &chain_name])
                            .output();

                        if let Err(e) = flush_result {
                            warn!("Failed to flush chain {}: {}", chain_name, e);
                        }

                        // Then delete the chain
                        let delete_result = std::process::Command::new("nft")
                            .args(&["delete", "chain", "ip", "filter", &chain_name])
                            .output();

                        match delete_result {
                            Ok(output) => {
                                if output.status.success() {
                                    debug!("Successfully deleted chain {}", chain_name);
                                } else {
                                    warn!(
                                        "Failed to delete chain {}: {}",
                                        chain_name,
                                        String::from_utf8_lossy(&output.stderr)
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("Failed to delete chain {}: {}", chain_name, e);
                            }
                        }
                    }
                }
            }

            // Also flush the main harborshield chain
            let flush_harborshield = std::process::Command::new("nft")
                .args(&["flush", "chain", "ip", "filter", "harborshield"])
                .output();

            if let Err(e) = flush_harborshield {
                warn!("Failed to flush harborshield chain: {}", e);
            }

            info!("Completed cleanup of Harborshield filter rules");
            Ok(())
        }
    }
}

// CleanupGuard lives in `cleanup::guard`; re-export for ergonomic access.
pub use guard::CleanupGuard;
