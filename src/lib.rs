pub mod database;
pub mod docker;
pub mod error;
pub mod handlers;
pub mod nftables;
#[cfg(target_os = "linux")]
pub mod security;
pub mod server;

use crate::{
    database::DB,
    docker::DockerClient,
    handlers::cleanup::CleanupTracker,
    nftables::{FILTER_TABLE, NftablesClient},
};
use bon::bon;
pub use error::{Error, Result};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::signal;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

pub const ENABLED_LABEL: &str = "harborshield.enabled";
pub const RULES_LABEL: &str = "harborshield.rules";

#[derive(Clone)]
pub struct Harborshield {
    docker_client: Arc<DockerClient>,
    nftables_client: Arc<Mutex<NftablesClient>>,
    db: Arc<Mutex<DB>>,
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: Arc<Mutex<mpsc::Receiver<()>>>,
    task_handles: Arc<StdMutex<Vec<JoinHandle<()>>>>,
    health_server_handle: Arc<Option<JoinHandle<()>>>,
    start_time: chrono::DateTime<chrono::Utc>,
    cleanup_tracker: Arc<CleanupTracker>,
    cancellation_token: CancellationToken,
}

#[bon]
impl Harborshield {
    #[builder]
    pub async fn new(
        db_path: &Path,
        timeout: Duration,
        health_server_addr: Option<&str>,
    ) -> Result<Self> {
        let docker_client = Arc::new(DockerClient::builder().timeout_duration(timeout).build()?);
        let mut nftables_client = NftablesClient::builder().build();
        // Enable NAT support for localhost mapped port gateway handling
        nftables_client.init_base_chains().await?;
        let nftables_client = Arc::new(Mutex::new(nftables_client));

        let db = Arc::new(Mutex::new(DB::builder().db_path(db_path).build().await?));

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let shutdown_rx = Arc::new(Mutex::new(shutdown_rx));

        // Setup metrics
        let prometheus_handle = server::setup_metrics()?;

        // Start health server if requested
        let health_server_handle = if let Some(addr) = health_server_addr {
            let health_server =
                server::HealthServer::new(addr, prometheus_handle, crate::VERSION.to_string())
                    .await?;

            let handle = tokio::spawn(async move {
                if let Err(e) = health_server.serve().await {
                    error!("Health server error: {}", e);
                }
            });
            Some(handle)
        } else {
            None
        };

        let cleanup_tracker = Arc::new(CleanupTracker::builder().db(db.clone()).build());

        let cancellation_token = CancellationToken::new();

        let handlers = Self {
            docker_client,
            nftables_client,
            db,
            shutdown_tx,
            shutdown_rx,
            task_handles: Arc::new(StdMutex::new(Vec::new())),
            health_server_handle: Arc::new(health_server_handle),
            start_time: chrono::Utc::now(),
            cleanup_tracker,
            cancellation_token,
        };

        Ok(handlers)
    }

    pub async fn start(self) -> Result<Self> {
        info!("Starting harborshield rule handlers");

        // Clean up orphaned rules from previous runs
        self.cleanup_orphaned_rules().await?;

        // Sync existing containers
        let stopped_container_ids = self
            .sync_containers(self.get_database_containers().await?)
            .await?;

        // Clean up stopped containers
        self.cleanup_stopped_containers(stopped_container_ids)
            .await?;

        let handlers = Arc::new(self.clone());
        // Start event listener
        let event_handle = self.spawn_event_listener(handlers);
        self.task_handles.lock().unwrap().push(event_handle);

        // Update metrics
        self.update_metrics().await;

        Ok(self)
    }

    pub async fn stop(self) {
        info!("Stopping harborshield rule handlers");

        // Cancel all operations
        self.cancellation_token.cancel();

        // Send shutdown signal to all tasks
        let _ = self.shutdown_tx.send(()).await;

        // Clean up any partially created resources
        info!("Performing cleanup of tracked resources");
        if let Err(e) = self.cleanup_tracker.cleanup_all().await {
            error!("Failed to cleanup tracked resources: {}", e);
        }

        // Wait for all background tasks to complete with timeout
        let timeout_duration = Duration::from_secs(30);
        let mut tasks = self.task_handles.lock().unwrap();
        let task_vec = std::mem::take(&mut *tasks);
        drop(tasks); // Release the lock

        let mut all_tasks = task_vec;

        if let Some(health_handle) = Arc::try_unwrap(self.health_server_handle)
            .ok()
            .and_then(|opt| opt)
        {
            all_tasks.push(health_handle);
        }

        for handle in all_tasks {
            let task_result = tokio::time::timeout(timeout_duration, handle).await;
            match task_result {
                Ok(Ok(())) => {
                    debug!("Task completed successfully");
                }
                Ok(Err(e)) => {
                    error!("Task completed with error: {}", e);
                }
                Err(_) => {
                    warn!("Task did not complete within timeout, forcing shutdown");
                }
            }
        }

        // Shutdown cleanup tracker
        let cleanup_tracker = Arc::try_unwrap(self.cleanup_tracker)
            .ok()
            .expect("Cleanup tracker has other references");
        if let Err(e) = cleanup_tracker.shutdown().await {
            error!("Failed to shutdown cleanup tracker: {}", e);
        }

        // Close database connection
        if let Ok(db_mutex) = Arc::try_unwrap(self.db) {
            match db_mutex.into_inner() {
                db => {
                    if let Err(e) = db.close().await {
                        error!("Failed to close database connection: {}", e);
                    }
                }
            }
        }

        info!("Harborshield rule handlers stopped gracefully");
    }

    pub async fn clear(&self) -> Result<()> {
        info!("Clearing all harborshield rules");

        // First, clear all Harborshield container chains from the filter table
        self.clear_all_harborshield_chains().await?;

        // Clear the main harborshield chain
        let mut nftables = self.nftables_client.lock().await;
        nftables.clear_table().await?;
        drop(nftables);

        // Clear database
        let db = self.db.lock().await;
        let containers = db.list_containers().await?;
        for container in containers {
            db.delete_container(&container.id).await?;
        }
        drop(db);

        // Clear tracker
        self.docker_client.container_tracker.clear();

        Ok(())
    }

    /// Clear all Harborshield container chains from the filter table
    async fn clear_all_harborshield_chains(&self) -> Result<()> {
        info!("Clearing all Harborshield container chains from filter table");

        // Get a list of all Harborshield chains (hs-* chains)
        let list_output = std::process::Command::new("nft")
            .args(&["-j", "list", "table", "ip", FILTER_TABLE])
            .output()
            .map_err(|e| Error::Config {
                message: format!("Failed to list filter table: {}", e),
                location: "clear_all_harborshield_chains".to_string(),
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
                        .args(&["flush", "chain", "ip", FILTER_TABLE, &chain_name])
                        .output();

                    if let Err(e) = flush_result {
                        warn!("Failed to flush chain {}: {}", chain_name, e);
                    }

                    // Then delete the chain
                    let delete_result = std::process::Command::new("nft")
                        .args(&["delete", "chain", "ip", FILTER_TABLE, &chain_name])
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

        Ok(())
    }

    /// Clean up orphaned Harborshield rules that don't belong to any running container
    async fn cleanup_orphaned_rules(&self) -> Result<()> {
        info!("Cleaning up orphaned Harborshield rules");

        // Get all running containers
        let running_containers = self.docker_client.get_sorted_containers().await?;
        let mut valid_chain_names = std::collections::HashSet::new();

        // Build set of valid chain names for running containers
        for container in running_containers {
            if let Some(id) = container.id {
                if let Ok(details) = self.docker_client.try_get_container_by_id(&id).await {
                    let chain_name = format!(
                        "hs-{}-{}",
                        details.name.replace(['_', '.', '/'], "-"),
                        &id[..12.min(id.len())]
                    );
                    valid_chain_names.insert(chain_name);
                }
            }
        }

        // Get all chains in the filter table
        let list_output = std::process::Command::new("nft")
            .args(&["-j", "list", "table", "ip", FILTER_TABLE])
            .output()
            .map_err(|e| Error::Config {
                message: format!("Failed to list filter table: {}", e),
                location: "cleanup_orphaned_rules".to_string(),
                suggestion: Some("Check nftables permissions".to_string()),
            })?;

        if !list_output.status.success() {
            warn!(
                "Failed to list filter table: {}",
                String::from_utf8_lossy(&list_output.stderr)
            );
            return Ok(()); // Don't fail startup if we can't list
        }

        let output_str = String::from_utf8_lossy(&list_output.stdout);

        // Parse JSON to find orphaned chains
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&output_str) {
            if let Some(nftables) = json.get("nftables").and_then(|n| n.as_array()) {
                let mut orphaned_chains = Vec::new();

                for item in nftables {
                    if let Some(chain) = item.get("chain") {
                        if let Some(name) = chain.get("name").and_then(|n| n.as_str()) {
                            if name.starts_with("hs-") && !valid_chain_names.contains(name) {
                                orphaned_chains.push(name.to_string());
                            }
                        }
                    }
                }

                if orphaned_chains.is_empty() {
                    info!("No orphaned Harborshield chains found");
                } else {
                    info!(
                        "Found {} orphaned Harborshield chains to remove",
                        orphaned_chains.len()
                    );

                    // Delete each orphaned chain
                    for chain_name in orphaned_chains {
                        info!("Removing orphaned chain: {}", chain_name);

                        // First flush the chain
                        let flush_result = std::process::Command::new("nft")
                            .args(&["flush", "chain", "ip", FILTER_TABLE, &chain_name])
                            .output();

                        if let Err(e) = flush_result {
                            warn!("Failed to flush orphaned chain {}: {}", chain_name, e);
                        }

                        // Then delete the chain
                        let delete_result = std::process::Command::new("nft")
                            .args(&["delete", "chain", "ip", FILTER_TABLE, &chain_name])
                            .output();

                        match delete_result {
                            Ok(output) => {
                                if output.status.success() {
                                    debug!("Successfully removed orphaned chain {}", chain_name);
                                } else {
                                    warn!(
                                        "Failed to delete orphaned chain {}: {}",
                                        chain_name,
                                        String::from_utf8_lossy(&output.stderr)
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("Failed to delete orphaned chain {}: {}", chain_name, e);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
    let s = s.trim();

    if let Some(stripped) = s.strip_suffix("ms") {
        stripped
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|e| format!("Invalid milliseconds: {}", e))
    } else if let Some(stripped) = s.strip_suffix('s') {
        stripped
            .parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|e| format!("Invalid seconds: {}", e))
    } else if let Some(stripped) = s.strip_suffix('m') {
        stripped
            .parse::<u64>()
            .map(|m| Duration::from_secs(m * 60))
            .map_err(|e| format!("Invalid minutes: {}", e))
    } else {
        // Default to seconds if no suffix
        s.parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|e| format!("Invalid duration: {}", e))
    }
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

pub fn check_kernel_version() {
    use std::process::Command;

    let output = match Command::new("uname").arg("-r").output() {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to check kernel version: {}", e);
            return;
        }
    };

    if !output.status.success() {
        error!("Failed to get kernel version");
        return;
    }

    let version = String::from_utf8_lossy(&output.stdout);
    let version = version.trim();

    // Parse major.minor version
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() >= 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
            if major < 5 || (major == 5 && minor < 10) {
                warn!(
                    "Current kernel version {} is unsupported, 5.10 or greater is required; harborshield will probably not work correctly",
                    version
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_milliseconds() {
        let result = parse_duration("100ms");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_millis(100));
    }

    #[test]
    fn test_parse_duration_seconds() {
        let result = parse_duration("30s");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_no_suffix() {
        let result = parse_duration("45");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(45));
    }

    #[test]
    fn test_parse_duration_minutes() {
        let result = parse_duration("5m");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_invalid_number() {
        let result = parse_duration("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_duration_empty_string() {
        let result = parse_duration("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_duration_whitespace_trimmed() {
        let result = parse_duration("  30s  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_zero() {
        let result = parse_duration("0s");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(0));
    }
}
