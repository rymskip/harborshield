use crate::{
    Result,
    database::ContainerIdentifiers,
    docker::{compose::ComposeInfo, config::RulePorts, container::Container},
    nftables::transaction::RuleSet,
    server,
};
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::Harborshield;

impl Harborshield {
    /// Create container rules using direct config translation (new approach)
    /// Also handles enabling container rules
    pub async fn create_container_rules(
        &self,
        container: &Container,
        cancellation_token: Option<CancellationToken>,
    ) -> Result<()> {
        if container.uses_host_network {
            tracing::warn!(
                container_id = %container.id,
                container_name = %container.name,
                "Container uses host networking mode - firewall rules cannot be created"
            );
            return Ok(());
        }

        // Get container IPs
        let mut container_ips: Vec<std::net::IpAddr> = Vec::new();
        for (_, network) in &container.networks {
            container_ips.extend(&network.ip_addresses);
        }

        // Check if container has rules defined
        if let Some(config) = &container.config {
            // Check for cancellation
            if let Some(token) = &cancellation_token {
                if token.is_cancelled() {
                    return Err(crate::Error::invalid_state(
                        "Operation cancelled",
                        "active",
                        "cancelled",
                    ));
                }
            }

            // Create container chain and apply rules using direct translation
            let mut nftables = self.nftables_client.lock().await;
            nftables
                .create_container_chain(&container.id, &container.name)
                .await?;

            // Extract container ports for rule creation
            let container_ports: Vec<(u16, String)> = container
                .ports
                .iter()
                .map(|p| (p.container_port, p.protocol.clone()))
                .collect();

            tracing::debug!(
                "Container {} has ports: {:?}",
                container.name,
                container_ports
            );

            // Resolve container references in output rules
            let mut resolved_config = config.clone();
            for (idx, output_rule) in resolved_config.output.iter_mut().enumerate() {
                if !output_rule.container.is_empty() {
                    let container_ref = output_rule.container.clone();
                    // Find the target container
                    if let Some(target_container) = self
                        .docker_client
                        .container_tracker
                        .find_container(&container_ref)
                    {
                        // Get target container IPs
                        let mut target_ips = Vec::new();
                        for (_, network) in &target_container.networks {
                            for ip in &network.ip_addresses {
                                target_ips.push(crate::docker::config::AddrOrRange::Addr(*ip));
                            }
                        }

                        if !target_ips.is_empty() {
                            // Replace container reference with actual IPs
                            output_rule.ips = target_ips;
                            output_rule.container.clear(); // Clear the container reference
                            debug!(
                                "Resolved container reference '{}' to IPs for output rule {} in container {}",
                                container_ref,
                                idx + 1,
                                container.name
                            );
                        } else {
                            debug!(
                                "Target container '{}' has no IPs yet, output rule {} will be handled as waiting rule",
                                container_ref,
                                idx + 1
                            );
                        }
                    } else {
                        debug!(
                            "Target container '{}' not found, output rule {} will be handled as waiting rule",
                            container_ref,
                            idx + 1
                        );
                    }
                }
            }

            // Apply rules directly from config
            nftables
                .add_rules_from_config(
                    &container.id,
                    &container.name,
                    &container_ips,
                    &container_ports,
                    &resolved_config,
                )
                .await?;

            // Commit the batch
            nftables.apply().await?;

            // Update verdict maps to include this container's IPs
            // This creates the vmap rules in the harborshield chain that route traffic
            // from container source IPs to their respective chains
            let container_mappings = vec![(
                container.id.clone(),
                container.name.clone(),
                container_ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>(),
            )];
            nftables
                .update_container_verdict_maps(&container_mappings)
                .await?;

            info!(
                "Applied firewall rules for container {} using direct config translation",
                container.name
            );

            // Update metrics
            let rule_count = config.output.len()
                + if config.mapped_ports.localhost.allow {
                    1
                } else {
                    0
                }
                + if config.mapped_ports.external.allow {
                    1
                } else {
                    0
                };

            for _ in 0..rule_count {
                server::increment_rules_applied();
            }
        } else {
            // No rules defined, just create the chain
            let mut nftables = self.nftables_client.lock().await;
            nftables
                .create_container_chain(&container.id, &container.name)
                .await?;
            nftables.apply().await?;

            // Even with no rules, we need to update verdict maps for the container's IPs
            // so traffic from/to this container can be routed to its chain
            let mut container_ips = Vec::new();
            for (_, network) in &container.networks {
                container_ips.extend(network.ip_addresses.iter().map(|ip| ip.to_string()));
            }

            if !container_ips.is_empty() {
                let container_mappings =
                    vec![(container.id.clone(), container.name.clone(), container_ips)];
                nftables
                    .update_container_verdict_maps(&container_mappings)
                    .await?;
            }
        }

        Ok(())
    }
    /// Log Docker Compose information if present
    pub fn log_compose_info(
        &self,
        info: &Container,
        container_id: &str,
        container_name: &str,
        is_new: bool,
    ) {
        let compose_info = ComposeInfo::from_labels(&info.labels);
        if compose_info.project.is_some() || compose_info.service.is_some() {
            debug!(
                container_id = %container_id,
                container_name = %container_name,
                compose_project = ?compose_info.project,
                compose_service = ?compose_info.service,
                compose_number = ?compose_info.container_number,
                dependencies = ?compose_info.depends_on,
                is_new = is_new,
                "Processing Docker Compose container"
            );
        }
    }
}

// Helper functions for rule management
pub fn convert_rule_ports(ports: &[RulePorts]) -> Vec<u16> {
    ports
        .iter()
        .flat_map(|p| match p {
            RulePorts::Single(port) => vec![*port],
            RulePorts::Range(start, end) => (*start..=*end).collect(),
        })
        .collect()
}

pub fn extract_mapped_ports(container: &Container) -> Option<(Vec<u16>, Vec<u16>, Vec<u16>)> {
    if container.ports.is_empty() {
        return None;
    }

    let mut external_ports = Vec::new();
    let mut tcp_ports = Vec::new();
    let mut udp_ports = Vec::new();

    for port_mapping in &container.ports {
        if let Some(host_port) = port_mapping.host_port {
            external_ports.push(host_port);
            match port_mapping.protocol.as_str() {
                "tcp" => tcp_ports.push(port_mapping.container_port),
                "udp" => udp_ports.push(port_mapping.container_port),
                _ => {}
            }
        }
    }

    if external_ports.is_empty() {
        None
    } else {
        Some((external_ports, tcp_ports, udp_ports))
    }
}

// Additional utility functions
impl Harborshield {
    /// Get gateway IPs for a container's connected networks
    pub async fn get_container_gateway_ips(&self, details: &Container) -> Vec<std::net::IpAddr> {
        let gateway_cache = self.docker_client.network_gateway_cache.lock().await;
        let mut gateway_ips = Vec::new();

        for (network_name, _) in &details.networks {
            if let Some(gateway_info) = gateway_cache.get(network_name) {
                gateway_ips.extend(&gateway_info.gateway_ips);
            }
        }

        gateway_ips
    }
    pub async fn sync_containers(
        &self,
        mut db_container_ids: HashMap<String, ContainerIdentifiers>,
    ) -> Result<HashMap<String, ContainerIdentifiers>> {
        info!("Syncing containers with current Docker state");

        // Refresh network gateway information first
        if let Err(e) = self.docker_client.refresh_network_gateways().await {
            warn!("Failed to refresh network gateway information: {}", e);
        }

        // Track containers that need to be restarted
        let mut containers_to_restart = Vec::new();

        // Phase 1: Get ALL containers to process waiting rules
        info!("Phase 1: Scanning all containers to create waiting rules");
        let all_containers = self.docker_client.list_all_containers().await?;

        // First, process ALL containers to create waiting rules
        // This ensures that any container references are registered
        for container_summary in &all_containers {
            if let Some(id) = &container_summary.id {
                match self.docker_client.try_get_container_by_id(id).await {
                    Ok(container) => {
                        if container.is_harborshield_enabled() {
                            // Add to container tracker so waiting rules can find it
                            if let Err(e) = self
                                .docker_client
                                .container_tracker
                                .add_container(container.clone())
                            {
                                debug!(
                                    "Could not add container {} to tracker: {}",
                                    container.name, e
                                );
                            }

                            // Store container in database first (required for foreign key constraints)
                            if let Err(e) = super::Harborshield::store_container_in_database(
                                &container, &self.db,
                            )
                            .await
                            {
                                debug!(
                                    "Could not store container {} in database (may already exist): {}",
                                    container.name, e
                                );
                            }

                            // Create waiting rules for this container's references
                            if container.config.is_some() {
                                if let Err(e) =
                                    self.create_waiting_rules_for_container(&container).await
                                {
                                    error!(
                                        "Failed to create waiting rules for container {}: {}",
                                        container.name, e
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Could not inspect container {}: {}", id, e);
                    }
                }
            }
        }

        // Phase 2: Process running containers to create actual firewall rules
        info!("Phase 2: Processing running containers to create firewall rules");
        let containers = self.docker_client.get_sorted_containers().await?;
        info!("Found {} running containers to process", containers.len());
        // Check for containers that might not be fully running yet
        let non_running_or_starting: Vec<_> = all_containers
            .iter()
            .filter(|c| {
                // Check if container is not in the running containers list
                if let Some(id) = &c.id {
                    !containers
                        .iter()
                        .any(|running| running.id.as_ref() == Some(id))
                } else {
                    false
                }
            })
            .collect();

        if !non_running_or_starting.is_empty() {
            info!(
                "Found {} containers not in running state (may be starting/created/exited)",
                non_running_or_starting.len()
            );

            // Check if any of these containers have harborshield enabled and need chains created
            for container_summary in &non_running_or_starting {
                if let Some(id) = &container_summary.id {
                    match self.docker_client.try_get_container_by_id(id).await {
                        Ok(container) => {
                            if container.is_harborshield_enabled() {
                                info!(
                                    "Found harborshield-enabled container not yet running: {} (state: {:?})",
                                    container.name, container_summary.state
                                );

                                // Add to container tracker so waiting rules can find it
                                if let Err(e) = self
                                    .docker_client
                                    .container_tracker
                                    .add_container(container.clone())
                                {
                                    debug!(
                                        "Could not add container {} to tracker: {}",
                                        container.name, e
                                    );
                                }

                                // Check if container is in exited state
                                let is_exited = container_summary
                                    .state
                                    .as_ref()
                                    .map(|s| {
                                        let state_str = format!("{:?}", s);
                                        state_str.contains("EXITED") || state_str.contains("Exited")
                                    })
                                    .unwrap_or(false);

                                if is_exited {
                                    info!(
                                        "Container {} is in exited state - will attempt restart after setting up rules",
                                        container.name
                                    );
                                    containers_to_restart
                                        .push((container.id.clone(), container.name.clone()));
                                }

                                // ALL harborshield-enabled containers need a chain, not just those with rules
                                // Create the chain proactively to avoid race conditions
                                info!(
                                    "Creating chain proactively for harborshield-enabled container {} that will start soon",
                                    container.name
                                );

                                // Create the chain (but not the rules yet, as the container might not have IPs)
                                let nftables = self.nftables_client.lock().await;
                                let mut transaction = RuleSet::builder()
                                    .family(nftables.family)
                                    .build();

                                let _chain_name =
                                    RuleSet::add_container_chain_to_transaction(
                                        nftables.family,
                                        &mut transaction,
                                        &container.id,
                                        &container.name,
                                    )?;

                                // Add DROP rule at the end
                                RuleSet::add_container_drop_rule_to_transaction(
                                    nftables.family,
                                    &mut transaction,
                                    &container.id,
                                    &container.name,
                                )?;

                                transaction.commit().await?;

                                info!("Created chain for container {} proactively", container.name);
                            }
                        }
                        Err(e) => {
                            debug!("Could not inspect container {}: {}", id, e);
                        }
                    }
                }
            }
        }

        // Process running containers
        for container_summary in containers {
            if let Some(id) = container_summary.id {
                let names = container_summary
                    .names
                    .as_ref()
                    .map(|n| n.join(", "))
                    .unwrap_or_else(|| "unknown".to_string());
                debug!("Checking container: {} ({})", names, &id[..12]);

                if let Err(e) = self
                    .process_running_container(&id, &mut db_container_ids)
                    .await
                {
                    error!("Failed to process container {}: {}", id, e);
                    // Continue processing other containers
                }
            }
        }

        // Phase 3: Restart containers that failed to start due to missing firewall rules
        if !containers_to_restart.is_empty() {
            info!(
                "Phase 3: Attempting to restart {} containers that were in exited state",
                containers_to_restart.len()
            );

            // Wait a bit to ensure all rules are fully applied
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            for (container_id, container_name) in containers_to_restart {
                info!(
                    "Attempting to restart container {} ({})",
                    container_name,
                    &container_id[..12.min(container_id.len())]
                );

                match self.docker_client.start_container(&container_id).await {
                    Ok(_) => {
                        info!(
                            "Successfully restarted container {} after applying firewall rules",
                            container_name
                        );
                    }
                    Err(e) => {
                        error!("Failed to restart container {}: {}", container_name, e);
                    }
                }
            }
        } else {
            debug!("No containers need to be restarted");
        }

        Ok(db_container_ids)
    }
    /// Create waiting rules for a container's references
    pub async fn create_waiting_rules_for_container(&self, container: &Container) -> Result<()> {
        // Get the container's config
        let config = match &container.config {
            Some(config) => config,
            None => {
                // No config means no waiting rules to create
                return Ok(());
            }
        };

        // Process output rules to create waiting rules
        for rule_config in &config.output {
            if !rule_config.container.is_empty() {
                let dst_ports: Vec<u16> = rule_config
                    .dst_ports
                    .iter()
                    .flat_map(|p| match p {
                        RulePorts::Single(port) => vec![*port],
                        RulePorts::Range(start, end) => (*start..=*end).collect(),
                    })
                    .collect();

                // Create waiting rule data
                #[derive(Debug, serde::Serialize)]
                struct WaitingRuleData {
                    protocol: String,
                    dst_ports: Vec<u16>,
                    log_prefix: Option<String>,
                }

                let waiting_rule_data = WaitingRuleData {
                    protocol: rule_config.proto.to_string(),
                    dst_ports,
                    log_prefix: if rule_config.log_prefix.is_empty() {
                        None
                    } else {
                        Some(rule_config.log_prefix.clone())
                    },
                };

                let serialized_rule = serde_json::to_vec(&waiting_rule_data)?;

                let waiting_rule = crate::database::WaitingContainerRule {
                    src_container_id: container.id.clone(),
                    dst_container_name: rule_config.container.clone(),
                    rule: serialized_rule,
                };

                let db_lock = self.db.lock().await;
                db_lock.insert_waiting_rule(&waiting_rule).await?;
                drop(db_lock);

                info!(
                    "Created waiting rule: {} wants to connect to {} on port(s) {:?}",
                    container.name, rule_config.container, waiting_rule_data.dst_ports
                );
            }
        }

        Ok(())
    }

    /// Process a non-running container to create waiting rules
    pub async fn process_non_running_container(&self, container: &Container) -> Result<()> {
        info!(
            "Processing non-running container {} to create waiting rules",
            container.name
        );

        // Check if container has rules defined
        if container.config.is_some() {
            self.create_waiting_rules_for_container(container).await?;
        }

        Ok(())
    }

    /// Process a single running container
    pub async fn process_running_container(
        &self,
        container_id: &str,
        db_container_ids: &mut HashMap<String, ContainerIdentifiers>,
    ) -> Result<()> {
        let container = self
            .docker_client
            .try_get_container_by_id(container_id)
            .await?;

        if !container.is_harborshield_enabled() {
            debug!(
                "Container {} is not harborshield enabled, skipping",
                container.name
            );
            return Ok(());
        }

        info!(
            "Processing harborshield-enabled container: {} ({})",
            container.name,
            &container.id[..12]
        );

        let is_new = !db_container_ids.contains_key(container_id);

        // Add to tracker
        self.docker_client
            .container_tracker
            .add_container(container.clone())?;

        // Store in database before creating rules to avoid foreign key issues
        // Check if already stored (might have been stored in Phase 1)
        if let Err(e) = super::Harborshield::store_container_in_database(&container, &self.db).await
        {
            debug!(
                "Could not store container {} in database (may already exist): {}",
                container.name, e
            );
        }

        // Apply rules if not using host network
        self.create_container_rules(&container, None).await?;

        // Process any waiting rules for this container
        // This is needed for containers that receive C2C rules from other containers
        self.process_waiting_rules_for_container(&container.name, container_id)
            .await?;

        // Remove from db_container_ids as it's still running
        db_container_ids.remove(container_id);

        // Log compose information
        self.log_compose_info(&container, container_id, &container.name, is_new);

        // Container IPs are added to the named set in create_container_rules

        Ok(())
    }

    // The old create_container_rules method has been replaced by create_container_rules
    // which uses direct config-to-nftables translation instead of intermediate types

    pub async fn delete_container_rules(
        &self,
        container_id: &str,
        container_name: &str,
    ) -> Result<()> {
        // Note: We don't have container IPs here, but that's okay because
        // the container is already stopped and IPs may have been released

        let mut transaction = RuleSet::builder().build();
        transaction.remove_container_rules(container_id, container_name)?;
        transaction.commit().await?;

        let db = self.db.lock().await;
        db.delete_container(container_id).await?;

        Ok(())
    }

    /// Update metrics for monitoring
    pub async fn update_metrics(&self) {
        let container_count = self.docker_client.container_tracker.container_count();
        crate::server::set_active_containers(container_count as u64);

        // In stateless mode, we don't track persistent rules
        crate::server::set_active_rules(0);
    }

    /// Get runtime statistics
    pub async fn get_stats(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();

        stats.insert(
            "start_time".to_string(),
            serde_json::Value::String(self.start_time.to_rfc3339()),
        );

        stats.insert(
            "uptime_seconds".to_string(),
            serde_json::Value::Number(serde_json::Number::from(
                (chrono::Utc::now() - self.start_time).num_seconds(),
            )),
        );

        let container_count = self.docker_client.container_tracker.container_count();
        stats.insert(
            "active_containers".to_string(),
            serde_json::Value::Number(serde_json::Number::from(container_count)),
        );

        // In stateless mode, we don't track persistent rules
        stats.insert(
            "persistent_rules".to_string(),
            serde_json::Value::Number(serde_json::Number::from(0)),
        );

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::container::{Container, PortMapping};
    use std::collections::HashMap;

    #[test]
    fn test_convert_rule_ports_single() {
        let ports = vec![RulePorts::Single(80)];
        let result = convert_rule_ports(&ports);
        assert_eq!(result, vec![80]);
    }

    #[test]
    fn test_convert_rule_ports_range() {
        let ports = vec![RulePorts::Range(80, 83)];
        let result = convert_rule_ports(&ports);
        assert_eq!(result, vec![80, 81, 82, 83]);
    }

    #[test]
    fn test_convert_rule_ports_mixed() {
        let ports = vec![RulePorts::Single(22), RulePorts::Range(80, 82)];
        let result = convert_rule_ports(&ports);
        assert_eq!(result, vec![22, 80, 81, 82]);
    }

    #[test]
    fn test_convert_rule_ports_empty() {
        let ports: Vec<RulePorts> = vec![];
        let result = convert_rule_ports(&ports);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_mapped_ports_empty() {
        let container = Container {
            id: "test".to_string(),
            name: "test".to_string(),
            labels: HashMap::new(),
            networks: HashMap::new(),
            ports: vec![],
            enabled: false,
            paused: false,
            config: None,
            uses_host_network: false,
            aliases: vec![],
        };
        let result = extract_mapped_ports(&container);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_mapped_ports_no_host_port() {
        let container = Container {
            id: "test".to_string(),
            name: "test".to_string(),
            labels: HashMap::new(),
            networks: HashMap::new(),
            ports: vec![PortMapping {
                container_port: 80,
                host_port: None,
                protocol: "tcp".to_string(),
            }],
            enabled: false,
            paused: false,
            config: None,
            uses_host_network: false,
            aliases: vec![],
        };
        let result = extract_mapped_ports(&container);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_mapped_ports_tcp() {
        let container = Container {
            id: "test".to_string(),
            name: "test".to_string(),
            labels: HashMap::new(),
            networks: HashMap::new(),
            ports: vec![PortMapping {
                container_port: 80,
                host_port: Some(8080),
                protocol: "tcp".to_string(),
            }],
            enabled: false,
            paused: false,
            config: None,
            uses_host_network: false,
            aliases: vec![],
        };
        let result = extract_mapped_ports(&container);
        assert!(result.is_some());
        let (external, tcp, udp) = result.unwrap();
        assert_eq!(external, vec![8080]);
        assert_eq!(tcp, vec![80]);
        assert!(udp.is_empty());
    }

    #[test]
    fn test_extract_mapped_ports_udp() {
        let container = Container {
            id: "test".to_string(),
            name: "test".to_string(),
            labels: HashMap::new(),
            networks: HashMap::new(),
            ports: vec![PortMapping {
                container_port: 53,
                host_port: Some(53),
                protocol: "udp".to_string(),
            }],
            enabled: false,
            paused: false,
            config: None,
            uses_host_network: false,
            aliases: vec![],
        };
        let result = extract_mapped_ports(&container);
        assert!(result.is_some());
        let (external, tcp, udp) = result.unwrap();
        assert_eq!(external, vec![53]);
        assert!(tcp.is_empty());
        assert_eq!(udp, vec![53]);
    }

    #[test]
    fn test_extract_mapped_ports_mixed() {
        let container = Container {
            id: "test".to_string(),
            name: "test".to_string(),
            labels: HashMap::new(),
            networks: HashMap::new(),
            ports: vec![
                PortMapping {
                    container_port: 80,
                    host_port: Some(8080),
                    protocol: "tcp".to_string(),
                },
                PortMapping {
                    container_port: 53,
                    host_port: Some(5353),
                    protocol: "udp".to_string(),
                },
            ],
            enabled: false,
            paused: false,
            config: None,
            uses_host_network: false,
            aliases: vec![],
        };
        let result = extract_mapped_ports(&container);
        assert!(result.is_some());
        let (external, tcp, udp) = result.unwrap();
        assert_eq!(external.len(), 2);
        assert_eq!(tcp, vec![80]);
        assert_eq!(udp, vec![53]);
    }
}
