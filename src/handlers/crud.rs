use super::Harborshield;
use crate::{
    Result,
    database::{
        Addr, ContainerAlias, DB, DbOp, WaitingContainerRule, models::ContainerIdentifiers,
    },
    docker::container::Container,
    nftables::transaction::RuleSet,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};

impl Harborshield {
    /// Remove container data from database
    pub async fn remove_container_from_database(&self, container_id: &str) -> Result<()> {
        let mut db_lock = self.db.lock().await;

        let ops = vec![
            DbOp::DeleteAddrsByContainer(container_id),
            DbOp::DeleteContainerAliases(container_id),
            DbOp::DeleteEstContainers(container_id),
            DbOp::DeleteWaitingRules(container_id),
            DbOp::DeleteContainer(container_id),
        ];

        db_lock
            .transaction()
            .execute_ops(&ops)
            .await?
            .commit()
            .await?;

        Ok(())
    }

    /// Handle container rename event
    pub async fn handle_container_rename(
        &self,
        container_id: &str,
        attributes: &Option<HashMap<String, String>>,
    ) -> Result<()> {
        if let Some(attributes) = attributes {
            let old_name = attributes
                .get("oldName")
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            let new_name = attributes
                .get("name")
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            info!(
                container_id = %container_id,
                old_name = %old_name,
                new_name = %new_name,
                "Container renamed"
            );

            // Update container if it's being tracked
            if self
                .docker_client
                .container_tracker
                .get_container(container_id)
                .is_some()
            {
                self.update_renamed_container(container_id).await?;
            }
        }
        Ok(())
    }

    /// Update container data after rename
    async fn update_renamed_container(&self, container_id: &str) -> Result<()> {
        // Re-inspect the container to get updated information
        match self
            .docker_client
            .try_get_container_by_id(container_id)
            .await
        {
            Ok(container_info) => {
                // Update container container
                self.docker_client
                    .container_tracker
                    .update_container(container_info.clone())?;

                // Update in database
                self.update_container_name_in_database(container_id, &container_info)
                    .await?;
            }
            Err(e) => {
                error!(
                    "Failed to inspect container {} after rename: {}",
                    container_id, e
                );
            }
        }
        Ok(())
    }

    /// Update container name and aliases in database
    async fn update_container_name_in_database(
        &self,
        container_id: &str,
        updated_details: &Container,
    ) -> Result<()> {
        let mut db_lock = self.db.lock().await;

        let mut ops = vec![];

        // Update container name
        ops.push(DbOp::UpdateContainerName {
            id: container_id,
            new_name: &updated_details.name,
        });

        // Remove old aliases
        ops.push(DbOp::DeleteContainerAliases(container_id));

        // Add new aliases
        let mut aliases = vec![];
        for alias in &updated_details.aliases {
            aliases.push(ContainerAlias {
                container_id: updated_details.id.clone(),
                container_alias: alias.clone(),
            });
        }
        for alias in &aliases {
            ops.push(DbOp::InsertContainerAlias(alias));
        }

        db_lock
            .transaction()
            .execute_ops(&ops)
            .await?
            .commit()
            .await?;

        Ok(())
    }

    /// Handle network connect/disconnect event
    pub async fn handle_network_event(
        &self,
        container_id: &str,
        action: &str,
        attributes: &Option<HashMap<String, String>>,
    ) -> Result<()> {
        if let Some(attributes) = attributes {
            let network_name = attributes
                .get("name")
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            let actual_container_id = attributes
                .get("container")
                .map(|s| s.as_str())
                .unwrap_or(container_id);

            info!(
                container_id = %actual_container_id,
                network_name = %network_name,
                action = %action,
                "Network event"
            );

            // If this is a tracked container, update its network information
            if self
                .docker_client
                .container_tracker
                .get_container(actual_container_id)
                .is_some()
            {
                self.update_container_network_info(actual_container_id)
                    .await?;
            }
        }
        Ok(())
    }

    /// Update container network information after network event
    async fn update_container_network_info(&self, container_id: &str) -> Result<()> {
        // Re-inspect the container to get updated network information
        match self
            .docker_client
            .try_get_container_by_id(container_id)
            .await
        {
            Ok(container_info) => {
                // Update container container with new network info
                self.docker_client
                    .container_tracker
                    .update_container(container_info.clone())?;

                // Update IP addresses and aliases in database
                self.update_container_network_in_database(container_id, &container_info)
                    .await?;

                // Update firewall rules that reference this container
                self.update_rules_for_container_network_change(container_id, &container_info)
                    .await?;

                // Container IPs will be updated in the named set when rules are recreated
            }
            Err(e) => {
                error!(
                    "Failed to inspect container {} after network event: {}",
                    container_id, e
                );
            }
        }
        Ok(())
    }

    /// Update container network data in database
    pub async fn update_container_network_in_database(
        &self,
        container_id: &str,
        updated_details: &Container,
    ) -> Result<()> {
        let mut db_lock = self.db.lock().await;

        let mut ops = vec![];

        // Remove old IP addresses for this container
        ops.push(DbOp::DeleteAddrsByContainer(container_id));

        // Add updated IP addresses
        let mut addrs = vec![];
        for (_, network) in &updated_details.networks {
            for ip in &network.ip_addresses {
                addrs.push(Addr::from_ip(*ip, container_id.to_string()));
            }
        }
        for addr in &addrs {
            ops.push(DbOp::InsertAddr(addr));
        }

        // Update aliases (network changes might affect aliases)
        ops.push(DbOp::DeleteContainerAliases(container_id));

        let mut aliases = vec![];
        for alias in &updated_details.aliases {
            aliases.push(ContainerAlias {
                container_id: updated_details.id.clone(),
                container_alias: alias.clone(),
            });
        }
        for alias in &aliases {
            ops.push(DbOp::InsertContainerAlias(alias));
        }

        db_lock
            .transaction()
            .execute_ops(&ops)
            .await?
            .commit()
            .await?;

        Ok(())
    }

    /// Add a waiting rule for a container that hasn't started yet
    pub async fn add_waiting_rule(
        &self,
        src_container_id: &str,
        dst_container_name: &str,
        rule_data: serde_json::Value,
    ) -> Result<()> {
        let serialized_rule = serde_json::to_vec(&rule_data).map_err(|e| {
            crate::Error::invalid_state(
                &format!("Failed to serialize rule: {}", e),
                "serializable",
                "serialization failed",
            )
        })?;

        let waiting_rule = WaitingContainerRule {
            src_container_id: src_container_id.to_string(),
            dst_container_name: dst_container_name.to_string(),
            rule: serialized_rule,
        };

        let db = self.db.lock().await;

        db.execute(&DbOp::InsertWaitingRule(&waiting_rule)).await?;

        info!(
            "Added waiting rule from {} to {} - will be applied when {} starts",
            src_container_id, dst_container_name, dst_container_name
        );

        Ok(())
    }

    /// Update rules when a container's network changes
    pub(super) async fn update_rules_for_container_network_change(
        &self,
        container_id: &str,
        updated_details: &Container,
    ) -> Result<()> {
        tracing::info!(
            "Updating rules for container {} after network change",
            container_id
        );

        // Get all containers that might have rules referencing this container
        let all_containers = self.docker_client.container_tracker.list_containers();
        let mut rules_to_update = Vec::new();

        // Check each container for rules that reference the changed container
        for container in &all_containers {
            if let Some(config) = &container.config {
                for rule_config in &config.output {
                    if rule_config.container == updated_details.name
                        || rule_config.container == container_id
                    {
                        // This rule references the container that changed networks
                        rules_to_update.push(container.clone());
                        break;
                    }
                }
            }
        }

        if rules_to_update.is_empty() {
            tracing::debug!(
                "No rules reference container {}, no updates needed",
                container_id
            );
            return Ok(());
        }

        tracing::info!(
            "Found {} containers with rules referencing {}",
            rules_to_update.len(),
            container_id
        );

        // Recreate rules for affected containers
        for container in rules_to_update {
            tracing::info!(
                "Recreating rules for container {} due to network change in {}",
                container.id,
                container_id
            );

            // We no longer need to remove from vmap - verdict maps are rebuilt dynamically

            let mut transaction = RuleSet::builder().build();
            transaction.remove_container_rules(&container.id, &container.name)?;
            transaction.commit().await?;

            // Recreate rules with updated IPs
            self.create_container_rules(
                &container, None, // cancellation_token
            )
            .await?;
        }

        Ok(())
    }

    /// Store container data in database
    pub(super) async fn store_container_in_database(
        container: &Container,
        db: &Arc<Mutex<DB>>,
    ) -> Result<()> {
        let mut db_lock = db.lock().await;

        let mut ops = vec![];

        // Insert container
        let container_identifiers = ContainerIdentifiers::builder()
            .id(container.id.clone())
            .name(container.name.clone())
            .build();

        ops.push(DbOp::InsertContainer(&container_identifiers));

        // Store IP addresses
        let mut addrs = vec![];
        for (_, network) in &container.networks {
            for ip in &network.ip_addresses {
                addrs.push(Addr::from_ip(*ip, container.id.clone()));
            }
        }
        for addr in &addrs {
            ops.push(DbOp::InsertAddr(addr));
        }

        // Store aliases
        let mut aliases = vec![];
        for alias in &container.aliases {
            aliases.push(ContainerAlias {
                container_id: container.id.clone(),
                container_alias: alias.clone(),
            });
        }
        for alias in &aliases {
            ops.push(DbOp::InsertContainerAlias(alias));
        }

        // Execute transaction
        db_lock
            .transaction()
            .execute_ops(&ops)
            .await?
            .commit()
            .await?;

        Ok(())
    }
}
