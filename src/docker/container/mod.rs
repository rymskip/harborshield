use crate::docker::compose::ComposeInfo;
use crate::docker::config::Config;
use crate::{ENABLED_LABEL, RULES_LABEL};
use crate::{Error, Result};
use bon::Builder;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Builder)]
pub struct Container {
    pub id: String,
    pub name: String,
    #[builder(default)]
    pub aliases: Vec<String>,
    #[builder(default)]
    pub labels: HashMap<String, String>,
    #[builder(default)]
    pub networks: HashMap<String, Network>,
    #[builder(default)]
    pub ports: Vec<PortMapping>,
    #[builder(default = true)]
    pub enabled: bool,
    pub config: Option<Config>,
    #[builder(default = false)]
    pub uses_host_network: bool,
    #[builder(default = false)]
    pub paused: bool,
}

#[derive(Debug, Clone, Builder)]
pub struct Network {
    pub name: String,
    #[builder(default)]
    pub ip_addresses: Vec<IpAddr>,
    #[builder(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Builder)]
pub struct Tracker {
    #[builder(default)]
    containers: Arc<Mutex<HashMap<String, Container>>>,
    #[builder(default)]
    name_to_id: Arc<Mutex<HashMap<String, String>>>,
    #[builder(default)]
    alias_to_id: Arc<Mutex<HashMap<String, String>>>,
    #[builder(default)]
    network_containers: Arc<Mutex<HashMap<String, HashSet<String>>>>,
}

#[derive(Debug, Clone, Builder)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: Option<u16>,
    pub protocol: String,
}

impl Tracker {
    pub fn add_container(&self, details: Container) -> Result<()> {
        let mut containers = self.containers.lock().unwrap();
        let mut name_to_id = self.name_to_id.lock().unwrap();
        let mut alias_to_id = self.alias_to_id.lock().unwrap();
        let mut network_containers = self.network_containers.lock().unwrap();

        // Add to main container map
        let id = details.id.clone();
        let name = details.name.clone();

        containers.insert(id.clone(), details.clone());
        name_to_id.insert(name.clone(), id.clone());

        // Add aliases
        for alias in &details.aliases {
            alias_to_id.insert(alias.clone(), id.clone());
        }

        // Track networks
        for (net_name, _) in &details.networks {
            network_containers
                .entry(net_name.clone())
                .or_insert_with(HashSet::new)
                .insert(id.clone());
        }

        info!(container_id = %id, container_name = %name, "Added container to tracker");
        Ok(())
    }

    pub fn remove_container(&self, id: &str) -> Result<Option<Container>> {
        let mut containers = self.containers.lock().unwrap();
        let mut name_to_id = self.name_to_id.lock().unwrap();
        let mut alias_to_id = self.alias_to_id.lock().unwrap();
        let mut network_containers = self.network_containers.lock().unwrap();

        if let Some(details) = containers.remove(id) {
            // Remove from name mapping
            name_to_id.remove(&details.name);

            // Remove aliases
            for alias in &details.aliases {
                alias_to_id.remove(alias);
            }

            // Remove from network tracking
            for (net_name, _) in &details.networks {
                if let Some(container_set) = network_containers.get_mut(net_name) {
                    container_set.remove(id);
                    if container_set.is_empty() {
                        network_containers.remove(net_name);
                    }
                }
            }

            info!(container_id = %id, container_name = %details.name, "Removed container from tracker");
            Ok(Some(details))
        } else {
            Ok(None)
        }
    }

    pub fn get_container(&self, id: &str) -> Option<Container> {
        self.containers.lock().unwrap().get(id).cloned()
    }

    pub fn get_container_by_name(&self, name: &str) -> Option<Container> {
        let name_to_id = self.name_to_id.lock().unwrap();
        if let Some(id) = name_to_id.get(name) {
            self.containers.lock().unwrap().get(id).cloned()
        } else {
            None
        }
    }

    pub fn get_container_by_alias(&self, alias: &str) -> Option<Container> {
        let alias_to_id = self.alias_to_id.lock().unwrap();
        if let Some(id) = alias_to_id.get(alias) {
            self.containers.lock().unwrap().get(id).cloned()
        } else {
            None
        }
    }

    pub fn get_containers_in_network(&self, network: &str) -> Vec<Container> {
        let network_containers = self.network_containers.lock().unwrap();
        let containers = self.containers.lock().unwrap();

        if let Some(container_ids) = network_containers.get(network) {
            container_ids
                .iter()
                .filter_map(|id| containers.get(id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn list_containers(&self) -> Vec<Container> {
        self.containers.lock().unwrap().values().cloned().collect()
    }

    pub fn clear(&self) {
        self.containers.lock().unwrap().clear();
        self.name_to_id.lock().unwrap().clear();
        self.alias_to_id.lock().unwrap().clear();
        self.network_containers.lock().unwrap().clear();
    }

    pub fn container_count(&self) -> usize {
        self.containers.lock().unwrap().len()
    }

    pub fn find_container(&self, identifier: &str) -> Option<Container> {
        // Try ID first
        if let Some(container) = self.get_container(identifier) {
            return Some(container);
        }

        // Try name
        if let Some(container) = self.get_container_by_name(identifier) {
            return Some(container);
        }

        // Try alias
        if let Some(container) = self.get_container_by_alias(identifier) {
            return Some(container);
        }

        None
    }

    pub fn update_container_networks(
        &self,
        id: &str,
        networks: HashMap<String, Network>,
    ) -> Result<()> {
        let mut containers = self.containers.lock().unwrap();
        let mut network_containers = self.network_containers.lock().unwrap();

        if let Some(details) = containers.get_mut(id) {
            // Remove from old networks
            for (old_net, _) in &details.networks {
                if !networks.contains_key(old_net) {
                    if let Some(container_set) = network_containers.get_mut(old_net) {
                        container_set.remove(id);
                        if container_set.is_empty() {
                            network_containers.remove(old_net);
                        }
                    }
                }
            }

            // Add to new networks
            for (new_net, _) in &networks {
                if !details.networks.contains_key(new_net) {
                    network_containers
                        .entry(new_net.clone())
                        .or_insert_with(HashSet::new)
                        .insert(id.to_string());
                }
            }

            details.networks = networks;
            Ok(())
        } else {
            Err(Error::container_not_found(id))
        }
    }

    pub fn update_container(&self, updated_details: Container) -> Result<()> {
        let mut containers = self.containers.lock().unwrap();
        let mut name_to_id = self.name_to_id.lock().unwrap();
        let mut alias_to_id = self.alias_to_id.lock().unwrap();
        let mut network_containers = self.network_containers.lock().unwrap();

        let id = &updated_details.id;

        if let Some(old_details) = containers.get(id) {
            // Update name mapping if name changed
            if old_details.name != updated_details.name {
                name_to_id.remove(&old_details.name);
                name_to_id.insert(updated_details.name.clone(), id.clone());
            }

            // Update alias mappings
            for old_alias in &old_details.aliases {
                if !updated_details.aliases.contains(old_alias) {
                    alias_to_id.remove(old_alias);
                }
            }
            for new_alias in &updated_details.aliases {
                if !old_details.aliases.contains(new_alias) {
                    alias_to_id.insert(new_alias.clone(), id.clone());
                }
            }

            // Update network mappings
            for (old_net, _) in &old_details.networks {
                if !updated_details.networks.contains_key(old_net) {
                    if let Some(container_set) = network_containers.get_mut(old_net) {
                        container_set.remove(id);
                        if container_set.is_empty() {
                            network_containers.remove(old_net);
                        }
                    }
                }
            }
            for (new_net, _) in &updated_details.networks {
                if !old_details.networks.contains_key(new_net) {
                    network_containers
                        .entry(new_net.clone())
                        .or_insert_with(HashSet::new)
                        .insert(id.clone());
                }
            }

            // Update the container details
            containers.insert(id.clone(), updated_details.clone());

            info!(container_id = %id, container_name = %updated_details.name, "Updated container in tracker");
            Ok(())
        } else {
            Err(Error::container_not_found(id))
        }
    }
}

impl Container {
    pub fn from_inspect(inspect: bollard::models::ContainerInspectResponse) -> Result<Self> {
        let id = inspect
            .id
            .ok_or_else(|| Error::invalid_state("Container missing ID", "has ID", "missing"))?;

        let name = inspect
            .name
            .ok_or_else(|| Error::invalid_state("Container missing name", "has name", "missing"))?
            .trim_start_matches('/')
            .to_string();

        let labels = inspect
            .config
            .as_ref()
            .and_then(|c| c.labels.clone())
            .unwrap_or_default();

        // Check if container uses host networking
        let uses_host_network = inspect
            .host_config
            .as_ref()
            .and_then(|hc| hc.network_mode.as_ref())
            .map(|mode| mode == "host")
            .unwrap_or(false);

        let mut networks = Vec::new();
        let mut all_aliases = Vec::new();

        if let Some(network_settings) = inspect.network_settings {
            if let Some(networks_map) = network_settings.networks {
                for (net_name, net_info) in networks_map {
                    let ip_addresses: Vec<IpAddr> = net_info
                        .ip_address
                        .and_then(|ip| ip.parse().ok())
                        .map(|ip| vec![ip])
                        .unwrap_or_else(Vec::new);

                    // Extract network aliases
                    let mut network_aliases = Vec::new();
                    if let Some(aliases) = net_info.aliases {
                        for alias in aliases {
                            network_aliases.push(alias.clone());
                            all_aliases.push(alias.clone());
                        }
                    }

                    networks.push(Network {
                        name: net_name,
                        ip_addresses: ip_addresses,
                        aliases: network_aliases,
                    });
                }
            }
        }

        let mut ports = Vec::new();
        if let Some(config) = inspect.config {
            if let Some(exposed_ports) = config.exposed_ports {
                for port_proto in exposed_ports {
                    let parts: Vec<&str> = port_proto.split('/').collect();
                    if parts.len() == 2 {
                        if let Ok(port_num) = parts[0].parse::<u16>() {
                            ports.push(PortMapping {
                                container_port: port_num,
                                host_port: None, // Will be filled from port bindings
                                protocol: parts[1].to_string(),
                            });
                        }
                    }
                }
            }
        }

        // Update port mappings with host port info
        if let Some(host_config) = inspect.host_config {
            if let Some(port_bindings) = host_config.port_bindings {
                for (container_port_str, bindings) in port_bindings {
                    let parts: Vec<&str> = container_port_str.split('/').collect();
                    if parts.len() == 2 {
                        if let Ok(container_port) = parts[0].parse::<u16>() {
                            if let Some(binding_list) = bindings {
                                if let Some(first_binding) = binding_list.first() {
                                    if let Some(host_port_str) = &first_binding.host_port {
                                        if let Ok(host_port) = host_port_str.parse::<u16>() {
                                            // Find and update the corresponding port
                                            for port in &mut ports {
                                                if port.container_port == container_port {
                                                    port.host_port = Some(host_port);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Extract Docker Compose aliases
        let compose_info = ComposeInfo::from_labels(&labels);
        for alias in compose_info.generate_aliases() {
            if !all_aliases.contains(&alias) {
                all_aliases.push(alias);
            }
        }

        // Add short container ID as alias (first 12 chars)
        if id.len() >= 12 {
            let short_id = &id[..12];
            if !all_aliases.contains(&short_id.to_string()) {
                all_aliases.push(short_id.to_string());
            }
        }

        // Add container name without leading slash as alias if different from main name
        let clean_name = name.trim_start_matches('/');
        if clean_name != name && !all_aliases.contains(&clean_name.to_string()) {
            all_aliases.push(clean_name.to_string());
        }

        // Extract custom aliases from harborshield labels
        if let Some(custom_aliases) = labels.get("harborshield.aliases") {
            for alias in custom_aliases.split(',') {
                let alias = alias.trim().to_string();
                if !alias.is_empty() && !all_aliases.contains(&alias) {
                    all_aliases.push(alias);
                }
            }
        }

        // Convert Network list to HashMap<String, Network>
        let network_details_map = networks
            .into_iter()
            .map(|net_info| {
                (
                    net_info.name.clone(),
                    Network::builder()
                        .name(net_info.name)
                        .ip_addresses(net_info.ip_addresses)
                        .aliases(net_info.aliases)
                        .build(),
                )
            })
            .collect();

        // Extract enabled and rules_yaml from labels
        let enabled = labels
            .get(ENABLED_LABEL)
            .map(|v| v == "true")
            .unwrap_or(false);

        // Parse and validate config during container creation
        let config = if let Some(rules_yaml) = labels.get(RULES_LABEL) {
            match serde_saphyr::from_str::<Config>(rules_yaml) {
                Ok(config) => Some(config),
                Err(e) => {
                    warn!(
                        "Failed to parse/validate rules for container {}: {}. Container will be created without rules.",
                        name, e
                    );
                    None
                }
            }
        } else {
            None
        };

        Ok(Container {
            id,
            name,
            labels,
            networks: network_details_map,
            ports,
            aliases: all_aliases,
            uses_host_network,
            enabled,
            config,
            paused: false, // Containers are not paused when starting/inspecting
        })
    }

    /// Check if harborshield is enabled for a container
    pub fn is_harborshield_enabled(&self) -> bool {
        self.labels
            .get(ENABLED_LABEL)
            .map(|v| v == "true")
            .unwrap_or(false)
    }
}
