use crate::docker::compose::ComposeInfo;
use crate::docker::config::{Config, Protocol};
use crate::{ENABLED_LABEL, RULES_LABEL};
use crate::{Error, Result};
use bon::Builder;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tracing::warn;

#[cfg(test)]
mod tests;

/// Label listing extra names other containers' rules may use for this one.
pub const ALIASES_LABEL: &str = "harborshield.aliases";

#[derive(Debug, Clone, Builder)]
pub struct Container {
    pub id: String,
    pub name: String,
    /// Names this container answers to besides `name`: compose service names, the short id
    /// and the `harborshield.aliases` label.
    #[builder(default)]
    pub aliases: Vec<String>,
    #[builder(default)]
    pub labels: HashMap<String, String>,
    #[builder(default)]
    pub networks: HashMap<String, Network>,
    /// Ports published on the host, which `mapped_ports` rules govern.
    #[builder(default)]
    pub published: Vec<PublishedPort>,
    #[builder(default = true)]
    pub enabled: bool,
    pub config: Option<Config>,
    #[builder(default = false)]
    pub uses_host_network: bool,
}

#[derive(Debug, Clone, Builder)]
pub struct Network {
    pub name: String,
    #[builder(default)]
    pub ip_addresses: Vec<IpAddr>,
    /// Gateways of this network, the addresses docker-proxy connects from.
    #[builder(default)]
    pub gateways: Vec<IpAddr>,
    /// DNS names the container answers to on this network.
    #[builder(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Builder)]
pub struct PublishedPort {
    pub container_port: u16,
    pub protocol: Protocol,
}

/// The running containers harborshield knows about, managed or not; unmanaged ones are kept
/// so rules that reference them by name can be resolved.
#[derive(Debug, Clone, Default)]
pub struct Tracker {
    containers: Arc<Mutex<HashMap<String, Container>>>,
}

impl Tracker {
    // Every critical section is a single map operation, so a panic elsewhere cannot leave the
    // map half-updated and a poisoned lock is safe to reuse.
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Container>> {
        self.containers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub fn upsert(&self, container: Container) {
        self.lock().insert(container.id.clone(), container);
    }

    pub fn remove(&self, id: &str) -> Option<Container> {
        self.lock().remove(id)
    }

    pub fn get(&self, id: &str) -> Option<Container> {
        self.lock().get(id).cloned()
    }

    pub fn replace_all(&self, containers: Vec<Container>) {
        let mut guard = self.lock();
        guard.clear();
        guard.extend(
            containers
                .into_iter()
                .map(|container| (container.id.clone(), container)),
        );
    }

    /// Every tracked container, ordered by id so reconciles are deterministic.
    pub fn snapshot(&self) -> Vec<Container> {
        let mut containers: Vec<Container> = self.lock().values().cloned().collect();
        containers.sort_by(|left, right| left.id.cmp(&right.id));
        containers
    }

    pub fn clear(&self) {
        self.lock().clear();
    }
}

impl Container {
    pub fn from_inspect(inspect: bollard::models::ContainerInspectResponse) -> Result<Self> {
        let id = inspect.id.ok_or(Error::IncompleteContainer("an id"))?;

        let name = inspect
            .name
            .ok_or(Error::IncompleteContainer("a name"))?
            .trim_start_matches('/')
            .to_string();

        let labels = inspect
            .config
            .as_ref()
            .and_then(|config| config.labels.clone())
            .unwrap_or_default();

        let uses_host_network = inspect
            .host_config
            .as_ref()
            .and_then(|host_config| host_config.network_mode.as_deref())
            == Some("host");

        let mut networks = HashMap::new();
        let mut aliases = Vec::new();
        if let Some(endpoints) = inspect
            .network_settings
            .and_then(|settings| settings.networks)
        {
            for (network_name, endpoint) in endpoints {
                let ip_addresses = [&endpoint.ip_address, &endpoint.global_ipv6_address]
                    .into_iter()
                    .filter_map(|address| parse_address(address.as_deref(), &name, "address"))
                    .collect();
                let gateways = [&endpoint.gateway, &endpoint.ipv6_gateway]
                    .into_iter()
                    .filter_map(|address| parse_address(address.as_deref(), &name, "gateway"))
                    .collect();
                let network_aliases: Vec<String> = endpoint
                    .aliases
                    .into_iter()
                    .flatten()
                    .chain(endpoint.dns_names.into_iter().flatten())
                    .collect();
                aliases.extend(network_aliases.iter().cloned());
                networks.insert(
                    network_name.clone(),
                    Network {
                        name: network_name,
                        ip_addresses,
                        gateways,
                        aliases: network_aliases,
                    },
                );
            }
        }

        let published = inspect
            .host_config
            .and_then(|host_config| host_config.port_bindings)
            .into_iter()
            .flatten()
            .filter(|(_, bindings)| bindings.as_ref().is_some_and(|list| !list.is_empty()))
            .filter_map(|(spec, _)| parse_published(&spec, &name))
            .collect();

        aliases.extend(ComposeInfo::from_labels(&labels).generate_aliases());
        if let Some(short_id) = id.get(..12) {
            aliases.push(short_id.to_owned());
        }
        if let Some(custom) = labels.get(ALIASES_LABEL) {
            aliases.extend(
                custom
                    .split(',')
                    .map(str::trim)
                    .filter(|alias| !alias.is_empty())
                    .map(str::to_owned),
            );
        }
        aliases.sort();
        aliases.dedup();

        let enabled = labels.get(ENABLED_LABEL).map(String::as_str) == Some("true");

        // A container whose rules do not parse stays managed with no grants: fully denied.
        let config = labels.get(RULES_LABEL).and_then(|rules| {
            serde_saphyr::from_str::<Config>(rules)
                .inspect_err(|error| {
                    warn!(
                        container = %name,
                        %error,
                        "invalid harborshield.rules; the container gets no grants and is fully denied"
                    );
                })
                .ok()
        });

        Ok(Container {
            id,
            name,
            aliases,
            labels,
            networks,
            published,
            enabled,
            config,
            uses_host_network,
        })
    }

    pub fn compose(&self) -> ComposeInfo {
        ComposeInfo::from_labels(&self.labels)
    }
}

/// Docker reports an absent address as an empty string; anything else must parse.
fn parse_address(raw: Option<&str>, container: &str, what: &str) -> Option<IpAddr> {
    let raw = raw.filter(|raw| !raw.is_empty())?;
    match raw.parse() {
        Ok(address) => Some(address),
        Err(error) => {
            warn!(%container, %raw, %error, "Docker reported an unparseable {what}; ignoring it");
            None
        }
    }
}

/// Parse a `8080/tcp` binding key. Protocols harborshield cannot match (such as sctp) are
/// left out, so their ports stay behind the default drop.
fn parse_published(spec: &str, container: &str) -> Option<PublishedPort> {
    let (port, protocol) = spec.split_once('/')?;
    let protocol = match protocol {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        other => {
            warn!(%container, port = %spec, "published {other} port cannot be allowed; it stays denied");
            return None;
        }
    };
    match port.parse() {
        Ok(container_port) => Some(PublishedPort {
            container_port,
            protocol,
        }),
        Err(error) => {
            warn!(%container, port = %spec, %error, "unparseable published port; it stays denied");
            None
        }
    }
}
