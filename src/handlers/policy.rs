//! Pure translation of the tracked containers into the firewall's desired state.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::docker::config::{AddrOrRange, Config, ConfigVerdict, RuleConfig};
use crate::docker::container::Container;
use crate::nftables::rules::{
    EstablishedQueues, ExternalAccess, LocalAccess, ManagedContainer, OutputRule, Peers,
    PublishedPort, Verdict,
};

/// The managed containers and their resolved policies. `containers` holds every running
/// container, managed or not, since rules may name either.
pub fn desired_state(containers: &[Container]) -> Vec<ManagedContainer> {
    containers
        .iter()
        .filter(|container| container.enabled && !container.uses_host_network)
        .map(|container| managed(container, containers))
        .collect()
}

fn managed(container: &Container, all: &[Container]) -> ManagedContainer {
    let addresses: BTreeSet<IpAddr> = container
        .networks
        .values()
        .flat_map(|network| network.ip_addresses.iter().copied())
        .collect();
    let gateways: BTreeSet<IpAddr> = container
        .networks
        .values()
        .flat_map(|network| network.gateways.iter().copied())
        .collect();
    let published = container
        .published
        .iter()
        .map(|port| PublishedPort {
            port: port.container_port,
            proto: port.protocol,
        })
        .collect();

    let (localhost, external, outputs) = match &container.config {
        None => (None, None, Vec::new()),
        Some(config) => (
            localhost_access(config, &gateways),
            external_access(config),
            config
                .output
                .iter()
                .filter_map(|rule| output_rule(container, rule, all))
                .collect(),
        ),
    };

    ManagedContainer {
        id: container.id.clone(),
        name: container.name.clone(),
        addresses: addresses.into_iter().collect(),
        gateways: gateways.iter().copied().collect(),
        published,
        localhost,
        external,
        outputs,
    }
}

fn localhost_access(config: &Config, gateways: &BTreeSet<IpAddr>) -> Option<LocalAccess> {
    let local = &config.mapped_ports.localhost;
    if !local.allow {
        return None;
    }
    let mut sources = vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    // docker-proxy relays connections to a published port from the network's gateway.
    if local.include_gateway_ips {
        sources.extend(gateways.iter().copied());
    }
    Some(LocalAccess {
        sources,
        log_prefix: non_empty(&local.log_prefix),
        verdict: verdict(&local.verdict),
    })
}

fn external_access(config: &Config) -> Option<ExternalAccess> {
    let external = &config.mapped_ports.external;
    if !external.allow {
        return None;
    }
    Some(ExternalAccess {
        sources: if external.ips.is_empty() {
            Peers::Any
        } else {
            Peers::Only(external.ips.clone())
        },
        log_prefix: non_empty(&external.log_prefix),
        verdict: verdict(&external.verdict),
    })
}

/// `None` when the rule names a container that is not running yet; the next reconcile after
/// it starts picks the rule up.
fn output_rule(source: &Container, rule: &RuleConfig, all: &[Container]) -> Option<OutputRule> {
    let destinations = if !rule.container.is_empty() {
        let addresses = resolve(source, rule, all);
        if addresses.is_empty() {
            tracing::debug!(
                container = %source.name,
                target = %rule.container,
                network = %rule.network,
                "rule target is not running on that network yet",
            );
            return None;
        }
        Peers::Only(addresses.into_iter().map(AddrOrRange::Addr).collect())
    } else if rule.ips.is_empty() {
        Peers::Any
    } else {
        Peers::Only(rule.ips.clone())
    };
    Some(OutputRule {
        destinations,
        proto: rule.proto,
        src_ports: rule.src_ports.clone(),
        dst_ports: rule.dst_ports.clone(),
        log_prefix: non_empty(&rule.log_prefix),
        verdict: verdict(&rule.verdict),
    })
}

/// Addresses, on the rule's network, of every container answering to the rule's name. A
/// compose project's containers may name the network as written in their compose file.
fn resolve(source: &Container, rule: &RuleConfig, all: &[Container]) -> BTreeSet<IpAddr> {
    let mut networks = vec![rule.network.clone()];
    if let Some(project) = source.compose().project {
        networks.push(format!("{project}_{}", rule.network));
    }
    all.iter()
        .filter(|target| target.id != source.id)
        .flat_map(|target| {
            networks
                .iter()
                .filter_map(|name| target.networks.get(name))
                .filter(|network| {
                    target.name == rule.container
                        || network.aliases.contains(&rule.container)
                        || target.aliases.contains(&rule.container)
                })
                .flat_map(|network| network.ip_addresses.iter().copied())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn verdict(config: &ConfigVerdict) -> Verdict {
    if !config.chain.is_empty() {
        Verdict::Jump(config.chain.clone())
    } else if config.queue != 0 {
        // Validation guarantees the two established queues are set together or not at all.
        let established = (config.input_est_queue != 0).then_some(EstablishedQueues {
            inbound: config.input_est_queue,
            outbound: config.output_est_queue,
        });
        Verdict::Queue {
            number: config.queue,
            established,
        }
    } else {
        Verdict::Accept
    }
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use super::desired_state;
    use crate::docker::compose::{COMPOSE_PROJECT_LABEL, COMPOSE_SERVICE_LABEL};
    use crate::docker::config::{AddrOrRange, Config};
    use crate::docker::container::{Container, Network};
    use crate::nftables::rules::{EstablishedQueues, Peers, Verdict};

    fn address(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(172, 18, 0, last))
    }

    fn network(name: &str, last: u8, aliases: &[&str]) -> (String, Network) {
        (
            name.to_owned(),
            Network::builder()
                .name(name.to_owned())
                .ip_addresses(vec![address(last)])
                .gateways(vec![address(1)])
                .aliases(aliases.iter().map(|alias| (*alias).to_owned()).collect())
                .build(),
        )
    }

    fn container(
        id: &str,
        name: &str,
        networks: Vec<(String, Network)>,
        rules: Option<&str>,
    ) -> Container {
        Container::builder()
            .id(id.to_owned())
            .name(name.to_owned())
            .networks(networks.into_iter().collect())
            .maybe_config(
                rules.map(|yaml| serde_saphyr::from_str::<Config>(yaml).expect("valid rules")),
            )
            .build()
    }

    fn rule_to(target: &str, network: &str) -> String {
        format!(
            "output:\n  - container: {target}\n    network: {network}\n    proto: tcp\n    dst_ports: [8080]\n"
        )
    }

    #[test]
    fn only_enabled_bridge_containers_are_managed() {
        let mut disabled = container("a", "plain", vec![network("net", 2, &[])], None);
        disabled.enabled = false;
        let mut host = container("b", "host", Vec::new(), None);
        host.uses_host_network = true;
        let managed = container("c", "managed", vec![network("net", 4, &[])], None);
        let desired = desired_state(&[disabled, host, managed]);
        assert_eq!(
            desired
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            vec!["managed"]
        );
    }

    #[test]
    fn a_container_without_rules_gets_no_grants() {
        let desired = desired_state(&[container("a", "web", vec![network("net", 2, &[])], None)]);
        let managed = desired.first().expect("managed");
        assert!(
            managed.localhost.is_none() && managed.external.is_none() && managed.outputs.is_empty()
        );
        assert_eq!(managed.addresses, vec![address(2)]);
    }

    #[test]
    fn a_container_reference_resolves_to_the_target_on_the_named_network_only() {
        let target = container(
            "t",
            "db",
            vec![network("back", 3, &[]), network("front", 9, &[])],
            None,
        );
        let source = container(
            "s",
            "app",
            vec![network("back", 2, &[])],
            Some(&rule_to("db", "back")),
        );
        let desired = desired_state(&[source, target]);
        let app = desired.iter().find(|item| item.name == "app").expect("app");
        let output = app.outputs.first().expect("resolved rule");
        assert_eq!(
            output.destinations,
            Peers::Only(vec![AddrOrRange::Addr(address(3))])
        );
    }

    #[test]
    fn a_reference_to_a_container_not_running_waits() {
        let source = container(
            "s",
            "app",
            vec![network("back", 2, &[])],
            Some(&rule_to("db", "back")),
        );
        let desired = desired_state(&[source]);
        assert!(desired.first().expect("app").outputs.is_empty());
    }

    #[test]
    fn compose_services_resolve_with_project_local_network_names() {
        let labels = |service: &str| {
            HashMap::from([
                (COMPOSE_PROJECT_LABEL.to_owned(), "shop".to_owned()),
                (COMPOSE_SERVICE_LABEL.to_owned(), service.to_owned()),
            ])
        };
        let mut target = container(
            "t",
            "shop-db-1",
            vec![network("shop_back", 3, &["db"])],
            None,
        );
        target.labels = labels("db");
        let mut source = container(
            "s",
            "shop-app-1",
            vec![network("shop_back", 2, &["app"])],
            Some(&rule_to("db", "back")),
        );
        source.labels = labels("app");
        let desired = desired_state(&[source, target]);
        let app = desired
            .iter()
            .find(|item| item.name == "shop-app-1")
            .expect("app");
        assert_eq!(
            app.outputs.first().expect("resolved rule").destinations,
            Peers::Only(vec![AddrOrRange::Addr(address(3))])
        );
    }

    #[test]
    fn localhost_sources_include_gateways_only_when_asked() {
        let with = container(
            "a",
            "web",
            vec![network("net", 2, &[])],
            Some("mapped_ports:\n  localhost:\n    allow: true\n"),
        );
        let without = container(
            "b",
            "api",
            vec![network("net", 3, &[])],
            Some("mapped_ports:\n  localhost:\n    allow: true\n    include_gateway_ips: false\n"),
        );
        let desired = desired_state(&[with, without]);
        let sources = |name: &str| {
            desired
                .iter()
                .find(|item| item.name == name)
                .and_then(|item| item.localhost.clone())
                .expect("localhost access")
                .sources
        };
        assert!(sources("web").contains(&address(1)));
        assert!(!sources("api").contains(&address(1)));
    }

    #[test]
    fn verdicts_map_to_jump_and_queue_with_established_queues() {
        let rules = "output:\n  - ips: [10.0.0.1]\n    proto: tcp\n    dst_ports: [80]\n    verdict:\n      queue: 5\n      input_est_queue: 6\n      output_est_queue: 7\n  - ips: [10.0.0.2]\n    proto: tcp\n    dst_ports: [80]\n    verdict:\n      chain: audit\n";
        let desired = desired_state(&[container(
            "a",
            "web",
            vec![network("net", 2, &[])],
            Some(rules),
        )]);
        let outputs = &desired.first().expect("managed").outputs;
        assert_eq!(
            outputs.first().map(|output| output.verdict.clone()),
            Some(Verdict::Queue {
                number: 5,
                established: Some(EstablishedQueues {
                    inbound: 6,
                    outbound: 7
                }),
            })
        );
        assert_eq!(
            outputs.get(1).map(|output| output.verdict.clone()),
            Some(Verdict::Jump("audit".to_owned()))
        );
    }
}
