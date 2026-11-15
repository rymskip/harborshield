use std::collections::HashMap;

use super::{Container, DockerClient};
use crate::docker::config::Protocol;
use crate::docker::container::PublishedPort;
use bollard::models::{
    ContainerConfig, ContainerInspectResponse, ContainerState, EndpointSettings, HostConfig,
    NetworkSettings, PortBinding,
};
use std::net::{IpAddr, Ipv4Addr};
use temp_env::with_vars;

fn create_test_inspect_response(id: &str, name: &str) -> ContainerInspectResponse {
    ContainerInspectResponse {
        id: Some(id.to_string()),
        name: Some(format!("/{}", name)),
        config: Some(ContainerConfig {
            labels: Some(HashMap::from([(
                "harborshield.enabled".to_string(),
                "true".to_string(),
            )])),
            exposed_ports: Some(vec!["80/tcp".to_string()]),
            ..Default::default()
        }),
        network_settings: Some(NetworkSettings {
            networks: Some(HashMap::from([(
                "bridge".to_string(),
                EndpointSettings {
                    ip_address: Some("172.17.0.2".to_string()),
                    gateway: Some("172.17.0.1".to_string()),
                    ..Default::default()
                },
            )])),
            ..Default::default()
        }),
        host_config: Some(HostConfig {
            port_bindings: Some(HashMap::from([(
                "80/tcp".to_string(),
                Some(vec![PortBinding {
                    host_port: Some("8080".to_string()),
                    ..Default::default()
                }]),
            )])),
            network_mode: None,
            ..Default::default()
        }),
        state: Some(ContainerState {
            running: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn test_container_info_from_inspect() {
    let inspect = create_test_inspect_response("test123", "test-container");
    let info = Container::from_inspect(inspect).unwrap();

    assert_eq!(info.id, "test123");
    assert_eq!(info.name, "test-container");
    assert_eq!(
        info.labels.get("harborshield.enabled"),
        Some(&"true".to_string())
    );
    assert_eq!(info.networks.len(), 1);
    let bridge_network = info.networks.get("bridge").expect("network present");
    assert_eq!(bridge_network.name, "bridge");
    assert_eq!(
        bridge_network.ip_addresses.first(),
        Some(&IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2)))
    );
    assert_eq!(
        info.published,
        vec![PublishedPort {
            container_port: 80,
            protocol: Protocol::Tcp
        }]
    );
    assert_eq!(
        bridge_network.gateways,
        vec![IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1))]
    );
    assert!(info.enabled);
    assert!(!info.uses_host_network);
}

#[test]
fn test_container_info_missing_id() {
    let mut inspect = create_test_inspect_response("test", "test");
    inspect.id = None;

    let result = Container::from_inspect(inspect);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("without an id"));
}

#[test]
fn test_container_info_missing_name() {
    let mut inspect = create_test_inspect_response("test", "test");
    inspect.name = None;

    let result = Container::from_inspect(inspect);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("without a name"));
}

#[test]
fn test_container_info_no_config() {
    let mut inspect = create_test_inspect_response("test", "test");
    inspect.config = None;

    let info = Container::from_inspect(inspect).unwrap();
    assert!(info.labels.is_empty());
    assert!(!info.enabled);
    assert!(info.config.is_none());
}

#[test]
fn test_container_info_no_networks() {
    let mut inspect = create_test_inspect_response("test", "test");
    inspect.network_settings = None;

    let info = Container::from_inspect(inspect).unwrap();
    assert!(info.networks.is_empty());
}

#[test]
fn test_container_info_multiple_networks() {
    let mut inspect = create_test_inspect_response("test", "test");

    if let Some(ref mut network_settings) = inspect.network_settings {
        network_settings.networks = Some(HashMap::from([
            (
                "bridge".to_string(),
                EndpointSettings {
                    ip_address: Some("172.17.0.2".to_string()),
                    ..Default::default()
                },
            ),
            (
                "custom".to_string(),
                EndpointSettings {
                    ip_address: Some("10.0.0.2".to_string()),
                    ..Default::default()
                },
            ),
        ]));
    }

    let info = Container::from_inspect(inspect).unwrap();
    assert_eq!(info.networks.len(), 2);
}

#[test]
fn test_container_info_invalid_ip() {
    let mut inspect = create_test_inspect_response("test", "test");

    if let Some(ref mut network_settings) = inspect.network_settings {
        network_settings.networks = Some(HashMap::from([(
            "bridge".to_string(),
            EndpointSettings {
                ip_address: Some("invalid-ip".to_string()),
                ..Default::default()
            },
        )]));
    }

    let info = Container::from_inspect(inspect).unwrap();
    assert_eq!(info.networks.len(), 1);
    let bridge_network = info.networks.get("bridge").expect("network present");
    assert!(bridge_network.ip_addresses.is_empty());
}

#[test]
fn test_container_info_published_ports_come_from_bindings() {
    let mut inspect = create_test_inspect_response("test", "test");
    let binding = || {
        Some(vec![PortBinding {
            host_port: Some("9000".to_string()),
            ..Default::default()
        }])
    };
    if let Some(ref mut config) = inspect.config {
        config.exposed_ports = Some(vec!["7000/tcp".to_string()]);
    }
    if let Some(ref mut host_config) = inspect.host_config {
        host_config.port_bindings = Some(HashMap::from([
            ("443/tcp".to_string(), binding()),
            ("53/udp".to_string(), binding()),
            ("9999/sctp".to_string(), binding()),
            ("8000/tcp".to_string(), Some(Vec::new())),
            ("8001/tcp".to_string(), None),
        ]));
    }

    let info = Container::from_inspect(inspect).unwrap();
    let mut published: Vec<_> = info
        .published
        .iter()
        .map(|port| (port.container_port, port.protocol))
        .collect();
    published.sort_by_key(|(port, _)| *port);
    // Exposed-only, unbound and sctp ports are not published ports harborshield can open.
    assert_eq!(published, vec![(53, Protocol::Udp), (443, Protocol::Tcp)]);
}

#[test]
fn test_container_info_strip_leading_slash() {
    let inspect = create_test_inspect_response("test", "test");
    let info = Container::from_inspect(inspect).unwrap();

    // Name should have leading slash stripped
    assert_eq!(info.name, "test");
    assert!(!info.name.starts_with('/'));
}

#[test]
fn test_container_info_complex_labels() {
    let mut inspect = create_test_inspect_response("test", "test");

    if let Some(ref mut config) = inspect.config {
        config.labels = Some(HashMap::from([
            ("harborshield.enabled".to_string(), "true".to_string()),
            (
                "harborshield.rules".to_string(),
                "complex yaml config".to_string(),
            ),
            ("com.example.version".to_string(), "1.0.0".to_string()),
            ("maintainer".to_string(), "test@example.com".to_string()),
        ]));
    }

    let info = Container::from_inspect(inspect).unwrap();
    assert_eq!(info.labels.len(), 4);
    assert_eq!(
        info.labels.get("harborshield.enabled"),
        Some(&"true".to_string())
    );
    assert_eq!(
        info.labels.get("harborshield.rules"),
        Some(&"complex yaml config".to_string())
    );
}

#[test]
fn test_container_info_compose_aliases() {
    let mut inspect = create_test_inspect_response("abcdef123456", "myproject_web_1");

    if let Some(ref mut config) = inspect.config {
        config.labels = Some(HashMap::from([
            (
                "com.docker.compose.project".to_string(),
                "myproject".to_string(),
            ),
            ("com.docker.compose.service".to_string(), "web".to_string()),
            (
                "harborshield.aliases".to_string(),
                "frontend,api".to_string(),
            ),
        ]));
    }

    let info = Container::from_inspect(inspect).unwrap();

    // Should contain: compose service name, service.project, project_service, short ID, custom aliases
    let expected_aliases = vec![
        "web".to_string(),
        "web.myproject".to_string(),
        "myproject_web".to_string(),
        "abcdef123456".to_string(), // short ID
        "frontend".to_string(),
        "api".to_string(),
    ];

    for alias in expected_aliases {
        assert!(info.aliases.contains(&alias), "Missing alias: {}", alias);
    }
}

#[test]
fn test_container_info_network_aliases() {
    let mut inspect = create_test_inspect_response("test", "test");

    if let Some(ref mut network_settings) = inspect.network_settings {
        network_settings.networks = Some(HashMap::from([
            (
                "bridge".to_string(),
                EndpointSettings {
                    ip_address: Some("172.17.0.2".to_string()),
                    aliases: Some(vec!["web".to_string(), "frontend".to_string()]),
                    ..Default::default()
                },
            ),
            (
                "custom".to_string(),
                EndpointSettings {
                    ip_address: Some("10.0.0.2".to_string()),
                    aliases: Some(vec!["api".to_string()]),
                    ..Default::default()
                },
            ),
        ]));
    }

    let info = Container::from_inspect(inspect).unwrap();

    // Check that network-specific aliases are preserved
    let bridge_network = info.networks.get("bridge").expect("network present");
    assert!(bridge_network.aliases.contains(&"web".to_string()));
    assert!(bridge_network.aliases.contains(&"frontend".to_string()));

    let custom_network = info.networks.get("custom").expect("network present");
    assert!(custom_network.aliases.contains(&"api".to_string()));

    // Check that all network aliases are included in container aliases
    assert!(info.aliases.contains(&"web".to_string()));
    assert!(info.aliases.contains(&"frontend".to_string()));
    assert!(info.aliases.contains(&"api".to_string()));
}

#[test]
fn test_container_info_host_network() {
    let mut inspect = create_test_inspect_response("test123", "test-container");
    if let Some(ref mut host_config) = inspect.host_config {
        host_config.network_mode = Some("host".to_string());
    }

    let info = Container::from_inspect(inspect).unwrap();
    assert!(info.uses_host_network);
}

#[test]
fn test_container_info_bridge_network() {
    let mut inspect = create_test_inspect_response("test123", "test-container");
    if let Some(ref mut host_config) = inspect.host_config {
        host_config.network_mode = Some("bridge".to_string());
    }

    let info = Container::from_inspect(inspect).unwrap();
    assert!(!info.uses_host_network);
}

#[test]
fn test_container_info_no_network_mode() {
    let inspect = create_test_inspect_response("test123", "test-container");
    // network_mode is already None in the default test response

    let info = Container::from_inspect(inspect).unwrap();
    assert!(!info.uses_host_network);
}

#[test]
fn test_connect_rejects_an_unsupported_docker_host() {
    with_vars(vec![("DOCKER_HOST", Some("ftp://docker.invalid"))], || {
        assert!(DockerClient::connect(std::time::Duration::from_secs(1)).is_err());
    });
}
