pub mod compose;
pub mod config;
pub mod container;
pub mod error;
pub mod network;

use crate::docker::container::{Container, Tracker};
use crate::docker::network::NetworkGatewayInfo;
use crate::{Error, Result};
use bollard::ClientVersion;
use bollard::{Docker, models::EventMessage};
use bon::bon;
use futures::stream::StreamExt;
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::debug;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
enum ConnectionInfo {
    Socket(String),
    Http(String),
    Ssl {
        url: String,
        cert_path: String,
        verify: bool,
    },
    Default,
}

pub struct DockerClient {
    client: Docker,
    timeout_duration: Duration,
    api_version: Option<String>,
    connection_info: ConnectionInfo,
    pub network_gateway_cache: Arc<Mutex<HashMap<String, NetworkGatewayInfo>>>,
    pub container_tracker: Arc<Tracker>,
}

#[bon]
impl DockerClient {
    #[builder]
    pub fn new(
        #[builder(default = Duration::from_secs(30))] timeout_duration: Duration,
    ) -> Result<Self> {
        // Check for API version override first
        let api_version_override = env::var("DOCKER_API_VERSION").ok();

        // Check DOCKER_HOST environment variable
        let (client, connection_info) = if let Ok(docker_host) = env::var("DOCKER_HOST") {
            // Check if TLS is required
            let tls_verify = env::var("DOCKER_TLS_VERIFY")
                .unwrap_or_default()
                .eq_ignore_ascii_case("1")
                || env::var("DOCKER_TLS_VERIFY")
                    .unwrap_or_default()
                    .eq_ignore_ascii_case("true");

            if docker_host.starts_with("unix://") || docker_host.starts_with("/") {
                // Unix socket connection
                let client =
                    Docker::connect_with_socket(&docker_host, 120, bollard::API_DEFAULT_VERSION)
                        .map_err(|e| Error::Docker(e))?;
                (client, ConnectionInfo::Socket(docker_host))
            } else if tls_verify || docker_host.starts_with("tcp://") {
                // TCP connection - check if TLS is needed
                let cert_path = env::var("DOCKER_CERT_PATH").unwrap_or_else(|_| {
                    // Default to ~/.docker if not specified
                    let home = env::var("HOME").unwrap_or_else(|_| "/root".to_string());
                    format!("{}/.docker", home)
                });

                // Check if cert files exist - if they do, use TLS
                let cert_path_obj = Path::new(&cert_path);
                let has_certs = cert_path_obj.join("ca.pem").exists()
                    && cert_path_obj.join("cert.pem").exists()
                    && cert_path_obj.join("key.pem").exists();

                if tls_verify || has_certs {
                    let client = Self::connect_with_tls(&docker_host, &cert_path, tls_verify)?;
                    (
                        client,
                        ConnectionInfo::Ssl {
                            url: docker_host,
                            cert_path,
                            verify: tls_verify,
                        },
                    )
                } else {
                    // TCP without TLS
                    let url = if docker_host.starts_with("http://") {
                        docker_host.to_string()
                    } else {
                        docker_host.replace("tcp://", "http://")
                    };
                    let client = Docker::connect_with_http(&url, 120, bollard::API_DEFAULT_VERSION)
                        .map_err(|e| Error::Docker(e))?;
                    (client, ConnectionInfo::Http(url))
                }
            } else {
                // HTTP connection
                let client =
                    Docker::connect_with_http(&docker_host, 120, bollard::API_DEFAULT_VERSION)
                        .map_err(|e| Error::Docker(e))?;
                (client, ConnectionInfo::Http(docker_host))
            }
        } else {
            // Default connection
            let client = Docker::connect_with_socket_defaults().map_err(|e| Error::Docker(e))?;
            (client, ConnectionInfo::Default)
        };

        // Handle API version
        if let Some(version) = api_version_override {
            Self::create_with_specific_version_sync(connection_info, &version, timeout_duration)
        } else {
            // Return client without negotiation - it will be done lazily or explicitly
            Ok(Self {
                client,
                timeout_duration,
                api_version: None,
                connection_info,
                network_gateway_cache: Arc::new(Mutex::new(HashMap::new())),
                container_tracker: Arc::new(Tracker::builder().build()),
            })
        }
    }

    fn recreate_client(connection_info: &ConnectionInfo) -> Result<Docker> {
        match connection_info {
            ConnectionInfo::Socket(socket_path) => {
                Docker::connect_with_socket(socket_path, 120, bollard::API_DEFAULT_VERSION)
                    .map_err(|e| Error::Docker(e))
            }
            ConnectionInfo::Http(url) => {
                Docker::connect_with_http(url, 120, bollard::API_DEFAULT_VERSION)
                    .map_err(|e| Error::Docker(e))
            }
            ConnectionInfo::Ssl {
                url,
                cert_path,
                verify,
            } => Self::connect_with_tls(url, cert_path, *verify),
            ConnectionInfo::Default => {
                Docker::connect_with_socket_defaults().map_err(|e| Error::Docker(e))
            }
        }
    }

    fn create_with_specific_version_sync(
        connection_info: ConnectionInfo,
        version: &str,
        timeout_duration: Duration,
    ) -> Result<Self> {
        tracing::info!("Using DOCKER_API_VERSION: {}", version);

        // Normalize version format (handle both "1.41" and "v1.41")
        let normalized_version = if version.starts_with('v') {
            version.to_string()
        } else {
            format!("v{}", version)
        };

        // Since bollard uses compile-time API version, we can't dynamically change it
        // But we can validate and warn about compatibility
        let bollard_version = Self::get_bollard_version();
        let parse_version =
            |v: &str| -> Option<f32> { v.trim_start_matches('v').parse::<f32>().ok() };

        if let (Some(requested_v), Some(bollard_v)) = (
            parse_version(&normalized_version),
            parse_version(&bollard_version.to_string()),
        ) {
            if (requested_v - bollard_v).abs() > 0.1 {
                tracing::warn!(
                    "DOCKER_API_VERSION {} differs significantly from bollard's compile-time version {}. \
                    This may cause compatibility issues.",
                    normalized_version,
                    bollard_version
                );
            }
        }

        // Create client with default version (can't change compile-time constant)
        let client = Self::recreate_client(&connection_info)?;

        // Store the requested version for reference
        Ok(Self {
            client,
            timeout_duration,
            api_version: Some(normalized_version),
            connection_info,
            network_gateway_cache: Arc::new(Mutex::new(HashMap::new())),
            container_tracker: Arc::new(Tracker::builder().build()),
        })
    }

    pub fn api_version(&self) -> Option<&str> {
        self.api_version.as_deref()
    }

    /// Explicitly negotiate API version with the Docker daemon
    /// This consumes self and returns a new instance with negotiated version
    pub async fn negotiate_version(self) -> Result<Self> {
        let timeout_duration = self.timeout_duration;
        let connection_info = self.connection_info.clone();

        match timeout(timeout_duration, self.client.negotiate_version()).await {
            Ok(Ok(negotiated_client)) => {
                tracing::info!("Successfully negotiated Docker API version");
                Ok(Self {
                    client: negotiated_client,
                    timeout_duration,
                    api_version: None, // Version is handled internally by bollard
                    connection_info,
                    network_gateway_cache: Arc::new(Mutex::new(HashMap::new())),
                    container_tracker: Arc::new(Tracker::builder().build()),
                })
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    "Failed to negotiate Docker API version: {}. Using default version.",
                    e
                );
                // Recreate the client since negotiate_version consumed it
                let client = Self::recreate_client(&connection_info)?;
                Ok(Self {
                    client,
                    timeout_duration,
                    api_version: None,
                    connection_info,
                    network_gateway_cache: Arc::new(Mutex::new(HashMap::new())),
                    container_tracker: Arc::new(Tracker::builder().build()),
                })
            }
            Err(_) => {
                tracing::warn!("Docker API version negotiation timed out. Using default version.");
                // Recreate the client since negotiate_version consumed it
                let client = Self::recreate_client(&connection_info)?;
                Ok(Self {
                    client,
                    timeout_duration,
                    api_version: None,
                    connection_info,
                    network_gateway_cache: Arc::new(Mutex::new(HashMap::new())),
                    container_tracker: Arc::new(Tracker::builder().build()),
                })
            }
        }
    }

    /// Get the bollard library's compile-time API version
    fn get_bollard_version() -> &'static ClientVersion {
        bollard::API_DEFAULT_VERSION
    }

    /// Check if a feature is supported by the current API version
    pub fn is_feature_supported(&self, feature: &str, min_version: &str) -> Result<()> {
        if let Some(_api_version) = &self.api_version {
            let parse_version =
                |v: &str| -> Option<f32> { v.trim_start_matches('v').parse::<f32>().ok() };

            if let (Some(current_v), Some(min_v)) =
                (parse_version(_api_version), parse_version(min_version))
            {
                if current_v < min_v {
                    return Err(Error::config(format!(
                        "Unsupported Docker feature: {} (minimum version: {})",
                        feature, min_version
                    )));
                }
            }
        }
        Ok(())
    }

    fn connect_with_tls(docker_host: &str, cert_path: &str, _verify: bool) -> Result<Docker> {
        let cert_path = Path::new(cert_path);

        // Check if certificate files exist
        let ca_path = cert_path.join("ca.pem");
        let cert_file_path = cert_path.join("cert.pem");
        let key_path = cert_path.join("key.pem");

        if !ca_path.exists() || !cert_file_path.exists() || !key_path.exists() {
            return Err(Error::config_at(
                format!(
                    "TLS certificate files not found: ca.pem, cert.pem, and key.pem are required"
                ),
                cert_path.display().to_string(),
            ));
        }

        // Parse the Docker host URL
        let host = docker_host
            .strip_prefix("tcp://")
            .or_else(|| docker_host.strip_prefix("https://"))
            .unwrap_or(docker_host);

        // Convert to proper URL format for bollard
        let url = if host.starts_with("http") {
            host.to_string()
        } else {
            format!("https://{}", host)
        };

        // Use bollard's connect_with_ssl method
        Docker::connect_with_ssl(
            &url,
            &key_path,
            &cert_file_path,
            &ca_path,
            120,
            bollard::API_DEFAULT_VERSION,
        )
        .map_err(|e| Error::Docker(e))
    }

    pub async fn ping(&self) -> Result<()> {
        timeout(self.timeout_duration, self.client.ping())
            .await
            .map_err(|_| Error::timeout(self.timeout_duration, "ping Docker daemon"))?
            .map_err(|e| Error::Docker(e))?;
        Ok(())
    }

    pub async fn list_containers(&self) -> Result<Vec<bollard::models::ContainerSummary>> {
        use bollard::query_parameters::ListContainersOptionsBuilder;

        let options = ListContainersOptionsBuilder::default().all(false).build();

        timeout(
            self.timeout_duration,
            self.client.list_containers(Some(options)),
        )
        .await
        .map_err(|_| Error::timeout(self.timeout_duration, "list containers"))?
        .map_err(|e| Error::Docker(e))
    }

    pub async fn list_all_containers(&self) -> Result<Vec<bollard::models::ContainerSummary>> {
        use bollard::query_parameters::ListContainersOptionsBuilder;

        let options = ListContainersOptionsBuilder::default().all(true).build();

        timeout(
            self.timeout_duration,
            self.client.list_containers(Some(options)),
        )
        .await
        .map_err(|_| Error::timeout(self.timeout_duration, "list all containers"))?
        .map_err(|e| Error::Docker(e))
    }

    pub async fn try_get_container_by_id(&self, id: &str) -> Result<Container> {
        Ok(Container::from_inspect(self.inspect_container(id).await?)?)
    }

    pub async fn inspect_container(
        &self,
        id: &str,
    ) -> Result<bollard::models::ContainerInspectResponse> {
        use bollard::query_parameters::InspectContainerOptionsBuilder;

        let options = InspectContainerOptionsBuilder::default().build();

        timeout(
            self.timeout_duration,
            self.client.inspect_container(id, Some(options)),
        )
        .await
        .map_err(|_| Error::timeout(self.timeout_duration, "inspect container"))?
        .map_err(|e| Error::Docker(e))
    }

    pub async fn events(
        &self,
    ) -> Result<impl futures::stream::Stream<Item = Result<EventMessage>>> {
        self.events_with_retry().await
    }

    async fn events_with_retry(
        &self,
    ) -> Result<impl futures::stream::Stream<Item = Result<EventMessage>>> {
        use bollard::query_parameters::EventsOptionsBuilder;

        let mut filters = HashMap::new();
        filters.insert("type", vec!["container", "network"]);
        filters.insert(
            "event",
            vec![
                "create",
                "start",
                "die",
                "pause",
                "unpause",
                "rename",
                "connect",
                "disconnect",
            ],
        );

        let options = EventsOptionsBuilder::default().filters(&filters).build();

        let stream = self.client.events(Some(options));
        Ok(stream.map(|res| res.map_err(|e| Error::Docker(e))))
    }

    pub async fn pause_container(&self, id: &str) -> Result<()> {
        timeout(self.timeout_duration, self.client.pause_container(id))
            .await
            .map_err(|_| Error::timeout(self.timeout_duration, "pause container"))?
            .map_err(|e| Error::Docker(e))
    }

    pub async fn unpause_container(&self, id: &str) -> Result<()> {
        timeout(self.timeout_duration, self.client.unpause_container(id))
            .await
            .map_err(|_| Error::timeout(self.timeout_duration, "unpause container"))?
            .map_err(|e| Error::Docker(e))
    }

    pub async fn start_container(&self, id: &str) -> Result<()> {
        use bollard::query_parameters::StartContainerOptionsBuilder;

        let options = StartContainerOptionsBuilder::default().build();

        timeout(
            self.timeout_duration,
            self.client.start_container(id, Some(options)),
        )
        .await
        .map_err(|_| Error::timeout(self.timeout_duration, "start container"))?
        .map_err(|e| Error::Docker(e))
    }

    /// Get detailed version information about the Docker daemon
    pub async fn version_info(&self) -> Result<bollard::models::SystemVersion> {
        timeout(self.timeout_duration, self.client.version())
            .await
            .map_err(|_| Error::timeout(self.timeout_duration, "get version info"))?
            .map_err(|e| Error::Docker(e))
    }

    /// List all Docker networks
    pub async fn list_networks(&self) -> Result<Vec<bollard::models::Network>> {
        use bollard::query_parameters::ListNetworksOptionsBuilder;

        let options = ListNetworksOptionsBuilder::default().build();

        timeout(
            self.timeout_duration,
            self.client.list_networks(Some(options)),
        )
        .await
        .map_err(|_| Error::timeout(self.timeout_duration, "list networks"))?
        .map_err(|e| Error::Docker(e))
    }

    /// Refresh network gateway information from Docker
    pub async fn refresh_network_gateways(&self) -> Result<()> {
        use crate::docker::network::extract_network_gateway;

        let networks = self.list_networks().await?;
        let mut gateway_cache = self.network_gateway_cache.lock().await;

        for network in networks {
            if let Ok(gateway_info) = extract_network_gateway(&network) {
                debug!(
                    "Found gateway info for network {}: {:?}",
                    gateway_info.network_name, gateway_info.gateway_ips
                );
                gateway_cache.insert(gateway_info.network_name.clone(), gateway_info);
            }
        }

        Ok(())
    }

    /// Get containers from Docker and sort by dependencies
    pub async fn get_sorted_containers(&self) -> Result<Vec<bollard::models::ContainerSummary>> {
        let mut containers = self.list_containers().await?;
        compose::sort_by_dependencies(&mut containers);
        Ok(containers)
    }
}
