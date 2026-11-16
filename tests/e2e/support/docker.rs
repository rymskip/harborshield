use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::Deserialize;

use super::command::{run, run_ok};
use super::failure::{Failure, TestResult};
use super::probe::{Origin, Proto, Verdict, probe};
use super::time::deadline_in;

pub const FIXTURE_IMAGE: &str = "harborshield-e2e-fixture";
pub const E2E_LABEL: &str = "harborshield.e2e";
pub const SCENARIO_LABEL: &str = "harborshield.e2e.scenario";

const DOCKER_LIMIT: Duration = Duration::from_secs(60);
const LISTENER_READY_LIMIT: Duration = Duration::from_secs(20);

pub async fn docker(args: &[&str]) -> TestResult<String> {
    run_ok("docker", args, DOCKER_LIMIT).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listener {
    Tcp(u16),
    Udp(u16),
}

impl Listener {
    fn spec(self) -> String {
        match self {
            Self::Tcp(port) => format!("tcp:{port}"),
            Self::Udp(port) => format!("udp:{port}"),
        }
    }

    fn proto_and_port(self) -> (Proto, u16) {
        match self {
            Self::Tcp(port) => (Proto::Tcp, port),
            Self::Udp(port) => (Proto::Udp, port),
        }
    }
}

/// A Docker network created for one scenario.
#[derive(Clone, Debug)]
pub struct Network {
    pub name: String,
}

impl Network {
    pub async fn create(name: &str, scenario: &str) -> TestResult<Self> {
        Self::create_with(name, scenario, &[]).await
    }

    /// A dual-stack network with the given IPv6 subnet.
    pub async fn create_ipv6(name: &str, scenario: &str, subnet: &str) -> TestResult<Self> {
        Self::create_with(name, scenario, &["--ipv6", "--subnet", subnet]).await
    }

    async fn create_with(name: &str, scenario: &str, extra: &[&str]) -> TestResult<Self> {
        let scenario_label = format!("{SCENARIO_LABEL}={scenario}");
        let mut args = vec![
            "network",
            "create",
            "--label",
            E2E_LABEL,
            "--label",
            &scenario_label,
        ];
        args.extend_from_slice(extra);
        args.push(name);
        docker(&args).await?;
        Ok(Self {
            name: name.to_owned(),
        })
    }
}

/// What to run in a scenario container. Every container serves banners on its listeners, so
/// any container can act as a server and a probe can prove which one answered.
#[derive(Clone, Debug)]
pub struct ContainerSpec {
    name: String,
    networks: Vec<String>,
    labels: Vec<(String, String)>,
    publish: Vec<String>,
    listeners: Vec<Listener>,
    restart_always: bool,
}

impl ContainerSpec {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            networks: Vec::new(),
            labels: Vec::new(),
            publish: Vec::new(),
            listeners: Vec::new(),
            restart_always: false,
        }
    }

    /// Have Docker start the container again whenever its daemon starts.
    pub fn restart_always(mut self) -> Self {
        self.restart_always = true;
        self
    }

    pub fn network(mut self, network: &Network) -> Self {
        self.networks.push(network.name.clone());
        self
    }

    pub fn tcp(mut self, port: u16) -> Self {
        self.listeners.push(Listener::Tcp(port));
        self
    }

    pub fn udp(mut self, port: u16) -> Self {
        self.listeners.push(Listener::Udp(port));
        self
    }

    /// Publish a port, in `docker run -p` syntax.
    pub fn publish(mut self, mapping: impl Into<String>) -> Self {
        self.publish.push(mapping.into());
        self
    }

    /// Put the container under harborshield management with no rules: deny everything.
    pub fn managed(self) -> Self {
        self.label("harborshield.enabled", "true")
    }

    /// Put the container under harborshield management with the given rules document.
    pub fn rules(self, rules: impl Into<String>) -> Self {
        self.managed().label("harborshield.rules", rules)
    }

    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }

    pub async fn run(&self, scenario: &str) -> TestResult<Container> {
        let listeners = if self.listeners.is_empty() {
            vec![Listener::Tcp(8080)]
        } else {
            self.listeners.clone()
        };

        let mut args: Vec<String> = vec![
            "run".into(),
            "--detach".into(),
            "--name".into(),
            self.name.clone(),
            "--hostname".into(),
            self.name.clone(),
            "--label".into(),
            E2E_LABEL.into(),
            "--label".into(),
            format!("{SCENARIO_LABEL}={scenario}"),
        ];
        for network in &self.networks {
            args.push("--network".into());
            args.push(network.clone());
        }
        if self.restart_always {
            args.push("--restart".into());
            args.push("always".into());
        }
        for mapping in &self.publish {
            args.push("--publish".into());
            args.push(mapping.clone());
        }
        for (key, value) in &self.labels {
            args.push("--label".into());
            args.push(format!("{key}={value}"));
        }
        args.push(FIXTURE_IMAGE.into());
        args.extend(listeners.iter().map(|listener| listener.spec()));

        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let id = docker(&borrowed).await?.trim().to_owned();
        let container = Container {
            id,
            name: self.name.clone(),
        };
        container.wait_for_listeners(&listeners).await?;
        Ok(container)
    }
}

/// A running scenario container.
#[derive(Clone, Debug)]
pub struct Container {
    pub id: String,
    pub name: String,
}

impl Container {
    /// A container started outside [`ContainerSpec`], such as by `docker compose`.
    pub async fn existing(name: &str) -> TestResult<Self> {
        let id = docker(&[
            "inspect",
            "--type",
            "container",
            "--format",
            "{{.Id}}",
            name,
        ])
        .await?
        .trim()
        .to_owned();
        Ok(Self {
            id,
            name: name.to_owned(),
        })
    }

    /// Loopback inside the container never crosses the host firewall, so this proves the
    /// service itself is up independently of any rule under test.
    pub async fn wait_for_listeners(&self, listeners: &[Listener]) -> TestResult {
        for listener in listeners {
            let (proto, port) = listener.proto_and_port();
            let deadline = deadline_in(LISTENER_READY_LIMIT);
            loop {
                let verdict = probe(
                    &Origin::Container(&self.name),
                    proto,
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port,
                )
                .await?;
                if matches!(verdict, Verdict::Connected { .. }) {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(Failure::new(format!(
                        "{} never started listening on {listener:?}: last probe {verdict:?}",
                        self.name
                    )));
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        Ok(())
    }

    pub async fn inspect(&self) -> TestResult<InspectContainer> {
        let raw = docker(&["inspect", "--type", "container", &self.id]).await?;
        let mut parsed: Vec<InspectContainer> = serde_json::from_str(&raw)
            .map_err(|error| Failure::context(format!("parse inspect of {}", self.name), error))?;
        parsed.pop().ok_or_else(|| {
            Failure::new(format!("docker inspect returned nothing for {}", self.name))
        })
    }

    pub async fn ip_on(&self, network: &Network) -> TestResult<Ipv4Addr> {
        let inspect = self.inspect().await?;
        let endpoint = inspect
            .network_settings
            .networks
            .get(&network.name)
            .ok_or_else(|| Failure::new(format!("{} is not on {}", self.name, network.name)))?;
        endpoint.ip_address.parse().map_err(|error| {
            Failure::context(
                format!(
                    "{} address on {} ({:?})",
                    self.name, network.name, endpoint.ip_address
                ),
                error,
            )
        })
    }

    pub async fn ip6_on(&self, network: &Network) -> TestResult<Ipv6Addr> {
        let inspect = self.inspect().await?;
        let endpoint = inspect
            .network_settings
            .networks
            .get(&network.name)
            .ok_or_else(|| Failure::new(format!("{} is not on {}", self.name, network.name)))?;
        endpoint.global_ipv6_address.parse().map_err(|error| {
            Failure::context(
                format!(
                    "{} IPv6 address on {} ({:?})",
                    self.name, network.name, endpoint.global_ipv6_address
                ),
                error,
            )
        })
    }

    pub async fn status(&self) -> TestResult<String> {
        Ok(self.inspect().await?.state.status)
    }

    pub fn short_id(&self) -> &str {
        self.id.get(..12).unwrap_or(&self.id)
    }

    pub async fn stop(&self) -> TestResult {
        docker(&["stop", "--time", "2", &self.id]).await.map(drop)
    }

    pub async fn start(&self) -> TestResult {
        docker(&["start", &self.id]).await.map(drop)
    }

    pub async fn remove(&self) -> TestResult {
        docker(&["rm", "--force", &self.id]).await.map(drop)
    }

    pub async fn pause(&self) -> TestResult {
        docker(&["pause", &self.id]).await.map(drop)
    }

    pub async fn unpause(&self) -> TestResult {
        docker(&["unpause", &self.id]).await.map(drop)
    }

    pub async fn connect(&self, network: &Network) -> TestResult {
        docker(&["network", "connect", &network.name, &self.id])
            .await
            .map(drop)
    }

    pub async fn disconnect(&self, network: &Network) -> TestResult {
        docker(&["network", "disconnect", &network.name, &self.id])
            .await
            .map(drop)
    }
}

/// Remove every container and network carrying the scenario label.
pub async fn remove_scenario_resources(scenario: &str) -> TestResult {
    remove_labelled(&format!("label={SCENARIO_LABEL}={scenario}")).await
}

/// Remove every e2e container and network, whichever scenario created it.
pub async fn remove_all_e2e_resources() -> TestResult {
    remove_labelled(&format!("label={E2E_LABEL}")).await
}

async fn remove_labelled(filter: &str) -> TestResult {
    let containers = docker(&["ps", "--all", "--quiet", "--filter", filter]).await?;
    for id in containers.split_whitespace() {
        docker(&["rm", "--force", id]).await?;
    }
    let networks = docker(&["network", "ls", "--quiet", "--filter", filter]).await?;
    for id in networks.split_whitespace() {
        let output = run("docker", &["network", "rm", id], DOCKER_LIMIT).await?;
        if !output.status.success() {
            return Err(Failure::new(format!(
                "could not remove e2e network {id}: {}",
                output.stderr.trim()
            )));
        }
    }
    Ok(())
}

// Docker's inspect documents carry far more than the suite reads; unknown fields are ignored
// on purpose so a daemon upgrade cannot break parsing.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InspectContainer {
    pub state: InspectState,
    pub network_settings: InspectNetworkSettings,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InspectState {
    pub status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InspectNetworkSettings {
    pub networks: BTreeMap<String, InspectEndpoint>,
}

#[derive(Debug, Deserialize)]
pub struct InspectEndpoint {
    #[serde(rename = "IPAddress")]
    pub ip_address: String,
    #[serde(rename = "GlobalIPv6Address")]
    pub global_ipv6_address: String,
}
