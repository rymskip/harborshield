use std::net::{IpAddr, Ipv4Addr};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};

use nftables::types::NfFamily;

use super::command::run_ok;
use super::failure::{Failure, TestResult};
use super::nft::{nft, ruleset};
use super::probe::{Origin, Proto, Verdict, probe};
use super::scenario::{Cleanup, Scenario};
use super::time::deadline_in;

const DOCKERD_RESTART_LIMIT: Duration = Duration::from_secs(150);
const READY_LIMIT: Duration = Duration::from_secs(20);
const IP_LIMIT: Duration = Duration::from_secs(15);

/// Restart the sandbox's dockerd. Containers with `restart: always` come back with it.
pub async fn restart_docker_daemon() -> TestResult {
    run_ok("hs-dockerd", &["restart"], DOCKERD_RESTART_LIMIT)
        .await
        .map(drop)
}

/// A banner server outside Docker, in the sandbox's own namespace or a test namespace; it
/// stops when dropped.
pub struct BannerService {
    _child: Child,
}

impl BannerService {
    /// Serve TCP `ports` as `name`, inside `namespace` or on the Docker host itself, and wait
    /// until each answers on `address`.
    pub async fn start(
        name: &str,
        namespace: Option<&str>,
        address: Ipv4Addr,
        ports: &[u16],
    ) -> TestResult<Self> {
        let specs: Vec<String> = ports.iter().map(|port| format!("tcp:{port}")).collect();
        let mut command = match namespace {
            Some(namespace) => {
                let mut command = Command::new("ip");
                command.args(["netns", "exec", namespace, "hs-serve"]);
                command
            }
            None => Command::new("hs-serve"),
        };
        let child = command
            .args(&specs)
            .env("HS_NAME", name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| Failure::context(format!("start banner service {name}"), error))?;
        let origin = match namespace {
            Some(namespace) => Origin::Namespace(namespace),
            None => Origin::Localhost,
        };
        for port in ports {
            let deadline = deadline_in(READY_LIMIT);
            loop {
                let verdict = probe(&origin, Proto::Tcp, IpAddr::V4(address), *port).await?;
                if matches!(verdict, Verdict::Connected { .. }) {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(Failure::new(format!(
                        "banner service {name} never listened on {address}:{port}: {verdict:?}"
                    )));
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        Ok(Self { _child: child })
    }
}

/// A Linux bridge outside Docker with two namespaces on it, at 10.77.0.1 and 10.77.0.2.
pub struct BridgedNamespaces {
    pub first: String,
    pub second: String,
}

const FIRST_BRIDGED: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
pub const SECOND_BRIDGED: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);

pub async fn bridged_namespaces(scenario: &mut Scenario) -> TestResult<BridgedNamespaces> {
    let tag = scenario.tag().to_owned();
    let bridge = format!("hsb-{tag}");
    ip(&["link", "add", &bridge, "type", "bridge"]).await?;
    scenario.on_teardown(Cleanup::Link(bridge.clone()));
    ip(&["link", "set", &bridge, "up"]).await?;

    let mut namespaces = Vec::new();
    for (side, address) in [("a", FIRST_BRIDGED), ("b", SECOND_BRIDGED)] {
        let namespace = format!("hsn-{tag}-{side}");
        let veth = format!("hsv-{tag}-{side}");
        ip(&["netns", "add", &namespace]).await?;
        scenario.on_teardown(Cleanup::NetworkNamespace(namespace.clone()));
        ip(&[
            "link", "add", &veth, "type", "veth", "peer", "name", "eth0", "netns", &namespace,
        ])
        .await?;
        scenario.on_teardown(Cleanup::Link(veth.clone()));
        ip(&["link", "set", &veth, "master", &bridge, "up"]).await?;
        let cidr = format!("{address}/24");
        ip(&["-n", &namespace, "addr", "add", &cidr, "dev", "eth0"]).await?;
        ip(&["-n", &namespace, "link", "set", "eth0", "up"]).await?;
        ip(&["-n", &namespace, "link", "set", "lo", "up"]).await?;
        namespaces.push(namespace);
    }
    let mut namespaces = namespaces.into_iter();
    match (namespaces.next(), namespaces.next()) {
        (Some(first), Some(second)) => Ok(BridgedNamespaces { first, second }),
        _ => Err(Failure::new("bridged namespaces were not both created")),
    }
}

async fn ip(args: &[&str]) -> TestResult {
    run_ok("ip", args, IP_LIMIT).await.map(drop)
}

/// Make sure Docker's `ip filter` table and its DOCKER-USER chain exist. The iptables backend
/// creates them; under the nftables backend this stands in for them, and teardown removes it.
pub async fn ensure_ip_filter_table(scenario: &mut Scenario) -> TestResult {
    let rules = ruleset().await?;
    if !rules.has_table(NfFamily::IP, "filter") {
        nft(&["add", "table", "ip", "filter"]).await?;
        scenario.on_teardown(Cleanup::NftTable {
            family: "ip",
            name: "filter".to_owned(),
        });
    }
    if !rules.has_legacy_chain("DOCKER-USER") {
        nft(&["add", "chain", "ip", "filter", "DOCKER-USER"]).await?;
    }
    Ok(())
}
