use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::failure::{Failure, TestResult};

/// Addresses and paths the sandbox entrypoint publishes for the suite.
#[derive(Clone, Debug)]
pub struct Sandbox {
    /// The sandbox's own address as seen from the external host; published ports answer here.
    pub host_addr: Ipv4Addr,
    /// Network namespace standing in for a machine outside the Docker host.
    pub external_netns: String,
    /// External source address that allowlists in the tests permit.
    pub external_addr: Ipv4Addr,
    /// Second external source address that allowlists in the tests do not permit.
    pub foreign_addr: Ipv4Addr,
    pub host_addr6: Ipv6Addr,
    pub external_addr6: Ipv6Addr,
    pub foreign_addr6: Ipv6Addr,
    pub log_root: PathBuf,
}

impl Sandbox {
    /// Read the sandbox description, refusing to run anywhere else: the suite rewrites the
    /// firewall and removes containers, which must never happen on a developer's host.
    pub fn require() -> TestResult<Self> {
        if std::env::var("HARBORSHIELD_E2E_SANDBOX").as_deref() != Ok("1") {
            return Err(Failure::new(
                "refusing to run outside the e2e sandbox: run the suite with `cargo xtask e2e`",
            ));
        }
        Ok(Self {
            host_addr: address("HARBORSHIELD_E2E_HOST_ADDR")?,
            external_netns: variable("HARBORSHIELD_E2E_EXT_NETNS")?,
            external_addr: address("HARBORSHIELD_E2E_EXT_ADDR")?,
            foreign_addr: address("HARBORSHIELD_E2E_EXT_FOREIGN_ADDR")?,
            host_addr6: address("HARBORSHIELD_E2E_HOST_ADDR6")?,
            external_addr6: address("HARBORSHIELD_E2E_EXT_ADDR6")?,
            foreign_addr6: address("HARBORSHIELD_E2E_EXT_FOREIGN_ADDR6")?,
            log_root: PathBuf::from(variable("HARBORSHIELD_E2E_LOG_DIR")?),
        })
    }
}

fn variable(name: &str) -> TestResult<String> {
    std::env::var(name).map_err(|error| Failure::context(format!("sandbox variable {name}"), error))
}

fn address<Value: std::str::FromStr>(name: &str) -> TestResult<Value>
where
    Value::Err: std::fmt::Display,
{
    let raw = variable(name)?;
    raw.parse()
        .map_err(|error| Failure::context(format!("sandbox variable {name}={raw}"), error))
}
