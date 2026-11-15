mod external;
mod localhost;
mod rule;
#[cfg(test)]
mod tests;
pub mod validation;
mod verdict;

use crate::{Error, Result};
use bon::Builder;
pub use external::ExternalRules;
use ipnet::IpNet;
pub use localhost::LocalRules;
pub use rule::RuleConfig;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use validation::error::ValidationError;
pub use verdict::ConfigVerdict;

#[derive(Debug, Clone, Serialize, Builder)]
pub struct Config {
    #[serde(default)]
    #[builder(default)]
    pub mapped_ports: MappedPorts,
    #[serde(default)]
    #[builder(default)]
    pub output: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Builder)]
#[serde(deny_unknown_fields)]
pub struct MappedPorts {
    #[serde(default)]
    #[builder(default)]
    pub localhost: LocalRules,
    #[serde(default)]
    #[builder(default)]
    pub external: ExternalRules,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrOrRange {
    Addr(IpAddr),
    Range(IpAddr, IpAddr),
    Net(IpNet),
}

impl Serialize for AddrOrRange {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AddrOrRange {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for AddrOrRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrOrRange::Addr(addr) => write!(f, "{}", addr),
            AddrOrRange::Range(start, end) => write!(f, "{}-{}", start, end),
            AddrOrRange::Net(net) => write!(f, "{}", net),
        }
    }
}

impl FromStr for AddrOrRange {
    type Err = Error;

    fn from_str(input: &str) -> std::result::Result<Self, Self::Err> {
        if input == "0.0.0.0/0" {
            return Err(Error::invalid_ip(
                input,
                "0.0.0.0/0 is not supported by nftables. Use specific IP addresses or ranges instead",
            ));
        }

        let address = |part: &str| {
            part.parse::<IpAddr>()
                .map_err(|failure| Error::invalid_ip(part, failure.to_string()))
        };

        if let Some((start, end)) = input.split_once('-') {
            let (start, end) = (address(start)?, address(end)?);
            if start.is_ipv4() != end.is_ipv4() {
                return Err(Error::invalid_ip(
                    input,
                    "a range must not mix IPv4 and IPv6",
                ));
            }
            if start > end {
                return Err(Error::invalid_ip(
                    input,
                    "a range must start at or before its end",
                ));
            }
            return Ok(AddrOrRange::Range(start, end));
        }

        if input.contains('/') {
            return input
                .parse::<IpNet>()
                .map(|network| AddrOrRange::Net(network.trunc()))
                .map_err(|failure| Error::invalid_ip(input, failure.to_string()));
        }

        address(input).map(AddrOrRange::Addr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulePorts {
    Single(u16),
    Range(u16, u16),
}

impl Serialize for RulePorts {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RulePorts {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for RulePorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RulePorts::Single(port) => write!(f, "{}", port),
            RulePorts::Range(start, end) => write!(f, "{}-{}", start, end),
        }
    }
}

impl FromStr for RulePorts {
    type Err = Error;

    fn from_str(input: &str) -> std::result::Result<Self, Self::Err> {
        let port = |part: &str| {
            part.parse::<u16>()
                .map_err(|failure| Error::config(format!("invalid port {part:?}: {failure}")))
        };
        match input.split_once('-') {
            Some((start, end)) => {
                let (start, end) = (port(start)?, port(end)?);
                if start > end {
                    return Err(Error::config(format!(
                        "invalid port range {input:?}: start {start} is after end {end}"
                    )));
                }
                Ok(RulePorts::Range(start, end))
            }
            None => port(input).map(RulePorts::Single),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        // Validate output rules
        for (index, rule) in self.output.iter().enumerate() {
            Self::validate_rule(rule, index)?;
        }

        // Validate mapped ports
        Self::validate_mapped_ports(&self.mapped_ports)?;

        // Verdicts are already validated in their custom deserializers

        Ok(())
    }

    fn validate_rule(rule: &RuleConfig, index: usize) -> Result<()> {
        if rule.ips.is_empty()
            && rule.container.is_empty()
            && rule.src_ports.is_empty()
            && rule.dst_ports.is_empty()
        {
            return Err(Error::config(format!("Output rule #{} is empty", index)));
        }

        if !rule.ips.is_empty() && !rule.container.is_empty() {
            return Err(Error::config(format!(
                "Output rule #{}: 'ips' and 'container' are mutually exclusive",
                index
            )));
        }

        if rule.network.is_empty() && !rule.container.is_empty() {
            return Err(Error::config(format!(
                "Output rule #{}: 'network' must be set when 'container' is set",
                index
            )));
        }

        // Validate IP family consistency
        if !rule.ips.is_empty() {
            Self::validate_ip_family_consistency(&rule.ips, &format!("Output rule #{}", index))?;
        }

        if !rule.src_ports.is_empty() && rule.dst_ports.is_empty() {
            return Err(Error::config(format!(
                "Output rule #{}: 'dst_ports' must be set when 'src_ports' is set",
                index
            )));
        }

        if rule.dst_ports.is_empty() {
            return Err(Error::config(format!(
                "Output rule #{}: 'dst_ports' must be set when 'proto' is set",
                index
            )));
        }

        Self::validate_verdict(&rule.verdict)?;

        Ok(())
    }

    fn validate_verdict(verdict: &ConfigVerdict) -> Result<()> {
        if !verdict.chain.is_empty() && verdict.queue != 0 {
            return Err(Error::config(
                "'chain' and 'queue' are mutually exclusive".to_string(),
            ));
        }

        if verdict.queue == 0 && verdict.input_est_queue != 0 {
            return Err(Error::config(
                "'queue' must be set when 'input_est_queue' is set".to_string(),
            ));
        }

        if verdict.queue == 0 && verdict.output_est_queue != 0 {
            return Err(Error::config(
                "'queue' must be set when 'output_est_queue' is set".to_string(),
            ));
        }

        if verdict.input_est_queue == 0 && verdict.output_est_queue != 0 {
            return Err(Error::config(
                "'input_est_queue' must be set when 'output_est_queue' is set".to_string(),
            ));
        }

        if verdict.output_est_queue == 0 && verdict.input_est_queue != 0 {
            return Err(Error::config(
                "'output_est_queue' must be set when 'input_est_queue' is set".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_mapped_ports(mapped_ports: &MappedPorts) -> Result<()> {
        // Validate external IPs consistency
        if !mapped_ports.external.ips.is_empty() {
            Self::validate_ip_family_consistency(
                &mapped_ports.external.ips,
                "External mapped ports",
            )?;
        }

        // Note: localhost should not have IPs field per the spec
        // This is enforced by not having an ips field in LocalRules struct

        Ok(())
    }

    fn validate_ip_family_consistency(ips: &[AddrOrRange], context: &str) -> Result<()> {
        let is_ipv4 = |entry: &AddrOrRange| match entry {
            AddrOrRange::Addr(address) | AddrOrRange::Range(address, _) => address.is_ipv4(),
            AddrOrRange::Net(network) => matches!(network, IpNet::V4(_)),
        };
        let family = |ipv4: bool| if ipv4 { "IPv4" } else { "IPv6" };
        let Some((first, rest)) = ips.split_first() else {
            return Ok(());
        };
        match rest.iter().find(|entry| is_ipv4(entry) != is_ipv4(first)) {
            Some(mixed) => Err(Error::config(format!(
                "{context}: mixed IPv4 and IPv6 addresses are not supported. {first} is {}, but {mixed} is {}",
                family(is_ipv4(first)),
                family(is_ipv4(mixed)),
            ))),
            None => Ok(()),
        }
    }
}

// Custom Deserialize implementation with validation
impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // First deserialize to a temporary structure
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TempConfig {
            #[serde(default)]
            mapped_ports: MappedPorts,
            #[serde(default)]
            output: Vec<RuleConfig>,
        }

        let temp = TempConfig::deserialize(deserializer)?;

        // Create the actual Config
        let config = Config {
            mapped_ports: temp.mapped_ports,
            output: temp.output,
        };

        // Basic structural validation - component types handle their own field validation
        config.validate().map_err(serde::de::Error::custom)?;

        Ok(config)
    }
}
