use crate::Result;
use crate::docker::config::{ConfigVerdict, Protocol, RulePorts, ToNftablesRule};
use bon::Builder;
use nftables::expr::{Expression, NamedExpression, Payload, PayloadField};
use nftables::stmt::{Match, Operator, Statement};
use serde::{Deserialize, Deserializer, Serialize};
use std::borrow::Cow;
#[derive(Debug, Clone, Serialize, Builder)]
pub struct RuleConfig {
    #[serde(default)]
    #[builder(default)]
    pub log_prefix: String,
    #[serde(default)]
    #[builder(default)]
    pub network: String,
    #[serde(default)]
    #[builder(default)]
    pub ips: Vec<super::AddrOrRange>,
    #[serde(default)]
    #[builder(default)]
    pub container: String,
    pub proto: Protocol,
    #[serde(default)]
    #[builder(default)]
    pub src_ports: Vec<RulePorts>,
    #[serde(default)]
    #[builder(default)]
    pub dst_ports: Vec<RulePorts>,
    #[serde(default)]
    #[builder(default)]
    pub verdict: ConfigVerdict,

    #[serde(skip)]
    #[builder(default = false)]
    pub skip: bool,
}

// Custom Deserialize for RuleConfig with validation
impl<'de> Deserialize<'de> for RuleConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct TempRuleConfig {
            #[serde(default)]
            log_prefix: String,
            #[serde(default)]
            network: String,
            #[serde(default)]
            ips: Vec<super::AddrOrRange>,
            #[serde(default)]
            container: String,
            proto: Protocol,
            #[serde(default)]
            src_ports: Vec<RulePorts>,
            #[serde(default)]
            dst_ports: Vec<RulePorts>,
            #[serde(default)]
            verdict: ConfigVerdict,
            #[serde(skip)]
            skip: bool,
        }

        let temp = TempRuleConfig::deserialize(deserializer)?;

        // Validate rule is not empty
        if temp.ips.is_empty()
            && temp.container.is_empty()
            && temp.src_ports.is_empty()
            && temp.dst_ports.is_empty()
        {
            return Err(serde::de::Error::custom(
                super::ValidationError::InvalidRule {
                    message: "Rule is empty (no ips, container, or ports specified)".to_string(),
                    rule_type: "output".to_string(),
                    rule_text: "empty rule".to_string(),
                    position: None,
                },
            ));
        }

        // Check mutually exclusive fields
        if !temp.ips.is_empty() && !temp.container.is_empty() {
            return Err(serde::de::Error::custom(
                super::ValidationError::InvalidFieldValue {
                    field: "rule".to_string(),
                    reason: "'ips' and 'container' are mutually exclusive".to_string(),
                    value: "both ips and container specified".to_string(),
                    expected_format: Some("Either 'ips' or 'container', not both".to_string()),
                },
            ));
        }

        // Check network requirement
        if temp.network.is_empty() && !temp.container.is_empty() {
            return Err(serde::de::Error::custom(
                super::ValidationError::MissingRequiredField {
                    field: "network".to_string(),
                    context: "rule with container reference".to_string(),
                },
            ));
        }

        // Check port requirements
        if !temp.src_ports.is_empty() && temp.dst_ports.is_empty() {
            return Err(serde::de::Error::custom(
                super::ValidationError::MissingRequiredField {
                    field: "dst_ports".to_string(),
                    context: "rule with src_ports".to_string(),
                },
            ));
        }

        if temp.dst_ports.is_empty() {
            return Err(serde::de::Error::custom(
                super::ValidationError::MissingRequiredField {
                    field: "dst_ports".to_string(),
                    context: format!("rule with protocol '{}'", temp.proto),
                },
            ));
        }

        // Validate log prefix
        if !temp.log_prefix.is_empty() && temp.log_prefix.len() > 64 {
            return Err(serde::de::Error::custom(
                super::ValidationError::InvalidFieldValue {
                    field: "log_prefix".to_string(),
                    reason: "Log prefix too long (max 64 characters)".to_string(),
                    value: temp.log_prefix.clone(),
                    expected_format: Some("String with max 64 characters".to_string()),
                },
            ));
        }

        // Validate ports
        for port_spec in &temp.dst_ports {
            match port_spec {
                RulePorts::Single(port) => {
                    if *port == 0 {
                        return Err(serde::de::Error::custom(
                            super::ValidationError::InvalidPort {
                                port: port.to_string(),
                                reason: "Port 0 is not valid".to_string(),
                            },
                        ));
                    }
                }
                RulePorts::Range(start, end) => {
                    if *start > *end {
                        return Err(serde::de::Error::custom(
                            super::ValidationError::InvalidPortRange {
                                range: format!("{}-{}", start, end),
                                reason: "Start port is greater than end port".to_string(),
                            },
                        ));
                    }
                    if *start == 0 {
                        return Err(serde::de::Error::custom(
                            super::ValidationError::InvalidPort {
                                port: start.to_string(),
                                reason: "Port 0 is not valid".to_string(),
                            },
                        ));
                    }
                    if *end == 0 {
                        return Err(serde::de::Error::custom(
                            super::ValidationError::InvalidPort {
                                port: end.to_string(),
                                reason: "Port 0 is not valid".to_string(),
                            },
                        ));
                    }
                }
            }
        }

        // Validate source ports as well
        for port_spec in &temp.src_ports {
            match port_spec {
                RulePorts::Single(port) => {
                    if *port == 0 {
                        return Err(serde::de::Error::custom(
                            super::ValidationError::InvalidPort {
                                port: port.to_string(),
                                reason: "Port 0 is not valid".to_string(),
                            },
                        ));
                    }
                }
                RulePorts::Range(start, end) => {
                    if *start > *end {
                        return Err(serde::de::Error::custom(
                            super::ValidationError::InvalidPortRange {
                                range: format!("{}-{}", start, end),
                                reason: "Start port is greater than end port".to_string(),
                            },
                        ));
                    }
                    if *start == 0 {
                        return Err(serde::de::Error::custom(
                            super::ValidationError::InvalidPort {
                                port: start.to_string(),
                                reason: "Port 0 is not valid".to_string(),
                            },
                        ));
                    }
                    if *end == 0 {
                        return Err(serde::de::Error::custom(
                            super::ValidationError::InvalidPort {
                                port: end.to_string(),
                                reason: "Port 0 is not valid".to_string(),
                            },
                        ));
                    }
                }
            }
        }

        Ok(RuleConfig {
            log_prefix: temp.log_prefix,
            network: temp.network,
            ips: temp.ips,
            container: temp.container,
            proto: temp.proto,
            src_ports: temp.src_ports,
            dst_ports: temp.dst_ports,
            verdict: temp.verdict,
            skip: temp.skip,
        })
    }
}

/// Implementation for RuleConfig (output rules)
impl ToNftablesRule for RuleConfig {
    fn to_nftables_statements(&self) -> Result<Vec<Statement<'static>>> {
        let mut statements = Vec::new();

        // Match protocol
        let protocol_str = match self.proto {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };
        statements.push(Self::match_protocol(protocol_str));

        // Match destination IPs if specified
        if !self.ips.is_empty() {
            // Create a set expression for multiple IPs
            let mut ip_exprs = Vec::new();

            for addr_or_range in &self.ips {
                match addr_or_range {
                    super::AddrOrRange::Addr(ip) => {
                        ip_exprs.push(Expression::String(Cow::Owned(ip.to_string())));
                    }
                    super::AddrOrRange::Range(start, end) => {
                        ip_exprs.push(Expression::Range(Box::new(nftables::expr::Range {
                            range: [
                                Expression::String(Cow::Owned(start.to_string())),
                                Expression::String(Cow::Owned(end.to_string())),
                            ],
                        })));
                    }
                    super::AddrOrRange::Net(net) => {
                        // Parse CIDR notation to create a prefix expression
                        let addr = net.addr();
                        let prefix_len = net.prefix_len() as u32;

                        ip_exprs.push(Expression::Named(NamedExpression::Prefix(
                            nftables::expr::Prefix {
                                addr: Box::new(Expression::String(Cow::Owned(addr.to_string()))),
                                len: prefix_len,
                            },
                        )));
                    }
                }
            }

            // Determine protocol based on first IP
            let protocol = match self.ips.first() {
                Some(super::AddrOrRange::Addr(ip)) => {
                    if ip.is_ipv4() {
                        "ip"
                    } else {
                        "ip6"
                    }
                }
                Some(super::AddrOrRange::Range(start, _)) => {
                    if start.is_ipv4() {
                        "ip"
                    } else {
                        "ip6"
                    }
                }
                Some(super::AddrOrRange::Net(net)) => {
                    if net.addr().is_ipv4() {
                        "ip"
                    } else {
                        "ip6"
                    }
                }
                _ => "ip",
            };

            if ip_exprs.len() == 1 {
                // Single IP/range/prefix - use direct match
                statements.push(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed(protocol),
                            field: Cow::Borrowed("daddr"),
                        },
                    ))),
                    right: ip_exprs.into_iter().next().unwrap(),
                    op: Operator::EQ,
                }));
            } else {
                // Multiple IPs - use anonymous set
                let set_items: Vec<nftables::expr::SetItem> = ip_exprs
                    .into_iter()
                    .map(|expr| nftables::expr::SetItem::Element(expr))
                    .collect();

                statements.push(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed(protocol),
                            field: Cow::Borrowed("daddr"),
                        },
                    ))),
                    right: Expression::Named(NamedExpression::Set(set_items)),
                    op: Operator::EQ,
                }));
            }
        }

        // Match source ports if specified
        for port in &self.src_ports {
            match port {
                RulePorts::Single(p) => {
                    statements.push(Self::match_src_port(protocol_str, *p));
                }
                RulePorts::Range(start, end) => {
                    statements.push(Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: Cow::Owned(protocol_str.to_string()),
                                field: Cow::Borrowed("sport"),
                            },
                        ))),
                        right: Expression::Range(Box::new(nftables::expr::Range {
                            range: [
                                Expression::Number(*start as u32),
                                Expression::Number(*end as u32),
                            ],
                        })),
                        op: Operator::EQ,
                    }));
                }
            }
            break; // For now, only handle first port/range
        }

        // Match destination ports
        for port in &self.dst_ports {
            match port {
                RulePorts::Single(p) => {
                    statements.push(Self::match_dst_port(protocol_str, *p));
                }
                RulePorts::Range(start, end) => {
                    statements.push(Self::match_dst_port_range(protocol_str, *start, *end));
                }
            }
            break; // For now, only handle first port/range
        }

        // Add counter
        statements.push(Self::counter_statement());

        // Add log if configured
        if !self.log_prefix.is_empty() {
            statements.push(Self::log_statement(Some(&self.log_prefix)));
        }

        // Add verdict
        statements.push(Self::verdict_to_statement(&self.verdict));

        Ok(statements)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_config_valid_minimal() {
        let yaml = r#"
proto: tcp
dst_ports:
  - 80
ips:
  - 192.168.1.1
"#;
        let result: std::result::Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rule_config_empty_rule() {
        let yaml = "proto: tcp";
        let result: std::result::Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_rule_config_ips_and_container_exclusive() {
        let yaml = r#"
proto: tcp
dst_ports:
  - 80
ips:
  - 192.168.1.1
container: my-container
network: default
"#;
        let result: std::result::Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn test_rule_config_container_requires_network() {
        let yaml = r#"
proto: tcp
dst_ports:
  - 80
container: my-container
"#;
        let result: std::result::Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_rule_config_src_ports_requires_dst_ports() {
        let yaml = r#"
proto: tcp
src_ports:
  - 8080
ips:
  - 192.168.1.1
"#;
        let result: std::result::Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_rule_config_port_zero_invalid() {
        let yaml = r#"
proto: tcp
dst_ports:
  - 0
ips:
  - 192.168.1.1
"#;
        let result: std::result::Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_rule_config_port_range_invalid() {
        let yaml = r#"
proto: tcp
dst_ports:
  - 8090-8080
ips:
  - 192.168.1.1
"#;
        let result: std::result::Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_rule_config_log_prefix_too_long() {
        let long_prefix = "a".repeat(65);
        let yaml = format!(r#"
proto: tcp
dst_ports:
  - 80
ips:
  - 192.168.1.1
log_prefix: '{}'
"#, long_prefix);
        let result: std::result::Result<RuleConfig, _> = serde_yaml::from_str(&yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_rule_config_valid_with_container() {
        let yaml = r#"
proto: tcp
dst_ports:
  - 80
container: my-container
network: default
"#;
        let result: std::result::Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rule_to_nftables_tcp() {
        let rule = RuleConfig::builder()
            .proto(Protocol::Tcp)
            .dst_ports(vec![RulePorts::Single(80)])
            .ips(vec!["192.168.1.1".parse().unwrap()])
            .build();
        let statements = rule.to_nftables_statements().unwrap();
        assert!(!statements.is_empty());
    }

    #[test]
    fn test_rule_to_nftables_udp() {
        let rule = RuleConfig::builder()
            .proto(Protocol::Udp)
            .dst_ports(vec![RulePorts::Single(53)])
            .ips(vec!["8.8.8.8".parse().unwrap()])
            .build();
        let statements = rule.to_nftables_statements().unwrap();
        assert!(!statements.is_empty());
    }
}
