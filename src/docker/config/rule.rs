use crate::docker::config::{ConfigVerdict, Protocol, RulePorts};
use bon::Builder;
use serde::{Deserialize, Deserializer, Serialize};
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
        #[serde(deny_unknown_fields)]
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

#[cfg(test)]
mod tests {
    use super::RuleConfig;

    #[test]
    fn test_rule_config_valid_minimal() {
        let yaml = r#"
proto: tcp
dst_ports:
  - 80
ips:
  - 192.168.1.1
"#;
        let result: std::result::Result<RuleConfig, _> = serde_saphyr::from_str(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rule_config_empty_rule() {
        let yaml = "proto: tcp";
        let result: std::result::Result<RuleConfig, _> = serde_saphyr::from_str(yaml);
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
        let result: std::result::Result<RuleConfig, _> = serde_saphyr::from_str(yaml);
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
        let result: std::result::Result<RuleConfig, _> = serde_saphyr::from_str(yaml);
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
        let result: std::result::Result<RuleConfig, _> = serde_saphyr::from_str(yaml);
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
        let result: std::result::Result<RuleConfig, _> = serde_saphyr::from_str(yaml);
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
        let result: std::result::Result<RuleConfig, _> = serde_saphyr::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_rule_config_log_prefix_too_long() {
        let long_prefix = "a".repeat(65);
        let yaml = format!(
            r#"
proto: tcp
dst_ports:
  - 80
ips:
  - 192.168.1.1
log_prefix: '{}'
"#,
            long_prefix
        );
        let result: std::result::Result<RuleConfig, _> = serde_saphyr::from_str(&yaml);
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
        let result: std::result::Result<RuleConfig, _> = serde_saphyr::from_str(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rule_config_rejects_unknown_fields() {
        let yaml = "proto: tcp\ndst_ports:\n  - 80\nip:\n  - 192.168.1.1";
        let result: std::result::Result<RuleConfig, _> = serde_saphyr::from_str(yaml);
        assert!(result.is_err());
    }
}
