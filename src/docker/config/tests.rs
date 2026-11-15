use super::{
    AddrOrRange, Config, ConfigVerdict, ExternalRules, LocalRules, MappedPorts, Protocol,
    RuleConfig, RulePorts,
};
use crate::Result;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_parse_single_ipv4_address() {
    let input = "192.168.1.1";
    let addr: AddrOrRange = input.parse().unwrap();

    match addr {
        AddrOrRange::Addr(ip) => {
            assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        }
        _ => panic!("Expected single address"),
    }
}

#[test]
fn test_parse_single_ipv6_address() {
    let input = "2001:db8::1";
    let addr: AddrOrRange = input.parse().unwrap();

    match addr {
        AddrOrRange::Addr(ip) => {
            assert!(matches!(ip, IpAddr::V6(_)));
        }
        _ => panic!("Expected single address"),
    }
}

#[test]
fn test_parse_ipv4_cidr() {
    let input = "192.168.0.0/24";
    let addr: AddrOrRange = input.parse().unwrap();

    match addr {
        AddrOrRange::Net(net) => {
            assert_eq!(net.to_string(), "192.168.0.0/24");
        }
        _ => panic!("Expected network"),
    }
}

#[test]
fn test_parse_ipv4_range() {
    let input = "192.168.1.1-192.168.1.10";
    let addr: AddrOrRange = input.parse().unwrap();

    match addr {
        AddrOrRange::Range(start, end) => {
            assert_eq!(start, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(end, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        }
        _ => panic!("Expected range"),
    }
}

#[test]
fn test_invalid_ip_address() {
    let input = "invalid.ip.address";
    let result: Result<AddrOrRange> = input.parse();
    assert!(result.is_err());
}

#[test]
fn test_parse_single_port() {
    let input = "8080";
    let ports: RulePorts = input.parse().unwrap();

    assert_eq!(ports, RulePorts::Single(8080));
}

#[test]
fn test_parse_port_range() {
    let input = "8080-8090";
    let ports: RulePorts = input.parse().unwrap();

    assert_eq!(ports, RulePorts::Range(8080, 8090));
}

#[test]
fn test_invalid_port_range() {
    let input = "8090-8080"; // End before start
    let ports: Result<RulePorts> = input.parse();

    assert!(ports.is_err());
}

#[test]
fn test_invalid_port_number() {
    let input = "70000"; // > 65535
    let ports: Result<RulePorts> = input.parse();

    assert!(ports.is_err());
}

#[test]
fn test_protocol_serialization() {
    assert_eq!(Protocol::Tcp.to_string(), "tcp");
    assert_eq!(Protocol::Udp.to_string(), "udp");
}

#[test]
fn test_config_validation_empty_rule() {
    let config = Config {
        mapped_ports: MappedPorts::default(),
        output: vec![RuleConfig {
            log_prefix: String::new(),
            network: String::new(),
            ips: vec![],
            container: String::new(),
            proto: Protocol::Tcp,
            src_ports: vec![],
            dst_ports: vec![],
            verdict: ConfigVerdict::default(),
            skip: false,
        }],
    };

    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("empty"));
}

#[test]
fn test_config_validation_ips_and_container_exclusive() {
    let config = Config {
        mapped_ports: MappedPorts::default(),
        output: vec![RuleConfig {
            log_prefix: String::new(),
            network: String::new(),
            ips: vec!["192.168.1.1".parse().unwrap()],
            container: "test".to_string(),
            proto: Protocol::Tcp,
            src_ports: vec![],
            dst_ports: vec![RulePorts::Single(80)],
            verdict: ConfigVerdict::default(),
            skip: false,
        }],
    };

    let result = config.validate();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("mutually exclusive")
    );
}

#[test]
fn test_config_validation_container_requires_network() {
    let config = Config {
        mapped_ports: MappedPorts::default(),
        output: vec![RuleConfig {
            log_prefix: String::new(),
            network: String::new(), // Empty network
            ips: vec![],
            container: "test".to_string(),
            proto: Protocol::Tcp,
            src_ports: vec![],
            dst_ports: vec![RulePorts::Single(80)],
            verdict: ConfigVerdict::default(),
            skip: false,
        }],
    };

    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("network"));
}

#[test]
fn test_config_validation_verdict_queue_exclusive() {
    let verdict = ConfigVerdict {
        chain: "test".to_string(),
        queue: 1,
        ..Default::default()
    };

    let result = Config::validate_verdict(&verdict);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("mutually exclusive")
    );
}

#[test]
fn test_valid_config() {
    let config = Config {
        mapped_ports: MappedPorts {
            localhost: LocalRules {
                allow: true,
                log_prefix: "test".to_string(),
                verdict: ConfigVerdict::default(),
                include_gateway_ips: true,
            },
            external: ExternalRules {
                allow: false,
                log_prefix: String::new(),
                ips: vec!["192.168.1.0/24".parse().unwrap()],
                verdict: ConfigVerdict::default(),
            },
        },
        output: vec![RuleConfig {
            log_prefix: String::new(),
            network: "default".to_string(),
            ips: vec![],
            container: "database".to_string(),
            proto: Protocol::Tcp,
            src_ports: vec![],
            dst_ports: vec![RulePorts::Single(5432)],
            verdict: ConfigVerdict::default(),
            skip: false,
        }],
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_yaml_parsing() {
    let yaml = r#"
mapped_ports:
  localhost:
    allow: true
    log_prefix: "test"
  external:
    allow: false
    ips:
      - "192.168.1.0/24"
output:
  - network: default
    container: database
    proto: tcp
    dst_ports:
      - 5432
"#;

    let config: Config = serde_saphyr::from_str(yaml).unwrap();
    assert!(config.mapped_ports.localhost.allow);
    assert!(!config.mapped_ports.external.allow);
    assert_eq!(config.output.len(), 1);
    assert_eq!(config.output[0].container, "database");
}

#[test]
fn test_mixed_ip_families_validation() {
    let yaml = r#"
mapped_ports:
  external:
    allow: true
    ips:
      - "10.0.0.0/8"
      - "2001:db8::/32"
"#;

    let result = serde_saphyr::from_str::<Config>(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("mixed IPv4 and IPv6"));
}

#[test]
fn test_output_rule_mixed_ip_families() {
    let yaml = r#"
output:
  - proto: tcp
    dst_ports: ["80"]
    ips: 
      - "192.168.1.1"
      - "2001:db8::1"
"#;

    let result = serde_saphyr::from_str::<Config>(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("mixed IPv4 and IPv6"));
}

#[test]
fn test_verdict_queue_validation() {
    // Test that input_est_queue requires output_est_queue
    let yaml = r#"
mapped_ports:
  localhost:
    allow: true
    verdict:
      queue: 100
      input_est_queue: 101
"#;

    let result = serde_saphyr::from_str::<Config>(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("output_est_queue"));
}

#[test]
fn test_verdict_chain_queue_mutually_exclusive() {
    let yaml = r#"
mapped_ports:
  localhost:
    allow: true
    verdict:
      chain: "custom-chain"
      queue: 100
"#;

    let result = serde_saphyr::from_str::<Config>(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("mutually exclusive"));
}

#[test]
fn test_external_multiple_ips_same_family() {
    let yaml = r#"
mapped_ports:
  external:
    allow: true
    ips:
      - "10.0.0.0/8"
      - "192.168.1.0/24"
      - "172.16.0.0-172.16.255.255"
"#;

    let config: Config = serde_saphyr::from_str(yaml).unwrap();
    assert_eq!(config.mapped_ports.external.ips.len(), 3);
}

#[test]
fn test_zero_ip_validation() {
    let yaml = r#"
output:
  - proto: tcp
    dst_ports: ["80"]
    ips: ["0.0.0.0/0"]
"#;

    let result = serde_saphyr::from_str::<Config>(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("0.0.0.0/0"));
}

#[test]
fn ranges_must_not_mix_families_or_run_backwards() {
    for invalid in [
        "10.0.0.1-::1",
        "10.0.0.9-10.0.0.1",
        "10.0.0.1-",
        "-10.0.0.1",
    ] {
        assert!(
            invalid.parse::<AddrOrRange>().is_err(),
            "{invalid} should be rejected"
        );
    }
    assert!("10.0.0.1-10.0.0.9".parse::<AddrOrRange>().is_ok());
    assert!("fd00::1-fd00::9".parse::<AddrOrRange>().is_ok());
}

#[test]
fn networks_drop_host_bits() {
    let parsed: AddrOrRange = "10.0.0.5/24".parse().expect("valid network");
    assert_eq!(parsed.to_string(), "10.0.0.0/24");
}

#[test]
fn port_ranges_must_run_forwards() {
    assert!("90-80".parse::<RulePorts>().is_err());
    assert!("80-".parse::<RulePorts>().is_err());
    assert_eq!(
        "80-90".parse::<RulePorts>().ok(),
        Some(RulePorts::Range(80, 90))
    );
}
