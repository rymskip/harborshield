use crate::common::{
    TestEnvironment,
    assertions::{ConnectivityAssertions, ContainerAssertions, NftablesAssertions},
};
use compose_spec::service::ports::{Port, Ports, ShortPort};
use compose_spec::{Compose, Service, ShortOrLong};
use harborshield::docker::config::Config;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A named test assertion
pub struct NamedAssertion {
    pub name: String,
    pub assertion: Box<
        dyn FnOnce(
                Arc<Mutex<TestEnvironment>>,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<(), Box<dyn std::error::Error + Send + Sync>>,
                        > + Send,
                >,
            > + Send,
    >,
}

/// Parser for Docker Compose files to generate test assertions
pub struct ComposeParser;

impl ComposeParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract all unique verdict chains from the compose configuration
    pub fn extract_verdict_chains(
        yaml: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let compose: Compose = serde_yaml::from_str(yaml)?;
        let mut verdict_chains = std::collections::HashSet::new();

        // Extract verdict chains from all services
        for (_, service) in compose.services.iter() {
            if Self::has_harborshield_enabled(service) {
                if let Some(rules_yaml) = Self::get_harborshield_rules(service) {
                    if let Ok(rules_value) = serde_yaml::from_str::<serde_yaml::Value>(rules_yaml) {
                        // Check mapped_ports for verdict chains
                        if let Some(mapped_ports) = rules_value.get("mapped_ports") {
                            // Check localhost rules
                            if let Some(localhost) = mapped_ports.get("localhost") {
                                if let Some(verdict) = localhost.get("verdict") {
                                    if let Some(chain) = verdict
                                        .get("chain")
                                        .and_then(|c| c.as_str())
                                        .filter(|s| !s.is_empty())
                                    {
                                        verdict_chains.insert(chain.to_string());
                                    }
                                }
                            }

                            // Check external rules
                            if let Some(external) = mapped_ports.get("external") {
                                if let Some(verdict) = external.get("verdict") {
                                    if let Some(chain) = verdict
                                        .get("chain")
                                        .and_then(|c| c.as_str())
                                        .filter(|s| !s.is_empty())
                                    {
                                        verdict_chains.insert(chain.to_string());
                                    }
                                }
                            }
                        }

                        // Check output rules
                        if let Some(outputs) =
                            rules_value.get("output").and_then(|o| o.as_sequence())
                        {
                            for output in outputs {
                                if let Some(verdict) = output.get("verdict") {
                                    if let Some(chain) = verdict
                                        .get("chain")
                                        .and_then(|c| c.as_str())
                                        .filter(|s| !s.is_empty())
                                    {
                                        verdict_chains.insert(chain.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(verdict_chains.into_iter().collect())
    }

    /// Extract all network names from the compose configuration
    pub fn extract_networks(compose: &Compose) -> Vec<String> {
        let mut networks = Vec::new();

        // Get explicitly defined networks
        for (network_name, _) in compose.networks.iter() {
            networks.push(network_name.to_string());
        }

        // If no networks are defined, docker-compose creates a default network
        if networks.is_empty() {
            networks.push("default".to_string());
        }

        networks
    }

    /// Extract cross-network rules from a service
    pub fn extract_cross_network_rules(
        service_name: &str,
        service: &Service,
    ) -> Vec<(String, String, String)> {
        let mut cross_network_rules = Vec::new();

        if let Some(rules_yaml) = Self::get_harborshield_rules(service) {
            if let Ok(config) = serde_yaml::from_str::<Config>(rules_yaml) {
                for rule in &config.output {
                    if !rule.network.is_empty() && !rule.container.is_empty() {
                        cross_network_rules.push((
                            service_name.to_string(),
                            rule.network.clone(),
                            rule.container.clone(),
                        ));
                    }
                }
            }
        }

        cross_network_rules
    }

    /// Parse a compose file and generate test assertions
    pub fn parse_compose_yaml(
        yaml: &str,
    ) -> Result<Vec<NamedAssertion>, Box<dyn std::error::Error + Send + Sync>> {
        eprintln!("🔍 Parsing compose YAML to generate test assertions...");
        let compose: Compose = serde_yaml::from_str(yaml)?;
        let mut assertions = Vec::new();

        // Extract information from the compose file
        let services: Vec<(String, &Service)> = compose
            .services
            .iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        eprintln!("📦 Found {} services in compose file", services.len());
        for (name, _) in &services {
            eprintln!("  - {}", name);
        }

        // Extract networks
        let networks = Self::extract_networks(&compose);
        eprintln!("🌐 Found {} networks in compose file", networks.len());
        for network in &networks {
            eprintln!("  - {}", network);
        }

        // Count harborshield-enabled services
        let harborshield_enabled_count = services
            .iter()
            .filter(|(_, service)| Self::has_harborshield_enabled(service))
            .count();
        eprintln!(
            "🔒 {} services have harborshield enabled",
            harborshield_enabled_count
        );

        // Add chain creation assertion
        eprintln!(
            "➕ Adding assertion: Check chain creation (expecting {} chains)",
            harborshield_enabled_count
        );
        assertions.push(NamedAssertion {
            name: "Check chain creation".to_string(),
            assertion: Box::new(NftablesAssertions::assert_chains_created(
                harborshield_enabled_count,
            )),
        });

        // Add container state assertions
        eprintln!(
            "➕ Adding assertion: Verify container states (expecting {} containers)",
            services.len()
        );
        assertions.push(NamedAssertion {
            name: "Verify container states".to_string(),
            assertion: Box::new(ContainerAssertions::assert_container_state(services.len())),
        });

        // Add NFTables setup assertion
        eprintln!("➕ Adding assertion: Verify Harborshield NFTables setup");
        assertions.push(NamedAssertion {
            name: "Verify Harborshield NFTables setup".to_string(),
            assertion: Box::new(NftablesAssertions::assert_nftables_setup()),
        });

        // Add individual service chain assertions for harborshield-enabled services
        let mut harborshield_enabled_services = Vec::new();
        for (service_name, service) in &services {
            if Self::has_harborshield_enabled(service) {
                harborshield_enabled_services.push(service_name.clone());
            }
        }

        if !harborshield_enabled_services.is_empty() {
            eprintln!("➕ Adding assertion: Verify individual service chains and labels");
            eprintln!("   Services to check:");
            for service in &harborshield_enabled_services {
                eprintln!("   - {}", service);
            }
            assertions.push(NamedAssertion {
                name: "Verify individual service chains and labels".to_string(),
                assertion: Box::new(NftablesAssertions::assert_service_chains_and_labels(
                    harborshield_enabled_services.clone(),
                )),
            });
        }

        // Add container rules assertions
        let mut port_rules = Vec::new();
        let mut connections = Vec::new();
        let mut blocked_connections: Vec<(String, String, u16)> = Vec::new();

        eprintln!("🔍 Analyzing service rules...");
        for (service_name, service) in &services {
            // Negative-path assertions are independent of harborshield.enabled —
            // any service can declare what it expects to be blocked.
            for (target, port) in Self::get_expect_blocked(service) {
                eprintln!(
                    "    🚫 Expect blocked: {} -> {} on port {}",
                    service_name, target, port
                );
                blocked_connections.push((service_name.to_string(), target, port));
            }

            if Self::has_harborshield_enabled(service) {
                eprintln!("  📋 Checking rules for service: {}", service_name);
                // Check for port rules
                if let Some(rules_yaml) = Self::get_harborshield_rules(service) {
                    // First, validate the rules by parsing them as Config
                    match serde_yaml::from_str::<Config>(rules_yaml) {
                        Ok(_config) => {
                            // Rules are valid, continue with extraction
                        }
                        Err(e) => {
                            eprintln!(
                                "    ❌ Invalid rules configuration for {}: {}",
                                service_name, e
                            );
                            return Err(format!(
                                "Service '{}' has invalid harborshield rules: {}",
                                service_name, e
                            )
                            .into());
                        }
                    }

                    // Parse the rules YAML to extract detailed configuration
                    if let Ok(rules_value) = serde_yaml::from_str::<serde_yaml::Value>(rules_yaml) {
                        // Check mapped_ports rules
                        if let Some(mapped_ports) = rules_value.get("mapped_ports") {
                            let localhost_allowed = mapped_ports
                                .get("localhost")
                                .and_then(|l| l.get("allow"))
                                .and_then(|a| a.as_bool())
                                .unwrap_or(false);

                            let external_allowed = mapped_ports
                                .get("external")
                                .and_then(|e| e.get("allow"))
                                .and_then(|a| a.as_bool())
                                .unwrap_or(false);

                            if (localhost_allowed || external_allowed) && !service.ports.is_empty()
                            {
                                // Extract the container port from the first port mapping
                                match Self::extract_container_port(&service.ports) {
                                    Ok(port) => {
                                        eprintln!(
                                            "    🔌 Found port rule for {}: port {} (localhost: {}, external: {})",
                                            service_name, port, localhost_allowed, external_allowed
                                        );
                                        port_rules.push((service_name.to_string(), port));
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "    ⚠️  Error extracting port for {}: {}",
                                            service_name, e
                                        );
                                    }
                                }
                            }
                        }

                        // Extract OUTPUT rules for connections
                        if let Some(outputs) =
                            rules_value.get("output").and_then(|o| o.as_sequence())
                        {
                            for output in outputs {
                                if let (Some(target), Some(ports)) = (
                                    output.get("container").and_then(|c| c.as_str()),
                                    output.get("dst_ports").and_then(|p| p.as_sequence()),
                                ) {
                                    if let Some(port) = ports.first().and_then(|p| p.as_u64()) {
                                        eprintln!(
                                            "    🔗 Found connection rule: {} -> {} on port {}",
                                            service_name, target, port
                                        );
                                        connections.push((
                                            service_name.to_string(),
                                            target.to_string(),
                                            port as u16,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Add container rules assertion
        if !port_rules.is_empty() {
            eprintln!("➕ Adding assertion: Verify container rules");
            eprintln!("   Port rules to check:");
            for (service, port) in &port_rules {
                eprintln!("   - {}: port {}", service, port);
            }
            assertions.push(NamedAssertion {
                name: "Verify container rules".to_string(),
                assertion: Box::new(NftablesAssertions::assert_container_rules(port_rules)),
            });
        }

        // Add connectivity assertion
        if !connections.is_empty() {
            eprintln!("➕ Adding assertion: Test connectivity between services");
            eprintln!("   Connections to test:");
            for (from, to, port) in &connections {
                eprintln!("   - {} -> {}:{}", from, to, port);
            }
            assertions.push(NamedAssertion {
                name: "Test connectivity between services".to_string(),
                assertion: Box::new(ConnectivityAssertions::assert_connectivity_batch(
                    connections,
                )),
            });
        }

        // Add negative-path assertion: services that declare expect_blocked
        if !blocked_connections.is_empty() {
            eprintln!("➕ Adding assertion: Verify expected drops");
            for (from, to, port) in &blocked_connections {
                eprintln!("   - {} -> {}:{} (expected BLOCKED)", from, to, port);
            }
            assertions.push(NamedAssertion {
                name: "Verify expected drops".to_string(),
                assertion: Box::new(ConnectivityAssertions::assert_blocked_batch(
                    blocked_connections,
                )),
            });
        }

        // Add advanced rule assertions
        let mut services_with_advanced_rules = Vec::new();

        eprintln!("🔍 Analyzing advanced rule features...");
        for (service_name, service) in &services {
            if Self::has_harborshield_enabled(service) {
                if let Some(rules_yaml) = Self::get_harborshield_rules(service) {
                    // Validate rules first
                    match serde_yaml::from_str::<Config>(rules_yaml) {
                        Ok(_) => {
                            // Rules are valid
                        }
                        Err(e) => {
                            eprintln!("  ❌ Invalid rules for service {}: {}", service_name, e);
                            return Err(format!(
                                "Service '{}' has invalid harborshield rules: {}",
                                service_name, e
                            )
                            .into());
                        }
                    }

                    if let Ok(rules_value) = serde_yaml::from_str::<serde_yaml::Value>(rules_yaml) {
                        let mut log_prefixes = Vec::new();
                        let mut verdict_chains = Vec::new();
                        let mut nfqueues = Vec::new();
                        let mut ip_filters = Vec::new();

                        // Check mapped_ports for advanced features
                        if let Some(mapped_ports) = rules_value.get("mapped_ports") {
                            // Check localhost rules
                            if let Some(localhost) = mapped_ports.get("localhost") {
                                if let Some(log_prefix) = localhost
                                    .get("log_prefix")
                                    .and_then(|l| l.as_str())
                                    .filter(|s| !s.is_empty())
                                {
                                    log_prefixes
                                        .push(("container".to_string(), log_prefix.to_string()));
                                }

                                if let Some(verdict) = localhost.get("verdict") {
                                    if let Some(chain) = verdict
                                        .get("chain")
                                        .and_then(|c| c.as_str())
                                        .filter(|s| !s.is_empty())
                                    {
                                        verdict_chains
                                            .push(("container".to_string(), chain.to_string()));
                                    }

                                    if let Some(queue) =
                                        verdict.get("queue").and_then(|q| q.as_u64())
                                    {
                                        nfqueues.push(("container".to_string(), queue as u32));
                                    }
                                }
                            }

                            // Check external rules
                            if let Some(external) = mapped_ports.get("external") {
                                if let Some(log_prefix) = external
                                    .get("log_prefix")
                                    .and_then(|l| l.as_str())
                                    .filter(|s| !s.is_empty())
                                {
                                    log_prefixes
                                        .push(("container".to_string(), log_prefix.to_string()));
                                }

                                if let Some(ips) = external.get("ips").and_then(|i| i.as_sequence())
                                {
                                    let ip_list: Vec<String> = ips
                                        .iter()
                                        .filter_map(|ip| ip.as_str())
                                        .map(|s| s.to_string())
                                        .collect();
                                    if !ip_list.is_empty() {
                                        ip_filters.push(("container".to_string(), ip_list));
                                    }
                                }

                                if let Some(verdict) = external.get("verdict") {
                                    if let Some(chain) = verdict
                                        .get("chain")
                                        .and_then(|c| c.as_str())
                                        .filter(|s| !s.is_empty())
                                    {
                                        verdict_chains
                                            .push(("container".to_string(), chain.to_string()));
                                    }

                                    if let Some(queue) =
                                        verdict.get("queue").and_then(|q| q.as_u64())
                                    {
                                        nfqueues.push(("container".to_string(), queue as u32));
                                    }
                                }
                            }
                        }

                        // Check output rules for advanced features
                        if let Some(outputs) =
                            rules_value.get("output").and_then(|o| o.as_sequence())
                        {
                            for output in outputs {
                                if let Some(log_prefix) = output
                                    .get("log_prefix")
                                    .and_then(|l| l.as_str())
                                    .filter(|s| !s.is_empty())
                                {
                                    log_prefixes
                                        .push(("container".to_string(), log_prefix.to_string()));
                                }

                                if let Some(verdict) = output.get("verdict") {
                                    if let Some(chain) = verdict
                                        .get("chain")
                                        .and_then(|c| c.as_str())
                                        .filter(|s| !s.is_empty())
                                    {
                                        verdict_chains
                                            .push(("container".to_string(), chain.to_string()));
                                    }

                                    if let Some(queue) =
                                        verdict.get("queue").and_then(|q| q.as_u64())
                                    {
                                        nfqueues.push(("container".to_string(), queue as u32));
                                    }
                                }
                            }
                        }

                        if !log_prefixes.is_empty()
                            || !verdict_chains.is_empty()
                            || !nfqueues.is_empty()
                            || !ip_filters.is_empty()
                        {
                            eprintln!("  🎯 Found advanced rules for service: {}", service_name);
                            if !log_prefixes.is_empty() {
                                eprintln!("    📝 Log prefixes: {:?}", log_prefixes);
                            }
                            if !verdict_chains.is_empty() {
                                eprintln!("    ⚖️  Verdict chains: {:?}", verdict_chains);
                            }
                            if !nfqueues.is_empty() {
                                eprintln!("    📦 NFQueues: {:?}", nfqueues);
                            }
                            if !ip_filters.is_empty() {
                                eprintln!("    🌐 IP filters: {:?}", ip_filters);
                            }

                            services_with_advanced_rules.push((
                                service_name.clone(),
                                log_prefixes,
                                verdict_chains,
                                nfqueues,
                                ip_filters,
                            ));
                        }
                    }
                }
            }
        }

        // Add advanced rule assertions
        for (service_name, log_prefixes, verdict_chains, nfqueues, ip_filters) in
            services_with_advanced_rules
        {
            eprintln!(
                "➕ Adding assertion: Verify advanced rules for {}",
                service_name
            );
            assertions.push(NamedAssertion {
                name: format!("Verify advanced rules for {}", service_name),
                assertion: Box::new(NftablesAssertions::assert_advanced_rules(
                    service_name,
                    log_prefixes,
                    verdict_chains,
                    nfqueues,
                    ip_filters,
                )),
            });
        }

        // Analyze and add cross-network rules
        let mut all_cross_network_rules = Vec::new();
        eprintln!("🔍 Analyzing cross-network dependencies...");
        for (service_name, service) in &services {
            if Self::has_harborshield_enabled(service) {
                let cross_network_rules = Self::extract_cross_network_rules(service_name, service);
                if !cross_network_rules.is_empty() {
                    eprintln!(
                        "  📡 Service {} has {} cross-network rules:",
                        service_name,
                        cross_network_rules.len()
                    );
                    for (_, network, container) in &cross_network_rules {
                        eprintln!("    - Can talk to {} on network {}", container, network);
                    }
                    all_cross_network_rules.extend(cross_network_rules);
                }
            }
        }

        if !all_cross_network_rules.is_empty() {
            eprintln!(
                "➕ Adding assertion: Verify cross-network rules (found {} rules)",
                all_cross_network_rules.len()
            );
            assertions.push(NamedAssertion {
                name: "Verify cross-network rules".to_string(),
                assertion: Box::new(NftablesAssertions::assert_cross_network_rules(
                    all_cross_network_rules,
                )),
            });
        }

        // Always add security isolation test at the end
        eprintln!("➕ Adding assertion: Verify security isolation from external attacker");
        assertions.push(NamedAssertion {
            name: "Verify security isolation from external attacker".to_string(),
            assertion: Box::new(
                crate::common::assertions::SecurityAssertions::assert_isolation_from_attacker(),
            ),
        });

        eprintln!("✅ Generated {} test assertions", assertions.len());
        Ok(assertions)
    }

    // Helper methods
    fn has_harborshield_enabled(service: &Service) -> bool {
        match &service.labels {
            compose_spec::ListOrMap::Map(map) => {
                if let Some(value) = map.get("harborshield.enabled") {
                    if let Some(value_ref) = value.as_ref() {
                        // Handle both string "true" and boolean true
                        if let Some(s) = value_ref.as_string() {
                            s == "true"
                        } else if let Some(b) = value_ref.as_bool() {
                            b
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn get_harborshield_rules(service: &Service) -> Option<&str> {
        match &service.labels {
            compose_spec::ListOrMap::Map(map) => map
                .get("harborshield.rules")
                .and_then(|v| v.as_ref())
                .and_then(|v| v.as_string())
                .map(|s| s.as_str()),
            _ => None,
        }
    }

    /// Parse `harborshield.test.expect_blocked` -> Vec<(target_service, port)>.
    /// Format: comma-separated `service:port` items, e.g. "server:9001,server:80".
    fn get_expect_blocked(service: &Service) -> Vec<(String, u16)> {
        let raw = match &service.labels {
            compose_spec::ListOrMap::Map(map) => map
                .get("harborshield.test.expect_blocked")
                .and_then(|v| v.as_ref())
                .and_then(|v| v.as_string())
                .map(|s| s.to_string()),
            _ => None,
        };
        let Some(raw) = raw else {
            return Vec::new();
        };
        raw.split(',')
            .filter_map(|item| {
                let mut parts = item.trim().splitn(2, ':');
                let target = parts.next()?.trim().to_string();
                let port = parts.next()?.trim().parse::<u16>().ok()?;
                if target.is_empty() {
                    None
                } else {
                    Some((target, port))
                }
            })
            .collect()
    }

    /// Extract container port from port mappings
    fn extract_container_port(
        ports: &Ports,
    ) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(port_spec) = ports.iter().next() {
            match port_spec {
                ShortOrLong::Short(short_port) => {
                    // Convert ShortPort to Port using into_long_iter
                    if let Some(port) = short_port.clone().into_long_iter().next() {
                        Ok(port.target)
                    } else {
                        Err("No port found in ShortPort".into())
                    }
                }
                ShortOrLong::Long(port) => {
                    // Long form has explicit target field
                    Ok(port.target)
                }
            }
        } else {
            Err("No ports defined in service".into())
        }
    }
}
