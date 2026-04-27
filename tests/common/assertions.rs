use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Assertion helpers for NFTables rules
pub struct NftablesAssertions;

impl NftablesAssertions {
    /// Create a closure that checks if a specific chain exists
    pub fn assert_chain_exists(
        chain_name: String,
        expected: bool,
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;
                let exists = Self::chain_exists(&env, "filter", &chain_name)?;

                if exists != expected {
                    return Err(format!(
                        "Chain {} existence check failed: expected {}, got {}",
                        chain_name, expected, exists
                    )
                    .into());
                }

                Ok(())
            })
        }
    }

    /// Check if a specific chain exists using JSON
    pub fn chain_exists(
        env: &crate::common::TestEnvironment,
        table: &str,
        chain_name: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(chain) = item.get("chain") {
                    if chain.get("table").and_then(|t| t.as_str()) == Some(table)
                        && chain.get("name").and_then(|n| n.as_str()) == Some(chain_name)
                    {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// Check if chain exists using structured data

    /// Create a closure that checks if a rule contains specific content
    pub fn assert_rule_contains(
        chain: String,
        content: String,
        expected: bool,
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;
                let contains = Self::rule_contains(&env, &chain, &content)?;

                if contains != expected {
                    return Err(format!(
                        "Rule content check failed in chain {}: expected to {} contain '{}', but it {}",
                        chain,
                        if expected { "" } else { "NOT" },
                        content,
                        if contains { "does" } else { "doesn't" }
                    ).into());
                }

                Ok(())
            })
        }
    }

    /// Check if a rule contains specific content using JSON
    pub fn rule_contains(
        env: &crate::common::TestEnvironment,
        chain: &str,
        content: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;

        // This is a generic content check - for specific checks like ports, use dedicated functions
        // For now, convert the JSON to a string representation and search
        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(rule) = item.get("rule") {
                    if rule.get("chain").and_then(|c| c.as_str()) == Some(chain) {
                        // Check if the rule JSON contains the content string
                        let rule_str = serde_json::to_string(rule).unwrap_or_default();
                        if rule_str.contains(content) {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Count rules in a specific chain
    pub fn count_rules_in_chain(
        env: &crate::common::TestEnvironment,
        table: &str,
        chain: &str,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;
        let mut count = 0;

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(rule) = item.get("rule") {
                    if rule.get("table").and_then(|t| t.as_str()) == Some(table)
                        && rule.get("chain").and_then(|c| c.as_str()) == Some(chain)
                    {
                        count += 1;
                    }
                }
            }
        }

        Ok(count)
    }

    /// Check if a jump rule exists using JSON
    pub fn jump_rule_exists(
        env: &crate::common::TestEnvironment,
        from_chain: &str,
        to_chain: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(rule) = item.get("rule") {
                    if rule.get("chain").and_then(|c| c.as_str()) == Some(from_chain) {
                        // Check if this rule has a jump to the target chain
                        if let Some(expr_array) = rule.get("expr").and_then(|e| e.as_array()) {
                            for expr in expr_array {
                                if let Some(jump) = expr.get("jump") {
                                    if jump.get("target").and_then(|t| t.as_str()) == Some(to_chain)
                                    {
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Check if a set exists
    pub fn set_exists(
        env: &crate::common::TestEnvironment,
        table: &str,
        set_name: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(set) = item.get("set") {
                    if set.get("table").and_then(|t| t.as_str()) == Some(table)
                        && set.get("name").and_then(|n| n.as_str()) == Some(set_name)
                    {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Check if a map exists
    pub fn map_exists(
        env: &crate::common::TestEnvironment,
        table: &str,
        map_name: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(map) = item.get("map") {
                    if map.get("table").and_then(|t| t.as_str()) == Some(table)
                        && map.get("name").and_then(|n| n.as_str()) == Some(map_name)
                    {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Get all chains in the harborshield table
    pub fn get_all_chains(
        env: &crate::common::TestEnvironment,
        table: &str,
    ) -> Result<HashSet<String>, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;
        let mut chains = HashSet::new();

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(chain) = item.get("chain") {
                    if chain.get("table").and_then(|t| t.as_str()) == Some(table) {
                        if let Some(name) = chain.get("name").and_then(|n| n.as_str()) {
                            chains.insert(name.to_string());
                        }
                    }
                }
            }
        }

        Ok(chains)
    }

    /// Check if port mapping rule exists using JSON
    pub fn port_rule_exists(
        env: &crate::common::TestEnvironment,
        chain: &str,
        port: u16,
        protocol: &str,
        action: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(rule) = item.get("rule") {
                    if rule.get("chain").and_then(|c| c.as_str()) == Some(chain) {
                        let mut has_port = false;
                        let mut has_protocol = false;
                        let mut has_action = false;

                        if let Some(expr_array) = rule.get("expr").and_then(|e| e.as_array()) {
                            for expr in expr_array {
                                // Check for port match
                                if let Some(match_obj) = expr.get("match") {
                                    if let (Some(left), Some(right)) =
                                        (match_obj.get("left"), match_obj.get("right"))
                                    {
                                        // Check for protocol
                                        if let (Some(proto_val), Some(proto_str)) = (
                                            left.get("payload")
                                                .and_then(|p| p.get("protocol"))
                                                .and_then(|p| p.as_str()),
                                            right.as_str(),
                                        ) {
                                            if proto_val == "ip" && proto_str == protocol {
                                                has_protocol = true;
                                            }
                                        }
                                        // Check for dport
                                        if let (Some(field), Some(port_val)) = (
                                            left.get("payload")
                                                .and_then(|p| p.get("field"))
                                                .and_then(|f| f.as_str()),
                                            right.as_u64(),
                                        ) {
                                            if field == "dport" && port_val == port as u64 {
                                                has_port = true;
                                            }
                                        }
                                    }
                                }
                                // Check for action
                                if expr.get(action).is_some()
                                    || (action == "jump" && expr.get("jump").is_some())
                                    || (action == "accept" && expr.get("accept").is_some())
                                {
                                    has_action = true;
                                }
                            }
                        }

                        if has_port && has_protocol && has_action {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Check if port mapping rule exists with any verdict (accept, queue, jump, etc.) using JSON
    pub fn port_rule_exists_any_verdict(
        env: &crate::common::TestEnvironment,
        chain: &str,
        port: u16,
        _protocol: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(rule) = item.get("rule") {
                    if rule.get("chain").and_then(|c| c.as_str()) == Some(chain) {
                        let mut has_port = false;
                        let mut has_verdict = false;

                        if let Some(expr_array) = rule.get("expr").and_then(|e| e.as_array()) {
                            for expr in expr_array {
                                // Check for port match
                                if let Some(match_obj) = expr.get("match") {
                                    if let (Some(left), Some(right)) =
                                        (match_obj.get("left"), match_obj.get("right"))
                                    {
                                        // Check for dport
                                        if let (Some(payload), Some(port_val)) =
                                            (left.get("payload"), right.as_u64())
                                        {
                                            if payload.get("field").and_then(|f| f.as_str())
                                                == Some("dport")
                                                && port_val == port as u64
                                            {
                                                has_port = true;
                                            }
                                        }
                                    }
                                }
                                // Check for any verdict
                                if expr.get("accept").is_some()
                                    || expr.get("queue").is_some()
                                    || expr.get("jump").is_some()
                                    || expr.get("drop").is_some()
                                    || expr.get("return").is_some()
                                {
                                    has_verdict = true;
                                }
                            }
                        }

                        if has_port && has_verdict {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Check if source IP restriction exists using JSON
    pub fn source_ip_rule_exists(
        env: &crate::common::TestEnvironment,
        chain: &str,
        source_ip: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(rule) = item.get("rule") {
                    if rule.get("chain").and_then(|c| c.as_str()) == Some(chain) {
                        if let Some(expr_array) = rule.get("expr").and_then(|e| e.as_array()) {
                            for expr in expr_array {
                                if let Some(match_obj) = expr.get("match") {
                                    if let (Some(left), Some(right)) =
                                        (match_obj.get("left"), match_obj.get("right"))
                                    {
                                        // Check for saddr match
                                        if let Some(payload) = left.get("payload") {
                                            if payload.get("field").and_then(|f| f.as_str())
                                                == Some("saddr")
                                            {
                                                // Handle different formats
                                                if let Some(addr) = right.as_str() {
                                                    if addr == source_ip {
                                                        return Ok(true);
                                                    }
                                                } else if let Some(prefix) = right.get("prefix") {
                                                    if prefix.get("addr").and_then(|a| a.as_str())
                                                        == Some(source_ip)
                                                        || format!(
                                                            "{}/{}",
                                                            prefix
                                                                .get("addr")
                                                                .and_then(|a| a.as_str())
                                                                .unwrap_or(""),
                                                            prefix
                                                                .get("len")
                                                                .and_then(|l| l.as_u64())
                                                                .unwrap_or(0)
                                                        ) == source_ip
                                                    {
                                                        return Ok(true);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Check if rate limit rule exists using JSON
    pub fn rate_limit_exists(
        env: &crate::common::TestEnvironment,
        chain: &str,
        rate: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Self::rule_contains(env, chain, rate)
    }

    /// Check if log rule exists using JSON
    pub fn log_rule_exists(
        env: &crate::common::TestEnvironment,
        chain: &str,
        log_prefix: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Self::rule_contains(env, chain, log_prefix)
    }

    /// Check if nfqueue rule exists using JSON
    pub fn nfqueue_rule_exists(
        env: &crate::common::TestEnvironment,
        chain: &str,
        queue_num: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(rule) = item.get("rule") {
                    if rule.get("chain").and_then(|c| c.as_str()) == Some(chain) {
                        if let Some(expr_array) = rule.get("expr").and_then(|e| e.as_array()) {
                            for expr in expr_array {
                                if let Some(queue) = expr.get("queue") {
                                    if queue.get("to").and_then(|t| t.as_u64())
                                        == Some(queue_num as u64)
                                        || queue.get("num").and_then(|n| n.as_u64())
                                            == Some(queue_num as u64)
                                    {
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Check if IP range rule exists using JSON
    pub fn ip_range_rule_exists(
        env: &crate::common::TestEnvironment,
        chain: &str,
        ip_range: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;

        // Parse the IP range to get address and prefix length
        let (addr, len) = if let Some(pos) = ip_range.find('/') {
            let addr = &ip_range[..pos];
            let len = ip_range[pos + 1..].parse::<u32>().unwrap_or(32);
            (addr, len)
        } else {
            (ip_range.as_ref(), 32)
        };

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(rule) = item.get("rule") {
                    if rule.get("chain").and_then(|c| c.as_str()) == Some(chain) {
                        if let Some(expr_array) = rule.get("expr").and_then(|e| e.as_array()) {
                            for expr in expr_array {
                                if let Some(match_obj) = expr.get("match") {
                                    if let Some(right) = match_obj.get("right") {
                                        // Check for set format (array of IPs)
                                        if let Some(set) =
                                            right.get("set").and_then(|s| s.as_array())
                                        {
                                            for item in set {
                                                // Check for range object format in set
                                                if let Some(range_arr) =
                                                    item.get("range").and_then(|r| r.as_array())
                                                {
                                                    if range_arr.len() == 2 {
                                                        if let (Some(start), Some(end)) = (
                                                            range_arr[0].as_str(),
                                                            range_arr[1].as_str(),
                                                        ) {
                                                            let range_str =
                                                                format!("{}-{}", start, end);
                                                            if range_str == ip_range {
                                                                return Ok(true);
                                                            }
                                                        }
                                                    }
                                                }
                                                // Check for prefix object format in set
                                                if let Some(prefix) = item.get("prefix") {
                                                    if prefix.get("addr").and_then(|a| a.as_str())
                                                        == Some(addr)
                                                        && prefix
                                                            .get("len")
                                                            .and_then(|l| l.as_u64())
                                                            == Some(len as u64)
                                                    {
                                                        return Ok(true);
                                                    }
                                                }
                                                // Check for direct string format in set
                                                if let Some(ip_str) = item.as_str() {
                                                    if ip_str == ip_range || ip_str == addr {
                                                        return Ok(true);
                                                    }
                                                }
                                            }
                                        }

                                        // Check for single prefix object format
                                        if let Some(prefix) = right.get("prefix") {
                                            if prefix.get("addr").and_then(|a| a.as_str())
                                                == Some(addr)
                                                && prefix.get("len").and_then(|l| l.as_u64())
                                                    == Some(len as u64)
                                            {
                                                return Ok(true);
                                            }
                                        }
                                        // Also check for direct string format
                                        if let Some(ip_str) = right.as_str() {
                                            if ip_str == ip_range {
                                                return Ok(true);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Check if verdict chain jump exists using JSON
    pub fn verdict_chain_exists(
        env: &crate::common::TestEnvironment,
        chain: &str,
        verdict_chain: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Self::jump_rule_exists(env, chain, verdict_chain)
    }

    /// Check if port range rule exists
    pub fn port_range_rule_exists(
        env: &crate::common::TestEnvironment,
        chain: &str,
        port_range: &str,
        protocol: &str,
        action: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed = env.check_nftables_rules()?;

        if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(rule) = item.get("rule") {
                    if rule.get("chain").and_then(|c| c.as_str()) == Some(chain) {
                        if let Some(expr_array) = rule.get("expr").and_then(|e| e.as_array()) {
                            let mut has_protocol = false;
                            let mut has_port_range = false;
                            let mut has_action = false;

                            for expr in expr_array {
                                // Check for protocol match
                                if let Some(match_obj) = expr.get("match") {
                                    if match_obj
                                        .get("left")
                                        .and_then(|l| l.get("payload"))
                                        .and_then(|p| p.get("protocol"))
                                        .and_then(|p| p.as_str())
                                        == Some(protocol)
                                    {
                                        has_protocol = true;
                                    }

                                    // Check for port range
                                    if let Some(left) = match_obj.get("left") {
                                        if let Some(payload) = left.get("payload") {
                                            if payload.get("field").and_then(|f| f.as_str())
                                                == Some("dport")
                                            {
                                                if let Some(right) = match_obj.get("right") {
                                                    if let Some(range) = right.get("range") {
                                                        // Handle range format
                                                        if let (Some(start), Some(end)) = (
                                                            range
                                                                .as_array()
                                                                .and_then(|a| a.get(0))
                                                                .and_then(|v| v.as_u64()),
                                                            range
                                                                .as_array()
                                                                .and_then(|a| a.get(1))
                                                                .and_then(|v| v.as_u64()),
                                                        ) {
                                                            let expected_range =
                                                                format!("{}-{}", start, end);
                                                            if expected_range == port_range {
                                                                has_port_range = true;
                                                            }
                                                        }
                                                    } else if let Some(port_val) = right.as_u64() {
                                                        // Single port
                                                        if port_range == port_val.to_string() {
                                                            has_port_range = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                // Check for action
                                if expr.get(action).is_some()
                                    || (expr
                                        .get("jump")
                                        .and_then(|j| j.get("target"))
                                        .and_then(|t| t.as_str())
                                        == Some(action))
                                {
                                    has_action = true;
                                }
                            }

                            if has_protocol && has_port_range && has_action {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Check if UDP rule exists
    pub fn udp_rule_exists(
        env: &crate::common::TestEnvironment,
        chain: &str,
        port: u16,
        action: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Self::port_rule_exists(env, chain, port, "udp", action)
    }

    /// Create assertion for chain creation with retry
    pub fn assert_chains_created(
        expected_chains: usize,
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;

                crate::common::retry_with_delay()
                    .operation(|| async {
                        // Use JSON-based check
                        match env.check_nftables_rules() {
                            Ok(parsed) => {
                                let mut chain_count = 0;
                                if let Some(nftables) =
                                    parsed.get("nftables").and_then(|n| n.as_array())
                                {
                                    for item in nftables {
                                        if let Some(chain) = item.get("chain") {
                                            if chain.get("table").and_then(|t| t.as_str())
                                                == Some("filter")
                                                && chain
                                                    .get("name")
                                                    .and_then(|n| n.as_str())
                                                    .map(|n| n.starts_with("hs-"))
                                                    .unwrap_or(false)
                                            {
                                                chain_count += 1;
                                            }
                                        }
                                    }
                                }
                                if chain_count >= expected_chains {
                                    Ok(())
                                } else {
                                    Err(format!(
                                        "Only {} chains created, waiting for {}",
                                        chain_count, expected_chains
                                    ))
                                }
                            }
                            Err(e) => Err(format!("Failed to check nftables rules: {}", e)),
                        }
                    })
                    .description("Waiting for container chains")
                    .max_attempts(10)
                    .delay_seconds(2)
                    .call()
                    .await
                    .map_err(|e| {
                        Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))
                            as Box<dyn std::error::Error + Send + Sync>
                    })?;

                Ok(())
            })
        }
    }

    /// Create assertion for individual service chains and labels
    pub fn assert_service_chains_and_labels(
        services: Vec<String>,
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;
                let containers = env.list_containers()?;

                for service_name in services {
                    // Find container by service name
                    let container = containers
                        .iter()
                        .find(|c| c.name.contains(&service_name))
                        .ok_or_else(|| format!("{} container not found", service_name))?;

                    // Check container has its chain
                    let chain_name = format!(
                        "hs-{}-{}",
                        container.name.replace(['_', '.', '/'], "-"),
                        &container.id[..12.min(container.id.len())]
                    );

                    // Check if chain exists using JSON
                    let exists = Self::chain_exists(&env, "filter", &chain_name)?;
                    if !exists {
                        return Err(
                            format!("{} chain {} not found", service_name, chain_name).into()
                        );
                    }

                    // Check harborshield.enabled label
                    if !crate::common::assertions::ContainerAssertions::has_label(
                        &containers,
                        &container.name,
                        "harborshield.enabled",
                        "true",
                    ) {
                        return Err(format!(
                            "{} should have harborshield.enabled label set to true",
                            service_name
                        )
                        .into());
                    }
                }

                Ok(())
            })
        }
    }

    /// Create assertion for nftables setup
    pub fn assert_nftables_setup() -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;

                println!("Checking for harborshield chain in filter table...");

                // Check if harborshield chain exists using JSON
                let exists = Self::chain_exists(&env, "filter", "harborshield")?;
                if !exists {
                    return Err("Harborshield chain not found in Docker filter table".into());
                }

                Ok(())
            })
        }
    }

    /// Create assertion for container rules with port checking
    pub fn assert_container_rules(
        port_rules: Vec<(String, u16)>,
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;

                // Get containers and rules
                let containers = env.list_containers()?;

                for (service_name, port) in port_rules {
                    // Find container by service name
                    let container = containers
                        .iter()
                        .find(|c| c.name.contains(&service_name))
                        .ok_or_else(|| format!("{} container not found", service_name))?;

                    // Check container has its chain
                    let chain_name = format!(
                        "hs-{}-{}",
                        container.name.replace(['_', '.', '/'], "-"),
                        &container.id[..12.min(container.id.len())]
                    );

                    // Check if chain exists using JSON
                    let exists = Self::chain_exists(&env, "filter", &chain_name)?;
                    if !exists {
                        return Err(
                            format!("{} chain {} not found", service_name, chain_name).into()
                        );
                    }

                    // Check for port rule with retry using JSON
                    let env_ref = &env;
                    let chain_name_ref = &chain_name;
                    let port_check =
                        crate::common::retry_with_delay()
                            .operation(|| async {
                                let parsed =
                                    env_ref.check_nftables_rules().map_err(|e| e.to_string())?;

                                // Look for the port rule in the JSON
                                let mut has_port_rule = false;
                                if let Some(nftables) =
                                    parsed.get("nftables").and_then(|n| n.as_array())
                                {
                                    for item in nftables {
                                        if let Some(rule) = item.get("rule") {
                                            if rule.get("chain").and_then(|c| c.as_str())
                                                == Some(chain_name_ref)
                                                && rule.get("table").and_then(|t| t.as_str())
                                                    == Some("filter")
                                            {
                                                // Check if this rule has the port
                                                if let Some(expr_array) =
                                                    rule.get("expr").and_then(|e| e.as_array())
                                                {
                                                    for expr in expr_array {
                                                        if let Some(match_obj) = expr.get("match") {
                                                            if let (Some(left), Some(right)) = (
                                                                match_obj.get("left"),
                                                                match_obj.get("right"),
                                                            ) {
                                                                // Check for dport match
                                                                if let (
                                                                    Some(payload),
                                                                    Some(port_val),
                                                                ) = (
                                                                    left.get("payload"),
                                                                    right.as_u64(),
                                                                ) {
                                                                    if payload
                                                                        .get("field")
                                                                        .and_then(|f| f.as_str())
                                                                        == Some("dport")
                                                                        && port_val == port as u64
                                                                    {
                                                                        has_port_rule = true;
                                                                        break;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if has_port_rule {
                                    Ok(())
                                } else {
                                    Err(format!(
                                        "Port {} rule not found in chain {}",
                                        port, chain_name_ref
                                    ))
                                }
                            })
                            .description(&format!(
                                "Waiting for {} port {} rule",
                                service_name, port
                            ))
                            .max_attempts(5)
                            .delay_seconds(2)
                            .call()
                            .await;

                    if let Err(e) = port_check {
                        return Err(format!(
                            "{} chain should have port {} rule: {}",
                            service_name, port, e
                        )
                        .into());
                    }
                }

                Ok(())
            })
        }
    }

    /// Create assertion for advanced rule features
    pub fn assert_advanced_rules(
        service_name: String,
        log_prefixes: Vec<(String, String)>,    // (chain, prefix)
        verdict_chains: Vec<(String, String)>,  // (from_chain, to_chain)
        nfqueues: Vec<(String, u32)>,           // (chain, queue_num)
        ip_filters: Vec<(String, Vec<String>)>, // (chain, ips)
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;
                let containers = env.list_containers()?;

                // Find container by service name
                let container = containers
                    .iter()
                    .find(|c| c.name.contains(&service_name))
                    .ok_or_else(|| format!("{} container not found", service_name))?;

                let chain_name = format!(
                    "hs-{}-{}",
                    container.name.replace(['_', '.', '/'], "-"),
                    &container.id[..12.min(container.id.len())]
                );

                // Check log prefixes
                for (chain, prefix) in log_prefixes {
                    let target_chain = if chain == "container" {
                        &chain_name
                    } else {
                        &chain
                    };

                    if !Self::log_rule_exists(&env, target_chain, &prefix)? {
                        return Err(format!(
                            "{} chain {} should have log rule with prefix '{}'",
                            service_name, target_chain, prefix
                        )
                        .into());
                    }
                }

                // Check verdict chains
                for (from_chain, to_chain) in verdict_chains {
                    let source_chain = if from_chain == "container" {
                        &chain_name
                    } else {
                        &from_chain
                    };

                    if !Self::verdict_chain_exists(&env, source_chain, &to_chain)? {
                        return Err(format!(
                            "{} chain {} should have jump to chain '{}'",
                            service_name, source_chain, to_chain
                        )
                        .into());
                    }
                }

                // Check nfqueues
                for (chain, queue_num) in nfqueues {
                    let target_chain = if chain == "container" {
                        &chain_name
                    } else {
                        &chain
                    };

                    if !Self::nfqueue_rule_exists(&env, target_chain, queue_num)? {
                        return Err(format!(
                            "{} chain {} should have nfqueue rule with num {}",
                            service_name, target_chain, queue_num
                        )
                        .into());
                    }
                }

                // Check IP filters
                for (chain, ips) in ip_filters {
                    let target_chain = if chain == "container" {
                        &chain_name
                    } else {
                        &chain
                    };

                    for ip in ips {
                        if !Self::ip_range_rule_exists(&env, target_chain, &ip)? {
                            return Err(format!(
                                "{} chain {} should have IP filter for '{}'",
                                service_name, target_chain, ip
                            )
                            .into());
                        }
                    }
                }

                Ok(())
            })
        }
    }

    /// Create assertion for cross-network rules
    pub fn assert_cross_network_rules(
        cross_network_rules: Vec<(String, String, String)>, // (service_name, network, container)
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;
                let containers = env.list_containers()?;

                eprintln!("🔍 Checking cross-network rules...");
                for (service_name, network, target_container) in cross_network_rules {
                    // Find source container by service name
                    let source_container = containers
                        .iter()
                        .find(|c| c.name.contains(&service_name))
                        .ok_or_else(|| format!("{} container not found", service_name))?;

                    // Find target container to get its IP addresses
                    let target = containers
                        .iter()
                        .find(|c| c.name.contains(&target_container))
                        .ok_or_else(|| format!("{} container not found", target_container))?;

                    let chain_name = format!(
                        "hs-{}-{}",
                        source_container.name.replace(['_', '.', '/'], "-"),
                        &source_container.id[..12.min(source_container.id.len())]
                    );

                    eprintln!(
                        "  Checking if {} can reach {} via network {}...",
                        service_name, target_container, network
                    );
                    eprintln!("    Source chain: {}", chain_name);

                    // Get all target container's IP addresses
                    let target_ips: Vec<String> = target
                        .networks
                        .values()
                        .map(|net| net.ip_address.clone())
                        .collect();

                    if target_ips.is_empty() {
                        return Err(format!("{} has no IP addresses", target_container).into());
                    }

                    eprintln!("    Target IPs: {:?}", target_ips);

                    // Check if there's a rule that allows communication to the target container's IP
                    let parsed = env.check_nftables_rules()?;
                    let mut found_rule = false;

                    if let Some(nftables) = parsed.get("nftables").and_then(|n| n.as_array()) {
                        for item in nftables {
                            if let Some(rule) = item.get("rule") {
                                if rule.get("chain").and_then(|c| c.as_str()) == Some(&chain_name) {
                                    // Check if this is an output rule
                                    if let Some(comment) =
                                        rule.get("comment").and_then(|c| c.as_str())
                                    {
                                        if comment.contains("Output rule") {
                                            // Check if the rule allows the target IP
                                            if let Some(expr_array) =
                                                rule.get("expr").and_then(|e| e.as_array())
                                            {
                                                for expr in expr_array {
                                                    if let Some(match_obj) = expr.get("match") {
                                                        if let Some(right) = match_obj.get("right")
                                                        {
                                                            // Check for direct IP match
                                                            if let Some(ip_str) = right.as_str() {
                                                                if target_ips
                                                                    .contains(&ip_str.to_string())
                                                                {
                                                                    eprintln!(
                                                                        "    ✓ Found rule allowing communication to {}",
                                                                        ip_str
                                                                    );
                                                                    found_rule = true;
                                                                    break;
                                                                }
                                                            }
                                                            // Check for IP in set
                                                            if let Some(set) = right
                                                                .get("set")
                                                                .and_then(|s| s.as_array())
                                                            {
                                                                for item in set {
                                                                    if let Some(ip_str) =
                                                                        item.as_str()
                                                                    {
                                                                        if target_ips.contains(
                                                                            &ip_str.to_string(),
                                                                        ) {
                                                                            eprintln!(
                                                                                "    ✓ Found rule allowing communication to {}",
                                                                                ip_str
                                                                            );
                                                                            found_rule = true;
                                                                            break;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                if found_rule {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !found_rule {
                        eprintln!(
                            "    ✗ No rule found allowing communication to any of {:?}",
                            target_ips
                        );
                        return Err(format!(
                            "Service {} should have rule allowing communication to {} (IPs: {:?}) on network {}",
                            service_name, target_container, target_ips, network
                        ).into());
                    }
                }

                eprintln!("✅ All cross-network rules verified");
                Ok(())
            })
        }
    }
}

/// Assertion helpers for container state
pub struct ContainerAssertions;

impl ContainerAssertions {
    /// Create a closure that checks if all containers are running
    pub fn assert_all_running(
        expected_count: usize,
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;
                let containers = env.list_containers()?;

                if containers.len() != expected_count {
                    return Err(format!(
                        "Expected {} containers, but found {}",
                        expected_count,
                        containers.len()
                    )
                    .into());
                }

                if !Self::all_running(&containers) {
                    let not_running: Vec<String> = containers
                        .iter()
                        .filter(|c| c.state != "running")
                        .map(|c| format!("{} ({})", c.name, c.state))
                        .collect();
                    return Err(format!(
                        "Not all containers are running: {}",
                        not_running.join(", ")
                    )
                    .into());
                }

                Ok(())
            })
        }
    }

    /// Check if all containers in list are running
    pub fn all_running(containers: &[crate::common::environment::Container]) -> bool {
        containers.iter().all(|c| c.state == "running")
    }

    /// Check if specific container is in expected state
    pub fn has_state(
        containers: &[crate::common::environment::Container],
        name: &str,
        state: &str,
    ) -> bool {
        containers
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.state == state)
            .unwrap_or(false)
    }

    /// Check if container has specific label
    pub fn has_label(
        containers: &[crate::common::environment::Container],
        name: &str,
        label: &str,
        value: &str,
    ) -> bool {
        containers
            .iter()
            .find(|c| c.name == name)
            .and_then(|c| c.labels.get(label))
            .map(|v| v == value)
            .unwrap_or(false)
    }

    /// Get container by name
    pub fn get_by_name<'a>(
        containers: &'a [crate::common::environment::Container],
        name: &str,
    ) -> Option<&'a crate::common::environment::Container> {
        containers.iter().find(|c| c.name == name)
    }

    /// Create assertion for container state with network checks
    pub fn assert_container_state(
        expected_containers: usize,
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;

                // List all networks for this project
                let project_name = env.project_name();
                let output = std::process::Command::new("docker")
                    .args(&[
                        "network",
                        "ls",
                        "--format",
                        "{{.Name}}",
                        "--filter",
                        &format!("name={}", project_name),
                    ])
                    .output()
                    .map_err(|e| format!("Failed to list docker networks: {}", e))?;

                if !output.status.success() {
                    return Err(format!(
                        "Failed to list docker networks: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )
                    .into());
                }

                let network_names: Vec<String> = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .filter(|line| !line.is_empty())
                    .map(|s| s.to_string())
                    .collect();

                // Check that we have at least one network
                if network_names.is_empty() {
                    return Err("No networks found for this project".into());
                }

                // Check each network has proper configuration
                for network_name in &network_names {
                    let network_info = env.get_network_info(network_name)?;
                    if network_info.id.is_empty() {
                        return Err(format!("Network {} should have ID", network_name).into());
                    }
                    if network_info.subnet.is_none() {
                        return Err(format!("Network {} should have subnet", network_name).into());
                    }
                }

                // Get container info
                let containers = env.list_containers()?;

                // Should have expected number of containers
                if containers.len() != expected_containers {
                    return Err(format!(
                        "Should have {} containers from compose, but found {}",
                        expected_containers,
                        containers.len()
                    )
                    .into());
                }

                // Check all containers are running - use retry since some containers may depend on others
                crate::common::retry_with_delay()
                    .operation(|| async {
                        let containers = env.list_containers().map_err(|e| e.to_string())?;
                        if Self::all_running(&containers) {
                            Ok(())
                        } else {
                            let not_running = containers
                                .iter()
                                .filter(|c| c.state != "running")
                                .map(|c| format!("{} ({})", c.name, c.state))
                                .collect::<Vec<_>>()
                                .join(", ");
                            Err(format!(
                                "Not all containers are running yet: {}",
                                not_running
                            ))
                        }
                    })
                    .description("Waiting for all containers to be running")
                    .max_attempts(15)
                    .delay_seconds(2)
                    .call()
                    .await
                    .map_err(|e| {
                        Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))
                            as Box<dyn std::error::Error + Send + Sync>
                    })?;

                Ok(())
            })
        }
    }
}

/// Assertion helpers for security isolation tests
pub struct SecurityAssertions;

impl SecurityAssertions {
    /// Create assertion that verifies all containers are protected from unauthorized access
    pub fn assert_isolation_from_attacker() -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;

                // Create the attacker container and network
                env.create_test_attacker()?;

                // Give harborshield time to react to the new container
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                // Test security isolation
                let results = env.test_security_isolation()?;

                // Check results
                let mut failures = Vec::new();
                for (container_name, port, connected) in results {
                    if connected {
                        failures.push(format!("{}:{}", container_name, port));
                    }
                }

                if !failures.is_empty() {
                    return Err(format!(
                        "Security isolation test failed! Attacker could reach: {}",
                        failures.join(", ")
                    )
                    .into());
                }

                eprintln!("✅ All containers are properly isolated from attacker");
                Ok(())
            })
        }
    }
}

/// Assertion helpers for connectivity tests
pub struct ConnectivityAssertions;

impl ConnectivityAssertions {
    /// Create a closure that tests connectivity between containers
    pub fn assert_connectivity(
        from_name: String,
        to_ip: String,
        port: u16,
        expected_connected: bool,
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let env = env.lock().await;
                let result = env.check_connectivity(&from_name, &to_ip, port, "tcp");

                match (result, expected_connected) {
                    (Ok(true), true) => Ok(()),   // Expected success
                    (Ok(false), false) => Ok(()), // Expected failure
                    (Ok(true), false) => Err(format!(
                        "Connection from {} to {}:{} succeeded but was expected to fail",
                        from_name, to_ip, port
                    )
                    .into()),
                    (Ok(false), true) => Err(format!(
                        "Connection from {} to {}:{} failed but was expected to succeed",
                        from_name, to_ip, port
                    )
                    .into()),
                    (Err(e), true) => Err(format!(
                        "Error testing connection from {} to {}:{} (expected success): {}",
                        from_name, to_ip, port, e
                    )
                    .into()),
                    (Err(e), false) => {
                        // Some errors indicate the connection was blocked (e.g., timeout)
                        if e.to_string().contains("timeout") || e.to_string().contains("refused") {
                            Ok(()) // This is expected for blocked connections
                        } else {
                            Err(format!(
                                "Unexpected error testing connection from {} to {}:{}: {}",
                                from_name, to_ip, port, e
                            )
                            .into())
                        }
                    }
                }
            })
        }
    }

    /// Assert that connection should succeed
    pub fn assert_connected(
        result: Result<bool, Box<dyn std::error::Error + Send + Sync>>,
        from: &str,
        to: &str,
        port: u16,
    ) {
        match result {
            Ok(true) => {} // Success
            Ok(false) => panic!(
                "Connection from {} to {}:{} failed but was expected to succeed",
                from, to, port
            ),
            Err(e) => panic!(
                "Error testing connection from {} to {}:{}: {}",
                from, to, port, e
            ),
        }
    }

    /// Assert that connection should fail
    pub fn assert_blocked(
        result: Result<bool, Box<dyn std::error::Error + Send + Sync>>,
        from: &str,
        to: &str,
        port: u16,
    ) {
        match result {
            Ok(false) => {} // Success - connection blocked
            Ok(true) => panic!(
                "Connection from {} to {}:{} succeeded but was expected to be blocked",
                from, to, port
            ),
            Err(e) => {
                // Some errors indicate the connection was blocked (e.g., timeout)
                if e.to_string().contains("timeout") || e.to_string().contains("refused") {
                    // This is expected for blocked connections
                } else {
                    panic!(
                        "Unexpected error testing connection from {} to {}:{}: {}",
                        from, to, port, e
                    );
                }
            }
        }
    }

    /// Create assertion for testing connectivity between multiple containers
    pub fn assert_connectivity_batch(
        connections: Vec<(String, String, u16)>,
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                // Collect connection info first
                let connection_info = {
                    let env = env.lock().await;
                    let containers = env.list_containers()?;

                    let mut info = Vec::new();
                    for (from_service, to_service, port) in connections {
                        let source = containers
                            .iter()
                            .find(|c| c.name.contains(&from_service))
                            .ok_or_else(|| format!("{} container not found", from_service))?;

                        let target = containers
                            .iter()
                            .find(|c| c.name.contains(&to_service))
                            .ok_or_else(|| format!("{} container not found", to_service))?;

                        if let Some(target_ip) = &target.ip_address {
                            info.push((
                                source.name.clone(),
                                target_ip.clone(),
                                port,
                                from_service,
                                to_service,
                            ));
                        }
                    }
                    info
                };

                // Test each connection
                for (source_name, target_ip, port, from_service, to_service) in connection_info {
                    let env_clone = env.clone();
                    let source_name_clone = source_name.clone();
                    let target_ip_clone = target_ip.clone();

                    let result = crate::common::retry_with_delay()
                        .operation(move || {
                            let env = env_clone.clone();
                            let source_name = source_name_clone.clone();
                            let target_ip = target_ip_clone.clone();
                            async move {
                                let env = env.lock().await;
                                match env.check_connectivity(&source_name, &target_ip, port, "tcp")
                                {
                                    Ok(true) => Ok(true),
                                    Ok(false) => Err("Connection failed".into()),
                                    Err(e) => Err(e),
                                }
                            }
                        })
                        .description(&format!("{} -> {} connectivity", from_service, to_service))
                        .max_attempts(5)
                        .delay_seconds(2)
                        .call()
                        .await;

                    Self::assert_connected(result, &source_name, &target_ip, port);
                }

                Ok(())
            })
        }
    }

    /// Like `assert_connectivity_batch`, but verifies every listed connection
    /// is *blocked* — a packet that should be dropped really is dropped.
    /// `connections` is `(from_service, to_service, port)` and resolves
    /// to_service's IP via docker inspect.
    pub fn assert_blocked_batch(
        connections: Vec<(String, String, u16)>,
    ) -> impl FnOnce(
        Arc<Mutex<crate::common::TestEnvironment>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > + Send {
        move |env: Arc<Mutex<crate::common::TestEnvironment>>| {
            Box::pin(async move {
                let connection_info = {
                    let env = env.lock().await;
                    let containers = env.list_containers()?;

                    let mut info = Vec::new();
                    for (from_service, to_service, port) in connections {
                        let source = containers
                            .iter()
                            .find(|c| c.name.contains(&from_service))
                            .ok_or_else(|| format!("{} container not found", from_service))?;
                        let target = containers
                            .iter()
                            .find(|c| c.name.contains(&to_service))
                            .ok_or_else(|| format!("{} container not found", to_service))?;
                        if let Some(target_ip) = &target.ip_address {
                            info.push((
                                source.name.clone(),
                                target_ip.clone(),
                                port,
                                from_service,
                                to_service,
                            ));
                        }
                    }
                    info
                };

                // For each blocked-path: a single attempt is enough. We don't
                // retry — the rule is either in place or it isn't, and we don't
                // want to wait 5×2s per blocked connection.
                for (source_name, target_ip, port, from_service, to_service) in connection_info {
                    let env_locked = env.lock().await;
                    let result =
                        env_locked.check_connectivity(&source_name, &target_ip, port, "tcp");
                    drop(env_locked);

                    match result {
                        Ok(false) => {} // Blocked as expected
                        Ok(true) => {
                            return Err(format!(
                                "Expected {} -> {}:{} to be BLOCKED but it succeeded",
                                from_service, to_service, port
                            )
                            .into());
                        }
                        Err(e) => {
                            // Timeouts and refused connections also count as blocked.
                            let msg = e.to_string();
                            if !(msg.contains("timeout") || msg.contains("refused")) {
                                return Err(format!(
                                    "Unexpected error testing {} -> {}:{} (expected blocked): {}",
                                    from_service, to_service, port, msg
                                )
                                .into());
                            }
                        }
                    }
                }

                Ok(())
            })
        }
    }
}
