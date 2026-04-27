use crate::Result;
use crate::docker::config::{Config, RuleContext, ToNftablesRule};
use crate::nftables::FILTER_TABLE;
use crate::nftables::common::helpers::family_to_string;
use bon::Builder;
use nftables::schema::{FlushObject, NfCmd};
use nftables::{
    batch::Batch,
    helper::{NftablesError, get_current_ruleset_raw},
    schema::{Chain, NfListObject, Rule},
    stmt::{Counter, Log, LogLevel, Statement},
    types::NfFamily,
};
use serde_json;
use std::borrow::Cow;
use tracing::{debug, info};

#[derive(Builder)]
/// Transaction wrapper for atomic operations
pub struct NftablesTransaction {
    #[builder(default = Batch::new())]
    pub batch: Batch<'static>,
    #[builder(default = NfFamily::IP)]
    pub family: NfFamily,
    #[builder(default = Vec::new())]
    pub deferred_drop_rules: Vec<Rule<'static>>,
}

impl NftablesTransaction {
    /// Delete an nftables object
    pub fn delete(&mut self, obj: NfListObject<'static>) {
        // Dump ruleset for the specific object being deleted
        let args = match &obj {
            NfListObject::Chain(chain) => {
                // For chains, dump the specific chain rules
                vec![
                    "list".to_string(),
                    "chain".to_string(),
                    family_to_string(&chain.family).to_string(),
                    chain.table.to_string(),
                    chain.name.to_string(),
                ]
            }
            NfListObject::Rule(rule) => {
                // For rules, dump the chain containing the rule
                vec![
                    "list".to_string(),
                    "chain".to_string(),
                    family_to_string(&rule.family).to_string(),
                    rule.table.to_string(),
                    rule.chain.to_string(),
                ]
            }
            NfListObject::Table(table) => {
                // For tables, dump the entire table
                vec![
                    "list".to_string(),
                    "table".to_string(),
                    family_to_string(&table.family).to_string(),
                    table.name.to_string(),
                ]
            }
            _ => {
                // For other objects, just dump the full ruleset
                vec!["list".to_string(), "ruleset".to_string()]
            }
        };

        match get_current_ruleset_raw::<String, String, _>(None, &args) {
            Ok(ruleset) => {
                debug!(
                    "Ruleset dump for item being deleted - {:#?}:\n{:#?}",
                    obj, ruleset
                );
            }
            Err(e) => {
                debug!("Failed to get ruleset dump before deletion: {:#?}", e);
            }
        }

        self.batch.delete(obj);
    }

    /// Flush a chain
    pub fn flush_chain(&mut self, table: &str, chain: &str) {
        // To flush a chain, we delete it and recreate it
        self.batch.add_cmd(NfCmd::Flush(FlushObject::Chain(Chain {
            family: self.family,
            table: Cow::Owned(table.to_string()),
            name: Cow::Owned(chain.to_string()),
            newname: None,
            handle: None,
            _type: None,
            hook: None,
            prio: None,
            dev: None,
            policy: None,
        })));
    }

    /// Commit the transaction
    pub async fn commit(mut self) -> Result<()> {
        info!(
            "Committing nftables transaction with {} deferred DROP rules",
            self.deferred_drop_rules.len()
        );

        // Add all deferred DROP rules at the end
        for drop_rule in self.deferred_drop_rules {
            tracing::debug!("Adding deferred DROP rule for chain: {}", drop_rule.chain);
            self.batch.add(NfListObject::Rule(drop_rule));
        }

        let nftables_obj = self.batch.to_nftables();
        match serde_json::to_string_pretty(&nftables_obj) {
            Ok(json) => tracing::debug!("NFTables JSON to apply: {:#?}", json),
            Err(e) => tracing::error!("Failed to serialize nftables object: {:#?}", e),
        }

        // Use apply_and_return_ruleset for better error details
        match nftables::helper::apply_and_return_ruleset(&nftables_obj) {
            Ok(_ruleset) => {
                // Log success
                tracing::debug!("Successfully applied nftables transaction");
                Ok(())
            }
            Err(e) => {
                // Get more detailed error information
                let error_msg = match &e {
                    NftablesError::NftFailed {
                        program,
                        hint,
                        stdout,
                        stderr,
                    } => {
                        format!(
                            "nft command failed - program: {:?}, hint: {}, stdout: '{}', stderr: '{}'",
                            program, hint, stdout, stderr
                        )
                    }
                    _ => format!("Failed to apply nftables transaction: {:?}", e),
                };

                tracing::error!("{}", error_msg);

                // Check if this is a "chain doesn't exist" error during deletion
                if error_msg.contains("No such file or directory")
                    || error_msg.contains("does not exist")
                {
                    // Log this as a warning instead of an error for cleanup operations
                    tracing::warn!(
                        "Ignoring deletion error (object may not exist): {}",
                        error_msg
                    );
                    // For now, we'll still return an error, but we could make this configurable
                }

                Err(crate::Error::Config {
                    message: error_msg,
                    location: "nftables".to_string(),
                    suggestion: Some("Check nftables permissions and syntax".to_string()),
                })
            }
        }
    }

    /// Remove container chain and vmap rules
    pub fn remove_container_rules(
        &mut self,
        container_id: &str,
        container_name: &str,
    ) -> Result<()> {
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );

        // Delete container chain
        self.delete(NfListObject::Chain(Chain {
            family: self.family,
            table: Cow::Borrowed(FILTER_TABLE),
            name: Cow::Owned(chain_name),
            newname: None,
            handle: None,
            _type: None,
            hook: None,
            prio: None,
            dev: None,
            policy: None,
        }));

        // Note: vmap rules will be removed when we re-create them with updated IPs

        Ok(())
    }

    /// Add container chain to a transaction
    pub fn add_container_chain_to_transaction(
        family: NfFamily,
        transaction: &mut NftablesTransaction,
        container_id: &str,
        container_name: &str,
    ) -> Result<String> {
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );

        transaction.batch.add(NfListObject::Chain(Chain {
            family: family,
            table: Cow::Borrowed(FILTER_TABLE),
            name: Cow::Owned(chain_name.clone()),
            newname: None,
            handle: None,
            _type: None,
            hook: None,
            prio: None,
            dev: None,
            policy: None,
        }));

        Ok(chain_name)
    }

    /// Add DROP rule to a transaction
    pub fn add_container_drop_rule_to_transaction(
        family: NfFamily,
        transaction: &mut NftablesTransaction,
        container_id: &str,
        container_name: &str,
    ) -> Result<()> {
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );

        let drop_rule = Rule {
            family: family,
            table: Cow::Borrowed(FILTER_TABLE),
            chain: Cow::Owned(chain_name.clone()),
            expr: Cow::Owned(vec![
                Statement::Counter(Counter::Anonymous(None)),
                Statement::Log(Some(Log {
                    prefix: Some(Cow::Owned(format!("{} DROP: ", chain_name))),
                    level: Some(LogLevel::Info),
                    flags: None,
                    group: None,
                    queue_threshold: None,
                    snaplen: None,
                })),
                Statement::Drop(None),
            ]),
            handle: None,
            index: None,
            comment: Some(Cow::Owned(format!(
                "Default DROP for container {}",
                container_name
            ))),
        };

        transaction.deferred_drop_rules.push(drop_rule);

        Ok(())
    }

    /// Add container rules to a transaction (this method remains for compatibility but now delegates to config-based method)
    pub fn add_container_rules_to_transaction(
        family: NfFamily,
        transaction: &mut NftablesTransaction,
        container_id: &str,
        container_name: &str,
        container_ips: &[std::net::IpAddr],
        container_ports: &[(u16, String)],
        config: &Config,
    ) -> Result<()> {
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );

        let ctx = RuleContext {
            container_id,
            container_name,
            container_ips,
            container_ports,
            chain_name: &chain_name,
            table_name: FILTER_TABLE,
            family: family,
        };

        // Add mapped port rules - create individual rules for each container port
        if config.mapped_ports.localhost.allow || config.mapped_ports.external.allow {
            tracing::debug!(
                "Creating mapped port rules for container {}: ports={:?}",
                container_name,
                container_ports
            );

            // Group ports by protocol
            let mut tcp_ports = Vec::new();
            let mut udp_ports = Vec::new();

            for (port, protocol) in container_ports {
                match protocol.as_str() {
                    "tcp" => tcp_ports.push(*port),
                    "udp" => udp_ports.push(*port),
                    _ => {} // Ignore other protocols for now
                }
            }

            // Create localhost rules for each port
            if config.mapped_ports.localhost.allow {
                tracing::debug!("Creating localhost rules for TCP ports: {:?}", tcp_ports);
                for port in &tcp_ports {
                    let mut statements = Vec::new();

                    // Match source IP as localhost
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_src_ip(
                            "127.0.0.1",
                        ),
                    );

                    // Match protocol and destination port
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_protocol(
                            "tcp",
                        ),
                    );
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_dst_port(
                            "tcp", *port,
                        ),
                    );

                    // Add counter
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::counter_statement(),
                    );

                    // Add log if configured
                    if !config.mapped_ports.localhost.log_prefix.is_empty() {
                        statements.push(
                            <crate::docker::config::LocalRules as ToNftablesRule>::log_statement(
                                Some(&config.mapped_ports.localhost.log_prefix),
                            ),
                        );
                    }

                    // Add verdict
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::verdict_to_statement(
                            &config.mapped_ports.localhost.verdict,
                        ),
                    );

                    let rule = Rule {
                        family: ctx.family,
                        table: Cow::Owned(ctx.table_name.to_string()),
                        chain: Cow::Owned(ctx.chain_name.to_string()),
                        expr: Cow::Owned(statements),
                        handle: None,
                        index: None,
                        comment: Some(Cow::Owned(format!(
                            "Localhost access to port {} for {}",
                            port, container_name
                        ))),
                    };

                    transaction.batch.add(NfListObject::Rule(rule));
                }

                for port in &udp_ports {
                    let mut statements = Vec::new();

                    // Match source IP as localhost
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_src_ip(
                            "127.0.0.1",
                        ),
                    );

                    // Match protocol and destination port
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_protocol(
                            "udp",
                        ),
                    );
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_dst_port(
                            "udp", *port,
                        ),
                    );

                    // Add counter
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::counter_statement(),
                    );

                    // Add log if configured
                    if !config.mapped_ports.localhost.log_prefix.is_empty() {
                        statements.push(
                            <crate::docker::config::LocalRules as ToNftablesRule>::log_statement(
                                Some(&config.mapped_ports.localhost.log_prefix),
                            ),
                        );
                    }

                    // Add verdict
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::verdict_to_statement(
                            &config.mapped_ports.localhost.verdict,
                        ),
                    );

                    let rule = Rule {
                        family: ctx.family,
                        table: Cow::Owned(ctx.table_name.to_string()),
                        chain: Cow::Owned(ctx.chain_name.to_string()),
                        expr: Cow::Owned(statements),
                        handle: None,
                        index: None,
                        comment: Some(Cow::Owned(format!(
                            "Localhost access to UDP port {} for {}",
                            port, container_name
                        ))),
                    };

                    transaction.batch.add(NfListObject::Rule(rule));
                }
            }

            // Create external rules for each port
            if config.mapped_ports.external.allow {
                for port in &tcp_ports {
                    let mut statements = Vec::new();

                    // Match source IPs if specified
                    if !config.mapped_ports.external.ips.is_empty() {
                        // For simplicity, handle the first IP only for now
                        if let Some(first_ip) = config.mapped_ports.external.ips.first() {
                            match first_ip {
                                crate::docker::config::AddrOrRange::Addr(ip) => {
                                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::match_src_ip(&ip.to_string()));
                                }
                                crate::docker::config::AddrOrRange::Net(net) => {
                                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::match_src_ip(&net.to_string()));
                                }
                                _ => {} // Handle ranges later
                            }
                        }
                    }

                    // Match protocol and destination port
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_protocol(
                            "tcp",
                        ),
                    );
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_dst_port(
                            "tcp", *port,
                        ),
                    );

                    // Add counter
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::counter_statement(),
                    );

                    // Add log if configured
                    if !config.mapped_ports.external.log_prefix.is_empty() {
                        statements.push(
                            <crate::docker::config::ExternalRules as ToNftablesRule>::log_statement(
                                Some(&config.mapped_ports.external.log_prefix),
                            ),
                        );
                    }

                    // Add verdict
                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::verdict_to_statement(&config.mapped_ports.external.verdict));

                    let rule = Rule {
                        family: ctx.family,
                        table: Cow::Owned(ctx.table_name.to_string()),
                        chain: Cow::Owned(ctx.chain_name.to_string()),
                        expr: Cow::Owned(statements),
                        handle: None,
                        index: None,
                        comment: Some(Cow::Owned(format!(
                            "External access to port {} for {}",
                            port, container_name
                        ))),
                    };

                    transaction.batch.add(NfListObject::Rule(rule));
                }

                for port in &udp_ports {
                    let mut statements = Vec::new();

                    // Match source IPs if specified
                    if !config.mapped_ports.external.ips.is_empty() {
                        // For simplicity, handle the first IP only for now
                        if let Some(first_ip) = config.mapped_ports.external.ips.first() {
                            match first_ip {
                                crate::docker::config::AddrOrRange::Addr(ip) => {
                                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::match_src_ip(&ip.to_string()));
                                }
                                crate::docker::config::AddrOrRange::Net(net) => {
                                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::match_src_ip(&net.to_string()));
                                }
                                _ => {} // Handle ranges later
                            }
                        }
                    }

                    // Match protocol and destination port
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_protocol(
                            "udp",
                        ),
                    );
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_dst_port(
                            "udp", *port,
                        ),
                    );

                    // Add counter
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::counter_statement(),
                    );

                    // Add log if configured
                    if !config.mapped_ports.external.log_prefix.is_empty() {
                        statements.push(
                            <crate::docker::config::ExternalRules as ToNftablesRule>::log_statement(
                                Some(&config.mapped_ports.external.log_prefix),
                            ),
                        );
                    }

                    // Add verdict
                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::verdict_to_statement(&config.mapped_ports.external.verdict));

                    let rule = Rule {
                        family: ctx.family,
                        table: Cow::Owned(ctx.table_name.to_string()),
                        chain: Cow::Owned(ctx.chain_name.to_string()),
                        expr: Cow::Owned(statements),
                        handle: None,
                        index: None,
                        comment: Some(Cow::Owned(format!(
                            "External access to UDP port {} for {}",
                            port, container_name
                        ))),
                    };

                    transaction.batch.add(NfListObject::Rule(rule));
                }
            }
        }

        // Add output rules
        for (i, output_rule) in config.output.iter().enumerate() {
            if !output_rule.skip {
                let rule = output_rule.to_nftables_rule(
                    &ctx,
                    Some(format!("Output rule {} for {}", i + 1, container_name)),
                )?;
                transaction.batch.add(NfListObject::Rule(rule));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_chain_name_basic() {
        let container_id = "abc123def456789";
        let container_name = "my-container";
        let expected = "hs-my-container-abc123def456";

        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );
        assert_eq!(chain_name, expected);
    }

    #[test]
    fn test_container_chain_name_sanitization_underscore() {
        let container_id = "abc123def456789";
        let container_name = "my_container";
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );
        assert_eq!(chain_name, "hs-my-container-abc123def456");
    }

    #[test]
    fn test_container_chain_name_sanitization_dot() {
        let container_id = "abc123def456789";
        let container_name = "my.container";
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );
        assert_eq!(chain_name, "hs-my-container-abc123def456");
    }

    #[test]
    fn test_container_chain_name_sanitization_slash() {
        let container_id = "abc123def456789";
        let container_name = "my/container";
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );
        assert_eq!(chain_name, "hs-my-container-abc123def456");
    }

    #[test]
    fn test_container_chain_name_id_truncation() {
        let container_id = "abc123def456789extra";
        let container_name = "test";
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );
        // ID should be truncated to 12 chars
        assert!(chain_name.ends_with("abc123def456"));
        assert!(!chain_name.contains("extra"));
    }

    #[test]
    fn test_container_chain_name_short_id() {
        let container_id = "abc";
        let container_name = "test";
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );
        // Short ID should be used as-is
        assert_eq!(chain_name, "hs-test-abc");
    }

    #[test]
    fn test_transaction_builder_default() {
        let transaction = NftablesTransaction::builder().build();
        assert_eq!(transaction.family, NfFamily::IP);
        assert!(transaction.deferred_drop_rules.is_empty());
    }

    #[test]
    fn test_transaction_builder_with_family() {
        let transaction = NftablesTransaction::builder()
            .family(NfFamily::IP6)
            .build();
        assert_eq!(transaction.family, NfFamily::IP6);
    }

    #[test]
    fn test_flush_chain_adds_command() {
        let mut transaction = NftablesTransaction::builder().build();
        transaction.flush_chain("filter", "test-chain");
        // The batch should now contain a flush command
        // We can't easily inspect the batch, but we can verify no panic occurred
    }

    use crate::docker::config::{Config, LocalRules, MappedPorts};
    use nftables::schema::{NfCmd, NfObject};
    use std::net::{IpAddr, Ipv4Addr};

    fn count_chain_adds(tx: &NftablesTransaction, expected_chain: &str) -> usize {
        let nft = tx.batch.clone().to_nftables();
        nft.objects
            .iter()
            .filter(|o| matches!(
                o,
                NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(c))) if c.name == expected_chain
            ))
            .count()
    }

    fn count_rule_adds_in_chain(tx: &NftablesTransaction, chain: &str) -> usize {
        let nft = tx.batch.clone().to_nftables();
        nft.objects
            .iter()
            .filter(|o| matches!(
                o,
                NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r))) if r.chain == chain
            ))
            .count()
    }

    #[test]
    fn chain_name_sanitizes_special_chars_and_truncates_id() {
        // Underscores, dots, slashes in container names get replaced with `-`,
        // and only the first 12 chars of the id are kept.
        let mut tx = NftablesTransaction::builder().build();
        let chain = NftablesTransaction::add_container_chain_to_transaction(
            NfFamily::IP,
            &mut tx,
            "abcdef0123456789deadbeef",
            "my_app.svc/web",
        )
        .unwrap();

        assert_eq!(chain, "hs-my-app-svc-web-abcdef012345");
        assert_eq!(count_chain_adds(&tx, &chain), 1);
    }

    #[test]
    fn chain_name_for_short_id_does_not_panic() {
        // A 4-char id should not trigger an out-of-bounds slice.
        let mut tx = NftablesTransaction::builder().build();
        let chain = NftablesTransaction::add_container_chain_to_transaction(
            NfFamily::IP,
            &mut tx,
            "abcd",
            "x",
        )
        .unwrap();
        assert_eq!(chain, "hs-x-abcd");
    }

    #[test]
    fn drop_rule_is_deferred_with_counter_log_drop_and_correct_chain() {
        let mut tx = NftablesTransaction::builder().build();
        NftablesTransaction::add_container_drop_rule_to_transaction(
            NfFamily::IP,
            &mut tx,
            "deadbeefcafebabe",
            "svc",
        )
        .unwrap();

        // Drop rules are deferred so they end up at the bottom of the chain at commit time.
        assert_eq!(tx.batch.clone().to_nftables().objects.len(), 0);
        assert_eq!(tx.deferred_drop_rules.len(), 1);

        let rule = &tx.deferred_drop_rules[0];
        assert_eq!(rule.chain, "hs-svc-deadbeefcafe");

        // Statement order: counter, log, drop (matches the audit-trail policy).
        let kinds: Vec<&str> = rule
            .expr
            .iter()
            .map(|s| match s {
                Statement::Counter(_) => "counter",
                Statement::Log(_) => "log",
                Statement::Drop(_) => "drop",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, vec!["counter", "log", "drop"]);

        // Log prefix should mention the chain so operators can grep dmesg by container.
        if let Statement::Log(Some(log)) = &rule.expr[1] {
            let prefix = log.prefix.as_ref().unwrap();
            assert!(prefix.contains("hs-svc-deadbeefcafe"));
        } else {
            panic!("expected Log statement at index 1");
        }
    }

    #[test]
    fn mapped_ports_localhost_allow_emits_one_rule_per_tcp_port() {
        let mut tx = NftablesTransaction::builder().build();
        let cfg = Config::builder()
            .mapped_ports(
                MappedPorts::builder()
                    .localhost(LocalRules::builder().allow(true).build())
                    .build(),
            )
            .build();

        NftablesTransaction::add_container_rules_to_transaction(
            NfFamily::IP,
            &mut tx,
            "deadbeefcafebabe",
            "svc",
            &[IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2))],
            &[(80, "tcp".to_string()), (443, "tcp".to_string())],
            &cfg,
        )
        .unwrap();

        let chain = "hs-svc-deadbeefcafe";
        assert_eq!(count_rule_adds_in_chain(&tx, chain), 2);
    }

    #[test]
    fn mapped_ports_disabled_emits_no_rules() {
        let mut tx = NftablesTransaction::builder().build();
        // Default Config has mapped_ports.localhost.allow = false and external.allow = false.
        let cfg = Config::builder().build();

        NftablesTransaction::add_container_rules_to_transaction(
            NfFamily::IP,
            &mut tx,
            "deadbeefcafebabe",
            "svc",
            &[IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2))],
            &[(80, "tcp".to_string())],
            &cfg,
        )
        .unwrap();

        assert_eq!(count_rule_adds_in_chain(&tx, "hs-svc-deadbeefcafe"), 0);
    }

    #[test]
    fn flush_chain_adds_flush_command() {
        let mut tx = NftablesTransaction::builder().build();
        tx.flush_chain("filter", "hs-svc-abcdef012345");

        let nft = tx.batch.clone().to_nftables();
        let flush_count = nft
            .objects
            .iter()
            .filter(|o| matches!(o, NfObject::CmdObject(NfCmd::Flush(_))))
            .count();
        assert_eq!(flush_count, 1);
    }
}
