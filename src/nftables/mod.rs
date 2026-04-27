//! Nftables integration: rule generation and kernel application.
//!
//! ## Pure vs. impure
//!
//! [`transaction::RuleSet`] is the pure value type — it accumulates batch
//! operations and deferred drop rules without touching the kernel. Build,
//! mutate, and snapshot `RuleSet`s freely.
//!
//! [`NftablesClient`] is the impure boundary. Functions here that mutate
//! kernel state ([`NftablesClient::apply`], [`NftablesClient::clear_table`],
//! [`NftablesClient::init_base_chains`],
//! [`NftablesClient::update_container_verdict_maps`],
//! [`NftablesClient::rebuild_container_chain`]) shell out to `nft` or invoke
//! [`nftables::helper::apply_and_return_ruleset`] under the hood.
//!
//! Rule-construction helpers on `RuleSet` (e.g.
//! [`transaction::RuleSet::add_container_chain_to_transaction`],
//! [`transaction::RuleSet::add_container_rules_to_transaction`]) are pure;
//! call them, then commit the resulting `RuleSet` once.
mod common;
pub mod docker;
pub mod error;
pub mod transaction;

use crate::{
    Error, Result,
    docker::config::{Config, RuleContext, ToNftablesRule},
    nftables::{
        docker::{
            check_docker_chains, check_harborshield_chain_exists, check_jump_rules_exist,
            create_harborshield_chain, create_jump_rules,
        },
        transaction::RuleSet,
    },
};
use bon::Builder;
use common::helpers;
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, SetItem, Verdict},
    helper::NftablesError,
    schema::{Chain, FlushObject, NfCmd, NfListObject, Rule},
    stmt::{Counter, JumpTarget, Log, LogLevel, Match, Operator, Queue, Statement, VerdictMap},
    types::NfFamily,
};
use std::borrow::Cow;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

// Constants for Docker filter table integration
pub const FILTER_TABLE: &str = "filter";
pub const DOCKER_USER_CHAIN: &str = "DOCKER-USER";
pub const INPUT_CHAIN: &str = "INPUT";
pub const OUTPUT_CHAIN: &str = "OUTPUT";
pub const HARBORSHIELD_CHAIN: &str = "harborshield";

#[derive(Builder)]
/// Nftables client that integrates with Docker's filter table
pub struct NftablesClient {
    #[builder(default = Arc::new(Mutex::new(Batch::new())))]
    batch: Arc<Mutex<Batch<'static>>>,
    #[builder(default = NfFamily::IP)]
    pub family: NfFamily,
}

impl NftablesClient {
    /// Clear the harborshield chain (flush rules)
    pub async fn clear_table(&mut self) -> Result<()> {
        info!("Clearing harborshield chain rules");

        // First, clear all Harborshield container chains
        self.clear_all_container_chains()
            .await
            .map_err(|e| Error::Nftables {
                message: format!("Failed to clear container chains: {}", e),
                command: None,
                exit_code: None,
                stderr: None,
            })?;

        let mut batch = self.batch.lock().await;

        // Flush the harborshield chain by deleting and recreating it
        batch.delete(NfListObject::Chain(Chain {
            family: self.family,
            table: Cow::Borrowed(FILTER_TABLE),
            name: Cow::Borrowed(HARBORSHIELD_CHAIN),
            newname: None,
            handle: None,
            _type: None,
            hook: None,
            prio: None,
            dev: None,
            policy: None,
        }));

        // Recreate empty chain
        batch.add(NfListObject::Chain(Chain {
            family: self.family,
            table: Cow::Borrowed(FILTER_TABLE),
            name: Cow::Borrowed(HARBORSHIELD_CHAIN),
            newname: None,
            handle: None,
            _type: None,
            hook: None,
            prio: None,
            dev: None,
            policy: None,
        }));

        drop(batch);
        self.apply().await.map_err(|e| Error::Nftables {
            message: format!("Failed to apply table clear: {}", e),
            command: Some("nft flush chain".to_string()),
            exit_code: None,
            stderr: None,
        })?;
        Ok(())
    }

    /// Clear all Harborshield container chains from the filter table
    async fn clear_all_container_chains(&self) -> Result<()> {
        debug!("Clearing all Harborshield container chains");

        // Get a list of all chains in the filter table
        let list_output = std::process::Command::new("nft")
            .args(&["list", "table", "ip", FILTER_TABLE, "-j"])
            .output()
            .map_err(|e| Error::Nftables {
                message: format!("Failed to list filter table: {}", e),
                command: Some("nft list table ip filter -j".to_string()),
                exit_code: None,
                stderr: Some(e.to_string()),
            })?;

        if !list_output.status.success() {
            debug!(
                "Failed to list filter table: {}",
                String::from_utf8_lossy(&list_output.stderr)
            );
            return Ok(()); // Don't fail if we can't list
        }

        let output_str = String::from_utf8_lossy(&list_output.stdout);

        // Parse JSON to find all chains starting with "hs-"
        if let Some(json) = serde_json::from_str::<serde_json::Value>(&output_str).ok() {
            json.get("nftables")
                .and_then(|n| n.as_array())
                .into_iter()
                .flatten()
                .filter_map(|item| item.get("chain"))
                .filter_map(|chain| chain.get("name").and_then(|n| n.as_str()))
                .filter(|name| name.starts_with("hs-"))
                .for_each(|name| {
                    // Flush and delete the chain
                    let _ = std::process::Command::new("nft")
                        .args(&["flush", "chain", "ip", FILTER_TABLE, name])
                        .output();

                    let _ = std::process::Command::new("nft")
                        .args(&["delete", "chain", "ip", FILTER_TABLE, name])
                        .output();

                    debug!("Deleted chain {}", name);
                });
        }

        Ok(())
    }

    /// Initialize base rules in Docker's filter table
    pub async fn init_base_chains(&mut self) -> Result<()> {
        // Check what chains exist in the filter table
        let (has_filter, has_docker_user, has_input, has_output) =
            check_docker_chains().await.map_err(|e| Error::Nftables {
                message: format!("Failed to check Docker chains: {}", e),
                command: Some("nft list tables".to_string()),
                exit_code: None,
                stderr: None,
            })?;

        if !has_filter {
            return Err(Error::Config {
                message: "Docker filter table not found".to_string(),
                location: "init_base_chains".to_string(),
                suggestion: Some(
                    "Ensure Docker is running and using nftables. You may need to:\n\
                    1. Start Docker service: sudo systemctl start docker\n\
                    2. Check if Docker is using nftables: sudo iptables -V\n\
                    3. If using iptables-legacy, switch to nftables:\n\
                       - sudo update-alternatives --set iptables /usr/sbin/iptables-nft\n\
                       - sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-nft\n\
                    4. Restart Docker after switching: sudo systemctl restart docker"
                        .to_string(),
                ),
            });
        }

        if !has_docker_user {
            warn!(
                "DOCKER-USER chain not found. Harborshield will create jump rules from INPUT/OUTPUT chains only. \
                Docker's built-in firewall rules may take precedence over Harborshield rules."
            );
        }

        let mut batch = self.batch.lock().await;

        // Check if harborshield chain already exists
        let harborshield_exists =
            check_harborshield_chain_exists()
                .await
                .map_err(|e| Error::Nftables {
                    message: format!("Failed to check harborshield chain existence: {}", e),
                    command: Some("nft list chain ip filter harborshield".to_string()),
                    exit_code: None,
                    stderr: None,
                })?;

        if !harborshield_exists {
            // Create harborshield chain in filter table
            create_harborshield_chain(&mut batch, self.family);
        }

        // Check which jump rules already exist
        let (docker_jump_exists, input_jump_exists, output_jump_exists) = check_jump_rules_exist()
            .await
            .map_err(|e| Error::Nftables {
                message: format!("Failed to check jump rules: {}", e),
                command: Some("nft list table ip filter".to_string()),
                exit_code: None,
                stderr: None,
            })?;

        // Create jump rules only if they don't exist
        if !docker_jump_exists || !input_jump_exists || !output_jump_exists {
            create_jump_rules(
                &mut batch,
                self.family,
                has_docker_user && !docker_jump_exists,
                has_input && !input_jump_exists,
                has_output && !output_jump_exists,
            );
        }

        // We no longer need to create a named set - we use inline verdict maps

        // Apply the batch
        let json =
            serde_json::to_string(&batch.clone().to_nftables()).map_err(|e| Error::Json(e))?;
        drop(batch); // Release the lock

        // Execute nft command
        let mut child = std::process::Command::new("nft")
            .args(&["-j", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Nftables {
                message: format!("Failed to spawn nft process: {}", e),
                command: Some("nft -j -f -".to_string()),
                exit_code: None,
                stderr: Some(e.to_string()),
            })?;

        // Write to stdin
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().ok_or_else(|| Error::Nftables {
                message: "Failed to get stdin handle".to_string(),
                command: Some("nft -j -f -".to_string()),
                exit_code: None,
                stderr: None,
            })?;

            stdin
                .write_all(json.as_bytes())
                .map_err(|e| Error::Nftables {
                    message: format!("Failed to write to nft stdin: {}", e),
                    command: Some("nft -j -f -".to_string()),
                    exit_code: None,
                    stderr: Some(e.to_string()),
                })?;
        } // stdin is dropped here, closing the pipe

        // Wait for output
        let output = child.wait_with_output().map_err(|e| Error::Nftables {
            message: format!("Failed to read nft output: {}", e),
            command: Some("nft -j -f -".to_string()),
            exit_code: None,
            stderr: Some(e.to_string()),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Check if the error is about objects already existing
            if stderr.contains("File exists") {
                debug!("Some nftables objects already exist, continuing...");
            } else {
                return Err(Error::Config {
                    message: format!("Failed to initialize Docker integration: {}", stderr),
                    location: "init_base_chains".to_string(),
                    suggestion: Some(
                        "Check nftables permissions and Docker installation".to_string(),
                    ),
                });
            }
        }

        Ok(())
    }

    /// Create container-specific chain
    pub async fn create_container_chain(
        &mut self,
        container_id: &str,
        container_name: &str,
    ) -> Result<String> {
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );

        // Check if chain already exists
        match helpers::find_chain(FILTER_TABLE, &chain_name) {
            Ok(Some(_existing_chain)) => {
                debug!(
                    "Container chain {} already exists, skipping creation",
                    chain_name
                );
                return Ok(chain_name);
            }
            Ok(None) => {
                // Chain doesn't exist, continue with creation
            }
            Err(e) => {
                // If the error is because chain doesn't exist, that's fine - we'll create it
                // The find_chain function will fail if the chain doesn't exist
                // This is expected for new containers
                debug!(
                    "Chain {} does not exist yet ({}), will create it",
                    chain_name, e
                );
                // Chain doesn't exist, continue with creation
            }
        }

        // Add chain to the current batch instead of creating a new one
        let mut batch = self.batch.lock().await;

        // Single container chain (matching Go implementation)
        batch.add(NfListObject::Chain(Chain {
            family: self.family,
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

        debug!("Added container chain {} to batch", chain_name);

        Ok(chain_name)
    }

    /// Update verdict map rules with current container mappings
    pub async fn update_container_verdict_maps(
        &mut self,
        container_mappings: &[(String, String, Vec<String>)], // (container_id, container_name, ips)
    ) -> Result<()> {
        debug!(
            "Updating verdict maps for {} containers",
            container_mappings.len()
        );

        // If no mappings, nothing to do
        if container_mappings.is_empty() {
            return Ok(());
        }

        let mut batch = self.batch.lock().await;

        if let Some(harborshield_chain) = helpers::find_chain(FILTER_TABLE, HARBORSHIELD_CHAIN)? {
            batch.add_cmd(NfCmd::Flush(FlushObject::Chain(
                harborshield_chain.to_owned(),
            )));
        }

        // Build set items for all containers
        let mut set_items = Vec::new();
        for (container_id, container_name, ips) in container_mappings {
            let chain_name = format!(
                "hs-{}-{}",
                container_name.replace(['_', '.', '/'], "-"),
                &container_id[..12.min(container_id.len())]
            );

            for ip in ips {
                set_items.push(SetItem::Mapping(
                    Expression::String(Cow::Owned(ip.clone())),
                    Expression::Verdict(Verdict::Jump(JumpTarget {
                        target: Cow::Owned(chain_name.clone()),
                    })),
                ));
            }
        }

        if !set_items.is_empty() {
            // Create the verdict map expression using a proper set
            let map_expr = Expression::Named(NamedExpression::Set(set_items));

            // Create source IP lookup rule
            let src_rule = Rule {
                family: self.family,
                table: Cow::Borrowed(FILTER_TABLE),
                chain: Cow::Borrowed(HARBORSHIELD_CHAIN),
                expr: Cow::Owned(vec![Statement::VerdictMap(VerdictMap {
                    key: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("ip"),
                            field: Cow::Borrowed("saddr"),
                        },
                    ))),
                    data: map_expr.clone(),
                })]),
                handle: None,
                index: None,
                comment: Some(Cow::Borrowed("Container source IP verdict map")),
            };

            // Create destination IP lookup rule
            let dst_rule = Rule {
                family: self.family,
                table: Cow::Borrowed(FILTER_TABLE),
                chain: Cow::Borrowed(HARBORSHIELD_CHAIN),
                expr: Cow::Owned(vec![Statement::VerdictMap(VerdictMap {
                    key: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("ip"),
                            field: Cow::Borrowed("daddr"),
                        },
                    ))),
                    data: map_expr,
                })]),
                handle: None,
                index: None,
                comment: Some(Cow::Borrowed("Container destination IP verdict map")),
            };

            batch.add(NfListObject::Rule(src_rule));
            batch.add(NfListObject::Rule(dst_rule));
        }

        // Apply the batch
        let json =
            serde_json::to_string(&batch.clone().to_nftables()).map_err(|e| Error::Json(e))?;
        drop(batch);

        let mut child = std::process::Command::new("nft")
            .args(&["-j", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Nftables {
                message: format!("Failed to spawn nft process: {}", e),
                command: Some("nft -j -f -".to_string()),
                exit_code: None,
                stderr: Some(e.to_string()),
            })?;

        // Write to stdin
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().ok_or_else(|| Error::Nftables {
                message: "Failed to get stdin handle".to_string(),
                command: Some("nft -j -f -".to_string()),
                exit_code: None,
                stderr: None,
            })?;

            stdin
                .write_all(json.as_bytes())
                .map_err(|e| Error::Nftables {
                    message: format!("Failed to write to nft stdin: {}", e),
                    command: Some("nft -j -f -".to_string()),
                    exit_code: None,
                    stderr: Some(e.to_string()),
                })?;
        } // stdin is dropped here, closing the pipe

        // Wait for output
        let output = child.wait_with_output().map_err(|e| Error::Nftables {
            message: format!("Failed to update verdict map rules: {}", e),
            command: Some("nft -j -f -".to_string()),
            exit_code: None,
            stderr: Some(e.to_string()),
        })?;

        if !output.status.success() {
            return Err(Error::Config {
                message: format!(
                    "Failed to update verdict map rules: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
                location: "update_container_verdict_maps".to_string(),
                suggestion: Some("Check nftables syntax".to_string()),
            });
        }

        self.reset().await.map_err(|e| Error::Nftables {
            message: format!("Failed to reset nftables batch: {}", e),
            command: None,
            exit_code: None,
            stderr: None,
        })?;

        debug!(
            "Updated verdict maps for {} containers",
            container_mappings.len()
        );
        Ok(())
    }

    /// Delete a container chain
    pub async fn delete_container_chain(
        &mut self,
        container_id: &str,
        container_name: &str,
    ) -> Result<()> {
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );

        let mut batch = self.batch.lock().await;

        batch.delete(NfListObject::Chain(Chain {
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

        Ok(())
    }

    /// Rebuild container chain with config.
    ///
    /// Flush + re-add are batched into a single nftables transaction so the
    /// chain never appears empty to the kernel — this is atomic relative to
    /// in-flight packets.
    pub async fn rebuild_container_chain(
        &mut self,
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

        // Build one batch: flush + new rules. nft commits atomically.
        let mut transaction = RuleSet::builder().family(self.family).build();
        transaction.flush_chain(FILTER_TABLE, &chain_name);

        // Add rules from config
        RuleSet::add_container_rules_to_transaction(
            self.family,
            &mut transaction,
            container_id,
            container_name,
            container_ips,
            container_ports,
            config,
        )
        .map_err(|e| Error::Nftables {
            message: format!("Failed to add container rules to transaction: {}", e),
            command: None,
            exit_code: None,
            stderr: None,
        })?;

        // IMPORTANT: Add DROP rule at the end
        RuleSet::add_container_drop_rule_to_transaction(
            self.family,
            &mut transaction,
            container_id,
            container_name,
        )
        .map_err(|e| Error::Nftables {
            message: format!("Failed to add container rules to transaction: {}", e),
            command: None,
            exit_code: None,
            stderr: None,
        })?;

        // Commit the transaction
        transaction.commit().await.map_err(|e| Error::Nftables {
            message: format!("Failed to commit nftables transaction: {}", e),
            command: Some("nft -j -f -".to_string()),
            exit_code: None,
            stderr: None,
        })?;

        debug!(
            "Rebuilt container chain {} with all rules in correct order",
            chain_name
        );

        Ok(())
    }

    /// Disable container rules (delete chain) for a transaction
    pub fn disable_container_rules(
        &mut self,
        transaction: &mut RuleSet,
        container_id: &str,
        container_name: &str,
    ) -> Result<()> {
        // Flush the container chain to remove all rules
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );

        transaction.flush_chain(FILTER_TABLE, &chain_name);

        debug!(
            "Disabled rules for container {} ({})",
            container_name, container_id
        );
        Ok(())
    }

    /// Apply all pending changes
    pub async fn apply(&mut self) -> Result<()> {
        info!("Applying nftables ruleset");
        let batch = self.batch.lock().await;
        let nftables = batch.clone().to_nftables();

        // Debug log the JSON being sent to nftables
        if let Ok(json) = serde_json::to_string_pretty(&nftables) {
            debug!("Applying nftables JSON: {}", json);
        }

        drop(batch);

        match nftables::helper::apply_and_return_ruleset(&nftables) {
            Ok(_) => {
                // Reset the batch after successful application
                self.reset().await.map_err(|e| Error::Nftables {
                    message: format!("Failed to reset nftables batch: {}", e),
                    command: None,
                    exit_code: None,
                    stderr: None,
                })?;
                Ok(())
            }
            Err(e) => {
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
                    _ => format!("Failed to apply nftables rules: {:?}", e),
                };

                tracing::error!("NFTables error: {}", error_msg);

                Err(crate::Error::Config {
                    message: error_msg,
                    location: "nftables".to_string(),
                    suggestion: Some("Check nftables permissions and syntax".to_string()),
                })
            }
        }
    }

    /// Reset the batch for new operations
    pub async fn reset(&mut self) -> Result<()> {
        let mut batch = self.batch.lock().await;
        *batch = Batch::new();
        Ok(())
    }

    /// Add rules from a Config directly (new direct translation)
    pub async fn add_rules_from_config(
        &mut self,
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
            family: self.family,
        };

        let mut batch = self.batch.lock().await;

        // Add mapped port rules
        if config.mapped_ports.localhost.allow {
            debug!(
                "Creating localhost rules for container {} with ports: {:?}",
                container_name, container_ports
            );
            // Create a rule for each container port
            for (port, protocol) in container_ports {
                debug!(
                    "Creating localhost rule for container {} port {} protocol {}",
                    container_name, port, protocol
                );
                let mut statements = Vec::new();

                // Match source IP as localhost
                statements.push(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed("ip"),
                            field: Cow::Borrowed("saddr"),
                        },
                    ))),
                    right: Expression::String(Cow::Borrowed("127.0.0.1")),
                    op: Operator::EQ,
                }));

                // Match protocol
                statements.push(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::L4proto,
                    })),
                    right: Expression::Number(match protocol.to_lowercase().as_str() {
                        "tcp" => 6,
                        "udp" => 17,
                        _ => 6,
                    }),
                    op: Operator::EQ,
                }));

                // Match destination port
                statements.push(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Owned(protocol.clone()),
                            field: Cow::Borrowed("dport"),
                        },
                    ))),
                    right: Expression::Number(*port as u32),
                    op: Operator::EQ,
                }));

                // Add counter
                statements.push(Statement::Counter(Counter::Anonymous(None)));

                // Add log if configured
                if !config.mapped_ports.localhost.log_prefix.is_empty() {
                    statements.push(Statement::Log(Some(Log {
                        prefix: Some(Cow::Owned(config.mapped_ports.localhost.log_prefix.clone())),
                        group: None,
                        snaplen: None,
                        queue_threshold: None,
                        level: Some(LogLevel::Info),
                        flags: None,
                    })));
                }

                // Add verdict
                let verdict = if !config.mapped_ports.localhost.verdict.chain.is_empty() {
                    debug!(
                        "Using jump verdict to chain: {}",
                        config.mapped_ports.localhost.verdict.chain
                    );
                    Statement::Jump(JumpTarget {
                        target: Cow::Owned(config.mapped_ports.localhost.verdict.chain.clone()),
                    })
                } else if config.mapped_ports.localhost.verdict.queue > 0 {
                    debug!(
                        "Using queue verdict with num: {}",
                        config.mapped_ports.localhost.verdict.queue
                    );
                    Statement::Queue(Queue {
                        num: Expression::Number(config.mapped_ports.localhost.verdict.queue as u32),
                        flags: None,
                    })
                } else {
                    debug!("Using accept verdict");
                    Statement::Accept(None)
                };
                statements.push(verdict);

                let rule = Rule {
                    family: ctx.family,
                    table: Cow::Owned(ctx.table_name.to_string()),
                    chain: Cow::Owned(ctx.chain_name.to_string()),
                    expr: Cow::Owned(statements),
                    handle: None,
                    index: None,
                    comment: Some(Cow::Owned(format!(
                        "Allow {} port {} from localhost for {}",
                        protocol, port, container_name
                    ))),
                };

                debug!(
                    "Adding localhost rule to batch for container {} chain {}",
                    container_name, ctx.chain_name
                );
                batch.add(NfListObject::Rule(rule));
            }
        }

        if config.mapped_ports.external.allow {
            // Create a rule for each container port
            for (port, protocol) in container_ports {
                let mut statements = Vec::new();

                // Only add NOT localhost check if no specific IPs are configured
                if config.mapped_ports.external.ips.is_empty() {
                    // Match NOT localhost (external traffic)
                    statements.push(Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: Cow::Borrowed("ip"),
                                field: Cow::Borrowed("saddr"),
                            },
                        ))),
                        right: Expression::String(Cow::Borrowed("127.0.0.1")),
                        op: Operator::NEQ,
                    }));
                }

                // Match protocol
                statements.push(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::L4proto,
                    })),
                    right: Expression::Number(match protocol.to_lowercase().as_str() {
                        "tcp" => 6,
                        "udp" => 17,
                        _ => 6,
                    }),
                    op: Operator::EQ,
                }));

                // Match destination port
                statements.push(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Owned(protocol.clone()),
                            field: Cow::Borrowed("dport"),
                        },
                    ))),
                    right: Expression::Number(*port as u32),
                    op: Operator::EQ,
                }));

                // Add source IP filtering if configured
                if !config.mapped_ports.external.ips.is_empty() {
                    // Create a set expression for multiple IPs/ranges
                    let mut set_items = Vec::new();
                    for addr_range in &config.mapped_ports.external.ips {
                        match addr_range {
                            crate::docker::config::AddrOrRange::Addr(ip) => {
                                set_items.push(SetItem::Element(Expression::String(Cow::Owned(
                                    ip.to_string(),
                                ))));
                            }
                            crate::docker::config::AddrOrRange::Range(start, end) => {
                                set_items.push(SetItem::Element(Expression::Range(Box::new(
                                    nftables::expr::Range {
                                        range: [
                                            Expression::String(Cow::Owned(start.to_string())),
                                            Expression::String(Cow::Owned(end.to_string())),
                                        ],
                                    },
                                ))));
                            }
                            crate::docker::config::AddrOrRange::Net(net) => {
                                // For CIDR networks, use the Prefix expression type
                                set_items.push(SetItem::Element(Expression::Named(
                                    NamedExpression::Prefix(nftables::expr::Prefix {
                                        addr: Box::new(Expression::String(Cow::Owned(
                                            net.addr().to_string(),
                                        ))),
                                        len: net.prefix_len() as u32,
                                    }),
                                )));
                            }
                        }
                    }

                    // If we have only one IP/range, use direct match
                    if set_items.len() == 1 {
                        if let SetItem::Element(expr) = &set_items[0] {
                            statements.push(Statement::Match(Match {
                                left: Expression::Named(NamedExpression::Payload(
                                    Payload::PayloadField(PayloadField {
                                        protocol: Cow::Borrowed("ip"),
                                        field: Cow::Borrowed("saddr"),
                                    }),
                                )),
                                right: expr.clone(),
                                op: Operator::EQ,
                            }));
                        }
                    } else if set_items.len() > 1 {
                        // For multiple IPs, use a set match
                        statements.push(Statement::Match(Match {
                            left: Expression::Named(NamedExpression::Payload(
                                Payload::PayloadField(PayloadField {
                                    protocol: Cow::Borrowed("ip"),
                                    field: Cow::Borrowed("saddr"),
                                }),
                            )),
                            right: Expression::Named(NamedExpression::Set(set_items)),
                            op: Operator::EQ,
                        }));
                    }
                }

                // Add counter
                statements.push(Statement::Counter(Counter::Anonymous(None)));

                // Add log if configured
                if !config.mapped_ports.external.log_prefix.is_empty() {
                    statements.push(Statement::Log(Some(Log {
                        prefix: Some(Cow::Owned(config.mapped_ports.external.log_prefix.clone())),
                        group: None,
                        snaplen: None,
                        queue_threshold: None,
                        level: Some(LogLevel::Info),
                        flags: None,
                    })));
                }

                // Add verdict
                let verdict = if !config.mapped_ports.external.verdict.chain.is_empty() {
                    Statement::Jump(JumpTarget {
                        target: Cow::Owned(config.mapped_ports.external.verdict.chain.clone()),
                    })
                } else if config.mapped_ports.external.verdict.queue > 0 {
                    Statement::Queue(Queue {
                        num: Expression::Number(config.mapped_ports.external.verdict.queue as u32),
                        flags: None,
                    })
                } else {
                    Statement::Accept(None)
                };
                statements.push(verdict);

                let rule = Rule {
                    family: ctx.family,
                    table: Cow::Owned(ctx.table_name.to_string()),
                    chain: Cow::Owned(ctx.chain_name.to_string()),
                    expr: Cow::Owned(statements),
                    handle: None,
                    index: None,
                    comment: Some(Cow::Owned(format!(
                        "Allow {} port {} from external for {}",
                        protocol, port, container_name
                    ))),
                };

                batch.add(NfListObject::Rule(rule));
            }
        }

        // Add output rules
        for (i, output_rule) in config.output.iter().enumerate() {
            if !output_rule.skip {
                let rule = output_rule
                    .to_nftables_rule(
                        &ctx,
                        Some(format!("Output rule {} for {}", i + 1, container_name)),
                    )
                    .map_err(|e| Error::Nftables {
                        message: format!("Failed to add container rules to transaction: {}", e),
                        command: None,
                        exit_code: None,
                        stderr: None,
                    })?;
                batch.add(NfListObject::Rule(rule));
            }
        }

        debug!(
            "Finished adding rules to batch for container {}. Localhost rules: {}, External rules: {}, Output rules: {}",
            container_name,
            if config.mapped_ports.localhost.allow {
                container_ports.len()
            } else {
                0
            },
            if config.mapped_ports.external.allow {
                container_ports.len()
            } else {
                0
            },
            config.output.iter().filter(|r| !r.skip).count()
        );

        Ok(())
    }
}

// Re-export minimal types needed by other modules
pub use nftables::schema::NfListObject as NftObject;
