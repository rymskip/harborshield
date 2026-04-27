use crate::{
    Error, Result,
    nftables::{DOCKER_USER_CHAIN, FILTER_TABLE, HARBORSHIELD_CHAIN, INPUT_CHAIN, OUTPUT_CHAIN},
};
use nftables::{
    batch::Batch,
    schema::{Chain, NfCmd, NfListObject, Rule},
    stmt::{Counter, JumpTarget, Statement},
    types::{NfChainType, NfFamily},
};
use serde_json;
use std::borrow::Cow;
use tracing::{debug, info, warn};

/// Check if Docker filter table and chains exist
/// Returns: (has_filter_table, has_docker_user_chain, has_input_chain, has_output_chain)
pub async fn check_docker_chains() -> Result<(bool, bool, bool, bool)> {
    let output = std::process::Command::new("nft")
        .args(&["-j", "list", "tables"])
        .output()
        .map_err(|e| Error::Config {
            message: format!("Failed to list nftables tables: {}", e),
            location: "check_docker_chains".to_string(),
            suggestion: Some("Ensure nftables is installed".to_string()),
        })?;

    if !output.status.success() {
        return Err(Error::Config {
            message: "Failed to list nftables tables".to_string(),
            location: "check_docker_chains".to_string(),
            suggestion: Some("Check nftables permissions".to_string()),
        });
    }

    let json_str = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check for filter table
    let has_filter_table = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
        if let Some(nftables) = json.get("nftables").and_then(|n| n.as_array()) {
            nftables.iter().any(|item| {
                if let Some(table) = item.get("table") {
                    table.get("family").and_then(|f| f.as_str()) == Some("ip")
                        && table.get("name").and_then(|n| n.as_str()) == Some("filter")
                } else {
                    false
                }
            })
        } else {
            false
        }
    } else {
        false
    };

    if !has_filter_table {
        debug!("Docker filter table not found");
        return Ok((false, false, false, false));
    }

    // Check for specific chains
    let output = std::process::Command::new("nft")
        .args(&["-j", "list", "chains", "ip", "filter"])
        .output()
        .map_err(|e| Error::Config {
            message: format!("Failed to list filter chains: {}", e),
            location: "check_docker_chains".to_string(),
            suggestion: Some("Ensure nftables is installed".to_string()),
        })?;

    if !output.status.success() {
        return Ok((true, false, false, false));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check for chains
    let (has_docker_user, has_input, has_output) =
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
            if let Some(nftables) = json.get("nftables").and_then(|n| n.as_array()) {
                let mut docker_user = false;
                let mut input = false;
                let mut output = false;

                for item in nftables {
                    if let Some(chain) = item.get("chain") {
                        if let Some(name) = chain.get("name").and_then(|n| n.as_str()) {
                            match name {
                                DOCKER_USER_CHAIN => docker_user = true,
                                INPUT_CHAIN => input = true,
                                OUTPUT_CHAIN => output = true,
                                _ => {}
                            }
                        }
                    }
                }

                (docker_user, input, output)
            } else {
                (false, false, false)
            }
        } else {
            (false, false, false)
        };

    if !has_docker_user {
        warn!("DOCKER-USER chain not found - Docker may not be running or not using nftables");
    }

    debug!(
        "Docker chains check - filter: true, DOCKER-USER: {}, INPUT: {}, OUTPUT: {}",
        has_docker_user, has_input, has_output
    );

    Ok((true, has_docker_user, has_input, has_output))
}

/// Create harborshield chain in filter table
pub fn create_harborshield_chain(batch: &mut Batch<'static>, family: NfFamily) {
    debug!("Creating harborshield chain in filter table");

    batch.add(NfListObject::Chain(Chain {
        family,
        table: Cow::Borrowed(FILTER_TABLE),
        name: Cow::Borrowed(HARBORSHIELD_CHAIN),
        newname: None,
        handle: None,
        _type: Some(NfChainType::Filter),
        hook: None,
        prio: None,
        dev: None,
        policy: None,
    }));
}

/// Create jump rules from Docker chains to harborshield chain
pub fn create_jump_rules(
    batch: &mut Batch<'static>,
    family: NfFamily,
    has_docker_user: bool,
    has_input: bool,
    has_output: bool,
) {
    // Helper function to create a jump rule
    let create_jump_rule = |chain_name: String| -> Rule {
        Rule {
            family,
            table: Cow::Borrowed(FILTER_TABLE),
            chain: Cow::Owned(chain_name),
            expr: Cow::Owned(vec![
                Statement::Counter(Counter::Anonymous(None)),
                Statement::Jump(JumpTarget {
                    target: Cow::Borrowed(HARBORSHIELD_CHAIN),
                }),
            ]),
            handle: None,
            index: None,
            comment: Some(Cow::Borrowed("Jump to harborshield chain")),
        }
    };

    // Always try to add jump from DOCKER-USER if it exists
    if has_docker_user {
        info!("Adding jump rule from DOCKER-USER to harborshield chain");
        // Insert at the beginning of the chain
        batch.add_cmd(NfCmd::Insert(NfListObject::Rule(create_jump_rule(
            DOCKER_USER_CHAIN.to_owned(),
        ))));
    } else {
        warn!("DOCKER-USER chain not found, Docker may not be running");
    }

    // Add jump from INPUT chain if it exists
    if has_input {
        debug!("Adding jump rule from INPUT to harborshield chain");
        // Insert at the beginning of the chain
        batch.add_cmd(NfCmd::Insert(NfListObject::Rule(create_jump_rule(
            INPUT_CHAIN.to_owned(),
        ))));
    }

    // Add jump from OUTPUT chain if it exists
    if has_output {
        debug!("Adding jump rule from OUTPUT to harborshield chain");
        // Insert at the beginning of the chain
        batch.add_cmd(NfCmd::Insert(NfListObject::Rule(create_jump_rule(
            OUTPUT_CHAIN.to_owned(),
        ))));
    }
}

/// Check if harborshield chain already exists in filter table
pub async fn check_harborshield_chain_exists() -> Result<bool> {
    let output = std::process::Command::new("nft")
        .args(&["-j", "list", "chains", "ip", "filter"])
        .output()
        .map_err(|e| Error::Config {
            message: format!("Failed to list filter chains: {}", e),
            location: "check_harborshield_chain_exists".to_string(),
            suggestion: Some("Ensure nftables is installed".to_string()),
        })?;

    if !output.status.success() {
        // If we can't list chains, assume it doesn't exist
        return Ok(false);
    }

    let json_output = String::from_utf8_lossy(&output.stdout);
    Ok(json_output.contains(&format!(r#""name":"{}""#, HARBORSHIELD_CHAIN)))
}

/// Check if jump rules already exist
pub async fn check_jump_rules_exist() -> Result<(bool, bool, bool)> {
    let output = std::process::Command::new("nft")
        .args(&["-j", "list", "table", "ip", "filter"])
        .output()
        .map_err(|e| Error::Config {
            message: format!("Failed to list filter table: {}", e),
            location: "check_jump_rules_exist".to_string(),
            suggestion: Some("Ensure nftables is installed".to_string()),
        })?;

    if !output.status.success() {
        return Ok((false, false, false));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check for jump rules more accurately
    let mut docker_user_jump = false;
    let mut input_jump = false;
    let mut output_jump = false;

    // Check if the JSON contains rules with jump to harborshield in each chain
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
        if let Some(nftables) = json.get("nftables").and_then(|n| n.as_array()) {
            for item in nftables {
                if let Some(rule) = item.get("rule") {
                    if let (Some(chain), Some(expr)) = (rule.get("chain"), rule.get("expr")) {
                        let chain_name = chain.as_str().unwrap_or("");

                        // Check if this rule has a jump to harborshield
                        if let Some(expr_array) = expr.as_array() {
                            for expr_item in expr_array {
                                if let Some(jump) = expr_item.get("jump") {
                                    if let Some(target) = jump.get("target") {
                                        if target.as_str() == Some(HARBORSHIELD_CHAIN) {
                                            match chain_name {
                                                DOCKER_USER_CHAIN => docker_user_jump = true,
                                                INPUT_CHAIN => input_jump = true,
                                                OUTPUT_CHAIN => output_jump = true,
                                                _ => {}
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

    debug!(
        "Jump rules exist - DOCKER-USER: {}, INPUT: {}, OUTPUT: {}",
        docker_user_jump, input_jump, output_jump
    );

    Ok((docker_user_jump, input_jump, output_jump))
}

/// Validate that Docker environment is properly configured for Harborshield
pub async fn validate_docker_environment() -> Result<()> {
    let (has_filter, has_docker_user, _, _) = check_docker_chains().await?;

    if !has_filter {
        return Err(Error::Config {
            message: "Docker is not properly configured".to_string(),
            location: "validate_docker_environment".to_string(),
            suggestion: Some(
                "Docker must be installed and running with nftables/iptables support. \
                Start Docker and ensure it creates its firewall rules."
                    .to_string(),
            ),
        });
    }

    if !has_docker_user {
        warn!(
            "DOCKER-USER chain not found. This may indicate:\n\
            1. Docker is using iptables-legacy instead of nftables\n\
            2. Docker's iptables integration is disabled\n\
            3. Docker version is too old (requires Docker 17.06+)\n\
            Harborshield will continue but rules may not work as expected."
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nftables::batch::Batch;
    use nftables::schema::{NfCmd, NfObject};
    use nftables::types::NfFamily;

    fn count_inserts_into(nft: &nftables::schema::Nftables, expected_chain: &str) -> usize {
        nft.objects
            .iter()
            .filter(|o| matches!(
                o,
                NfObject::CmdObject(NfCmd::Insert(NfListObject::Rule(r))) if r.chain == expected_chain
            ))
            .count()
    }

    #[test]
    fn create_harborshield_chain_adds_filter_typed_chain() {
        let mut batch: Batch<'static> = Batch::new();
        create_harborshield_chain(&mut batch, NfFamily::IP);

        let nft = batch.to_nftables();
        let mut chains = nft
            .objects
            .iter()
            .filter_map(|o| match o {
                NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(c))) => Some(c),
                _ => None,
            });
        let chain = chains.next().expect("chain should be added");
        assert_eq!(chain.name, HARBORSHIELD_CHAIN);
        assert_eq!(chain.table, FILTER_TABLE);
        // _type should be set to Filter; verify via JSON shape since the enum is non-pub.
        let chain_json = serde_json::to_value(chain).unwrap();
        assert_eq!(chain_json["type"], "filter");
        assert!(chains.next().is_none(), "exactly one chain expected");
    }

    #[test]
    fn create_jump_rules_skips_missing_chains() {
        // Only DOCKER-USER present -> exactly one Insert into DOCKER-USER, none elsewhere.
        let mut batch: Batch<'static> = Batch::new();
        create_jump_rules(&mut batch, NfFamily::IP, true, false, false);

        let nft = batch.to_nftables();
        assert_eq!(count_inserts_into(&nft, DOCKER_USER_CHAIN), 1);
        assert_eq!(count_inserts_into(&nft, INPUT_CHAIN), 0);
        assert_eq!(count_inserts_into(&nft, OUTPUT_CHAIN), 0);
    }

    #[test]
    fn create_jump_rules_emits_one_per_present_chain() {
        let mut batch: Batch<'static> = Batch::new();
        create_jump_rules(&mut batch, NfFamily::IP, true, true, true);

        let nft = batch.to_nftables();
        assert_eq!(count_inserts_into(&nft, DOCKER_USER_CHAIN), 1);
        assert_eq!(count_inserts_into(&nft, INPUT_CHAIN), 1);
        assert_eq!(count_inserts_into(&nft, OUTPUT_CHAIN), 1);
    }

    #[test]
    fn create_jump_rules_targets_harborshield_chain() {
        let mut batch: Batch<'static> = Batch::new();
        create_jump_rules(&mut batch, NfFamily::IP, true, false, false);

        let nft = batch.to_nftables();
        let rule = nft
            .objects
            .iter()
            .find_map(|o| match o {
                NfObject::CmdObject(NfCmd::Insert(NfListObject::Rule(r))) => Some(r),
                _ => None,
            })
            .expect("jump rule should be inserted");

        // Statement order: counter then jump-to-harborshield.
        assert!(matches!(rule.expr[0], Statement::Counter(_)));
        match &rule.expr[1] {
            Statement::Jump(target) => assert_eq!(target.target, HARBORSHIELD_CHAIN),
            _ => panic!("expected Jump statement at index 1"),
        }
    }

    #[test]
    fn create_jump_rules_with_no_chains_emits_nothing() {
        let mut batch: Batch<'static> = Batch::new();
        create_jump_rules(&mut batch, NfFamily::IP, false, false, false);
        let nft = batch.to_nftables();
        assert_eq!(nft.objects.len(), 0);
    }
}
