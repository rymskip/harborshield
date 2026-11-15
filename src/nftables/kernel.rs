//! The impure boundary: reading harborshield's objects from the kernel and applying batches,
//! both through the `nft` binary with a bounded lifetime.

use std::collections::BTreeSet;
use std::process::Stdio;
use std::time::Duration;

use nftables::batch::Batch;
use nftables::schema::{NfListObject, NfObject, Nftables};
use nftables::stmt::Statement;
use nftables::types::NfFamily;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::error::{NftablesError, Result};
use super::plan::{LEGACY_CHAIN, LEGACY_TABLE};
use super::rules::{CHAIN_PREFIX, Layer, TABLE};

const NFT: &str = "nft";
const NFT_LIMIT: Duration = Duration::from_secs(30);
/// Base chains earlier versions jumped from into their chain in `ip filter`.
const LEGACY_BASE_CHAINS: [&str; 3] = ["DOCKER-USER", "INPUT", "OUTPUT"];

/// harborshield's objects as the kernel holds them right now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KernelState {
    pub routed: TableState,
    pub bridged: TableState,
    pub legacy: LegacyState,
}

impl KernelState {
    pub fn table(&self, layer: Layer) -> &TableState {
        match layer {
            Layer::Routed => &self.routed,
            Layer::Bridged => &self.bridged,
        }
    }
}

/// One of harborshield's tables.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TableState {
    pub exists: bool,
    /// Every chain in the table, harborshield's and any verdict chains users added.
    pub chains: BTreeSet<String>,
}

/// Objects versions before the dedicated table left in Docker's `ip filter` table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacyState {
    pub jumps: Vec<LegacyJump>,
    pub chains: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyJump {
    pub chain: String,
    pub handle: u32,
}

pub async fn read_state() -> Result<KernelState> {
    Ok(KernelState {
        routed: read_table(Layer::Routed).await?,
        bridged: read_table(Layer::Bridged).await?,
        legacy: read_legacy().await?,
    })
}

async fn read_table(layer: Layer) -> Result<TableState> {
    let family = match layer {
        Layer::Routed => "inet",
        Layer::Bridged => "bridge",
    };
    let Some(document) = list(&["list", "table", family, TABLE], "list harborshield table").await?
    else {
        return Ok(TableState::default());
    };
    let chains = document
        .objects
        .iter()
        .filter_map(|object| match object {
            NfObject::ListObject(NfListObject::Chain(chain)) => Some(chain.name.to_string()),
            _ => None,
        })
        .collect();
    Ok(TableState {
        exists: true,
        chains,
    })
}

async fn read_legacy() -> Result<LegacyState> {
    // Chain listings carry no rules, so Docker's iptables-nft rules never need parsing here.
    let all = list(&["list", "chains"], "list chains")
        .await?
        .unwrap_or_else(empty_document);
    let chains: Vec<String> = all
        .objects
        .iter()
        .filter_map(|object| match object {
            NfObject::ListObject(NfListObject::Chain(chain))
                if chain.family == NfFamily::IP
                    && chain.table == LEGACY_TABLE
                    && (chain.name == LEGACY_CHAIN || chain.name.starts_with(CHAIN_PREFIX)) =>
            {
                Some(chain.name.to_string())
            }
            _ => None,
        })
        .collect();

    let mut jumps = Vec::new();
    if chains.iter().any(|name| name == LEGACY_CHAIN) {
        for base in LEGACY_BASE_CHAINS {
            let Some(document) = list(
                &["list", "chain", "ip", LEGACY_TABLE, base],
                "list legacy base chain",
            )
            .await?
            else {
                continue;
            };
            for object in document.objects.iter() {
                let NfObject::ListObject(NfListObject::Rule(rule)) = object else {
                    continue;
                };
                let jumps_to_legacy = rule.expr.iter().any(|statement| {
                    matches!(statement, Statement::Jump(jump) if jump.target == LEGACY_CHAIN)
                });
                if jumps_to_legacy {
                    let handle = rule.handle.ok_or_else(|| NftablesError::MissingHandle {
                        chain: base.to_owned(),
                    })?;
                    jumps.push(LegacyJump {
                        chain: base.to_owned(),
                        handle,
                    });
                }
            }
        }
    }
    Ok(LegacyState { jumps, chains })
}

/// Apply a batch as one nft transaction.
pub async fn apply(batch: Batch<'static>) -> Result<()> {
    let document = batch.to_nftables();
    if document.objects.is_empty() {
        return Ok(());
    }
    let json = serde_json::to_vec(&document).map_err(|source| NftablesError::Json {
        operation: "encode batch",
        source,
    })?;
    tokio::time::timeout(NFT_LIMIT, run_with_input(&json))
        .await
        .map_err(|_elapsed| NftablesError::Timeout {
            operation: "apply batch",
            limit: NFT_LIMIT,
        })?
}

async fn run_with_input(input: &[u8]) -> Result<()> {
    let operation = "apply batch";
    let mut child = Command::new(NFT)
        .args(["--json", "--file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|source| NftablesError::Spawn { operation, source })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or(NftablesError::MissingPipe { operation })?;
    stdin
        .write_all(input)
        .await
        .map_err(|source| NftablesError::Io { operation, source })?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .await
        .map_err(|source| NftablesError::Io { operation, source })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(NftablesError::Failed {
            operation,
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

/// List an object, returning `None` when it does not exist.
async fn list(args: &[&str], operation: &'static str) -> Result<Option<Nftables<'static>>> {
    let output = tokio::time::timeout(
        NFT_LIMIT,
        Command::new(NFT)
            .arg("--json")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_elapsed| NftablesError::Timeout {
        operation,
        limit: NFT_LIMIT,
    })?
    .map_err(|source| NftablesError::Spawn { operation, source })?;

    if output.status.success() {
        let document = serde_json::from_slice(&output.stdout)
            .map_err(|source| NftablesError::Json { operation, source })?;
        return Ok(Some(document));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    // nft reports a missing table or chain only through this message.
    if stderr.contains("No such file or directory") {
        Ok(None)
    } else {
        Err(NftablesError::Failed {
            operation,
            status: output.status,
            stderr: stderr.trim().to_owned(),
        })
    }
}

fn empty_document() -> Nftables<'static> {
    Nftables {
        objects: Vec::new().into(),
    }
}
