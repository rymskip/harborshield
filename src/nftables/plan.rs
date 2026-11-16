//! Pure planning: from the kernel's current state and the desired containers to one nft batch.
//!
//! A batch is applied as a single transaction, so a reconcile never exposes a moment where a
//! managed container is unprotected or a chain is deleted while still referenced.

use std::borrow::Cow;
use std::collections::BTreeSet;

use nftables::batch::Batch;
use nftables::schema::{Chain, FlushObject, NfCmd, NfListObject, Rule, Table};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily};

use super::kernel::{KernelState, LegacyState, TableState};
use super::rules::{
    CHAIN_PREFIX, Layer, ManagedContainer, TABLE, Verdict, container_rules, dispatch_rules,
};

/// Where versions before the dedicated tables put their objects.
pub const LEGACY_TABLE: &str = "filter";
pub const LEGACY_CHAIN: &str = "harborshield";

/// Replace harborshield's whole ruleset, in both layers, with the one `containers` call for.
pub fn reconcile(kernel: &KernelState, containers: &[ManagedContainer]) -> Batch<'static> {
    let mut batch = Batch::new();
    remove_legacy(&mut batch, &kernel.legacy);
    for layer in Layer::ALL {
        reconcile_layer(&mut batch, layer, kernel.table(layer), containers);
    }
    batch
}

fn reconcile_layer(
    batch: &mut Batch<'static>,
    layer: Layer,
    table_state: &TableState,
    containers: &[ManagedContainer],
) {
    let containers: Vec<ManagedContainer> = containers
        .iter()
        .map(|container| without_missing_jumps(layer, container, &table_state.chains))
        .collect();

    batch.add(NfListObject::Table(table(layer)));
    for (name, hook) in layer.base_chains() {
        batch.add(NfListObject::Chain(Chain {
            family: layer.family(),
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(name),
            _type: Some(NfChainType::Filter),
            hook: Some(*hook),
            prio: Some(0),
            policy: Some(NfChainPolicy::Accept),
            ..Chain::default()
        }));
        batch.add_cmd(NfCmd::Flush(FlushObject::Chain(chain(layer, name))));
    }

    let mut desired = BTreeSet::new();
    for container in &containers {
        let name = container.chain();
        batch.add(NfListObject::Chain(chain(layer, &name)));
        batch.add_cmd(NfCmd::Flush(FlushObject::Chain(chain(layer, &name))));
        for rule in container_rules(layer, container) {
            batch.add(NfListObject::Rule(rule));
        }
        desired.insert(name);
    }

    for (name, _) in layer.base_chains() {
        for rule in dispatch_rules(layer, name, &containers) {
            batch.add(NfListObject::Rule(rule));
        }
    }

    // The base chains no longer reference these, so they can go in the same transaction.
    for orphan in table_state
        .chains
        .iter()
        .filter(|name| name.starts_with(CHAIN_PREFIX) && !desired.contains(*name))
    {
        batch.add_cmd(NfCmd::Flush(FlushObject::Chain(chain(layer, orphan))));
        batch.delete(NfListObject::Chain(chain(layer, orphan)));
    }
}

/// A jump to a chain that does not exist fails the whole transaction, so such a grant is left
/// out: that one rule fails closed and every other container still gets its update.
fn without_missing_jumps(
    layer: Layer,
    container: &ManagedContainer,
    chains: &BTreeSet<String>,
) -> ManagedContainer {
    let usable = |verdict: &Verdict, what: &str| match verdict {
        Verdict::Jump(target) if !chains.contains(target) => {
            tracing::warn!(
                container = %container.name,
                %target,
                ?layer,
                "{what} jumps to a chain missing from harborshield's table; the rule is left out there",
            );
            false
        }
        Verdict::Accept | Verdict::Jump(_) | Verdict::Queue { .. } => true,
    };
    let mut usable_container = container.clone();
    usable_container.localhost = container
        .localhost
        .clone()
        .filter(|local| usable(&local.verdict, "mapped_ports.localhost"));
    usable_container.external = container
        .external
        .clone()
        .filter(|external| usable(&external.verdict, "mapped_ports.external"));
    usable_container
        .outputs
        .retain(|output| usable(&output.verdict, "an output rule"));
    usable_container
}

/// Remove everything harborshield owns, current and legacy.
pub fn clear(kernel: &KernelState) -> Batch<'static> {
    let mut batch = Batch::new();
    remove_legacy(&mut batch, &kernel.legacy);
    for layer in Layer::ALL {
        if kernel.table(layer).exists {
            batch.delete(NfListObject::Table(table(layer)));
        }
    }
    batch
}

fn remove_legacy(batch: &mut Batch<'static>, legacy: &LegacyState) {
    for jump in &legacy.jumps {
        batch.delete(NfListObject::Rule(Rule {
            family: NfFamily::IP,
            table: Cow::Borrowed(LEGACY_TABLE),
            chain: Cow::Owned(jump.chain.clone()),
            handle: Some(jump.handle),
            ..Rule::default()
        }));
    }
    // Flush everything first: the base chain's verdict maps reference the container chains.
    for name in &legacy.chains {
        batch.add_cmd(NfCmd::Flush(FlushObject::Chain(legacy_chain(name))));
    }
    for name in &legacy.chains {
        batch.delete(NfListObject::Chain(legacy_chain(name)));
    }
}

fn table(layer: Layer) -> Table<'static> {
    Table {
        family: layer.family(),
        name: Cow::Borrowed(TABLE),
        handle: None,
    }
}

fn chain(layer: Layer, name: &str) -> Chain<'static> {
    Chain {
        family: layer.family(),
        table: Cow::Borrowed(TABLE),
        name: Cow::Owned(name.to_owned()),
        ..Chain::default()
    }
}

fn legacy_chain(name: &str) -> Chain<'static> {
    Chain {
        family: NfFamily::IP,
        table: Cow::Borrowed(LEGACY_TABLE),
        name: Cow::Owned(name.to_owned()),
        ..Chain::default()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use nftables::batch::Batch;
    use nftables::schema::{NfCmd, NfListObject, NfObject, Nftables};
    use nftables::types::{NfChainPolicy, NfChainType, NfFamily};

    use super::{LEGACY_CHAIN, clear, reconcile};
    use crate::docker::config::{Protocol, RulePorts};
    use crate::nftables::kernel::{KernelState, LegacyJump, LegacyState, TableState};
    use crate::nftables::rules::{
        Layer, ManagedContainer, OutputRule, Peers, TABLE, Verdict, chain_name,
    };

    fn container(id: &str, name: &str, last_octet: u8) -> ManagedContainer {
        ManagedContainer {
            id: id.to_owned(),
            name: name.to_owned(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(172, 18, 0, last_octet))],
            gateways: Vec::new(),
            published: Vec::new(),
            localhost: None,
            external: None,
            outputs: Vec::new(),
        }
    }

    fn commands(batch: Batch<'static>) -> Vec<NfCmd<'static>> {
        let Nftables { objects } = batch.to_nftables();
        objects
            .iter()
            .filter_map(|object| match object {
                NfObject::CmdObject(command) => Some(command.clone()),
                NfObject::ListObject(_) => None,
            })
            .collect()
    }

    fn deleted_chains(commands: &[NfCmd<'static>], family: NfFamily) -> Vec<String> {
        commands
            .iter()
            .filter_map(|command| match command {
                NfCmd::Delete(NfListObject::Chain(chain)) if chain.family == family => {
                    Some(chain.name.to_string())
                }
                _ => None,
            })
            .collect()
    }

    fn added_chains(commands: &[NfCmd<'static>], family: NfFamily) -> Vec<String> {
        commands
            .iter()
            .filter_map(|command| match command {
                NfCmd::Add(NfListObject::Chain(chain)) if chain.family == family => {
                    Some(chain.name.to_string())
                }
                _ => None,
            })
            .collect()
    }

    fn table_with(chains: &[&str]) -> TableState {
        TableState {
            exists: true,
            chains: chains.iter().map(|chain| (*chain).to_owned()).collect(),
        }
    }

    #[test]
    fn reconcile_builds_table_base_chains_and_one_chain_per_container() {
        let containers = [
            container("aaaaaaaaaaaa1", "web", 2),
            container("bbbbbbbbbbbb2", "db", 3),
        ];
        let commands = commands(reconcile(&KernelState::default(), &containers));

        for layer in Layer::ALL {
            let family = layer.family();
            assert!(commands.iter().any(|command| matches!(command,
                NfCmd::Add(NfListObject::Table(table)) if table.name == TABLE && table.family == family)));
            let added = added_chains(&commands, family);
            for (base, _) in layer.base_chains() {
                assert!(
                    added.iter().any(|name| name == base),
                    "missing {family:?} base chain {base}"
                );
            }
            assert!(added.contains(&chain_name("aaaaaaaaaaaa1", "web")));
            assert!(added.contains(&chain_name("bbbbbbbbbbbb2", "db")));
            assert!(deleted_chains(&commands, family).is_empty());
        }
    }

    #[test]
    fn base_chains_hook_with_accept_policy_in_both_layers() {
        let commands = commands(reconcile(&KernelState::default(), &[]));
        for layer in Layer::ALL {
            for (base, hook) in layer.base_chains() {
                let found = commands.iter().any(|command| {
                    matches!(command, NfCmd::Add(NfListObject::Chain(chain))
                        if chain.family == layer.family()
                            && chain.name == *base
                            && chain.hook == Some(*hook)
                            && chain.policy == Some(NfChainPolicy::Accept)
                            && chain._type == Some(NfChainType::Filter))
                });
                assert!(found, "{layer:?} base chain {base} not hooked at {hook:?}");
            }
        }
    }

    #[test]
    fn reconcile_deletes_orphaned_container_chains_only() {
        let kept = container("aaaaaaaaaaaa1", "web", 2);
        let orphan = chain_name("cccccccccccc3", "gone");
        let kept_chain = kept.chain();
        let kernel = KernelState {
            routed: table_with(&["forward", "user-chain", &kept_chain, &orphan]),
            bridged: table_with(&["forward", &kept_chain]),
            legacy: LegacyState::default(),
        };
        let commands = commands(reconcile(&kernel, &[kept]));
        assert_eq!(deleted_chains(&commands, NfFamily::INet), vec![orphan]);
        assert!(deleted_chains(&commands, NfFamily::Bridge).is_empty());
    }

    #[test]
    fn reconcile_is_deterministic() {
        let containers = [
            container("aaaaaaaaaaaa1", "web", 2),
            container("bbbbbbbbbbbb2", "db", 3),
        ];
        let first = reconcile(&KernelState::default(), &containers).to_nftables();
        let second = reconcile(&KernelState::default(), &containers).to_nftables();
        assert_eq!(first, second);
    }

    #[test]
    fn a_grant_jumping_to_a_missing_chain_is_left_out() {
        let mut broken = container("aaaaaaaaaaaa1", "web", 2);
        broken.outputs.push(OutputRule {
            destinations: Peers::Any,
            proto: Protocol::Tcp,
            src_ports: Vec::new(),
            dst_ports: vec![RulePorts::Single(80)],
            log_prefix: None,
            verdict: Verdict::Jump("absent".to_owned()),
        });
        let mut present = broken.clone();
        present.id = "bbbbbbbbbbbb2".to_owned();
        if let Some(output) = present.outputs.first_mut() {
            output.verdict = Verdict::Jump("audit".to_owned());
        }
        let kernel = KernelState {
            routed: table_with(&["audit"]),
            bridged: TableState::default(),
            legacy: LegacyState::default(),
        };
        let Nftables { objects } = reconcile(&kernel, &[broken, present]).to_nftables();
        let rules_in = |family: NfFamily| -> String {
            let rules: Vec<_> = objects
                .iter()
                .filter(|object| matches!(object, NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule))) if rule.family == family))
                .collect();
            serde_json::to_string(&rules).expect("render rules")
        };
        assert!(!rules_in(NfFamily::INet).contains("\"target\":\"absent\""));
        assert!(rules_in(NfFamily::INet).contains("\"target\":\"audit\""));
        // The bridge table has no "audit" chain, so the rule is left out there.
        assert!(!rules_in(NfFamily::Bridge).contains("\"target\":\"audit\""));
    }

    #[test]
    fn clear_deletes_the_table_only_when_it_exists() {
        assert!(commands(clear(&KernelState::default())).is_empty());
        let present = KernelState {
            routed: table_with(&[]),
            ..KernelState::default()
        };
        let commands = commands(clear(&present));
        assert!(matches!(commands.as_slice(),
            [NfCmd::Delete(NfListObject::Table(table))] if table.name == TABLE && table.family == NfFamily::INet));
    }

    #[test]
    fn legacy_objects_are_removed_jumps_first_then_flushed_then_deleted() {
        let kernel = KernelState {
            routed: TableState::default(),
            bridged: TableState::default(),
            legacy: LegacyState {
                jumps: vec![LegacyJump {
                    chain: "DOCKER-USER".to_owned(),
                    handle: 7,
                }],
                chains: vec![LEGACY_CHAIN.to_owned(), "hs-old-123456789012".to_owned()],
            },
        };
        let commands = commands(clear(&kernel));
        let kinds: Vec<&str> = commands
            .iter()
            .map(|command| match command {
                NfCmd::Delete(NfListObject::Rule(rule)) if rule.handle == Some(7) => "jump",
                NfCmd::Flush(_) => "flush",
                NfCmd::Delete(NfListObject::Chain(_)) => "delete",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, vec!["jump", "flush", "flush", "delete", "delete"]);
    }
}
