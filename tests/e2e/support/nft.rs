use std::time::Duration;

use nftables::schema::{Chain, NfListObject, NfObject, Nftables, Rule};
use nftables::stmt::{Counter, Statement};
use nftables::types::{NfFamily, NfHook};

use super::command::run_ok;
use super::docker::Container;
use super::failure::{Failure, TestResult};

const NFT_LIMIT: Duration = Duration::from_secs(15);
pub const TABLE: &str = "harborshield";
/// harborshield's base chains, per table family, and the hooks they must sit on.
pub const BASE_CHAINS: [(NfFamily, &str, NfHook); 4] = [
    (NfFamily::INet, "forward", NfHook::Forward),
    (NfFamily::INet, "input", NfHook::Input),
    (NfFamily::INet, "output", NfHook::Output),
    (NfFamily::Bridge, "forward", NfHook::Forward),
];

/// A snapshot of the kernel ruleset, read as typed nftables JSON.
pub struct Ruleset {
    objects: Vec<NfListObject<'static>>,
}

pub async fn ruleset() -> TestResult<Ruleset> {
    let raw = run_ok("nft", &["--json", "list", "ruleset"], NFT_LIMIT).await?;
    let document: Nftables<'static> =
        serde_json::from_str(&raw).map_err(|error| Failure::context("parse nft ruleset", error))?;
    let objects = document
        .objects
        .iter()
        .filter_map(|object| match object {
            NfObject::ListObject(item) => Some(item.clone()),
            NfObject::CmdObject(_) => None,
        })
        .collect();
    Ok(Ruleset { objects })
}

/// Run an nft command for fixture setup, such as creating a user verdict chain.
pub async fn nft(args: &[&str]) -> TestResult {
    run_ok("nft", args, NFT_LIMIT).await.map(drop)
}

impl Ruleset {
    fn our_chains(&self) -> impl Iterator<Item = &Chain<'static>> {
        self.objects.iter().filter_map(|object| match object {
            NfListObject::Chain(chain)
                if chain.family == NfFamily::INet && chain.table == TABLE =>
            {
                Some(chain)
            }
            _ => None,
        })
    }

    fn our_rules(&self) -> impl Iterator<Item = &Rule<'static>> {
        self.objects.iter().filter_map(|object| match object {
            NfListObject::Rule(rule) if rule.family == NfFamily::INet && rule.table == TABLE => {
                Some(rule)
            }
            _ => None,
        })
    }

    /// Families of harborshield's tables present in the kernel.
    pub fn tables(&self) -> Vec<NfFamily> {
        self.objects
            .iter()
            .filter_map(|object| match object {
                NfListObject::Table(table) if table.name == TABLE => Some(table.family),
                _ => None,
            })
            .collect()
    }

    /// The hook a chain in harborshield's table of `family` is attached to, if it is a base
    /// chain.
    pub fn hook_of(&self, family: NfFamily, name: &str) -> Option<NfHook> {
        self.objects.iter().find_map(|object| match object {
            NfListObject::Chain(chain)
                if chain.family == family && chain.table == TABLE && chain.name == name =>
            {
                chain.hook
            }
            _ => None,
        })
    }

    /// Whether `ip filter` holds a chain by this name, as versions before the dedicated table
    /// left behind.
    pub fn has_legacy_chain(&self, name: &str) -> bool {
        self.objects.iter().any(|object| {
            matches!(object, NfListObject::Chain(chain)
                if chain.family == NfFamily::IP && chain.table == "filter" && chain.name == name)
        })
    }

    /// Every per-container chain harborshield owns.
    pub fn container_chains(&self) -> Vec<String> {
        self.our_chains()
            .filter(|chain| chain.name.starts_with("hs-"))
            .map(|chain| chain.name.to_string())
            .collect()
    }

    /// The chain harborshield created for `container`, found by its id suffix.
    pub fn chain_for(&self, container: &Container) -> Option<String> {
        let suffix = format!("-{}", container.short_id());
        self.container_chains()
            .into_iter()
            .find(|name| name.ends_with(&suffix))
    }

    pub fn rules_in(&self, chain: &str) -> Vec<&Rule<'static>> {
        self.our_rules()
            .filter(|rule| rule.chain == chain)
            .collect()
    }

    /// Whether any other rule in harborshield's table sends packets to `chain`, through a
    /// plain jump or a verdict map entry.
    pub fn references(&self, chain: &str) -> TestResult<bool> {
        let needle = format!("\"target\":\"{chain}\"");
        for rule in self.our_rules().filter(|rule| rule.chain != chain) {
            let rendered = serde_json::to_string(&rule.expr)
                .map_err(|error| Failure::context("render nft rule", error))?;
            if rendered.contains(&needle) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Sum of the anonymous counters in `chain`.
    pub fn packets_counted(&self, chain: &str) -> usize {
        self.rules_in(chain)
            .iter()
            .flat_map(|rule| rule.expr.iter())
            .filter_map(|statement| match statement {
                Statement::Counter(Counter::Anonymous(Some(counter))) => counter.packets,
                _ => None,
            })
            .sum()
    }

    /// Log prefixes of every `log` statement in `chain`.
    pub fn log_prefixes(&self, chain: &str) -> Vec<String> {
        self.rules_in(chain)
            .iter()
            .flat_map(|rule| rule.expr.iter())
            .filter_map(|statement| match statement {
                Statement::Log(Some(log)) => log.prefix.as_ref().map(ToString::to_string),
                _ => None,
            })
            .collect()
    }

    /// Queue numbers of every `queue` statement in `chain`.
    pub fn queues(&self, chain: &str) -> TestResult<Vec<String>> {
        self.rules_in(chain)
            .iter()
            .flat_map(|rule| rule.expr.iter())
            .filter_map(|statement| match statement {
                Statement::Queue(queue) => Some(
                    serde_json::to_string(&queue.num)
                        .map_err(|error| Failure::context("render queue number", error)),
                ),
                _ => None,
            })
            .collect()
    }
}
