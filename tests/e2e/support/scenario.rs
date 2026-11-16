use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::{Mutex, MutexGuard};

use super::daemon::{CURRENT_BINARY, Daemon, clear};
use super::docker::{
    Container, ContainerSpec, E2E_LABEL, Network, SCENARIO_LABEL, remove_all_e2e_resources,
    remove_scenario_resources,
};
use super::failure::{Failure, TestResult};
use super::nft::{Ruleset, TABLE, family_keyword, nft, ruleset};
use super::sandbox::Sandbox;
use super::time::deadline_in;

/// Scenarios share one kernel ruleset and one Docker daemon, so they never overlap.
static SERIAL: Mutex<()> = Mutex::const_new(());

const CONVERGE_LIMIT: Duration = Duration::from_secs(20);

/// One test's world: its containers, networks, data directory and harborshield process.
pub struct Scenario {
    pub sandbox: Sandbox,
    tag: String,
    log_dir: PathBuf,
    data_dir: tempfile::TempDir,
    daemon: Option<Daemon>,
    generation: u32,
    teardown: Vec<Cleanup>,
    _serial: MutexGuard<'static, ()>,
}

/// Something a test created outside Docker that teardown must remove.
#[derive(Clone, Debug)]
pub enum Cleanup {
    /// An nftables table, by family keyword and name.
    NftTable {
        family: &'static str,
        name: String,
    },
    NetworkNamespace(String),
    Link(String),
}

impl Cleanup {
    async fn run(&self) -> TestResult {
        match self {
            Self::NftTable { family, name } => nft(&["delete", "table", family, name]).await,
            Self::NetworkNamespace(name) => {
                super::command::run_ok("ip", &["netns", "delete", name], CONVERGE_LIMIT)
                    .await
                    .map(drop)
            }
            Self::Link(name) => {
                super::command::run_ok("ip", &["link", "delete", name], CONVERGE_LIMIT)
                    .await
                    .map(drop)
            }
        }
    }
}

/// Run `body` in a fresh scenario and always tear it down, reporting the body's failure first
/// and any teardown failure after it.
pub async fn run_scenario<F>(name: &str, body: F) -> TestResult
where
    F: AsyncFnOnce(&mut Scenario) -> TestResult,
{
    let mut scenario = Scenario::begin(name).await?;
    let outcome = body(&mut scenario).await;
    let teardown = scenario.finish().await;
    match (outcome, teardown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(failure), Ok(())) => Err(failure),
        (Ok(()), Err(teardown)) => Err(Failure::new(format!("teardown failed: {teardown}"))),
        (Err(failure), Err(teardown)) => Err(Failure::new(format!(
            "{failure}\n(teardown also failed: {teardown})"
        ))),
    }
}

impl Scenario {
    async fn begin(name: &str) -> TestResult<Self> {
        let sandbox = Sandbox::require()?;
        let serial = SERIAL.lock().await;

        let log_dir = sandbox.log_root.join(name);
        if log_dir.exists() {
            std::fs::remove_dir_all(&log_dir)
                .map_err(|error| Failure::context(format!("reset {}", log_dir.display()), error))?;
        }
        std::fs::create_dir_all(&log_dir)
            .map_err(|error| Failure::context(format!("create {}", log_dir.display()), error))?;

        remove_all_e2e_resources().await?;
        repair_leftover_firewall_state().await?;

        let data_dir =
            tempfile::tempdir().map_err(|error| Failure::context("create data dir", error))?;
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let tag = tag.get(..6).unwrap_or(&tag).to_owned();

        Ok(Self {
            sandbox,
            tag,
            log_dir,
            data_dir,
            daemon: None,
            generation: 0,
            teardown: Vec::new(),
            _serial: serial,
        })
    }

    /// This scenario's short unique tag, for names with tight length limits.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// A Docker-unique name for a logical container or network name.
    pub fn name(&self, logical: &str) -> String {
        format!("e2e-{}-{logical}", self.tag)
    }

    /// Labels that mark a resource as belonging to this scenario, for resources the suite does
    /// not create itself (such as a compose stack).
    pub fn resource_labels(&self) -> Vec<(String, String)> {
        vec![
            (E2E_LABEL.to_owned(), String::new()),
            (SCENARIO_LABEL.to_owned(), self.tag.clone()),
        ]
    }

    pub fn data_dir(&self) -> &Path {
        self.data_dir.path()
    }

    pub async fn network(&self, logical: &str) -> TestResult<Network> {
        Network::create(&self.name(logical), &self.tag).await
    }

    pub async fn network_ipv6(&self, logical: &str, subnet: &str) -> TestResult<Network> {
        Network::create_ipv6(&self.name(logical), &self.tag, subnet).await
    }

    pub async fn run(&self, spec: ContainerSpec) -> TestResult<Container> {
        spec.run(&self.tag).await
    }

    pub async fn start_daemon(&mut self) -> TestResult {
        self.start_binary(Path::new(CURRENT_BINARY)).await
    }

    /// Start the previous release, built by `cargo xtask e2e`, on this scenario's data.
    pub async fn start_legacy_daemon(&mut self) -> TestResult {
        let binary = std::env::var("HARBORSHIELD_E2E_LEGACY_BIN").map_err(|error| {
            Failure::context(
                "HARBORSHIELD_E2E_LEGACY_BIN names the previous release",
                error,
            )
        })?;
        self.start_binary(Path::new(&binary)).await
    }

    async fn start_binary(&mut self, binary: &Path) -> TestResult {
        if self.daemon.is_some() {
            return Err(Failure::new(
                "harborshield is already running in this scenario",
            ));
        }
        self.generation = self.generation.saturating_add(1);
        let daemon =
            Daemon::start(binary, self.data_dir.path(), &self.log_dir, self.generation).await?;
        self.daemon = Some(daemon);
        Ok(())
    }

    /// Remove `cleanup`'s object during teardown, after harborshield has stopped.
    pub fn on_teardown(&mut self, cleanup: Cleanup) {
        self.teardown.push(cleanup);
    }

    pub async fn stop_daemon(&mut self) -> TestResult {
        self.daemon
            .take()
            .ok_or_else(|| Failure::new("harborshield is not running"))?
            .stop()
            .await
    }

    pub async fn crash_daemon(&mut self) -> TestResult {
        self.daemon
            .take()
            .ok_or_else(|| Failure::new("harborshield is not running"))?
            .crash()
            .await
    }

    pub async fn restart_daemon(&mut self) -> TestResult {
        self.stop_daemon().await?;
        self.start_daemon().await
    }

    pub fn daemon(&self) -> TestResult<&Daemon> {
        self.daemon
            .as_ref()
            .ok_or_else(|| Failure::new("harborshield is not running"))
    }

    pub async fn clear(&self) -> TestResult {
        clear(self.data_dir.path()).await
    }

    /// Wait until harborshield has a chain for `container` and dispatches traffic into it.
    pub async fn wait_until_managed(&self, container: &Container) -> TestResult<String> {
        let deadline = deadline_in(CONVERGE_LIMIT);
        loop {
            let rules = ruleset().await?;
            if let Some(chain) = rules.chain_for(container)
                && rules.references(&chain)?
            {
                return Ok(chain);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Failure::new(format!(
                    "{} was not managed within {CONVERGE_LIMIT:?}: chains {:?}",
                    container.name,
                    rules.container_chains()
                )));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Wait until no chain for `container` remains.
    pub async fn wait_until_unmanaged(&self, container: &Container) -> TestResult {
        let deadline = deadline_in(CONVERGE_LIMIT);
        loop {
            let rules = ruleset().await?;
            match rules.chain_for(container) {
                None => return Ok(()),
                Some(chain) if tokio::time::Instant::now() >= deadline => {
                    return Err(Failure::new(format!(
                        "chain {chain} for {} still present after {CONVERGE_LIMIT:?}",
                        container.name
                    )));
                }
                Some(_) => tokio::time::sleep(Duration::from_millis(250)).await,
            }
        }
    }

    async fn finish(mut self) -> TestResult {
        let mut failures = Vec::new();
        if let Some(daemon) = self.daemon.take()
            && let Err(failure) = daemon.stop().await
        {
            failures.push(format!("stop harborshield: {failure}"));
        }
        if let Err(failure) = remove_scenario_resources(&self.tag).await {
            failures.push(format!("remove scenario resources: {failure}"));
        }
        for cleanup in self.teardown.iter().rev() {
            if let Err(failure) = cleanup.run().await {
                failures.push(format!("remove {cleanup:?}: {failure}"));
            }
        }
        if let Err(failure) = clear(self.data_dir.path()).await {
            failures.push(format!("harborshield --clear: {failure}"));
        }
        match ruleset().await {
            Ok(rules) => {
                let leftover = leftover_state(&rules);
                if !leftover.is_empty() {
                    failures.push(format!("state left after --clear: {leftover:?}"));
                }
            }
            Err(failure) => failures.push(format!("read ruleset: {failure}")),
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Failure::new(failures.join("; ")))
        }
    }
}

/// Everything of harborshield's, or of an interrupted test's, left in the kernel.
fn leftover_state(rules: &Ruleset) -> Vec<String> {
    let mut leftover: Vec<String> = rules
        .tables()
        .iter()
        .map(|family| format!("table {family:?} {TABLE}"))
        .collect();
    if rules.has_legacy_chain("harborshield") {
        leftover.push("legacy chain ip filter harborshield".to_owned());
    }
    leftover.extend(rules.legacy_container_chains());
    leftover.extend(
        rules
            .tables_named_with_prefix(TEST_TABLE_PREFIX)
            .into_iter()
            .map(|(family, name)| format!("test table {family:?} {name}")),
    );
    leftover
}

/// Tables tests create for other firewalls start with this.
const TEST_TABLE_PREFIX: &str = "e2e_";
/// Namespaces and links tests create outside Docker start with these.
const TEST_NETNS_PREFIX: &str = "hsn-";
const TEST_LINK_PREFIXES: [&str; 2] = ["hsb-", "hsv-"];

/// Remove harborshield and test state an interrupted run left behind, so every scenario
/// starts from Docker's own ruleset. Every removal is checked.
async fn repair_leftover_firewall_state() -> TestResult {
    remove_test_network_objects().await?;
    let rules = ruleset().await?;
    let leftover = leftover_state(&rules);
    if leftover.is_empty() {
        return Ok(());
    }
    eprintln!("repairing state left by an earlier run: {leftover:?}");
    for family in rules.tables() {
        nft(&["delete", "table", family_keyword(family), TABLE]).await?;
    }
    for (family, name) in rules.tables_named_with_prefix(TEST_TABLE_PREFIX) {
        nft(&["delete", "table", family_keyword(family), &name]).await?;
    }
    if rules.has_legacy_chain("harborshield") || !rules.legacy_container_chains().is_empty() {
        // `--clear` removes the legacy layout, jumps included.
        clear_legacy_layout().await?;
    }
    let after = leftover_state(&ruleset().await?);
    if after.is_empty() {
        Ok(())
    } else {
        Err(Failure::new(format!(
            "leftover state survived repair: {after:?}"
        )))
    }
}

async fn clear_legacy_layout() -> TestResult {
    let scratch =
        tempfile::tempdir().map_err(|error| Failure::context("create scratch data dir", error))?;
    clear(scratch.path()).await
}

async fn remove_test_network_objects() -> TestResult {
    let limit = CONVERGE_LIMIT;
    let namespaces = super::command::run_ok("ip", &["netns", "list"], limit).await?;
    for namespace in namespaces
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.starts_with(TEST_NETNS_PREFIX))
    {
        super::command::run_ok("ip", &["netns", "delete", namespace], limit).await?;
    }
    let links = super::command::run_ok("ip", &["-o", "link", "show"], limit).await?;
    for link in links
        .lines()
        .filter_map(|line| line.split(": ").nth(1))
        .map(|name| name.split('@').next().unwrap_or(name))
        .filter(|name| {
            TEST_LINK_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
    {
        super::command::run_ok("ip", &["link", "delete", link], limit).await?;
    }
    Ok(())
}
