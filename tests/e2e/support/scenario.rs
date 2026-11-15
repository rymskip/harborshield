use std::path::{Path, PathBuf};
use std::time::Duration;

use nftables::types::NfFamily;

use tokio::sync::{Mutex, MutexGuard};

use super::daemon::{Daemon, clear};
use super::docker::{
    Container, ContainerSpec, E2E_LABEL, Network, SCENARIO_LABEL, remove_all_e2e_resources,
    remove_scenario_resources,
};
use super::failure::{Failure, TestResult};
use super::nft::{Ruleset, TABLE, nft, ruleset};
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
    _serial: MutexGuard<'static, ()>,
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
            _serial: serial,
        })
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
        if self.daemon.is_some() {
            return Err(Failure::new(
                "harborshield is already running in this scenario",
            ));
        }
        self.generation = self.generation.saturating_add(1);
        let daemon = Daemon::start(self.data_dir.path(), &self.log_dir, self.generation).await?;
        self.daemon = Some(daemon);
        Ok(())
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

/// Everything of harborshield's left in the kernel: its table, and any legacy chains in
/// Docker's `ip filter` table.
fn leftover_state(rules: &Ruleset) -> Vec<String> {
    let mut leftover: Vec<String> = rules
        .tables()
        .iter()
        .map(|family| format!("table {family:?} {TABLE}"))
        .collect();
    if rules.has_legacy_chain("harborshield") {
        leftover.push("legacy chain ip filter harborshield".to_owned());
    }
    leftover
}

/// Remove harborshield state an interrupted run left in the kernel, so every scenario starts
/// from Docker's own ruleset. The removal is checked.
async fn repair_leftover_firewall_state() -> TestResult {
    let rules = ruleset().await?;
    let leftover = leftover_state(&rules);
    if leftover.is_empty() {
        return Ok(());
    }
    eprintln!("repairing firewall state left by an earlier run: {leftover:?}");
    for family in rules.tables() {
        let family = match family {
            NfFamily::INet => "inet",
            NfFamily::Bridge => "bridge",
            other => {
                return Err(Failure::new(format!(
                    "unexpected {other:?} table named {TABLE}"
                )));
            }
        };
        nft(&["delete", "table", family, TABLE]).await?;
    }
    if rules.has_legacy_chain("harborshield") {
        return Err(Failure::new(
            "a legacy ip filter harborshield chain is present; only the legacy-cleanup test creates one and its teardown removes it",
        ));
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
