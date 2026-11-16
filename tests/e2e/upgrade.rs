//! Upgrading over a deployment of the previous release, which kept its rules in Docker's
//! `ip filter` table.

use std::time::Duration;

use crate::support::{
    ContainerSpec, Failure, Origin, deadline_in, e2e, ensure_ip_filter_table, ruleset,
    stored_container_ids, tcp,
};

const LEGACY_SETUP_LIMIT: Duration = Duration::from_secs(30);

e2e! {
    /// The previous release runs, manages a container and is killed; the new one starts on its
    /// data directory, removes its leftovers, migrates its database and enforces the rules.
    async fn upgrade_from_the_previous_release_keeps_enforcing(scenario) {
        // The previous release refuses to start without Docker's iptables-nft table.
        ensure_ip_filter_table(scenario).await?;
        let net = scenario.network("net").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&net).managed()).await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;

        scenario.start_legacy_daemon().await?;
        let deadline = deadline_in(LEGACY_SETUP_LIMIT);
        loop {
            let rules = ruleset().await?;
            if rules.has_legacy_chain("harborshield") && !rules.legacy_container_chains().is_empty() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Failure::new(format!(
                    "the previous release did not set up its chains: {:?}",
                    rules.legacy_container_chains()
                )));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        scenario.crash_daemon().await?;

        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        let rules = ruleset().await?;
        if rules.has_legacy_chain("harborshield") || !rules.legacy_container_chains().is_empty() {
            return Err(Failure::new(format!(
                "legacy chains survived the upgrade: {:?}",
                rules.legacy_container_chains()
            )));
        }
        tcp(Origin::Container(&intruder.name), server.ip_on(&net).await?, 8080)
            .expect_dropped()
            .await?;
        let stored = stored_container_ids(scenario.data_dir()).await?;
        if stored.contains(&server.id) {
            Ok(())
        } else {
            Err(Failure::new(format!("migrated database lacks {}: {stored:?}", server.name)))
        }
    }
}
