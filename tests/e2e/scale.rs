//! Many containers at once, and repeated churn, without lost enforcement or leaked state.

use std::time::Duration;

use futures::future::try_join_all;
use serde_json::json;

use crate::support::{ContainerSpec, Failure, Origin, e2e, ruleset, stored_container_ids, tcp};

const FLEET: usize = 40;
const CONVERGE_LIMIT: Duration = Duration::from_secs(90);

e2e! {
    /// A burst of container starts while the daemon runs: every one ends up enforced, the
    /// gauge counts them, and rules naming one of them resolve.
    async fn a_burst_of_containers_is_enforced_together(scenario) {
        let net = scenario.network("net").await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;

        let started = tokio::time::Instant::now();
        let fleet = try_join_all((0..FLEET).map(|index| {
            scenario.run(ContainerSpec::new(scenario.name(&format!("member{index}"))).network(&net).managed())
        }))
        .await?;
        let target = fleet.first().ok_or_else(|| Failure::new("empty fleet"))?;
        let rules = json!({
            "output": [{ "container": target.name, "network": net.name, "proto": "tcp", "dst_ports": [8080] }]
        });
        let client = scenario
            .run(ContainerSpec::new(scenario.name("client")).network(&net).rules(rules.to_string()))
            .await?;
        for member in fleet.iter().chain(std::iter::once(&client)) {
            scenario.wait_until_managed(member).await?;
        }
        let elapsed = started.elapsed();
        if elapsed > CONVERGE_LIMIT {
            return Err(Failure::new(format!("{FLEET} containers took {elapsed:?} to converge")));
        }

        let (_, metrics) = scenario.daemon()?.get("/metrics").await?;
        let expected = format!("harborshield_active_containers {}", fleet.len().saturating_add(1));
        if !metrics.lines().any(|line| line == expected) {
            return Err(Failure::new(format!("metrics lack {expected:?}")));
        }

        tcp(Origin::Container(&client.name), target.ip_on(&net).await?, 8080)
            .expect_connected(&target.name, 8080)
            .await?;
        let step = FLEET / 4;
        for member in fleet.iter().step_by(step) {
            tcp(Origin::Container(&intruder.name), member.ip_on(&net).await?, 8080)
                .expect_dropped()
                .await?;
        }
        Ok(())
    }
}

e2e! {
    /// Containers coming and going over and over leave exactly the long-lived container's
    /// state behind, and it stays enforced throughout.
    async fn churn_leaves_no_state_behind(scenario) {
        let net = scenario.network("net").await?;
        let sentinel = scenario.run(ContainerSpec::new(scenario.name("sentinel")).network(&net).managed()).await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;
        let sentinel_chain = scenario.wait_until_managed(&sentinel).await?;

        for cycle in 0..6 {
            let batch = try_join_all((0..4).map(|index| {
                scenario.run(
                    ContainerSpec::new(scenario.name(&format!("churn{cycle}x{index}"))).network(&net).managed(),
                )
            }))
            .await?;
            for member in &batch {
                scenario.wait_until_managed(member).await?;
            }
            try_join_all(batch.iter().map(|member| member.remove())).await?;
            for member in &batch {
                scenario.wait_until_unmanaged(member).await?;
            }
            tcp(Origin::Container(&intruder.name), sentinel.ip_on(&net).await?, 8080)
                .expect_dropped()
                .await?;
        }

        let chains = ruleset().await?.container_chains();
        if chains != vec![sentinel_chain] {
            return Err(Failure::new(format!("chains left after churn: {chains:?}")));
        }
        let stored = stored_container_ids(scenario.data_dir()).await?;
        if stored == vec![sentinel.id.clone()] {
            Ok(())
        } else {
            Err(Failure::new(format!("database after churn: {stored:?}")))
        }
    }
}
