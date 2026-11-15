//! What survives harborshield stopping, restarting, crashing and clearing.

use serde_json::json;

use crate::support::{ContainerSpec, Failure, Origin, e2e, ruleset, stored_container_ids, tcp};

e2e! {
    async fn containers_running_before_start_are_enforced(scenario) {
        let net = scenario.network("net").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&net).managed()).await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        tcp(Origin::Container(&intruder.name), server.ip_on(&net).await?, 8080)
            .expect_dropped()
            .await
    }
}

e2e! {
    /// Protection must not lapse while the daemon is down.
    async fn rules_stay_in_force_while_the_daemon_is_stopped(scenario) {
        let net = scenario.network("net").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&net).managed()).await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        scenario.stop_daemon().await?;
        tcp(Origin::Container(&intruder.name), server.ip_on(&net).await?, 8080)
            .expect_dropped()
            .await
    }
}

e2e! {
    /// Restarting rebuilds the same rules instead of stacking duplicates.
    async fn restart_keeps_enforcement_without_duplicate_rules(scenario) {
        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let server_name = scenario.name("server");
        let server_rules = json!({ "mapped_ports": { "external": { "allow": true } } });
        let server = scenario
            .run(ContainerSpec::new(&server_name).network(&net).publish("18080:8080").rules(server_rules.to_string()))
            .await?;
        let client_rules = json!({
            "output": [{ "container": server_name, "network": net.name, "proto": "tcp", "dst_ports": [8080] }]
        });
        let client = scenario
            .run(ContainerSpec::new(scenario.name("client")).network(&net).rules(client_rules.to_string()))
            .await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;
        let server_chain = scenario.wait_until_managed(&server).await?;
        let client_chain = scenario.wait_until_managed(&client).await?;
        let before = ruleset().await?;
        let counts = (before.rules_in(&server_chain).len(), before.rules_in(&client_chain).len());

        for _ in 0..2 {
            scenario.restart_daemon().await?;
            scenario.wait_until_managed(&server).await?;
            scenario.wait_until_managed(&client).await?;
        }

        let after = ruleset().await?;
        let after_counts = (after.rules_in(&server_chain).len(), after.rules_in(&client_chain).len());
        if after_counts != counts {
            return Err(Failure::new(format!(
                "rule counts (server, client) changed across restarts: {counts:?} -> {after_counts:?}"
            )));
        }
        let server_ip = server.ip_on(&net).await?;
        tcp(Origin::Container(&client.name), server_ip, 8080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::Container(&intruder.name), server_ip, 8080)
            .expect_dropped()
            .await?;
        tcp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr }, sandbox.host_addr, 18080)
            .expect_connected(&server.name, 8080)
            .await
    }
}

e2e! {
    /// A container removed while the daemon was down leaves neither a chain nor a database row
    /// once the daemon is back.
    async fn crash_recovery_removes_orphaned_state(scenario) {
        let net = scenario.network("net").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&net).managed()).await?;
        let keeper = scenario.run(ContainerSpec::new(scenario.name("keeper")).network(&net).managed()).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        scenario.wait_until_managed(&keeper).await?;

        scenario.crash_daemon().await?;
        server.remove().await?;
        scenario.start_daemon().await?;

        scenario.wait_until_unmanaged(&server).await?;
        scenario.wait_until_managed(&keeper).await?;
        let stored = stored_container_ids(scenario.data_dir()).await?;
        if stored.contains(&server.id) {
            return Err(Failure::new(format!("removed {} is still stored: {stored:?}", server.name)));
        }
        if !stored.contains(&keeper.id) {
            return Err(Failure::new(format!("running {} is not stored: {stored:?}", keeper.name)));
        }
        Ok(())
    }
}

e2e! {
    /// `--clear` hands the firewall back to Docker: nothing of harborshield's remains and
    /// traffic it used to drop flows again.
    async fn clear_restores_docker_defaults(scenario) {
        let net = scenario.network("net").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&net).managed()).await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        let server_ip = server.ip_on(&net).await?;
        tcp(Origin::Container(&intruder.name), server_ip, 8080).expect_dropped().await?;

        scenario.stop_daemon().await?;
        scenario.clear().await?;

        let rules = ruleset().await?;
        if !rules.container_chains().is_empty() {
            return Err(Failure::new(format!("chains left after --clear: {:?}", rules.container_chains())));
        }
        tcp(Origin::Container(&intruder.name), server_ip, 8080)
            .expect_connected(&server.name, 8080)
            .await?;
        let stored = stored_container_ids(scenario.data_dir()).await?;
        if stored.is_empty() {
            Ok(())
        } else {
            Err(Failure::new(format!("containers still stored after --clear: {stored:?}")))
        }
    }
}
