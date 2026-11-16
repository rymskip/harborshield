//! Container lifecycle events while harborshield runs: stop, start, removal, pause, rename and
//! network changes.

use std::time::Duration;

use serde_json::json;

use crate::support::{
    Container, ContainerSpec, Failure, Network, Origin, Scenario, TestResult, deadline_in, e2e,
    restart_docker_daemon, ruleset, tcp,
};

/// A managed server and a managed client allowed to reach it on 8080.
async fn server_and_client(
    scenario: &Scenario,
    net: &Network,
) -> TestResult<(Container, Container)> {
    let server_name = scenario.name("server");
    let server = scenario
        .run(ContainerSpec::new(&server_name).network(net).managed())
        .await?;
    let rules = json!({
        "output": [{ "container": server_name, "network": net.name, "proto": "tcp", "dst_ports": [8080] }]
    });
    let client = scenario
        .run(
            ContainerSpec::new(scenario.name("client"))
                .network(net)
                .rules(rules.to_string()),
        )
        .await?;
    Ok((server, client))
}

async fn expect_status_for(container: &Container, expected: &str, settle: Duration) -> TestResult {
    let deadline = deadline_in(settle);
    while tokio::time::Instant::now() < deadline {
        let status = container.status().await?;
        if status != expected {
            return Err(Failure::new(format!(
                "{} should stay {expected} but became {status}",
                container.name
            )));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}

e2e! {
    async fn stopped_container_loses_its_rules_and_regains_them_on_start(scenario) {
        let net = scenario.network("net").await?;
        let (server, client) = server_and_client(scenario, &net).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        scenario.wait_until_managed(&client).await?;
        tcp(Origin::Container(&client.name), server.ip_on(&net).await?, 8080)
            .expect_connected(&server.name, 8080)
            .await?;

        server.stop().await?;
        scenario.wait_until_unmanaged(&server).await?;

        server.start().await?;
        server.wait_for_listeners(&[crate::support::Listener::Tcp(8080)]).await?;
        scenario.wait_until_managed(&server).await?;
        tcp(Origin::Container(&client.name), server.ip_on(&net).await?, 8080)
            .expect_connected(&server.name, 8080)
            .await
    }
}

e2e! {
    /// `docker stop` is the user's decision; harborshield must not start the container again,
    /// neither on the stop event nor when the daemon itself restarts.
    async fn user_stopped_container_stays_stopped(scenario) {
        let net = scenario.network("net").await?;
        let (server, client) = server_and_client(scenario, &net).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        scenario.wait_until_managed(&client).await?;

        client.stop().await?;
        expect_status_for(&client, "exited", Duration::from_secs(6)).await?;

        scenario.restart_daemon().await?;
        expect_status_for(&client, "exited", Duration::from_secs(6)).await
    }
}

e2e! {
    async fn removed_container_leaves_no_rules_behind(scenario) {
        let net = scenario.network("net").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&net).managed()).await?;
        scenario.start_daemon().await?;
        let chain = scenario.wait_until_managed(&server).await?;

        server.remove().await?;
        scenario.wait_until_unmanaged(&server).await?;
        if ruleset().await?.references(&chain)? {
            return Err(Failure::new(format!("dispatch still references removed chain {chain}")));
        }
        Ok(())
    }
}

e2e! {
    async fn unpaused_container_is_enforced_again(scenario) {
        let net = scenario.network("net").await?;
        let (server, client) = server_and_client(scenario, &net).await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        scenario.wait_until_managed(&client).await?;

        server.pause().await?;
        server.unpause().await?;

        let server_ip = server.ip_on(&net).await?;
        tcp(Origin::Container(&client.name), server_ip, 8080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::Container(&intruder.name), server_ip, 8080)
            .expect_dropped_eventually()
            .await
    }
}

e2e! {
    async fn renamed_container_stays_enforced(scenario) {
        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let rules = json!({ "mapped_ports": { "external": { "allow": true } } });
        let server = scenario
            .run(ContainerSpec::new(scenario.name("server")).network(&net).publish("18080:8080").rules(rules.to_string()))
            .await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        let renamed = scenario.name("renamed");
        crate::support::docker(&["rename", &server.id, &renamed]).await?;
        let server = Container { id: server.id.clone(), name: renamed };
        scenario.wait_until_managed(&server).await?;

        // The banner carries the hostname, which a rename does not change.
        let banner_name = scenario.name("server");
        tcp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr.into() }, sandbox.host_addr, 18080)
            .expect_connected(&banner_name, 8080)
            .await?;
        tcp(Origin::Container(&intruder.name), server.ip_on(&net).await?, 8080)
            .expect_dropped()
            .await
    }
}

e2e! {
    /// A managed container joining a network at runtime is protected there too.
    async fn network_joined_at_runtime_is_enforced(scenario) {
        let front = scenario.network("front").await?;
        let back = scenario.network("back").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&front).managed()).await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&back)).await?;
        let peer = scenario.run(ContainerSpec::new(scenario.name("peer")).network(&back)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        server.connect(&back).await?;
        tcp(Origin::Container(&intruder.name), peer.ip_on(&back).await?, 8080)
            .expect_connected(&peer.name, 8080)
            .await?;
        tcp(Origin::Container(&intruder.name), server.ip_on(&back).await?, 8080)
            .expect_dropped_eventually()
            .await?;

        server.disconnect(&back).await?;
        scenario.wait_until_managed(&server).await.map(drop)
    }
}

e2e! {
    /// Docker restarting drops harborshield's event stream and restarts every container; the
    /// daemon must resync, report ready again and enforce the rules on the new containers.
    async fn enforcement_survives_a_docker_daemon_restart(scenario) {
        let net = scenario.network("net").await?;
        let server_name = scenario.name("server");
        let server = scenario
            .run(ContainerSpec::new(&server_name).network(&net).managed().restart_always())
            .await?;
        let rules = json!({
            "output": [{ "container": server_name, "network": net.name, "proto": "tcp", "dst_ports": [8080] }]
        });
        let client = scenario
            .run(ContainerSpec::new(scenario.name("client")).network(&net).rules(rules.to_string()).restart_always())
            .await?;
        let intruder = scenario
            .run(ContainerSpec::new(scenario.name("intruder")).network(&net).restart_always())
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        scenario.wait_until_managed(&client).await?;

        restart_docker_daemon().await?;
        for container in [&server, &client, &intruder] {
            container.wait_for_listeners(&[crate::support::Listener::Tcp(8080)]).await?;
        }
        let deadline = deadline_in(Duration::from_secs(90));
        loop {
            let (status, _) = scenario.daemon()?.get("/ready").await?;
            if status == 200 {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Failure::new("harborshield never became ready again after Docker restarted"));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        scenario.wait_until_managed(&server).await?;
        scenario.wait_until_managed(&client).await?;

        let server_ip = server.ip_on(&net).await?;
        tcp(Origin::Container(&client.name), server_ip, 8080)
            .expect_connected(&server_name, 8080)
            .await?;
        tcp(Origin::Container(&intruder.name), server_ip, 8080)
            .expect_dropped_eventually()
            .await
    }
}
