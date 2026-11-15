//! Default-deny: what a managed container may not do without rules, and that unmanaged
//! containers are left alone.

use serde_json::json;

use crate::support::{ContainerSpec, Failure, Origin, e2e, ruleset, tcp};

e2e! {
    async fn unmanaged_containers_are_untouched(scenario) {
        let net = scenario.network("net").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&net)).await?;
        let client = scenario.run(ContainerSpec::new(scenario.name("client")).network(&net)).await?;
        scenario.start_daemon().await?;

        tcp(Origin::Container(&client.name), server.ip_on(&net).await?, 8080)
            .expect_connected(&server.name, 8080)
            .await?;

        let rules = ruleset().await?;
        for container in [&server, &client] {
            if let Some(chain) = rules.chain_for(container) {
                return Err(Failure::new(format!(
                    "unmanaged {} got chain {chain}",
                    container.name
                )));
            }
        }
        Ok(())
    }
}

e2e! {
    async fn managed_container_drops_inbound_by_default(scenario) {
        let net = scenario.network("net").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&net).managed()).await?;
        let peer = scenario.run(ContainerSpec::new(scenario.name("peer")).network(&net)).await?;
        let client = scenario.run(ContainerSpec::new(scenario.name("client")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        tcp(Origin::Container(&client.name), peer.ip_on(&net).await?, 8080)
            .expect_connected(&peer.name, 8080)
            .await?;
        tcp(Origin::Container(&client.name), server.ip_on(&net).await?, 8080)
            .expect_dropped()
            .await
    }
}

e2e! {
    async fn managed_container_drops_outbound_by_default(scenario) {
        let net = scenario.network("net").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&net)).await?;
        let peer = scenario.run(ContainerSpec::new(scenario.name("peer")).network(&net)).await?;
        let client = scenario.run(ContainerSpec::new(scenario.name("client")).network(&net).managed()).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&client).await?;

        let server_ip = server.ip_on(&net).await?;
        let external = scenario.sandbox.external_addr;
        tcp(Origin::Container(&peer.name), server_ip, 8080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::Container(&peer.name), external, 7000)
            .expect_connected("external", 7000)
            .await?;

        tcp(Origin::Container(&client.name), server_ip, 8080)
            .expect_dropped()
            .await?;
        tcp(Origin::Container(&client.name), external, 7000)
            .expect_dropped()
            .await
    }
}

e2e! {
    /// Each container started after the first must still be enforced: dispatch for earlier
    /// containers must survive later ones.
    async fn every_managed_container_is_enforced(scenario) {
        let net = scenario.network("net").await?;
        let client = scenario.run(ContainerSpec::new(scenario.name("client")).network(&net)).await?;
        scenario.start_daemon().await?;

        let mut servers = Vec::new();
        for index in 1..=3 {
            let server = scenario
                .run(ContainerSpec::new(scenario.name(&format!("server{index}"))).network(&net).managed())
                .await?;
            scenario.wait_until_managed(&server).await?;
            servers.push(server);
        }
        for server in &servers {
            tcp(Origin::Container(&client.name), server.ip_on(&net).await?, 8080)
                .expect_dropped()
                .await?;
        }
        Ok(())
    }
}

e2e! {
    async fn intruder_on_the_same_network_is_dropped(scenario) {
        let net = scenario.network("net").await?;
        let server_name = scenario.name("server");
        let server = scenario.run(ContainerSpec::new(&server_name).network(&net).managed()).await?;
        let rules = json!({
            "output": [{
                "container": server_name,
                "network": net.name,
                "proto": "tcp",
                "dst_ports": [8080],
            }]
        });
        let client = scenario
            .run(ContainerSpec::new(scenario.name("client")).network(&net).rules(rules.to_string()))
            .await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        scenario.wait_until_managed(&client).await?;

        let server_ip = server.ip_on(&net).await?;
        tcp(Origin::Container(&client.name), server_ip, 8080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::Container(&intruder.name), server_ip, 8080)
            .expect_dropped()
            .await
    }
}

e2e! {
    /// A managed container on a dual-stack network is protected over IPv6 too.
    async fn managed_container_drops_ipv6_by_default(scenario) {
        let net = scenario.network_ipv6("net6", "fd00:e2e:1::/64").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&net).managed()).await?;
        let peer = scenario.run(ContainerSpec::new(scenario.name("peer")).network(&net)).await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        tcp(Origin::Container(&intruder.name), peer.ip6_on(&net).await?, 8080)
            .expect_connected(&peer.name, 8080)
            .await?;
        tcp(Origin::Container(&intruder.name), server.ip6_on(&net).await?, 8080)
            .expect_dropped()
            .await?;
        tcp(Origin::Container(&intruder.name), server.ip_on(&net).await?, 8080)
            .expect_dropped()
            .await
    }
}
