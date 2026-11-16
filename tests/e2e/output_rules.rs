//! `output` rules: what a managed container may reach, by container reference or address.

use serde_json::json;

use crate::support::{ContainerSpec, Origin, e2e, tcp, udp};

e2e! {
    async fn container_rule_admits_the_listed_port_only(scenario) {
        let net = scenario.network("net").await?;
        let server_name = scenario.name("server");
        let server = scenario
            .run(ContainerSpec::new(&server_name).network(&net).tcp(8080).tcp(9090).managed())
            .await?;
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
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        scenario.wait_until_managed(&client).await?;

        let server_ip = server.ip_on(&net).await?;
        tcp(Origin::Container(&client.name), server_ip, 8080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::Container(&client.name), server_ip, 9090)
            .expect_dropped()
            .await?;
        // The rule opens client -> server only, never the reverse direction.
        tcp(Origin::Container(&server.name), client.ip_on(&net).await?, 8080)
            .expect_dropped()
            .await
    }
}

e2e! {
    async fn address_rule_admits_the_listed_destination_only(scenario) {
        let net = scenario.network("net").await?;
        let external = scenario.sandbox.external_addr;
        let foreign = scenario.sandbox.foreign_addr;
        let rules = json!({
            "output": [{ "ips": [external.to_string()], "proto": "tcp", "dst_ports": [7000] }]
        });
        let client = scenario
            .run(ContainerSpec::new(scenario.name("client")).network(&net).rules(rules.to_string()))
            .await?;
        let peer = scenario.run(ContainerSpec::new(scenario.name("peer")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&client).await?;

        tcp(Origin::Container(&peer.name), external, 7001)
            .expect_connected("external", 7001)
            .await?;
        tcp(Origin::Container(&peer.name), foreign, 7000)
            .expect_connected("external", 7000)
            .await?;

        tcp(Origin::Container(&client.name), external, 7000)
            .expect_connected("external", 7000)
            .await?;
        tcp(Origin::Container(&client.name), external, 7001)
            .expect_dropped()
            .await?;
        tcp(Origin::Container(&client.name), foreign, 7000)
            .expect_dropped()
            .await
    }
}

e2e! {
    async fn udp_rule_admits_the_listed_port_only(scenario) {
        let net = scenario.network("net").await?;
        let external = scenario.sandbox.external_addr;
        let rules = json!({
            "output": [{ "ips": [external.to_string()], "proto": "udp", "dst_ports": [7053] }]
        });
        let client = scenario
            .run(ContainerSpec::new(scenario.name("client")).network(&net).rules(rules.to_string()))
            .await?;
        let peer = scenario.run(ContainerSpec::new(scenario.name("peer")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&client).await?;

        udp(Origin::Container(&peer.name), external, 7054)
            .expect_connected("external", 7054)
            .await?;
        udp(Origin::Container(&client.name), external, 7053)
            .expect_connected("external", 7053)
            .await?;
        udp(Origin::Container(&client.name), external, 7054)
            .expect_dropped()
            .await
    }
}

e2e! {
    async fn port_range_rule_admits_ports_inside_the_range_only(scenario) {
        let net = scenario.network("net").await?;
        let server_name = scenario.name("server");
        let server = scenario
            .run(ContainerSpec::new(&server_name).network(&net).tcp(8080).tcp(8081).tcp(8082).managed())
            .await?;
        let rules = json!({
            "output": [{
                "container": server_name,
                "network": net.name,
                "proto": "tcp",
                "dst_ports": ["8080-8081"],
            }]
        });
        let client = scenario
            .run(ContainerSpec::new(scenario.name("client")).network(&net).rules(rules.to_string()))
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        scenario.wait_until_managed(&client).await?;

        let server_ip = server.ip_on(&net).await?;
        for port in [8080, 8081] {
            tcp(Origin::Container(&client.name), server_ip, port)
                .expect_connected(&server.name, port)
                .await?;
        }
        tcp(Origin::Container(&client.name), server_ip, 8082)
            .expect_dropped()
            .await
    }
}

e2e! {
    /// A rule naming a container that does not exist yet takes effect once it starts.
    async fn rule_waits_for_a_target_that_starts_later(scenario) {
        let net = scenario.network("net").await?;
        let server_name = scenario.name("server");
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
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&client).await?;

        let server = scenario
            .run(ContainerSpec::new(&server_name).network(&net).tcp(8080).tcp(9090).managed())
            .await?;
        scenario.wait_until_managed(&server).await?;

        let server_ip = server.ip_on(&net).await?;
        tcp(Origin::Container(&client.name), server_ip, 8080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::Container(&client.name), server_ip, 9090)
            .expect_dropped()
            .await
    }
}

e2e! {
    /// `network` scopes a container rule to the target's address on that network alone.
    async fn container_rule_targets_only_the_named_network(scenario) {
        let front = scenario.network("front").await?;
        let back = scenario.network("back").await?;
        let server_name = scenario.name("server");
        let server = scenario
            .run(ContainerSpec::new(&server_name).network(&front).network(&back).managed())
            .await?;
        let rules = json!({
            "output": [{
                "container": server_name,
                "network": back.name,
                "proto": "tcp",
                "dst_ports": [8080],
            }]
        });
        let client = scenario
            .run(
                ContainerSpec::new(scenario.name("client"))
                    .network(&front)
                    .network(&back)
                    .rules(rules.to_string()),
            )
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        scenario.wait_until_managed(&client).await?;

        tcp(Origin::Container(&client.name), server.ip_on(&back).await?, 8080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::Container(&client.name), server.ip_on(&front).await?, 8080)
            .expect_dropped()
            .await
    }
}

e2e! {
    /// Allowed traffic flows over IPv6 too, between two managed containers, while everything
    /// else stays dropped. Neighbour discovery must work for any of it to.
    async fn container_rule_admits_traffic_over_ipv6(scenario) {
        let net = scenario.network_ipv6("net6", "fd00:e2e:3::/64").await?;
        let server_name = scenario.name("server");
        let server = scenario.run(ContainerSpec::new(&server_name).network(&net).managed()).await?;
        let rules = json!({
            "output": [{ "container": server_name, "network": net.name, "proto": "tcp", "dst_ports": [8080] }]
        });
        let client = scenario
            .run(ContainerSpec::new(scenario.name("client")).network(&net).rules(rules.to_string()))
            .await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        scenario.wait_until_managed(&client).await?;

        let server_ip6 = server.ip6_on(&net).await?;
        tcp(Origin::Container(&client.name), server_ip6, 8080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::Container(&intruder.name), server_ip6, 8080)
            .expect_dropped()
            .await
    }
}
