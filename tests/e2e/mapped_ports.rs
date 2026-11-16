//! `mapped_ports`: who may reach a container's published ports, from the Docker host itself
//! and from outside it.

use std::net::Ipv4Addr;

use serde_json::json;

use crate::support::{ContainerSpec, Origin, e2e, tcp, udp};

e2e! {
    async fn localhost_rule_admits_the_docker_host_only(scenario) {
        let net = scenario.network("net").await?;
        let rules = json!({ "mapped_ports": { "localhost": { "allow": true } } });
        let server = scenario
            .run(ContainerSpec::new(scenario.name("server")).network(&net).publish("18080:8080").rules(rules.to_string()))
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        tcp(Origin::Localhost, Ipv4Addr::LOCALHOST, 18080)
            .expect_connected(&server.name, 8080)
            .await?;
        let outside = Origin::External { sandbox: &scenario.sandbox, source: scenario.sandbox.external_addr.into() };
        tcp(outside, scenario.sandbox.host_addr, 18080)
            .expect_dropped()
            .await
    }
}

e2e! {
    async fn external_rule_admits_outside_sources_only(scenario) {
        let net = scenario.network("net").await?;
        let rules = json!({ "mapped_ports": { "external": { "allow": true } } });
        let server = scenario
            .run(ContainerSpec::new(scenario.name("server")).network(&net).publish("18080:8080").rules(rules.to_string()))
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        let sandbox = scenario.sandbox.clone();
        for source in [sandbox.external_addr, sandbox.foreign_addr] {
            tcp(Origin::External { sandbox: &sandbox, source: source.into() }, sandbox.host_addr, 18080)
                .expect_connected(&server.name, 8080)
                .await?;
        }
        tcp(Origin::Localhost, Ipv4Addr::LOCALHOST, 18080)
            .expect_dropped()
            .await
    }
}

e2e! {
    async fn external_allowlist_admits_listed_sources_only(scenario) {
        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let rules = json!({
            "mapped_ports": { "external": { "allow": true, "ips": [sandbox.external_addr.to_string()] } }
        });
        let server = scenario
            .run(ContainerSpec::new(scenario.name("server")).network(&net).publish("18080:8080").rules(rules.to_string()))
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        tcp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr.into() }, sandbox.host_addr, 18080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::External { sandbox: &sandbox, source: sandbox.foreign_addr.into() }, sandbox.host_addr, 18080)
            .expect_dropped()
            .await
    }
}

e2e! {
    /// Several allowlist entries, mixing CIDR and range forms, all take effect together.
    async fn external_allowlist_accepts_cidr_and_range_entries(scenario) {
        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let rules = json!({
            "mapped_ports": { "external": {
                "allow": true,
                "ips": ["10.9.0.1-10.9.0.9", format!("{}/32", sandbox.external_addr)],
            } }
        });
        let server = scenario
            .run(ContainerSpec::new(scenario.name("server")).network(&net).publish("18080:8080").rules(rules.to_string()))
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        tcp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr.into() }, sandbox.host_addr, 18080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::External { sandbox: &sandbox, source: sandbox.foreign_addr.into() }, sandbox.host_addr, 18080)
            .expect_dropped()
            .await
    }
}

e2e! {
    async fn published_port_without_mapped_rules_is_dropped(scenario) {
        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let server = scenario
            .run(ContainerSpec::new(scenario.name("server")).network(&net).publish("18080:8080").managed())
            .await?;
        let twin = scenario
            .run(ContainerSpec::new(scenario.name("twin")).network(&net).publish("18081:8080"))
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        tcp(Origin::Localhost, Ipv4Addr::LOCALHOST, 18081)
            .expect_connected(&twin.name, 8080)
            .await?;
        tcp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr.into() }, sandbox.host_addr, 18081)
            .expect_connected(&twin.name, 8080)
            .await?;

        tcp(Origin::Localhost, Ipv4Addr::LOCALHOST, 18080)
            .expect_dropped()
            .await?;
        tcp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr.into() }, sandbox.host_addr, 18080)
            .expect_dropped()
            .await
    }
}

e2e! {
    async fn udp_published_port_follows_the_external_rule(scenario) {
        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let rules = json!({
            "mapped_ports": { "external": { "allow": true, "ips": [sandbox.external_addr.to_string()] } }
        });
        let server = scenario
            .run(
                ContainerSpec::new(scenario.name("server"))
                    .network(&net)
                    .udp(5353)
                    .publish("15353:5353/udp")
                    .rules(rules.to_string()),
            )
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        udp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr.into() }, sandbox.host_addr, 15353)
            .expect_connected(&server.name, 5353)
            .await?;
        udp(Origin::External { sandbox: &sandbox, source: sandbox.foreign_addr.into() }, sandbox.host_addr, 15353)
            .expect_dropped()
            .await
    }
}

e2e! {
    /// Published ports reached over IPv6 honour the same allowlist.
    async fn external_allowlist_applies_over_ipv6(scenario) {
        let net = scenario.network_ipv6("net6", "fd00:e2e:2::/64").await?;
        let sandbox = scenario.sandbox.clone();
        let rules = json!({
            "mapped_ports": { "external": { "allow": true, "ips": [sandbox.external_addr6.to_string()] } }
        });
        let server = scenario
            .run(ContainerSpec::new(scenario.name("server")).network(&net).publish("18080:8080").rules(rules.to_string()))
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        tcp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr6.into() }, sandbox.host_addr6, 18080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::External { sandbox: &sandbox, source: sandbox.foreign_addr6.into() }, sandbox.host_addr6, 18080)
            .expect_dropped()
            .await?;
        // The allowlist names only an IPv6 source, so IPv4 gets nothing.
        tcp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr.into() }, sandbox.host_addr, 18080)
            .expect_dropped()
            .await
    }
}
