//! harborshield alongside other firewalls and networks on the same host: its accepts never
//! override another table's drop, and it leaves traffic it does not manage alone.

use serde_json::json;

use crate::support::{
    BannerService, Cleanup, ContainerSpec, Origin, SECOND_BRIDGED, bridged_namespaces, e2e, nft,
    tcp,
};

e2e! {
    /// A host firewall dropping a port on the forward path still drops it for a container
    /// harborshield allows.
    async fn a_drop_in_another_table_still_wins(scenario) {
        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let rules = json!({ "mapped_ports": { "external": { "allow": true } } });
        let server = scenario
            .run(ContainerSpec::new(scenario.name("server")).network(&net).publish("18080:8080").rules(rules.to_string()))
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;

        let outside = || Origin::External { sandbox: &sandbox, source: sandbox.external_addr.into() };
        tcp(outside(), sandbox.host_addr, 18080)
            .expect_connected(&server.name, 8080)
            .await?;

        nft(&["add", "table", "inet", "e2e_other"]).await?;
        scenario.on_teardown(Cleanup::NftTable { family: "inet", name: "e2e_other".to_owned() });
        nft(&["add", "chain", "inet", "e2e_other", "forward",
            "{ type filter hook forward priority 10; policy accept; }"]).await?;
        nft(&["add", "rule", "inet", "e2e_other", "forward", "tcp", "dport", "8080", "drop"]).await?;

        tcp(outside(), sandbox.host_addr, 18080).expect_dropped().await
    }
}

e2e! {
    /// A container harborshield lets reach a host service is still subject to the host's own
    /// input rules.
    async fn container_traffic_to_the_host_obeys_other_tables(scenario) {
        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let _host_service = BannerService::start("host", None, sandbox.host_addr, &[7100, 7101]).await?;
        let rules = json!({
            "output": [{ "ips": [sandbox.host_addr.to_string()], "proto": "tcp", "dst_ports": [7100, 7101] }]
        });
        let client = scenario
            .run(ContainerSpec::new(scenario.name("client")).network(&net).rules(rules.to_string()))
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&client).await?;

        for port in [7100, 7101] {
            tcp(Origin::Container(&client.name), sandbox.host_addr, port)
                .expect_connected("host", port)
                .await?;
        }

        nft(&["add", "table", "inet", "e2e_host"]).await?;
        scenario.on_teardown(Cleanup::NftTable { family: "inet", name: "e2e_host".to_owned() });
        nft(&["add", "chain", "inet", "e2e_host", "input",
            "{ type filter hook input priority 10; policy accept; }"]).await?;
        nft(&["add", "rule", "inet", "e2e_host", "input", "tcp", "dport", "7100", "drop"]).await?;

        tcp(Origin::Container(&client.name), sandbox.host_addr, 7100)
            .expect_dropped()
            .await?;
        tcp(Origin::Container(&client.name), sandbox.host_addr, 7101)
            .expect_connected("host", 7101)
            .await
    }
}

e2e! {
    /// A bridge Docker does not own (LXD, libvirt, a hand-made one) keeps working while
    /// harborshield filters Docker's bridges.
    async fn unrelated_bridges_are_untouched(scenario) {
        let net = scenario.network("net").await?;
        let server = scenario.run(ContainerSpec::new(scenario.name("server")).network(&net).managed()).await?;
        let bridged = bridged_namespaces(scenario).await?;
        let _service = BannerService::start("bridged", Some(&bridged.second), SECOND_BRIDGED, &[9000]).await?;

        tcp(Origin::Namespace(&bridged.first), SECOND_BRIDGED, 9000)
            .expect_connected("bridged", 9000)
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&server).await?;
        tcp(Origin::Namespace(&bridged.first), SECOND_BRIDGED, 9000)
            .expect_connected("bridged", 9000)
            .await
    }
}
