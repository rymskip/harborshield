//! Verdict options on a rule: a jump to a user chain, an nfqueue, and logging.

use serde_json::json;

use crate::support::{ContainerSpec, Failure, Origin, TABLE, e2e, nft, ruleset, tcp};

const ACCEPT_CHAIN: &str = "e2e-verdict-accept";
const DROP_CHAIN: &str = "e2e-verdict-drop";

e2e! {
    /// A jump verdict hands the decision to the user's chain: its counter sees the traffic and
    /// its own verdict wins. Jump targets live in harborshield's tables, which users create
    /// ahead of the daemon when they need verdict chains; published-port traffic is routed, so
    /// the `inet` table's chain decides it.
    async fn verdict_chain_decides_the_traffic(scenario) {
        nft(&["add", "table", "inet", TABLE]).await?;
        for (chain, verdict) in [(ACCEPT_CHAIN, "accept"), (DROP_CHAIN, "drop")] {
            nft(&["add", "chain", "inet", TABLE, chain]).await?;
            nft(&["add", "rule", "inet", TABLE, chain, "counter", verdict]).await?;
        }

        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let accepting = json!({ "mapped_ports": { "external": { "allow": true, "verdict": { "chain": ACCEPT_CHAIN } } } });
        let dropping = json!({ "mapped_ports": { "external": { "allow": true, "verdict": { "chain": DROP_CHAIN } } } });
        let open = scenario
            .run(ContainerSpec::new(scenario.name("open")).network(&net).publish("18080:8080").rules(accepting.to_string()))
            .await?;
        let shut = scenario
            .run(ContainerSpec::new(scenario.name("shut")).network(&net).publish("18081:8080").rules(dropping.to_string()))
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&open).await?;
        scenario.wait_until_managed(&shut).await?;

        let outside = || Origin::External { sandbox: &sandbox, source: sandbox.external_addr };
        tcp(outside(), sandbox.host_addr, 18080)
            .expect_connected(&open.name, 8080)
            .await?;
        tcp(outside(), sandbox.host_addr, 18081).expect_dropped().await?;

        let rules = ruleset().await?;
        for chain in [ACCEPT_CHAIN, DROP_CHAIN] {
            if rules.packets_counted(chain) == 0 {
                return Err(Failure::new(format!("verdict chain {chain} never saw a packet")));
            }
        }
        Ok(())
    }
}

e2e! {
    /// A rule jumping to a chain that does not exist is left out, failing closed for that
    /// rule alone, instead of failing the whole ruleset for every container.
    async fn missing_verdict_chain_fails_closed_without_blocking_others(scenario) {
        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let broken = json!({ "mapped_ports": { "external": { "allow": true, "verdict": { "chain": "e2e-no-such-chain" } } } });
        let healthy = json!({ "mapped_ports": { "external": { "allow": true } } });
        let shut = scenario
            .run(ContainerSpec::new(scenario.name("shut")).network(&net).publish("18080:8080").rules(broken.to_string()))
            .await?;
        let open = scenario
            .run(ContainerSpec::new(scenario.name("open")).network(&net).publish("18081:8080").rules(healthy.to_string()))
            .await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&shut).await?;
        scenario.wait_until_managed(&open).await?;

        let outside = || Origin::External { sandbox: &sandbox, source: sandbox.external_addr };
        tcp(outside(), sandbox.host_addr, 18081)
            .expect_connected(&open.name, 8080)
            .await?;
        tcp(outside(), sandbox.host_addr, 18080).expect_dropped().await
    }
}

e2e! {
    /// Queued packets with no consumer on the queue are dropped by the kernel. The
    /// established-traffic queues get their own rules ahead of the established accept.
    async fn queue_verdict_without_a_consumer_drops(scenario) {
        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let rules = json!({ "mapped_ports": { "external": { "allow": true, "verdict": {
            "queue": 100, "input_est_queue": 101, "output_est_queue": 102
        } } } });
        let server = scenario
            .run(ContainerSpec::new(scenario.name("server")).network(&net).publish("18080:8080").rules(rules.to_string()))
            .await?;
        scenario.start_daemon().await?;
        let chain = scenario.wait_until_managed(&server).await?;

        let queues = ruleset().await?.queues(&chain)?;
        for expected in ["100", "101", "102"] {
            if !queues.iter().any(|queue| queue == expected) {
                return Err(Failure::new(format!("{chain} has no queue {expected} rule: {queues:?}")));
            }
        }
        tcp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr }, sandbox.host_addr, 18080)
            .expect_dropped()
            .await
    }
}

e2e! {
    /// Kernel log output is not observable from inside a network namespace, so this checks
    /// the installed statements and that logging does not change the verdict.
    async fn log_prefixes_are_installed_on_matching_rules(scenario) {
        let net = scenario.network("net").await?;
        let sandbox = scenario.sandbox.clone();
        let rules = json!({
            "mapped_ports": { "external": { "allow": true, "log_prefix": "e2e-mapped" } },
            "output": [{
                "ips": [sandbox.external_addr.to_string()],
                "proto": "tcp",
                "dst_ports": [7000],
                "log_prefix": "e2e-output",
            }]
        });
        let server = scenario
            .run(ContainerSpec::new(scenario.name("server")).network(&net).publish("18080:8080").rules(rules.to_string()))
            .await?;
        scenario.start_daemon().await?;
        let chain = scenario.wait_until_managed(&server).await?;

        let prefixes = ruleset().await?.log_prefixes(&chain);
        for expected in ["e2e-mapped", "e2e-output"] {
            if !prefixes.iter().any(|prefix| prefix.starts_with(expected)) {
                return Err(Failure::new(format!("{chain} lacks log prefix {expected}: {prefixes:?}")));
            }
        }
        tcp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr }, sandbox.host_addr, 18080)
            .expect_connected(&server.name, 8080)
            .await?;
        tcp(Origin::Container(&server.name), sandbox.external_addr, 7000)
            .expect_connected("external", 7000)
            .await
    }
}
