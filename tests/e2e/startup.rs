//! Daemon start-up: base chain installation, health endpoints, and bad input.

use crate::support::{BASE_CHAINS, ContainerSpec, Failure, Origin, TABLE, e2e, nft, ruleset, tcp};

e2e! {
    async fn installs_its_table_and_serves_health_endpoints(scenario) {
        scenario.start_daemon().await?;

        let rules = ruleset().await?;
        for (family, chain, hook) in BASE_CHAINS {
            if rules.hook_of(family, chain) != Some(hook) {
                return Err(Failure::new(format!(
                    "base chain {chain} of {family:?} table {TABLE} should hook {hook:?} but hooks {:?}",
                    rules.hook_of(family, chain)
                )));
            }
        }

        let daemon = scenario.daemon()?;
        for (path, needle) in [
            ("/health", "healthy"),
            ("/ready", "ready"),
            ("/version", env!("CARGO_PKG_VERSION")),
            ("/metrics", "harborshield_"),
        ] {
            let (status, body) = daemon.get(path).await?;
            if status != 200 || !body.contains(needle) {
                return Err(Failure::new(format!(
                    "{path} answered {status} without {needle:?}: {body}"
                )));
            }
        }
        let (status, _) = daemon.get("/no-such-endpoint").await?;
        if status != 404 {
            return Err(Failure::new(format!("unknown path answered {status}, expected 404")));
        }
        Ok(())
    }
}

e2e! {
    /// A container whose rules do not parse stays fully denied, and the daemon keeps serving
    /// the containers that follow it.
    async fn invalid_rules_fail_closed(scenario) {
        let net = scenario.network("net").await?;
        let broken = scenario
            .run(ContainerSpec::new(scenario.name("broken")).network(&net).rules("output: [ {proto: tcp"))
            .await?;
        let intruder = scenario.run(ContainerSpec::new(scenario.name("intruder")).network(&net)).await?;
        scenario.start_daemon().await?;
        scenario.wait_until_managed(&broken).await?;

        tcp(Origin::Container(&intruder.name), broken.ip_on(&net).await?, 8080)
            .expect_dropped()
            .await?;

        let healthy = scenario.run(ContainerSpec::new(scenario.name("healthy")).network(&net).managed()).await?;
        scenario.wait_until_managed(&healthy).await?;
        let (status, body) = scenario.daemon()?.get("/health").await?;
        if status == 200 {
            Ok(())
        } else {
            Err(Failure::new(format!("daemon unhealthy after bad rules: {status} {body}")))
        }
    }
}

e2e! {
    /// Versions before the dedicated table jumped from Docker's chains into their own chain in
    /// `ip filter`; starting must remove all of it, leaving Docker's chains intact.
    async fn start_removes_objects_left_by_the_legacy_layout(scenario) {
        nft(&["add", "chain", "ip", "filter", "harborshield"]).await?;
        nft(&["add", "chain", "ip", "filter", "hs-legacy-0123456789ab"]).await?;
        nft(&["add", "rule", "ip", "filter", "harborshield", "jump", "hs-legacy-0123456789ab"]).await?;
        nft(&["insert", "rule", "ip", "filter", "DOCKER-USER", "jump", "harborshield"]).await?;

        scenario.start_daemon().await?;

        let rules = ruleset().await?;
        for chain in ["harborshield", "hs-legacy-0123456789ab"] {
            if rules.has_legacy_chain(chain) {
                return Err(Failure::new(format!("legacy chain ip filter {chain} survived start")));
            }
        }
        if !rules.has_legacy_chain("DOCKER-USER") {
            return Err(Failure::new("Docker's DOCKER-USER chain was removed"));
        }
        Ok(())
    }
}
