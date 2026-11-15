# End-to-end tests

The e2e suite runs the real `harborshield` binary against a real Docker daemon and kernel
firewall, and checks every expectation by sending traffic.

```sh
cargo xtask e2e              # whole suite, plus the unit tests that need root
cargo xtask e2e lifecycle    # only e2e tests whose name contains "lifecycle"
```

Logs land in `target/e2e/logs/<test>/`: each harborshield run's stdout and stderr, plus the
sandbox's `dockerd.log`.

## The sandbox

The suite rewrites the firewall and removes containers, so it never runs on the host.
`cargo xtask e2e` builds the test binaries on the host, then runs them inside a privileged
container (`tests/e2e/images/sandbox.Dockerfile`) that has its own `dockerd`, network namespace
and nftables ruleset. The tests refuse to start unless `HARBORSHIELD_E2E_SANDBOX=1`, which only
the sandbox image sets, and plain `cargo test` skips them as ignored.

The inner daemon's images live in the `harborshield-e2e-docker` volume, so only the first run
pulls. Only one sandbox runs at a time, since the volume cannot be shared by two daemons.

Inside the sandbox:

- **Workload containers** run `harborshield-e2e-fixture`, built from
  `tests/e2e/images/fixture.Dockerfile`. Each serves a banner `hs-e2e <name> <port>` on its
  listeners, so a probe proves which service answered, not just that a port was open.
- **The external host** is a network namespace, `hs-ext`, behind a veth at `198.18.0.1`. It has
  two source addresses: `198.18.0.2`, which allowlists in the tests permit, and `198.18.0.3`,
  which they do not. It also serves banners on TCP 7000/7001 and UDP 7053/7054 for output rules
  that target addresses outside Docker.
- **Probes** (`hs-probe`) print exactly one verdict: `CONNECTED <banner>`, `REFUSED`,
  `TIMEOUT`, or `SILENT` (a TCP connection opened but no service answered). Anything else,
  such as a missing binary or an unreachable route, fails the test rather than counting as a
  drop. A drop is `TIMEOUT`, except from the Docker host itself: there docker-proxy accepts the
  connection and a dropped backend shows as `SILENT`.

## How a test reads

```rust
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
```

Rules every test follows:

- **A drop needs a control.** Every `expect_dropped` sits next to an `expect_connected` that
  proves the source can send and the target's listener is up, so the drop is harborshield's.
  Each container's listeners are also checked over its own loopback before the test uses them.
- **Converge, then assert.** `wait_until_managed` waits until the container has its chain and
  the dispatch rules reference it. After that a single probe is authoritative.
  `expect_dropped_eventually` is only for runtime changes harborshield applies asynchronously,
  such as a network joined while running.
- **Teardown always runs.** `e2e!` wraps each test in a scenario that stops harborshield (and
  requires a clean exit), removes every container and network carrying the scenario's label,
  runs `harborshield --clear`, and fails if any harborshield state remains. A preflight repairs
  state left by an interrupted run before the next test starts.

## Coverage

| Area | Tests |
| --- | --- |
| Default deny | inbound, outbound, IPv6, several containers at once, an intruder on the same network, unmanaged containers left alone |
| Output rules | container reference (listed port only, not the reverse direction), address rule, UDP, port range, a target that starts later, scoping to the named network |
| Mapped ports | localhost only, external only, allowlist, CIDR and range entries, published port without rules, UDP |
| Verdicts | jump to a user chain, a missing user chain failing closed for that rule only, nfqueue with established queues, log prefixes |
| Lifecycle | stop and start, `docker stop` staying stopped (also across a daemon restart), removal, pause and unpause, rename, network joined at runtime |
| Persistence | containers running before start, rules holding while the daemon is stopped, restart without duplicate rules, crash recovery, `--clear` |
| Start-up | both tables and their hooked base chains, health endpoints, invalid rules failing closed, removal of the legacy `ip filter` layout |
| Compose | a three-service stack using compose-local service and network names |

The privileged unit tests (`cargo test --lib -- --ignored`) run in the same sandbox.

## Known limits

- Kernel log output is not observable from inside a network namespace, so log prefixes are
  checked as installed statements rather than as log lines.
- The external host reaches published ports through DNAT; Docker's `userland-proxy` handles
  the localhost path, which is the default Docker setup. A daemon with the proxy disabled is
  not exercised.
