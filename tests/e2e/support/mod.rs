mod command;
mod daemon;
mod database;
mod docker;
mod failure;
mod host;
mod nft;
mod probe;
mod queue;
mod sandbox;
mod scenario;
mod time;

pub use database::stored_container_ids;
pub use docker::{Container, ContainerSpec, FIXTURE_IMAGE, Listener, Network, docker};
pub use failure::{Failure, TestResult};
pub use host::{
    BannerService, SECOND_BRIDGED, bridged_namespaces, ensure_ip_filter_table,
    restart_docker_daemon,
};
pub use nft::{BASE_CHAINS, TABLE, nft, ruleset};
pub use probe::{Origin, tcp, udp};
pub use queue::QueueConsumer;
pub use scenario::{Cleanup, Scenario, run_scenario};
pub use time::deadline_in;

/// Declare an e2e test: it runs inside a fresh [`Scenario`] that is always torn down, and is
/// ignored by plain `cargo test` because it needs the privileged sandbox.
macro_rules! e2e {
    ($(#[$meta:meta])* async fn $name:ident($scenario:ident) $body:block) => {
        $(#[$meta])*
        #[tokio::test]
        #[ignore = "e2e: needs the privileged sandbox, run with `cargo xtask e2e`"]
        async fn $name() -> $crate::support::TestResult {
            $crate::support::run_scenario(
                stringify!($name),
                async |$scenario: &mut $crate::support::Scenario| $body,
            )
            .await
        }
    };
}
pub(crate) use e2e;
