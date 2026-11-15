pub mod compose;
pub mod config;
pub mod container;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bollard::Docker;
use bollard::models::{ContainerInspectResponse, ContainerSummary, EventMessage};
use bollard::query_parameters::{
    EventsOptionsBuilder, InspectContainerOptionsBuilder, ListContainersOptionsBuilder,
};
use futures::stream::{Stream, StreamExt};
use tokio::time::timeout;

use crate::docker::container::{Container, Tracker};
use crate::{Error, Result};

#[cfg(test)]
mod tests;

/// Docker API access, every request bounded by a timeout, plus the container tracker.
pub struct DockerClient {
    client: Docker,
    timeout_duration: Duration,
    pub container_tracker: Arc<Tracker>,
}

impl DockerClient {
    /// Connect the way the Docker CLI does: `DOCKER_HOST`, with TLS from `DOCKER_TLS_VERIFY`
    /// and `DOCKER_CERT_PATH`. No request is made yet.
    pub fn connect(timeout_duration: Duration) -> Result<Self> {
        Ok(Self {
            client: Docker::connect_with_defaults()?,
            timeout_duration,
            container_tracker: Arc::new(Tracker::default()),
        })
    }

    /// The same client speaking the newest API version both sides support, so an older
    /// daemon is addressed in a version it understands.
    pub async fn negotiated(&self) -> Result<Self> {
        let client = timeout(
            self.timeout_duration,
            self.client.clone().negotiate_version(),
        )
        .await
        .map_err(|_elapsed| Error::timeout(self.timeout_duration, "negotiate the API version"))??;
        Ok(Self {
            client,
            timeout_duration: self.timeout_duration,
            container_tracker: Arc::clone(&self.container_tracker),
        })
    }

    /// Running containers.
    pub async fn list_containers(&self) -> Result<Vec<ContainerSummary>> {
        let options = ListContainersOptionsBuilder::default().all(false).build();
        Ok(timeout(
            self.timeout_duration,
            self.client.list_containers(Some(options)),
        )
        .await
        .map_err(|_elapsed| Error::timeout(self.timeout_duration, "list containers"))??)
    }

    async fn inspect_container(&self, id: &str) -> Result<ContainerInspectResponse> {
        let options = InspectContainerOptionsBuilder::default().build();
        Ok(timeout(
            self.timeout_duration,
            self.client.inspect_container(id, Some(options)),
        )
        .await
        .map_err(|_elapsed| Error::timeout(self.timeout_duration, "inspect a container"))??)
    }

    /// The running container `id`, or `None` when it has exited or no longer exists.
    pub async fn inspect_running(&self, id: &str) -> Result<Option<Container>> {
        let inspect = match self.inspect_container(id).await {
            Ok(inspect) => inspect,
            Err(Error::Docker(bollard::errors::Error::DockerResponseServerError {
                status_code: 404,
                ..
            })) => return Ok(None),
            Err(other) => return Err(other),
        };
        let running = inspect
            .state
            .as_ref()
            .and_then(|state| state.running)
            .unwrap_or(false);
        if running {
            Container::from_inspect(inspect).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Container and network events from `since` (a Unix timestamp) onwards. The stream ends
    /// or fails when the daemon connection does.
    pub fn events(&self, since: i64) -> impl Stream<Item = Result<EventMessage>> + use<> {
        let filters = HashMap::from([
            ("type", vec!["container", "network"]),
            (
                "event",
                vec!["start", "die", "rename", "connect", "disconnect"],
            ),
        ]);
        let options = EventsOptionsBuilder::default()
            .since(&since.to_string())
            .filters(&filters)
            .build();
        self.client
            .events(Some(options))
            .map(|event| event.map_err(Error::Docker))
    }
}
