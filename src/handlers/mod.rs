//! Keeping the firewall in step with Docker: a full resync at start-up and after every lost
//! event stream, then one reconcile per relevant container event.

pub mod policy;

use std::time::Duration;

use bollard::models::EventMessage;
use futures::StreamExt;
use tracing::{debug, error, info, warn};

use crate::database::ContainerIdentifiers;
use crate::docker::container::Container;
use crate::nftables::{kernel, plan};
use crate::{Harborshield, Result, server};

/// Container attribute Docker puts on network connect and disconnect events.
const CONTAINER_ATTRIBUTE: &str = "container";
const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);

impl Harborshield {
    /// Rebuild harborshield's ruleset from the tracked containers in one transaction.
    pub(crate) async fn reconcile(&self) -> Result<()> {
        let _serial = self.firewall.lock().await;
        let desired = policy::desired_state(&self.docker_client.container_tracker.snapshot());
        let state = kernel::read_state().await?;
        kernel::apply(plan::reconcile(&state, &desired)).await?;
        server::set_active_containers(desired.len());
        server::increment_rules_applied();
        debug!(managed = desired.len(), "firewall reconciled");
        Ok(())
    }

    /// Replace the tracked containers with Docker's running ones and record the managed set.
    pub(crate) async fn resync(&self) -> Result<()> {
        let mut containers = Vec::new();
        for summary in self.docker_client.list_containers().await? {
            let Some(id) = summary.id else {
                warn!("Docker listed a container without an id; skipping it");
                continue;
            };
            // A container can exit between listing and inspecting it.
            if let Some(container) = self.docker_client.inspect_running(&id).await? {
                containers.push(container);
            }
        }
        for container in &containers {
            warn_if_unenforceable(container);
        }
        let managed: Vec<ContainerIdentifiers> = containers
            .iter()
            .filter(|container| container.enabled)
            .map(identifiers)
            .collect();
        self.docker_client.container_tracker.replace_all(containers);
        self.db.replace_containers(&managed).await?;
        info!(managed = managed.len(), "synchronised with Docker");
        Ok(())
    }

    /// Bring the tracker up to date with one event. Returns whether the firewall needs a
    /// reconcile.
    async fn apply_event(&self, event: &EventMessage) -> Result<bool> {
        let (Some(action), Some(actor)) = (event.action.as_deref(), event.actor.as_ref()) else {
            return Ok(false);
        };
        let container_id = match action {
            "start" | "die" | "rename" => actor.id.as_deref(),
            // On network events the actor is the network; the container is an attribute.
            "connect" | "disconnect" => actor
                .attributes
                .as_ref()
                .and_then(|attributes| attributes.get(CONTAINER_ATTRIBUTE))
                .map(String::as_str),
            _ => None,
        };
        let Some(container_id) = container_id else {
            return Ok(false);
        };
        debug!(action, container_id, "container event");

        if action == "die" {
            self.forget(container_id).await?;
        } else {
            self.refresh(container_id).await?;
        }
        Ok(true)
    }

    async fn refresh(&self, container_id: &str) -> Result<()> {
        match self.docker_client.inspect_running(container_id).await? {
            Some(container) => {
                warn_if_unenforceable(&container);
                if container.enabled {
                    self.db.upsert_container(&identifiers(&container)).await?;
                } else {
                    self.db.delete_container(&container.id).await?;
                }
                self.docker_client.container_tracker.upsert(container);
                Ok(())
            }
            None => self.forget(container_id).await,
        }
    }

    async fn forget(&self, container_id: &str) -> Result<()> {
        self.docker_client.container_tracker.remove(container_id);
        self.db.delete_container(container_id).await?;
        Ok(())
    }

    /// Follow Docker's events until cancelled. Events after `since` (a Unix timestamp taken
    /// before the initial resync) are replayed, so nothing between the two is missed; after a
    /// lost stream the resync covers the gap and following resumes from its start.
    pub(crate) async fn follow_events(&self, mut since: i64) {
        let mut backoff = RETRY_MIN;
        loop {
            let mut stream = self.docker_client.events(since);
            let mut dirty = false;
            let mut retry_at = deadline_after(Duration::ZERO);
            loop {
                tokio::select! {
                    () = self.cancellation.cancelled() => return,
                    () = tokio::time::sleep_until(retry_at), if dirty => {
                        dirty = !self.try_reconcile().await;
                        retry_at = deadline_after(backoff);
                        backoff = next_backoff(backoff, dirty);
                    }
                    event = stream.next() => match event {
                        Some(Ok(event)) => {
                            match self.apply_event(&event).await {
                                Ok(true) => {
                                    dirty = !self.try_reconcile().await;
                                    retry_at = deadline_after(backoff);
                                    backoff = next_backoff(backoff, dirty);
                                }
                                Ok(false) => {}
                                Err(failure) => {
                                    server::increment_errors();
                                    error!(%failure, "could not apply a container event; resyncing");
                                    break;
                                }
                            }
                        }
                        Some(Err(failure)) => {
                            server::increment_errors();
                            warn!(%failure, "Docker event stream failed; resubscribing");
                            break;
                        }
                        None => {
                            warn!("Docker event stream ended; resubscribing");
                            break;
                        }
                    }
                }
            }

            // Events may have been lost: rebuild from Docker's state before following again.
            self.readiness.set(false);
            loop {
                tokio::select! {
                    () = self.cancellation.cancelled() => return,
                    () = tokio::time::sleep(backoff) => {}
                }
                let resync_started = chrono::Utc::now().timestamp();
                match self.resync().await {
                    Ok(()) if self.try_reconcile().await => {
                        // The resync captured everything before it began.
                        since = resync_started;
                        self.readiness.set(true);
                        backoff = RETRY_MIN;
                        break;
                    }
                    Ok(()) => backoff = next_backoff(backoff, true),
                    Err(failure) => {
                        server::increment_errors();
                        error!(%failure, ?backoff, "resync with Docker failed; retrying");
                        backoff = next_backoff(backoff, true);
                    }
                }
            }
        }
    }

    /// Reconcile, logging a failure instead of returning it. Returns whether it succeeded.
    async fn try_reconcile(&self) -> bool {
        match self.reconcile().await {
            Ok(()) => true,
            Err(failure) => {
                server::increment_errors();
                error!(%failure, "could not reconcile the firewall; will retry");
                false
            }
        }
    }
}

/// `delay` from now. The backoff never exceeds `RETRY_MAX`, so the addition cannot overflow in
/// practice; if it ever did, retrying immediately is the safe answer.
fn deadline_after(delay: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(delay).unwrap_or(now)
}

fn next_backoff(current: Duration, failed: bool) -> Duration {
    if failed {
        current.saturating_mul(2).min(RETRY_MAX)
    } else {
        RETRY_MIN
    }
}

fn identifiers(container: &Container) -> ContainerIdentifiers {
    ContainerIdentifiers {
        id: container.id.clone(),
        name: container.name.clone(),
    }
}

fn warn_if_unenforceable(container: &Container) {
    if container.enabled && container.uses_host_network {
        warn!(
            container = %container.name,
            "harborshield.enabled is set on a host-network container, which has no addresses of its own to filter"
        );
    }
}
