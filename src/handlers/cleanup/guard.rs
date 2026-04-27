use super::{CleanupResource, CleanupTracker};
use bon::bon;
use std::sync::Arc;
use tracing::{debug, error};

/// RAII guard that registers a specific set of resources with the cleanup
/// tracker on creation and triggers cleanup of just those resources if it is
/// dropped without `commit()`.
///
/// The guard is not async-aware on drop (Rust drop is sync), so cleanup is
/// dispatched to the tracker's worker via a channel send. The channel send
/// itself is async, so on a panic-induced drop with no live runtime the
/// cleanup may not actually run — that case is covered by the orphan-scan at
/// next startup.
pub struct CleanupGuard {
    tracker: Arc<CleanupTracker>,
    resources: Vec<CleanupResource>,
    cleanup_on_drop: bool,
}

#[bon]
impl CleanupGuard {
    /// Create a guard that owns the cleanup of `resources`. Each resource is
    /// registered with the tracker so that a process-wide shutdown also
    /// cleans them up if this guard never gets a chance to run.
    #[builder]
    pub async fn new(
        tracker: Arc<CleanupTracker>,
        resources: Vec<CleanupResource>,
    ) -> crate::Result<Self> {
        for resource in &resources {
            tracker.register_resource(resource.clone()).await?;
        }
        Ok(Self {
            tracker,
            resources,
            cleanup_on_drop: true,
        })
    }

    /// Mark the operation successful — unregister the resources so neither
    /// drop nor shutdown will clean them up.
    pub async fn commit(mut self) -> crate::Result<()> {
        self.cleanup_on_drop = false;
        for resource in self.resources.drain(..) {
            self.tracker.unregister_resource(resource).await?;
        }
        debug!("CleanupGuard committed");
        Ok(())
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if !self.cleanup_on_drop || self.resources.is_empty() {
            return;
        }
        debug!(
            "CleanupGuard dropped without commit; scheduling cleanup of {} resource(s)",
            self.resources.len()
        );
        let tracker = self.tracker.clone();
        let resources = std::mem::take(&mut self.resources);
        // Best-effort: spawn a task on the current runtime. If there is no
        // runtime (e.g. mid-panic shutdown) this silently fails; orphan-scan
        // at next startup is the backstop.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = tracker.cleanup_subset(resources).await {
                    error!("Failed to send cleanup_subset on guard drop: {}", e);
                }
            });
        }
    }
}
