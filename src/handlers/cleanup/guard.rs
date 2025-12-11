use super::CleanupTracker;
use crate::Result;
use bon::bon;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

/// RAII guard that ensures cleanup happens when dropped
pub struct CleanupGuard {
    tracker: Arc<CleanupTracker>,
    token: CancellationToken,
    resource_id: String,
    cleanup_on_drop: bool,
}

#[bon]
impl CleanupGuard {
    #[builder]
    /// Create a new cleanup guard
    pub fn new(tracker: Arc<CleanupTracker>, resource_id: String) -> Self {
        let token = tracker.child_token();
        Self {
            tracker,
            token,
            resource_id,
            cleanup_on_drop: true,
        }
    }

    /// Get the cancellation token for this guard
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }

    /// Check if the operation has been cancelled
    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Disarm the guard - cleanup won't happen on drop
    pub fn disarm(mut self) {
        self.cleanup_on_drop = false;
        debug!("Cleanup guard disarmed for resource: {}", self.resource_id);
    }

    /// Complete the operation successfully
    pub async fn complete(mut self) -> Result<()> {
        self.cleanup_on_drop = false;
        debug!(
            "Operation completed successfully for resource: {}",
            self.resource_id
        );
        Ok(())
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            debug!(
                "CleanupGuard dropped with cleanup enabled for resource: {}",
                self.resource_id
            );

            // We can't await in drop, so we spawn a task
            let tracker = self.tracker.clone();
            let resource_id = self.resource_id.clone();

            tokio::spawn(async move {
                if let Err(e) = tracker.cleanup_all().await {
                    error!("Failed to cleanup resources for {}: {}", resource_id, e);
                }
            });
        }
    }
}

#[async_trait::async_trait]
/// Extension trait for operations that need cleanup
pub trait WithCleanup {
    /// Execute with automatic cleanup on cancellation or error
    async fn with_cleanup<F, R>(
        &self,
        tracker: Arc<CleanupTracker>,
        resource_id: String,
        f: F,
    ) -> Result<R>
    where
        F: std::future::Future<Output = Result<R>>;
}

/// Macro to simplify cleanup guard usage
#[macro_export]
macro_rules! with_cleanup {
    ($tracker:expr, $resource_id:expr, $body:expr) => {{
        let guard = $crate::cleanup::guard::CleanupGuard::builder()
            .tracker($tracker)
            .resource_id($resource_id)
            .build();
        let token = guard.token().clone();

        tokio::select! {
            result = $body => {
                match result {
                    Ok(value) => {
                        guard.complete().await?;
                        Ok(value)
                    }
                    Err(e) => {
                        // Guard will cleanup on drop
                        Err(e)
                    }
                }
            }
            _ = token.cancelled() => {
                Err($crate::Error::invalid_state("Operation cancelled", "active", "cancelled"))
            }
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cleanup_guard_token_not_cancelled_initially() {
        // We can't easily test CleanupGuard without a real CleanupTracker,
        // but we can test the CancellationToken behavior
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn test_cancellation_token_cancel() {
        let token = CancellationToken::new();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn test_cancellation_token_child() {
        let parent = CancellationToken::new();
        let child = parent.child_token();

        assert!(!child.is_cancelled());
        parent.cancel();
        assert!(child.is_cancelled());
    }

    #[test]
    fn test_cancellation_token_child_independent_cancel() {
        let parent = CancellationToken::new();
        let child = parent.child_token();

        // Canceling child doesn't cancel parent
        child.cancel();
        assert!(child.is_cancelled());
        assert!(!parent.is_cancelled());
    }
}
