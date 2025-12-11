use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HandlersError {
    // Initialization errors
    #[error("handlers initialization failed: {reason}")]
    InitializationFailed {
        reason: String,
        component: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Health server failed to start on {address}: {reason}")]
    HealthServerStartFailed {
        address: String,
        reason: String,
        #[source]
        source: std::io::Error,
    },

    // Rule management errors
    #[error("Rule application failed for container '{container_id}': {reason}")]
    RuleApplicationFailed {
        container_id: String,
        reason: String,
        rule_type: String,
        rule_details: Option<String>,
    },

    #[error("Rule removal failed for container '{container_id}': {reason}")]
    RuleRemovalFailed {
        container_id: String,
        reason: String,
        rules_removed: usize,
        rules_failed: usize,
    },

    #[error("Rule conflict detected: {description}")]
    RuleConflict {
        description: String,
        existing_rule: String,
        new_rule: String,
        resolution: Option<String>,
    },

    #[error("Rule parsing failed for container '{container_id}': {reason}")]
    RuleParsingFailed {
        container_id: String,
        reason: String,
        raw_rules: String,
        line: Option<usize>,
    },

    // Synchronization errors
    #[error("Container sync failed: {reason}")]
    ContainerSyncFailed {
        reason: String,
        containers_synced: usize,
        containers_failed: usize,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("State inconsistency detected: {description}")]
    StateInconsistency {
        description: String,
        expected_state: String,
        actual_state: String,
        affected_containers: Vec<String>,
    },

    // Event handling errors
    #[error("Event processing failed: {event_type} - {reason}")]
    EventProcessingFailed {
        event_type: String,
        reason: String,
        event_data: Option<String>,
        container_id: Option<String>,
    },

    #[error("Event stream lost: {reason}")]
    EventStreamLost {
        reason: String,
        duration_since_last_event: Duration,
        reconnect_attempts: u32,
    },

    // Cleanup errors
    #[error("Cleanup failed for container '{container_id}': {reason}")]
    CleanupFailed {
        container_id: String,
        reason: String,
        resources_cleaned: Vec<String>,
        resources_failed: Vec<String>,
    },

    #[error("Orphaned resources detected: {count} resources without containers")]
    OrphanedResources {
        count: usize,
        resource_types: Vec<String>,
        cleanup_attempted: bool,
        cleanup_successful: bool,
    },

    // Shutdown errors
    #[error("Shutdown timeout after {duration:?}: {pending_operations} operations pending")]
    ShutdownTimeout {
        duration: Duration,
        pending_operations: usize,
        forced: bool,
    },

    #[error("Graceful shutdown failed: {reason}")]
    GracefulShutdownFailed {
        reason: String,
        cleanup_completed: bool,
        state_saved: bool,
    },

    // Task management errors
    #[error("Task '{task_name}' failed: {reason}")]
    TaskFailed {
        task_name: String,
        reason: String,
        restart_attempted: bool,
        restart_count: u32,
    },

    #[error("Task spawn failed: {task_name} - {reason}")]
    TaskSpawnFailed { task_name: String, reason: String },

    // Metrics errors
    #[error("Metrics collection failed: {reason}")]
    MetricsCollectionFailed {
        reason: String,
        metric_type: String,
        last_successful_collection: Option<chrono::DateTime<chrono::Utc>>,
    },

    // Configuration errors
    #[error("Configuration reload failed: {reason}")]
    ConfigReloadFailed {
        reason: String,
        config_path: Option<String>,
        validation_errors: Vec<String>,
    },

    // Network management errors
    #[error("Network setup failed for container '{container_id}': {reason}")]
    NetworkSetupFailed {
        container_id: String,
        reason: String,
        network_id: Option<String>,
    },

    #[error("Network isolation breach detected: {description}")]
    NetworkIsolationBreach {
        description: String,
        source_container: String,
        target_container: String,
        blocked: bool,
    },
}

impl HandlersError {
    // Helper constructors
    pub fn initialization_failed(reason: impl Into<String>, component: impl Into<String>) -> Self {
        Self::InitializationFailed {
            reason: reason.into(),
            component: component.into(),
            source: None,
        }
    }

    pub fn rule_application_failed(
        container_id: impl Into<String>,
        reason: impl Into<String>,
        rule_type: impl Into<String>,
    ) -> Self {
        Self::RuleApplicationFailed {
            container_id: container_id.into(),
            reason: reason.into(),
            rule_type: rule_type.into(),
            rule_details: None,
        }
    }

    pub fn container_sync_failed(reason: impl Into<String>, synced: usize, failed: usize) -> Self {
        Self::ContainerSyncFailed {
            reason: reason.into(),
            containers_synced: synced,
            containers_failed: failed,
            source: None,
        }
    }

    pub fn event_processing_failed(
        event_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::EventProcessingFailed {
            event_type: event_type.into(),
            reason: reason.into(),
            event_data: None,
            container_id: None,
        }
    }

    pub fn cleanup_failed(container_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::CleanupFailed {
            container_id: container_id.into(),
            reason: reason.into(),
            resources_cleaned: Vec::new(),
            resources_failed: Vec::new(),
        }
    }

    pub fn task_failed(task_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::TaskFailed {
            task_name: task_name.into(),
            reason: reason.into(),
            restart_attempted: false,
            restart_count: 0,
        }
    }

    // Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::EventStreamLost { .. }
                | Self::TaskFailed {
                    restart_attempted: true,
                    ..
                }
                | Self::MetricsCollectionFailed { .. }
        )
    }

    // Check if error is critical (requires immediate attention)
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::StateInconsistency { .. }
                | Self::NetworkIsolationBreach { .. }
                | Self::InitializationFailed { .. }
                | Self::ShutdownTimeout { .. }
        )
    }

    // Get suggested action for the error
    pub fn suggested_action(&self) -> Option<&str> {
        match self {
            Self::EventStreamLost { .. } => {
                Some("Check Docker daemon connectivity and restart event monitoring")
            }
            Self::StateInconsistency { .. } => {
                Some("Run full synchronization to restore consistency")
            }
            Self::OrphanedResources { .. } => {
                Some("Run cleanup command to remove orphaned resources")
            }
            Self::ConfigReloadFailed { .. } => {
                Some("Check configuration file syntax and permissions")
            }
            Self::NetworkIsolationBreach { .. } => {
                Some("Review network policies and container configurations")
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization_failed_constructor() {
        let err = HandlersError::initialization_failed("test reason", "test component");
        assert!(matches!(err, HandlersError::InitializationFailed { .. }));
    }

    #[test]
    fn test_rule_application_failed_constructor() {
        let err = HandlersError::rule_application_failed("container1", "nftables error", "input");
        match err {
            HandlersError::RuleApplicationFailed { container_id, reason, rule_type, .. } => {
                assert_eq!(container_id, "container1");
                assert_eq!(reason, "nftables error");
                assert_eq!(rule_type, "input");
            }
            _ => panic!("Expected RuleApplicationFailed variant"),
        }
    }

    #[test]
    fn test_container_sync_failed_constructor() {
        let err = HandlersError::container_sync_failed("sync failed", 5, 2);
        match err {
            HandlersError::ContainerSyncFailed { containers_synced, containers_failed, .. } => {
                assert_eq!(containers_synced, 5);
                assert_eq!(containers_failed, 2);
            }
            _ => panic!("Expected ContainerSyncFailed variant"),
        }
    }

    #[test]
    fn test_event_processing_failed_constructor() {
        let err = HandlersError::event_processing_failed("container_start", "invalid state");
        match err {
            HandlersError::EventProcessingFailed { event_type, reason, .. } => {
                assert_eq!(event_type, "container_start");
                assert_eq!(reason, "invalid state");
            }
            _ => panic!("Expected EventProcessingFailed variant"),
        }
    }

    #[test]
    fn test_cleanup_failed_constructor() {
        let err = HandlersError::cleanup_failed("container1", "rule removal failed");
        match err {
            HandlersError::CleanupFailed { container_id, reason, .. } => {
                assert_eq!(container_id, "container1");
                assert_eq!(reason, "rule removal failed");
            }
            _ => panic!("Expected CleanupFailed variant"),
        }
    }

    #[test]
    fn test_task_failed_constructor() {
        let err = HandlersError::task_failed("event_listener", "connection lost");
        match err {
            HandlersError::TaskFailed { task_name, reason, restart_attempted, restart_count } => {
                assert_eq!(task_name, "event_listener");
                assert_eq!(reason, "connection lost");
                assert!(!restart_attempted);
                assert_eq!(restart_count, 0);
            }
            _ => panic!("Expected TaskFailed variant"),
        }
    }

    #[test]
    fn test_is_retryable() {
        let event_stream_err = HandlersError::EventStreamLost {
            reason: "test".to_string(),
            duration_since_last_event: Duration::from_secs(60),
            reconnect_attempts: 3,
        };
        assert!(event_stream_err.is_retryable());

        let init_err = HandlersError::initialization_failed("test", "test");
        assert!(!init_err.is_retryable());
    }

    #[test]
    fn test_is_critical() {
        let state_err = HandlersError::StateInconsistency {
            description: "test".to_string(),
            expected_state: "running".to_string(),
            actual_state: "stopped".to_string(),
            affected_containers: vec!["container1".to_string()],
        };
        assert!(state_err.is_critical());

        let init_err = HandlersError::initialization_failed("test", "test");
        assert!(init_err.is_critical());

        let cleanup_err = HandlersError::cleanup_failed("test", "test");
        assert!(!cleanup_err.is_critical());
    }

    #[test]
    fn test_suggested_action() {
        let event_stream_err = HandlersError::EventStreamLost {
            reason: "test".to_string(),
            duration_since_last_event: Duration::from_secs(60),
            reconnect_attempts: 3,
        };
        assert!(event_stream_err.suggested_action().is_some());

        let state_err = HandlersError::StateInconsistency {
            description: "test".to_string(),
            expected_state: "running".to_string(),
            actual_state: "stopped".to_string(),
            affected_containers: vec![],
        };
        assert!(state_err.suggested_action().is_some());

        let task_err = HandlersError::task_failed("test", "test");
        assert!(task_err.suggested_action().is_none());
    }
}
