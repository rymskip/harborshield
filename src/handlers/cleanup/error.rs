use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CleanupError {
    // Resource cleanup errors
    #[error("Failed to cleanup resources for container '{container_id}': {reason}")]
    ResourceCleanupFailed {
        container_id: String,
        reason: String,
        resource_type: String,
        resources_affected: usize,
    },

    #[error(
        "Partial cleanup for container '{container_id}': {succeeded} succeeded, {failed} failed"
    )]
    PartialCleanup {
        container_id: String,
        succeeded: usize,
        failed: usize,
        failed_resources: Vec<String>,
    },

    #[error("Cleanup timeout after {duration:?} for container '{container_id}'")]
    CleanupTimeout {
        container_id: String,
        duration: Duration,
        pending_operations: Vec<String>,
    },

    // Orphaned resource errors
    #[error("Found {count} orphaned {resource_type} resources")]
    OrphanedResourcesFound {
        count: usize,
        resource_type: String,
        resource_ids: Vec<String>,
        age: Option<Duration>,
    },

    #[error("Failed to remove orphaned {resource_type}: {reason}")]
    OrphanedResourceRemovalFailed {
        resource_type: String,
        reason: String,
        resource_id: String,
        retry_possible: bool,
    },

    // Rule cleanup errors
    #[error("Failed to cleanup rules for container '{container_id}': {reason}")]
    RuleCleanupFailed {
        container_id: String,
        reason: String,
        rules_removed: usize,
        rules_failed: usize,
    },

    #[error("NFTables cleanup failed: {reason}")]
    NftablesCleanupFailed {
        reason: String,
        command: Option<String>,
        stderr: Option<String>,
    },

    #[error("Stale rule detected: {rule_id} for non-existent container '{container_id}'")]
    StaleRuleDetected {
        rule_id: String,
        container_id: String,
        rule_age: Duration,
    },

    // Database cleanup errors
    #[error("Database cleanup failed: {reason}")]
    DatabaseCleanupFailed {
        reason: String,
        table: String,
        records_affected: usize,
        #[source]
        source: Option<sqlx::Error>,
    },

    #[error("Failed to purge old records: {reason}")]
    RecordPurgeFailed {
        reason: String,
        cutoff_date: chrono::DateTime<chrono::Utc>,
        records_to_purge: usize,
    },

    // State cleanup errors
    #[error("State inconsistency during cleanup: {description}")]
    StateInconsistency {
        description: String,
        expected_state: String,
        actual_state: String,
    },

    #[error("Failed to restore state after cleanup failure: {reason}")]
    StateRestoreFailed {
        reason: String,
        backup_available: bool,
    },

    // Tracking errors
    #[error("Cleanup tracking error: {reason}")]
    TrackingError {
        reason: String,
        operation: String,
        container_id: Option<String>,
    },

    #[error("Lost track of cleanup operation '{operation_id}' after {duration:?}")]
    OperationLost {
        operation_id: String,
        duration: Duration,
        last_status: String,
    },

    // Concurrent cleanup errors
    #[error("Concurrent cleanup conflict for container '{container_id}'")]
    ConcurrentCleanupConflict {
        container_id: String,
        existing_operation: String,
        requested_operation: String,
    },

    #[error("Cleanup lock acquisition failed after {duration:?}")]
    LockAcquisitionFailed {
        duration: Duration,
        lock_holder: Option<String>,
    },

    // Validation errors
    #[error("Invalid cleanup request: {reason}")]
    InvalidCleanupRequest {
        reason: String,
        request_type: String,
    },

    #[error("Cleanup precondition failed: {condition}")]
    PreconditionFailed {
        condition: String,
        required_state: String,
    },

    // Recovery errors
    #[error("Cleanup recovery failed: {reason}")]
    RecoveryFailed {
        reason: String,
        attempted_actions: Vec<String>,
        successful_actions: Vec<String>,
    },

    #[error("Rollback failed during cleanup: {reason}")]
    RollbackFailed {
        reason: String,
        partial_rollback: bool,
        affected_resources: Vec<String>,
    },
}

impl CleanupError {
    // Helper constructors
    pub fn resource_cleanup_failed(
        container_id: impl Into<String>,
        reason: impl Into<String>,
        resource_type: impl Into<String>,
    ) -> Self {
        Self::ResourceCleanupFailed {
            container_id: container_id.into(),
            reason: reason.into(),
            resource_type: resource_type.into(),
            resources_affected: 0,
        }
    }

    pub fn partial_cleanup(
        container_id: impl Into<String>,
        succeeded: usize,
        failed: usize,
        failed_resources: Vec<String>,
    ) -> Self {
        Self::PartialCleanup {
            container_id: container_id.into(),
            succeeded,
            failed,
            failed_resources,
        }
    }

    pub fn orphaned_resources_found(
        count: usize,
        resource_type: impl Into<String>,
        resource_ids: Vec<String>,
    ) -> Self {
        Self::OrphanedResourcesFound {
            count,
            resource_type: resource_type.into(),
            resource_ids,
            age: None,
        }
    }

    pub fn rule_cleanup_failed(
        container_id: impl Into<String>,
        reason: impl Into<String>,
        removed: usize,
        failed: usize,
    ) -> Self {
        Self::RuleCleanupFailed {
            container_id: container_id.into(),
            reason: reason.into(),
            rules_removed: removed,
            rules_failed: failed,
        }
    }

    pub fn database_cleanup_failed(reason: impl Into<String>, table: impl Into<String>) -> Self {
        Self::DatabaseCleanupFailed {
            reason: reason.into(),
            table: table.into(),
            records_affected: 0,
            source: None,
        }
    }

    pub fn tracking_error(reason: impl Into<String>, operation: impl Into<String>) -> Self {
        Self::TrackingError {
            reason: reason.into(),
            operation: operation.into(),
            container_id: None,
        }
    }

    // Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::CleanupTimeout { .. }
                | Self::LockAcquisitionFailed { .. }
                | Self::ConcurrentCleanupConflict { .. }
                | Self::OrphanedResourceRemovalFailed {
                    retry_possible: true,
                    ..
                }
        )
    }

    // Check if cleanup was partially successful
    pub fn is_partial_success(&self) -> bool {
        matches!(
            self,
            Self::PartialCleanup { succeeded, .. } if *succeeded > 0
        )
    }

    // Get suggested recovery action
    pub fn recovery_action(&self) -> Option<&str> {
        match self {
            Self::PartialCleanup { .. } => Some("Retry cleanup for failed resources only"),
            Self::OrphanedResourcesFound { .. } => {
                Some("Run forced cleanup to remove orphaned resources")
            }
            Self::StateInconsistency { .. } => {
                Some("Run state reconciliation before retrying cleanup")
            }
            Self::ConcurrentCleanupConflict { .. } => Some("Wait for existing cleanup to complete"),
            Self::LockAcquisitionFailed { .. } => {
                Some("Check for stuck cleanup operations and clear locks if necessary")
            }
            _ => None,
        }
    }

    // Check if manual intervention is required
    pub fn requires_manual_intervention(&self) -> bool {
        matches!(
            self,
            Self::StateInconsistency { .. }
                | Self::StateRestoreFailed { .. }
                | Self::RollbackFailed { .. }
                | Self::RecoveryFailed { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_cleanup_failed_constructor() {
        let err = CleanupError::resource_cleanup_failed("container1", "nftables error", "chain");
        match err {
            CleanupError::ResourceCleanupFailed { container_id, reason, resource_type, .. } => {
                assert_eq!(container_id, "container1");
                assert_eq!(reason, "nftables error");
                assert_eq!(resource_type, "chain");
            }
            _ => panic!("Expected ResourceCleanupFailed variant"),
        }
    }

    #[test]
    fn test_partial_cleanup_constructor() {
        let err = CleanupError::partial_cleanup(
            "container1",
            3,
            2,
            vec!["rule1".to_string(), "rule2".to_string()],
        );
        match err {
            CleanupError::PartialCleanup { container_id, succeeded, failed, failed_resources } => {
                assert_eq!(container_id, "container1");
                assert_eq!(succeeded, 3);
                assert_eq!(failed, 2);
                assert_eq!(failed_resources.len(), 2);
            }
            _ => panic!("Expected PartialCleanup variant"),
        }
    }

    #[test]
    fn test_orphaned_resources_found_constructor() {
        let err = CleanupError::orphaned_resources_found(
            5,
            "chain",
            vec!["chain1".to_string(), "chain2".to_string()],
        );
        match err {
            CleanupError::OrphanedResourcesFound { count, resource_type, resource_ids, .. } => {
                assert_eq!(count, 5);
                assert_eq!(resource_type, "chain");
                assert_eq!(resource_ids.len(), 2);
            }
            _ => panic!("Expected OrphanedResourcesFound variant"),
        }
    }

    #[test]
    fn test_rule_cleanup_failed_constructor() {
        let err = CleanupError::rule_cleanup_failed("container1", "permission denied", 3, 1);
        match err {
            CleanupError::RuleCleanupFailed { container_id, reason, rules_removed, rules_failed } => {
                assert_eq!(container_id, "container1");
                assert_eq!(reason, "permission denied");
                assert_eq!(rules_removed, 3);
                assert_eq!(rules_failed, 1);
            }
            _ => panic!("Expected RuleCleanupFailed variant"),
        }
    }

    #[test]
    fn test_database_cleanup_failed_constructor() {
        let err = CleanupError::database_cleanup_failed("connection error", "containers");
        match err {
            CleanupError::DatabaseCleanupFailed { reason, table, .. } => {
                assert_eq!(reason, "connection error");
                assert_eq!(table, "containers");
            }
            _ => panic!("Expected DatabaseCleanupFailed variant"),
        }
    }

    #[test]
    fn test_tracking_error_constructor() {
        let err = CleanupError::tracking_error("lost track", "cleanup");
        match err {
            CleanupError::TrackingError { reason, operation, .. } => {
                assert_eq!(reason, "lost track");
                assert_eq!(operation, "cleanup");
            }
            _ => panic!("Expected TrackingError variant"),
        }
    }

    #[test]
    fn test_is_retryable() {
        let timeout_err = CleanupError::CleanupTimeout {
            container_id: "test".to_string(),
            duration: Duration::from_secs(30),
            pending_operations: vec!["op1".to_string()],
        };
        assert!(timeout_err.is_retryable());

        let lock_err = CleanupError::LockAcquisitionFailed {
            duration: Duration::from_secs(5),
            lock_holder: Some("other".to_string()),
        };
        assert!(lock_err.is_retryable());

        let db_err = CleanupError::database_cleanup_failed("error", "table");
        assert!(!db_err.is_retryable());
    }

    #[test]
    fn test_is_partial_success() {
        let partial_with_success = CleanupError::PartialCleanup {
            container_id: "test".to_string(),
            succeeded: 3,
            failed: 1,
            failed_resources: vec!["res1".to_string()],
        };
        assert!(partial_with_success.is_partial_success());

        let partial_no_success = CleanupError::PartialCleanup {
            container_id: "test".to_string(),
            succeeded: 0,
            failed: 3,
            failed_resources: vec!["res1".to_string()],
        };
        assert!(!partial_no_success.is_partial_success());
    }

    #[test]
    fn test_recovery_action() {
        let partial_err = CleanupError::partial_cleanup("test", 1, 1, vec!["res1".to_string()]);
        assert!(partial_err.recovery_action().is_some());

        let orphan_err = CleanupError::orphaned_resources_found(1, "chain", vec!["c1".to_string()]);
        assert!(orphan_err.recovery_action().is_some());

        let state_err = CleanupError::StateInconsistency {
            description: "test".to_string(),
            expected_state: "clean".to_string(),
            actual_state: "dirty".to_string(),
        };
        assert!(state_err.recovery_action().is_some());

        let db_err = CleanupError::database_cleanup_failed("error", "table");
        assert!(db_err.recovery_action().is_none());
    }

    #[test]
    fn test_requires_manual_intervention() {
        let state_err = CleanupError::StateInconsistency {
            description: "test".to_string(),
            expected_state: "clean".to_string(),
            actual_state: "dirty".to_string(),
        };
        assert!(state_err.requires_manual_intervention());

        let rollback_err = CleanupError::RollbackFailed {
            reason: "test".to_string(),
            partial_rollback: true,
            affected_resources: vec!["res1".to_string()],
        };
        assert!(rollback_err.requires_manual_intervention());

        let timeout_err = CleanupError::CleanupTimeout {
            container_id: "test".to_string(),
            duration: Duration::from_secs(30),
            pending_operations: vec![],
        };
        assert!(!timeout_err.requires_manual_intervention());
    }
}
