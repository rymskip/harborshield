use std::path::PathBuf;
use thiserror::Error;

// Define our own Result type
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    // External library errors with automatic conversion
    #[error("Docker error")]
    Docker(#[from] bollard::errors::Error),

    #[error("Database error")]
    Database(String),

    #[error("YAML parsing error")]
    Yaml(#[from] serde_yaml::Error),

    #[error("JSON parsing error")]
    Json(#[from] serde_json::Error),

    #[error("IO error")]
    Io(#[from] std::io::Error),

    // Metrics errors with context
    #[error("Metrics error: {message}")]
    Metrics {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    // NFTables errors with detailed context
    #[error("nftables error: {message}")]
    Nftables {
        message: String,
        command: Option<String>,
        exit_code: Option<i32>,
        stderr: Option<String>,
    },

    // Configuration errors with location info
    #[error("Configuration error at {location}: {message}")]
    Config {
        message: String,
        location: String,
        suggestion: Option<String>,
    },

    // Container-related errors
    #[error("Container '{id}' not found{}", .context.as_ref().map(|c| format!(" ({})", c)).unwrap_or_default())]
    ContainerNotFound { id: String, context: Option<String> },

    #[error("Container '{id}' in invalid state: expected {expected}, got {actual}")]
    ContainerInvalidState {
        id: String,
        expected: String,
        actual: String,
    },

    // Network and IP errors
    #[error("Invalid IP address or range: {input} - {reason}")]
    InvalidIpAddress { input: String, reason: String },

    #[error("Network error: {message}")]
    Network {
        message: String,
        endpoint: Option<String>,
        retry_after: Option<std::time::Duration>,
    },

    // Permission and security errors
    #[error("Permission denied - {context}: {details}")]
    PermissionDenied {
        context: String,
        details: String,
        required_permission: Option<String>,
    },

    #[error("Security restriction: {message} (policy: {policy})")]
    SecurityRestriction {
        message: String,
        policy: String,
        violated_rule: Option<String>,
    },

    // Timeout errors with operation context
    #[error("Timeout after {duration:?} while {operation}")]
    Timeout {
        duration: std::time::Duration,
        operation: String,
    },

    // Validation errors
    #[error("Invalid container label '{label}': {reason}")]
    InvalidLabel {
        label: String,
        reason: String,
        container_id: Option<String>,
    },

    #[error("Rule validation failed: {message}")]
    RuleValidation {
        message: String,
        rule_type: String,
        field: Option<String>,
        value: Option<String>,
    },

    // State and synchronization errors
    #[error("Invalid state: {message} (current: {current_state}, expected: {expected_state})")]
    InvalidState {
        message: String,
        current_state: String,
        expected_state: String,
    },

    #[error("Synchronization error: {message}")]
    SyncError {
        message: String,
        resource_type: String,
        resource_id: Option<String>,
    },

    // File system errors
    #[error("File operation failed on {}: {operation}", path.display())]
    FileOperation {
        path: PathBuf,
        operation: String,
        #[source]
        source: std::io::Error,
    },

    // Transaction errors
    #[error("Transaction failed: {message}")]
    Transaction {
        message: String,
        rollback_successful: bool,
        operations_completed: usize,
        operations_failed: usize,
    },

    // Resource errors
    #[error("Resource limit exceeded: {resource} (limit: {limit}, requested: {requested})")]
    ResourceLimit {
        resource: String,
        limit: String,
        requested: String,
    },

    // Module-specific errors that will be converted from module error types
    #[error(transparent)]
    DatabaseModule(#[from] crate::database::error::DatabaseError),

    #[error(transparent)]
    DockerModule(#[from] crate::docker::error::DockerError),

    #[error(transparent)]
    HandlerModule(#[from] crate::handlers::error::HandlersError),

    #[error(transparent)]
    ValidationModule(#[from] crate::docker::config::validation::error::ValidationError),

    #[error(transparent)]
    CleanupModule(#[from] crate::handlers::cleanup::error::CleanupError),

    #[error(transparent)]
    SecurityModule(#[from] crate::security::error::SecurityError),

    #[error(transparent)]
    NftablesModule(#[from] crate::nftables::error::NftablesError),
}

// Helper methods for creating errors with context
impl Error {
    // NFTables error constructors
    pub fn nftables(message: impl Into<String>) -> Self {
        Self::Nftables {
            message: message.into(),
            command: None,
            exit_code: None,
            stderr: None,
        }
    }

    pub fn nftables_command(
        message: impl Into<String>,
        command: impl Into<String>,
        exit_code: i32,
        stderr: impl Into<String>,
    ) -> Self {
        Self::Nftables {
            message: message.into(),
            command: Some(command.into()),
            exit_code: Some(exit_code),
            stderr: Some(stderr.into()),
        }
    }

    // Configuration error constructors
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
            location: "unknown".to_string(),
            suggestion: None,
        }
    }

    pub fn config_at(message: impl Into<String>, location: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
            location: location.into(),
            suggestion: None,
        }
    }

    pub fn config_with_suggestion(
        message: impl Into<String>,
        location: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self::Config {
            message: message.into(),
            location: location.into(),
            suggestion: Some(suggestion.into()),
        }
    }

    // Container error constructors
    pub fn container_not_found(id: impl Into<String>) -> Self {
        Self::ContainerNotFound {
            id: id.into(),
            context: None,
        }
    }

    pub fn container_not_found_with_context(
        id: impl Into<String>,
        context: impl Into<String>,
    ) -> Self {
        Self::ContainerNotFound {
            id: id.into(),
            context: Some(context.into()),
        }
    }

    pub fn container_invalid_state(
        id: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::ContainerInvalidState {
            id: id.into(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    // Network error constructors
    pub fn invalid_ip(input: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidIpAddress {
            input: input.into(),
            reason: reason.into(),
        }
    }

    pub fn network(message: impl Into<String>) -> Self {
        Self::Network {
            message: message.into(),
            endpoint: None,
            retry_after: None,
        }
    }

    pub fn network_with_endpoint(message: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self::Network {
            message: message.into(),
            endpoint: Some(endpoint.into()),
            retry_after: None,
        }
    }

    pub fn network_retry(message: impl Into<String>, retry_after: std::time::Duration) -> Self {
        Self::Network {
            message: message.into(),
            endpoint: None,
            retry_after: Some(retry_after),
        }
    }

    // Permission error constructors
    pub fn permission_denied(context: impl Into<String>, details: impl Into<String>) -> Self {
        Self::PermissionDenied {
            context: context.into(),
            details: details.into(),
            required_permission: None,
        }
    }

    pub fn permission_denied_with_required(
        context: impl Into<String>,
        details: impl Into<String>,
        required: impl Into<String>,
    ) -> Self {
        Self::PermissionDenied {
            context: context.into(),
            details: details.into(),
            required_permission: Some(required.into()),
        }
    }

    // Security error constructors
    pub fn security(message: impl Into<String>, policy: impl Into<String>) -> Self {
        Self::SecurityRestriction {
            message: message.into(),
            policy: policy.into(),
            violated_rule: None,
        }
    }

    pub fn security_with_rule(
        message: impl Into<String>,
        policy: impl Into<String>,
        rule: impl Into<String>,
    ) -> Self {
        Self::SecurityRestriction {
            message: message.into(),
            policy: policy.into(),
            violated_rule: Some(rule.into()),
        }
    }

    // Timeout error constructor
    pub fn timeout(duration: std::time::Duration, operation: impl Into<String>) -> Self {
        Self::Timeout {
            duration,
            operation: operation.into(),
        }
    }

    // Validation error constructors
    pub fn invalid_label(label: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidLabel {
            label: label.into(),
            reason: reason.into(),
            container_id: None,
        }
    }

    pub fn invalid_label_with_container(
        label: impl Into<String>,
        reason: impl Into<String>,
        container_id: impl Into<String>,
    ) -> Self {
        Self::InvalidLabel {
            label: label.into(),
            reason: reason.into(),
            container_id: Some(container_id.into()),
        }
    }

    pub fn rule_validation(message: impl Into<String>, rule_type: impl Into<String>) -> Self {
        Self::RuleValidation {
            message: message.into(),
            rule_type: rule_type.into(),
            field: None,
            value: None,
        }
    }

    pub fn rule_validation_field(
        message: impl Into<String>,
        rule_type: impl Into<String>,
        field: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self::RuleValidation {
            message: message.into(),
            rule_type: rule_type.into(),
            field: Some(field.into()),
            value: Some(value.into()),
        }
    }

    // State error constructors
    pub fn invalid_state(
        message: impl Into<String>,
        current: impl Into<String>,
        expected: impl Into<String>,
    ) -> Self {
        Self::InvalidState {
            message: message.into(),
            current_state: current.into(),
            expected_state: expected.into(),
        }
    }

    pub fn sync_error(message: impl Into<String>, resource_type: impl Into<String>) -> Self {
        Self::SyncError {
            message: message.into(),
            resource_type: resource_type.into(),
            resource_id: None,
        }
    }

    pub fn sync_error_with_id(
        message: impl Into<String>,
        resource_type: impl Into<String>,
        id: impl Into<String>,
    ) -> Self {
        Self::SyncError {
            message: message.into(),
            resource_type: resource_type.into(),
            resource_id: Some(id.into()),
        }
    }

    // Transaction error constructor
    pub fn transaction(
        message: impl Into<String>,
        rollback_successful: bool,
        completed: usize,
        failed: usize,
    ) -> Self {
        Self::Transaction {
            message: message.into(),
            rollback_successful,
            operations_completed: completed,
            operations_failed: failed,
        }
    }

    // Resource limit error constructor
    pub fn resource_limit(
        resource: impl Into<String>,
        limit: impl Into<String>,
        requested: impl Into<String>,
    ) -> Self {
        Self::ResourceLimit {
            resource: resource.into(),
            limit: limit.into(),
            requested: requested.into(),
        }
    }

    // Metrics error constructor
    pub fn metrics(message: impl Into<String>) -> Self {
        Self::Metrics {
            message: message.into(),
            source: None,
        }
    }

    pub fn metrics_with_source(
        message: impl Into<String>,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self::Metrics {
            message: message.into(),
            source: Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_nftables_constructor() {
        let err = Error::nftables("rule failed");
        match err {
            Error::Nftables { message, command, exit_code, stderr } => {
                assert_eq!(message, "rule failed");
                assert!(command.is_none());
                assert!(exit_code.is_none());
                assert!(stderr.is_none());
            }
            _ => panic!("Expected Nftables variant"),
        }
    }

    #[test]
    fn test_nftables_command_constructor() {
        let err = Error::nftables_command("rule failed", "nft add rule", 1, "permission denied");
        match err {
            Error::Nftables { message, command, exit_code, stderr } => {
                assert_eq!(message, "rule failed");
                assert_eq!(command, Some("nft add rule".to_string()));
                assert_eq!(exit_code, Some(1));
                assert_eq!(stderr, Some("permission denied".to_string()));
            }
            _ => panic!("Expected Nftables variant"),
        }
    }

    #[test]
    fn test_config_constructor() {
        let err = Error::config("invalid port");
        match err {
            Error::Config { message, location, suggestion } => {
                assert_eq!(message, "invalid port");
                assert_eq!(location, "unknown");
                assert!(suggestion.is_none());
            }
            _ => panic!("Expected Config variant"),
        }
    }

    #[test]
    fn test_config_at_constructor() {
        let err = Error::config_at("invalid port", "container.label");
        match err {
            Error::Config { message, location, suggestion } => {
                assert_eq!(message, "invalid port");
                assert_eq!(location, "container.label");
                assert!(suggestion.is_none());
            }
            _ => panic!("Expected Config variant"),
        }
    }

    #[test]
    fn test_config_with_suggestion_constructor() {
        let err = Error::config_with_suggestion("invalid port", "container.label", "use 1-65535");
        match err {
            Error::Config { message, location, suggestion } => {
                assert_eq!(message, "invalid port");
                assert_eq!(location, "container.label");
                assert_eq!(suggestion, Some("use 1-65535".to_string()));
            }
            _ => panic!("Expected Config variant"),
        }
    }

    #[test]
    fn test_container_not_found_constructor() {
        let err = Error::container_not_found("abc123");
        match err {
            Error::ContainerNotFound { id, context } => {
                assert_eq!(id, "abc123");
                assert!(context.is_none());
            }
            _ => panic!("Expected ContainerNotFound variant"),
        }
    }

    #[test]
    fn test_container_not_found_with_context_constructor() {
        let err = Error::container_not_found_with_context("abc123", "during rule application");
        match err {
            Error::ContainerNotFound { id, context } => {
                assert_eq!(id, "abc123");
                assert_eq!(context, Some("during rule application".to_string()));
            }
            _ => panic!("Expected ContainerNotFound variant"),
        }
    }

    #[test]
    fn test_container_invalid_state_constructor() {
        let err = Error::container_invalid_state("abc123", "running", "stopped");
        match err {
            Error::ContainerInvalidState { id, expected, actual } => {
                assert_eq!(id, "abc123");
                assert_eq!(expected, "running");
                assert_eq!(actual, "stopped");
            }
            _ => panic!("Expected ContainerInvalidState variant"),
        }
    }

    #[test]
    fn test_invalid_ip_constructor() {
        let err = Error::invalid_ip("not.an.ip", "parse failed");
        match err {
            Error::InvalidIpAddress { input, reason } => {
                assert_eq!(input, "not.an.ip");
                assert_eq!(reason, "parse failed");
            }
            _ => panic!("Expected InvalidIpAddress variant"),
        }
    }

    #[test]
    fn test_network_constructor() {
        let err = Error::network("connection refused");
        match err {
            Error::Network { message, endpoint, retry_after } => {
                assert_eq!(message, "connection refused");
                assert!(endpoint.is_none());
                assert!(retry_after.is_none());
            }
            _ => panic!("Expected Network variant"),
        }
    }

    #[test]
    fn test_network_with_endpoint_constructor() {
        let err = Error::network_with_endpoint("connection refused", "localhost:8080");
        match err {
            Error::Network { message, endpoint, retry_after } => {
                assert_eq!(message, "connection refused");
                assert_eq!(endpoint, Some("localhost:8080".to_string()));
                assert!(retry_after.is_none());
            }
            _ => panic!("Expected Network variant"),
        }
    }

    #[test]
    fn test_network_retry_constructor() {
        let err = Error::network_retry("rate limited", Duration::from_secs(60));
        match err {
            Error::Network { message, endpoint, retry_after } => {
                assert_eq!(message, "rate limited");
                assert!(endpoint.is_none());
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
            }
            _ => panic!("Expected Network variant"),
        }
    }

    #[test]
    fn test_permission_denied_constructor() {
        let err = Error::permission_denied("nftables", "CAP_NET_ADMIN required");
        match err {
            Error::PermissionDenied { context, details, required_permission } => {
                assert_eq!(context, "nftables");
                assert_eq!(details, "CAP_NET_ADMIN required");
                assert!(required_permission.is_none());
            }
            _ => panic!("Expected PermissionDenied variant"),
        }
    }

    #[test]
    fn test_permission_denied_with_required_constructor() {
        let err = Error::permission_denied_with_required(
            "nftables",
            "cannot modify rules",
            "CAP_NET_ADMIN",
        );
        match err {
            Error::PermissionDenied { context, details, required_permission } => {
                assert_eq!(context, "nftables");
                assert_eq!(details, "cannot modify rules");
                assert_eq!(required_permission, Some("CAP_NET_ADMIN".to_string()));
            }
            _ => panic!("Expected PermissionDenied variant"),
        }
    }

    #[test]
    fn test_timeout_constructor() {
        let err = Error::timeout(Duration::from_secs(30), "waiting for container");
        match err {
            Error::Timeout { duration, operation } => {
                assert_eq!(duration, Duration::from_secs(30));
                assert_eq!(operation, "waiting for container");
            }
            _ => panic!("Expected Timeout variant"),
        }
    }

    #[test]
    fn test_invalid_label_constructor() {
        let err = Error::invalid_label("harborshield.rules", "invalid YAML");
        match err {
            Error::InvalidLabel { label, reason, container_id } => {
                assert_eq!(label, "harborshield.rules");
                assert_eq!(reason, "invalid YAML");
                assert!(container_id.is_none());
            }
            _ => panic!("Expected InvalidLabel variant"),
        }
    }

    #[test]
    fn test_invalid_label_with_container_constructor() {
        let err = Error::invalid_label_with_container("harborshield.rules", "invalid YAML", "abc123");
        match err {
            Error::InvalidLabel { label, reason, container_id } => {
                assert_eq!(label, "harborshield.rules");
                assert_eq!(reason, "invalid YAML");
                assert_eq!(container_id, Some("abc123".to_string()));
            }
            _ => panic!("Expected InvalidLabel variant"),
        }
    }

    #[test]
    fn test_rule_validation_constructor() {
        let err = Error::rule_validation("port out of range", "input");
        match err {
            Error::RuleValidation { message, rule_type, field, value } => {
                assert_eq!(message, "port out of range");
                assert_eq!(rule_type, "input");
                assert!(field.is_none());
                assert!(value.is_none());
            }
            _ => panic!("Expected RuleValidation variant"),
        }
    }

    #[test]
    fn test_rule_validation_field_constructor() {
        let err = Error::rule_validation_field("port out of range", "input", "dst_port", "70000");
        match err {
            Error::RuleValidation { message, rule_type, field, value } => {
                assert_eq!(message, "port out of range");
                assert_eq!(rule_type, "input");
                assert_eq!(field, Some("dst_port".to_string()));
                assert_eq!(value, Some("70000".to_string()));
            }
            _ => panic!("Expected RuleValidation variant"),
        }
    }

    #[test]
    fn test_invalid_state_constructor() {
        let err = Error::invalid_state("operation failed", "running", "stopped");
        match err {
            Error::InvalidState { message, current_state, expected_state } => {
                assert_eq!(message, "operation failed");
                assert_eq!(current_state, "running");
                assert_eq!(expected_state, "stopped");
            }
            _ => panic!("Expected InvalidState variant"),
        }
    }

    #[test]
    fn test_sync_error_constructor() {
        let err = Error::sync_error("failed to sync", "container");
        match err {
            Error::SyncError { message, resource_type, resource_id } => {
                assert_eq!(message, "failed to sync");
                assert_eq!(resource_type, "container");
                assert!(resource_id.is_none());
            }
            _ => panic!("Expected SyncError variant"),
        }
    }

    #[test]
    fn test_sync_error_with_id_constructor() {
        let err = Error::sync_error_with_id("failed to sync", "container", "abc123");
        match err {
            Error::SyncError { message, resource_type, resource_id } => {
                assert_eq!(message, "failed to sync");
                assert_eq!(resource_type, "container");
                assert_eq!(resource_id, Some("abc123".to_string()));
            }
            _ => panic!("Expected SyncError variant"),
        }
    }

    #[test]
    fn test_transaction_constructor() {
        let err = Error::transaction("commit failed", false, 3, 1);
        match err {
            Error::Transaction { message, rollback_successful, operations_completed, operations_failed } => {
                assert_eq!(message, "commit failed");
                assert!(!rollback_successful);
                assert_eq!(operations_completed, 3);
                assert_eq!(operations_failed, 1);
            }
            _ => panic!("Expected Transaction variant"),
        }
    }

    #[test]
    fn test_resource_limit_constructor() {
        let err = Error::resource_limit("chains", "100", "150");
        match err {
            Error::ResourceLimit { resource, limit, requested } => {
                assert_eq!(resource, "chains");
                assert_eq!(limit, "100");
                assert_eq!(requested, "150");
            }
            _ => panic!("Expected ResourceLimit variant"),
        }
    }

    #[test]
    fn test_metrics_constructor() {
        let err = Error::metrics("collection failed");
        match err {
            Error::Metrics { message, source } => {
                assert_eq!(message, "collection failed");
                assert!(source.is_none());
            }
            _ => panic!("Expected Metrics variant"),
        }
    }
}
