use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Landlock error: {message}")]
    Landlock {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Seccomp error: {message}")]
    Seccomp {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Security feature not supported: {feature}")]
    NotSupported { feature: String },

    #[error("Invalid security configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Failed to apply security restrictions: {0}")]
    ApplicationFailed(String),

    #[error("File access error: {path}")]
    FileAccess {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Ruleset creation failed: {0}")]
    RulesetCreation(String),

    #[error("Rule addition failed: {rule}")]
    RuleAddition {
        rule: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error(
        "Missing capability: {capability} in {capability_set} set\n\nRemediation:\n{remediation}"
    )]
    MissingCapability {
        capability: String,
        capability_set: String,
        remediation: String,
    },

    #[error("Capability check failed for {capability}: {message}")]
    CapabilityCheck { capability: String, message: String },
}

impl SecurityError {
    pub fn landlock<E>(message: impl Into<String>, source: Option<E>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Landlock {
            message: message.into(),
            source: source.map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        }
    }

    pub fn seccomp<E>(message: impl Into<String>, source: Option<E>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Seccomp {
            message: message.into(),
            source: source.map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        }
    }

    pub fn file_access(path: impl Into<String>, source: std::io::Error) -> Self {
        Self::FileAccess {
            path: path.into(),
            source,
        }
    }

    pub fn rule_addition<E>(rule: impl Into<String>, source: Option<E>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::RuleAddition {
            rule: rule.into(),
            source: source.map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        }
    }
}

pub type Result<T> = std::result::Result<T, SecurityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landlock_constructor_without_source() {
        let err = SecurityError::landlock::<std::io::Error>("ruleset failed", None);
        match err {
            SecurityError::Landlock { message, source } => {
                assert_eq!(message, "ruleset failed");
                assert!(source.is_none());
            }
            _ => panic!("Expected Landlock variant"),
        }
    }

    #[test]
    fn test_landlock_constructor_with_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let err = SecurityError::landlock("ruleset failed", Some(io_err));
        match err {
            SecurityError::Landlock { message, source } => {
                assert_eq!(message, "ruleset failed");
                assert!(source.is_some());
            }
            _ => panic!("Expected Landlock variant"),
        }
    }

    #[test]
    fn test_seccomp_constructor_without_source() {
        let err = SecurityError::seccomp::<std::io::Error>("filter failed", None);
        match err {
            SecurityError::Seccomp { message, source } => {
                assert_eq!(message, "filter failed");
                assert!(source.is_none());
            }
            _ => panic!("Expected Seccomp variant"),
        }
    }

    #[test]
    fn test_seccomp_constructor_with_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "syscall error");
        let err = SecurityError::seccomp("filter failed", Some(io_err));
        match err {
            SecurityError::Seccomp { message, source } => {
                assert_eq!(message, "filter failed");
                assert!(source.is_some());
            }
            _ => panic!("Expected Seccomp variant"),
        }
    }

    #[test]
    fn test_file_access_constructor() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = SecurityError::file_access("/etc/passwd", io_err);
        match err {
            SecurityError::FileAccess { path, .. } => {
                assert_eq!(path, "/etc/passwd");
            }
            _ => panic!("Expected FileAccess variant"),
        }
    }

    #[test]
    fn test_rule_addition_constructor_without_source() {
        let err = SecurityError::rule_addition::<std::io::Error>("read /var/run/docker.sock", None);
        match err {
            SecurityError::RuleAddition { rule, source } => {
                assert_eq!(rule, "read /var/run/docker.sock");
                assert!(source.is_none());
            }
            _ => panic!("Expected RuleAddition variant"),
        }
    }

    #[test]
    fn test_rule_addition_constructor_with_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid rule");
        let err = SecurityError::rule_addition("write /tmp", Some(io_err));
        match err {
            SecurityError::RuleAddition { rule, source } => {
                assert_eq!(rule, "write /tmp");
                assert!(source.is_some());
            }
            _ => panic!("Expected RuleAddition variant"),
        }
    }

    #[test]
    fn test_permission_denied() {
        let err = SecurityError::PermissionDenied("CAP_NET_ADMIN required".to_string());
        assert!(matches!(err, SecurityError::PermissionDenied(_)));
    }

    #[test]
    fn test_not_supported() {
        let err = SecurityError::NotSupported {
            feature: "landlock".to_string(),
        };
        match err {
            SecurityError::NotSupported { feature } => {
                assert_eq!(feature, "landlock");
            }
            _ => panic!("Expected NotSupported variant"),
        }
    }

    #[test]
    fn test_invalid_configuration() {
        let err = SecurityError::InvalidConfiguration("invalid seccomp profile".to_string());
        assert!(matches!(err, SecurityError::InvalidConfiguration(_)));
    }

    #[test]
    fn test_application_failed() {
        let err = SecurityError::ApplicationFailed("failed to apply seccomp".to_string());
        assert!(matches!(err, SecurityError::ApplicationFailed(_)));
    }

    #[test]
    fn test_ruleset_creation() {
        let err = SecurityError::RulesetCreation("failed to create ruleset".to_string());
        assert!(matches!(err, SecurityError::RulesetCreation(_)));
    }

    #[test]
    fn test_missing_capability() {
        let err = SecurityError::MissingCapability {
            capability: "CAP_NET_ADMIN".to_string(),
            capability_set: "effective".to_string(),
            remediation: "Run with --cap-add=NET_ADMIN".to_string(),
        };
        match err {
            SecurityError::MissingCapability { capability, capability_set, remediation } => {
                assert_eq!(capability, "CAP_NET_ADMIN");
                assert_eq!(capability_set, "effective");
                assert!(remediation.contains("NET_ADMIN"));
            }
            _ => panic!("Expected MissingCapability variant"),
        }
    }

    #[test]
    fn test_capability_check() {
        let err = SecurityError::CapabilityCheck {
            capability: "CAP_NET_ADMIN".to_string(),
            message: "not in effective set".to_string(),
        };
        match err {
            SecurityError::CapabilityCheck { capability, message } => {
                assert_eq!(capability, "CAP_NET_ADMIN");
                assert_eq!(message, "not in effective set");
            }
            _ => panic!("Expected CapabilityCheck variant"),
        }
    }
}
