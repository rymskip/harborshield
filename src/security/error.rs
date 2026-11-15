use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SecurityError>;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("could not build or apply the landlock ruleset: {0}")]
    Landlock(#[from] landlock::RulesetError),

    #[error("could not open {} for a landlock rule: {source}", path.display())]
    LandlockPath {
        path: PathBuf,
        #[source]
        source: landlock::PathFdError,
    },

    #[error("could not prepare {}: {source}", path.display())]
    FileAccess {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not build the seccomp filter: {0}")]
    SeccompFilter(#[from] seccompiler::BackendError),

    #[error("could not apply the seccomp filter: {0}")]
    SeccompApply(#[from] seccompiler::Error),

    #[error("seccomp filtering is not supported on {0}")]
    UnsupportedArch(&'static str),

    #[error("missing capability {capability} in the {set} set\n\nRemediation:\n{remediation}")]
    MissingCapability {
        capability: String,
        set: &'static str,
        remediation: &'static str,
    },

    #[error("could not read the {set} capability set: {source}")]
    CapabilityCheck {
        set: &'static str,
        #[source]
        source: caps::errors::CapsError,
    },
}
