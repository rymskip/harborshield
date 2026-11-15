use std::process::ExitStatus;
use std::time::Duration;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, NftablesError>;

#[derive(Debug, Error)]
pub enum NftablesError {
    #[error("could not run nft to {operation}")]
    Spawn {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("I/O with nft failed while trying to {operation}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("nft has no stdin pipe to {operation}")]
    MissingPipe { operation: &'static str },

    #[error("nft did not {operation} within {limit:?}")]
    Timeout {
        operation: &'static str,
        limit: Duration,
    },

    #[error("nft failed to {operation} ({status}): {stderr}")]
    Failed {
        operation: &'static str,
        status: ExitStatus,
        stderr: String,
    },

    #[error("invalid nft JSON while trying to {operation}")]
    Json {
        operation: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("a jump rule in legacy chain {chain} has no handle, so it cannot be removed")]
    MissingHandle { chain: String },
}
