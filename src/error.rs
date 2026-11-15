use std::time::Duration;

use thiserror::Error;

use crate::database::DatabaseError;
use crate::nftables::error::NftablesError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Docker API request failed: {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("invalid IP address or range {input:?}: {reason}")]
    InvalidIpAddress { input: String, reason: String },

    #[error("timed out after {duration:?} trying to {operation}")]
    Timeout {
        duration: Duration,
        operation: &'static str,
    },

    #[error("Docker reported a container without {0}")]
    IncompleteContainer(&'static str),

    #[error("could not set up metrics: {0}")]
    Metrics(String),

    #[error(transparent)]
    Database(#[from] DatabaseError),

    #[error(transparent)]
    Nftables(#[from] NftablesError),
}

impl Error {
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn invalid_ip(input: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidIpAddress {
            input: input.into(),
            reason: reason.into(),
        }
    }

    pub fn timeout(duration: Duration, operation: &'static str) -> Self {
        Self::Timeout {
            duration,
            operation,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::Error;

    #[test]
    fn messages_carry_their_context() {
        assert_eq!(
            Error::config("bad port").to_string(),
            "configuration error: bad port"
        );
        assert_eq!(
            Error::invalid_ip("1.2.3", "not an address").to_string(),
            "invalid IP address or range \"1.2.3\": not an address"
        );
        assert_eq!(
            Error::timeout(Duration::from_secs(10), "list containers").to_string(),
            "timed out after 10s trying to list containers"
        );
        assert_eq!(
            Error::IncompleteContainer("an id").to_string(),
            "Docker reported a container without an id"
        );
    }

    #[test]
    fn wrapped_io_errors_keep_their_cause_in_the_message() {
        let error = Error::from(std::io::Error::other("disk on fire"));
        assert_eq!(error.to_string(), "I/O failed: disk on fire");
    }
}
