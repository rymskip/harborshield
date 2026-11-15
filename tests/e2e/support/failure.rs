use std::fmt;

/// Why an e2e step failed, carrying enough context to diagnose it from the test output alone.
#[derive(Debug)]
pub struct Failure {
    message: String,
}

impl Failure {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Wrap a lower-level error with the operation that produced it.
    pub fn context(operation: impl fmt::Display, cause: impl fmt::Display) -> Self {
        Self::new(format!("{operation}: {cause}"))
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

pub type TestResult<T = ()> = Result<T, Failure>;
