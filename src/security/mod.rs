//! Process hardening: a capability check, a landlock filesystem sandbox and a seccomp syscall
//! denylist.

pub mod capabilities;
pub mod error;
pub mod landlock;
pub mod seccomp;

use std::path::Path;

pub use error::{Result, SecurityError};

/// Fail unless the process holds the capabilities harborshield needs.
pub fn check_capabilities() -> Result<()> {
    capabilities::check_required_capabilities()
}

/// Confine the process: a filesystem sandbox, then a syscall denylist. Call this before any
/// other thread starts, since the filesystem sandbox only covers the calling thread and the
/// threads and processes it starts afterwards.
pub fn apply_restrictions(data_dir: &Path, log_path: Option<&Path>) -> Result<()> {
    landlock::apply_landlock_rules(data_dir, log_path)?;
    seccomp::apply_seccomp_filters()
}
