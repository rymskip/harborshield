use std::time::Duration;

use tokio::time::Instant;

/// The instant `limit` from now. Test limits are seconds long, so this never overflows; if it
/// did, an immediate deadline fails the wait loudly rather than hanging it.
pub fn deadline_in(limit: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(limit).unwrap_or(now)
}
