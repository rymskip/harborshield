pub mod database;
pub mod docker;
pub mod error;
pub mod handlers;
pub mod nftables;
#[cfg(target_os = "linux")]
pub mod security;
pub mod server;

use crate::{
    database::DB,
    docker::DockerClient,
    nftables::{kernel, plan},
    server::Readiness,
};
use bon::bon;
pub use error::{Error, Result};
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use std::time::Duration;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub const ENABLED_LABEL: &str = "harborshield.enabled";
pub const RULES_LABEL: &str = "harborshield.rules";

/// How long `stop` waits for each background task to finish.
const TASK_STOP_LIMIT: Duration = Duration::from_secs(30);

/// The daemon: tracks Docker's containers and keeps harborshield's firewall table in step.
#[derive(Clone)]
pub struct Harborshield {
    docker_client: Arc<DockerClient>,
    db: Arc<DB>,
    /// Serialises reconciles so two never interleave their read and apply.
    firewall: Arc<Mutex<()>>,
    readiness: Readiness,
    cancellation: CancellationToken,
    tasks: Arc<StdMutex<Vec<JoinHandle<()>>>>,
}

#[bon]
impl Harborshield {
    /// Connect to Docker and open the database. Nothing touches the firewall until `start` or
    /// `clear`.
    #[builder]
    pub async fn new(
        db_path: &Path,
        timeout: Duration,
        health_server_addr: Option<&str>,
    ) -> Result<Self> {
        let docker_client = Arc::new(DockerClient::connect(timeout)?);
        let db = Arc::new(DB::builder().db_path(db_path).build().await?);
        let readiness = Readiness::default();
        let cancellation = CancellationToken::new();
        let mut tasks = Vec::new();

        if let Some(addr) = health_server_addr {
            let health_server = server::HealthServer::new(
                addr,
                server::setup_metrics()?,
                VERSION.to_string(),
                readiness.clone(),
            )
            .await?;
            let shutdown = cancellation.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(failure) = health_server.serve(shutdown).await {
                    error!(%failure, "health server failed");
                }
            }));
        }

        Ok(Self {
            docker_client,
            db,
            firewall: Arc::new(Mutex::new(())),
            readiness,
            cancellation,
            tasks: Arc::new(StdMutex::new(tasks)),
        })
    }

    /// Synchronise with Docker, install the firewall, report ready, then follow events.
    pub async fn start(mut self) -> Result<Self> {
        info!("Starting harborshield");
        self.docker_client = Arc::new(self.docker_client.negotiated().await?);
        let since = chrono::Utc::now().timestamp();
        self.resync().await?;
        self.reconcile().await?;
        self.readiness.set(true);

        let follower = self.clone();
        let handle = tokio::spawn(async move { follower.follow_events(since).await });
        self.lock_tasks().push(handle);
        Ok(self)
    }

    /// Stop following events and wait for background tasks. The firewall stays in force, so
    /// containers remain protected while the daemon is down.
    pub async fn stop(self) {
        info!("Stopping harborshield");
        self.readiness.set(false);
        self.cancellation.cancel();
        let tasks = std::mem::take(&mut *self.lock_tasks());
        for task in tasks {
            match tokio::time::timeout(TASK_STOP_LIMIT, task).await {
                Ok(Ok(())) => {}
                Ok(Err(failure)) => error!(%failure, "background task failed"),
                Err(_elapsed) => warn!("background task did not stop within {TASK_STOP_LIMIT:?}"),
            }
        }
        match Arc::into_inner(self.db) {
            Some(db) => db.close().await,
            None => warn!("database still shared at shutdown; it closes when the last user drops"),
        }
        info!("harborshield stopped");
    }

    /// Remove every firewall object harborshield owns, current or legacy, and forget all
    /// containers.
    pub async fn clear(&self) -> Result<()> {
        info!("Clearing harborshield's firewall rules");
        let _serial = self.firewall.lock().await;
        let state = kernel::read_state().await?;
        kernel::apply(plan::clear(&state)).await?;
        self.db.delete_all_containers().await?;
        self.docker_client.container_tracker.clear();
        Ok(())
    }

    // Pushes and takes are single operations, so a poisoned lock is safe to reuse.
    fn lock_tasks(&self) -> std::sync::MutexGuard<'_, Vec<JoinHandle<()>>> {
        self.tasks.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parse `100ms`, `10s`, `5m`, or a bare number of seconds.
pub fn parse_duration(input: &str) -> std::result::Result<Duration, String> {
    let input = input.trim();
    let (number, unit_ms) = if let Some(millis) = input.strip_suffix("ms") {
        (millis, 1)
    } else if let Some(seconds) = input.strip_suffix('s') {
        (seconds, 1_000)
    } else if let Some(minutes) = input.strip_suffix('m') {
        (minutes, 60_000)
    } else {
        (input, 1_000)
    };
    let count: u64 = number
        .parse()
        .map_err(|failure| format!("invalid duration {input:?}: {failure}"))?;
    count
        .checked_mul(unit_ms)
        .map(Duration::from_millis)
        .ok_or_else(|| format!("duration {input:?} is too long"))
}

/// Wait for SIGINT or SIGTERM.
pub async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        signal::ctrl_c().await
    }
}

/// Warn when the kernel is older than the 5.10 harborshield is tested against.
pub fn check_kernel_version() {
    let release = match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(release) => release,
        Err(failure) => {
            warn!(%failure, "could not read the kernel version");
            return;
        }
    };
    let release = release.trim();
    let mut numbers = release.split(['.', '-']).map(str::parse::<u32>);
    match (numbers.next(), numbers.next()) {
        (Some(Ok(major)), Some(Ok(minor))) if (major, minor) < (5, 10) => warn!(
            "kernel {release} is older than 5.10, which harborshield requires; it will probably not work correctly"
        ),
        (Some(Ok(_)), Some(Ok(_))) => {}
        _ => warn!(%release, "could not parse the kernel version"),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::parse_duration;

    #[test]
    fn test_parse_duration_overflow_is_an_error() {
        assert!(parse_duration("18446744073709551615m").is_err());
    }

    #[test]
    fn test_parse_duration_milliseconds() {
        let result = parse_duration("100ms");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_millis(100));
    }

    #[test]
    fn test_parse_duration_seconds() {
        let result = parse_duration("30s");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_no_suffix() {
        let result = parse_duration("45");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(45));
    }

    #[test]
    fn test_parse_duration_minutes() {
        let result = parse_duration("5m");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_invalid_number() {
        let result = parse_duration("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_duration_empty_string() {
        let result = parse_duration("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_duration_whitespace_trimmed() {
        let result = parse_duration("  30s  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_zero() {
        let result = parse_duration("0s");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(0));
    }
}
