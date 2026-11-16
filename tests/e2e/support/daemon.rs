use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::process::{Child, Command};

use super::command::run;
use super::failure::{Failure, TestResult};
use super::time::deadline_in;

/// The harborshield this build produced.
pub const CURRENT_BINARY: &str = env!("CARGO_BIN_EXE_harborshield");
const READY_LIMIT: Duration = Duration::from_secs(60);
/// The daemon allows its tasks 30 s to wind down; give it a margin on top.
const STOP_LIMIT: Duration = Duration::from_secs(45);
const CLEAR_LIMIT: Duration = Duration::from_secs(60);

/// A running harborshield process.
pub struct Daemon {
    child: Child,
    health: SocketAddr,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
    http: reqwest::Client,
}

impl Daemon {
    pub async fn start(
        binary: &Path,
        data_dir: &Path,
        log_dir: &Path,
        generation: u32,
    ) -> TestResult<Self> {
        let health = free_local_port()?;
        let stdout_log = log_dir.join(format!("harborshield-{generation}.stdout.log"));
        let stderr_log = log_dir.join(format!("harborshield-{generation}.stderr.log"));
        let stdout = std::fs::File::create(&stdout_log)
            .map_err(|error| Failure::context(format!("create {}", stdout_log.display()), error))?;
        let stderr = std::fs::File::create(&stderr_log)
            .map_err(|error| Failure::context(format!("create {}", stderr_log.display()), error))?;

        let child = Command::new(binary)
            .arg("--data-dir")
            .arg(data_dir)
            .arg("--debug")
            .arg("--health-server")
            .arg(health.to_string())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| Failure::context(format!("spawn {}", binary.display()), error))?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|error| Failure::context("build HTTP client", error))?;

        let mut daemon = Self {
            child,
            health,
            stdout_log,
            stderr_log,
            http,
        };
        daemon.wait_until_ready().await?;
        Ok(daemon)
    }

    async fn wait_until_ready(&mut self) -> TestResult {
        let deadline = deadline_in(READY_LIMIT);
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|error| Failure::context("poll harborshield", error))?
            {
                return Err(Failure::new(format!(
                    "harborshield exited with {status} before becoming ready\n{}",
                    self.log_tail()
                )));
            }
            // Connection errors are expected until the server binds; the last one is reported
            // if readiness never arrives.
            let last = match self.get("/ready").await {
                Ok((200, _)) => return Ok(()),
                Ok((status, body)) => format!("/ready answered {status}: {body}"),
                Err(error) => error.to_string(),
            };
            if tokio::time::Instant::now() >= deadline {
                return Err(Failure::new(format!(
                    "harborshield was not ready after {READY_LIMIT:?} (last: {last})\n{}",
                    self.log_tail()
                )));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// GET a path on the health server, returning the status code and body.
    pub async fn get(&self, path: &str) -> TestResult<(u16, String)> {
        let url = format!("http://{}{path}", self.health);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|error| Failure::context(format!("GET {url}"), error))?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .map_err(|error| Failure::context(format!("read body of {url}"), error))?;
        Ok((status, body))
    }

    /// Ask for a graceful shutdown with SIGTERM and require a clean exit.
    pub async fn stop(mut self) -> TestResult {
        let pid = self
            .child
            .id()
            .ok_or_else(|| Failure::new("harborshield already exited before stop"))?;
        let pid =
            i32::try_from(pid).map_err(|error| Failure::context("harborshield pid", error))?;
        kill(Pid::from_raw(pid), Signal::SIGTERM)
            .map_err(|error| Failure::context("send SIGTERM to harborshield", error))?;
        let status = self.wait_for_exit(STOP_LIMIT).await?;
        if status.success() {
            Ok(())
        } else {
            Err(Failure::new(format!(
                "harborshield exited with {status} on SIGTERM\n{}",
                self.log_tail()
            )))
        }
    }

    /// Kill the process outright, as a crash would.
    pub async fn crash(mut self) -> TestResult {
        self.child
            .kill()
            .await
            .map_err(|error| Failure::context("SIGKILL harborshield", error))
    }

    async fn wait_for_exit(&mut self, limit: Duration) -> TestResult<ExitStatus> {
        match tokio::time::timeout(limit, self.child.wait()).await {
            Ok(result) => result.map_err(|error| Failure::context("wait for harborshield", error)),
            Err(elapsed) => {
                let tail = self.log_tail();
                self.child
                    .kill()
                    .await
                    .map_err(|error| Failure::context("SIGKILL hung harborshield", error))?;
                Err(Failure::new(format!(
                    "harborshield did not exit within {limit:?} ({elapsed})\n{tail}"
                )))
            }
        }
    }

    fn log_tail(&self) -> String {
        [&self.stdout_log, &self.stderr_log]
            .iter()
            .map(|path| match std::fs::read_to_string(path) {
                Ok(contents) => {
                    let lines: Vec<&str> = contents.lines().collect();
                    let start = lines.len().saturating_sub(40);
                    format!(
                        "--- {} (last 40 lines)\n{}",
                        path.display(),
                        lines.get(start..).unwrap_or_default().join("\n")
                    )
                }
                Err(error) => format!("--- {} unreadable: {error}", path.display()),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Run `harborshield --clear` against a data directory and require success.
pub async fn clear(data_dir: &Path) -> TestResult {
    let data_dir = data_dir
        .to_str()
        .ok_or_else(|| Failure::new(format!("data dir {} is not UTF-8", data_dir.display())))?;
    let output = run(
        CURRENT_BINARY,
        &["--clear", "--data-dir", data_dir],
        CLEAR_LIMIT,
    )
    .await?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Failure::new(format!(
            "harborshield --clear exited with {}\nstdout: {}\nstderr: {}",
            output.status,
            output.stdout.trim(),
            output.stderr.trim()
        )))
    }
}

fn free_local_port() -> TestResult<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| Failure::context("reserve a health server port", error))?;
    listener
        .local_addr()
        .map_err(|error| Failure::context("read reserved port", error))
}
