use bon::builder;
use std::future::Future;
use std::time::{Duration, Instant};

/// Initialize tracing for integration tests with maximum verbosity
pub fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("harborshield=trace,integration_tests=trace")
        .with_test_writer()
        .try_init();
}

/// Initialize tracing with custom filter
pub fn init_test_tracing_with_filter(filter: &str) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

#[builder]
pub async fn retry_with_delay<F, Fut, T, E>(
    mut operation: F,
    #[builder(default)] description: &str,
    #[builder(default = 5)] max_attempts: u32,
    #[builder(default = 5)] delay_seconds: u64,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    for attempt in 1..=max_attempts {
        println!("{} - attempt {}/{}", description, attempt, max_attempts);

        match operation().await {
            Ok(result) => {
                println!("✓ {} succeeded on attempt {}", description, attempt);
                return Ok(result);
            }
            Err(e) => {
                if attempt < max_attempts {
                    println!(
                        "✗ {} failed on attempt {}: {:?}, retrying in {} seconds...",
                        description, attempt, e, delay_seconds
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(delay_seconds)).await;
                } else {
                    println!("✗ {} failed after {} attempts", description, max_attempts);
                    return Err(e);
                }
            }
        }
    }
    unreachable!()
}

/// Poll `check` every `interval` until it returns true or `timeout` elapses.
/// Returns Err with a descriptive message on timeout.
pub async fn poll_until<F, Fut>(
    description: &str,
    timeout: Duration,
    interval: Duration,
    mut check: F,
) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let start = Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        if check().await {
            eprintln!(
                "✓ {} ready (attempt {}, {:.1}s)",
                description,
                attempt,
                start.elapsed().as_secs_f32()
            );
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(format!(
                "{} not ready after {:.1}s ({} attempts)",
                description,
                timeout.as_secs_f32(),
                attempt
            ));
        }
        tokio::time::sleep(interval).await;
    }
}

/// Reserve an unused TCP port on 127.0.0.1 and return it.
/// There is a TOCTOU race between the bind and the caller's reuse — fine for tests.
pub fn pick_free_port() -> std::io::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Probe a TCP endpoint with a short connect timeout.
pub fn tcp_probe(addr: &str, timeout: Duration) -> bool {
    use std::net::ToSocketAddrs;
    let Some(socket_addr) = addr.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        return false;
    };
    std::net::TcpStream::connect_timeout(&socket_addr, timeout).is_ok()
}

/// Block until all docker compose services for `project` report state "running",
/// or `timeout` elapses.
pub async fn wait_for_compose_services(
    compose_file: &std::path::Path,
    project: &str,
    timeout: Duration,
) -> Result<(), String> {
    poll_until(
        &format!("docker compose project {}", project),
        timeout,
        Duration::from_millis(500),
        || async move {
            let output = std::process::Command::new("docker")
                .args([
                    "compose",
                    "-f",
                    compose_file.to_str().unwrap(),
                    "-p",
                    project,
                    "ps",
                    "--format",
                    "json",
                ])
                .output();
            let Ok(output) = output else { return false };
            if !output.status.success() {
                return false;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut total = 0u32;
            let mut running = 0u32;
            for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                total += 1;
                if v.get("State").and_then(|s| s.as_str()) == Some("running") {
                    running += 1;
                }
            }
            total > 0 && running == total
        },
    )
    .await
}

/// Block until harborshield's health endpoint returns 200, or `timeout` elapses.
pub async fn wait_for_harborshield_health(
    health_addr: &str,
    timeout: Duration,
) -> Result<(), String> {
    let url = format!("http://{}/health", health_addr);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| format!("reqwest client build failed: {}", e))?;
    poll_until(
        &format!("harborshield health at {}", health_addr),
        timeout,
        Duration::from_millis(250),
        || {
            let client = client.clone();
            let url = url.clone();
            async move {
                client
                    .get(&url)
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
            }
        },
    )
    .await
}
