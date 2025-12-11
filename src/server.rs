use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use crate::Result;

pub struct HealthServer {
    listener: TcpListener,
    prometheus_handle: PrometheusHandle,
    start_time: chrono::DateTime<chrono::Utc>,
    version: String,
}

impl HealthServer {
    pub async fn new(
        bind_addr: &str,
        prometheus_handle: PrometheusHandle,
        version: String,
    ) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr).await?;
        let bind_addr = listener.local_addr()?;

        info!("Health check server will bind to {}", bind_addr);

        Ok(Self {
            listener,
            prometheus_handle,
            start_time: chrono::Utc::now(),
            version,
        })
    }

    pub async fn serve(self) -> Result<()> {
        info!(
            "Starting health check server on {}",
            self.listener.local_addr()?
        );

        loop {
            match self.listener.accept().await {
                Ok((stream, _)) => {
                    let prometheus_handle = self.prometheus_handle.clone();
                    let start_time = self.start_time;
                    let version = self.version.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection(stream, prometheus_handle, start_time, version).await
                        {
                            error!("Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    prometheus_handle: PrometheusHandle,
    start_time: chrono::DateTime<chrono::Utc>,
    version: String,
) -> Result<()> {
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..n]);

    // Parse the HTTP request line
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        send_response(&mut stream, 400, "Bad Request", "text/plain", "Bad Request").await?;
        return Ok(());
    }

    let path = parts[1];

    match path {
        "/health" => {
            let response = json!({
                "status": "healthy",
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            send_json_response(&mut stream, 200, "OK", &response).await?;
        }
        "/ready" => {
            let response = json!({
                "status": "ready",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "uptime_seconds": (chrono::Utc::now() - start_time).num_seconds()
            });
            send_json_response(&mut stream, 200, "OK", &response).await?;
        }
        "/metrics" => {
            let metrics = prometheus_handle.render();
            send_response(&mut stream, 200, "OK", "text/plain", &metrics).await?;
        }
        "/version" => {
            let response = json!({
                "version": version,
                "build_time": option_env!("BUILD_TIME").unwrap_or("unknown"),
                "git_commit": option_env!("GIT_COMMIT").unwrap_or("unknown"),
                "rust_version": option_env!("RUST_VERSION").unwrap_or("unknown")
            });
            send_json_response(&mut stream, 200, "OK", &response).await?;
        }
        "/status" => {
            let uptime = chrono::Utc::now() - start_time;
            let response = json!({
                "status": "running",
                "version": version,
                "uptime_seconds": uptime.num_seconds(),
                "start_time": start_time.to_rfc3339(),
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            send_json_response(&mut stream, 200, "OK", &response).await?;
        }
        _ => {
            send_response(&mut stream, 404, "Not Found", "text/plain", "Not Found").await?;
        }
    }

    Ok(())
}

async fn send_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        status_text,
        content_type,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn send_json_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    json_value: &serde_json::Value,
) -> Result<()> {
    let body = json_value.to_string();
    send_response(stream, status_code, status_text, "application/json", &body).await
}

pub fn setup_metrics() -> Result<PrometheusHandle> {
    let builder = PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .map_err(|e| crate::Error::metrics(format!("Failed to setup metrics: {}", e)))?;

    // Register some custom metrics
    metrics::describe_counter!(
        "harborshield_rules_applied_total",
        "Total number of firewall rules applied"
    );
    metrics::describe_counter!(
        "harborshield_containers_tracked_total",
        "Total number of containers being tracked"
    );
    metrics::describe_counter!(
        "harborshield_errors_total",
        "Total number of errors encountered"
    );
    metrics::describe_gauge!(
        "harborshield_active_containers",
        "Number of currently active containers"
    );
    metrics::describe_gauge!(
        "harborshield_active_rules",
        "Number of currently active firewall rules"
    );
    metrics::describe_histogram!(
        "harborshield_rule_apply_duration_seconds",
        "Time taken to apply firewall rules"
    );

    Ok(handle)
}

// Metrics helper functions
pub fn increment_rules_applied() {
    metrics::counter!("harborshield_rules_applied_total").increment(1);
}

pub fn increment_containers_tracked() {
    metrics::counter!("harborshield_containers_tracked_total").increment(1);
}

pub fn increment_errors() {
    metrics::counter!("harborshield_errors_total").increment(1);
}

pub fn set_active_containers(count: u64) {
    metrics::gauge!("harborshield_active_containers").set(count as f64);
}

pub fn set_active_rules(count: u64) {
    metrics::gauge!("harborshield_active_rules").set(count as f64);
}

pub fn record_rule_apply_duration(duration: std::time::Duration) {
    metrics::histogram!("harborshield_rule_apply_duration_seconds").record(duration.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Note: These tests verify the metric helper functions don't panic.
    // The actual metric recording depends on the metrics recorder being installed.

    #[test]
    fn test_increment_rules_applied_no_panic() {
        // This should not panic even without a metrics recorder
        increment_rules_applied();
    }

    #[test]
    fn test_increment_containers_tracked_no_panic() {
        // This should not panic even without a metrics recorder
        increment_containers_tracked();
    }

    #[test]
    fn test_increment_errors_no_panic() {
        // This should not panic even without a metrics recorder
        increment_errors();
    }

    #[test]
    fn test_set_active_containers_no_panic() {
        // This should not panic even without a metrics recorder
        set_active_containers(0);
        set_active_containers(5);
        set_active_containers(100);
    }

    #[test]
    fn test_set_active_rules_no_panic() {
        // This should not panic even without a metrics recorder
        set_active_rules(0);
        set_active_rules(10);
        set_active_rules(1000);
    }

    #[test]
    fn test_record_rule_apply_duration_no_panic() {
        // This should not panic even without a metrics recorder
        record_rule_apply_duration(Duration::from_secs(0));
        record_rule_apply_duration(Duration::from_millis(100));
        record_rule_apply_duration(Duration::from_secs(1));
    }

    #[test]
    fn test_record_rule_apply_duration_subsecond() {
        // Verify subsecond durations are handled correctly
        let duration = Duration::from_millis(500);
        assert_eq!(duration.as_secs_f64(), 0.5);
        record_rule_apply_duration(duration);
    }

    #[test]
    fn test_record_rule_apply_duration_large_value() {
        // Verify large durations are handled correctly
        let duration = Duration::from_secs(3600); // 1 hour
        assert_eq!(duration.as_secs_f64(), 3600.0);
        record_rule_apply_duration(duration);
    }
}
