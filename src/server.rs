//! HTTP health/metrics server.
//!
//! Exposes `/health`, `/ready`, `/metrics`, `/version`, `/status` over HTTP/1.1
//! using axum. Metrics setup and the small counter/gauge helpers below are
//! unrelated to the HTTP layer and used from across the crate.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::get,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde_json::json;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

use crate::Result;

#[derive(Clone)]
struct HealthState {
    prometheus_handle: PrometheusHandle,
    start_time: chrono::DateTime<chrono::Utc>,
    version: String,
}

pub struct HealthServer {
    listener: TcpListener,
    state: HealthState,
}

impl HealthServer {
    pub async fn new(
        bind_addr: &str,
        prometheus_handle: PrometheusHandle,
        version: String,
    ) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("Health check server will bind to {}", listener.local_addr()?);

        Ok(Self {
            listener,
            state: HealthState {
                prometheus_handle,
                start_time: chrono::Utc::now(),
                version,
            },
        })
    }

    pub async fn serve(self) -> Result<()> {
        info!(
            "Starting health check server on {}",
            self.listener.local_addr()?
        );

        let router = Router::new()
            .route("/health", get(health))
            .route("/ready", get(ready))
            .route("/metrics", get(metrics))
            .route("/version", get(version))
            .route("/status", get(status))
            .with_state(Arc::new(self.state));

        axum::serve(self.listener, router).await?;
        Ok(())
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn ready(State(state): State<Arc<HealthState>>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ready",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "uptime_seconds": (chrono::Utc::now() - state.start_time).num_seconds(),
    }))
}

async fn metrics(State(state): State<Arc<HealthState>>) -> Response {
    let body = state.prometheus_handle.render();
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    response
}

async fn version(State(state): State<Arc<HealthState>>) -> Json<serde_json::Value> {
    Json(json!({
        "version": state.version,
        "build_time": option_env!("BUILD_TIME").unwrap_or("unknown"),
        "git_commit": option_env!("GIT_COMMIT").unwrap_or("unknown"),
        "rust_version": option_env!("RUST_VERSION").unwrap_or("unknown"),
    }))
}

async fn status(State(state): State<Arc<HealthState>>) -> Json<serde_json::Value> {
    let uptime = chrono::Utc::now() - state.start_time;
    Json(json!({
        "status": "running",
        "version": state.version,
        "uptime_seconds": uptime.num_seconds(),
        "start_time": state.start_time.to_rfc3339(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

pub fn setup_metrics() -> Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| crate::Error::metrics(format!("Failed to setup metrics: {}", e)))?;

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

    /// Spin the server on port 0 in a background task and return the bound URL
    /// plus a JoinHandle that can be aborted to stop the server.
    async fn spawn_server() -> (String, tokio::task::JoinHandle<Result<()>>) {
        // Each test gets its own recorder without binding any listener.
        // install_recorder() is global state and would clash across parallel
        // tests; build() also installs an exporter on a default port.
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let server = HealthServer::new("127.0.0.1:0", handle, "test-version".into())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let url = format!("http://{}", addr);

        let join = tokio::spawn(server.serve());
        // Brief settle so the listener is in accept loop before reqwest hits it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        (url, join)
    }

    fn http() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn health_endpoint_returns_healthy_json() {
        let (url, srv) = spawn_server().await;
        let resp = http().get(format!("{}/health", url)).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/json"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "healthy");
        assert!(body["timestamp"].is_string());
        srv.abort();
    }

    #[tokio::test]
    async fn ready_endpoint_includes_uptime() {
        let (url, srv) = spawn_server().await;
        let resp = http().get(format!("{}/ready", url)).send().await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "ready");
        assert!(body["uptime_seconds"].as_i64().is_some());
        srv.abort();
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus_text() {
        let (url, srv) = spawn_server().await;
        let resp = http()
            .get(format!("{}/metrics", url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "text/plain; version=0.0.4"
        );
        // Body is prometheus text exposition; should at least be a valid utf-8
        // string. Empty is acceptable when no metrics have been recorded.
        let body = resp.text().await.unwrap();
        let _ = body;
        srv.abort();
    }

    #[tokio::test]
    async fn version_endpoint_echoes_configured_version() {
        let (url, srv) = spawn_server().await;
        let resp = http()
            .get(format!("{}/version", url))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["version"], "test-version");
        // build-time/git/rust default to "unknown" without env vars.
        assert!(body["build_time"].is_string());
        srv.abort();
    }

    #[tokio::test]
    async fn status_endpoint_returns_running_with_start_time() {
        let (url, srv) = spawn_server().await;
        let resp = http().get(format!("{}/status", url)).send().await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "running");
        assert_eq!(body["version"], "test-version");
        assert!(body["start_time"].is_string());
        srv.abort();
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let (url, srv) = spawn_server().await;
        let resp = http().get(format!("{}/nope", url)).send().await.unwrap();
        assert_eq!(resp.status(), 404);
        srv.abort();
    }
}
