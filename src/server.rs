//! HTTP health and metrics server.
//!
//! Exposes `/health`, `/ready`, `/metrics`, `/version` and `/status` over HTTP/1.1 using
//! axum. The metric helpers at the bottom are used from across the crate.

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
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::Result;

/// Whether the firewall currently reflects Docker's state: false until the first reconcile
/// is applied, and while the event stream is being re-established.
#[derive(Clone, Debug, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }

    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
struct HealthState {
    prometheus_handle: PrometheusHandle,
    start_time: chrono::DateTime<chrono::Utc>,
    version: String,
    readiness: Readiness,
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
        readiness: Readiness,
    ) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!(
            "Health check server will bind to {}",
            listener.local_addr()?
        );

        Ok(Self {
            listener,
            state: HealthState {
                prometheus_handle,
                start_time: chrono::Utc::now(),
                version,
                readiness,
            },
        })
    }

    /// Serve until `shutdown` is cancelled.
    pub async fn serve(self, shutdown: CancellationToken) -> Result<()> {
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

        axum::serve(self.listener, router)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await?;
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

async fn ready(State(state): State<Arc<HealthState>>) -> Response {
    let ready = state.readiness.is_ready();
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = Json(json!({
        "status": if ready { "ready" } else { "starting" },
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "uptime_seconds": chrono::Utc::now().signed_duration_since(state.start_time).num_seconds(),
    }));
    (status, body).into_response()
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
    let uptime = chrono::Utc::now().signed_duration_since(state.start_time);
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
        .map_err(|error| crate::Error::Metrics(error.to_string()))?;

    metrics::describe_counter!(
        "harborshield_reconciles_total",
        "Total number of firewall reconciles applied"
    );
    metrics::describe_counter!(
        "harborshield_errors_total",
        "Total number of errors encountered"
    );
    metrics::describe_gauge!(
        "harborshield_active_containers",
        "Number of containers under management"
    );

    Ok(handle)
}

pub fn increment_rules_applied() {
    metrics::counter!("harborshield_reconciles_total").increment(1);
}

pub fn increment_errors() {
    metrics::counter!("harborshield_errors_total").increment(1);
}

pub fn set_active_containers(count: usize) {
    // A gauge is an f64; any realistic container count fits a u32 exactly.
    let count = u32::try_from(count).unwrap_or(u32::MAX);
    metrics::gauge!("harborshield_active_containers").set(count);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use metrics_exporter_prometheus::PrometheusBuilder;
    use tokio_util::sync::CancellationToken;

    use super::{
        HealthServer, Readiness, increment_errors, increment_rules_applied, set_active_containers,
    };

    #[test]
    fn metric_helpers_work_without_a_recorder() {
        increment_rules_applied();
        increment_errors();
        set_active_containers(0);
        set_active_containers(usize::MAX);
    }

    /// Serve on port 0 in a background task; cancel the token to stop it.
    async fn spawn_server(readiness: Readiness) -> (String, CancellationToken) {
        // install_recorder() is global and would clash across parallel tests.
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let server = HealthServer::new("127.0.0.1:0", handle, "test-version".into(), readiness)
            .await
            .expect("bind health server");
        let url = format!("http://{}", server.local_addr().expect("bound address"));
        let shutdown = CancellationToken::new();
        tokio::spawn(server.serve(shutdown.clone()));
        (url, shutdown)
    }

    fn http() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("HTTP client")
    }

    async fn get_json(url: &str) -> (u16, serde_json::Value) {
        let response = http().get(url).send().await.expect("request");
        let status = response.status().as_u16();
        (status, response.json().await.expect("JSON body"))
    }

    #[tokio::test]
    async fn health_endpoint_returns_healthy_json() {
        let (url, shutdown) = spawn_server(Readiness::default()).await;
        let (status, body) = get_json(&format!("{url}/health")).await;
        assert_eq!(status, 200);
        assert_eq!(body["status"], "healthy");
        assert!(body["timestamp"].is_string());
        shutdown.cancel();
    }

    #[tokio::test]
    async fn ready_endpoint_follows_readiness() {
        let readiness = Readiness::default();
        let (url, shutdown) = spawn_server(readiness.clone()).await;

        let (status, body) = get_json(&format!("{url}/ready")).await;
        assert_eq!(status, 503);
        assert_eq!(body["status"], "starting");

        readiness.set(true);
        let (status, body) = get_json(&format!("{url}/ready")).await;
        assert_eq!(status, 200);
        assert_eq!(body["status"], "ready");
        assert!(body["uptime_seconds"].as_i64().is_some());

        readiness.set(false);
        let (status, _) = get_json(&format!("{url}/ready")).await;
        assert_eq!(status, 503);
        shutdown.cancel();
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus_text() {
        let (url, shutdown) = spawn_server(Readiness::default()).await;
        let response = http()
            .get(format!("{url}/metrics"))
            .send()
            .await
            .expect("request");
        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .map(|value| value.as_bytes()),
            Some(&b"text/plain; version=0.0.4"[..])
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn version_endpoint_echoes_configured_version() {
        let (url, shutdown) = spawn_server(Readiness::default()).await;
        let (_, body) = get_json(&format!("{url}/version")).await;
        assert_eq!(body["version"], "test-version");
        assert!(body["build_time"].is_string());
        shutdown.cancel();
    }

    #[tokio::test]
    async fn status_endpoint_returns_running_with_start_time() {
        let (url, shutdown) = spawn_server(Readiness::default()).await;
        let (_, body) = get_json(&format!("{url}/status")).await;
        assert_eq!(body["status"], "running");
        assert_eq!(body["version"], "test-version");
        assert!(body["start_time"].is_string());
        shutdown.cancel();
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let (url, shutdown) = spawn_server(Readiness::default()).await;
        let response = http()
            .get(format!("{url}/nope"))
            .send()
            .await
            .expect("request");
        assert_eq!(response.status(), 404);
        shutdown.cancel();
    }

    #[tokio::test]
    async fn cancelling_shuts_the_server_down() {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let server = HealthServer::new("127.0.0.1:0", handle, "v".into(), Readiness::default())
            .await
            .expect("bind health server");
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(server.serve(shutdown.clone()));
        shutdown.cancel();
        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("server stops promptly")
            .expect("server task joins");
        assert!(result.is_ok());
    }
}
