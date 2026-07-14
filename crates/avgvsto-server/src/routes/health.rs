use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use utoipa::ToSchema;

use super::AppState;

static START_TIME: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);

pub fn increment_request_count() {
    TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(metrics_handler))
        .route("/stats", get(stats_handler))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: &'static str,
    pub uptime_secs: u64,
    pub database: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Server health status", body = HealthResponse),
        (status = 503, description = "Service degraded"),
    )
)]
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let db_status = sqlx::query("SELECT 1")
        .execute(&state.pool)
        .await
        .is_ok();

    let status = if db_status { "healthy" } else { "degraded" };
    let http_status = if db_status {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        http_status,
        Json(HealthResponse {
            status: status.to_string(),
            version: avgvsto_core::APP_VERSION,
            uptime_secs: START_TIME.elapsed().as_secs(),
            database: if db_status {
                "connected".to_string()
            } else {
                "disconnected".to_string()
            },
        }),
    )
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MetricsResponse {
    pub uptime_secs: u64,
    pub total_requests: u64,
    pub memory_usage_bytes: u64,
}

fn get_memory_usage() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    if let Some(val) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = val.parse::<u64>() {
                            return kb * 1024;
                        }
                    }
                }
            }
        }
    }
    0
}

#[utoipa::path(
    get,
    path = "/api/v1/metrics",
    tag = "health",
    responses(
        (status = 200, description = "Server metrics", body = MetricsResponse),
    )
)]
async fn metrics_handler() -> impl IntoResponse {
    let metrics = MetricsResponse {
        uptime_secs: START_TIME.elapsed().as_secs(),
        total_requests: TOTAL_REQUESTS.load(Ordering::Relaxed),
        memory_usage_bytes: get_memory_usage(),
    };
    (StatusCode::OK, Json(metrics))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StatsResponse {
    pub app_name: &'static str,
    pub app_version: &'static str,
    pub uptime_secs: u64,
    pub total_requests: u64,
}

#[utoipa::path(
    get,
    path = "/api/v1/stats",
    tag = "health",
    responses(
        (status = 200, description = "Server stats", body = StatsResponse),
    )
)]
async fn stats_handler() -> impl IntoResponse {
    Json(StatsResponse {
        app_name: avgvsto_core::APP_NAME,
        app_version: avgvsto_core::APP_VERSION,
        uptime_secs: START_TIME.elapsed().as_secs(),
        total_requests: TOTAL_REQUESTS.load(Ordering::Relaxed),
    })
}
