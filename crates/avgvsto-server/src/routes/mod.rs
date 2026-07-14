pub mod admin;
pub mod auth;
pub mod crypto;
pub mod health;
pub mod ws;

use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use sqlx::PgPool;
use utoipa::OpenApi;

use avgvsto_auth::JwtService;
use avgvsto_audit::AuditStore;

use crate::error::ApiError;
use crate::middleware::{admin_middleware, auth_middleware};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub jwt_service: JwtService,
    pub audit_store: AuditStore,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        auth::register,
        auth::login,
        auth::refresh,
        crypto::encrypt_handler,
        crypto::decrypt_handler,
        crypto::verify_handler,
        crypto::encrypt_file_handler,
        crypto::decrypt_file_handler,
        crypto::bind_usb_key,
        crypto::list_keys,
        health::health_check,
        health::metrics_handler,
        health::stats_handler,
        admin::audit_log_handler,
    ),
    components(
        schemas(
            ApiError,
            auth::RegisterBody,
            auth::LoginBody,
            auth::RefreshBody,
            auth::RegisterResponse,
            crypto::EncryptBody,
            crypto::EncryptResponseBody,
            crypto::DecryptBody,
            crypto::VerifyBody,
            crypto::BindUsbBody,
            health::HealthResponse,
            health::MetricsResponse,
            health::StatsResponse,
            admin::AuditLogParams,
            avgvsto_core::VerifyResponse,
            avgvsto_core::DecryptResponse,
            avgvsto_core::CipherSuite,
            avgvsto_auth::AuthResponse,
        )
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "crypto", description = "Encryption/decryption endpoints"),
        (name = "health", description = "Health and metrics endpoints"),
        (name = "admin", description = "Admin-only endpoints"),
    ),
    info(
        title = "AVGVSTO Server API",
        description = "Hardware-bound encryption server with AES-256-GCM, ChaCha20-Poly1305, USB key enforcement, and audit logging",
        version = "0.1.0",
    )
)]
struct ApiDoc;

async fn openapi_json() -> impl IntoResponse {
    (StatusCode::OK, Json(ApiDoc::openapi()))
}

pub fn create_router(state: AppState) -> Router {
    let public_routes = Router::new()
        .merge(auth::routes())
        .merge(health::routes());

    let protected_routes = Router::new()
        .merge(crypto::routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let admin_routes = Router::new()
        .merge(admin::routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin_middleware,
        ));

    Router::new()
        .route("/api/v1/openapi.json", get(openapi_json))
        .merge(public_routes)
        .merge(protected_routes)
        .merge(admin_routes)
        .with_state(state)
}
