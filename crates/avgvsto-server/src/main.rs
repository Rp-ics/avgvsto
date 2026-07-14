mod config;
mod db;
mod error;
mod middleware;
mod routes;
mod ws;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use axum::http::{header, HeaderValue, Method};
use axum_server::tls_rustls::RustlsConfig;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::RequestBodyTimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use avgvsto_auth::JwtService;
use avgvsto_audit::AuditStore;

use crate::config::AppConfig;
use crate::routes::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AppConfig::load().unwrap_or_default();

    init_logging(&config);

    tracing::info!("AVGVSTO Server v{} starting", avgvsto_core::APP_VERSION);

    let pool = db::create_pool(&config.database).await?;

    sqlx::migrate!("../../migrations").run(&pool).await?;
    tracing::info!("Database migrations applied");

    let jwt_service = JwtService::new(&config.auth.jwt_secret);
    let audit_store = AuditStore::new(pool.clone());

    let state = AppState {
        pool,
        jwt_service,
        audit_store,
    };

    let security_headers = (
        SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ),
        SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        ),
        SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        ),
        SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        ),
        SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ),
        SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
        ),
    );

    let cors = if config.server.allowed_origins.is_empty() {
        CorsLayer::new()
            .allow_origin(AllowOrigin::any())
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
    } else {
        let origins: Vec<HeaderValue> = config
            .server
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
    };

    let app = routes::create_router(state)
        .layer(security_headers)
        .layer(RequestBodyTimeoutLayer::new(Duration::from_secs(
            config.server.request_timeout_secs,
        )))
        .layer(RequestBodyLimitLayer::new(config.server.max_body_size as usize))
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    let addr = SocketAddr::new(
        config.server.host.parse().expect("Invalid host address"),
        config.server.port,
    );

    if config.server.tls.enabled {
        let tls_config = RustlsConfig::from_pem_file(
            Path::new(&config.server.tls.cert_path),
            Path::new(&config.server.tls.key_path),
        )
        .await?;

        tracing::info!("Listening on https://{}", addr);
        tracing::info!("API: https://{}/api/v1/health", addr);
        tracing::info!("Docs: https://{}/api/v1/swagger-ui/", addr);

        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        tracing::info!("Listening on http://{}", addr);
        tracing::info!("API: http://{}/api/v1/health", addr);
        tracing::info!("Docs: http://{}/api/v1/swagger-ui/", addr);

        axum_server::bind(addr)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    }

    Ok(())
}

fn init_logging(config: &AppConfig) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::Layer::new()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true),
        )
        .init();
}
