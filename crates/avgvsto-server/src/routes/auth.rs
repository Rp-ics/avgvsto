use axum::{
    extract::ConnectInfo,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use std::net::SocketAddr;
use utoipa::ToSchema;

use avgvsto_auth::{AuthService, CreateUserRequest, LoginRequest};

use super::AppState;
use crate::error::{ApiError, ApiResult};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterBody {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshBody {
    pub refresh_token: String,
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct RegisterResponse {
    pub user_id: uuid::Uuid,
    pub username: String,
    pub role: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/register",
    tag = "auth",
    request_body = RegisterBody,
    responses(
        (status = 201, description = "User registered", body = RegisterResponse),
        (status = 400, description = "Validation error", body = ApiError),
        (status = 409, description = "User already exists", body = ApiError),
    )
)]
async fn register(
    state: axum::extract::State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RegisterBody>,
) -> ApiResult<impl IntoResponse> {
    let auth_service = AuthService::new(state.pool.clone(), state.jwt_service.clone());

    let req = CreateUserRequest {
        username: body.username,
        password: body.password,
    };

    let user = auth_service
        .register_user(
            req,
            Some(addr.ip().to_string()),
            headers
                .get("User-Agent")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        )
        .await
        .map_err(|e| match e {
            avgvsto_auth::AuthError::UserAlreadyExists => {
                crate::error::conflict("User already exists", "USER_EXISTS")
            }
            avgvsto_auth::AuthError::ValidationError(msg) => {
                crate::error::bad_request(msg, "VALIDATION_ERROR")
            }
            _ => crate::error::internal("Registration failed"),
        })?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!(RegisterResponse {
            user_id: user.id,
            username: user.username,
            role: user.role,
        })),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/login",
    tag = "auth",
    request_body = LoginBody,
    responses(
        (status = 200, description = "Login successful", body = avgvsto_auth::AuthResponse),
        (status = 401, description = "Invalid credentials", body = ApiError),
    )
)]
async fn login(
    state: axum::extract::State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginBody>,
) -> ApiResult<impl IntoResponse> {
    let auth_service = AuthService::new(state.pool.clone(), state.jwt_service.clone());

    let req = LoginRequest {
        username: body.username,
        password: body.password,
    };

    let response = auth_service
        .login(
            req,
            Some(addr.ip().to_string()),
            headers
                .get("User-Agent")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        )
        .await
        .map_err(|e| match e {
            avgvsto_auth::AuthError::InvalidCredentials => {
                crate::error::unauthorized("Invalid credentials", "INVALID_CREDENTIALS")
            }
            _ => crate::error::internal("Login failed"),
        })?;

    Ok(Json(serde_json::json!(response)))
}

#[utoipa::path(
    post,
    path = "/api/v1/refresh",
    tag = "auth",
    request_body = RefreshBody,
    responses(
        (status = 200, description = "Token refreshed", body = avgvsto_auth::AuthResponse),
        (status = 401, description = "Invalid or expired refresh token", body = ApiError),
    )
)]
async fn refresh(
    state: axum::extract::State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RefreshBody>,
) -> ApiResult<impl IntoResponse> {
    let auth_service = AuthService::new(state.pool.clone(), state.jwt_service.clone());

    let response = auth_service
        .refresh_token(
            &body.refresh_token,
            Some(addr.ip().to_string()),
            headers
                .get("User-Agent")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        )
        .await
        .map_err(|e| match e {
            avgvsto_auth::AuthError::InvalidToken
            | avgvsto_auth::AuthError::TokenExpired => {
                crate::error::unauthorized("Invalid or expired refresh token", "REFRESH_FAILED")
            }
            _ => crate::error::internal("Token refresh failed"),
        })?;

    Ok(Json(serde_json::json!(response)))
}
