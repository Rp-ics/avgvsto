use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiError {
    pub error: String,
    pub code: String,
}

impl ApiError {
    pub fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.into(),
        }
    }
}

pub type ApiResult<T> = Result<T, (StatusCode, Json<ApiError>)>;

pub fn bad_request(error: impl Into<String>, code: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (StatusCode::BAD_REQUEST, Json(ApiError::new(error, code)))
}

pub fn unauthorized(error: impl Into<String>, code: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (StatusCode::UNAUTHORIZED, Json(ApiError::new(error, code)))
}

pub fn forbidden(error: impl Into<String>, code: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (StatusCode::FORBIDDEN, Json(ApiError::new(error, code)))
}

pub fn not_found(error: impl Into<String>, code: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (StatusCode::NOT_FOUND, Json(ApiError::new(error, code)))
}

pub fn conflict(error: impl Into<String>, code: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (StatusCode::CONFLICT, Json(ApiError::new(error, code)))
}

pub fn internal(error: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError::new(error, "INTERNAL_ERROR")),
    )
}
