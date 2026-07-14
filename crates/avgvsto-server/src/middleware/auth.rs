use axum::{
    extract::{FromRequestParts, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use uuid::Uuid;

use super::super::routes::AppState;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

impl AuthenticatedUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    let auth_header = match auth_header {
        Some(h) => h,
        None => {
            return (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                error: "Missing Authorization header".to_string(),
                code: "MISSING_AUTH".to_string(),
            })).into_response();
        }
    };

    let token = match auth_header.strip_prefix("Bearer ") {
        Some(t) => t,
        None => {
            return (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                error: "Invalid Authorization format. Use: Bearer <token>".to_string(),
                code: "INVALID_AUTH_FORMAT".to_string(),
            })).into_response();
        }
    };

    let claims = match state.jwt_service.validate_access_token(token) {
        Ok(c) => c,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                error: "Invalid or expired token".to_string(),
                code: "INVALID_TOKEN".to_string(),
            })).into_response();
        }
    };

    let authenticated_user = AuthenticatedUser {
        user_id: claims.sub,
        username: claims.username,
        role: claims.role,
    };

    req.extensions_mut().insert(authenticated_user);
    next.run(req).await
}

pub async fn admin_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    let auth_header = match auth_header {
        Some(h) => h,
        None => {
            return (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                error: "Missing Authorization header".to_string(),
                code: "MISSING_AUTH".to_string(),
            })).into_response();
        }
    };

    let token = match auth_header.strip_prefix("Bearer ") {
        Some(t) => t,
        None => {
            return (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                error: "Invalid Authorization format".to_string(),
                code: "INVALID_AUTH_FORMAT".to_string(),
            })).into_response();
        }
    };

    let claims = match state.jwt_service.validate_access_token(token) {
        Ok(c) => c,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                error: "Invalid or expired token".to_string(),
                code: "INVALID_TOKEN".to_string(),
            })).into_response();
        }
    };

    if claims.role != "admin" {
        return (StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "Admin access required".to_string(),
            code: "ADMIN_REQUIRED".to_string(),
        })).into_response();
    }

    let authenticated_user = AuthenticatedUser {
        user_id: claims.sub,
        username: claims.username,
        role: claims.role,
    };

    req.extensions_mut().insert(authenticated_user);
    next.run(req).await
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedUser>()
            .cloned()
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Authentication required".to_string(),
                        code: "AUTH_REQUIRED".to_string(),
                    }),
                )
            })
    }
}
