use axum::{
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;
use utoipa::ToSchema;

use avgvsto_audit::{AuditAction, AuditQuery};

use super::AppState;
use crate::error::{ApiError, ApiResult};
use crate::middleware::auth::AuthenticatedUser;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/audit-log", get(audit_log_handler))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AuditLogParams {
    pub user_id: Option<Uuid>,
    pub action: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/audit-log",
    tag = "admin",
    params(
        ("user_id" = Option<Uuid>, Query, description = "Filter by user ID"),
        ("action" = Option<String>, Query, description = "Filter by action type"),
        ("from" = Option<String>, Query, description = "Start date (RFC 3339)"),
        ("to" = Option<String>, Query, description = "End date (RFC 3339)"),
        ("limit" = Option<i64>, Query, description = "Max results"),
        ("offset" = Option<i64>, Query, description = "Pagination offset"),
    ),
    responses(
        (status = 200, description = "Audit log entries"),
        (status = 403, description = "Admin access required", body = ApiError),
    )
)]
async fn audit_log_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(params): Query<AuditLogParams>,
) -> ApiResult<impl IntoResponse> {
    if !user.is_admin() {
        return Err(crate::error::forbidden("Admin access required", "ADMIN_REQUIRED"));
    }

    let action = params.action.as_deref().map(AuditAction::from);
    let from = params.from.as_ref().and_then(|s| {
        DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))
    });
    let to = params.to.as_ref().and_then(|s| {
        DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))
    });

    let query = AuditQuery {
        user_id: params.user_id,
        action,
        from,
        to,
        limit: params.limit,
        offset: params.offset,
    };

    let events = state.audit_store.query_events(query).await
        .map_err(|_| crate::error::internal("Failed to query audit log"))?;

    Ok(Json(serde_json::json!(events)))
}
