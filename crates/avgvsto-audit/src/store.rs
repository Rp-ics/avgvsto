use sqlx::PgPool;
use uuid::Uuid;

use crate::models::*;

#[derive(Clone)]
pub struct AuditStore {
    pool: PgPool,
}

impl AuditStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_event(&self, event: CreateAuditEvent) -> Result<AuditEvent, sqlx::Error> {
        let action_str = event.action.to_string();
        sqlx::query_as::<_, AuditEvent>(
            r#"
            INSERT INTO audit_logs (user_id, action, resource, details, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, user_id, action, resource, details, ip_address, user_agent, created_at
            "#,
        )
        .bind(event.user_id)
        .bind(&action_str)
        .bind(event.resource)
        .bind(event.details)
        .bind(event.ip_address)
        .bind(event.user_agent)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn query_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>, sqlx::Error> {
        let limit = query.limit.unwrap_or(50).min(1000);
        let offset = query.offset.unwrap_or(0);
        let action_str = query.action.as_ref().map(|a| a.to_string());

        sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT id, user_id, action, resource, details, ip_address, user_agent, created_at
            FROM audit_logs
            WHERE ($1::uuid IS NULL OR user_id = $1)
              AND ($2::text IS NULL OR action = $2)
              AND ($3::timestamptz IS NULL OR created_at >= $3)
              AND ($4::timestamptz IS NULL OR created_at <= $4)
            ORDER BY created_at DESC
            LIMIT $5 OFFSET $6
            "#,
        )
        .bind(query.user_id)
        .bind(&action_str)
        .bind(query.from)
        .bind(query.to)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_event_by_id(&self, id: Uuid) -> Result<Option<AuditEvent>, sqlx::Error> {
        sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT id, user_id, action, resource, details, ip_address, user_agent, created_at
            FROM audit_logs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn count_events(&self, query: AuditQuery) -> Result<i64, sqlx::Error> {
        let action_str = query.action.as_ref().map(|a| a.to_string());

        let row: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT COUNT(*) as count
            FROM audit_logs
            WHERE ($1::uuid IS NULL OR user_id = $1)
              AND ($2::text IS NULL OR action = $2)
              AND ($3::timestamptz IS NULL OR created_at >= $3)
              AND ($4::timestamptz IS NULL OR created_at <= $4)
            "#,
        )
        .bind(query.user_id)
        .bind(&action_str)
        .bind(query.from)
        .bind(query.to)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.0).unwrap_or(0))
    }
}
